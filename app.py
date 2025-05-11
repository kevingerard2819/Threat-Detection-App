from flask import Flask, request, jsonify, render_template, send_file, redirect, session
from flask_cors import CORS
from functools import wraps
from dotenv import load_dotenv
import os
import json
import csv
from datetime import datetime
import tempfile
import google.generativeai as genai
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Load environment variables from .env
load_dotenv()

# Configure Gemini model
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

def generate_email_alert(threat_type, severity, description, response, confidence):
    email_body = f"""
    Subject: Urgent: {threat_type} detected with {severity} severity

    Hello Security Team,

    We have detected a new threat with the following details:

    - **Threat Type**: {threat_type}
    - **Severity**: {severity}
    - **Description**: {description}
    - **Confidence**: {confidence}%
    - **Suggested Response**: {response}

    Please review and take immediate action according to our [Incident Response Plan].

    Thank you,
    Threat Detection System
    """
    return email_body
    
def send_email_alert(subject, body, to_email):
    from_email = os.getenv("SENDER_EMAIL")  # Set in your .env
    password = os.getenv("SENDER_PASSWORD")  # Set in your .env

    # Set up the MIME
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Establish connection to the Gmail SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Secure the connection
        server.login(from_email, password)

        # Send the email
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()

        print("Email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {str(e)}")

# Flask app setup
app = Flask(__name__, static_folder='../frontend/static', template_folder='../frontend/templates')
CORS(app)
app.secret_key = os.getenv("SECRET_KEY", "super-secret-key")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")

# Middleware
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-KEY")
        if key != ADMIN_API_KEY:
            return jsonify({"error": "Unauthorized"}), 403
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    if data.get("username") == "admin" and data.get("password") == "admin123":
        session["logged_in"] = True
        return jsonify({"success": True})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/classify")
@login_required
def classify_page():
    return render_template("index.html")

def classify_threat(description, mode="strict"):
    if mode == "chat":
        prompt = (
            f"You are a cybersecurity analyst. Explain in plain language what this threat is and why it could be dangerous: {description}"
        )
        response = model.generate_content([prompt])
        return "Chat", "N/A", response.text.strip(), 0, 0

    prompt = (
        "You are a cybersecurity expert. Analyze the following threat description and respond strictly in JSON format "
        "with the following fields: threat_type, severity, suggested_response, confidence_score(0-100), risk_score(0-100)."
        f"Threat: {description}"
    )
    response = model.generate_content([prompt])
    result = response.text.strip()

    # Ensure no markdown before attempting JSON parsing
    if result.startswith("```json"):
        result = result.removeprefix("```json").removesuffix("```")

    print(f"LLM Raw Output: {result}")  # Log the raw result for debugging

    try:
        parsed = json.loads(result)
        threat_type = parsed.get("threat_type", "Unknown")
        severity = parsed.get("severity", "Unknown")
        suggested_response = parsed.get("suggested_response", result)
        confidence = parsed.get("confidence_score", 0)
        risk = parsed.get("risk_score", 0)

        # Fix for cases where LLM gives string, null, or bad number
        try:
             risk = int(risk)
        except (ValueError, TypeError):
             risk = 0
        
        severity_norm = severity.strip().capitalize()
        if not (0 <= risk <= 100):
           severity_weight = {"Low": 20, "Medium": 50, "High": 80}
           risk = min(100, severity_weight.get(severity, 30) + int(confidence * 0.6))

        return threat_type, severity, suggested_response, confidence, risk

    except json.JSONDecodeError as e:
        # If parsing fails, return error and log the result
        print(f"Error parsing JSON: {e}\nRaw result: {result}")
        return "Unknown", "Unknown", result, 0, 0

def log_threat(entry):
    entry["timestamp"] = datetime.now().isoformat()
    with open("threat_log.json", "a") as f:
        json.dump(entry, f)
        f.write("\n")

@app.route('/api/classify', methods=['POST'])
def classify():
    data = request.get_json()
    description = data.get("description", "").strip()
    if not description:
        return jsonify({"error": "No description provided."}), 400
    if len(description) > 500:
        return jsonify({"error": "Description too long (max 500 characters)."}), 400

    try:
        # Classify the threat
        threat_type, severity, response_text, confidence, risk = classify_threat(description)

        # Generate the email alert content
        email_subject = f"Urgent: {threat_type} detected with {severity} severity"
        email_body = generate_email_alert(threat_type, severity, description, response_text, confidence)

        # Send the email (to your email for now)
        send_email_alert(email_subject, email_body, "your_email@example.com")

        # Log the threat
        log_threat({
            "description": description,
            "type": threat_type,
            "severity": severity,
            "response": response_text,
            "confidence": confidence,
            "risk": risk

        })

        return jsonify({
            "type": threat_type,
            "severity": severity,
            "response": response_text,
            "confidence": confidence,
            "risk": risk

        })

    except Exception as e:
        return jsonify({"error": f"Error: {str(e)}"}), 500
        
@app.route('/api/review', methods=['POST'])
def mark_review():
    data = request.get_json()
    timestamp = data.get("timestamp")
    resolution = data.get("resolution")

    if not timestamp:
        return jsonify({"error": "Missing timestamp"}), 400

    comments = {}
    if os.path.exists("comments.json"):
        with open("comments.json", "r") as f:
            comments = json.load(f)

    comments[timestamp] = {"resolution": resolution}
    with open("comments.json", "w") as f:
        json.dump(comments, f, indent=2)

    return jsonify({"status": "updated"})

@app.route("/api/log", methods=["GET"])
def get_log():
    try:
        with open("threat_log.json", "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        logs = [json.loads(line) for line in lines][-10:][::-1]

        reviewed = 0
        unreviewed = 0
        comments = {}
        if os.path.exists("comments.json"):
            with open("comments.json", "r") as cf:
                comments = json.load(cf)

        for log in logs:
            timestamp = log.get("timestamp")
            if timestamp and timestamp in comments:
                if comments[timestamp].get("resolution"):
                    reviewed += 1
                else:
                    unreviewed += 1
            else:
                unreviewed += 1

        return jsonify({
            "logs": logs,
            "reviewed_count": reviewed,
            "unreviewed_count": unreviewed
        })
    except FileNotFoundError:
        return jsonify({"logs": [], "reviewed_count": 0, "unreviewed_count": 0})

@app.route("/api/stats", methods=["GET"])
def stats():
    try:
        with open("threat_log.json", "r") as f:
            logs = [json.loads(line) for line in f if line.strip()]
        summary = {}
        severity_count = {"High": 0, "Medium": 0, "Low": 0}

 
        for log in logs:
            severity = log.get("severity", "").strip().capitalize()
            threat_type = log.get("type", "Unknown").strip()

            key = f"{threat_type} ({severity})"
            summary[key] = summary.get(key, 0) + 1

            if severity in severity_count:
                severity_count[severity] += 1


        prompt = (
            "Here is the following threat type summary with counts:\n"
            + json.dumps(summary, indent=2)
            + "\nAnd here is the severity count:\n"
            + json.dumps(severity_count, indent=2)
            + "\n\nGenerate a 2-sentence analysis describing the dominant threat types and overall risk pattern."
        )
        response = model.generate_content([prompt])
        return jsonify({
            "chart_data": summary,
            "severity": severity_count,
            "insight": response.text.strip()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/summary", methods=["GET"])
def summary():
    try:
        with open("threat_log.json", "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        logs = [json.loads(line) for line in lines][-20:]
        if not logs:
            return jsonify({"summary": "No recent threats to summarize."})
        summary_input = "\n".join(f"{l['type']} - {l['severity']}" for l in logs)
        prompt = (
            "Summarize the following recent threat incidents in 3 concise sentences for an executive report:\n"
            + summary_input
        )
        response = model.generate_content([prompt])
        return jsonify({"summary": response.text.strip()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/view-all")
def view_all_logs():
    try:
        with open("threat_log.json", "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        logs = [json.loads(line) for line in lines][::-1]

        comments = {}
        if os.path.exists("comments.json"):
            with open("comments.json", "r") as cf:
                comments = json.load(cf)

        return render_template("all_logs.html", logs=logs, comments=comments)
    except FileNotFoundError:
        return render_template("all_logs.html", logs=[], comments={})


@app.route("/api/report", methods=["POST"])
def generate_report():
    data = request.get_json()
    description = data.get("description", "").strip()
    if not description:
        return jsonify({"error": "No description provided."}), 400

    prompt = (
        "You are a cybersecurity analyst. Write a full executive-style incident report for the following threat:"
        f"{description}"
        "Include:"
        "- Threat type and summary"
        "- Severity and risk explanation"
        "- Potential impact"
        "- Recommended detection and mitigation steps"
        "- Conclusion"
    )
    try:
        response = model.generate_content([prompt])
        return jsonify({"report": response.text.strip()})
    except Exception as e:
        return jsonify({"error": f"Failed to generate report: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5033)
