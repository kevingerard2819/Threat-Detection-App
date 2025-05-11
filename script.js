
// Enhanced script.js for Threat Dashboard + Classifier Page
const API_KEY = "my-super-secret"; // Match your .env ADMIN_API_KEY

console.log("✅ script.js loaded");

function loadLog() {
  console.log("⏳ Loading recent classifications...");
  fetch("/api/log", {
    headers: { "X-API-KEY": API_KEY }
  })
    .then(res => res.json())
    .then(data => {
      const log = document.getElementById("logList");
      if (!log) return;
      log.innerHTML = "";
      const counter = document.getElementById("reviewStatus");
      if (counter) {
        counter.textContent = `✅ Reviewed: ${data.reviewed_count} | ⚠️ Unreviewed: ${data.unreviewed_count}`;
      }
      if (data.length === 0) {
        log.innerHTML = "<li>No recent classifications found.</li>";
        return;
      }
      data.logs.forEach(entry => {
        const li = document.createElement("li");
        li.innerHTML = `
          <strong>${entry.timestamp.split("T")[0]}</strong> -
          <span class="badge ${entry.severity.toLowerCase()}">${entry.type} (${entry.severity})</span><br>
          <em>${entry.description}</em><br>
          Confidence: ${entry.confidence}%<br>
          <strong>Response:</strong> ${entry.response}<hr>
        `;
        log.appendChild(li);
      });
    })
    .catch(err => console.error("❌ Failed to load logs:", err));
}

function loadStats() {
  console.log("⏳ Loading threat statistics...");
  fetch("/api/stats")
    .then(res => res.json())
    .then(data => {
      const canvas = document.getElementById("statsChart");
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      if (window.statsChart) window.statsChart.destroy();
      window.statsChart = new Chart(ctx, {
        type: "bar",
        data: {
          labels: Object.keys(data.chart_data),
          datasets: [{
            label: "Threats",
            data: Object.values(data.chart_data),
            backgroundColor: "rgba(229, 9, 20, 0.7)"
          }]
        },
        options: {
          responsive: true,
          scales: {
            y: { beginAtZero: true }
          }
        }
      });

      const insightDiv = document.getElementById("llmInsight");
      if (insightDiv && data.insight) {
        insightDiv.innerHTML = `<p><strong>Gemini Insight:</strong> ${data.insight}</p>`;
      }
    })
    .catch(err => console.error("❌ Failed to load stats:", err));
}

function loadSummary() {
  console.log("⏳ Loading summary...");
  fetch("/api/summary")
    .then(res => res.json())
    .then(data => {
      const summaryBox = document.getElementById("summaryBox");
      if (summaryBox) {
        summaryBox.textContent = data.summary || "No summary available.";
      }
    })
    .catch(err => console.error("❌ Failed to load summary:", err));
}

const classifyBtn = document.getElementById("submitBtn");
if (classifyBtn) {
  classifyBtn.addEventListener("click", () => {
    const input = document.getElementById("threatInput").value.trim();
    const resultDiv = document.getElementById("result");
    const flagThreat = document.getElementById("flagThreat")?.checked || false;
    const rawJsonBox = document.getElementById("rawJsonBox");
    const toggleRaw = document.getElementById("toggleRawJson");
    const mode = document.getElementById("modeSelect")?.value || "strict";

    if (!input) return alert("Please enter a description.");
    resultDiv.innerHTML = "Analyzing...";
    if (rawJsonBox) rawJsonBox.style.display = "none";

    fetch("/api/classify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description: input, mode: mode })
    })
      .then(res => res.json())
      .then(data => {
        if (data.error) {
          resultDiv.innerHTML = `<span class='error'>${data.error}</span>`;
          return;
        }

        if (mode === "chat") {
          resultDiv.innerHTML = `<div class="badge">Chat Response</div><p>${data.response}</p>`;
        } else {
          let responseHTML = `<div class="badge ${data.severity.toLowerCase()}">${data.severity}</div>
            <strong>Type:</strong> ${data.type}<br>
            <strong>Confidence:</strong> ${data.confidence}%<br>
            <strong>Risk:</strong> ${data.risk}<br>
            <strong>Response:</strong>`;
          if (Array.isArray(data.response)) {
            responseHTML += "<ul>" + data.response.map(step => `<li>${step}</li>`).join("") + "</ul>";
          } else {
            responseHTML += `<p>${data.response}</p>`;
          }
          if (flagThreat) {
            responseHTML += `<p><span class="badge high">⚠️ Flagged</span></p>`;
          }
          resultDiv.innerHTML = responseHTML;
        }

        if (rawJsonBox && toggleRaw?.checked) {
          rawJsonBox.style.display = "block";
          rawJsonBox.textContent = JSON.stringify(data, null, 2);
        }

        if (document.getElementById("logList")) {
          loadLog(); // only on dashboard
        }
        loadStats();
        loadSummary();
      });
  });
}

const reportBtn = document.getElementById("generateReportBtn");
if (reportBtn) {
  reportBtn.addEventListener("click", () => {
    const input = document.getElementById("threatInput").value.trim();
    if (!input) return alert("Please enter a threat description first.");

    const reportBox = document.getElementById("fullReport");
    reportBox.innerHTML = "🧠 Generating full report...";

    fetch("/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description: input })
    })
      .then(res => res.json())
      .then(data => {
        if (data.error) {
          reportBox.innerHTML = `<span class='error'>${data.error}</span>`;
        } else {
          reportBox.innerHTML = `<h3>📄 Threat Report</h3><p>${data.report.replaceAll("\n", "<br>")}</p>`;
        }
      })
      .catch(err => {
        reportBox.innerHTML = `<span class='error'>❌ Failed to generate report</span>`;
        console.error(err);
      });
  });
}

function loadThreatFeed() {
  console.log("⏳ Loading threat intelligence feed...");
  fetch("https://cve.circl.lu/api/last")
    .then(res => res.json())
    .then(data => {
      const feedList = document.getElementById("feedList");
      if (!feedList) return;
      feedList.innerHTML = "";
      data.slice(0, 10).forEach(item => {
        const li = document.createElement("li");
        const link = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${item.id}`;
        li.innerHTML = `<strong><a href="${link}" target="_blank">${item.id}</a></strong>: ${item.summary}`;
        feedList.appendChild(li);
      });
    })
    .catch(err => {
      const feedList = document.getElementById("feedList");
      if (feedList) feedList.innerHTML = "<li>❌ Failed to load threat feed</li>";
      console.error("Feed load error:", err);
    });
}

// Run all loaders on load
window.onload = () => {
  if (document.getElementById("logList")) loadLog();
  loadStats();
  loadSummary();
  loadThreatFeed();
};
