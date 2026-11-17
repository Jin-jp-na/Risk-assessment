let currentScanId = null;
let currentExposure = null;
let currentServices = [];
let statusIntervalId = null;

document.addEventListener("DOMContentLoaded", async () => {
  const form = document.getElementById("scan-form");
  const statusDiv = document.getElementById("scan-status");
  const startBtn = document.getElementById("start-scan-btn");
  const pathOption = document.getElementById("path-discovery");
  const profileOption = document.getElementById("profile");
  profileOption.addEventListener("change", () => {
    pathOption.disabled = profileOption.value !== "web";
    if (pathOption.disabled) pathOption.checked = false;
  });
  document.getElementById("stop-path-discovery").addEventListener("click", async () => {
    if (!currentScanId) return;
    try {
      const response = await fetch(`/webscan/${currentScanId}/stop`, {method: "POST"});
      document.getElementById("path-job-state").textContent = response.ok
        ? "Stop requested; waiting for the discovery process to exit."
        : "No optional path job is currently available to stop.";
    } catch (error) {
      document.getElementById("path-job-state").textContent = "Could not send the stop request; check the local backend.";
    }
  });
  // Discard old rendered scores/claims once after the evidence rules change.
  if (localStorage.getItem("pcvp:evidenceVersion") !== "2") {
    for (const key of ["pcvp:lastGobusterHtml", "pcvp:lastServicesHtml", "pcvp:lastStats", "pcvp:lastServices", "pcvp:lastGraph", "pcvp:lastGraphText"]) {
      localStorage.removeItem(key);
    }
    localStorage.setItem("pcvp:evidenceVersion", "2");
  }

  // Check server boot id to detect backend restarts and avoid restoring stale cached scans
  try {
    const hb = await fetch("/health");
    if (hb.ok) {
      const info = await hb.json();
      const serverBoot = info.boot_id || null;
      const savedBoot = localStorage.getItem("pcvp:bootId");
      if (!savedBoot || savedBoot !== serverBoot) {
        localStorage.removeItem("pcvp:lastScanId");
        localStorage.removeItem("pcvp:lastServicesHtml");
        localStorage.removeItem("pcvp:lastStats");
        localStorage.removeItem("pcvp:lastTarget");
        localStorage.removeItem("pcvp:lastExposure");
      }
      if (serverBoot) localStorage.setItem("pcvp:bootId", serverBoot);
    }
  } catch (e) {}

  const saved = localStorage.getItem("pcvp:lastScanId");
  if (saved) {
    try { await restoreHistoricalScan(saved); }
    catch (error) { statusDiv.textContent = "Saved results are unavailable: " + error.message; }
  }
  document.getElementById("compare-scans-btn").addEventListener("click", compareSelectedScans);
  document.getElementById("compare-pdf").addEventListener("click", () => exportComparison("pdf"));
  document.getElementById("compare-csv").addEventListener("click", () => exportComparison("csv"));
  const savedTarget = localStorage.getItem("pcvp:lastTarget");
  const savedExposure = localStorage.getItem("pcvp:lastExposure");
  if (savedTarget) document.getElementById("target").value = savedTarget;
  if (savedExposure) document.getElementById("exposure").value = savedExposure;

  const modal = document.getElementById("service-details-modal");
  const modalCloseBtn = document.getElementById("modal-close-btn");
  modalCloseBtn.addEventListener("click", () => (modal.style.display = "none"));
  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.style.display = "none";
  });

  const clearBtn = document.getElementById("clear-scans-btn");
  await loadScanHistory();
  const refreshHistoryBtn = document.getElementById("refresh-history-btn");
  if (refreshHistoryBtn) refreshHistoryBtn.addEventListener("click", loadScanHistory);
  const scanHistoryBtn = document.getElementById("scan-history-btn");
  if (scanHistoryBtn) {
    scanHistoryBtn.addEventListener("click", () => {
      showTab("tab-history");
      loadScanHistory();
    });
  }
  const historyBody = document.querySelector("#history-table tbody");
  if (historyBody) {
    historyBody.addEventListener("click", (event) => {
      const button = event.target.closest("[data-history-scan-id]");
      if (button) restoreHistoricalScan(button.dataset.historyScanId);
    });
  }
  const findingsDownload = document.getElementById("download-findings-btn");
  if (findingsDownload) {
    findingsDownload.addEventListener("click", () => {
      if (currentScanId) window.location.href = `/scan/${currentScanId}/findings.csv`;
    });
  }
  if (clearBtn) {
    clearBtn.addEventListener("click", async () => {
      if (!confirm("Clear persisted scan metadata from the server and local cache?")) return;
      try {
        const resp = await fetch("/scans/clear", { method: "POST" });
        if (!resp.ok) {
          const data = await resp.json().catch(() => ({}));
          alert(`Failed to clear persisted scans: ${data.detail || resp.status}`);
          return;
        }

        localStorage.removeItem("pcvp:lastScanId");
        localStorage.removeItem("pcvp:lastServicesHtml");
        localStorage.removeItem("pcvp:lastStats");
        localStorage.removeItem("pcvp:lastServices");
        localStorage.removeItem("pcvp:lastTarget");
        localStorage.removeItem("pcvp:lastExposure");
        localStorage.removeItem("pcvp:bootId");
        localStorage.removeItem("pcvp:lastGobusterHtml");
        localStorage.removeItem("pcvp:lastGraphText");
        currentScanId = null;
        resetOverview();
        setTableLoadingStates();
        updateHeaderScanInfo();
        document.getElementById("scan-status").textContent = "Cleared persisted scans.";
        await loadScanHistory();
      } catch (err) {
        console.error(err);
        alert("Error clearing persisted scans (see console)");
      }
    });
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    // ✅ Clear cached UI from previous scan
    localStorage.removeItem("pcvp:lastServicesHtml");
    localStorage.removeItem("pcvp:lastStats");
    localStorage.removeItem("pcvp:lastServices");
    localStorage.removeItem("pcvp:lastGobusterHtml");
    localStorage.removeItem("pcvp:lastGraphText");

    const target = document.getElementById("target").value.trim();
    const exposure = document.getElementById("exposure").value;
    const profile = document.getElementById("profile").value;
    const authorized = document.getElementById("authorized").checked;

    if (!target) {
      statusDiv.textContent = "Please enter a target.";
      return;
    }

    if (statusIntervalId !== null) {
      clearInterval(statusIntervalId);
      statusIntervalId = null;
    }

    resetOverview();
    setTableLoadingStates();

    const reportBtn = document.getElementById("download-report-btn");
    if (reportBtn) reportBtn.disabled = true;

    startBtn.disabled = true;
    statusDiv.textContent = "Starting scan...";

    try {
      const resp = await fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, exposure, profile, authorized, network_scan: profile !== "web",
          path_discovery: profile === "web" && document.getElementById("path-discovery").checked }),
      });

      if (!resp.ok) {
        const error = await resp.json().catch(() => ({}));
        statusDiv.textContent = `Error starting scan: ${error.detail || resp.status}`;
        startBtn.disabled = false;
        return;
      }

      const data = await resp.json();
      currentScanId = data.scan_id;
      currentExposure = data.exposure || exposure;
      localStorage.setItem("pcvp:lastScanId", currentScanId);
      localStorage.setItem("pcvp:lastTarget", target);
      localStorage.setItem("pcvp:lastExposure", currentExposure);
      updateHeaderScanInfo();
      statusDiv.textContent = `Scan started (ID: ${currentScanId}). Waiting for completion...`;
      pollScanStatus(currentScanId);
      await loadScanHistory();
    } catch (err) {
      console.error(err);
      statusDiv.textContent = "Error starting scan (check console/logs).";
      startBtn.disabled = false;
    }
  });
});

function resetOverview() {
  document.getElementById("stat-hosts").textContent = "0";
  document.getElementById("stat-services").textContent = "0";
  document.getElementById("stat-critical").textContent = "0 / 0";
  document.getElementById("stat-weak-creds").textContent = "0";
  const findingsSummary = document.getElementById("finding-summary");
  const findingsBody = document.querySelector("#findings-table tbody");
  if (findingsSummary) findingsSummary.textContent = "";
  if (findingsBody) findingsBody.innerHTML = `<tr><td colspan="5">Waiting for scan to complete...</td></tr>`;
  for (const id of ["web-assessment", "web-findings", "path-job-state"]) {
    const element = document.getElementById(id);
    if (element) element.textContent = "Waiting for this scan's saved web results.";
  }
  const stopButton = document.getElementById("stop-path-discovery");
  if (stopButton) stopButton.disabled = true;
}

async function loadScanHistory() {
  const body = document.querySelector("#history-table tbody");
  if (!body) return;
  try {
    const response = await fetch("/scans/history");
    if (!response.ok) throw new Error(`History request failed: ${response.status}`);
    const scans = await response.json();
    populateComparisonSelectors(scans);
    if (!scans.length) {
      body.innerHTML = `<tr><td colspan="6" class="px-3 py-2">No scans recorded yet.</td></tr>`;
      return;
    }
    body.innerHTML = scans.map((scan) => `
      <tr>
        <td class="px-3 py-2">${escapeHtml(formatHistoryDate(scan.created_at))}</td>
        <td class="px-3 py-2 font-medium">${escapeHtml(scan.target || "")}</td>
        <td class="px-3 py-2">${escapeHtml(scan.profile || "standard")}</td>
        <td class="px-3 py-2">${escapeHtml(scan.exposure_effective || scan.exposure || "auto")}</td>
        <td class="px-3 py-2">${escapeHtml(scan.status || "unknown")}</td>
        <td class="px-3 py-2"><button type="button" data-history-scan-id="${escapeHtml(scan.scan_id)}" class="btn-link">View results</button></td>
      </tr>
    `).join("");
  } catch (error) {
    console.error("[HISTORY] Failed to load scan history:", error);
    body.innerHTML = `<tr><td colspan="6" class="px-3 py-2">Unable to load scan history.</td></tr>`;
  }
}

async function loadFindings(scanId) {
  const body = document.querySelector("#findings-table tbody");
  const summary = document.getElementById("finding-summary");
  body.innerHTML = `<tr><td colspan="5">Loading findings...</td></tr>`;
  const resp = await fetch(`/scan/${scanId}/findings`);
  if (!resp.ok) {
    body.innerHTML = `<tr><td colspan="5">Findings are not available yet.</td></tr>`;
    return;
  }
  const data = await resp.json();
  summary.textContent = `Observed open services: ${(data.network_observations || []).filter(o => o.state === "open").length} · Unverified CVE candidates: ${(data.candidate_vulnerabilities || []).length} · Web recommendations: ${(data.findings || []).filter(f => f.domain === "web").length}`;
  const findings = data.findings || [];
  if (!findings.length) {
    body.innerHTML = `<tr><td colspan="5">No findings were generated.</td></tr>`;
    return;
  }
  body.innerHTML = "";
  for (const finding of findings) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="px-3 py-2"><span class="badge badge-${escapeHtml(finding.severity || "info")}">${escapeHtml(finding.severity || "info")}</span></td>
      <td class="px-3 py-2">${escapeHtml(finding.title || "")}<div>${escapeHtml(finding.domain || "")} / ${escapeHtml(finding.category || "review")}</div><div>Confidence: ${escapeHtml(finding.confidence || "unknown")} (${escapeHtml(finding.confidence_scope || "saved check")})</div></td>
      <td class="px-3 py-2">${escapeHtml(finding.asset || "")}</td>
      <td class="px-3 py-2 max-w-xl">${escapeHtml(finding.reason || "")}<pre style="white-space:pre-wrap">${escapeHtml(finding.evidence || "")}</pre>${finding.original_evidence ? `<details><summary>Original evidence</summary><pre style="white-space:pre-wrap">${escapeHtml(JSON.stringify(finding.original_evidence, null, 2))}</pre></details>` : ""}</td>
      <td class="px-3 py-2">${escapeHtml(finding.source || "")}<div>${escapeHtml(finding.rule_id || "")}</div><div>Remediation: ${escapeHtml(finding.remediation || "Review saved evidence.")}</div><div>Re-test: ${escapeHtml(finding.retest || "Explicitly repeat the authorized assessment after changes.")}</div></td>
    `;
    body.appendChild(tr);
  }
}

function formatHistoryDate(value) {
  if (!value) return "Unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

async function restoreHistoricalScan(scanId) {
  if (!scanId) return;
  if (statusIntervalId !== null) {
    clearInterval(statusIntervalId);
    statusIntervalId = null;
  }
  const response = await fetch(`/scan/${encodeURIComponent(scanId)}`);
  if (!response.ok) {
    alert("This scan is no longer available.");
    await loadScanHistory();
    return;
  }
  const scan = await response.json();
  currentScanId = scan.scan_id;
  currentExposure = scan.exposure || scan.exposure_effective || "auto";
  localStorage.setItem("pcvp:lastScanId", currentScanId);
  updateHeaderScanInfo();
  document.getElementById("scan-status").textContent = `Viewing scan ${scan.scan_id}`;
  document.getElementById("profile").value = scan.profile || "standard";
  document.getElementById("path-discovery").checked = false;
  document.getElementById("path-discovery").disabled = scan.profile !== "web";
  resetOverview();
  setTableLoadingStates();
  if (["completed", "failed", "partial", "cancelled"].includes(scan.status)) {
    await renderSavedScan(scan.scan_id);
    document.getElementById("download-report-btn").disabled = false;
  } else {
    pollScanStatus(scan.scan_id);
  }
}

function setTableLoadingStates() {
  const servicesBody = document.querySelector("#services-table tbody");
  const gobBody = document.querySelector("#gobuster-table tbody");
  const agDiv = document.getElementById("attack-graph-content");
  const agNet = document.getElementById("attack-graph-network");
  servicesBody.innerHTML = `<tr><td colspan="9">Waiting for scan to complete...</td></tr>`;
  gobBody.innerHTML = `<tr><td colspan="3">Waiting for scan to complete...</td></tr>`;
  agDiv.textContent = "Waiting for scan to complete...";
  agNet.innerHTML = "";
}

function updateHeaderScanInfo() {
  const el = document.getElementById("header-scan-info");
  if (!currentScanId) { el.innerHTML = ""; return; }
  const badgeClass =
    currentExposure === "external" ? "badge-external" :
    currentExposure === "internal" ? "badge-internal" : "badge-auto";
  el.innerHTML = `
    <div style="text-align:right;">
      <div style="font-size:0.75rem; color:#9ca3af;">Current Scan ID</div>
      <div style="font-size:0.85rem;">${currentScanId}</div>
      <div style="margin-top:4px;">
        <span class="badge ${badgeClass}">${currentExposure || "auto"}</span>
      </div>
    </div>
  `;
}

function pollScanStatus(scanId) {
  const statusDiv = document.getElementById("scan-status");
  const startBtn = document.getElementById("start-scan-btn");
  const reportBtn = document.getElementById("download-report-btn");

  const doPoll = async () => {
    try {
      const resp = await fetch(`/scan/${scanId}`);
      if (!resp.ok) {
        statusDiv.textContent = `Error checking status: ${resp.status}`;
        clearInterval(statusIntervalId);
        statusIntervalId = null;
        startBtn.disabled = false;
        if (reportBtn) reportBtn.disabled = true;
        return;
      }

      const data = await resp.json();
      currentExposure = data.exposure || currentExposure;
      const stopButton = document.getElementById("stop-path-discovery");
      if (stopButton) stopButton.disabled = !data.path_discovery || !["pending", "running"].includes(data.gobuster_status);
      updateHeaderScanInfo();

      if (data.status === "completed") {
        // ✅ Fully done — stop polling and load everything
        clearInterval(statusIntervalId);
        statusIntervalId = null;
        startBtn.disabled = false;
        if (reportBtn) reportBtn.disabled = false;

        statusDiv.textContent = `Loading results...`;

        try {
          await renderSavedScan(scanId);
          statusDiv.textContent = data.message || "Assessment completed.";
          await loadScanHistory();
        } catch (loadErr) {
          console.error("[LOADING] Error loading results:", loadErr);
          statusDiv.textContent = `Scan completed but error loading results. Check console.`;
        }

      } else if (data.status === "failed") {
        clearInterval(statusIntervalId);
        statusIntervalId = null;
        startBtn.disabled = false;
        if (reportBtn) reportBtn.disabled = true;
        statusDiv.textContent = `Scan failed: ${data.message || "unknown error"}`;
        await renderSavedScan(scanId);
        if (reportBtn) reportBtn.disabled = false;
        await loadScanHistory();

      } else if (data.status === "nmap_done") {
        // ✅ Nmap done but gobuster still running
        if (data.gobuster_status === "completed") {
          statusDiv.textContent = `Gobuster completed. Finalizing...`;
        } else {
          statusDiv.textContent = `${data.network_scan === false ? "Web assessment running" : "Nmap completed"}. HTTP/TLS: ${data.web_status || "pending"}; optional path discovery: ${data.gobuster_status}.`;
          if (data.web_status === "completed") await loadWebAssessment(scanId);
        }

      } else if (data.status === "running") {
        statusDiv.textContent = `Scan running... ${data.message || ""}`;

      } else {
        statusDiv.textContent = `Scan status: ${data.status} — ${data.message || ""}`;
      }

    } catch (err) {
      console.error("[POLL] Error in poll callback:", err);
      statusDiv.textContent = "Error checking status (see console).";
      clearInterval(statusIntervalId);
      statusIntervalId = null;
      startBtn.disabled = false;
      if (reportBtn) reportBtn.disabled = true;
    }
  };

  // Start polling
  statusIntervalId = setInterval(doPoll, 3000);
  // Also poll immediately
  doPoll();
}

async function loadScanResults(scanId) {
  const servicesBody = document.querySelector("#services-table tbody");
  servicesBody.innerHTML = `<tr><td colspan="9">Loading saved RiskLens data...</td></tr>`;
  currentServices = [];

  try {
    const url = `/scan/${scanId}/nvd`;
    const resp = await fetch(url);
    
    if (!resp.ok) {
      const errorText = await resp.text().catch(() => "Unknown error");
      console.error("[loadScanResults] Server error:", resp.status, errorText);
      servicesBody.innerHTML = `<tr><td colspan="9">Server error: ${resp.status}</td></tr>`;
      return;
    }

    const data = await resp.json();
    const hosts = data.data.hosts || [];
    
    const rows = [];
    for (const host of hosts) {
      const ip = host.ip;
      for (const svc of host.services || []) {
        rows.push({ ip, ...svc });
      }
    }

    currentServices = rows;
    rows.sort((a, b) => (b.pcvp_score || 0) - (a.pcvp_score || 0));

    const hostCount = hosts.length;
    const serviceCount = rows.length;
    let criticalCount = 0, highCount = 0, weakCount = 0;
    for (const s of rows) {
      if (s.pcvp_level === "critical") criticalCount++;
      if (s.pcvp_level === "high") highCount++;
      if (s.weak_creds && s.weak_creds.found) weakCount++;
    }

    document.getElementById("stat-hosts").textContent = hostCount;
    document.getElementById("stat-services").textContent = serviceCount;
    document.getElementById("stat-critical").textContent = `${criticalCount} / ${highCount}`;
    document.getElementById("stat-weak-creds").textContent = weakCount;

   // ✅ Save stats immediately
localStorage.setItem("pcvp:lastStats", JSON.stringify({
  hosts: hostCount, services: serviceCount,
  critical: `${criticalCount} / ${highCount}`, weak: weakCount,
}));
localStorage.setItem("pcvp:lastServices", JSON.stringify(currentServices));

if (!rows.length) {
  servicesBody.innerHTML = `<tr><td colspan="9">No services detected for this scan.</td></tr>`;
  return;
}

servicesBody.innerHTML = "";
for (const svc of rows) {
  const tr = document.createElement("tr");
  const level = svc.pcvp_level || "informational";
  const badgeClass =
    level === "critical" ? "badge-critical" :
    level === "high" ? "badge-high" :
    level === "medium" ? "badge-medium" :
    level === "low" ? "badge-low" : "badge-info";
  const weakCredsText = svc.weak_creds && svc.weak_creds.found
    ? `${svc.weak_creds.protocol || ""} ${svc.weak_creds.username}:${svc.weak_creds.password}`
    : "Not tested";
  const weakPillClass = svc.weak_creds && svc.weak_creds.found ? "pill pill-weak" : "pill";
  const nseCount = Array.isArray(svc.nse_findings) ? svc.nse_findings.length : 0;
  tr.innerHTML = `
    <td>${escapeHtml(svc.ip || "")}</td>
    <td>${svc.port}</td>
    <td>${escapeHtml(svc.service || "")} (${escapeHtml(svc.state || "unknown")})</td>
    <td>${escapeHtml((svc.product || "unknown") + " " + (svc.version || "unknown"))}</td>
    <td><span class="badge ${badgeClass}">${level}</span></td>
    <td>${svc.pcvp_score ?? ""}</td>
    <td><span class="${weakPillClass}">${weakCredsText}</span></td>
    <td>${nseCount ? `<span class="pill">${nseCount} saved output(s)</span>` : "None"}</td>
    <td><button class="btn-link" data-ip="${escapeHtml(svc.ip)}" data-port="${svc.port}" data-proto="${escapeHtml(svc.protocol)}">Details</button></td>
  `;
  servicesBody.appendChild(tr);
}
servicesBody.querySelectorAll(".btn-link").forEach((btn) =>
  btn.addEventListener("click", onDetailsClick)
);

// ✅ Save HTML AFTER rows are fully rendered
localStorage.setItem("pcvp:lastServicesHtml", servicesBody.innerHTML);
} catch (err) {
  console.error("[loadScanResults] CATCH ERROR:", err.name, err.message);
  console.error("[loadScanResults] Full error:", err);
  servicesBody.innerHTML = `<tr><td colspan="9">Error loading saved observations: ${err.message}</td></tr>`;
}
}

async function loadAliveHosts(scanId) {
  const body = document.querySelector("#alive-hosts-table tbody");
  body.innerHTML = `<tr><td colspan="6">Loading alive hosts...</td></tr>`;

  try {
    const resp = await fetch(`/scan/${scanId}/alive-hosts`);
    if (!resp.ok) {
      body.innerHTML = `<tr><td colspan="6">Alive hosts are not available yet.</td></tr>`;
      return;
    }

    const data = await resp.json();
    const hosts = data.hosts || [];
    if (!hosts.length) {
      body.innerHTML = `<tr><td colspan="6">No alive hosts detected.</td></tr>`;
      return;
    }

    body.innerHTML = "";
    for (const host of hosts) {
      const tr = document.createElement("tr");
      const os = Array.isArray(host.os) && host.os.length
        ? host.os.map(item => `${item.name || ""} (${item.accuracy || "?"}%)`).join(", ")
        : "Unknown";
      tr.innerHTML = `
        <td class="px-3 py-2">${escapeHtml(host.ip || "")}</td>
        <td class="px-3 py-2">${escapeHtml((host.hostnames || []).join(", ") || "—")}</td>
        <td class="px-3 py-2">${escapeHtml([host.mac, host.mac_vendor].filter(Boolean).join(" / ") || "—")}</td>
        <td class="px-3 py-2">${escapeHtml(os)}</td>
        <td class="px-3 py-2">${host.services ?? "—"}</td>
        <td class="px-3 py-2">${escapeHtml((host.ports || []).join(", ") || "—")}</td>
      `;
      body.appendChild(tr);
    }
  } catch (err) {
    console.error("[loadAliveHosts] Error:", err);
    body.innerHTML = `<tr><td colspan="6">Error loading alive hosts.</td></tr>`;
  }
}

async function loadWebAssessment(scanId) {
  const container = document.getElementById("web-assessment");
  if (!container) return;
  container.textContent = "Loading HTTP/TLS assessment...";
  try {
    const resp = await fetch(`/webscan/${scanId}/assessment`);
    if (!resp.ok) {
      container.textContent = "Web assessment is not available for this scan.";
      const findingsView = document.getElementById("web-findings");
      if (findingsView) findingsView.textContent = "No saved web assessment is available.";
      return;
    }
    const data = await resp.json();
    const checks = data.checks || [];
    const technologies = data.technologies || [];
    const tls = data.tls || {};
    const checkRows = checks.length
      ? checks.map(check => `<li><strong>${escapeHtml(check.name)}</strong>: ${escapeHtml(check.status)} — ${escapeHtml(check.detail)}</li>`).join("")
      : "<li>No HTTP checks returned.</li>";
    const technologyText = technologies.length
      ? technologies.map(item => `${item.name}: ${item.evidence}`).join(", ")
      : "No technology evidence recorded";
    container.innerHTML = `
      <div><strong>Final URL:</strong> ${escapeHtml(data.http?.final_url || data.url || "")}</div>
      <div><strong>HTTP status:</strong> ${escapeHtml(data.http?.status ?? "Unavailable")}</div>
      <div><strong>Technologies:</strong> ${escapeHtml(technologyText)}</div>
      <div><strong>Assessment:</strong> ${escapeHtml(data.status || "Saved assessment (legacy)")}</div>
      <div><strong>TLS:</strong> ${escapeHtml(tls.protocol || (String(data.url || "").startsWith("https:") ? "Unavailable" : "Not HTTPS"))} ${tls.cipher ? `(${escapeHtml(tls.cipher)})` : ""}; verification: ${escapeHtml(tls.verification || "Not recorded")}</div>
      ${tls.subject ? `<div><strong>Certificate:</strong> ${escapeHtml(tls.subject)}; issuer: ${escapeHtml(tls.issuer || "")}; expires: ${escapeHtml(tls.expires || "Not recorded")}</div>` : ""}
      <details><summary>Saved HTTP/TLS evidence and redirect decisions</summary><pre>${escapeHtml(JSON.stringify({http: data.http || {}, tls, redirects: data.redirects || []}, null, 2))}</pre></details>
      <div class="section-title">Configuration observations (impact requires review)</div>
      <ul>${checkRows}</ul>
      ${data.error ? `<div style="color:#fca5a5;">${escapeHtml(data.error_category || "Assessment error")}: ${escapeHtml(data.error)}</div>` : ""}
    `;
    const findingsView = document.getElementById("web-findings");
    if (findingsView) {
      const findingsResponse = await fetch(`/webscan/${scanId}/findings`);
      const rules = findingsResponse.ok ? (await findingsResponse.json()).findings || [] : [];
      findingsView.innerHTML = `<strong>Independent web configuration findings</strong>` + (rules.length
        ? rules.map(rule => `<div class="mt-3"><strong>${escapeHtml(rule.rule_id)}: ${escapeHtml(rule.title)}</strong> (${escapeHtml(rule.severity)})<pre style="white-space:pre-wrap">${escapeHtml(rule.evidence)}</pre><div>Remediation: ${escapeHtml(rule.remediation)}</div><div>Re-test: ${escapeHtml(rule.retest)}</div></div>`).join("")
        : "<div>No rule observations were generated from this saved assessment; this does not establish site security.</div>");
    }
  } catch (err) {
    console.error("[loadWebAssessment] Error:", err);
    container.textContent = "Error loading web assessment.";
  }
}

async function loadGobusterResults(scanId) {
  const gobBody = document.querySelector("#gobuster-table tbody");
  gobBody.innerHTML = `<tr><td colspan="3">Loading Gobuster results...</td></tr>`;

  try {
    const resp = await fetch(`/webscan/${scanId}/results`);
    if (!resp.ok) {
      gobBody.innerHTML = `<tr><td colspan="3">No Gobuster results yet or error: ${resp.status}</td></tr>`;
      return;
    }

    const data = await resp.json();
    const results = data.results || [];
    const jobState = document.getElementById("path-job-state");
    if (jobState) jobState.textContent = `Optional path discovery: ${data.discovery_status || "legacy saved output"}${data.partial ? " (incomplete coverage)" : ""}.`;
    const error = data.error || null;
    const errorDetail = data.error_detail || null;

    if (error && !results.length) {
      gobBody.innerHTML = `
        <tr><td colspan="3">
          <div style="color:#fbbf24;">${escapeHtml(error)}</div>
          ${errorDetail ? `<details style="margin-top:6px;"><summary>Technical details</summary><pre style="white-space:pre-wrap; margin-top:4px;">${escapeHtml(errorDetail)}</pre></details>` : ""}
        </td></tr>`;
      return;
    }

    if (!results.length) {
      gobBody.innerHTML = `
        <tr><td colspan="3">
          <div>${data.discovery_status === "skipped" ? "Path discovery was not requested." : `No paths observed (${escapeHtml(data.discovery_status || "saved output")}); this is not a security verdict.`}</div>
          ${error ? `<div style="color:#fbbf24; margin-top:4px;">${escapeHtml(error)}</div>` : ""}
          ${errorDetail ? `<details style="margin-top:6px;"><summary>Technical details</summary><pre style="white-space:pre-wrap; margin-top:4px;">${escapeHtml(errorDetail)}</pre></details>` : ""}
        </td></tr>`;
      return;
    }

    gobBody.innerHTML = "";
    if (error) {
      const notice = document.createElement("tr");
      notice.innerHTML = `<td colspan="3" style="color:#fbbf24;">${escapeHtml(error)} <details style="display:inline;"><summary style="display:inline; cursor:pointer;">details</summary><pre style="white-space:pre-wrap; margin-top:4px;">${escapeHtml(errorDetail || "")}</pre></details></td>`;
      gobBody.appendChild(notice);
    }
    for (const r of results) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(r.path)}</td>
        <td>${escapeHtml(r.status)}</td>
        <td>${escapeHtml(r.size ?? "")}</td>
      `;
      gobBody.appendChild(tr);
    }
    localStorage.setItem("pcvp:lastGobusterHtml", gobBody.innerHTML);
  } catch (err) {
    console.error(err);
    gobBody.innerHTML = `<tr><td colspan="3">Error loading Gobuster results (see console).</td></tr>`;
  }
}

async function loadAttackGraph(scanId) {
  const textContainer = document.getElementById("attack-graph-content");
  const graphContainer = document.getElementById("attack-graph-network");
  textContainer.textContent = "Loading attack graph...";
  graphContainer.innerHTML = "";

  try {
    const resp = await fetch(`/scan/${scanId}/attack-graph`);
    if (!resp.ok) {
      const errorText = await resp.text().catch(() => "Unknown error");
      console.error("[loadAttackGraph] Error response:", errorText);
      textContainer.textContent = `Error loading attack graph: ${resp.status}`;
      return;
    }

    const data = await resp.json();
    const graph = data.graph || {};
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];

    if (!nodes.length || !edges.length) {
      textContainer.textContent = "No attack paths identified for this scan.";
      return;
    }

    const nodeById = {};
    nodes.forEach((n) => (nodeById[n.id] = n));

    graphContainer.innerHTML = renderLocalGraph(graph);
    const hostServices = {};
    edges.forEach((e) => {
      if (e.relation === "runs") {
        if (!hostServices[e.from]) hostServices[e.from] = [];
        hostServices[e.from].push(e.to);
      }
    });

    const chains = [];
    for (const [hostId, serviceIds] of Object.entries(hostServices)) {
      const hostNode = nodeById[hostId];
      const hostIp = hostNode && hostNode.ip ? hostNode.ip : hostId;
      for (const sid of serviceIds) {
        const svc = nodeById[sid];
        if (!svc) continue;
        const level = (svc.pcvp_level || "").toLowerCase();
        const score = svc.pcvp_score || 0;
        if (!(level === "critical" || level === "high")) continue;
        const cveEdges = edges.filter((e) => e.from === sid && (e.relation === "candidate_cve" || e.relation === "has_vulnerability"));
        const cveIds = cveEdges.map((e) => nodeById[e.to]).filter(Boolean).map((c) => c.cve_id || c.id || c.name).filter(Boolean);
        const chainEdges = edges.filter((e) => e.from === sid && e.relation === "possible_chain");
        const nextServices = chainEdges.map((e) => nodeById[e.to]).filter(Boolean).map((ns) => `${ns.service || "service"} on ${ns.ip || hostIp}:${ns.port}`);
        chains.push({ hostIp, service: svc.service || "service", port: svc.port, level, score, cves: cveIds, nextServices });
      }
    }
if (!chains.length) {
  textContainer.textContent = "No high-priority services. This view does not establish exploitability or attack paths.";
} else {
  let html = "<ul>";
  for (const ch of chains) {
    html += "<li style='margin-bottom:6px;'>";
    html += `<strong>${ch.service}</strong> on <strong>${ch.hostIp}:${ch.port}</strong> `;
    html += `(Review priority: ${ch.level.toUpperCase()} score ${ch.score})`;
    if (ch.cves.length) { html += "<br><span style='color:#9ca3af;'>Unverified CVE candidates:</span> " + ch.cves.map((id) => `<code>${id}</code>`).join(", "); }
    if (ch.nextServices.length) { html += "<br><span style='color:#9ca3af;'>Unverified association with:</span> " + ch.nextServices.join(", "); }
    html += "</li>";
  }
  html += "</ul>";
  textContainer.innerHTML = html;
}

// ✅ Always save cache regardless of chains length
localStorage.setItem("pcvp:lastGraph", JSON.stringify(graph));
localStorage.setItem("pcvp:lastGraphText", textContainer.innerHTML || textContainer.textContent);
  } catch (err) {
    console.error(err);
    textContainer.textContent = "Error building attack graph (see console).";
  }
}

function onDetailsClick(e) {
  const ip = e.target.getAttribute("data-ip");
  const port = parseInt(e.target.getAttribute("data-port"), 10);
  const proto = e.target.getAttribute("data-proto") || "tcp";
  const svc = currentServices.find((s) => s.ip === ip && s.port === port && (s.protocol || "tcp") === proto);
  if (!svc) return;

  const modal = document.getElementById("service-details-modal");
  const title = document.getElementById("modal-title");
  const body = document.getElementById("modal-body");
  title.textContent = `${svc.service || ""} on ${svc.ip}:${svc.port}/${svc.protocol}`;

  const reasons = svc.pcvp_reasons || [];
  const nvd = svc.nvd || {};
  const cves = nvd.cves || nvd.CVEs || [];

  let html = "";
  html += `<div><strong>Observed product/version:</strong> ${escapeHtml(svc.product || "unknown")} ${escapeHtml(svc.version || "unknown")}</div>`;
  html += `<div>Identity confidence: ${escapeHtml(svc.identity_confidence || "unknown")}. ${escapeHtml(svc.identity_reason || "Scanner observations require verification.")}</div>`;
  html += `<div><strong>Exposure:</strong> ${escapeHtml(currentExposure || "auto")}</div>`;
  html += `<div><strong>Exposure review priority:</strong> ${escapeHtml(svc.pcvp_level || "")} (score ${svc.pcvp_score ?? ""}/25). Vulnerability severity: informational.</div>`;
  if (svc.weak_creds && svc.weak_creds.found) {
    html += `<div style="margin-top:4px;"><strong>Weak Credentials:</strong> ${escapeHtml(`${svc.weak_creds.protocol || ""} ${svc.weak_creds.username}:${svc.weak_creds.password}`)}</div>`;
  }
  html += `<div class="section-title">Why this is prioritized</div>`;
  if (reasons.length) { html += "<ul>"; for (const r of reasons) html += `<li>${escapeHtml(r)}</li>`; html += "</ul>"; }
  else { html += "<div>No reasons available.</div>"; }
  html += `<div class="section-title">Unverified CVE candidates — applicability not established</div>`;
  if (cves.length) {
    html += "<ul>";
    for (const c of cves) {
      const id = c.cve_id || c.id || "Unknown";
      const sev = c.reported_severity || "Unknown";
      const score = c.reported_cvss ?? "unknown";
      html += `<li>${escapeHtml(id)} — unverified keyword candidate. Advisory severity: ${escapeHtml(sev)}; advisory CVSS: ${escapeHtml(score)} (not an asset rating). ${escapeHtml(c.applicability?.reason || "Product/version applicability requires verification.")}</li>`;
    }
    html += "</ul>";
  } else { html += "<div>NVD was not queried. An empty list does not confirm the absence of vulnerabilities.</div>"; }
  const nseFindings = Array.isArray(svc.nse_findings) ? svc.nse_findings : [];
  html += `<div class="section-title">Saved NSE output — interpretation unreviewed</div>`;
  if (nseFindings.length) {
    html += "<ul>";
    for (const finding of nseFindings) {
      html += `<li><strong>${escapeHtml(finding.id || "NSE script")}</strong><pre style="white-space:pre-wrap; margin-top:4px;">${escapeHtml(finding.output || "")}</pre></li>`;
    }
    html += "</ul>";
  } else {
    html += "<div>No saved NSE output for this service.</div>";
  }
  html += `<div class="section-title">Review guidance</div>`;
  html += `<details><summary>Original network evidence</summary><pre style="white-space:pre-wrap">${escapeHtml(JSON.stringify(svc.evidence || {}, null, 2))}</pre></details>`;
  html += `<div>${escapeHtml(svc.remediation || "Confirm this service is required and restrict access to authorized clients.")}</div>`;
  html += `<div style="margin-top:6px; color:#9ca3af;">Credential testing was not performed. This guidance does not establish a vulnerability.</div>`;
  body.innerHTML = html;
  modal.style.display = "flex";
}

function escapeHtml(str) {
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function downloadReport() {
  if (!currentScanId) { alert("Run a scan first, then download the report."); return; }
  window.location.href = `/scan/${currentScanId}/report.pdf`;
}


function renderLocalGraph(graph) {
  const nodes = Object.fromEntries((graph.nodes || []).map(node => [node.id, node]));
  const label = id => {const node = nodes[id] || {}; return node.ip || node.cve_id || `${node.service || id}${node.port ? ":" + node.port : ""}`;};
  const positions = {}, rows = [0, 0, 0];
  for (const node of graph.nodes || []) {
    const column = node.type === "host" ? 0 : node.type === "service" ? 1 : 2;
    positions[node.id] = {x: 125 + column * 310, y: 40 + rows[column]++ * 65};
  }
  const height = Math.max(240, Math.max(...rows) * 65 + 30);
  const lines = (graph.edges || []).filter(edge => positions[edge.from] && positions[edge.to]).map(edge => {
    const from = positions[edge.from], to = positions[edge.to];
    return `<line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" stroke="#64748b" />`;
  }).join("");
  const shapes = Object.entries(positions).map(([id, point]) => `<g><rect x="${point.x - 115}" y="${point.y - 20}" width="230" height="40" rx="6" fill="#172533" stroke="#f59e0b"/><text x="${point.x}" y="${point.y + 4}" text-anchor="middle" fill="#edf2f7" font-size="12">${escapeHtml(label(id))}</text></g>`).join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Saved network observations and unverified associations" width="900" height="${height}">${lines}${shapes}</svg>` + '<strong>Saved evidence associations (not proven attack paths)</strong><ul>' + (graph.edges || []).map(edge => {
    return `<li>${escapeHtml(label(edge.from))} &rarr; ${escapeHtml(edge.relation === "runs" ? "runs" : "unverified association")} &rarr; ${escapeHtml(label(edge.to))}</li>`;
  }).join("") + '</ul>';
}

async function renderSavedScan(scanId) {
  const response = await fetch(`/scans/${encodeURIComponent(scanId)}/snapshot`);
  if (!response.ok) throw new Error((await response.json()).detail || "Cannot load snapshot");
  const snapshot = await response.json();
  await loadFindings(scanId);
  const components = snapshot.components;
  if (components.network.status !== "not_run" && components.network.hosts.length) {
    await loadScanResults(scanId);
    if (components.network.status === "completed") await Promise.all([loadAliveHosts(scanId), loadAttackGraph(scanId)]);
    else {
      document.querySelector("#alive-hosts-table tbody").innerHTML = `<tr><td colspan="6">Partial network coverage: ${escapeHtml(components.network.hosts.map(host => host.ip).join(", "))}</td></tr>`;
      document.getElementById("attack-graph-content").textContent = "Network coverage is incomplete; review the saved observations.";
      document.getElementById("attack-graph-network").innerHTML = "";
    }
  } else {
    document.querySelector("#services-table tbody").innerHTML = `<tr><td colspan="9">Network component: ${escapeHtml(components.network.status)}. No saved port observations.</td></tr>`;
    document.querySelector("#alive-hosts-table tbody").innerHTML = '<tr><td colspan="6">No saved host observations.</td></tr>';
    document.getElementById("attack-graph-content").textContent = "No saved network graph for this assessment.";
    document.getElementById("attack-graph-network").innerHTML = "";
  }
  if (components.http.status !== "not_run") await loadWebAssessment(scanId);
  else {
    document.getElementById("web-assessment").textContent = "HTTP/TLS was not run for this scan.";
    document.getElementById("web-findings").textContent = "No web component was assessed.";
  }
  await loadGobusterResults(scanId);
}

function populateComparisonSelectors(scans) {
  const options = scans.map(scan => `<option value="${escapeHtml(scan.scan_id)}">${escapeHtml(scan.created_at || "Unknown time")} | ${escapeHtml(scan.target)} | ${escapeHtml(scan.profile)} | ${escapeHtml(scan.status)}</option>`).join("");
  for (const id of ["compare-old", "compare-new"]) {
    const element = document.getElementById(id);
    if (!element) continue;
    const selected = element.value;
    element.innerHTML = '<option value="">Select saved scan</option>' + options;
    if (scans.some(scan => scan.scan_id === selected)) element.value = selected;
  }
  const old = document.getElementById("compare-old"), current = document.getElementById("compare-new");
  if (current && !current.value && scans.length) current.value = scans[0].scan_id;
  if (old && !old.value && scans.length > 1) old.value = scans[1].scan_id;
}

async function compareSelectedScans() {
  const output = document.getElementById("comparison-results");
  const oldId = document.getElementById("compare-old").value;
  const newId = document.getElementById("compare-new").value;
  if (!oldId || !newId) {output.textContent = "Select baseline and current scans."; return;}
  output.textContent = "Comparing saved evidence...";
  try {
    const response = await fetch(`/scans/${encodeURIComponent(newId)}/compare/${encodeURIComponent(oldId)}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Comparison failed");
    output.innerHTML = renderComparison(data);
  } catch (error) {output.textContent = "Comparison unavailable: " + error.message;}
}

function renderComparison(data) {
  let html = '<p>Observation changes only. Missing or incomplete coverage never confirms a fix.</p>';
  for (const category of ["added", "removed", "changed", "uncertain"]) {
    const entries = data[category] || [];
    html += `<h3>${escapeHtml(category)} (${entries.length})</h3>`;
    html += entries.length ? '<table><thead><tr><th>Component / observation</th><th>Before</th><th>After</th><th>Evidence limits</th></tr></thead><tbody>' + entries.map(entry => `<tr><td>${escapeHtml(entry.component)} / ${escapeHtml(entry.kind)}<br>${escapeHtml(entry.key)}</td><td><pre>${escapeHtml(JSON.stringify(entry.before, null, 2))}</pre></td><td><pre>${escapeHtml(JSON.stringify(entry.after, null, 2))}</pre></td><td>${escapeHtml(entry.reason)}</td></tr>`).join("") + '</tbody></table>' : '<p>No entries in this category.</p>';
  }
  if (!["added", "removed", "changed"].some(key => (data[key] || []).length)) html += '<p>No comparable exposure changes observed. Review uncertain coverage above.</p>';
  return html;
}

function exportComparison(format) {
  const oldId = document.getElementById("compare-old").value;
  const newId = document.getElementById("compare-new").value;
  if (!oldId || !newId) return;
  window.location.href = `/scan/${encodeURIComponent(newId)}/${format === "pdf" ? "report.pdf" : "findings.csv"}?baseline=${encodeURIComponent(oldId)}`;
}
