/**
 * CyberArmor EDR - Real Windows Event Log & Server Log File Tailer
 */

// ==========================================
// 1. WINDOWS EVENT LOG VIEWER
// ==========================================
let cachedEventLogs = [];

async function loadWindowsEventLogs(logName = "System") {
  const container = document.getElementById("eventLogsContainer");
  if (!container) return;
  container.innerHTML = `<div style="text-align:center; padding:40px;"><i class="fa-solid fa-spinner fa-spin" style="font-size:28px; color:var(--neon-cyan);"></i><p style="margin-top:10px; color:var(--text-secondary);">Querying Windows Event Log [${logName}]...</p></div>`;

  try {
    const res = await fetch(`${API_BASE}/api/device/event-logs?log_name=${encodeURIComponent(logName)}&max_events=40`);
    const data = await res.json();
    cachedEventLogs = data.events;

    const countEl = document.getElementById("eventLogsTotalCount");
    if (countEl) countEl.innerText = `${data.total_events} Events Extracted`;

    renderWindowsEventLogs(cachedEventLogs);
  } catch (err) {
    container.innerHTML = `<div style="color:var(--neon-crimson); padding:20px;">Failed to fetch Windows Event Logs: ${err.message}</div>`;
  }
}

function renderWindowsEventLogs(events) {
  const container = document.getElementById("eventLogsContainer");
  if (!container) return;

  if (events.length === 0) {
    container.innerHTML = `<div style="text-align:center; padding:40px; color:var(--text-muted); font-size:12px;">No events recorded in this log channel.</div>`;
    return;
  }

  let html = `<div style="display:flex; flex-direction:column; gap:8px;">`;
  events.forEach(ev => {
    const isError = ev.level === "Error" || ev.level === "Critical" || ev.risk_level === "CRITICAL";
    const isWarn = ev.level === "Warning";
    const badgeClass = isError ? "badge-Critical" : isWarn ? "badge-High" : "badge-Low";

    html += `
      <div class="threat-item" style="border-left-color: ${isError ? 'var(--neon-crimson)' : isWarn ? 'var(--neon-amber)' : 'var(--neon-blue)'};">
        <div class="threat-item-top">
          <div class="threat-title-group">
            <span class="badge-tag ${badgeClass}">${ev.level}</span>
            <strong style="color:#fff; font-size:13px;">Event ID ${ev.event_id} - ${ev.provider}</strong>
          </div>
          <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">${ev.timestamp}</span>
        </div>
        <p style="font-size:12px; color:var(--text-secondary); line-height:1.4; margin-top:4px;">${ev.summary}</p>
        <div style="font-size:10px; font-family:var(--font-mono); color:var(--text-muted); margin-top:6px;">
          Log Source: <strong>${ev.log_source}</strong> | Risk Grade: <strong style="color:${isError ? 'var(--neon-crimson)' : 'var(--neon-emerald)'};">${ev.risk_level}</strong>
        </div>
      </div>
    `;
  });

  html += `</div>`;
  container.innerHTML = html;
}

function filterEventLogs() {
  const query = document.getElementById("eventLogSearch")?.value?.toLowerCase() || "";
  const levelFilter = document.getElementById("eventLogLevelFilter")?.value || "ALL";

  const filtered = cachedEventLogs.filter(e => {
    const matchQ = e.summary.toLowerCase().includes(query) || e.event_id.toString().includes(query) || e.provider.toLowerCase().includes(query);
    const matchL = levelFilter === "ALL" ? true : e.level === levelFilter;
    return matchQ && matchL;
  });

  renderWindowsEventLogs(filtered);
}

// ==========================================
// 2. LOCAL SERVER LOG FILE TAILER
// ==========================================
async function tailLocalLogFile() {
  const pathInput = document.getElementById("localLogPathInput");
  const resultContainer = document.getElementById("localLogResultContainer");
  const path = pathInput?.value?.trim();

  if (!path) {
    showToast("Please enter a valid log file path.", "warning");
    return;
  }

  resultContainer.innerHTML = `<div style="text-align:center; padding:30px;"><i class="fa-solid fa-spinner fa-spin" style="font-size:24px; color:var(--neon-cyan);"></i><p style="margin-top:10px; font-size:12px; color:var(--text-secondary);">Reading and parsing log file...</p></div>`;

  try {
    const res = await fetch(`${API_BASE}/api/device/tail-server-log`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_path: path, max_lines: 80 })
    });
    const data = await res.json();

    if (data.status === "ERROR") {
      resultContainer.innerHTML = `<div style="color:var(--neon-crimson); padding:16px;">${data.message}</div>`;
      return;
    }

    let html = `
      <div style="background:rgba(25,36,77,0.4); border:1px solid var(--border-glass); border-radius:var(--radius-sm); padding:12px; margin-bottom:12px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <strong style="color:#fff; font-size:13px;">${data.file_path}</strong>
          <div style="font-size:11px; color:var(--text-muted);">${data.total_lines_read} lines inspected</div>
        </div>
        <span class="badge-tag ${data.threats_flagged > 0 ? 'badge-Critical' : 'badge-Low'}">
          ${data.threats_flagged} Threats Flagged
        </span>
      </div>

      <div style="max-height:350px; overflow-y:auto; background:#04060d; border:1px solid rgba(56,189,248,0.15); border-radius:var(--radius-sm); padding:12px; font-family:var(--font-mono); font-size:11px; display:flex; flex-direction:column; gap:4px;">
    `;

    data.records.forEach(rec => {
      const isCrit = rec.threat_detected;
      const isErr = rec.level === "ERROR";
      const color = isCrit ? "var(--neon-crimson)" : isErr ? "var(--neon-amber)" : "#94a3b8";

      html += `<div style="color:${color}; line-height:1.4;">${rec.line}</div>`;
    });

    html += `</div>`;
    resultContainer.innerHTML = html;
  } catch (err) {
    resultContainer.innerHTML = `<div style="color:var(--neon-crimson);">Failed to tail log: ${err.message}</div>`;
  }
}
