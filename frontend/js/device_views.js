/**
 * CyberArmor EDR - Device Security, Process Sentinel & Network Monitor Handlers
 */

const API_BASE = window.location.origin;

// ==========================================
// 1. DEVICE OVERVIEW & SYSTEM HEALTH
// ==========================================
async function loadDeviceOverview() {
  try {
    const res = await fetch(`${API_BASE}/api/device/overview`);
    const data = await res.json();
    renderDeviceOverview(data);
  } catch (err) {
    console.error("Failed to load device overview:", err);
  }
}

function renderDeviceOverview(data) {
  const sys = data.system;
  
  // Update Top Host Info Banner
  const hostEl = document.getElementById("deviceHostName");
  if (hostEl) hostEl.innerText = sys.hostname;
  
  const osEl = document.getElementById("deviceOsInfo");
  if (osEl) osEl.innerText = sys.os;
  
  const ipEl = document.getElementById("deviceIpAddress");
  if (ipEl) ipEl.innerText = sys.ip_address;

  // Update Top Score & Grade
  const scoreVal = document.getElementById("deviceHealthScoreVal");
  if (scoreVal) scoreVal.innerText = `${data.device_health_score}/100`;

  const gradeBadge = document.getElementById("deviceSecurityGradeBadge");
  if (gradeBadge) {
    gradeBadge.innerText = data.security_grade;
    gradeBadge.className = `badge-tag ${data.device_health_score >= 80 ? 'badge-Low' : data.device_health_score >= 60 ? 'badge-Medium' : 'badge-Critical'}`;
  }

  // Update Resource Bars
  updateResourceBar("cpuBarFill", "cpuPercentVal", sys.cpu_percent, `${sys.cpu_percent}% (${sys.cpu_count} Cores)`);
  updateResourceBar("ramBarFill", "ramPercentVal", sys.ram_percent, `${sys.ram_used_gb} GB / ${sys.ram_total_gb} GB (${sys.ram_percent}%)`);
  updateResourceBar("diskBarFill", "diskPercentVal", sys.disk_percent, `${sys.disk_used_gb} GB / ${sys.disk_total_gb} GB (${sys.disk_percent}%)`);

  // Update Metric Counters
  const connCount = document.getElementById("kpiActiveSockets");
  if (connCount) connCount.innerText = data.active_connections_count;

  const fwCount = document.getElementById("kpiFirewallRules");
  if (fwCount) fwCount.innerText = data.firewall_active_rules;

  const qCount = document.getElementById("kpiQuarantinedFiles");
  if (qCount) qCount.innerText = data.quarantined_files_count;
}

function updateResourceBar(fillId, valId, percent, text) {
  const fill = document.getElementById(fillId);
  const label = document.getElementById(valId);
  if (fill) {
    fill.style.width = `${Math.min(100, Math.max(0, percent))}%`;
    if (percent > 85) fill.style.background = "linear-gradient(90deg, var(--neon-amber), var(--neon-crimson))";
    else fill.style.background = "linear-gradient(90deg, var(--neon-cyan), var(--neon-purple))";
  }
  if (label) label.innerText = text;
}

// ==========================================
// 2. LIVE PROCESS SENTINEL (PROCESS MANAGER)
// ==========================================
let cachedProcesses = [];

async function loadDeviceProcesses() {
  const tableBody = document.getElementById("processTableBody");
  if (!tableBody) return;
  tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin"></i> Scanning real host processes...</td></tr>`;

  try {
    const res = await fetch(`${API_BASE}/api/device/processes?limit=120`);
    const data = await res.json();
    cachedProcesses = data.processes;

    const countEl = document.getElementById("processTotalCount");
    if (countEl) countEl.innerText = `${data.total_processes} Active`;

    const highRiskEl = document.getElementById("processHighRiskCount");
    if (highRiskEl) highRiskEl.innerText = `${data.high_risk_count} Flagged`;

    renderProcessTable(cachedProcesses);
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="7" style="color:var(--neon-crimson); text-align:center;">Failed loading processes: ${err.message}</td></tr>`;
  }
}

function renderProcessTable(processes) {
  const tableBody = document.getElementById("processTableBody");
  if (!tableBody) return;

  if (processes.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">No processes matching filter.</td></tr>`;
    return;
  }

  let html = "";
  processes.forEach(proc => {
    const isHighRisk = proc.risk_level === "CRITICAL" || proc.risk_level === "HIGH";
    const badgeClass = proc.risk_level === "CRITICAL" ? "badge-Critical" : proc.risk_level === "HIGH" ? "badge-High" : proc.risk_level === "MEDIUM" ? "badge-Medium" : "badge-Low";

    html += `
      <tr style="${isHighRisk ? 'background: rgba(255, 0, 85, 0.08);' : ''}">
        <td style="font-family:var(--font-mono); font-weight:700; color:var(--neon-cyan);">${proc.pid}</td>
        <td>
          <div style="font-weight:700; color:#fff;">${proc.name}</div>
          <div style="font-size:10px; color:var(--text-muted); font-family:var(--font-mono);">${proc.exe || 'SYSTEM PROCESS'}</div>
        </td>
        <td>
          <span class="badge-tag ${badgeClass}">${proc.risk_level}</span>
        </td>
        <td style="font-family:var(--font-mono); font-size:12px;">${proc.cpu_percent}%</td>
        <td style="font-family:var(--font-mono); font-size:12px;">${proc.memory_percent}%</td>
        <td style="font-size:11px; color:var(--text-secondary); max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${proc.risk_reasons.join(', ')}">
          ${proc.risk_reasons[0]}
        </td>
        <td>
          <button class="action-btn-sm" onclick="killProcessByPid(${proc.pid}, '${proc.name}')" style="padding:4px 10px;">
            <i class="fa-solid fa-skull"></i> Kill PID
          </button>
        </td>
      </tr>
    `;
  });

  tableBody.innerHTML = html;
}

function filterProcesses() {
  const query = document.getElementById("processSearchInput")?.value?.toLowerCase() || "";
  const filterSev = document.getElementById("processRiskFilter")?.value || "ALL";

  const filtered = cachedProcesses.filter(p => {
    const matchQuery = p.name.toLowerCase().includes(query) || p.pid.toString().includes(query) || (p.exe && p.exe.toLowerCase().includes(query));
    const matchSev = filterSev === "ALL" ? true : p.risk_level === filterSev;
    return matchQuery && matchSev;
  });

  renderProcessTable(filtered);
}

async function killProcessByPid(pid, name) {
  if (!confirm(`Are you sure you want to terminate process '${name}' (PID: ${pid})?`)) return;

  try {
    const res = await fetch(`${API_BASE}/api/device/kill-process`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pid: pid, reason: `Manual termination of ${name}` })
    });
    const result = await res.json();
    if (result.status === "SUCCESS") {
      showToast(`⚡ Process '${name}' (PID ${pid}) successfully terminated.`, "success");
      loadDeviceProcesses();
      loadDeviceOverview();
    } else {
      showToast(`Failed: ${result.message}`, "danger");
    }
  } catch (err) {
    showToast(`Error killing process: ${err.message}`, "danger");
  }
}

// ==========================================
// 3. REAL NETWORK SOCKETS & PORT ARMOR
// ==========================================
let cachedConnections = [];

async function loadDeviceConnections() {
  const tableBody = document.getElementById("connectionsTableBody");
  if (!tableBody) return;
  tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin"></i> Inspecting live network sockets...</td></tr>`;

  try {
    const res = await fetch(`${API_BASE}/api/device/connections?limit=100`);
    const data = await res.json();
    cachedConnections = data.connections;

    const estEl = document.getElementById("connEstCount");
    if (estEl) estEl.innerText = `${data.established_count} Established`;

    const listEl = document.getElementById("connListenCount");
    if (listEl) listEl.innerText = `${data.listening_count} Listening`;

    renderConnectionsTable(cachedConnections);
    renderListeningPorts(data.listening_ports);
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="7" style="color:var(--neon-crimson); text-align:center;">Failed loading sockets: ${err.message}</td></tr>`;
  }
}

function renderConnectionsTable(connections) {
  const tableBody = document.getElementById("connectionsTableBody");
  if (!tableBody) return;

  if (connections.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">No active network connections matching criteria.</td></tr>`;
    return;
  }

  let html = "";
  connections.forEach(conn => {
    const isThreat = conn.risk_level === "CRITICAL" || conn.risk_level === "HIGH";
    const badgeClass = conn.risk_level === "CRITICAL" ? "badge-Critical" : conn.risk_level === "HIGH" ? "badge-High" : conn.risk_level === "MEDIUM" ? "badge-Medium" : "badge-Low";

    html += `
      <tr style="${isThreat ? 'background: rgba(255, 0, 85, 0.08);' : ''}">
        <td><span class="badge-tag" style="background:rgba(56,189,248,0.15); color:var(--neon-blue);">${conn.proto}</span></td>
        <td style="font-family:var(--font-mono); font-size:12px; color:#cbd5e1;">${conn.local_address}</td>
        <td style="font-family:var(--font-mono); font-size:12px; color:var(--neon-cyan); font-weight:700;">${conn.remote_address}</td>
        <td><span style="font-size:11px; font-weight:700; color:${conn.status === 'ESTABLISHED' ? 'var(--neon-emerald)' : conn.status === 'LISTEN' ? 'var(--neon-blue)' : 'var(--text-muted)'};">${conn.status}</span></td>
        <td style="font-size:12px;">
          <span style="color:#fff; font-weight:600;">${conn.process_name}</span>
          <span style="color:var(--text-muted); font-size:10px; font-family:var(--font-mono);"> (PID ${conn.pid})</span>
        </td>
        <td><span class="badge-tag ${badgeClass}">${conn.risk_level}</span></td>
        <td>
          ${conn.remote_ip && conn.remote_ip !== '0.0.0.0' && !conn.remote_ip.startsWith('127.') ? `
            <button class="action-btn-sm" onclick="blockIpAtFirewall('${conn.remote_ip}')" style="padding:4px 10px;">
              🛡️ Block IP
            </button>
          ` : '<span style="color:var(--text-muted); font-size:11px;">Local</span>'}
        </td>
      </tr>
    `;
  });

  tableBody.innerHTML = html;
}

function renderListeningPorts(ports) {
  const container = document.getElementById("listeningPortsList");
  if (!container) return;

  if (!ports || ports.length === 0) {
    container.innerHTML = `<div style="color:var(--text-muted); font-size:12px;">No active listening ports discovered.</div>`;
    return;
  }

  let html = "";
  ports.slice(0, 16).forEach(p => {
    const isRisky = p.risk === "HIGH";
    html += `
      <div style="background:rgba(13,19,43,0.6); border:1px solid ${isRisky ? 'var(--neon-crimson)' : 'var(--border-glass)'}; border-radius:var(--radius-sm); padding:10px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <strong style="color:${isRisky ? 'var(--neon-crimson)' : 'var(--neon-cyan)'}; font-family:var(--font-mono); font-size:13px;">Port ${p.port} (${p.proto})</strong>
          <div style="font-size:11px; color:var(--text-secondary); margin-top:2px;">${p.process_name} (PID ${p.pid})</div>
        </div>
        <span class="badge-tag ${isRisky ? 'badge-Critical' : 'badge-Low'}">${p.risk}</span>
      </div>
    `;
  });

  container.innerHTML = html;
}

async function blockIpAtFirewall(ip) {
  if (!confirm(`Enforce Windows Defender Firewall block for remote IP ${ip}?`)) return;

  try {
    const res = await fetch(`${API_BASE}/api/device/block-ip`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip: ip, reason: "Manual ban from Network Socket Sentinel" })
    });
    const data = await res.json();
    showToast(`🛡️ IP ${ip} successfully blocked in Windows Defender Firewall.`, "danger");
    loadDeviceConnections();
    loadDeviceOverview();
  } catch (err) {
    showToast(`Failed to block IP: ${err.message}`, "danger");
  }
}

// ==========================================
// 4. SYSTEM HARDENING & VULNERABILITY AUDIT
// ==========================================
async function runSystemAudit() {
  const container = document.getElementById("auditResultsContainer");
  if (!container) return;
  container.innerHTML = `<div style="text-align:center; padding:40px;"><i class="fa-solid fa-spinner fa-spin" style="font-size:32px; color:var(--neon-cyan);"></i><p style="margin-top:12px; color:var(--text-secondary);">Auditing Windows Defender, Registry Persistence, Ports & File Hygiene...</p></div>`;

  try {
    const res = await fetch(`${API_BASE}/api/device/audit`);
    const audit = await res.json();

    let html = `
      <div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:14px; margin-bottom:20px;">
        <div class="glass-card" style="padding:16px; text-align:center;">
          <div style="font-size:11px; color:var(--text-secondary);">DEVICE HEALTH SCORE</div>
          <div style="font-size:26px; font-weight:800; color:${audit.device_health_score >= 80 ? 'var(--neon-emerald)' : 'var(--neon-amber)'}; font-family:var(--font-mono); margin-top:4px;">
            ${audit.device_health_score}/100
          </div>
        </div>
        <div class="glass-card" style="padding:16px; text-align:center;">
          <div style="font-size:11px; color:var(--text-secondary);">SECURITY GRADE</div>
          <div style="font-size:26px; font-weight:800; color:var(--neon-cyan); font-family:var(--font-mono); margin-top:4px;">
            ${audit.security_grade}
          </div>
        </div>
        <div class="glass-card" style="padding:16px; text-align:center;">
          <div style="font-size:11px; color:var(--text-secondary);">PASSED CHECKS</div>
          <div style="font-size:26px; font-weight:800; color:var(--neon-emerald); font-family:var(--font-mono); margin-top:4px;">
            ${audit.passed_checks} / ${audit.total_checks}
          </div>
        </div>
        <div class="glass-card" style="padding:16px; text-align:center;">
          <div style="font-size:11px; color:var(--text-secondary);">WARNINGS / FAILS</div>
          <div style="font-size:26px; font-weight:800; color:${audit.warning_checks + audit.failed_checks > 0 ? 'var(--neon-crimson)' : 'var(--neon-emerald)'}; font-family:var(--font-mono); margin-top:4px;">
            ${audit.warning_checks + audit.failed_checks}
          </div>
        </div>
      </div>

      <div style="display:flex; flex-direction:column; gap:12px; margin-bottom:24px;">
    `;

    audit.audit_items.forEach(item => {
      const isPass = item.status === "PASS";
      const statusColor = isPass ? "var(--neon-emerald)" : item.status === "WARN" ? "var(--neon-amber)" : "var(--neon-crimson)";

      html += `
        <div style="background:rgba(13,19,43,0.7); border:1px solid ${statusColor}; border-radius:var(--radius-sm); padding:16px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <div style="display:flex; align-items:center; gap:10px;">
              <i class="fa-solid ${isPass ? 'fa-circle-check' : 'fa-triangle-exclamation'}" style="color:${statusColor}; font-size:16px;"></i>
              <strong style="color:#fff; font-size:14px;">${item.title}</strong>
            </div>
            <span class="badge-tag ${isPass ? 'badge-Low' : item.status === 'WARN' ? 'badge-High' : 'badge-Critical'}">${item.status}</span>
          </div>
          <p style="font-size:12px; color:var(--text-secondary); line-height:1.4;">${item.description}</p>
          ${item.remediation ? `
            <div style="margin-top:10px; font-size:11px; color:var(--neon-cyan); background:rgba(0,242,254,0.06); padding:8px 12px; border-radius:4px;">
              <strong>Recommended Action:</strong> ${item.remediation}
            </div>
          ` : ''}
        </div>
      `;
    });

    html += `</div>`;
    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<div style="color:var(--neon-crimson);">Audit execution failed: ${err.message}</div>`;
  }
}

// ==========================================
// 5. ACTIVE FIREWALL & QUARANTINE MANAGER
// ==========================================
async function loadFirewallAndQuarantine() {
  const fwTable = document.getElementById("fwRulesTableBody");
  const qTable = document.getElementById("quarantineTableBody");

  try {
    const res = await fetch(`${API_BASE}/api/device/firewall-rules`);
    const data = await res.json();

    // Render Firewall Rules
    if (fwTable) {
      if (data.blocked_ips.length === 0) {
        fwTable.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:25px; color:var(--text-muted);">No active firewall quarantine rules.</td></tr>`;
      } else {
        let fwHtml = "";
        data.blocked_ips.forEach(entry => {
          fwHtml += `
            <tr>
              <td style="font-family:var(--font-mono); font-weight:700; color:var(--neon-cyan);">${entry.ip}</td>
              <td><span class="badge-tag badge-Critical">${entry.threat_type}</span></td>
              <td style="font-size:12px; color:var(--text-secondary);">${entry.reason}</td>
              <td style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">${new Date(entry.blocked_at).toLocaleTimeString()}</td>
              <td>
                <button class="action-btn-sm" onclick="unblockHostIp('${entry.ip}')">Unblock</button>
              </td>
            </tr>
          `;
        });
        fwTable.innerHTML = fwHtml;
      }
    }

    // Render Quarantined Files
    if (qTable) {
      if (data.quarantined_files.length === 0) {
        qTable.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:25px; color:var(--text-muted);">Quarantine isolation vault is empty.</td></tr>`;
      } else {
        let qHtml = "";
        data.quarantined_files.forEach(item => {
          qHtml += `
            <tr>
              <td style="font-weight:700; color:#fff;">${item.filename}</td>
              <td style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">${item.original_path}</td>
              <td style="font-size:12px; color:var(--text-secondary);">${item.reason}</td>
              <td><span class="badge-tag badge-Critical">ISOLATED</span></td>
            </tr>
          `;
        });
        qTable.innerHTML = qHtml;
      }
    }
  } catch (err) {
    console.error("Error loading firewall/quarantine:", err);
  }
}

async function unblockHostIp(ip) {
  try {
    await fetch(`${API_BASE}/api/device/unblock-ip`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip: ip })
    });
    showToast(`IP ${ip} removed from Windows Defender Firewall rules.`, "success");
    loadFirewallAndQuarantine();
    loadDeviceOverview();
  } catch (err) {
    showToast(`Failed unblocking IP: ${err.message}`, "danger");
  }
}
