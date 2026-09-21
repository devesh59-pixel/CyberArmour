/**
 * CyberGuard AI - Simulator, Inspector, Defense & Reporting Controller
 */

const API_BASE = window.location.origin;

// 1. Trigger Attack Simulation Storm
async function triggerSimulation(attackType) {
  try {
    const btn = event?.currentTarget;
    if (btn) {
      btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Launching Storm...`;
      btn.disabled = true;
    }

    const response = await fetch(`${API_BASE}/api/simulate-attack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_type: attackType })
    });

    const data = await response.json();
    
    // Play alert sound if available
    if (window.CyberApp && window.CyberApp.soundEnabled) {
      window.CyberApp.playAlertSound('critical');
    }

    // Switch to Live SOC tab so user immediately sees the visual impact
    switchTab('soc-tab');

    // Notify user
    showToast(`⚡ Simulation Active: ${attackType.toUpperCase()} storm triggered (${data.events_generated} events).`, 'danger');

    setTimeout(() => {
      if (btn) {
        btn.innerHTML = btn.getAttribute('data-original-text') || `<i class="fa-solid fa-bolt"></i> Launch Attack Storm`;
        btn.disabled = false;
      }
    }, 2000);
  } catch (err) {
    console.error('Error launching simulation:', err);
    showToast('Failed to trigger simulation: ' + err.message, 'danger');
  }
}

// 2. Test Raw Custom Payload in Sandbox
async function analyzeRawPayload() {
  const payloadInput = document.getElementById('rawPayloadInput');
  const methodSelect = document.getElementById('payloadMethod');
  const srcIpInput = document.getElementById('payloadSrcIp');
  const resultContainer = document.getElementById('payloadResultBox');

  const payload = payloadInput?.value?.trim();
  if (!payload) {
    showToast('Please enter a payload or query string to inspect.', 'warning');
    return;
  }

  resultContainer.innerHTML = `<div style="text-align:center; padding: 20px;"><i class="fa-solid fa-spinner fa-spin" style="font-size:24px; color:var(--neon-cyan);"></i><p style="margin-top:10px; font-size:12px; color:var(--text-secondary);">Analyzing with Multi-Model AI Engine...</p></div>`;

  try {
    const res = await fetch(`${API_BASE}/api/analyze-payload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        payload: payload,
        method: methodSelect?.value || 'GET',
        src_ip: srcIpInput?.value || '198.51.100.42'
      })
    });

    const analysis = await res.json();
    renderPayloadInspectionResult(analysis, resultContainer);
  } catch (err) {
    resultContainer.innerHTML = `<div style="color:var(--neon-crimson); font-size:13px;">Error analyzing payload: ${err.message}</div>`;
  }
}

function renderPayloadInspectionResult(analysis, container) {
  const isThreat = analysis.threat_detected;
  const sevClass = `badge-${analysis.severity}`;
  
  let html = `
    <div style="background:rgba(5,7,17,0.7); border:1px solid ${isThreat ? 'var(--neon-crimson)' : 'var(--neon-emerald)'}; border-radius:var(--radius-sm); padding:16px;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <div>
          <span class="badge-tag ${sevClass}">${analysis.severity}</span>
          <strong style="margin-left:8px; font-size:15px; color:#fff;">${analysis.threat_type}</strong>
        </div>
        <div style="font-family:var(--font-mono); font-size:13px; color:${isThreat ? 'var(--neon-crimson)' : 'var(--neon-emerald)'}; font-weight:700;">
          Risk Score: ${analysis.risk_score}/100 | Conf: ${analysis.confidence}%
        </div>
      </div>
      
      <p style="font-size:13px; color:var(--text-primary); margin-bottom:12px; line-height:1.4;">
        ${analysis.human_summary}
      </p>

      <div style="font-size:11px; font-family:var(--font-mono); color:var(--text-secondary); background:rgba(25,36,77,0.4); padding:8px 12px; border-radius:4px; margin-bottom:12px;">
        <strong>MITRE ATT&CK:</strong> ${analysis.mitre_attack.technique_id} - ${analysis.mitre_attack.technique_name} (${analysis.mitre_attack.tactic})
      </div>

      <div style="margin-bottom:14px;">
        <strong style="font-size:12px; color:var(--text-secondary); text-transform:uppercase;">AI Detection Rationale:</strong>
        <ul style="margin-top:6px; padding-left:18px; font-size:12px; color:#cbd5e1; line-height:1.5;">
          ${analysis.key_factors.map(k => `<li>${k}</li>`).join('')}
        </ul>
      </div>
  `;

  if (isThreat) {
    html += `
      <div style="display:flex; gap:10px; margin-top:14px;">
        <button class="action-btn-sm" onclick="blockAttackerIP('${analysis.src_ip}', '${analysis.threat_type}')" style="padding:8px 16px; font-size:12px;">
          🛡️ 1-Click Block IP (${analysis.src_ip})
        </button>
        <button class="action-btn-primary" onclick="openPlaybookModal('${analysis.threat_type}')" style="padding:8px 16px; font-size:12px;">
          📋 Remediation Playbook
        </button>
      </div>
    `;
  }

  html += `</div>`;
  container.innerHTML = html;
}

// 3. File Upload Handler
function initFileUpload() {
  const dropZone = document.getElementById('logDropZone');
  const fileInput = document.getElementById('logFileInput');
  const uploadResults = document.getElementById('uploadResults');

  if (!dropZone || !fileInput) return;

  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });

  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    if (e.dataTransfer.files.length) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length) {
      handleFileUpload(e.target.files[0]);
    }
  });
}

async function handleFileUpload(file) {
  const uploadResults = document.getElementById('uploadResults');
  uploadResults.innerHTML = `<div style="text-align:center; padding: 25px;"><i class="fa-solid fa-spinner fa-spin" style="font-size:28px; color:var(--neon-cyan);"></i><p style="margin-top:12px; color:var(--text-secondary);">Parsing & Inspecting ${file.name}...</p></div>`;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch(`${API_BASE}/api/upload-log-file`, {
      method: 'POST',
      body: formData
    });

    const data = await res.json();
    renderUploadedBatchResults(data, uploadResults);
  } catch (err) {
    uploadResults.innerHTML = `<div style="color:var(--neon-crimson);">Upload failed: ${err.message}</div>`;
  }
}

function renderUploadedBatchResults(data, container) {
  let html = `
    <div style="background:var(--bg-glass-card); border:1px solid var(--border-glass); border-radius:var(--radius-sm); padding:16px; margin-bottom:16px;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <h4 style="color:#fff; font-size:14px;"><i class="fa-solid fa-file-shield" style="color:var(--neon-cyan); margin-right:6px;"></i> ${data.filename}</h4>
          <p style="font-size:12px; color:var(--text-muted); font-family:var(--font-mono); margin-top:2px;">
            ${data.total_records} Records Analyzed | ${data.threats_found} Threats Flagged | ${data.high_severity_count} Critical/High
          </p>
        </div>
        <div>
          <span class="badge-tag ${data.threats_found > 0 ? 'badge-Critical' : 'badge-Low'}">
            ${data.threats_found > 0 ? 'THREATS DETECTED' : 'CLEAN BATCH'}
          </span>
        </div>
      </div>
    </div>

    <div style="max-height: 380px; overflow-y:auto; display:flex; flex-direction:column; gap:8px;">
  `;

  data.items.forEach(item => {
    html += `
      <div class="threat-item severity-${item.severity}" onclick='openThreatModal(${JSON.stringify(item)})'>
        <div class="threat-item-top">
          <div class="threat-title-group">
            <span class="badge-tag badge-${item.severity}">${item.severity}</span>
            <span class="threat-name">${item.threat_type}</span>
          </div>
          <span class="threat-src">${item.src_ip} (${item.src_country || 'Unknown'})</span>
        </div>
        <p class="threat-summary">${item.human_summary}</p>
      </div>
    `;
  });

  html += `</div>`;
  container.innerHTML = html;
}

// 4. Active Defense & Blocklist Functions
async function loadBlockedIPs() {
  const tableBody = document.getElementById('blockedIpsTableBody');
  if (!tableBody) return;

  try {
    const res = await fetch(`${API_BASE}/api/blocked-ips`);
    const data = await res.json();
    
    // Update blocked count KPI
    const kpi = document.getElementById('kpiBlockedCount');
    if (kpi) kpi.innerText = data.blocked_ips.length;

    if (data.blocked_ips.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:30px;">No active blocked IPs. Firewall perimeter clear.</td></tr>`;
      return;
    }

    let html = '';
    data.blocked_ips.forEach(entry => {
      html += `
        <tr>
          <td style="font-family:var(--font-mono); font-weight:700; color:var(--neon-cyan);">${entry.ip}</td>
          <td><span class="badge-tag badge-Critical">${entry.threat_type}</span></td>
          <td style="color:var(--text-secondary); font-size:12px;">${entry.reason}</td>
          <td style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">${new Date(entry.blocked_at).toLocaleTimeString()}</td>
          <td><span style="color:var(--neon-crimson); font-weight:700; font-size:11px;">● BLOCKED</span></td>
          <td>
            <button class="action-btn-primary" onclick="viewFirewallScript('${entry.ip}')">📜 Rules</button>
            <button class="action-btn-sm" onclick="unblockIP('${entry.ip}')">Unblock</button>
          </td>
        </tr>
      `;
    });
    tableBody.innerHTML = html;
  } catch (err) {
    console.error('Failed to load blocked IPs:', err);
  }
}

async function blockAttackerIP(ip, threatType = 'Hostile Attack') {
  try {
    const res = await fetch(`${API_BASE}/api/block-ip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, threat_type: threatType, reason: `Neutralized threat: ${threatType}` })
    });
    const data = await res.json();
    showToast(`🛡️ IP ${ip} successfully quarantined and dropped at firewall.`, 'danger');
    loadBlockedIPs();
    closeModal('threatDetailModal');
  } catch (err) {
    showToast('Failed to block IP: ' + err.message, 'danger');
  }
}

async function unblockIP(ip) {
  try {
    await fetch(`${API_BASE}/api/unblock-ip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    showToast(`IP ${ip} removed from blocklist.`, 'success');
    loadBlockedIPs();
  } catch (err) {
    showToast('Failed to unblock IP: ' + err.message, 'danger');
  }
}

async function viewFirewallScript(ip) {
  try {
    const res = await fetch(`${API_BASE}/api/firewall-script?ip=${ip}&os_type=linux`);
    const dataLinux = await res.json();
    const resWin = await fetch(`${API_BASE}/api/firewall-script?ip=${ip}&os_type=windows`);
    const dataWin = await resWin.json();

    const body = document.getElementById('firewallScriptModalBody');
    body.innerHTML = `
      <div style="margin-bottom:14px;">
        <strong style="color:var(--neon-cyan); font-size:13px;">Linux iptables / UFW Command:</strong>
        <pre class="code-block" style="margin-top:6px;">${dataLinux.script}</pre>
      </div>
      <div>
        <strong style="color:var(--neon-purple); font-size:13px;">Windows Defender PowerShell Command:</strong>
        <pre class="code-block" style="margin-top:6px;">${dataWin.script}</pre>
      </div>
    `;
    openModal('firewallScriptModal');
  } catch (err) {
    showToast('Failed to fetch firewall scripts: ' + err.message, 'danger');
  }
}

// 5. Open Remediation Playbook Modal
async function openPlaybookModal(threatType) {
  try {
    const res = await fetch(`${API_BASE}/api/playbook/${encodeURIComponent(threatType)}`);
    const playbook = await res.json();

    const body = document.getElementById('playbookModalBody');
    body.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
        <h3 style="color:#fff; font-size:16px;">${playbook.title}</h3>
        <span class="badge-tag badge-${playbook.severity}">${playbook.severity}</span>
      </div>

      <div style="background:rgba(25,36,77,0.4); padding:12px; border-radius:var(--radius-sm); border:1px solid var(--border-glass); margin-bottom:14px;">
        <strong style="font-size:12px; color:var(--neon-cyan); text-transform:uppercase;">Plain-English Explanation:</strong>
        <p style="font-size:13px; color:#cbd5e1; margin-top:4px; line-height:1.4;">${playbook.non_technical_explanation}</p>
      </div>

      <div style="margin-bottom:14px;">
        <strong style="font-size:12px; color:var(--neon-crimson); text-transform:uppercase;">Immediate Containment Steps:</strong>
        <ul style="margin-top:6px; padding-left:20px; font-size:12px; color:#f8fafc; line-height:1.5;">
          ${playbook.immediate_containment.map(s => `<li>${s}</li>`).join('')}
        </ul>
      </div>

      <div style="margin-bottom:14px;">
        <strong style="font-size:12px; color:var(--neon-emerald); text-transform:uppercase;">Permanent Hardening / Code Fixes:</strong>
        <ul style="margin-top:6px; padding-left:20px; font-size:12px; color:#f8fafc; line-height:1.5;">
          ${playbook.permanent_fix_steps.map(s => `<li>${s}</li>`).join('')}
        </ul>
      </div>

      ${playbook.code_example_good !== 'N/A' ? `
        <div>
          <strong style="font-size:12px; color:var(--neon-blue); text-transform:uppercase;">Secure Code Implementation:</strong>
          <pre class="code-block" style="margin-top:6px;">${playbook.code_example_good}</pre>
        </div>
      ` : ''}
    `;
    openModal('playbookModal');
  } catch (err) {
    showToast('Failed to load playbook: ' + err.message, 'danger');
  }
}

// 6. Security Audit Report Generator
async function loadExecutiveReport() {
  const container = document.getElementById('reportContainer');
  if (!container) return;

  try {
    const res = await fetch(`${API_BASE}/api/export-report`);
    const rep = await res.json();

    container.innerHTML = `
      <div class="report-paper">
        <div class="report-header-banner">
          <div>
            <h2 style="font-size:22px; font-weight:800; color:#fff; letter-spacing:0.5px;">CYBERGUARD AI SOC REPORT</h2>
            <p style="font-size:12px; color:var(--text-secondary); font-family:var(--font-mono); margin-top:4px;">
              Report ID: ${rep.report_id} | Generated: ${rep.generated_at}
            </p>
          </div>
          <div style="text-align:right;">
            <button class="action-btn-primary" onclick="window.print()" style="padding:8px 16px; font-size:12px;">
              🖨️ Print / Save PDF
            </button>
          </div>
        </div>

        <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:14px; margin-bottom:24px;">
          <div class="glass-card" style="padding:14px; text-align:center;">
            <div style="font-size:11px; color:var(--text-secondary);">PACKETS INSPECTED</div>
            <div style="font-size:20px; font-weight:800; color:#fff; font-family:var(--font-mono); margin-top:4px;">${rep.executive_summary.total_packets_inspected.toLocaleString()}</div>
          </div>
          <div class="glass-card" style="padding:14px; text-align:center;">
            <div style="font-size:11px; color:var(--text-secondary);">THREATS NEUTRALIZED</div>
            <div style="font-size:20px; font-weight:800; color:var(--neon-emerald); font-family:var(--font-mono); margin-top:4px;">${rep.executive_summary.total_threats_neutralized}</div>
          </div>
          <div class="glass-card" style="padding:14px; text-align:center;">
            <div style="font-size:11px; color:var(--text-secondary);">SECURITY HEALTH SCORE</div>
            <div style="font-size:20px; font-weight:800; color:var(--neon-cyan); font-family:var(--font-mono); margin-top:4px;">${rep.executive_summary.overall_health_score}/100</div>
          </div>
        </div>

        <div style="margin-bottom:24px;">
          <h3 style="font-size:14px; color:#fff; margin-bottom:10px; border-bottom:1px solid var(--border-glass); padding-bottom:6px;">
            🛡️ Executive Recommendations
          </h3>
          <ul style="padding-left:20px; font-size:12px; color:var(--text-secondary); line-height:1.6;">
            ${rep.recommendations.map(r => `<li>${r}</li>`).join('')}
          </ul>
        </div>

        <div>
          <h3 style="font-size:14px; color:#fff; margin-bottom:10px; border-bottom:1px solid var(--border-glass); padding-bottom:6px;">
            ⚠️ Active Quarantined IP Addresses (${rep.quarantined_hosts.length})
          </h3>
          ${rep.quarantined_hosts.length > 0 ? `
            <table class="data-table" style="font-size:12px;">
              <thead>
                <tr><th>IP</th><th>Attack Vector</th><th>Blocked At</th><th>Status</th></tr>
              </thead>
              <tbody>
                ${rep.quarantined_hosts.map(h => `<tr><td style="font-family:var(--font-mono); color:var(--neon-cyan);">${h.ip}</td><td>${h.threat_type}</td><td>${h.blocked_at}</td><td style="color:var(--neon-crimson); font-weight:700;">QUARANTINED</td></tr>`).join('')}
              </tbody>
            </table>
          ` : '<p style="font-size:12px; color:var(--text-muted);">No active blocked hosts at this time.</p>'}
        </div>
      </div>
    `;
  } catch (err) {
    console.error('Failed to load report:', err);
  }
}
