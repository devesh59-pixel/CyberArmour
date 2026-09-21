/**
 * CyberArmor EDR - Master Product Application Controller
 */

class CyberArmorApp {
  constructor() {
    this.ws = null;
    this.audioCtx = null;
    this.soundEnabled = true;
    this.autoShield = false;
    
    this.init();
  }

  init() {
    this.initAudio();
    this.initWebSocket();
    this.initClock();
    this.initControls();
    
    // Initial Data Loads
    loadDeviceOverview();
    loadDeviceProcesses();
    loadDeviceConnections();
    loadWindowsEventLogs("System");
    runSystemAudit();
    loadFirewallAndQuarantine();

    // Auto-refresh interval for device overview & sockets every 5 seconds
    setInterval(() => {
      loadDeviceOverview();
    }, 4000);
  }

  initAudio() {
    try {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) {
        this.audioCtx = new AudioContext();
      }
    } catch (e) {}
  }

  playAlertSound(type = 'alert') {
    if (!this.soundEnabled || !this.audioCtx) return;
    if (this.audioCtx.state === 'suspended') {
      this.audioCtx.resume();
    }

    try {
      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();
      osc.connect(gain);
      gain.connect(this.audioCtx.destination);

      if (type === 'critical') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, this.audioCtx.currentTime);
        osc.frequency.setValueAtTime(440, this.audioCtx.currentTime + 0.1);
        gain.gain.setValueAtTime(0.12, this.audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, this.audioCtx.currentTime + 0.35);
        osc.start();
        osc.stop(this.audioCtx.currentTime + 0.35);
      } else {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(540, this.audioCtx.currentTime);
        gain.gain.setValueAtTime(0.06, this.audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, this.audioCtx.currentTime + 0.15);
        osc.start();
        osc.stop(this.audioCtx.currentTime + 0.15);
      }
    } catch (e) {}
  }

  initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live-feed`;
    
    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      console.log('[CyberArmor WS] Connected to live device telemetry stream');
      const badge = document.getElementById('wsStatusBadge');
      if (badge) badge.style.display = 'flex';
    };

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        this.handleStreamMessage(msg);
      } catch (err) {
        console.error('Error parsing live feed message:', err);
      }
    };

    this.ws.onclose = () => {
      setTimeout(() => this.initWebSocket(), 3000);
    };
  }

  handleStreamMessage(msg) {
    if (msg.type === "DEVICE_TELEMETRY") {
      const sys = msg.system;
      updateResourceBar("cpuBarFill", "cpuPercentVal", sys.cpu_percent, `${sys.cpu_percent}% (${sys.cpu_count} Cores)`);
      updateResourceBar("ramBarFill", "ramPercentVal", sys.ram_percent, `${sys.ram_used_gb} GB / ${sys.ram_total_gb} GB (${sys.ram_percent}%)`);

      if (msg.high_risk_processes && msg.high_risk_processes.length > 0) {
        this.playAlertSound('critical');
        showToast(`🚨 High-risk process alert: ${msg.high_risk_processes[0].name} (PID: ${msg.high_risk_processes[0].pid})`, "danger");
      }
    } else if (msg.type === "SIMULATION_ALERT") {
      const data = msg.data;
      this.playAlertSound('critical');
      showToast(`⚡ Simulation Attack Detected: ${data.threat_type} from ${data.src_ip}`, "danger");
    }
  }

  initClock() {
    const updateTime = () => {
      const el = document.getElementById('socClock');
      if (el) {
        const now = new Date();
        el.innerText = `${now.toUTCString().slice(17, 25)} UTC`;
      }
    };
    setInterval(updateTime, 1000);
    updateTime();
  }

  initControls() {
    const soundBtn = document.getElementById('toggleSoundBtn');
    if (soundBtn) {
      soundBtn.addEventListener('click', () => {
        this.soundEnabled = !this.soundEnabled;
        soundBtn.innerHTML = this.soundEnabled ? `<i class="fa-solid fa-volume-high"></i>` : `<i class="fa-solid fa-volume-xmark"></i>`;
        soundBtn.classList.toggle('active', this.soundEnabled);
        showToast(`Audible Threat Alerts ${this.soundEnabled ? 'Enabled' : 'Muted'}`, 'info');
      });
    }

    const autoShieldBtn = document.getElementById('toggleAutoShieldBtn');
    if (autoShieldBtn) {
      autoShieldBtn.addEventListener('click', async () => {
        this.autoShield = !this.autoShield;
        autoShieldBtn.classList.toggle('active', this.autoShield);
        
        await fetch(`${API_BASE}/api/device/toggle-auto-shield`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: this.autoShield })
        });

        showToast(`Autonomous Host Shield: ${this.autoShield ? 'ARMED & ACTIVE' : 'STANDBY'}`, this.autoShield ? 'danger' : 'info');
      });
    }
  }
}

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.classList.toggle('active', tab.getAttribute('data-tab') === tabId);
  });

  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.toggle('active', pane.id === tabId);
  });

  if (tabId === 'process-tab') {
    loadDeviceProcesses();
  } else if (tabId === 'sockets-tab') {
    loadDeviceConnections();
  } else if (tabId === 'logs-tab') {
    loadWindowsEventLogs("System");
  } else if (tabId === 'audit-tab') {
    runSystemAudit();
  } else if (tabId === 'quarantine-tab') {
    loadFirewallAndQuarantine();
  } else if (tabId === 'report-tab') {
    loadDeviceExecutiveReport();
  }
}

// Executive Device Security Report
async function loadDeviceExecutiveReport() {
  const container = document.getElementById('reportContainer');
  if (!container) return;

  try {
    const res = await fetch(`${API_BASE}/api/device/export-report`);
    const rep = await res.json();

    container.innerHTML = `
      <div class="report-paper">
        <div class="report-header-banner">
          <div>
            <h2 style="font-size:22px; font-weight:800; color:#fff; letter-spacing:0.5px;">CYBERARMOR EDR DEVICE AUDIT</h2>
            <p style="font-size:12px; color:var(--text-secondary); font-family:var(--font-mono); margin-top:4px;">
              Report ID: ${rep.report_id} | Host: ${rep.host_information.hostname} (${rep.host_information.ip_address}) | Generated: ${rep.generated_at}
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
            <div style="font-size:11px; color:var(--text-secondary);">DEVICE HEALTH SCORE</div>
            <div style="font-size:22px; font-weight:800; color:${rep.device_security_score >= 80 ? 'var(--neon-emerald)' : 'var(--neon-amber)'}; font-family:var(--font-mono); margin-top:4px;">
              ${rep.device_security_score}/100 (${rep.security_grade})
            </div>
          </div>
          <div class="glass-card" style="padding:14px; text-align:center;">
            <div style="font-size:11px; color:var(--text-secondary);">HOST RAM UTILIZATION</div>
            <div style="font-size:22px; font-weight:800; color:var(--neon-cyan); font-family:var(--font-mono); margin-top:4px;">
              ${rep.host_information.ram_percent}%
            </div>
          </div>
          <div class="glass-card" style="padding:14px; text-align:center;">
            <div style="font-size:11px; color:var(--text-secondary);">FIREWALL QUARANTINES</div>
            <div style="font-size:22px; font-weight:800; color:var(--neon-purple); font-family:var(--font-mono); margin-top:4px;">
              ${rep.active_firewall_quarantines.length} Enforced
            </div>
          </div>
        </div>

        <div style="margin-bottom:24px;">
          <h3 style="font-size:14px; color:#fff; margin-bottom:10px; border-bottom:1px solid var(--border-glass); padding-bottom:6px;">
            🛡️ System Hardening Audit Findings
          </h3>
          <div style="display:flex; flex-direction:column; gap:8px;">
            ${rep.hardening_checks.map(c => `
              <div style="background:rgba(5,7,17,0.5); padding:10px 14px; border-radius:var(--radius-sm); border:1px solid var(--border-glass); display:flex; justify-content:space-between; align-items:center;">
                <div>
                  <strong style="color:#fff; font-size:12px;">${c.title}</strong>
                  <div style="font-size:11px; color:var(--text-secondary); margin-top:2px;">${c.description}</div>
                </div>
                <span class="badge-tag ${c.status === 'PASS' ? 'badge-Low' : 'badge-Critical'}">${c.status}</span>
              </div>
            `).join('')}
          </div>
        </div>

        <div>
          <h3 style="font-size:14px; color:#fff; margin-bottom:10px; border-bottom:1px solid var(--border-glass); padding-bottom:6px;">
            ⚠️ Top Monitored Host Processes
          </h3>
          <table class="data-table" style="font-size:12px;">
            <thead>
              <tr><th>PID</th><th>Process</th><th>CPU</th><th>RAM</th><th>Risk Level</th></tr>
            </thead>
            <tbody>
              ${rep.top_active_processes.map(p => `
                <tr>
                  <td style="font-family:var(--font-mono); color:var(--neon-cyan);">${p.pid}</td>
                  <td>${p.name}</td>
                  <td>${p.cpu_percent}%</td>
                  <td>${p.memory_percent}%</td>
                  <td><span class="badge-tag ${p.risk_level === 'CRITICAL' ? 'badge-Critical' : p.risk_level === 'HIGH' ? 'badge-High' : 'badge-Low'}">${p.risk_level}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div style="color:var(--neon-crimson);">Failed generating audit report: ${err.message}</div>`;
  }
}

// Modal helpers
function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.add('active');
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.remove('active');
}

// Toast Notifications
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.style.cssText = `
    background: ${type === 'danger' ? 'rgba(255, 0, 85, 0.95)' : type === 'warning' ? 'rgba(245, 158, 11, 0.95)' : 'rgba(9, 13, 31, 0.95)'};
    border: 1px solid ${type === 'danger' ? 'var(--neon-crimson)' : 'var(--neon-cyan)'};
    color: #fff;
    padding: 12px 18px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-weight: 600;
    box-shadow: 0 10px 30px rgba(0,0,0,0.6);
    backdrop-filter: blur(10px);
    display: flex;
    align-items: center;
    gap: 10px;
    animation: fadeIn 0.2s ease-out;
  `;
  toast.innerHTML = `<i class="fa-solid fa-shield-halved"></i> <span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// Start
window.addEventListener('DOMContentLoaded', () => {
  window.CyberApp = new CyberArmorApp();
});
