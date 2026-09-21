/**
 * CyberArmor Pro EDR - GenAI Interactive Cyber Security Copilot
 */

function toggleCopilotDrawer() {
  const drawer = document.getElementById("copilotDrawer");
  if (!drawer) return;
  drawer.classList.toggle("active");
}

async function sendCopilotMessage(customText = null) {
  const input = document.getElementById("copilotInput");
  const messagesContainer = document.getElementById("copilotMessages");
  const query = customText || input?.value?.trim();

  if (!query || !messagesContainer) return;
  if (input && !customText) input.value = "";

  // 1. Append User Message
  messagesContainer.innerHTML += `
    <div style="align-self:flex-end; max-width:85%; background:rgba(0,242,254,0.15); border:1px solid var(--neon-cyan); color:#fff; padding:10px 14px; border-radius:12px 12px 2px 12px; font-size:13px; margin-bottom:12px;">
      ${query}
    </div>
  `;
  messagesContainer.scrollTop = messagesContainer.scrollHeight;

  // 2. Append Loading Placeholder
  const loadingId = `copilot-load-${Date.now()}`;
  messagesContainer.innerHTML += `
    <div id="${loadingId}" style="align-self:flex-start; max-width:85%; background:rgba(13,19,43,0.8); border:1px solid var(--border-glass); color:var(--text-secondary); padding:12px 16px; border-radius:12px 12px 12px 2px; font-size:13px; margin-bottom:12px;">
      <i class="fa-solid fa-spinner fa-spin" style="color:var(--neon-cyan); margin-right:6px;"></i> Analyzing live host telemetry...
    </div>
  `;
  messagesContainer.scrollTop = messagesContainer.scrollHeight;

  try {
    const res = await fetch(`${API_BASE}/api/edr/copilot-query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: query })
    });
    const data = await res.json();
    
    // Remove loading placeholder
    const loader = document.getElementById(loadingId);
    if (loader) loader.remove();

    // Render Copilot Response with Action Buttons
    let actionsHtml = "";
    if (data.action_buttons && data.action_buttons.length > 0) {
      actionsHtml = `<div style="display:flex; flex-wrap:wrap; gap:8px; margin-top:12px;">`;
      data.action_buttons.forEach(btn => {
        if (btn.type === "kill_pid") {
          actionsHtml += `<button class="action-btn-sm" onclick="killProcessByPid(${btn.pid}, 'Target')">${btn.label}</button>`;
        } else if (btn.type === "view_tree") {
          actionsHtml += `<button class="action-btn-primary" onclick="switchTab('tree-tab'); loadProcessTree(${btn.pid});">${btn.label}</button>`;
        } else if (btn.type === "switch_tab") {
          actionsHtml += `<button class="action-btn-primary" onclick="switchTab('${btn.tab}')">${btn.label}</button>`;
        } else if (btn.type === "trip_canary") {
          actionsHtml += `<button class="action-btn-primary" onclick="testCanarySimulation()">${btn.label}</button>`;
        } else if (btn.type === "run_audit") {
          actionsHtml += `<button class="action-btn-primary" onclick="switchTab('audit-tab'); runSystemAudit();">${btn.label}</button>`;
        }
      });
      actionsHtml += `</div>`;
    }

    let badgesHtml = "";
    if (data.context_badges && data.context_badges.length > 0) {
      badgesHtml = `<div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:8px;">`;
      data.context_badges.forEach(b => {
        badgesHtml += `<span class="badge-tag badge-Medium" style="font-size:10px;">${b}</span>`;
      });
      badgesHtml += `</div>`;
    }

    // Convert markdown bold and bullets
    let formattedText = data.response
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,0.1); padding:2px 4px; border-radius:3px; font-family:var(--font-mono); color:var(--neon-cyan);">$1</code>')
      .replace(/\n\n/g, '<br><br>')
      .replace(/\n- /g, '<br>• ');

    messagesContainer.innerHTML += `
      <div style="align-self:flex-start; max-width:90%; background:rgba(13,19,43,0.9); border:1px solid var(--border-glass-glow); color:#f8fafc; padding:14px 18px; border-radius:12px 12px 12px 2px; font-size:13px; margin-bottom:12px; line-height:1.5;">
        ${badgesHtml}
        <div>${formattedText}</div>
        ${actionsHtml}
        <div style="font-size:10px; color:var(--text-muted); font-family:var(--font-mono); text-align:right; margin-top:8px;">${data.timestamp}</div>
      </div>
    `;
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  } catch (err) {
    const loader = document.getElementById(loadingId);
    if (loader) loader.innerHTML = `<span style="color:var(--neon-crimson);">Copilot communication error: ${err.message}</span>`;
  }
}

async function testCanarySimulation() {
  try {
    const res = await fetch(`${API_BASE}/api/edr/trip-canary-test`, { method: "POST" });
    const data = await res.json();
    showToast("🪤 Ransomware canary decoy file modification tripped & detected!", "danger");
    loadDeviceOverview();
  } catch (err) {
    showToast("Error tripping canary: " + err.message, "danger");
  }
}

async function toggleAirgapIsolation(enable) {
  if (enable && !confirm("⚠️ ACTIVATE EMERGENCY AIRGAP: This will temporarily block all inbound and outbound network traffic to stop active data exfiltration. Proceed?")) return;

  try {
    const res = await fetch(`${API_BASE}/api/edr/toggle-isolation`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enable: enable })
    });
    const data = await res.json();
    showToast(data.message, enable ? "danger" : "success");
    loadDeviceOverview();
  } catch (err) {
    showToast("Failed to toggle isolation: " + err.message, "danger");
  }
}
