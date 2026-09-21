/**
 * CyberArmor Pro EDR - Process Attack Tree & Lineage DAG Visualizer (Root Cause Analysis)
 */

async function loadProcessTree(pid = null) {
  const container = document.getElementById("processTreeCanvasContainer");
  const detailsPanel = document.getElementById("processTreeDetailsPanel");
  if (!container) return;

  container.innerHTML = `<div style="text-align:center; padding:50px;"><i class="fa-solid fa-spinner fa-spin" style="font-size:32px; color:var(--neon-cyan);"></i><p style="margin-top:12px; color:var(--text-secondary);">Reconstructing Process Execution Lineage & Ancestry Tree...</p></div>`;

  try {
    const url = pid ? `${API_BASE}/api/edr/process-tree?pid=${pid}` : `${API_BASE}/api/edr/process-tree`;
    const res = await fetch(url);
    const data = await res.json();
    renderProcessTree(data, container, detailsPanel);
  } catch (err) {
    container.innerHTML = `<div style="color:var(--neon-crimson); padding:20px;">Failed to load process attack tree: ${err.message}</div>`;
  }
}

function renderProcessTree(data, container, detailsPanel) {
  if (!data.nodes || data.nodes.length === 0) {
    container.innerHTML = `<div style="text-align:center; padding:40px; color:var(--text-muted);">No process execution tree found for this target.</div>`;
    return;
  }

  let html = `
    <div style="display:flex; flex-direction:column; gap:16px; position:relative; padding:10px 0;">
  `;

  data.nodes.forEach((node, index) => {
    const isTarget = node.is_target;
    const isHighRisk = node.risk_level === "CRITICAL" || node.risk_level === "HIGH";
    const borderColor = isTarget ? "var(--neon-cyan)" : isHighRisk ? "var(--neon-crimson)" : "var(--border-glass)";
    const badgeClass = node.risk_level === "CRITICAL" ? "badge-Critical" : node.risk_level === "HIGH" ? "badge-High" : "badge-Low";

    html += `
      <div class="glass-card" style="border:1px solid ${borderColor}; padding:14px; background:${isTarget ? 'rgba(0, 242, 254, 0.08)' : 'rgba(13, 19, 43, 0.7)'}; cursor:pointer;" onclick='inspectTreeNodeDetails(${JSON.stringify(node)})'>
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div style="display:flex; align-items:center; gap:12px;">
            <div style="width:36px; height:36px; border-radius:var(--radius-sm); background:${isTarget ? 'rgba(0,242,254,0.2)' : 'rgba(139,92,246,0.15)'}; display:flex; align-items:center; justify-content:center; color:${isTarget ? 'var(--neon-cyan)' : 'var(--neon-purple)'}; font-size:16px;">
              <i class="fa-solid ${isTarget ? 'fa-crosshairs' : 'fa-microchip'}"></i>
            </div>
            <div>
              <div style="font-weight:800; font-size:14px; color:#fff; display:flex; align-items:center; gap:8px;">
                ${node.name}
                ${isTarget ? '<span class="badge-tag badge-Medium" style="font-size:10px;">TARGET PID</span>' : ''}
              </div>
              <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono); margin-top:2px;">
                PID: <strong style="color:var(--neon-cyan);">${node.pid}</strong> | Exe: ${node.exe}
              </div>
            </div>
          </div>

          <div style="text-align:right;">
            <span class="badge-tag ${badgeClass}">${node.risk_level}</span>
            <div style="font-size:11px; font-family:var(--font-mono); color:var(--text-secondary); margin-top:4px;">
              ${node.cpu_percent}% CPU | ${node.memory_mb} MB RAM
            </div>
          </div>
        </div>

        <div style="margin-top:10px; font-size:11px; font-family:var(--font-mono); color:#94a3b8; background:rgba(5,7,17,0.5); padding:6px 10px; border-radius:4px; display:flex; justify-content:space-between;">
          <span><strong>MITRE:</strong> ${node.mitre_tag}</span>
          <span><strong>Entropy:</strong> ${node.entropy} / 8.0</span>
        </div>
      </div>
    `;

    // Draw connecting arrow if not the last node
    if (index < data.nodes.length - 1) {
      html += `
        <div style="display:flex; justify-content:center; color:var(--neon-cyan); font-size:16px; margin:-6px 0;">
          <i class="fa-solid fa-arrow-down"></i>
        </div>
      `;
    }
  });

  html += `</div>`;
  container.innerHTML = html;

  // Pre-select target node in details panel
  const targetNode = data.nodes.find(n => n.is_target) || data.nodes[0];
  inspectTreeNodeDetails(targetNode);
}

function inspectTreeNodeDetails(node) {
  const panel = document.getElementById("processTreeDetailsPanel");
  if (!panel || !node) return;

  panel.innerHTML = `
    <div style="background:rgba(5,7,17,0.8); border:1px solid var(--border-glass); border-radius:var(--radius-sm); padding:16px;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <h4 style="color:#fff; font-size:15px; font-weight:700;">${node.name} (PID ${node.pid})</h4>
        <span class="badge-tag badge-${node.risk_level === 'CRITICAL' ? 'Critical' : node.risk_level === 'HIGH' ? 'High' : 'Low'}">${node.risk_level}</span>
      </div>

      <div style="display:flex; flex-direction:column; gap:10px; font-size:12px;">
        <div>
          <span style="color:var(--text-muted); font-size:11px;">COMMAND LINE:</span>
          <pre class="code-block" style="margin-top:4px; font-size:11px; max-height:80px; overflow-y:auto;">${node.cmdline}</pre>
        </div>

        <div>
          <span style="color:var(--text-muted); font-size:11px;">SHA-256 HASH:</span>
          <div style="font-family:var(--font-mono); font-size:11px; color:var(--neon-cyan); word-break:break-all; margin-top:2px;">${node.sha256}</div>
        </div>

        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
          <div style="background:rgba(25,36,77,0.4); padding:8px; border-radius:4px;">
            <div style="font-size:10px; color:var(--text-muted);">SHANNON ENTROPY</div>
            <div style="font-size:14px; font-weight:700; color:${node.entropy > 7.2 ? 'var(--neon-crimson)' : '#fff'};">${node.entropy} / 8.0</div>
          </div>
          <div style="background:rgba(25,36,77,0.4); padding:8px; border-radius:4px;">
            <div style="font-size:10px; color:var(--text-muted);">MEMORY (RSS)</div>
            <div style="font-size:14px; font-weight:700; color:#fff;">${node.memory_mb} MB</div>
          </div>
        </div>

        <div>
          <span style="color:var(--text-muted); font-size:11px;">MITRE ATT&CK TACTIC:</span>
          <div style="color:var(--neon-purple); font-family:var(--font-mono); font-size:12px; margin-top:2px;">${node.mitre_tag}</div>
        </div>

        <div style="margin-top:14px; display:flex; gap:10px;">
          <button class="action-btn-sm" onclick="killProcessByPid(${node.pid}, '${node.name}')" style="flex:1; padding:8px 12px; font-size:12px;">
            ⚡ Kill Process
          </button>
        </div>
      </div>
    </div>
  `;
}
