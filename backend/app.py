import os
import io
import csv
import json
import random
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from backend.device_monitor import device_monitor
from backend.network_monitor import network_monitor
from backend.log_monitor import log_monitor
from backend.audit_engine import audit_engine
from backend.advanced_sentinel import advanced_sentinel
from backend.copilot_engine import copilot_engine
from backend.defense_handler import defense_matrix
from backend.ml_engine import engine, MITRE_MAPPING
from backend.attack_simulator import simulator

app = FastAPI(
    title="CyberArmor Pro EDR Platform",
    description="Autonomous Device Security, Attack Tree Lineage & AI Threat Hunting Platform",
    version="4.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connected_clients: List[WebSocket] = []
simulation_queue: List[Dict[str, Any]] = []

# ==========================================
# 1. CORE DEVICE TELEMETRY ENDPOINTS
# ==========================================

@app.get("/api/device/overview")
async def get_device_overview():
    """Returns real live host hardware metrics, network sockets summary, and security grade."""
    overview = device_monitor.get_system_overview()
    conns = network_monitor.get_active_connections(limit=10)
    audit = audit_engine.run_full_security_audit()
    canary = advanced_sentinel.check_canary_status()

    return {
        "system": overview,
        "active_connections_count": conns["total_connections"],
        "threat_sockets_found": conns["threat_sockets_found"],
        "device_health_score": audit["device_health_score"],
        "security_grade": audit["security_grade"],
        "firewall_active_rules": len(defense_matrix.blocked_ips),
        "quarantined_files_count": len(defense_matrix.quarantined_files),
        "host_isolated": advanced_sentinel.host_isolated,
        "canary_status": canary["shield_status"],
        "auto_shield_enabled": defense_matrix.auto_shield_enabled,
        "mitigation_stats": defense_matrix.stats
    }

@app.get("/api/device/processes")
async def get_device_processes(limit: int = Query(100)):
    """Returns real live running processes on the host with AI behavioral risk analysis."""
    procs = device_monitor.get_running_processes(limit=limit)
    high_risk_count = sum(1 for p in procs if p["risk_level"] in ["HIGH", "CRITICAL"])
    return {
        "total_processes": len(procs),
        "high_risk_count": high_risk_count,
        "processes": procs
    }

@app.post("/api/device/kill-process")
async def kill_process(body: Dict[str, Any]):
    """Safely terminates a process on the host operating system by PID."""
    pid = body.get("pid")
    if not pid:
        raise HTTPException(status_code=400, detail="Missing 'pid'")
    res = defense_matrix.kill_process(int(pid), reason=body.get("reason", "Analyst terminated via CyberArmor EDR"))
    return res

@app.get("/api/device/connections")
async def get_device_connections(limit: int = Query(120)):
    """Returns real live network connections and open listening ports on the host."""
    return network_monitor.get_active_connections(limit=limit)

@app.get("/api/device/event-logs")
async def get_event_logs(log_name: str = Query("System"), max_events: int = Query(40)):
    """Returns real Windows Event Logs (System, Application, Security)."""
    logs = log_monitor.get_windows_event_logs(log_name=log_name, max_events=max_events)
    return {
        "log_name": log_name,
        "total_events": len(logs),
        "events": logs
    }

@app.post("/api/device/tail-server-log")
async def tail_server_log(body: Dict[str, Any]):
    """Tails and analyzes lines from a real local log file on the machine."""
    file_path = body.get("file_path", "")
    max_lines = body.get("max_lines", 100)
    if not file_path:
        raise HTTPException(status_code=400, detail="Missing 'file_path'")
    return log_monitor.tail_local_file(file_path=file_path, max_lines=max_lines)

@app.get("/api/device/audit")
async def get_security_audit():
    """Runs a full system hardening and vulnerability assessment on the host."""
    return audit_engine.run_full_security_audit()

# ==========================================
# 2. ADVANCED EDR & THREAT HUNTING ENDPOINTS
# ==========================================

@app.get("/api/edr/process-tree")
async def get_process_attack_tree(pid: Optional[int] = Query(None)):
    """Returns interactive parent-child process execution DAG lineage for root cause analysis."""
    return advanced_sentinel.get_process_attack_tree(target_pid=pid)

@app.post("/api/edr/inspect-binary")
async def inspect_binary(body: Dict[str, Any]):
    """Calculates real SHA-256, MD5, and Shannon Entropy for binary file inspection."""
    file_path = body.get("file_path", "")
    if not file_path:
        raise HTTPException(status_code=400, detail="Missing 'file_path'")
    return advanced_sentinel.inspect_binary_threat_intel(file_path)

@app.get("/api/edr/canary-status")
async def get_canary_status():
    """Returns Anti-Ransomware Canary Honey-Trap status."""
    return advanced_sentinel.check_canary_status()

@app.post("/api/edr/trip-canary-test")
async def trip_canary_test():
    """Simulates a ransomware attack encrypting the canary for defense validation."""
    return advanced_sentinel.trip_canary_simulation()

@app.get("/api/edr/fim-status")
async def get_fim_status():
    """Returns File Integrity Monitoring (FIM) status."""
    return advanced_sentinel.check_fim_integrity()

@app.post("/api/edr/toggle-isolation")
async def toggle_host_isolation(body: Dict[str, Any]):
    """Toggles Emergency Host Network Isolation (Airgap Mode)."""
    enable = body.get("enable", False)
    return advanced_sentinel.toggle_emergency_host_isolation(enable)

@app.post("/api/edr/copilot-query")
async def query_copilot(body: Dict[str, Any]):
    """Interacts with the GenAI Cyber Security Copilot."""
    query = body.get("query", "")
    if not query:
        raise HTTPException(status_code=400, detail="Missing 'query'")
    return copilot_engine.ask(query)

# ==========================================
# 3. ACTIVE DEFENSE & REMEDIATION ENDPOINTS
# ==========================================

@app.post("/api/device/block-ip")
async def block_host_ip(body: Dict[str, Any]):
    """Blocks an IP address on Windows Defender Firewall."""
    ip = body.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="Missing 'ip'")
    entry = defense_matrix.block_ip(
        ip=ip,
        reason=body.get("reason", "Hostile network activity flagged by CyberArmor"),
        threat_type=body.get("threat_type", "Network Threat")
    )
    return {"status": "SUCCESS", "entry": entry}

@app.post("/api/device/unblock-ip")
async def unblock_host_ip(body: Dict[str, Any]):
    """Removes an IP block rule from Windows Defender Firewall."""
    ip = body.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="Missing 'ip'")
    success = defense_matrix.unblock_ip(ip)
    return {"status": "SUCCESS" if success else "NOT_FOUND", "ip": ip}

@app.get("/api/device/firewall-rules")
async def get_firewall_rules():
    """Returns active blocked IPs, quarantine vault contents, and defense history."""
    return {
        "blocked_ips": list(defense_matrix.blocked_ips.values()),
        "quarantined_files": defense_matrix.quarantined_files,
        "mitigation_history": defense_matrix.mitigation_history[:40],
        "stats": defense_matrix.stats
    }

@app.post("/api/device/quarantine-file")
async def quarantine_suspicious_file(body: Dict[str, Any]):
    """Moves a suspicious file into the quarantine vault."""
    path = body.get("file_path")
    if not path:
        raise HTTPException(status_code=400, detail="Missing 'file_path'")
    return defense_matrix.quarantine_file(path, reason=body.get("reason", "Manual quarantine"))

@app.post("/api/device/remove-startup-key")
async def remove_startup_key(body: Dict[str, Any]):
    """Deletes rogue startup persistence from registry."""
    loc = body.get("registry_location", "HKCU_Run")
    name = body.get("name", "")
    if not name:
        raise HTTPException(status_code=400, detail="Missing 'name'")
    return defense_matrix.remove_startup_key(loc, name)

@app.post("/api/device/toggle-auto-shield")
async def toggle_auto_shield(body: Dict[str, Any]):
    """Toggles autonomous threat neutralization mode."""
    enabled = body.get("enabled", False)
    val = defense_matrix.toggle_auto_shield(enabled)
    return {"auto_shield_enabled": val}

@app.get("/api/device/export-report")
async def export_device_security_report():
    """Generates an executive device security compliance audit document."""
    overview = device_monitor.get_system_overview()
    audit = audit_engine.run_full_security_audit()
    conns = network_monitor.get_active_connections(limit=20)
    procs = device_monitor.get_running_processes(limit=20)

    return {
        "report_id": f"EDR-AUDIT-{int(datetime.utcnow().timestamp())}",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "host_information": overview,
        "device_security_score": audit["device_health_score"],
        "security_grade": audit["security_grade"],
        "hardening_checks": audit["audit_items"],
        "active_firewall_quarantines": list(defense_matrix.blocked_ips.values()),
        "top_active_processes": procs[:8],
        "listening_ports_summary": conns["listening_ports"][:10],
        "defense_stats": defense_matrix.stats
    }

# ==========================================
# 4. AI DETECTION & SIMULATION ENDPOINTS
# ==========================================

@app.post("/api/analyze-payload")
async def analyze_payload(payload_data: Dict[str, Any]):
    """Inspects a raw HTTP/SQL/Script payload with AI models."""
    event = {
        "event_type": "web_request",
        "payload": payload_data.get("payload", ""),
        "url": payload_data.get("url", "/test"),
        "method": payload_data.get("method", "GET"),
        "src_ip": payload_data.get("src_ip", "198.51.100.42")
    }
    return engine.analyze_event(event)

@app.post("/api/simulate-attack")
async def simulate_attack(body: Dict[str, Any]):
    """Triggers an on-demand attack scenario to demonstrate real-time detection."""
    attack_type = body.get("attack_type", "ddos")
    events = simulator.create_attack_scenario(attack_type)
    analyzed_events = []
    for evt in events:
        res = engine.analyze_event(evt)
        analyzed_events.append(res)
        simulation_queue.append(res)
    return {
        "status": "SIMULATION_TRIGGERED",
        "attack_type": attack_type,
        "events_generated": len(events),
        "sample_result": analyzed_events[0] if analyzed_events else None
    }

# ==========================================
# 5. REAL-TIME WEBSOCKET STREAM
# ==========================================

@app.websocket("/ws/live-feed")
async def websocket_live_feed(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    print(f"[CyberArmor WS] Client connected. Active: {len(connected_clients)}")

    try:
        while True:
            # 1. Process simulated queue events if any
            if simulation_queue:
                sim_evt = simulation_queue.pop(0)
                await websocket.send_json({
                    "type": "SIMULATION_ALERT",
                    "data": sim_evt
                })
                await asyncio.sleep(0.3)
                continue

            # 2. Stream real device telemetry pulse
            overview = device_monitor.get_system_overview()
            top_procs = device_monitor.get_running_processes(limit=5)
            high_risk_procs = [p for p in top_procs if p["risk_level"] in ["HIGH", "CRITICAL"]]
            canary = advanced_sentinel.check_canary_status()

            await websocket.send_json({
                "type": "DEVICE_TELEMETRY",
                "system": overview,
                "high_risk_processes": high_risk_procs,
                "host_isolated": advanced_sentinel.host_isolated,
                "canary_tampered": canary["is_under_attack"],
                "blocked_count": len(defense_matrix.blocked_ips),
                "quarantined_count": len(defense_matrix.quarantined_files)
            })

            await asyncio.sleep(1.5)

    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
        print(f"[CyberArmor WS] Client disconnected. Active: {len(connected_clients)}")
    except Exception as e:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
        print(f"[CyberArmor WS] Error: {e}")

# Static frontend mount
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
async def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"status": "CyberArmor Pro EDR Backend Online."})
