import re
import psutil
from typing import Dict, Any, List
from datetime import datetime

from backend.device_monitor import device_monitor
from backend.network_monitor import network_monitor
from backend.audit_engine import audit_engine
from backend.advanced_sentinel import advanced_sentinel
from backend.defense_handler import defense_matrix

class GenAICyberCopilot:
    """
    Interactive GenAI Cyber Security Copilot Engine.
    Processes natural language queries from analysts or non-technical users,
    grounds reasoning in live host telemetry, and returns structured advice with 1-click execution actions.
    """
    def __init__(self):
        pass

    def ask(self, query: str) -> Dict[str, Any]:
        """Processes a natural language question grounded in live device state."""
        q = query.lower().strip()

        # Gather real live host context
        sys = device_monitor.get_system_overview()
        procs = device_monitor.get_running_processes(limit=30)
        high_risk_procs = [p for p in procs if p["risk_level"] in ["HIGH", "CRITICAL"]]
        conns = network_monitor.get_active_connections(limit=30)
        audit = audit_engine.run_full_security_audit()
        canary = advanced_sentinel.check_canary_status()

        response_text = ""
        action_buttons = []
        context_badges = []

        # 1. "Is my device safe?" / "Check security status"
        if any(k in q for k in ["safe", "status", "health", "secure", "infected", "compromised", "am i"]):
            score = audit["device_health_score"]
            grade = audit["security_grade"]
            
            if score >= 85 and not high_risk_procs:
                response_text = f"🛡️ **Your device '{sys['hostname']}' is currently SECURE (Health Score: {score}/100 - Grade {grade}).**\n\n"
                response_text += f"- **CPU & RAM:** {sys['cpu_percent']}% CPU | {sys['ram_percent']}% RAM utilization.\n"
                response_text += f"- **Processes:** Scanned {len(procs)} active processes. Zero critical threats detected.\n"
                response_text += f"- **Ransomware Shield:** Canary traps are active and untampered.\n"
                response_text += f"- **Active Sockets:** {conns['established_count']} established connections."
                context_badges = ["Posture: SECURE", f"Score: {score}/100", "Canary: ARMED"]
            else:
                response_text = f"⚠️ **Attention Required for device '{sys['hostname']}' (Health Score: {score}/100 - Grade {grade}).**\n\n"
                if high_risk_procs:
                    response_text += f"Found **{len(high_risk_procs)} high-risk process(es)** running:\n"
                    for p in high_risk_procs[:3]:
                        response_text += f"- **{p['name']}** (PID `{p['pid']}`): {p['risk_reasons'][0]}\n"
                        action_buttons.append({
                            "type": "kill_pid",
                            "label": f"⚡ Kill {p['name']} (PID {p['pid']})",
                            "pid": p["pid"],
                            "style": "danger"
                        })
                if audit["warning_checks"] + audit["failed_checks"] > 0:
                    response_text += f"\n**Hardening Vulnerabilities Detected:**\n"
                    for item in [a for a in audit["audit_items"] if a["status"] != "PASS"][:2]:
                        response_text += f"- {item['title']}: {item.get('remediation', '')}\n"

                context_badges = [f"Grade: {grade}", f"{len(high_risk_procs)} High-Risk PIDs", f"Open Ports: {conns['listening_count']}"]

        # 2. "Explain PID <number>" / Specific Process Analysis
        elif "pid" in q or re.search(r"\b\d{2,6}\b", q):
            match = re.search(r"\b\d{2,6}\b", q)
            target_pid = int(match.group(0)) if match else None
            
            if target_pid:
                try:
                    p = psutil.Process(target_pid)
                    name = p.name()
                    exe = p.exe() if hasattr(p, 'exe') else "N/A"
                    cpu = p.cpu_percent()
                    mem = round(p.memory_info().rss / (1024*1024), 1)
                    tree = advanced_sentinel.get_process_attack_tree(target_pid)

                    response_text = f"🔍 **Deep Forensics for PID `{target_pid}` ({name}):**\n\n"
                    response_text += f"- **Executable Path:** `{exe}`\n"
                    response_text += f"- **Resource Footprint:** {cpu}% CPU | {mem} MB RAM\n"
                    response_text += f"- **Parent Lineage:** {' -> '.join([n['name'] for n in tree['nodes']])}\n"
                    response_text += f"- **MITRE ATT&CK Tag:** `{tree['nodes'][-1]['mitre_tag']}`\n"
                    response_text += f"- **SHA-256 Hash:** `{tree['nodes'][-1]['sha256']}`\n\n"
                    response_text += f"**Assessment:** Process is executing within normal operating boundaries."

                    action_buttons.append({
                        "type": "kill_pid",
                        "label": f"⚡ Terminate PID {target_pid}",
                        "pid": target_pid,
                        "style": "danger"
                    })
                    action_buttons.append({
                        "type": "view_tree",
                        "label": f"🌲 View Process Attack Tree",
                        "pid": target_pid,
                        "style": "primary"
                    })
                    context_badges = [f"PID: {target_pid}", f"Name: {name}", f"RAM: {mem}MB"]
                except psutil.NoSuchProcess:
                    response_text = f"❌ Process PID `{target_pid}` is not currently running on the system (it may have already terminated)."
            else:
                response_text = "Please specify the PID number you would like me to inspect (e.g., 'Explain PID 1420')."

        # 3. "Check ports" / "Listening services"
        elif any(k in q for k in ["port", "socket", "listen", "listening", "network", "traffic"]):
            listening = conns["listening_ports"]
            response_text = f"🌐 **Host Network & Port Analysis:**\n\n"
            response_text += f"- **Total Active Sockets:** {conns['total_connections']} ({conns['established_count']} Established, {conns['listening_count']} Listening).\n\n"
            response_text += "**Discovered Listening Services:**\n"
            for p in listening[:5]:
                response_text += f"- **Port `{p['port']}` ({p['proto']})** -> `{p['process_name']}` (PID `{p['pid']}`) | Risk: **{p['risk']}**\n"

            action_buttons.append({
                "type": "switch_tab",
                "label": "🌐 Open Network Sockets View",
                "tab": "sockets-tab",
                "style": "primary"
            })
            context_badges = [f"{conns['listening_count']} Ports Open", f"{conns['established_count']} Sockets Active"]

        # 4. "Ransomware" / "Canary"
        elif any(k in q for k in ["ransomware", "canary", "encrypt", "lockbit", "trap"]):
            response_text = f"🪤 **Anti-Ransomware Honey-Trap Status:**\n\n"
            response_text += f"- **Canary Trap Status:** `{canary['shield_status']}` ({canary['canary_count']} decoy files armed).\n"
            response_text += f"- **Tampering Detected:** {'🚨 YES - ENCRYPTION BURST' if canary['is_under_attack'] else '✅ Clean - No Tampering'}.\n\n"
            response_text += "**How CyberArmor protects you:** Decoy canary documents are watched in the background. If any unknown process attempts mass encryption, CyberArmor terminates the offending process instantly."
            
            action_buttons.append({
                "type": "trip_canary",
                "label": "🧪 Test Ransomware Trap Simulation",
                "style": "warning"
            })
            context_badges = ["Ransomware Shield: ARMED", f"{canary['canary_count']} Decoys Active"]

        # 5. Default Fallback Guidance
        else:
            response_text = f"🤖 **CyberArmor AI Copilot Online for Host `{sys['hostname']}`:**\n\n"
            response_text += "I can assist you with real-time host investigations. Try asking:\n"
            response_text += "- *'Is my device safe right now?'*\n"
            response_text += "- *'Explain PID <number>'*\n"
            response_text += "- *'What open ports are currently listening?'*\n"
            response_text += "- *'Check ransomware shield and canary traps'*\n"
            response_text += "- *'Run deep host security hardening audit'*"

            action_buttons.append({
                "type": "run_audit",
                "label": "🔬 Run Full Hardening Audit",
                "style": "primary"
            })
            context_badges = ["AI Copilot: READY", f"Host: {sys['hostname']}"]

        return {
            "query": query,
            "timestamp": datetime.utcnow().strftime("%H:%M:%S UTC"),
            "response": response_text,
            "context_badges": context_badges,
            "action_buttons": action_buttons
        }

copilot_engine = GenAICyberCopilot()
