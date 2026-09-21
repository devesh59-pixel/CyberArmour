import psutil
import socket
from typing import Dict, Any, List
from datetime import datetime

# Known high-risk or commonly exploited ports
RISK_PORTS = {
    4444: ("Metasploit Default C2 Port", "CRITICAL"),
    1337: ("Hacker Backdoor / Elite Port", "HIGH"),
    6667: ("IRC Botnet Control Port", "HIGH"),
    50050: ("Cobalt Strike Team Server Port", "CRITICAL"),
    3389: ("RDP Remote Desktop (Exposed Service)", "MEDIUM"),
    445: ("SMB Windows File Sharing (WannaCry/EternalBlue Vector)", "HIGH"),
    135: ("RPC Endpoint Mapper", "MEDIUM"),
    21: ("FTP Unencrypted File Transfer", "LOW"),
    23: ("Telnet Insecure Remote Shell", "HIGH")
}

class NetworkMonitor:
    """
    Real-Time Host Network Socket & Port Inspection Engine.
    Inspects live TCP/UDP sockets, resolves process ownership, and flags malicious remote connections.
    """
    def __init__(self):
        pass

    def get_active_connections(self, limit: int = 150) -> Dict[str, Any]:
        """
        Gathers all real live active network sockets on the host machine.
        """
        connections = []
        listening_ports = []
        
        # Build PID to Name cache for speed
        pid_map = {}
        for p in psutil.process_iter(['pid', 'name']):
            try:
                pid_map[p.info['pid']] = p.info['name']
            except Exception:
                pass

        try:
            raw_conns = psutil.net_connections(kind='inet')
        except Exception:
            raw_conns = []

        total_established = 0
        total_listening = 0
        threat_sockets_found = 0

        for c in raw_conns:
            try:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "0.0.0.0:0"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                r_ip = c.raddr.ip if c.raddr else ""
                r_port = c.raddr.port if c.raddr else 0
                l_port = c.laddr.port if c.laddr else 0
                
                status = c.status
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                pid = c.pid or 0
                proc_name = pid_map.get(pid, "SYSTEM" if pid == 4 else "Unknown")

                if status == "ESTABLISHED":
                    total_established += 1
                elif status == "LISTEN":
                    total_listening += 1
                    listening_ports.append({
                        "port": l_port,
                        "proto": proto,
                        "pid": pid,
                        "process_name": proc_name,
                        "bind_ip": c.laddr.ip if c.laddr else "0.0.0.0",
                        "risk": "HIGH" if l_port in [3389, 445, 23] else "LOW"
                    })

                # Risk Analysis
                risk_level = "LOW"
                risk_desc = "Standard network connection"

                if r_port in RISK_PORTS:
                    desc, sev = RISK_PORTS[r_port]
                    risk_level = sev
                    risk_desc = f"Remote port {r_port} is known: {desc}"
                    threat_sockets_found += 1
                elif l_port in RISK_PORTS and status == "LISTEN":
                    desc, sev = RISK_PORTS[l_port]
                    risk_level = sev
                    risk_desc = f"Listening on sensitive port {l_port}: {desc}"
                    threat_sockets_found += 1

                # Flag non-standard outbound connections from system processes
                if r_ip and not (r_ip.startswith("127.") or r_ip.startswith("192.168.") or r_ip.startswith("10.") or r_ip.startswith("172.")):
                    if r_port not in [80, 443, 8080, 53, 123] and risk_level == "LOW":
                        risk_level = "MEDIUM"
                        risk_desc = f"Outbound connection to non-standard remote port {r_port}"

                connections.append({
                    "proto": proto,
                    "local_address": laddr,
                    "remote_address": raddr,
                    "remote_ip": r_ip,
                    "remote_port": r_port,
                    "status": status,
                    "pid": pid,
                    "process_name": proc_name,
                    "risk_level": risk_level,
                    "risk_desc": risk_desc
                })
            except Exception:
                continue

        # Sort: Highest risk first
        risk_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        connections.sort(key=lambda x: risk_weights.get(x["risk_level"], 0), reverse=True)

        return {
            "total_connections": len(connections),
            "established_count": total_established,
            "listening_count": total_listening,
            "threat_sockets_found": threat_sockets_found,
            "connections": connections[:limit],
            "listening_ports": listening_ports[:50]
        }

network_monitor = NetworkMonitor()
