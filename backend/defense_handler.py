import os
import shutil
import subprocess
import winreg
import psutil
from datetime import datetime
from typing import Dict, Any, List, Optional

QUARANTINE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".quarantine"))
os.makedirs(QUARANTINE_DIR, exist_ok=True)

class DefenseMatrixManager:
    """
    Active Defense and Host OS Remediation Engine.
    Executes real process termination, Windows Firewall blocking/unblocking,
    file quarantine isolation, and registry cleaning.
    """
    def __init__(self):
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.quarantined_files: List[Dict[str, Any]] = []
        self.mitigation_history: List[Dict[str, Any]] = []
        self.auto_shield_enabled: bool = False
        self.stats = {
            "total_threats_neutralized": 0,
            "firewall_rules_active": 0,
            "quarantined_files_count": 0,
            "processes_killed_count": 0
        }

    def kill_process(self, pid: int, reason: str = "Hostile/Abnormal behavior detected") -> Dict[str, Any]:
        """Terminates a process on the host OS by PID."""
        now = datetime.utcnow().isoformat() + "Z"
        try:
            proc = psutil.Process(pid)
            p_name = proc.name()
            proc.kill()
            
            record = {
                "id": f"MIT-PROC-{len(self.mitigation_history)+1:04d}",
                "action": "PROCESS_KILL",
                "target": f"{p_name} (PID: {pid})",
                "reason": reason,
                "timestamp": now,
                "status": "SUCCESS"
            }
            self.mitigation_history.insert(0, record)
            self.stats["total_threats_neutralized"] += 1
            self.stats["processes_killed_count"] += 1
            return {"status": "SUCCESS", "message": f"Process '{p_name}' (PID: {pid}) was terminated."}
        except psutil.NoSuchProcess:
            return {"status": "NOT_FOUND", "message": f"Process PID {pid} does not exist or has already exited."}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def block_ip(self, ip: str, reason: str = "Hostile threat activity detected", threat_type: str = "Remote Threat", auto_action: bool = False) -> Dict[str, Any]:
        """Blocks an IP address on Windows Defender Firewall using netsh."""
        now = datetime.utcnow().isoformat() + "Z"
        
        # Execute real Windows Defender Firewall Rule
        rule_name = f"CyberArmor_Block_{ip.replace('.', '_')}"
        try:
            # Add inbound block rule
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}_IN", "dir=in", "action=block", f"remoteip={ip}"],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Add outbound block rule
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}_OUT", "dir=out", "action=block", f"remoteip={ip}"],
                capture_output=True,
                text=True,
                timeout=5
            )
        except Exception as e:
            print(f"[DefenseHandler] Warning executing firewall command: {e}")

        entry = {
            "ip": ip,
            "rule_name": rule_name,
            "reason": reason,
            "threat_type": threat_type,
            "blocked_at": now,
            "auto_blocked": auto_action,
            "status": "ENFORCED_IN_FIREWALL"
        }
        self.blocked_ips[ip] = entry
        
        mitigation_record = {
            "id": f"MIT-FW-{len(self.mitigation_history)+1:04d}",
            "action": "FIREWALL_DROP",
            "target": ip,
            "threat_type": threat_type,
            "timestamp": now,
            "auto": auto_action,
            "status": "SUCCESS"
        }
        self.mitigation_history.insert(0, mitigation_record)
        self.stats["total_threats_neutralized"] += 1
        self.stats["firewall_rules_active"] = len(self.blocked_ips)
        
        return entry

    def unblock_ip(self, ip: str) -> bool:
        """Removes an IP block rule from Windows Defender Firewall."""
        if ip in self.blocked_ips:
            rule_name = self.blocked_ips[ip].get("rule_name", f"CyberArmor_Block_{ip.replace('.', '_')}")
            try:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_IN"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_OUT"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            except Exception as e:
                print(f"[DefenseHandler] Warning removing firewall rule: {e}")

            del self.blocked_ips[ip]
            self.stats["firewall_rules_active"] = len(self.blocked_ips)
            return True
        return False

    def quarantine_file(self, file_path: str, reason: str = "Suspicious binary detected") -> Dict[str, Any]:
        """Moves a malicious binary into the isolated quarantine vault."""
        if not os.path.exists(file_path):
            return {"status": "NOT_FOUND", "message": f"File '{file_path}' not found on disk."}

        try:
            filename = os.path.basename(file_path)
            now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            quarantine_target = os.path.join(QUARANTINE_DIR, f"{filename}_{now}.locked")
            
            shutil.move(file_path, quarantine_target)
            
            entry = {
                "original_path": file_path,
                "filename": filename,
                "quarantine_path": quarantine_target,
                "quarantined_at": datetime.utcnow().isoformat() + "Z",
                "reason": reason,
                "status": "ISOLATED"
            }
            self.quarantined_files.append(entry)
            self.stats["quarantined_files_count"] = len(self.quarantined_files)
            self.stats["total_threats_neutralized"] += 1
            return {"status": "SUCCESS", "entry": entry}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def remove_startup_key(self, registry_location: str, name: str) -> Dict[str, Any]:
        """Removes a persistence Run key from the Windows Registry."""
        try:
            root = winreg.HKEY_CURRENT_USER if "HKCU" in registry_location else winreg.HKEY_LOCAL_MACHINE
            subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
            
            key = winreg.OpenKey(root, subkey, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            return {"status": "SUCCESS", "message": f"Startup registry entry '{name}' removed."}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def toggle_auto_shield(self, enabled: bool) -> bool:
        self.auto_shield_enabled = enabled
        return self.auto_shield_enabled

    def generate_firewall_script(self, ip: str, os_type: str = "windows") -> str:
        """Generates ready-to-run firewall rules."""
        if os_type == "windows":
            return f"""# Windows Defender Firewall Rule (Run in Administrator PowerShell)
netsh advfirewall firewall add rule name="CyberArmor_Block_{ip}_IN" dir=in action=block remoteip={ip}
netsh advfirewall firewall add rule name="CyberArmor_Block_{ip}_OUT" dir=out action=block remoteip={ip}
Write-Host "[CyberArmor] Remote Host {ip} blocked at Windows Defender Firewall."
"""
        else:
            return f"""# Linux iptables Rule
sudo iptables -I INPUT 1 -s {ip} -j DROP
sudo iptables -I OUTPUT 1 -d {ip} -j DROP
echo "[CyberArmor] Host {ip} dropped."
"""

    def get_remediation_playbook(self, threat_type: str) -> Dict[str, Any]:
        """Provides human-readable remediation instructions."""
        from backend.ml_engine import MITRE_MAPPING
        mitre = MITRE_MAPPING.get(threat_type, MITRE_MAPPING["Normal"])
        return {
            "title": f"{threat_type} Remediation Playbook",
            "technique_id": mitre["id"],
            "tactic": mitre["tactic"],
            "description": mitre["desc"],
            "steps": [
                "1. Terminate any associated suspicious process using the Process Sentinel.",
                "2. Enforce Windows Firewall quarantine for the remote attacker IP.",
                "3. Inspect Windows Event Log 4688 to audit process execution lineage.",
                "4. Check Registry Run keys to ensure no persistence mechanism was left behind."
            ]
        }

defense_matrix = DefenseMatrixManager()
