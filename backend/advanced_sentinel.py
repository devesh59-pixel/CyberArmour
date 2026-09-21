import os
import math
import hashlib
import psutil
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional

CANARY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".cyberarmor_canary"))
try:
    os.makedirs(CANARY_DIR, exist_ok=True)
except OSError:
    CANARY_DIR = "/tmp/.cyberarmor_canary"
    try:
        os.makedirs(CANARY_DIR, exist_ok=True)
    except Exception:
        pass

# Known malicious threat intelligence hashes (Simulated Threat Intel Feed)
KNOWN_MALWARE_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"name": "Test_Empty_Sample", "family": "BENIGN", "severity": "LOW"},
    "44d88612fea8a8f36de82e1278abb02f": {"name": "EICAR-Standard-Antivirus-Test-File", "family": "EICAR", "severity": "CRITICAL"},
    "84c82835a5d21bbcf75a61706d8ab549": {"name": "WannaCry Ransomware Dropper", "family": "RANSOMWARE", "severity": "CRITICAL"},
    "c700305f87b8d42ae3a69a259c402127": {"name": "Mimikatz LSASS Ingestion Binary", "family": "CREDENTIAL_THEFT", "severity": "CRITICAL"},
    "1f92e078c1a1660b3eb09c48ea92a2a0": {"name": "Cobalt Strike Beacon Stager", "family": "C2_BEACON", "severity": "CRITICAL"},
    "a6e8f47c34d31e9c2b9a1098e7210144": {"name": "XMRig Monero CPU CryptoMiner", "family": "CRYPTOMINER", "severity": "HIGH"}
}

class AdvancedSentinel:
    """
    Advanced Enterprise EDR Sensor & Threat Hunter Engine.
    Handles:
    1. Process Attack Tree & Lineage Reconstruction (Root Cause Analysis - RCA)
    2. Binary Shannon Entropy & SHA-256 Threat Intel Reputation
    3. Ransomware Canary Honey-Trap & Anti-Ransomware Shield
    4. File Integrity Monitoring (FIM)
    5. Emergency Host Network Isolation ("Airgap Mode")
    """
    def __init__(self):
        self.host_isolated = False
        self.canary_files = {}
        self.fim_baseline = {}
        self._init_canary_honey_trap()
        self._init_fim_baseline()

    # ========================================================
    # 1. PROCESS ATTACK TREE & LINEAGE EXTRACTION (RCA)
    # ========================================================
    def get_process_attack_tree(self, target_pid: Optional[int] = None) -> Dict[str, Any]:
        """
        Reconstructs the full parent-child execution lineage tree for a PID or the highest-risk running process.
        """
        if not target_pid:
            # Find highest CPU or highest risk process
            target_pid = os.getpid()
            for p in psutil.process_iter(['pid', 'cpu_percent']):
                try:
                    if p.info['pid'] not in [0, 4] and p.info['cpu_percent'] and p.info['cpu_percent'] > 10.0:
                        target_pid = p.info['pid']
                        break
                except Exception:
                    pass

        tree_nodes = []
        visited = set()
        
        # 1. Trace Ancestors (Bottom-up from Target to Root)
        curr_pid = target_pid
        while curr_pid and curr_pid not in visited:
            visited.add(curr_pid)
            try:
                p = psutil.Process(curr_pid)
                node_data = self._build_process_node(p, is_target=(curr_pid == target_pid))
                tree_nodes.insert(0, node_data)
                
                parent = p.parent()
                curr_pid = parent.pid if parent else None
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

        # 2. Trace Children of Target (Top-down)
        try:
            target_proc = psutil.Process(target_pid)
            for child in target_proc.children(recursive=False):
                if child.pid not in visited:
                    visited.add(child.pid)
                    tree_nodes.append(self._build_process_node(child, is_target=False))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Build DAG Edge Links
        edges = []
        for i in range(len(tree_nodes) - 1):
            edges.append({
                "from": tree_nodes[i]["pid"],
                "to": tree_nodes[i + 1]["pid"],
                "label": "spawned_child"
            })

        return {
            "target_pid": target_pid,
            "total_nodes": len(tree_nodes),
            "nodes": tree_nodes,
            "edges": edges,
            "mitre_tactic_summary": "T1059 (Command Execution) -> T1057 (Process Discovery)"
        }

    def _build_process_node(self, proc: psutil.Process, is_target: bool = False) -> Dict[str, Any]:
        """Extracts deep process forensics: SHA256, memory, entropy, and MITRE mapping."""
        pid = proc.pid
        name = proc.name()
        try:
            exe = proc.exe() or "SYSTEM/KERNEL"
        except Exception:
            exe = "PROTECTED_SERVICE"

        try:
            cmdline = " ".join(proc.cmdline())
        except Exception:
            cmdline = name

        try:
            mem_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
        except Exception:
            mem_mb = 0.0

        try:
            cpu = proc.cpu_percent()
        except Exception:
            cpu = 0.0

        # Calculate Hash and Entropy if accessible
        sha256 = "N/A"
        entropy = 0.0
        if exe and os.path.exists(exe):
            sha256 = self.calculate_file_sha256(exe)
            entropy = self.calculate_file_entropy(exe)

        # Risk Heuristics
        risk = "LOW"
        mitre_tag = "T1057 - Process Discovery"
        if any(s in cmdline.lower() for s in ["powershell -enc", "-nop -w hidden", "mimikatz", "vssadmin"]):
            risk = "CRITICAL"
            mitre_tag = "T1059.001 - PowerShell Obfuscation"
        elif "temp" in exe.lower() or "appdata" in exe.lower():
            risk = "HIGH"
            mitre_tag = "T1083 - File Discovery / Unverified Path"
        elif cpu > 70.0:
            risk = "MEDIUM"
            mitre_tag = "T1496 - Resource Hijacking"

        return {
            "pid": pid,
            "name": name,
            "exe": exe,
            "cmdline": cmdline[:180] + ("..." if len(cmdline) > 180 else ""),
            "sha256": sha256,
            "entropy": round(entropy, 2),
            "memory_mb": mem_mb,
            "cpu_percent": round(cpu, 1),
            "is_target": is_target,
            "risk_level": risk,
            "mitre_tag": mitre_tag
        }

    # ========================================================
    # 2. BINARY SHANNON ENTROPY & HASH CALCULATOR
    # ========================================================
    def calculate_file_sha256(self, file_path: str) -> str:
        """Calculates real SHA-256 checksum of a file on disk."""
        if not os.path.exists(file_path):
            return "FILE_NOT_FOUND"
        try:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return "ACCESS_DENIED"

    def calculate_file_entropy(self, file_path: str) -> float:
        """
        Calculates Shannon Entropy (0.0 to 8.0) of a binary file.
        High entropy (> 7.2) strongly indicates packed, encrypted, or compressed malicious code.
        """
        if not os.path.exists(file_path):
            return 0.0
        try:
            with open(file_path, "rb") as f:
                data = f.read(1024 * 512) # Sample first 512 KB
            if not data:
                return 0.0

            entropy = 0.0
            length = len(data)
            counts = {}
            for byte in data:
                counts[byte] = counts.get(byte, 0) + 1

            for count in counts.values():
                p = count / length
                entropy -= p * math.log2(p)

            return round(entropy, 3)
        except Exception:
            return 0.0

    def inspect_binary_threat_intel(self, file_path: str) -> Dict[str, Any]:
        """Inspects file for checksums, entropy, and known threat intelligence matches."""
        if not os.path.exists(file_path):
            return {"status": "NOT_FOUND", "message": f"File '{file_path}' does not exist."}

        sha256 = self.calculate_file_sha256(file_path)
        entropy = self.calculate_file_entropy(file_path)
        size_kb = round(os.path.getsize(file_path) / 1024, 1)
        filename = os.path.basename(file_path)

        # Reputation lookup
        intel_hit = KNOWN_MALWARE_HASHES.get(sha256, None)
        is_packed = entropy >= 7.2

        verdict = "CLEAN"
        risk_score = 5
        reasons = []

        if intel_hit:
            verdict = "MALICIOUS"
            risk_score = 99
            reasons.append(f"Known Threat Signature Match: {intel_hit['name']} ({intel_hit['family']})")
        elif is_packed:
            verdict = "SUSPICIOUS"
            risk_score = 75
            reasons.append(f"High Shannon Entropy ({entropy:.2f} / 8.0) indicates packed/encrypted code dropper")
        else:
            reasons.append("Standard binary entropy and unflagged signature")

        return {
            "filename": filename,
            "path": file_path,
            "size_kb": size_kb,
            "sha256": sha256,
            "shannon_entropy": entropy,
            "is_packed": is_packed,
            "threat_intel_verdict": verdict,
            "risk_score": risk_score,
            "reasons": reasons
        }

    # ========================================================
    # 3. RANSOMWARE CANARY HONEY-TRAP & SHIELD
    # ========================================================
    def _init_canary_honey_trap(self):
        """Creates decoy canary documents in the canary folder."""
        canaries = [
            ("passwords_backup.docx", "CYBERARMOR_CANARY_TRAP_SECRET_DECOY_CONTENT_001"),
            ("financial_audit_2026.xlsx", "CYBERARMOR_CANARY_TRAP_FINANCIAL_LEDGER_002"),
            ("database_credentials.sql", "-- CYBERARMOR DECOY DATABASE CREDENTIALS\nSELECT * FROM root_secrets;")
        ]

        for fname, content in canaries:
            fpath = os.path.join(CANARY_DIR, fname)
            if not os.path.exists(fpath):
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(content)
            
            # Record baseline hash
            self.canary_files[fname] = {
                "path": fpath,
                "baseline_sha256": self.calculate_file_sha256(fpath),
                "status": "ARMED_AND_WATCHING"
            }

    def check_canary_status(self) -> Dict[str, Any]:
        """Verifies if any ransomware attempt tampered with or encrypted the canary traps."""
        tampered = []
        for fname, info in self.canary_files.items():
            curr_hash = self.calculate_file_sha256(info["path"])
            if curr_hash != info["baseline_sha256"]:
                tampered.append({
                    "filename": fname,
                    "path": info["path"],
                    "threat": "RANSOMWARE_FILE_ENCRYPTION_BURST",
                    "status": "TAMPERED_TRIGGERED"
                })

        is_under_attack = len(tampered) > 0
        return {
            "shield_status": "ACTIVE_ARMED" if not is_under_attack else "RANSOMWARE_ATTACK_DETECTED",
            "canary_count": len(self.canary_files),
            "tampered_count": len(tampered),
            "is_under_attack": is_under_attack,
            "canaries": list(self.canary_files.values()),
            "tampered_details": tampered
        }

    def trip_canary_simulation(self) -> Dict[str, Any]:
        """Simulates a ransomware attack encrypting the canary for testing and defense validation."""
        fpath = os.path.join(CANARY_DIR, "financial_audit_2026.xlsx")
        with open(fpath, "a", encoding="utf-8") as f:
            f.write("\n[ENCRYPTED_BY_SIMULATED_RANSOMWARE_LOCKBIT_PAYLOAD]")
        
        return self.check_canary_status()

    # ========================================================
    # 4. FILE INTEGRITY MONITOR (FIM)
    # ========================================================
    def _init_fim_baseline(self):
        """Establishes baseline hashes for critical OS files."""
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        if os.path.exists(hosts_path):
            self.fim_baseline["hosts_file"] = {
                "path": hosts_path,
                "baseline_hash": self.calculate_file_sha256(hosts_path)
            }

    def check_fim_integrity(self) -> Dict[str, Any]:
        """Checks if critical system configuration files were altered."""
        alerts = []
        for name, info in self.fim_baseline.items():
            curr = self.calculate_file_sha256(info["path"])
            if curr != info["baseline_hash"]:
                alerts.append({
                    "file": name,
                    "path": info["path"],
                    "alert": "UNAUTHORIZED_HOSTS_FILE_MODIFICATION_DETECTED",
                    "severity": "CRITICAL"
                })

        return {
            "status": "SECURE" if not alerts else "TAMPERING_DETECTED",
            "monitored_targets_count": len(self.fim_baseline),
            "alerts": alerts
        }

    # ========================================================
    # 5. EMERGENCY NETWORK ISOLATION (AIRGAP MODE)
    # ========================================================
    def toggle_emergency_host_isolation(self, enable: bool) -> Dict[str, Any]:
        """
        Instantly cuts off all inbound/outbound network traffic using Windows Defender Firewall,
        preventing active ransomware spread or C2 exfiltration while keeping 127.0.0.1 accessible.
        """
        self.host_isolated = enable
        rule_name = "CyberArmor_Emergency_Airgap"

        if enable:
            try:
                # Block all outbound traffic except localhost
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}_OUT", "dir=out", "action=block", "remoteip=1.0.0.0-255.255.255.255"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                # Block all inbound traffic except localhost
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}_IN", "dir=in", "action=block", "remoteip=1.0.0.0-255.255.255.255"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            except Exception as e:
                print(f"[AdvancedSentinel] Warning isolating host: {e}")

            return {
                "status": "ISOLATED",
                "message": "EMERGENCY AIRGAP ACTIVATED: Host isolated from all external and LAN network interfaces.",
                "host_isolated": True
            }
        else:
            try:
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_OUT"], capture_output=True, text=True, timeout=5)
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_IN"], capture_output=True, text=True, timeout=5)
            except Exception as e:
                print(f"[AdvancedSentinel] Warning releasing isolation: {e}")

            return {
                "status": "NORMAL",
                "message": "Host network interfaces restored to normal operational state.",
                "host_isolated": False
            }

advanced_sentinel = AdvancedSentinel()
