import os
import time
import socket
import platform
import psutil
from datetime import datetime
from typing import Dict, Any, List, Optional

class DeviceMonitor:
    """
    Real-time Device and Process Telemetry Engine for Windows.
    Gathers live process telemetry, evaluates process behavioral risks with AI heuristics,
    and monitors hardware resources.
    """
    def __init__(self):
        self.hostname = socket.gethostname()
        self.os_info = f"{platform.system()} {platform.release()} ({platform.version()})"
        self.boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        self.ip_address = self._get_primary_ip()

    def _get_primary_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def get_system_overview(self) -> Dict[str, Any]:
        """Returns real live CPU, RAM, Disk, Uptime, and Host Metadata."""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net_io = psutil.net_io_counters()

        return {
            "hostname": self.hostname,
            "os": self.os_info,
            "boot_time": self.boot_time,
            "ip_address": self.ip_address,
            "cpu_percent": round(cpu_percent, 1),
            "cpu_count": psutil.cpu_count(logical=True),
            "ram_total_gb": round(mem.total / (1024**3), 2),
            "ram_used_gb": round(mem.used / (1024**3), 2),
            "ram_percent": mem.percent,
            "disk_total_gb": round(disk.total / (1024**3), 2),
            "disk_used_gb": round(disk.used / (1024**3), 2),
            "disk_percent": disk.percent,
            "bytes_sent_mb": round(net_io.bytes_sent / (1024**2), 2),
            "bytes_recv_mb": round(net_io.bytes_recv / (1024**2), 2),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def get_running_processes(self, limit: int = 150) -> List[Dict[str, Any]]:
        """
        Scans all real live running processes on the host and runs behavioral AI risk analysis.
        """
        processes = []
        suspicious_paths = ["\\appdata\\local\\temp", "\\temp\\", "\\appdata\\roaming", "\\public\\"]
        suspicious_keywords = ["powershell -enc", "-nop -w hidden", "mimikatz", "certutil -urlcache", "bitsadmin", "vssadmin delete shadows", "xmrig", "cryptominer"]

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent', 'status', 'create_time', 'username']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name'] or 'unknown'
                exe = info['exe'] or ''
                cmdline = " ".join(info['cmdline']) if info['cmdline'] else ''
                cpu = info['cpu_percent'] or 0.0
                mem = round(info['memory_percent'] or 0.0, 2)
                user = info['username'] or 'SYSTEM'
                
                # Behavioral Risk Assessment
                risk_level = "LOW"
                risk_score = 5
                risk_reasons = []

                exe_lower = exe.lower()
                cmd_lower = cmdline.lower()

                # 1. Path Anomaly (Running from Temp or Roaming directories)
                if any(p in exe_lower for p in suspicious_paths):
                    risk_level = "HIGH"
                    risk_score += 45
                    risk_reasons.append(f"Executable running from temporary directory: {exe}")

                # 2. Obfuscated / Dangerous Command-Line Arguments
                for kw in suspicious_keywords:
                    if kw in cmd_lower:
                        risk_level = "CRITICAL"
                        risk_score += 60
                        risk_reasons.append(f"Detected suspicious command-line signature: '{kw}'")

                # 3. High CPU Crypto-Mining Heuristic
                if cpu > 80.0 and name.lower() not in ["chrome.exe", "msedge.exe", "code.exe", "python.exe", "devenv.exe", "game.exe"]:
                    if risk_level != "CRITICAL":
                        risk_level = "HIGH"
                    risk_score += 30
                    risk_reasons.append(f"Sustained extreme CPU consumption ({cpu:.1f}%) indicative of cryptomining or runaway rogue process")

                # 4. Masquerading or Double Extension
                if name.lower().endswith(".exe.exe") or name.lower() in ["svch0st.exe", "lsasss.exe", "csrsss.exe"]:
                    risk_level = "CRITICAL"
                    risk_score = 99
                    risk_reasons.append(f"Masquerading system process name: {name}")

                if risk_score > 90:
                    risk_level = "CRITICAL"
                elif risk_score >= 40:
                    risk_level = "HIGH"
                elif risk_score >= 20:
                    risk_level = "MEDIUM"

                processes.append({
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "cmdline": cmdline[:150] + ("..." if len(cmdline) > 150 else ""),
                    "cpu_percent": round(cpu, 1),
                    "memory_percent": mem,
                    "username": user,
                    "status": info['status'],
                    "created_at": datetime.fromtimestamp(info['create_time']).strftime("%H:%M:%S") if info['create_time'] else "N/A",
                    "risk_level": risk_level,
                    "risk_score": min(100, risk_score),
                    "risk_reasons": risk_reasons if risk_reasons else ["Normal system process footprint"]
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Sort: Highest risk first, then highest CPU
        processes.sort(key=lambda x: (x["risk_score"], x["cpu_percent"]), reverse=True)
        return processes[:limit]

    def kill_process(self, pid: int) -> Dict[str, Any]:
        """Safely terminates a process on the host OS by PID."""
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            proc.terminate()
            proc.wait(timeout=2.0)
            return {"status": "SUCCESS", "message": f"Process '{name}' (PID: {pid}) was successfully terminated."}
        except psutil.NoSuchProcess:
            return {"status": "NOT_FOUND", "message": f"Process PID {pid} does not exist or has already exited."}
        except psutil.AccessDenied:
            return {"status": "ACCESS_DENIED", "message": f"Access denied when trying to terminate PID {pid}. Administrator rights required."}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

device_monitor = DeviceMonitor()
