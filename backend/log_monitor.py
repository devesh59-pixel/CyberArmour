import os
import subprocess
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

class LogMonitor:
    """
    Real-Time Host Windows Event Log and Server Log File Inspection Engine.
    Fetches real Windows Event logs (Security, System, Application) and tails local log files.
    """
    def __init__(self):
        pass

    def get_windows_event_logs(self, log_name: str = "System", max_events: int = 50) -> List[Dict[str, Any]]:
        """
        Extracts real recent Windows Event Logs using PowerShell Get-WinEvent.
        """
        # Supported logs: System, Application, Security
        valid_logs = ["System", "Application", "Security"]
        target_log = log_name if log_name in valid_logs else "System"

        ps_cmd = f"""
        try {{
            $events = Get-WinEvent -LogName '{target_log}' -MaxEvents {max_events} -ErrorAction SilentlyContinue | ForEach-Object {{
                [PSCustomObject]@{{
                    Id = $_.Id
                    TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    LevelDisplayName = $_.LevelDisplayName
                    ProviderName = $_.ProviderName
                    Message = ($_.Message -split "`r`n")[0]
                    MachineName = $_.MachineName
                }}
            }}
            $events | ConvertTo-Json -Compress
        }} catch {{
            "[]"
        }}
        """
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=8
            )
            raw_output = res.stdout.strip()
            if not raw_output:
                return []

            parsed = json.loads(raw_output)
            if isinstance(parsed, dict):
                parsed = [parsed]

            formatted_events = []
            for ev in parsed:
                lvl = ev.get("LevelDisplayName", "Information") or "Information"
                event_id = ev.get("Id", 0)
                msg = ev.get("Message", "") or f"Windows Event ID {event_id}"
                
                # Risk heuristics
                risk_level = "LOW"
                if lvl in ["Error", "Critical"] or event_id in [4625, 7045, 1102]:
                    risk_level = "HIGH" if event_id != 4625 else "CRITICAL"
                elif lvl == "Warning":
                    risk_level = "MEDIUM"

                formatted_events.append({
                    "event_id": event_id,
                    "timestamp": ev.get("TimeCreated", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
                    "log_source": target_log,
                    "provider": ev.get("ProviderName", "Microsoft-Windows"),
                    "level": lvl,
                    "risk_level": risk_level,
                    "summary": msg[:180] + ("..." if len(msg) > 180 else "")
                })

            return formatted_events
        except Exception as e:
            print(f"[LogMonitor] Error retrieving {target_log} events: {e}")
            return []

    def tail_local_file(self, file_path: str, max_lines: int = 100) -> Dict[str, Any]:
        """
        Tails and analyzes lines from any real local server or application log file.
        """
        if not os.path.exists(file_path):
            return {"status": "ERROR", "message": f"Log file '{file_path}' does not exist on disk."}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                recent_lines = lines[-max_lines:] if len(lines) > max_lines else lines

            records = []
            threat_count = 0

            for line in recent_lines:
                text = line.strip()
                if not text:
                    continue

                is_suspicious = False
                sev = "INFO"
                
                lower = text.lower()
                if any(k in lower for k in ["error", "fatal", "exception", "unhandled"]):
                    sev = "ERROR"
                elif any(k in lower for k in ["warn", "unauthorized", "forbidden"]):
                    sev = "WARNING"

                if any(k in lower for k in ["select", "union", "<script", "../", "; cat", "powershell -enc", "mimikatz"]):
                    is_suspicious = True
                    sev = "CRITICAL"
                    threat_count += 1

                records.append({
                    "line": text,
                    "level": sev,
                    "threat_detected": is_suspicious
                })

            return {
                "status": "SUCCESS",
                "file_path": file_path,
                "total_lines_read": len(recent_lines),
                "threats_flagged": threat_count,
                "records": records
            }
        except Exception as e:
            return {"status": "ERROR", "message": f"Failed reading log file: {str(e)}"}

log_monitor = LogMonitor()
