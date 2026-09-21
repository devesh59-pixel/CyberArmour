# 🛡️ CyberArmor EDR: Next-Gen Real-Time Device Security & Threat Defense Product

**CyberArmor EDR** is a full-featured, enterprise-grade **Endpoint Detection & Response (EDR), Host Hardening & Device Security Product**. It continuously monitors, audits, and secures the **actual host operating system, live running processes, network connections, Windows event logs, and server logs** in real time with AI.

---

## 🌟 Core Product Capabilities

### 1. ⚡ Live Process Sentinel & Process Manager
- **Live Process Monitoring**: Scans and profiles all real live running Windows processes (PID, CPU %, RAM %, User, Command-line args, Exe path).
- **AI Behavioral Risk Assessment**:
  - Detects executables launching from `%TEMP%`, `%APPDATA%`, or anomalous hidden paths.
  - Catches obfuscated command-line arguments (e.g. `powershell -enc`, `-nop -w hidden`, `certutil`, `bitsadmin`).
  - Heuristic detection for runaway crypto-miners and background CPU hogs.
  - Detects process masquerading (e.g. `svch0st.exe`, `lsasss.exe`).
- **Real Host Action**: 1-Click **Kill Process** by PID directly on Windows.

### 2. 🌐 Network Sockets & Port Armor
- **Live Socket Telemetry**: Maps real active TCP/UDP connections to their owning Process Name and PID.
- **Port Vulnerability Scanning**: Audits open listening ports on the host (RDP `3389`, SMB `445`, Telnet `23`, FTP `21`).
- **C2 & Backdoor Detection**: Flags connections to high-risk remote ports (e.g. Metasploit `4444`, Cobalt Strike `50050`, IRC `6667`).
- **Real Host Action**: 1-Click **Block Remote IP in Windows Defender Firewall** (`netsh advfirewall`).

### 3. 📜 Windows Event & Server Log Monitor
- **Direct Windows Event Log Feed**: Fetches and classifies real events from `System`, `Application`, and `Security` event log channels (Failed logons Event 4625, Service installations Event 7045, Process executions Event 4688).
- **Local Server Log File Tailer**: Point to any server log file on the machine (Apache, Nginx, Node, Python, IIS) with real-time log tailing and AI anomaly classification.

### 4. 🔬 System Hardening & Vulnerability Audit
- **Windows Defender Firewall State**: Checks Domain, Private, and Public network firewall profiles.
- **Startup Persistence Inspection**: Scans Windows Registry Run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `HKLM\...`) for suspicious autostart programs.
- **Temp Folder Dropper Scanner**: Scans `%TEMP%` for unsigned dropped binaries (`.exe`, `.bat`, `.ps1`, `.vbs`).
- **Device Health Score (0–100)**: Calculates dynamic security health grade with actionable 1-click remediation guidance.

### 5. 🔒 Active Firewall & Quarantine Vault
- **Firewall Rules Manager**: View and manage all active blocked IP rules enforced on Windows Defender Firewall.
- **Quarantine Isolation Vault**: Safely isolates suspicious files with `.locked` extensions in a secure sandbox vault.
- **Autonomous Host Shield Mode**: Configurable auto-quarantine for critical threat signatures.

### 6. 📊 Executive Security Compliance Report
- Generates a comprehensive, printable device security audit document containing hardware telemetry, vulnerability findings, top running processes, and compliance score.

---

## 🚀 Quick Start Guide

### Running the Application

Simply run:
```bash
python run.py
```
This will automatically:
1. Verify and load the pre-trained ML models.
2. Launch the CyberArmor FastAPI backend on `http://127.0.0.1:8008`.
3. Open the luxury CyberArmor EDR interface in your default browser.

---

## 📂 Project Architecture

```
c:\Users\deves\mini\
├── backend\
│   ├── app.py                     # FastAPI REST API & WebSocket Real-Time Device Feed
│   ├── device_monitor.py          # Real Windows Process & System Telemetry Engine
│   ├── network_monitor.py         # Real Sockets, Active Connections & Port Analyzer
│   ├── log_monitor.py             # Real Windows Event Log & Server Log File Tailer
│   ├── audit_engine.py            # Device Security Hardening & Vulnerability Auditor
│   ├── defense_handler.py         # Real Host Remediation (Kill PID, Windows Firewall, Quarantine)
│   ├── ml_engine.py               # AI/ML Threat Classification & XAI Engine
│   ├── train_models.py            # Pretrained ML weights
│   ├── test_detection.py          # ML Unit test suite
│   ├── test_device_e2e.py         # Real device EDR integration test suite
│   └── models/                    # Serialized AI models (.joblib)
├── frontend\
│   ├── index.html                 # CyberArmor EDR Commercial Product Interface
│   ├── css\
│   │   └── style.css              # Custom Luxury Cyber Glassmorphism Stylesheet
│   └── js\
│       ├── app.js                 # WebSocket Live Telemetry & Device Health State
│       ├── device_views.js        # Process Manager, Network Sockets & System Audit Handlers
│       └── log_viewer.js          # Windows Event Log & Server Log Real-Time Viewer
├── sample_logs.csv                # Sample log file for instant drag-and-drop testing
├── run.py                         # Single-command application launcher
└── README.md                      # Documentation
```

---

## 🧪 Verification & Testing

To test the real device security subsystems:
```bash
python backend/test_device_e2e.py
```
To test the ML threat detection engine:
```bash
python backend/test_detection.py
```
