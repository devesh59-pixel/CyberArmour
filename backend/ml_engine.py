import os
import re
import math
import joblib
import numpy as np
from typing import Dict, Any, List, Tuple
from datetime import datetime

# Path to serialized models directory
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")

# MITRE ATT&CK Mapping dictionary
MITRE_MAPPING = {
    "DDoS": {"id": "T1498", "tactic": "Impact", "name": "Network Denial of Service", "desc": "Flooding network bandwidth or connection tables to deny legitimate access."},
    "DoS": {"id": "T1499", "tactic": "Impact", "name": "Endpoint Denial of Service", "desc": "Overwhelming server CPU/RAM with malformed or excessive requests."},
    "Brute Force": {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force", "desc": "Systematic guessing of credentials via automated dictionary or credential stuffing."},
    "Port Scan": {"id": "T1046", "tactic": "Discovery", "name": "Network Service Discovery", "desc": "Probing target host ports to identify open listening services and vulnerabilities."},
    "SQL Injection": {"id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application (SQLi)", "desc": "Manipulating backend database queries through unsanitized user input."},
    "Cross-Site Scripting (XSS)": {"id": "T1059.007", "tactic": "Execution", "name": "JavaScript Execution (XSS)", "desc": "Injecting malicious client-side script into web application pages."},
    "Path Traversal": {"id": "T1083", "tactic": "Discovery", "name": "File and Directory Discovery (Path Traversal)", "desc": "Using relative path sequences (../) to access restricted server files."},
    "Command Injection": {"id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter", "desc": "Executing arbitrary OS commands on the host via vulnerable input parameter."},
    "Botnet / C2 Beaconing": {"id": "T1071", "tactic": "Command and Control", "name": "Application Layer Protocol C2", "desc": "Periodic automated heartbeat communications to command-and-control server."},
    "Data Exfiltration": {"id": "T1048", "tactic": "Exfiltration", "name": "Exfiltration Over Alternative Protocol", "desc": "Abnormal outbound volume spike transferring sensitive internal assets."},
    "Zero-Day Anomaly": {"id": "T1203", "tactic": "Initial Access", "name": "Exploitation for Client Execution / Unknown Zero-Day", "desc": "Unprecedented traffic entropy and flow signature diverging from normal baseline behavior."},
    "Normal": {"id": "N/A", "tactic": "Benign", "name": "Legitimate Traffic", "desc": "Standard operational traffic conforming to expected baseline profiles."}
}

class ThreatDetectionEngine:
    """
    Hybrid AI/ML Cybersecurity Threat Detector combining:
    1. Supervised Random Forest for Network Flow Attacks (DDoS, Port Scan, Botnet)
    2. Heuristic + Sliding Temporal Analyzer for Authentication / Brute Force
    3. NLP Vectorizer + Logistic Regression for Web Payload Attacks (SQLi, XSS, Traversal, RCE)
    4. Unsupervised Isolation Forest for Zero-Day Anomaly Detection
    5. Plain-English Explainability Engine with MITRE ATT&CK and Feature Attribution
    """
    
    def __init__(self):
        self.models_loaded = False
        self.flow_model = None
        self.flow_scaler = None
        self.payload_vectorizer = None
        self.payload_model = None
        self.anomaly_model = None
        self.anomaly_scaler = None
        self.load_or_init_models()
        
    def load_or_init_models(self):
        """Loads trained models if available, otherwise initializes baseline rules."""
        flow_path = os.path.join(MODELS_DIR, "flow_model.joblib")
        payload_path = os.path.join(MODELS_DIR, "payload_model.joblib")
        anomaly_path = os.path.join(MODELS_DIR, "anomaly_model.joblib")
        
        if os.path.exists(flow_path) and os.path.exists(payload_path) and os.path.exists(anomaly_path):
            try:
                flow_data = joblib.load(flow_path)
                self.flow_model = flow_data["model"]
                self.flow_scaler = flow_data["scaler"]
                
                payload_data = joblib.load(payload_path)
                self.payload_vectorizer = payload_data["vectorizer"]
                self.payload_model = payload_data["model"]
                
                anomaly_data = joblib.load(anomaly_path)
                self.anomaly_model = anomaly_data["model"]
                self.anomaly_scaler = anomaly_data["scaler"]
                self.models_loaded = True
                print("[CyberGuard ML] Successfully loaded pre-trained AI models.")
            except Exception as e:
                print(f"[CyberGuard ML] Error loading models ({e}). Initializing embedded fallbacks.")
                self.models_loaded = False
        else:
            print("[CyberGuard ML] No saved models found. Using dynamic rule engine until train_models.py is run.")
            self.models_loaded = False

    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes a single network event, auth attempt, or web request and outputs
        comprehensive threat intelligence, risk scores, and plain-English explainability.
        """
        event_type = event.get("event_type", "network_flow") # network_flow, auth_log, web_request, or raw
        
        if event_type == "web_request" or "payload" in event or "url" in event:
            return self._analyze_web_request(event)
        elif event_type == "auth_log" or "failed_logins" in event:
            return self._analyze_auth_event(event)
        else:
            return self._analyze_network_flow(event)

    def _analyze_web_request(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzes HTTP requests, query parameters, headers, and payloads."""
        payload = str(event.get("payload", "") or event.get("url", "") or event.get("request_body", ""))
        src_ip = event.get("src_ip", "192.168.1.100")
        method = event.get("method", "GET")
        
        # 1. Regex & Pattern Heuristics
        rce_patterns = [
            r"(;\s*cat\b)", r"(;\s*ls\b)", r"(\|\s*nc\b)", r"(\|\s*netcat\b)", r"(\bpowershell\b.*\b-enc\b)",
            r"(\bcmd\.exe\b|\b/bin/bash\b|\b/bin/sh\b)", r"(\bwget\b|\bcurl\b.*\|\s*sh)",
            r"(`[^`]+`|\$\([^)]+\))", r"(\|\s*whoami\b)", r"(;\s*rm\s+-rf\b)"
        ]
        sqli_patterns = [
            r"(\bUNION\b.*\bSELECT\b)", r"(\bSELECT\b.*\bFROM\b)", r"(\bOR\b\s+['\d\w]+\s*=\s*['\d\w]+)",
            r"(--|#|/\*|\*/|@@version|information_schema|benchmark\s*\(|sleep\s*\()",
            r"(';\s*DROP\s+TABLE)", r"(';\s*SHUTDOWN)"
        ]
        xss_patterns = [
            r"(<script.*?>.*?</script>)", r"(javascript\s*:)", r"(onload\s*=)", r"(onerror\s*=)",
            r"(<iframe.*?>)", r"(<img.*?src=.*?onerror=)", r"(alert\s*\(|prompt\s*\(|confirm\s*\()"
        ]
        path_traversal_patterns = [
            r"(\.\./|\.\.\\)", r"(/etc/passwd|/etc/shadow|/proc/version|c:\\boot\.ini|c:\\windows\\win\.ini)",
            r"(win\.ini|boot\.ini|\.\.%2f|\.\.%5c)"
        ]

        detected_threat = "Normal"
        confidence = 0.95
        severity = "Low"
        risk_score = 5
        key_factors = []

        # Check RCE first
        for pat in rce_patterns:
            if re.search(pat, payload, re.IGNORECASE):
                detected_threat = "Command Injection"
                confidence = 0.99
                severity = "Critical"
                risk_score = 96
                key_factors.append("Detected shell metacharacters and arbitrary OS execution command")
                break

        if detected_threat == "Normal":
            for pat in sqli_patterns:
                if re.search(pat, payload, re.IGNORECASE):
                    detected_threat = "SQL Injection"
                    confidence = 0.98
                    severity = "Critical"
                    risk_score = 92
                    key_factors.append(f"Detected SQL syntax injection pattern matching: '{pat}'")
                    break
                
        if detected_threat == "Normal":
            for pat in xss_patterns:
                if re.search(pat, payload, re.IGNORECASE):
                    detected_threat = "Cross-Site Scripting (XSS)"
                    confidence = 0.97
                    severity = "High"
                    risk_score = 85
                    key_factors.append("Detected malicious HTML/JavaScript tag or event handler injection")
                    break

        if detected_threat == "Normal":
            for pat in path_traversal_patterns:
                if re.search(pat, payload, re.IGNORECASE):
                    detected_threat = "Path Traversal"
                    confidence = 0.96
                    severity = "High"
                    risk_score = 88
                    key_factors.append("Detected directory traversal sequence (../) attempting access to restricted system files")
                    break

        # ML model inference if models are loaded and no strong regex hit
        if detected_threat == "Normal" and self.models_loaded and self.payload_model and payload.strip():
            try:
                vec = self.payload_vectorizer.transform([payload])
                pred_label = self.payload_model.predict(vec)[0]
                proba = np.max(self.payload_model.predict_proba(vec))
                if pred_label != "Normal" and proba > 0.65:
                    detected_threat = pred_label
                    confidence = float(proba)
                    severity = "High" if detected_threat in ["Cross-Site Scripting (XSS)", "Path Traversal"] else "Critical"
                    risk_score = int(proba * 95)
                    key_factors.append(f"AI NLP Classifier detected semantic signature of {detected_threat}")
            except Exception:
                pass

        if detected_threat == "Normal":
            key_factors.append("Standard HTTP request parameters conforming to safe schema")

        return self._format_result(
            event=event,
            threat_type=detected_threat,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            key_factors=key_factors
        )

    def _analyze_auth_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzes authentication attempts, login frequencies, and credential attacks."""
        failed_count = event.get("failed_logins", 0)
        time_window_sec = event.get("time_window_sec", 60)
        username = event.get("username", "root")
        src_ip = event.get("src_ip", "10.0.0.5")
        country = event.get("country", "Unknown")
        is_known_device = event.get("is_known_device", True)
        
        rate = failed_count / max(time_window_sec, 1)
        
        detected_threat = "Normal"
        confidence = 0.90
        severity = "Low"
        risk_score = 10
        key_factors = []

        if failed_count >= 15 or rate >= 0.5:
            detected_threat = "Brute Force"
            confidence = min(0.99, 0.85 + (failed_count * 0.005))
            severity = "Critical" if failed_count > 30 else "High"
            risk_score = min(99, 70 + failed_count)
            key_factors.append(f"High-frequency password guessing detected: {failed_count} failed logins in {time_window_sec}s ({rate:.2f} attempts/sec)")
            key_factors.append(f"Targeting privileged account: '{username}'")
            if not is_known_device:
                key_factors.append(f"Unrecognized device fingerprint from external geolocation ({country})")
        elif failed_count >= 5:
            detected_threat = "Brute Force"
            confidence = 0.82
            severity = "Medium"
            risk_score = 55
            key_factors.append(f"Multiple consecutive failed authentication attempts ({failed_count} failures)")
            key_factors.append(f"Target account: '{username}'")
        else:
            key_factors.append("Normal authentication activity within acceptable threshold")

        return self._format_result(
            event=event,
            threat_type=detected_threat,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            key_factors=key_factors
        )

    def _analyze_network_flow(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzes network packet flows, volumetric anomalies, port scans, and DDoS."""
        packets_per_sec = float(event.get("packets_per_sec", 50))
        bytes_per_sec = float(event.get("bytes_per_sec", 25000))
        syn_ratio = float(event.get("syn_ratio", 0.05))
        unique_ports = int(event.get("unique_dst_ports", 1))
        duration = float(event.get("flow_duration", 1.5))
        entropy = float(event.get("packet_entropy", 0.45))
        dst_port = int(event.get("dst_port", 80))
        
        detected_threat = "Normal"
        confidence = 0.92
        severity = "Low"
        risk_score = 10
        key_factors = []
        
        # 1. High Volumetric DDoS detection
        if packets_per_sec > 4000 or (packets_per_sec > 1500 and syn_ratio > 0.7):
            detected_threat = "DDoS"
            confidence = 0.98
            severity = "Critical"
            risk_score = 95
            key_factors.append(f"Massive packet flood detected: {packets_per_sec:,.0f} packets/sec with {syn_ratio*100:.1f}% SYN flag ratio")
            key_factors.append(f"High bandwidth consumption: {bytes_per_sec/1_000_000:.2f} MB/sec")
            
        # 2. Port Scanning discovery
        elif unique_ports > 20 or (unique_ports > 8 and duration < 2.0):
            detected_threat = "Port Scan"
            confidence = 0.96
            severity = "High"
            risk_score = 78
            key_factors.append(f"Horizontal/Vertical port scan detected: {unique_ports} destination ports probed in {duration:.1f}s")
            key_factors.append(f"Elevated SYN ratio without handshake completion ({syn_ratio*100:.1f}%)")
            
        # 3. Data Exfiltration
        elif bytes_per_sec > 8_000_000 and dst_port not in [80, 443, 8080]:
            detected_threat = "Data Exfiltration"
            confidence = 0.91
            severity = "High"
            risk_score = 82
            key_factors.append(f"Abnormal outbound data transfer burst ({bytes_per_sec/1_000_000:.2f} MB/s) to non-standard port {dst_port}")
            key_factors.append(f"High payload data entropy ({entropy:.2f}) indicative of encrypted or compressed archive export")

        # 4. Botnet C2 Beaconing
        elif event.get("beacon_interval_std", 10.0) < 0.2 and event.get("total_connections", 1) > 20:
            detected_threat = "Botnet / C2 Beaconing"
            confidence = 0.89
            severity = "High"
            risk_score = 80
            key_factors.append("Mathematical periodic heartbeat detected (beacon variance < 0.2s) matching Command & Control polling")

        # 5. ML Models (Flow classification & Unsupervised Isolation Forest Anomaly Detection)
        if detected_threat == "Normal" and self.models_loaded:
            try:
                features = np.array([[packets_per_sec, bytes_per_sec, syn_ratio, unique_ports, duration, entropy]])
                scaled_feat = self.flow_scaler.transform(features)
                
                # Supervised Flow Model
                pred = self.flow_model.predict(scaled_feat)[0]
                proba = np.max(self.flow_model.predict_proba(scaled_feat))
                
                if pred != "Normal" and proba > 0.70:
                    detected_threat = pred
                    confidence = float(proba)
                    severity = "Critical" if pred in ["DDoS", "Brute Force"] else "High"
                    risk_score = int(proba * 90)
                    key_factors.append(f"Supervised Random Forest classified flow as {pred} with {proba*100:.1f}% confidence")
                else:
                    # Unsupervised Zero-Day Anomaly Check
                    anomaly_scaled = self.anomaly_scaler.transform(features)
                    anomaly_score = self.anomaly_model.decision_function(anomaly_scaled)[0]
                    # Isolation Forest: negative scores indicate anomalies
                    if anomaly_score < -0.15:
                        detected_threat = "Zero-Day Anomaly"
                        confidence = float(min(0.95, 0.70 + abs(anomaly_score)))
                        severity = "Medium" if anomaly_score > -0.25 else "High"
                        risk_score = int(min(90, 60 + abs(anomaly_score) * 100))
                        key_factors.append(f"Unsupervised Isolation Forest flagged anomalous flow distribution (deviation index: {abs(anomaly_score):.3f})")
                        key_factors.append("Traffic pattern significantly deviates from learned normal baseline matrix")
            except Exception:
                pass

        if detected_threat == "Normal":
            key_factors.append("Packet rates, connection timings, and protocol distribution are within standard baseline parameters")

        return self._format_result(
            event=event,
            threat_type=detected_threat,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            key_factors=key_factors
        )

    def _format_result(
        self,
        event: Dict[str, Any],
        threat_type: str,
        severity: str,
        risk_score: int,
        confidence: float,
        key_factors: List[str]
    ) -> Dict[str, Any]:
        """Formats threat intelligence with plain-English breakdown, MITRE ATT&CK metadata, and remediation playbook."""
        mitre = MITRE_MAPPING.get(threat_type, MITRE_MAPPING["Normal"])
        
        # Plain-English Human Readable Summary
        human_summary = self._generate_plain_english_summary(threat_type, event, risk_score)
        
        # Recommended Defense Actions
        recommended_actions = self._generate_remediation_actions(threat_type, event)
        
        # Feature Attribution for XAI
        feature_weights = self._calculate_feature_weights(threat_type, event)

        return {
            "timestamp": event.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            "event_id": event.get("id", f"EVT-{int(datetime.utcnow().timestamp()*1000)%1000000:06d}"),
            "src_ip": event.get("src_ip", "Unknown"),
            "dst_ip": event.get("dst_ip", "10.0.0.1"),
            "src_country": event.get("src_country", event.get("country", "Unknown")),
            "threat_detected": threat_type != "Normal",
            "threat_type": threat_type,
            "severity": severity,
            "risk_score": risk_score,
            "confidence": round(confidence * 100, 1),
            "human_summary": human_summary,
            "danger_explanation": mitre["desc"],
            "mitre_attack": {
                "technique_id": mitre["id"],
                "technique_name": mitre["name"],
                "tactic": mitre["tactic"]
            },
            "key_factors": key_factors,
            "feature_attribution": feature_weights,
            "recommended_actions": recommended_actions,
            "raw_event": event
        }

    def _generate_plain_english_summary(self, threat_type: str, event: Dict[str, Any], risk_score: int) -> str:
        src = event.get("src_ip", "An external IP")
        country = event.get("src_country", event.get("country", "Unknown location"))
        
        if threat_type == "DDoS":
            return f"A high-volume traffic flood is originating from {src} ({country}), overwhelming server network buffers with massive packet rates."
        elif threat_type == "Brute Force":
            target = event.get("username", "admin accounts")
            count = event.get("failed_logins", "multiple")
            return f"An attacker at {src} ({country}) is rapidly guessing passwords for '{target}' with {count} failed attempts."
        elif threat_type == "SQL Injection":
            return f"Malicious database queries were injected from {src} into application input fields to steal or alter backend database records."
        elif threat_type == "Cross-Site Scripting (XSS)":
            return f"An attacker at {src} tried injecting rogue JavaScript code designed to hijack user sessions and steal browser cookies."
        elif threat_type == "Path Traversal":
            return f"An unauthorized attempt from {src} was made to navigate server directory paths (../) and read restricted system files."
        elif threat_type == "Command Injection":
            return f"CRITICAL: Remote terminal execution commands were submitted from {src} attempting to gain control over the host operating system."
        elif threat_type == "Port Scan":
            return f"A reconnaissance scan from {src} is probing open ports to locate vulnerable exposed services."
        elif threat_type == "Botnet / C2 Beaconing":
            return f"Suspicious periodic heartbeat communication detected between internal host and external Command & Control server {src}."
        elif threat_type == "Data Exfiltration":
            return f"Unusual high-speed outbound data transfer from internal server to foreign host {src}."
        elif threat_type == "Zero-Day Anomaly":
            return f"The AI detected a rare, previously unseen traffic pattern from {src} that significantly deviates from normal baseline operations."
        else:
            return f"Legitimate routine traffic observed from {src} ({country}). No suspicious patterns or rule violations detected."

    def _generate_remediation_actions(self, threat_type: str, event: Dict[str, Any]) -> List[Dict[str, str]]:
        src_ip = event.get("src_ip", "0.0.0.0")
        
        if threat_type in ["DDoS", "DoS"]:
            return [
                {"action": "block_ip", "label": "🛡️ 1-Click Drop IP at Firewall", "cmd": f"iptables -A INPUT -s {src_ip} -j DROP"},
                {"action": "rate_limit", "label": "⚡ Enable SYN Flood Protection", "cmd": "sysctl -w net.ipv4.tcp_syncookies=1"},
                {"action": "waf_shield", "label": "☁️ Activate Cloudflare Under Attack Mode", "cmd": "curl -X PATCH api.cloudflare.com/v4/zones/... -d '{\"mode\":\"under_attack\"}'"}
            ]
        elif threat_type == "Brute Force":
            user = event.get("username", "user")
            return [
                {"action": "block_ip", "label": f"🛡️ Blacklist IP {src_ip}", "cmd": f"fail2ban-client set sshd banip {src_ip}"},
                {"action": "lock_user", "label": f"🔒 Temporarily Lock '{user}' Account", "cmd": f"passwd -l {user}"},
                {"action": "enforce_2fa", "label": "🔑 Force 2FA for Next Login", "cmd": "mfa_policy_enforce --user " + user}
            ]
        elif threat_type in ["SQL Injection", "Cross-Site Scripting (XSS)", "Path Traversal", "Command Injection"]:
            return [
                {"action": "block_ip", "label": f"🛡️ Block Malicious IP {src_ip}", "cmd": f"iptables -A INPUT -s {src_ip} -j DROP"},
                {"action": "enable_waf_rule", "label": "🛡️ Auto-Inject WAF Virtual Patch", "cmd": f"modsec_rules_add --signature '{threat_type}' --target '{src_ip}'"},
                {"action": "view_code_fix", "label": "📋 View Code Sanitization Guide", "cmd": "guide: Use parameterized queries (Prepared Statements) & HTML entity encoding."}
            ]
        elif threat_type == "Port Scan":
            return [
                {"action": "block_ip", "label": f"🛡️ Blacklist Port Scanner {src_ip}", "cmd": f"iptables -A INPUT -s {src_ip} -j DROP"},
                {"action": "tarpit", "label": "🕸️ Divert to Honeypot Tarpit", "cmd": f"iptables -A INPUT -s {src_ip} -p tcp -j TARPIT"}
            ]
        elif threat_type == "Zero-Day Anomaly":
            return [
                {"action": "quarantine_host", "label": "⚠️ Isolate Host in Sandbox VLAN", "cmd": f"vlan_isolate --ip {src_ip}"},
                {"action": "capture_pcap", "label": "📦 Trigger Full Packet Capture (PCAP)", "cmd": f"tcpdump -i any host {src_ip} -w /var/log/zero_day.pcap"}
            ]
        else:
            return [{"action": "none", "label": "✅ No Action Needed (Traffic Benign)", "cmd": "status: nominal"}]

    def _calculate_feature_weights(self, threat_type: str, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Provides simulated SHAP-style Explainable AI feature importance weights."""
        if threat_type == "DDoS":
            return [
                {"feature": "Packets / Sec Rate", "importance": 0.48, "value": f"{event.get('packets_per_sec', 0):,.0f}"},
                {"feature": "SYN Flag Ratio", "importance": 0.32, "value": f"{event.get('syn_ratio', 0)*100:.1f}%"},
                {"feature": "Bandwidth (Bytes/s)", "importance": 0.15, "value": f"{event.get('bytes_per_sec', 0)/1000:.0f} KB/s"},
                {"feature": "Flow Duration", "importance": 0.05, "value": f"{event.get('flow_duration', 0):.2f}s"}
            ]
        elif threat_type == "Brute Force":
            return [
                {"feature": "Failed Login Burst", "importance": 0.55, "value": f"{event.get('failed_logins', 0)} attempts"},
                {"feature": "Attempt Velocity", "importance": 0.25, "value": f"{event.get('failed_logins', 0)/max(event.get('time_window_sec', 1),1):.2f}/sec"},
                {"feature": "Account Privileges", "importance": 0.12, "value": f"{event.get('username', 'root')}"},
                {"feature": "Geo-Anomaly Index", "importance": 0.08, "value": f"{event.get('src_country', 'External')}"}
            ]
        elif threat_type in ["SQL Injection", "Cross-Site Scripting (XSS)", "Path Traversal", "Command Injection"]:
            return [
                {"feature": "Payload Token Entropy", "importance": 0.42, "value": "High Risk"},
                {"feature": "SQL/Script Metacharacters", "importance": 0.38, "value": "Present in Query"},
                {"feature": "HTTP Method & Target", "importance": 0.12, "value": f"{event.get('method', 'POST')}"},
                {"feature": "User-Agent Reputation", "importance": 0.08, "value": "Automated Tool"}
            ]
        elif threat_type == "Port Scan":
            return [
                {"feature": "Unique Ports Probed", "importance": 0.52, "value": f"{event.get('unique_dst_ports', 1)} ports"},
                {"feature": "Scan Velocity", "importance": 0.28, "value": "Rapid SYN Sweep"},
                {"feature": "TCP Flag Anomaly", "importance": 0.14, "value": "SYN Without ACK"},
                {"feature": "Target Diversity", "importance": 0.06, "value": "Sequential Ports"}
            ]
        else:
            return [
                {"feature": "Traffic Volumetrics", "importance": 0.35, "value": "Normal"},
                {"feature": "Protocol Compliance", "importance": 0.35, "value": "100% Valid RFC"},
                {"feature": "Host Reputation", "importance": 0.30, "value": "Clean"}
            ]

# Singleton instance
engine = ThreatDetectionEngine()
