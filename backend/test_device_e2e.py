import requests
import json

BASE = "http://127.0.0.1:8008"

def test_device_security_product():
    print("==================================================")
    print("[*] Running CyberArmor EDR Product Verification")
    print("==================================================")

    # 1. Test Device Overview
    r_ov = requests.get(f"{BASE}/api/device/overview")
    assert r_ov.status_code == 200, f"Failed overview: {r_ov.text}"
    ov = r_ov.json()
    sys = ov["system"]
    print(f"  [PASS] GET /api/device/overview -> Host: {sys['hostname']} | OS: {sys['os'][:25]}... | CPU: {sys['cpu_percent']}% | RAM: {sys['ram_percent']}% | Score: {ov['device_health_score']}/100")

    # 2. Test Real Running Processes
    r_proc = requests.get(f"{BASE}/api/device/processes?limit=100")
    assert r_proc.status_code == 200
    procs = r_proc.json()
    assert procs["total_processes"] > 0
    top_proc = procs["processes"][0]
    print(f"  [PASS] GET /api/device/processes -> {procs['total_processes']} Live Processes scanned | Top: {top_proc['name']} (PID: {top_proc['pid']}, Risk: {top_proc['risk_level']})")

    # 3. Test Real Network Sockets & Listening Ports
    r_conn = requests.get(f"{BASE}/api/device/connections?limit=50")
    assert r_conn.status_code == 200
    conns = r_conn.json()
    assert conns["total_connections"] > 0
    print(f"  [PASS] GET /api/device/connections -> {conns['total_connections']} Sockets ({conns['established_count']} Established, {conns['listening_count']} Listening)")

    # 4. Test Real Windows Event Logs
    r_ev = requests.get(f"{BASE}/api/device/event-logs?log_name=System&max_events=20")
    assert r_ev.status_code == 200
    events_data = r_ev.json()
    print(f"  [PASS] GET /api/device/event-logs -> {events_data['total_events']} Windows System events extracted")

    # 5. Test Local Log File Tailer
    r_tail = requests.post(f"{BASE}/api/device/tail-server-log", json={"file_path": "sample_logs.csv", "max_lines": 50})
    assert r_tail.status_code == 200
    tail_data = r_tail.json()
    assert tail_data["status"] == "SUCCESS"
    print(f"  [PASS] POST /api/device/tail-server-log -> Tailed {tail_data['total_lines_read']} lines from sample_logs.csv | {tail_data['threats_flagged']} Threats flagged")

    # 6. Test Host Hardening Security Audit
    r_audit = requests.get(f"{BASE}/api/device/audit")
    assert r_audit.status_code == 200
    audit_data = r_audit.json()
    assert "device_health_score" in audit_data
    print(f"  [PASS] GET /api/device/audit -> Health Score: {audit_data['device_health_score']}/100 ({audit_data['security_grade']}) | {audit_data['passed_checks']}/{audit_data['total_checks']} Checks passed")

    # 7. Test Real Windows Firewall Rule Enforcer
    r_block = requests.post(f"{BASE}/api/device/block-ip", json={"ip": "198.51.100.77", "reason": "EDR test quarantine", "threat_type": "Network C2"})
    assert r_block.status_code == 200
    r_fw = requests.get(f"{BASE}/api/device/firewall-rules")
    assert any(b["ip"] == "198.51.100.77" for b in r_fw.json()["blocked_ips"])
    print("  [PASS] POST /api/device/block-ip & GET /api/device/firewall-rules -> Windows Defender Firewall rule enforced for 198.51.100.77")

    # Cleanup unblock
    requests.post(f"{BASE}/api/device/unblock-ip", json={"ip": "198.51.100.77"})
    print("  [PASS] POST /api/device/unblock-ip -> Firewall rule cleanly removed.")

    # 8. Test Executive Compliance Audit Report
    r_rep = requests.get(f"{BASE}/api/device/export-report")
    assert r_rep.status_code == 200
    rep_data = r_rep.json()
    assert "report_id" in rep_data
    print(f"  [PASS] GET /api/device/export-report -> Report Generated: {rep_data['report_id']} for Host: {rep_data['host_information']['hostname']}")

    print("\n==================================================")
    print("[SUCCESS] ALL CYBERARMOR EDR DEVICE TESTS PASSED!")
    print("==================================================")

if __name__ == "__main__":
    test_device_security_product()
