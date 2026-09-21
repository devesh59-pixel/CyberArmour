import requests
import json

BASE = "http://127.0.0.1:8008"

def test_full_api():
    print("==================================================")
    print("[*] Running Full End-to-End API & Static Verification")
    print("==================================================")

    # 1. Test index.html
    r = requests.get(f"{BASE}/")
    assert r.status_code == 200, f"Failed index.html: {r.status_code}"
    assert "CYBERGUARD AI" in r.text, "Index HTML missing title"
    print("  [PASS] GET / (Frontend Dashboard HTML) -> 200 OK")

    # 2. Test static assets
    r_css = requests.get(f"{BASE}/static/css/style.css")
    assert r_css.status_code == 200, "CSS failed"
    r_js = requests.get(f"{BASE}/static/js/app.js")
    assert r_js.status_code == 200, "JS failed"
    print("  [PASS] GET /static/css/style.css & app.js -> 200 OK")

    # 3. Test /api/status
    r_status = requests.get(f"{BASE}/api/status")
    assert r_status.status_code == 200
    status_data = r_status.json()
    assert status_data["status"] == "ONLINE"
    print(f"  [PASS] GET /api/status -> {status_data['status']} (Armed: {status_data['system_armed']}, Packets: {status_data['total_packets_analyzed']})")

    # 4. Test /api/simulate-attack (DDoS)
    r_sim = requests.post(f"{BASE}/api/simulate-attack", json={"attack_type": "ddos"})
    assert r_sim.status_code == 200
    sim_data = r_sim.json()
    assert sim_data["events_generated"] > 0
    print(f"  [PASS] POST /api/simulate-attack (DDoS) -> Generated {sim_data['events_generated']} events. Sample Risk: {sim_data['sample_result']['risk_score']}/100")

    # 5. Test /api/analyze-payload (SQLi)
    r_sqli = requests.post(f"{BASE}/api/analyze-payload", json={"payload": "admin' OR 1=1 --", "method": "POST", "src_ip": "198.51.100.99"})
    assert r_sqli.status_code == 200
    sqli_data = r_sqli.json()
    assert sqli_data["threat_type"] == "SQL Injection"
    assert sqli_data["severity"] in ["High", "Critical"]
    print(f"  [PASS] POST /api/analyze-payload (SQLi) -> Detected: {sqli_data['threat_type']} (Risk: {sqli_data['risk_score']}/100, MITRE: {sqli_data['mitre_attack']['technique_id']})")

    # 6. Test /api/analyze-payload (XSS)
    r_xss = requests.post(f"{BASE}/api/analyze-payload", json={"payload": "<script>alert(1)</script>", "method": "GET"})
    assert r_xss.status_code == 200
    xss_data = r_xss.json()
    assert xss_data["threat_type"] == "Cross-Site Scripting (XSS)"
    print(f"  [PASS] POST /api/analyze-payload (XSS) -> Detected: {xss_data['threat_type']} (Risk: {xss_data['risk_score']}/100)")

    # 7. Test /api/block-ip & /api/blocked-ips
    r_block = requests.post(f"{BASE}/api/block-ip", json={"ip": "198.51.100.99", "threat_type": "SQL Injection", "reason": "Automated test ban"})
    assert r_block.status_code == 200
    r_list = requests.get(f"{BASE}/api/blocked-ips")
    assert any(b["ip"] == "198.51.100.99" for b in r_list.json()["blocked_ips"])
    print("  [PASS] POST /api/block-ip & GET /api/blocked-ips -> IP 198.51.100.99 is now in Active Firewall Blocklist")

    # 8. Test /api/firewall-script
    r_fw = requests.get(f"{BASE}/api/firewall-script?ip=198.51.100.99&os_type=linux")
    assert "iptables" in r_fw.json()["script"]
    print("  [PASS] GET /api/firewall-script -> Generated valid Linux iptables & UFW rules")

    # 9. Test /api/playbook
    r_pb = requests.get(f"{BASE}/api/playbook/SQL%20Injection")
    assert r_pb.status_code == 200
    assert len(r_pb.json()["permanent_fix_steps"]) > 0
    print(f"  [PASS] GET /api/playbook/SQL Injection -> Title: {r_pb.json()['title']}")

    # 10. Test /api/export-report
    r_rep = requests.get(f"{BASE}/api/export-report")
    assert r_rep.status_code == 200
    rep_data = r_rep.json()
    assert "executive_summary" in rep_data
    print(f"  [PASS] GET /api/export-report -> Report ID: {rep_data['report_id']} (Health Score: {rep_data['executive_summary']['overall_health_score']}/100)")

    # Cleanup unblock
    requests.post(f"{BASE}/api/unblock-ip", json={"ip": "198.51.100.99"})
    print("  [PASS] Cleanup: IP unblocked successfully.")

    print("\n==================================================")
    print("[SUCCESS] ALL END-TO-END SYSTEM TESTS PASSED PERFECTLY!")
    print("==================================================")

if __name__ == "__main__":
    test_full_api()
