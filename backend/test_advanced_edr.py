import sys
import os
import requests
import json

BASE = "http://127.0.0.1:8008"

def test_advanced_edr_capabilities():
    print("==================================================")
    print("[*] Running CyberArmor Pro Advanced EDR Verification")
    print("==================================================")

    # 1. Test Process Attack Tree & Lineage DAG
    r_tree = requests.get(f"{BASE}/api/edr/process-tree")
    assert r_tree.status_code == 200, f"Failed tree: {r_tree.text}"
    tree_data = r_tree.json()
    assert tree_data["total_nodes"] > 0
    print(f"  [PASS] GET /api/edr/process-tree -> Traced {tree_data['total_nodes']} lineage nodes (Target PID: {tree_data['target_pid']})")
    print(f"         Lineage Path: {' -> '.join([n['name'] for n in tree_data['nodes']])}")

    # 2. Test Binary Shannon Entropy & SHA-256 Checksum
    python_exe = sys.executable
    r_bin = requests.post(f"{BASE}/api/edr/inspect-binary", json={"file_path": python_exe})
    assert r_bin.status_code == 200
    bin_data = r_bin.json()
    assert len(bin_data["sha256"]) == 64
    print(f"  [PASS] POST /api/edr/inspect-binary -> File: {bin_data['filename']} | Entropy: {bin_data['shannon_entropy']} / 8.0 | Verdict: {bin_data['threat_intel_verdict']}")
    print(f"         SHA-256: {bin_data['sha256'][:24]}...")

    # 3. Test Ransomware Canary Honey-Trap
    r_canary = requests.get(f"{BASE}/api/edr/canary-status")
    assert r_canary.status_code == 200
    canary_data = r_canary.json()
    print(f"  [PASS] GET /api/edr/canary-status -> Status: {canary_data['shield_status']} ({canary_data['canary_count']} Decoy Traps Armed)")

    # 4. Test File Integrity Monitor (FIM)
    r_fim = requests.get(f"{BASE}/api/edr/fim-status")
    assert r_fim.status_code == 200
    fim_data = r_fim.json()
    print(f"  [PASS] GET /api/edr/fim-status -> Integrity: {fim_data['status']} ({fim_data['monitored_targets_count']} System Config Targets Monitored)")

    # 5. Test GenAI Cyber Copilot (Queries)
    test_queries = [
        "Is my device safe right now?",
        "Check open listening ports",
        "How do I prevent ransomware attacks?"
    ]
    for q in test_queries:
        r_copilot = requests.post(f"{BASE}/api/edr/copilot-query", json={"query": q})
        assert r_copilot.status_code == 200
        cop_data = r_copilot.json()
        assert len(cop_data["response"]) > 20
        print(f"  [PASS] POST /api/edr/copilot-query ('{q}') -> Returned {len(cop_data['response'])} chars response ({len(cop_data['action_buttons'])} Action Buttons generated)")

    # 6. Test Emergency Network Isolation (Airgap Mode)
    r_iso_on = requests.post(f"{BASE}/api/edr/toggle-isolation", json={"enable": True})
    assert r_iso_on.status_code == 200
    print(f"  [PASS] POST /api/edr/toggle-isolation (Enable) -> Status: {r_iso_on.json()['status']}")
    
    r_iso_off = requests.post(f"{BASE}/api/edr/toggle-isolation", json={"enable": False})
    assert r_iso_off.status_code == 200
    print(f"  [PASS] POST /api/edr/toggle-isolation (Disable) -> Status: {r_iso_off.json()['status']}")

    print("\n==================================================")
    print("[SUCCESS] ALL ADVANCED CYBERARMOR PRO EDR TESTS PASSED!")
    print("==================================================")

if __name__ == "__main__":
    test_advanced_edr_capabilities()
