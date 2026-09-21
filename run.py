import os
import sys
import webbrowser
import threading
import time
import uvicorn

def main():
    print("=" * 60)
    print("🛡️  CYBERGUARD AI: Next-Gen Cybersecurity Threat Detector & SOC")
    print("=" * 60)

    # 1. Verify ML Models
    models_dir = os.path.join(os.path.dirname(__file__), "backend", "models")
    flow_model = os.path.join(models_dir, "flow_model.joblib")
    if not os.path.exists(flow_model):
        print("[*] Training baseline AI/ML detection models...")
        from backend.train_models import train_and_save_all
        train_and_save_all()

    # 2. Start browser after small delay
    port = 8008
    def open_browser():
        time.sleep(1.5)
        url = f"http://127.0.0.1:{port}"
        print(f"\n[+] Opening CyberGuard SOC Dashboard at {url}")
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=open_browser, daemon=True).start()

    # 3. Launch FastAPI backend via Uvicorn
    print(f"\n[*] Starting CyberGuard FastAPI server on http://127.0.0.1:{port} ...")
    uvicorn.run("backend.app:app", host="127.0.0.1", port=port, reload=False, log_level="info")

if __name__ == "__main__":
    main()
