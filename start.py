import os
import sys
import time
import ctypes
import subprocess
import json


def prompt_for_api_key():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent", "config.json")
    api_key = None
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
                api_key = config.get("api_key", "").strip()
        except: pass
        
    if not api_key or api_key == "YOUR_API_KEY_HERE":
        print("\n" + "="*50)
        api_key = input("  [?] Enter your API key for the Agent: ").strip()
        print("="*50 + "\n")
        if not api_key:
            print("[!] API key cannot be empty. Exiting.")
            sys.exit(1)
        
        try:
            config = {"api_key": api_key, "server_url": "http://127.0.0.1:5000/ingest"}
            with open(config_path, "w") as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"[!] Could not save config.json: {e}")


def run():
    print("=======================================================")
    print("     Starting Windows LOLBins Detection System...")
    print("=======================================================")

    # Windows requires Admin privileges to read Security Event Logs (ID 4688)
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] Requesting Administrator privileges for Event Log monitoring...")
        # Automatically prompts UAC and restarts as admin
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit()

    print("[+] Administrator privileges confirmed.")
    print("[1/2] Launching Backend Server silently...")
    # CREATE_NO_WINDOW = 0x08000000
    subprocess.Popen([sys.executable, "server/app.py"], creationflags=0x08000000)
    
    time.sleep(3)
    prompt_for_api_key()
    
    print("[2/2] Launching Agent in this terminal...")
    subprocess.call([sys.executable, "agent/agent.py"])
    
    print("\n[*] Exiting CLI monitor.")


if __name__ == "__main__":
    # Ensure we run from the project root
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    run()

