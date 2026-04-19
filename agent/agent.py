"""
Windows LOLBins Detection Agent - Monitors process creation in REAL-TIME
using Windows Event Log (Event ID 4688) and sends alerts to the Flask server.
"""

import subprocess

import requests
import time
import json
import os
import sys
import threading

API_URL = "http://127.0.0.1:5000/ingest"

# Windows LOLBins to monitor
LOLBINS = [
    "powershell",
    "certutil",
    "mshta",
    "rundll32",
    "regsvr32",
    "wmic",
    "bitsadmin",
    "cscript",
    "wscript",
    "cmd",
    "net",
    "net1",
    # Extended LOLBins (persistence, execution, recon)
    "schtasks",
    "reg",
    "forfiles",
    "pcalua",
    "msiexec",
    "installutil",
    "msbuild",
    "regasm",
    "regsvcs",
    "cmstp",
    "wevtutil",
    "fsutil",
    "nltest",
    "dsquery",
    "systeminfo",
    "whoami",
    "tasklist",
    "psexec",
    "netsh",
]

# Will be set when agent starts
API_KEY = None
HEADERS = {}


def load_config():
    """Load API key and server URL from config.json."""
    global API_URL

    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

    if not os.path.exists(config_path):
        return None

    try:
        with open(config_path, "r") as f:
            config = json.load(f)

        if config.get("server_url"):
            API_URL = config["server_url"]

        api_key = config.get("api_key", "").strip()

        if api_key and api_key != "YOUR_API_KEY_HERE" and api_key != "ENTER_YOU_API_KEY":
            return api_key

    except (json.JSONDecodeError, IOError) as e:
        print(f"[!] Error reading config.json: {e}")

    return None


# Known safe processes to ignore completely
ALLOWLIST = ["nvcontainer", "nvidia", "nearby_share", "jsonservermain", "steam", "gamingservices"]


def is_suspicious(cmd, parent="Unknown"):
    """Pre-filter: check if the command involves a known Windows LOLBin."""
    cmd_lower = cmd.lower()

    # Ignore known safe background noise
    if any(safe in cmd_lower for safe in ALLOWLIST):
        return False

    # Ignore the agent's own watcher process and its script block
    if "poll_events.ps1" in cmd_lower or "param([string]$timestr)" in cmd_lower:
        return False

    # Ignore wmic polling commands from our own agent
    if "wmic process get commandline" in cmd_lower:
        return False

    if parent == "PowerShell_Script":
        sus_kws = [
            "invoke-expression", "iex", "downloadstring", "downloadfile",
            "invoke-webrequest", "bypass", "hidden", "frombase64string",
            "net.webclient", "bitstransfer", "powershell"
        ]
        return any(kw in cmd_lower for kw in sus_kws)

    return any(tool in cmd_lower for tool in LOLBINS)


def send_log(command, parent="Unknown"):
    """Send a suspicious command (and parent) to the server for analysis."""
    data = {"command": command.strip(), "parent": parent.strip()}

    try:
        res = requests.post(API_URL, json=data, headers=HEADERS, timeout=5)
        result = res.json()

        if result.get("status") == "alert_created":
            alert = result.get("alert", {})
            severity = alert.get("severity", "").upper()
            method = alert.get("method", "unknown")
            confidence = alert.get("confidence")
            parent_proc = alert.get("parent", parent)

            print(f"\n[ALERT] {severity}: {command.strip()[:100]}...", flush=True)
            print(f"    Parent    : {parent_proc}", flush=True)
            print(f"    Reason    : {alert.get('reason', 'N/A')}", flush=True)
            print(f"    Method    : {method}", flush=True)
            if confidence is not None:
                print(f"    Confidence: {confidence:.1%}", flush=True)
            print(flush=True)
        else:
            msg = command.strip()[:60]
            print(f"[OK] {msg}...", flush=True)

    except requests.exceptions.ConnectionError:
        print("[-] Server not reachable. Is the Flask server running?")
    except Exception as e:
        print(f"[-] Error: {e}")


def run_windows_polling():
    """True kernel-level monitoring using Windows Event Log (Event ID 4688) via poll_events.ps1."""
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "poll_events.ps1")

    if not os.path.exists(script_path):
        print("[!] poll_events.ps1 not found, cannot start kernel-level monitoring.")
        return

    print("[+] Starting Kernel-Level Event Log monitor (Event ID 4688)...")
    print("    This guarantees NO race conditions. Every fast process is captured.\n")

    from datetime import datetime, timedelta
    
    seen_times = {}

    # Start looking for events from a few seconds ago
    last_time = datetime.now() - timedelta(seconds=3)

    try:
        while True:
            time_str = last_time.strftime("%m/%d/%Y %H:%M:%S")

            next_time = datetime.now()

            proc = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path, time_str],
                capture_output=True,
                text=True,
                errors="ignore"
            )

            # overlap by 2 seconds to catch late-flushing events
            last_time = next_time - timedelta(seconds=2)
            now = datetime.now()

            for line in proc.stdout.strip().split("\n"):
                line = line.strip()
                if not line or "|||" not in line:
                    continue

                parent, command = line.split("|||", 1)
                command = command.strip()
                parent = parent.strip()

                if not command:
                    continue

                # Deduplicate exact same commands within 10 seconds 
                # (Prevents overlap spam but allows manual retries to trigger again)
                last_seen = seen_times.get(command)
                if last_seen and (now - last_seen).total_seconds() < 10:
                    continue

                if is_suspicious(command, parent):
                    send_log(command, parent)
                    seen_times[command] = now
                    
                    if len(seen_times) > 5000:
                        cutoff = now - timedelta(seconds=10)
                        seen_times = {k: v for k, v in seen_times.items() if v > cutoff}

            time.sleep(1.5)

    except KeyboardInterrupt:
        pass




def run():
    """Main entry point."""
    global API_KEY, HEADERS

    print(f"[*] Monitoring {len(LOLBINS)} Windows LOLBins")

    # Try loading from config.json first
    API_KEY = load_config()

    if API_KEY:
        print(f"[OK] API key loaded from config.json")
    else:
        API_KEY = input("Enter your API key: ").strip()
        if not API_KEY:
            print("[!] API key cannot be empty.")
            return

        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        try:
            config = {"api_key": API_KEY, "server_url": API_URL}
            with open(config_path, "w") as f:
                json.dump(config, f, indent=4)
            print("[OK] API key saved to config.json for future runs.")
        except IOError:
            pass

    HEADERS = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json",
    }

    print("=" * 55)
    print("  Windows LOLBins Detection Agent")
    print(f"  Server  : {API_URL}")
    print("  Monitoring system activity...")
    print("=" * 55)

    try:
        run_windows_polling()
    except KeyboardInterrupt:
        print("\n[*] Agent stopped.")


if __name__ == "__main__":
    run()