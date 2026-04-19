"""
Detector - Analyzes command strings for suspicious Windows LOLBin activity.

Uses a trained Random Forest model (model.pkl) for ML-based detection.
Falls back to rule-based regex detection if the model is not available.

Detection Pipeline (in order of priority):
  1. Behavioral Analysis  — parent-child process relationship
  2. Signature Engine     — explicit malicious LOLBin tactical patterns
  3. ML Model             — Random Forest classifier
  4. Rule-based fallback  — regex pattern counting
"""

import sys
import os
import re

# Ensure sibling modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from feature_extractor import extract_features, features_to_list, ALL_LOLBINS

# Try to load the trained model
_model = None
try:
    import joblib
    _model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")
    if os.path.exists(_model_path):
        _model = joblib.load(_model_path)
        print("[OK] ML model loaded successfully.")
    else:
        print("[!] model.pkl not found - using rule-based fallback.")
except ImportError:
    print("[!] joblib/sklearn not installed - using rule-based fallback.")

# ---------------------------------------------------------------------------
# Suspicious patterns (used for rule-based fallback + reason generation)
# ---------------------------------------------------------------------------
SUSPICIOUS_PATTERNS = [
    r"-enc\s+",                   # Encoded PowerShell commands
    r"-encodedcommand\s+",        # Encoded PowerShell (full flag)
    r"-urlcache",                 # certutil download trick
    r"http[s]?://",               # URLs in command line
    r"Invoke-Expression",         # PowerShell remote execution
    r"IEX\s*\(",                  # PowerShell IEX shorthand
    r"DownloadString",            # PowerShell download
    r"DownloadFile",              # PowerShell download
    r"Start-Process",             # Launching processes
    r"bypass",                    # Execution policy bypass
    r"hidden",                    # Hidden window
    r"regsvr32\s+/s\s+/n\s+/u",  # Squiblydoo attack
    r"vbscript\s*:",              # MSHTA inline VBScript
    r"javascript\s*:",            # Rundll32 inline JavaScript
    r"schtasks\s+/create",        # Scheduled task creation
    r"reg\s+add\s+.*\\run",       # Registry run key persistence
]


# Known safe processes to ignore completely (Allowlist)
ALLOWLIST = [
    r"nvcontainer",
    r"nvidia",
    r"nearby_share",
    r"jsonservermain",
]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _extract_exe_name(cmd):
    """Extract the base executable name from a command line string.

    Handles quoted paths, full paths, and bare exe names.
    Returns lowercase exe name (e.g. 'cmd.exe', 'powershell.exe').
    """
    cmd = cmd.strip().strip('"').strip("'")
    # Take first token (the executable)
    first_token = cmd.split()[0] if cmd.split() else cmd
    first_token = first_token.strip('"').strip("'")
    # Get just the filename
    basename = os.path.basename(first_token).lower()
    return basename


def _confidence_to_severity(confidence):
    """Map model confidence to a severity level."""
    if confidence >= 0.75:
        return "high"
    elif confidence >= 0.5:
        return "medium"
    else:
        return "low"


def _rule_based_severity(command):
    """Determine severity based on regex pattern matches (fallback)."""
    cmd_lower = command.lower()
    matches = sum(1 for p in SUSPICIOUS_PATTERNS if re.search(p, cmd_lower))

    if matches >= 3:
        return "high"
    elif matches >= 2:
        return "medium"
    elif matches >= 1:
        return "low"
    else:
        return "information"


def _get_reason(command):
    """Return a human-readable reason for why the command is suspicious."""
    cmd_lower = command.lower()
    reasons = []

    # Windows reasons
    if re.search(r"-enc\s+", cmd_lower) or re.search(r"-encodedcommand\s+", cmd_lower):
        reasons.append("Encoded command detected")
    if re.search(r"-urlcache", cmd_lower):
        reasons.append("File download via certutil")
    if re.search(r"https?://", cmd_lower):
        reasons.append("URL found in command line")
    if re.search(r"(Invoke-Expression|IEX\s*\()", cmd_lower):
        reasons.append("Remote code execution attempt")
    if re.search(r"(DownloadString|DownloadFile)", cmd_lower):
        reasons.append("File download detected")
    if re.search(r"bypass", cmd_lower):
        reasons.append("Execution policy bypass")
    if re.search(r"hidden", cmd_lower):
        reasons.append("Hidden execution")
    if re.search(r"vbscript\s*:", cmd_lower):
        reasons.append("Inline VBScript execution")
    if re.search(r"javascript\s*:", cmd_lower):
        reasons.append("Inline JavaScript execution")
    if re.search(r"schtasks\s+/create", cmd_lower):
        reasons.append("Scheduled task creation for persistence")
    if re.search(r"reg\s+add\s+.*\\run", cmd_lower):
        reasons.append("Registry Run key persistence")

    if not reasons:
        reasons.append("Known Windows LOLBin usage detected")

    return "; ".join(reasons)


# ---------------------------------------------------------------------------
# Stage 1: Behavioral Analysis  (parent → child process relationships)
# ---------------------------------------------------------------------------

def _behavioral_severity(command, parent):
    """Analyze parent-child process relationship for malicious behavior.

    This is the highest-fidelity detection: certain parent-child combos are
    almost always malicious (e.g., WINWORD.EXE spawning cmd.exe).
    """
    if not parent or parent == "Unknown":
        return None, None

    parent_lower = parent.lower()
    command_lower = command.lower()

    # Extract parent executable name from full path
    parent_exe = os.path.basename(parent_lower).strip()

    # Extract child executable name from command line
    child_exe = _extract_exe_name(command_lower)

    # --- Process category definitions ---

    # Office applications (DOCM macro attack surface)
    office_apps = [
        "winword.exe",    # Word
        "excel.exe",      # Excel
        "powerpnt.exe",   # PowerPoint
        "mspub.exe",      # Publisher
        "visio.exe",      # Visio
        "outlook.exe",    # Outlook
        "msaccess.exe",   # Access
        "onenote.exe",    # OneNote
    ]

    # Browsers (drive-by download / exploit kit surface)
    browsers = [
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "iexplore.exe",
        "brave.exe",
        "opera.exe",
    ]

    # Scripting engines
    scripts = [
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    ]

    # Critical system services
    services = [
        "services.exe",
        "svchost.exe",
        "smss.exe",
        "lsass.exe",
        "csrss.exe",
        "winlogon.exe",
    ]

    # Task/WMI engines (used for persistence/lateral movement)
    task_engines = [
        "wmiprvse.exe",
        "taskeng.exe",
        "taskhostw.exe",
    ]

    # Suspicious children — shells and LOLBins that should NOT be spawned
    # by Office, browsers, etc.
    sus_children = [
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "wmic.exe",
        "cscript.exe",
        "wscript.exe",
        "net.exe",
        "net1.exe",
        "schtasks.exe",
        "reg.exe",
        "msiexec.exe",
        "forfiles.exe",
        "pcalua.exe",
        "bash.exe",         # WSL bash
        "wsl.exe",          # WSL
    ]

    child_is_sus = child_exe in sus_children

    # Also check if the command LINE contains a suspicious binary even if
    # the child exe itself is something neutral (e.g., conhost.exe wrapping cmd.exe)
    if not child_is_sus:
        child_is_sus = any(s in command_lower for s in sus_children)

    if child_is_sus:
        # --- OFFICE APP spawning shell/LOLBin = MACRO ATTACK ---
        if parent_exe in office_apps:
            return "high", f"Malicious Office Macro Behavior: {parent_exe} spawned {child_exe} [{command[:60]}...]"

        # --- BROWSER spawning shell/LOLBin = EXPLOIT / DRIVE-BY ---
        if parent_exe in browsers:
            return "high", f"Browser Exploit Behavior: {parent_exe} spawned {child_exe} [{command[:60]}...]"

        # --- SCRIPT ENGINE spawning another shell = STAGED ATTACK ---
        if parent_exe in scripts:
            return "high", f"Malicious Script Execution: {parent_exe} spawned {child_exe} [{command[:60]}...]"

        # --- TASK/WMI ENGINE spawning shell = PERSISTENCE FIRING ---
        if parent_exe in task_engines:
            return "medium", f"Scheduled/WMI Task Execution: {parent_exe} spawned {child_exe} [{command[:60]}...]"

    # --- SERVICE spawning unexpected interactive process ---
    if parent_exe in services:
        unexpected_from_service = [
            "cmd.exe", "powershell.exe", "pwsh.exe",
            "calc.exe", "notepad.exe", "mspaint.exe",
            "mshta.exe", "wscript.exe", "cscript.exe",
        ]
        if child_exe in unexpected_from_service:
            return "high", f"Service Hijack/Lateral Movement: {parent_exe} spawned {child_exe} [{command[:60]}...]"

    # --- CMD spawning PowerShell (multi-stage chain) ---
    if parent_exe == "cmd.exe" and child_exe in ["powershell.exe", "pwsh.exe"]:
        # Check if the PowerShell command has suspicious flags
        if re.search(r"(-enc\s|-w\s*hidden|-nop|-executionpolicy\s+bypass|downloadstring|iex)", command_lower):
            return "high", f"Multi-stage Attack Chain: cmd.exe -> powershell.exe with suspicious flags [{command[:60]}...]"

    return None, None


# ---------------------------------------------------------------------------
# Stage 2: Signature Engine  (explicit malicious LOLBin tactical patterns)
# ---------------------------------------------------------------------------

def _lolbin_signature_match(command):
    """Detect explicitly malicious LOLBin tactical signatures.

    Each signature matches a specific, well-documented attack technique
    from the LOLBAS project and MITRE ATT&CK framework.
    """
    cmd_lower = command.lower()

    signatures = {
        # =================================================================
        # EXECUTION — Running arbitrary code via trusted binaries
        # =================================================================
        "MSHTA Remote Script Execution": r"mshta\s+(http|ftp)",
        "MSHTA Inline VBScript Execution": r"mshta\s+vbscript\s*:",
        "MSHTA Inline JavaScript Execution": r"mshta\s+javascript\s*:",
        "Rundll32 JavaScript Execution": r"rundll32\s+javascript\s*:",
        "Rundll32 VBScript via mshtml": r"rundll32.*mshtml.*RunHTMLApplication",
        "Rundll32 DLL Entry Point": r"rundll32\.exe\s+.*\.dll\s*,\s*#?\w+",
        "WMIC Process Create": r"wmic.*process\s+call\s+create",
        "WMIC Remote Execution": r"wmic\s+/node\s*:",
        "Forfiles Proxy Execution": r"forfiles\s+.*?/c\s+",
        "Pcalua Proxy Execution": r"pcalua\.exe\s+-a\s+",
        "InstallUtil .NET Execution": r"installutil\s+(/logfile=|/logtoconsole=false|/u\s+)",
        "MSBuild Inline Task Execution": r"msbuild\.exe\s+.*\.(xml|csproj|targets)",
        "Regasm/Regsvcs .NET Execution": r"(regasm|regsvcs)\.exe\s+.*\.dll",
        "Cmstp INF Execution (UAC Bypass)": r"cmstp\.exe\s+/s\s+.*\.inf",
        "Squiblydoo AppLocker Bypass (Regsvr32)": r"regsvr32.*(/i|/s|/u).*http.*scrobj\.dll",
        "Regsvr32 Remote Scriptlet": r"regsvr32.*(/i\s*:\s*http|/i\s*:\s*ftp).*scrobj",
        "PowerShell Fileless Obfuscation": r"powershell.*?-(e|enc|encodedcommand)\s+[a-z0-9+/=\s]{20,}",
        "Execution Policy Bypass": r"powershell.*?-executionpolicy\s+(bypass|unrestricted)",
        "PowerShell Hidden Window": r"powershell.*?(-w\s+hidden|-windowstyle\s+hidden)",

        # =================================================================
        # DOWNLOAD / PAYLOAD DELIVERY
        # =================================================================
        "Certutil Network Fetch": r"certutil.*?-(urlcache|split|f).*?http",
        "Certutil Base64 Decode": r"certutil\s+-decode\s+",
        "Bitsadmin Download Payload": r"bitsadmin.*?/transfer.*?http",
        "Bitsadmin Create + AddFile": r"bitsadmin.*?/addfile\s+",
        "PowerShell Remote Download": r"powershell.*?(downloadstring|downloadfile|invoke-webrequest|invoke-restmethod).*?http",
        "PowerShell File Download and Save": r"powershell.*?(new-object\s+net\.webclient|invoke-webrequest|wget|curl).*?(out-file|set-content|-outfile)",
        "PowerShell WebClient Execution": r"net\.webclient",
        "PowerShell IEX Remote Execution": r"(iex|invoke-expression)\s*\(\s*(new-object|iwr|invoke-webrequest)",
        "Msiexec Remote Package Install": r"msiexec\s+.*?/i\s+http",
        "Msiexec Quiet Install": r"msiexec\s+.*?(/q|/quiet)\s+",

        # =================================================================
        # FILE CREATE (Writing payloads to disk)
        # =================================================================
        "PowerShell File Write (Out-File)": r"powershell.*?(out-file|set-content|add-content)\s+.*?(-filepath\s+|'[a-z]:\\|\"[a-z]:\\)",
        "PowerShell File Write (.NET)": r"powershell.*?(writealltext|writeallbytes|writeallines|streamwriter)",
        "PowerShell File Write to Disk": r"powershell.*?(out-file|set-content|add-content).*?\\.*?\.(exe|bat|ps1|vbs|txt|cmd|dll|js|hta|log|csv)",
        "PowerShell File Create (New-Item)": r"powershell.*?new-item\s+.*?(-path\s+|-itemtype\s+)",
        "PowerShell File Copy (Copy-Item)": r"powershell.*?copy-item\s+.*?-destination\s+",
        "CMD File Drop via Echo": r"cmd.*?echo.*?>.*?\\.*?\.(exe|bat|ps1|vbs|cmd|js|hta)",

        # =================================================================
        # FILE READ / DATA EXFILTRATION
        # =================================================================
        "PowerShell File Read (Get-Content)": r"powershell.*?(get-content|gc|cat|type)\s+.*?(-path\s+|'[a-z]:\\|\"[a-z]:\\)",
        "PowerShell File Read (.NET)": r"powershell.*?(readalltext|readallbytes|readallines|streamreader)",
        "PowerShell Registry Read": r"powershell.*?(get-itemproperty|get-itempropertyvalue)\s+.*?(hklm|hkcu|registry)",
        "PowerShell Credential Harvesting": r"powershell.*?(get-credential|convertto-securestring|get-localuser|get-aduser)",
        "CMD File Read": r"cmd.*?type\s+.*?\\.*?\.(txt|log|csv|ini|conf|xml|json|dat)",

        # =================================================================
        # SYSTEM MODIFICATION / PERSISTENCE
        # =================================================================
        "PowerShell Registry Modification": r"powershell.*?(set-itemproperty|new-itemproperty)\s+.*?(hklm|hkcu|registry)",
        "PowerShell Service Modification": r"powershell.*?(set-service|new-service|sc\.exe)\s+",
        "PowerShell Scheduled Task Creation": r"powershell.*?(register-scheduledtask|schtasks)\s+",
        "Schtasks Command-Line Persistence": r"schtasks\s+/create\s+.*?/tr\s+",
        "Schtasks Immediate Run": r"schtasks\s+/run\s+/tn\s+",
        "PowerShell Firewall Rule Change": r"powershell.*?(new-netfirewallrule|set-netfirewallrule|netsh\s+firewall)",
        "Registry Run Key Persistence (reg.exe)": r"reg\s+add\s+.*(\\run|\\runonce)\s+",
        "Registry Run Key via PowerShell": r"powershell.*?(set-itemproperty|new-itemproperty).*?(\\run|\\runonce)",
        "PowerShell File Modify (Set-Content)": r"powershell.*?set-content\s+.*?-value\s+",
        "Net User Add": r"net\s+user\s+\S+\s+\S+\s+/add",
        "Net Localgroup Admin Add": r"net\s+localgroup\s+administrators\s+\S+\s+/add",
        "Netsh Firewall Disable": r"netsh\s+(advfirewall\s+set|firewall\s+set).*?(off|disable)",
        "Netsh Port Forwarding": r"netsh\s+interface\s+portproxy\s+add",

        # =================================================================
        # FILE DELETE / ANTI-FORENSICS
        # =================================================================
        "PowerShell File Delete (Remove-Item)": r"powershell.*?(remove-item|rm|del|erase)\s+.*?(-path\s+|'[a-z]:\\|\"[a-z]:\\)",
        "PowerShell File Delete (.NET)": r"powershell.*?(file::delete|directory::delete)",
        "PowerShell File Delete from Disk": r"powershell.*?(remove-item|del|rm)\s+.*?\\.*?\.(exe|bat|ps1|vbs|txt|cmd|dll|js|hta|log|csv)",
        "PowerShell Event Log Clearing": r"powershell.*?(clear-eventlog|wevtutil\s+cl|remove-eventlog)",
        "CMD File Deletion": r"cmd.*?(del|erase|rmdir)\s+.*?\\.*?\.(exe|bat|ps1|vbs|txt|cmd|dll|js|hta)",
        "Wevtutil Event Log Clearing": r"wevtutil\s+cl\s+",
        "Fsutil USN Journal Delete": r"fsutil\s+usn\s+deletejournal",

        # =================================================================
        # RECONNAISSANCE
        # =================================================================
        "Net Domain Enumeration": r"net\s+(user|group|localgroup|share|view|session)\s+/domain",
        "Nltest Domain Trust Enum": r"nltest\s+/domain_trusts",
        "PowerShell AD Enumeration": r"powershell.*?(get-adcomputer|get-addomain|get-adgroup|get-aduser|get-adforest)",
        "Dsquery Enumeration": r"dsquery\s+(user|computer|group|ou)\s+",
        "Systeminfo Reconnaissance": r"systeminfo\s*(\||>|$)",
        "Whoami Privilege Check": r"whoami\s+/priv",
        "Tasklist Process Enum": r"tasklist\s+/v",

        # =================================================================
        # LATERAL MOVEMENT
        # =================================================================
        "PsExec Remote Execution": r"psexec.*?\\\\",
        "WinRM Remote Execution": r"(invoke-command|enter-pssession)\s+.*?-computername\s+",

    }

    for reason, pattern in signatures.items():
        if re.search(pattern, cmd_lower):
            return "high", f"Signature Match: {reason}"

    return None, None


# ---------------------------------------------------------------------------
# Main detection entry point
# ---------------------------------------------------------------------------

def detect(command, parent="Unknown"):
    """
    Analyze a command string and its parent process for suspicious Windows LOLBin activity.

    Detection pipeline (in priority order):
        1. Behavioral Analysis  — parent-child relationship
        2. Signature Engine     — tactical LOLBin patterns
        3. ML Model             — Random Forest
        4. Rule-based fallback  — regex counting

    Args:
        command: The command-line string to analyze.
        parent: The creator process name (full path or exe name).

    Returns:
        A dict with keys (command, parent, severity, reason, confidence, method)
        if suspicious, or None if the command appears benign.
    """
    if not command or not isinstance(command, str):
        return None

    cmd_lower = command.lower().strip()

    # --- Check if any Windows LOLBin is present ---
    is_lolbin = any(tool in cmd_lower for tool in ALL_LOLBINS)

    if parent == "PowerShell_Script":
        is_lolbin = True

    # Also check if the parent is an Office app (DOCM macro scenario):
    # even a simple `cmd.exe /c echo test` is suspicious from Word
    if parent and parent != "Unknown":
        parent_exe = os.path.basename(parent.lower()).strip()
        office_parents = [
            "winword.exe", "excel.exe", "powerpnt.exe", "mspub.exe",
            "visio.exe", "outlook.exe", "msaccess.exe", "onenote.exe",
        ]
        if parent_exe in office_parents:
            is_lolbin = True

    if not is_lolbin:
        return None

    # --- Allowlist Check ---
    if any(re.search(pattern, cmd_lower) for pattern in ALLOWLIST):
        return None

    # --- STAGE 1: BEHAVIORAL ANALYSIS (highest priority) ---
    b_severity, b_reason = _behavioral_severity(command, parent)
    if b_severity:
        return {
            "command": command.strip(),
            "parent": parent,
            "severity": b_severity,
            "reason": b_reason,
            "confidence": 1.0,
            "method": "behavior_analyzer",
        }

    # --- STAGE 2: SIGNATURE ENGINE ---
    sig_severity, sig_reason = _lolbin_signature_match(command)
    if sig_severity:
        return {
            "command": command.strip(),
            "parent": parent,
            "severity": sig_severity,
            "reason": sig_reason,
            "confidence": 1.0,
            "method": "signature_match"
        }

    # --- STAGE 3: ML MODEL ---
    if _model is not None:
        try:
            features = extract_features(command)
            feature_vector = [features_to_list(features)]
            prediction = _model.predict(feature_vector)[0]
            probabilities = _model.predict_proba(feature_vector)[0]
            confidence = float(probabilities[1])  # probability of malicious

            if prediction == 1 or confidence >= 0.4:
                # Sanity check: if NO suspicious regex patterns match, discard
                rule_severity = _rule_based_severity(command)
                if rule_severity == "information":
                    return None

                severity = _confidence_to_severity(confidence)
                reason = _get_reason(command)

                return {
                    "command": command.strip(),
                    "parent": parent,
                    "severity": severity,
                    "reason": reason,
                    "confidence": round(confidence, 4),
                    "method": "ml_model",
                }
            else:
                return None

        except Exception as e:
            print(f"[!] ML prediction error: {e} - falling back to rules")

    # --- STAGE 4: RULE-BASED FALLBACK ---
    severity = _rule_based_severity(command)
    if severity == "information":
        return None

    reason = _get_reason(command)

    return {
        "command": command.strip(),
        "parent": parent,
        "severity": severity,
        "reason": reason,
        "confidence": None,
        "method": "rule_based",
    }