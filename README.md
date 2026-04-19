<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows-blue?logo=windows" />
  <img src="https://img.shields.io/badge/python-3.8%2B-green?logo=python" />
  <img src="https://img.shields.io/badge/license-MIT-orange" />
  <img src="https://img.shields.io/badge/ML-Random%20Forest-purple" />
  <img src="https://img.shields.io/github/stars/turtle0x21/lolbins-threat-detection?style=social" />
</p>

# 🛡️ LOLBins Threat Detection System

A **real-time Windows LOLBins (Living Off The Land Binaries) threat detection system** that monitors process creation events at the kernel level and uses a multi-stage detection pipeline — combining behavioral analysis, signature matching, and machine learning — to identify malicious abuse of legitimate Windows binaries.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Detection Pipeline](#detection-pipeline)
- [Monitored LOLBins](#monitored-lolbins)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Training the ML Model](#training-the-ml-model)
- [Web Dashboard](#web-dashboard)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Attackers frequently abuse trusted, legitimate Windows binaries — known as **LOLBins** — to execute malicious payloads, download malware, establish persistence, and evade traditional antivirus solutions. This project provides a defense system that:

- 🔍 **Monitors** Windows Event Log (Event ID 4688) for real-time process creation events
- 🧠 **Analyzes** command-line arguments using a 4-stage detection pipeline
- 🚨 **Alerts** in real-time via CLI output and a web dashboard
- 📊 **Classifies** threats by severity (Low / Medium / High) with confidence scores

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Windows Event Log                         │
│                  (Event ID 4688 — Process Creation)          │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                      AGENT (agent.py)                        │
│  • Polls Security Event Log via PowerShell (poll_events.ps1) │
│  • Pre-filters LOLBin usage                                  │
│  • Sends suspicious commands to server via REST API          │
└────────────────────────┬─────────────────────────────────────┘
                         │  HTTP POST /ingest
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                   SERVER (Flask — app.py)                     │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │           4-STAGE DETECTION PIPELINE                  │    │
│  │                                                       │    │
│  │  Stage 1: Behavioral Analysis (parent-child process)  │    │
│  │  Stage 2: Signature Engine (LOLBAS/MITRE ATT&CK)     │    │
│  │  Stage 3: ML Model (Random Forest Classifier)         │    │
│  │  Stage 4: Rule-Based Fallback (regex patterns)        │    │
│  └──────────────────────────────────────────────────────┘    │
│                                                              │
│  • SQLite database for alerts & user management              │
│  • API key authentication                                    │
│  • Real-time alert logging                                   │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                    WEB DASHBOARD                              │
│  • Live alert feed with severity indicators                  │
│  • User registration & login                                 │
│  • API key management                                        │
└──────────────────────────────────────────────────────────────┘
```

---

## Detection Pipeline

The system processes each command through **4 detection stages** in priority order:

| Stage | Method | Description | Confidence |
|-------|--------|-------------|------------|
| **1** | Behavioral Analysis | Detects malicious parent→child process relationships (e.g., `WINWORD.EXE` → `cmd.exe`) | 100% |
| **2** | Signature Engine | Matches ~50+ tactical signatures from LOLBAS project & MITRE ATT&CK | 100% |
| **3** | ML Model | Random Forest classifier trained on LOLBin attack samples | Variable |
| **4** | Rule-Based Fallback | Regex pattern counting for suspicious indicators | N/A |

### Attack Categories Detected

- **Execution** — MSHTA, Rundll32, WMIC process create, Squiblydoo, etc.
- **Download / Payload Delivery** — Certutil, BitsAdmin, PowerShell webclient
- **Persistence** — Scheduled tasks, registry run keys, service modification
- **Defense Evasion** — Encoded commands, execution policy bypass, event log clearing
- **Reconnaissance** — Domain enumeration, privilege checking, AD queries
- **Lateral Movement** — PsExec, WinRM remote execution

---

## Monitored LOLBins

| Binary | Abuse Type |
|--------|-----------|
| `powershell.exe` | Encoded commands, download cradles, fileless execution |
| `cmd.exe` | Command chaining, payload staging |
| `certutil.exe` | File download, base64 decode |
| `mshta.exe` | Remote HTA execution, inline VBScript/JavaScript |
| `rundll32.exe` | DLL sideloading, JavaScript execution |
| `regsvr32.exe` | Squiblydoo attack, remote scriptlet loading |
| `wmic.exe` | Remote process creation, shadow copy deletion |
| `bitsadmin.exe` | Background file download |
| `cscript.exe` / `wscript.exe` | Malicious script execution |
| `schtasks.exe` | Scheduled task persistence |
| `reg.exe` | Registry run key persistence |
| `msiexec.exe` | Remote MSI package install |
| `net.exe` | User creation, privilege escalation |
| `netsh.exe` | Firewall disable, port forwarding |
| + 8 more | `forfiles`, `pcalua`, `installutil`, `msbuild`, `regasm`, `cmstp`, `wevtutil`, `fsutil` |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Agent | Python, PowerShell (Event ID 4688 polling) |
| Server | Flask, SQLite |
| ML Model | scikit-learn (Random Forest Classifier) |
| Feature Extraction | Custom 10-feature vector (regex-based) |
| Frontend | HTML, CSS, JavaScript |
| Auth | API key + session-based authentication |

---

## Prerequisites

- **Windows 10/11** (or Windows Server 2016+)
- **Python 3.8+**
- **Administrator privileges** (required for Security Event Log access)
- **Audit Process Creation** policy enabled (Event ID 4688)

### Enable Audit Policy

Run the following in an elevated PowerShell:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

To also capture command-line arguments in Event 4688:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

---

## Installation

1. **Clone the repository**

```bash
git clone https://github.com/turtle0x21/lolbins-threat-detection.git
cd lolbins-threat-detection
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

3. **Train the ML model** (one-time setup)

```bash
python server/model_trainer.py
```

4. **Run the system**

```bash
python start.py
```

> The start script will automatically request Administrator privileges via UAC, launch the Flask server in the background, and start the agent in the terminal.

---

## Usage

### Quick Start

```bash
python start.py
```

You will be prompted for an API key on first run. Register an account via the web dashboard first:

1. Open `http://127.0.0.1:5000/register` in your browser
2. Create an account
3. Copy your API key from the dashboard
4. Paste it when the agent prompts you

### Running Components Individually

**Server only:**
```bash
python server/app.py
```

**Agent only:**
```bash
python agent/agent.py
```

### Testing Detection

Open a new terminal and run something suspicious:

```powershell
# This will trigger a HIGH severity alert
certutil.exe -urlcache -split -f http://example.com/test.txt C:\temp\test.txt
```

The agent will detect it and print an alert like:

```
[ALERT] HIGH: certutil.exe -urlcache -split -f http://example.com/test.txt...
    Parent    : cmd.exe
    Reason    : Signature Match: Certutil Network Fetch
    Method    : signature_match
    Confidence: 100.0%
```

---

## Project Structure

```
lolbins-threat-detection/
├── start.py                    # Main entry point (launches server + agent)
├── requirements.txt            # Python dependencies
├── agent/
│   ├── agent.py                # Windows Event Log monitoring agent
│   ├── config.json             # API key & server URL configuration
│   ├── enable_logging.ps1      # Script to enable audit policies
│   └── poll_events.ps1         # PowerShell script for Event ID 4688 polling
├── server/
│   ├── app.py                  # Flask web server & API endpoints
│   ├── auth.py                 # API key authentication middleware
│   ├── database.py             # SQLite database operations
│   ├── detector.py             # 4-stage detection pipeline
│   ├── feature_extractor.py    # ML feature extraction (10-feature vector)
│   ├── model_trainer.py        # Random Forest model training script
│   └── lolbins.db              # SQLite database (auto-created)
└── web/
    ├── static/
    │   └── style.css           # Dashboard styling
    └── templates/
        ├── dashboard.html      # Alert dashboard
        ├── login.html          # Login page
        └── register.html       # Registration page
```

---

## Training the ML Model

The system uses a **Random Forest classifier** with 10 engineered features:

| # | Feature | Description |
|---|---------|-------------|
| 1 | `cmd_length` | Total command string length |
| 2 | `has_encoded_flag` | Presence of `-enc` / `-encodedcommand` |
| 3 | `has_url` | HTTP/HTTPS URL detected |
| 4 | `has_download_keyword` | Download functions (DownloadString, etc.) |
| 5 | `has_bypass` | Execution policy bypass keyword |
| 6 | `has_hidden` | Hidden window style flag |
| 7 | `keyword_count` | Count of suspicious keyword matches |
| 8 | `special_char_ratio` | Special character density (obfuscation indicator) |
| 9 | `is_lolbin` | Known LOLBin binary present |
| 10 | `pipe_count` | Number of pipe operators (command chaining) |

To retrain the model with updated training data:

```bash
python server/model_trainer.py
```

This generates `server/model.pkl` which the detector loads at startup.

---

## Web Dashboard

The web dashboard provides a visual interface for monitoring alerts:

- **Login / Register** — Create an account to access the dashboard
- **API Key** — Each user gets a unique API key for agent authentication
- **Alert Feed** — View real-time alerts with severity, reason, confidence, and detection method
- **Alert History** — Browse historical alerts with filtering

Access the dashboard at: `http://127.0.0.1:5000`

---

## 🤝 Contributing

We welcome contributions from the security community! This project is **open for open-source contributions**.

### How to Contribute

1. **Fork the repo** — Click the "Fork" button on [GitHub](https://github.com/turtle0x21/lolbins-threat-detection)

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/lolbins-threat-detection.git
   cd lolbins-threat-detection
   ```

3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make your changes** — Write clean, documented code

5. **Test your changes** — Ensure the detection pipeline works correctly

6. **Commit and push**
   ```bash
   git add .
   git commit -m "feat: description of your change"
   git push origin feature/your-feature-name
   ```

7. **Open a Pull Request** — Describe your changes and link any related issues

### What We're Looking For

| Area | Ideas |
|------|-------|
| 🔍 **Detection Signatures** | New LOLBin attack signatures from LOLBAS/MITRE ATT&CK |
| 🧠 **ML Improvements** | More training data, better features, model tuning |
| 🖥️ **Dashboard** | UI improvements, filtering, search, export |
| 📊 **Reporting** | PDF/CSV alert export, email notifications |
| 🧪 **Testing** | Unit tests, integration tests, test attack samples |
| 📝 **Documentation** | Tutorials, setup guides, detection rule docs |
| 🐛 **Bug Fixes** | Fix issues, improve error handling |
| 🔧 **Performance** | Reduce resource usage, optimize polling |

### Contribution Guidelines

- Follow existing code style and patterns
- Add docstrings to new functions
- Update the README if adding new features
- Keep commits focused and well-described
- Be respectful in all interactions

### Reporting Issues

Found a bug or have a feature request? [Open an issue](https://github.com/turtle0x21/lolbins-threat-detection/issues) with:
- A clear title and description
- Steps to reproduce (for bugs)
- Expected vs. actual behavior
- Your Windows version and Python version

---

## ⚠️ Disclaimer

This tool is designed for **defensive security research and monitoring** purposes only. Use it responsibly and only on systems you own or have explicit permission to monitor. The authors are not responsible for any misuse.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ⭐ Star This Repo

If you find this project useful, please give it a ⭐ on [GitHub](https://github.com/turtle0x21/lolbins-threat-detection)! It helps others discover the project.

---

<p align="center">
  Made with 🔒 for the security community
</p>
