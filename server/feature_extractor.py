"""
Feature Extractor - Converts raw command strings into numeric feature vectors
for the Random Forest classifier.

Each command is transformed into a dictionary of features that capture
suspicious patterns commonly seen in Windows LOLBin abuse.
"""

import re

# Windows LOLBins
WINDOWS_LOLBINS = [
    "powershell.exe",
    "certutil.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
    "bitsadmin.exe",
    "cscript.exe",
    "wscript.exe",
    "cmd.exe",
    "net.exe",
    "net1.exe",
    "schtasks.exe",
    "reg.exe",
    "forfiles.exe",
    "pcalua.exe",
    "msiexec.exe",
]

# LOLBins list for feature extraction
ALL_LOLBINS = WINDOWS_LOLBINS

# Suspicious keywords (Windows LOLBin patterns)
SUSPICIOUS_KEYWORDS = [
    "invoke-expression", "iex", "downloadstring", "downloadfile",
    "invoke-webrequest", "start-process", "new-object", "bypass",
    "hidden", "noprofile", "noninteractive", "executionpolicy",
    "urlcache", "encodedcommand", "frombase64string",
    "net.webclient", "bitstransfer", "scrobj.dll",
]


def extract_features(command):
    """
    Extract numeric features from a command string.

    Args:
        command: The raw command-line string.

    Returns:
        A dict mapping feature names to float values.
    """
    if not command or not isinstance(command, str):
        return _empty_features()

    cmd_lower = command.lower().strip()

    # Feature 1: Command length
    cmd_length = len(cmd_lower)

    # Feature 2: Has encoded flag (-enc, -encodedcommand, or base64)
    has_encoded_flag = 1.0 if (
        re.search(r"-(enc|encodedcommand)\s+", cmd_lower) or
        re.search(r"base64\s+(-d|--decode)", cmd_lower) or
        re.search(r"\|\s*base64", cmd_lower)
    ) else 0.0

    # Feature 3: Has URL (http:// or https://)
    has_url = 1.0 if re.search(r"https?://", cmd_lower) else 0.0

    # Feature 4: Has download keywords
    download_keywords = [
        "downloadstring", "downloadfile", "invoke-webrequest",
        "urlcache", "bitstransfer",
        "curl", "wget", "/dev/tcp", "scp",
    ]
    has_download_keyword = 1.0 if any(kw in cmd_lower for kw in download_keywords) else 0.0

    # Feature 5: Has bypass keyword
    has_bypass = 1.0 if "bypass" in cmd_lower else 0.0

    # Feature 6: Has hidden execution flag
    has_hidden = 1.0 if re.search(
        r"(hidden|windowstyle\s+hidden|-w\s+hidden)",
        cmd_lower
    ) else 0.0

    # Feature 7: Total count of suspicious keyword matches
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in cmd_lower)

    # Feature 8: Special character ratio (high ratio = possible base64 or obfuscation)
    if len(cmd_lower) > 0:
        special_chars = sum(1 for c in cmd_lower if not c.isalnum() and c != ' ')
        special_char_ratio = special_chars / len(cmd_lower)
    else:
        special_char_ratio = 0.0

    # Feature 9: Is a known Windows LOLBin
    is_lolbin = 1.0 if any(tool in cmd_lower for tool in ALL_LOLBINS) else 0.0

    # Feature 10: Number of pipe operators (chaining)
    pipe_count = cmd_lower.count("|")

    return {
        "cmd_length": float(cmd_length),
        "has_encoded_flag": has_encoded_flag,
        "has_url": has_url,
        "has_download_keyword": has_download_keyword,
        "has_bypass": has_bypass,
        "has_hidden": has_hidden,
        "keyword_count": float(keyword_count),
        "special_char_ratio": round(special_char_ratio, 4),
        "is_lolbin": is_lolbin,
        "pipe_count": float(pipe_count),
    }


def features_to_list(features):
    """
    Convert a features dict to a list in consistent order (for model input).

    Args:
        features: dict from extract_features()

    Returns:
        A list of float values in the canonical feature order.
    """
    return [features[key] for key in FEATURE_NAMES]


def _empty_features():
    """Return a zeroed-out feature dict."""
    return {name: 0.0 for name in FEATURE_NAMES}


# Canonical feature order - must match between trainer and detector
FEATURE_NAMES = [
    "cmd_length",
    "has_encoded_flag",
    "has_url",
    "has_download_keyword",
    "has_bypass",
    "has_hidden",
    "keyword_count",
    "special_char_ratio",
    "is_lolbin",
    "pipe_count",
]
