# modules/audio_ext.py

import os
import threading
import datetime
import wave
import time
import platform
import logging
from modules.logger import log_event

# Dependencies
try:
    import sounddevice as sd
    import soundfile as sf
except ImportError:
    sd = None
    sf = None

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

AUDIO_DIR = os.path.join(os.path.expanduser("~"), "audio_clips")
os.makedirs(AUDIO_DIR, exist_ok=True)

DEFAULT_DURATION = 10       # seconds
SAMPLE_RATE = 44100         # Hz
CHANNELS = 1
DEFAULT_INTERVAL = 120      # seconds

# ──────────────────────────────────────────────────────────────────────────────

def list_audio_devices():
    """
    Return a list of available input audio devices: [{'index': i, 'name': n}, ...]
    """
    if sd is None:
        return []
    devs = []
    try:
        for idx, info in enumerate(sd.query_devices()):
            if info["max_input_channels"] > 0:
                devs.append({"index": idx, "name": info["name"]})
    except Exception as e:
        logging.error(f"[audio_ext] list_audio_devices error: {e}")
    return devs

def record_audio_clip(duration: int = DEFAULT_DURATION, output_path: str = None, device=None, gain: float = 1.0, silence_threshold: float = None, min_len: int = 1) -> bool:
    """
    Records `duration` seconds from the specified microphone `device` (None=default).
    Writes to `output_path` (timestamped file in AUDIO_DIR if None).
    Enhanced:
    - Supports gain (amplification), silence threshold (skip saving if mostly silent), and min_len (min seconds to save).
    - Returns True on success, False on failure.
    """
    if sd is None or sf is None:
        logging.error("[audio_ext] sounddevice or soundfile not installed")
        return False

    # Determine output file path
    if output_path is None:
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(AUDIO_DIR, f"audio_{ts}.wav")

    try:
        # If device is a name, find its index
        dev_index = None
        if device:
            devs = list_audio_devices()
            for d in devs:
                if device.lower() in d["name"].lower():
                    dev_index = d["index"]
                    break
            if dev_index is None and isinstance(device, int):
                dev_index = device
        # Record audio
        frames = sd.rec(int(duration * SAMPLE_RATE),
                        samplerate=SAMPLE_RATE,
                        channels=CHANNELS,
                        device=dev_index)
        sd.wait()
        # Apply gain
        if gain != 1.0:
            frames = frames * gain
        # Silence detection: skip saving if below threshold
        if silence_threshold is not None:
            import numpy as np
            rms = np.sqrt(np.mean(frames**2))
            if rms < silence_threshold:
                logging.info(f"[audio_ext] Skipped saving silent audio (RMS={rms:.5f})")
                log_event({"type": "audio_record_skipped", "reason": "silence", "rms": float(rms)})
                return False
        # Save only if duration is at least min_len
        if duration < min_len:
            logging.info(f"[audio_ext] Skipped saving short audio (<{min_len}s)")
            log_event({"type": "audio_record_skipped", "reason": "too_short"})
            return False
        sf.write(output_path, frames, SAMPLE_RATE, subtype="PCM_16")
        log_event({"type": "audio_record", "file": output_path})
        return True
    except Exception as e:
        logging.error(f"[audio_ext] record_audio_clip error: {e}")
        log_event({"type": "audio_record_failed", "error": str(e)})
        return False

def audio_worker(duration: int, interval: int, device=None, gain: float = 1.0, silence_threshold: float = None, min_len: int = 1):
    """
    Continuously record `duration`-second clips every `interval` seconds.
    Enhanced: passes gain, silence_threshold, min_len to record_audio_clip.
    """
    while True:
        record_audio_clip(duration=duration, output_path=None, device=device, gain=gain, silence_threshold=silence_threshold, min_len=min_len)
        time.sleep(interval)

def start_audio_capture(duration: int = DEFAULT_DURATION, interval: int = DEFAULT_INTERVAL, device=None, gain: float = 1.0, silence_threshold: float = None, min_len: int = 1):
    """
    Start a daemon thread that records `duration`-second audio clip every `interval` seconds.
    Enhanced: supports gain, silence_threshold, min_len.
    Returns Thread object.
    """
    if sd is None or sf is None:
        logging.error("[audio_ext] sounddevice or soundfile not installed; audio disabled")
        return None
    t = threading.Thread(target=audio_worker, args=(duration, interval, device, gain, silence_threshold, min_len), daemon=True)
    t.start()
    return t

def mass_audio_capture(devices=None, duration=DEFAULT_DURATION, interval=DEFAULT_INTERVAL, gain=1.0, silence_threshold=None, min_len=1):
    """
    Dangerous: Start audio capture on multiple devices in parallel.
    Returns list of Thread objects.
    """
    threads = []
    if not devices:
        devices = [None]
    for dev in devices:
        t = start_audio_capture(duration=duration, interval=interval, device=dev, gain=gain, silence_threshold=silence_threshold, min_len=min_len)
        if t:
            threads.append(t)
    return threads

if __name__ == "__main__":
    if sd is None or sf is None:
        print("[!] Install: pip install sounddevice soundfile")
        exit(1)
    print("[+] Available audio devices (indexes):")
    devs = list_audio_devices()
    for d in devs:
        print(f"  {d['index']}: {d['name']}")
    import argparse
    parser = argparse.ArgumentParser(description="Audio Ext (Enhanced)")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION, help="Clip duration (seconds)")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Interval between clips (seconds)")
    parser.add_argument("--gain", type=float, default=1.0, help="Amplification factor")
    parser.add_argument("--silence_threshold", type=float, help="RMS silence threshold (skip if below)")
    parser.add_argument("--min_len", type=int, default=1, help="Minimum duration to save (seconds)")
    parser.add_argument("--device", help="Audio device name or index")
    parser.add_argument("--mass", action="store_true", help="Capture from all input devices")
    args = parser.parse_args()

    if sd is None or sf is None:
        print("[!] Install: pip install sounddevice soundfile")
        exit(1)
    print("[+] Available audio devices (indexes):")
    devs = list_audio_devices()
    for d in devs:
        print(f"  {d['index']}: {d['name']}")
    if args.mass:
        print("[+] Starting mass audio capture on all input devices …")
        mass_audio_capture(
            devices=[d["index"] for d in devs],
            duration=args.duration,
            interval=args.interval,
            gain=args.gain,
            silence_threshold=args.silence_threshold,
            min_len=args.min_len
        )
        print("[+] Mass audio capture threads started (daemon mode).")
        while True:
            time.sleep(60)
    else:
        print(f"[+] Recording {args.duration}s clip …")
        if record_audio_clip(duration=args.duration, device=args.device, gain=args.gain, silence_threshold=args.silence_threshold, min_len=args.min_len):
            print(f"[+] Audio saved to {AUDIO_DIR}")
        else:
            print("[!] Recording failed.")
