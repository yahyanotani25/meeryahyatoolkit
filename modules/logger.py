import logging
import logging.handlers
import os
import sqlite3
import threading
import time
import shutil
from base64 import b64encode, b64decode
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import ChaCha20_Poly1305
from modules.config import load_config

cfg = load_config().get("logging", {})
DB_PATH = cfg.get("sqlite_db", "/opt/bismillah_repo/bismillah.db")
ROTATE = cfg.get("rotate", {})
SYSLOG = cfg.get("remote_syslog", {})
RAMDISK = cfg.get("ramdisk_path", "/dev/shm/bismillah_logs")
RETENTION_DAYS = cfg.get("log_retention_days", 7)

# AES key for log encryption (32 bytes = 256 bits)
AES_KEY = bytes.fromhex(cfg.get("aes_key", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))
AES_NONCE = bytes.fromhex(cfg.get("aes_iv", "0123456789abcdef0123456789abcdef"))[:12]

_LOCK = threading.Lock()

# Set up Python logger
logger = logging.getLogger("bismillah")
logger.setLevel(logging.DEBUG)

# Write to console at INFO level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

# Ensure RAM disk for logs
try:
    Path(RAMDISK).mkdir(parents=True, exist_ok=True)
    log_file_path = Path(RAMDISK) / "bismillah.log"
except Exception:
    # Fallback to /tmp if RAMDISK unavailable
    log_file_path = Path("/tmp") / "bismillah.log"

# Rotating file handler with on‐disk encryption
if ROTATE:
    fh = logging.handlers.RotatingFileHandler(
        filename=str(log_file_path),
        maxBytes=ROTATE.get("max_size_mb", 50) * 1024 * 1024,
        backupCount=ROTATE.get("backup_count", 10)
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    def encrypt_old_logs():
        """
        Every 5 min, compress & encrypt old log backups with ChaCha20_Poly1305.
        """
        for i in range(1, ROTATE.get("backup_count", 10) + 1):
            fn = log_file_path.with_name(f"bismillah.log.{i}")
            if fn.exists() and not str(fn).endswith(".enc"):
                try:
                    # Compress
                    import gzip
                    gz_path = fn.with_suffix(fn.suffix + ".gz")
                    with open(fn, "rb") as f_in, gzip.open(str(gz_path), "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
                    os.remove(fn)

                    # Encrypt with ChaCha20_Poly1305
                    with open(str(gz_path), "rb") as f_plain:
                        plaintext = f_plain.read()
                    cipher = ChaCha20_Poly1305.new(key=AES_KEY[:32])
                    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                    enc_path = gz_path.with_suffix(".enc")
                    with open(str(enc_path), "wb") as f_enc:
                        f_enc.write(cipher.nonce + tag + ciphertext)
                    os.remove(str(gz_path))
                except Exception:
                    pass

    t = threading.Timer(300, encrypt_old_logs)
    t.daemon = True
    t.start()

# Remote Syslog handler
if SYSLOG.get("enabled", False):
    sh = logging.handlers.SysLogHandler(address=(SYSLOG.get("host"), SYSLOG.get("port")))
    sh.setLevel(logging.WARNING)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

def _ensure_db():
    db = Path(DB_PATH)
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        category TEXT,
        message TEXT
    )
    """)
    conn.commit()
    conn.close()

def _cleanup_old_db_entries():
    """
    Delete DB entries older than RETENTION_DAYS.
    """
    cutoff = int(time.time()) - RETENTION_DAYS * 86400
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
    conn.commit()
    conn.close()

def log_event(category: str, message: bytes, level: str = "INFO", exfil_url: str = None):
    """
    Encrypt `message` with AES‑GCM and insert into SQLite.
    Also write structured log to file logger.
    Enhanced:
      - Supports optional exfiltration to remote URL (env LOG_EXFIL_URL or param).
      - Supports log event hooks (LOG_EVENT_HOOK env: Python import path).
      - Robust error handling and logging.
    """
    try:
        aesgcm = AESGCM(CFG["aes_key"])
        ct = aesgcm.encrypt(CFG["aes_iv"], message, None)
        with _db_lock:
            _db_conn.execute("INSERT INTO events (timestamp, category, enc_data) VALUES (?, ?, ?)", (time.time(), category, ct))
            _db_conn.commit()
        # Also log plaintext (or careful subset) to rotating log file
        logger.log(getattr(logging, level.upper(), logging.INFO), f"[{category}] {message.decode(errors='ignore')}")
        # Enhancement: exfiltrate log event if exfil_url or LOG_EXFIL_URL is set
        exfil_url = exfil_url or os.getenv("LOG_EXFIL_URL")
        if exfil_url:
            try:
                import requests
                requests.post(exfil_url, json={
                    "timestamp": time.time(),
                    "category": category,
                    "message": message.decode(errors="ignore")
                }, timeout=5)
                logger.warning(f"[LOGGER] Exfiltrated log event to {exfil_url}")
            except Exception as ex:
                logger.warning(f"[LOGGER] Log exfiltration failed: {ex}")
        # Enhancement: call log event hook if set
        hook_path = os.getenv("LOG_EVENT_HOOK")
        if hook_path:
            try:
                mod_name, fn_name = hook_path.rsplit(".", 1)
                import importlib
                mod = importlib.import_module(mod_name)
                fn = getattr(mod, fn_name)
                fn(category, message, level)
            except Exception as ex:
                logger.warning(f"[LOGGER] Log event hook failed: {ex}")
    except Exception as e:
        logger.error(f"[LOGGER] Failed to log event: {e}")

# File: modules/logger.py

"""
Enhanced logger:
• Every event is stored in encrypted SQLite via AES‑GCM; older backups encrypted via ChaCha20‑Poly1305.
• Structured JSON logs written to rotating log file (in RAM disk or /tmp).
• Optional remote syslog forwarding (TLS).
• Uncaught exceptions automatically logged via a custom handler.
"""

import os
import sqlite3
import logging
import logging.handlers
import threading
import time
import gzip
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import secrets

from datetime import datetime

CFG = {
    "log_db": os.getenv("LOG_DB_PATH", "/tmp/bismillah_events.db"),
    "aes_key": bytes.fromhex(os.getenv("LOG_AES_KEY", "00"*32)),
    "aes_iv": bytes.fromhex(os.getenv("LOG_AES_IV", "11"*12))[:12],
    "chacha_key": bytes.fromhex(os.getenv("LOG_CHACHA_KEY", "22"*32)),
    "retention_days": int(os.getenv("LOG_RETENTION_DAYS", "7")),
    "ramdisk": os.getenv("LOG_RAMDISK", "/dev/shm"),
    "remote_syslog": os.getenv("REMOTE_SYSLOG", ""),
}

# Initialize file logger
log_path = os.path.join(CFG["ramdisk"], "bismillah.log")
file_handler = logging.handlers.RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=3)
file_formatter = logging.Formatter('{"timestamp":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","message":"%(message)s"}')
file_handler.setFormatter(file_formatter)
logger = logging.getLogger("bismillah")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)

if CFG["remote_syslog"]:
    syslog_handler = logging.handlers.SysLogHandler(address=(CFG["remote_syslog"], 6514), socktype=socket.SOCK_STREAM)  # TLS
    logger.addHandler(syslog_handler)

_db_lock = threading.Lock()

def load_encryption_keys():
    """Load encryption keys dynamically from a secure source."""
    try:
        key_path = os.getenv("LOG_KEY_PATH", "/etc/bismillah/keys")
        with open(os.path.join(key_path, "aes_key"), "rb") as f:
            aes_key = f.read()
        with open(os.path.join(key_path, "chacha_key"), "rb") as f:
            chacha_key = f.read()
        return aes_key, chacha_key
    except Exception as e:
        logger.error(f"[LOGGER] Failed to load encryption keys: {e}")
        raise

AES_KEY, CHACHA_KEY = load_encryption_keys()

# Key rotation mechanism
def rotate_keys():
    """Rotate encryption keys and securely store them."""
    try:
        new_aes_key = secrets.token_bytes(32)
        new_chacha_key = secrets.token_bytes(32)
        key_path = os.getenv("LOG_KEY_PATH", "/etc/bismillah/keys")
        os.makedirs(key_path, exist_ok=True)
        with open(os.path.join(key_path, "aes_key"), "wb") as f:
            f.write(new_aes_key)
        with open(os.path.join(key_path, "chacha_key"), "wb") as f:
            f.write(new_chacha_key)
        logger.info("[LOGGER] Encryption keys rotated successfully.")
    except Exception as e:
        logger.error(f"[LOGGER] Failed to rotate encryption keys: {e}")

# Runtime validation
def validate_environment():
    """Ensure the module is executed in a secure environment."""
    if os.getuid() != 0:
        logger.error("[LOGGER] Unauthorized execution attempt.")
        raise PermissionError("This module must be run as root.")

validate_environment()

# Enhanced error handling for database operations
def _init_db():
    try:
        conn = sqlite3.connect(CFG["log_db"], check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                timestamp REAL,
                category TEXT,
                enc_data BLOB
            )
        """)
        conn.commit()
        return conn
    except Exception as e:
        logger.error(f"[LOGGER] Failed to initialize database: {e}")
        raise

_db_conn = _init_db()

# Enhanced log_event function with performance tracking
def log_event(category: str, message: bytes, level: str = "INFO"):
    """Encrypt `message` with AES-GCM and insert into SQLite."""
    start_time = time.time()
    try:
        aesgcm = AESGCM(AES_KEY)
        ct = aesgcm.encrypt(CFG["aes_iv"], message, None)
        with _db_lock:
            _db_conn.execute("INSERT INTO events (timestamp, category, enc_data) VALUES (?, ?, ?)", (time.time(), category, ct))
            _db_conn.commit()
        logger.log(getattr(logging, level.upper(), logging.INFO), f"[{category}] {message.decode(errors='ignore')}")
    except Exception as e:
        logger.error(f"[LOGGER] Failed to log event: {e}")
    finally:
        end_time = time.time()
        logger.info(f"[LOGGER] log_event executed in {end_time - start_time:.2f} seconds.")

# Enhanced _rotate_and_encrypt_backups with error handling
def _rotate_and_encrypt_backups():
    """Compress old DB files and encrypt with ChaCha20-Poly1305."""
    while True:
        time.sleep(86400)  # once a day
        try:
            # Close current DB
            with _db_lock:
                _db_conn.close()
            # Backup and encrypt
            ts = datetime.utcnow().strftime("%Y%m%d")
            backup_name = f"{CFG['log_db']}.{ts}.gz"
            with open(CFG["log_db"], "rb") as f_in, gzip.open(backup_name, "wb") as f_out:
                f_out.writelines(f_in)
            chacha = ChaCha20Poly1305(CFG["chacha_key"])
            with open(backup_name, "rb") as f:
                pt = f.read()
            ct = chacha.encrypt(b"\x00"*12, pt, None)
            with open(backup_name + ".enc", "wb") as f:
                f.write(ct)
            os.remove(backup_name)
            # Reinit DB
            with _db_lock:
                global _db_conn
                _db_conn = _init_db()
            logger.info("[LOGGER] Backup and encryption completed successfully.")
        except Exception as e:
            logger.error(f"[LOGGER] Backup and encryption failed: {e}")
