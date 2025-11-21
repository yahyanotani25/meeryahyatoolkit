#!/usr/bin/env python3
"""
Enhanced Terminal UI with Animations and Visual Effects
Beautiful, production-ready interface for MeeryahyaToolkit
"""

import os
import sys
import time
import threading
import itertools
from typing import List, Optional
from ui_manager import TerminalUI, Colors


class AnimatedUI(TerminalUI):
    """Enhanced UI with animations and visual effects"""

    def __init__(self):
        super().__init__()
        self.spinner_active = False
        self.spinner_thread = None

    def animate_text(self, text: str, delay: float = 0.03):
        """Type-writer effect for text"""
        for char in text:
            print(char, end='', flush=True)
            time.sleep(delay)
        print()

    def loading_bar_animated(self, duration: float = 2.0, message: str = "Loading"):
        """Animated loading bar"""
        width = 50
        for i in range(width + 1):
            percent = (i / width) * 100
            filled = int(width * i / width)
            bar = f"{self.colors.GREEN}{'█' * filled}{self.colors.DIM}{'░' * (width - filled)}{self.colors.RESET}"
            print(f"\r{message}... [{bar}] {int(percent)}%", end='', flush=True)
            time.sleep(duration / width)
        print()

    def spinner(self, message: str = "Processing"):
        """Animated spinner"""
        spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'] if os.name != 'nt' else ['|', '/', '-', '\\']

        for char in itertools.cycle(spinner_chars):
            if not self.spinner_active:
                break
            print(f"\r{self.colors.CYAN}{char}{self.colors.RESET} {message}...", end='', flush=True)
            time.sleep(0.1)
        print(f"\r{' ' * (len(message) + 10)}\r", end='', flush=True)

    def start_spinner(self, message: str = "Processing"):
        """Start spinner in background thread"""
        self.spinner_active = True
        self.spinner_thread = threading.Thread(target=self.spinner, args=(message,))
        self.spinner_thread.daemon = True
        self.spinner_thread.start()

    def stop_spinner(self):
        """Stop background spinner"""
        self.spinner_active = False
        if self.spinner_thread:
            self.spinner_thread.join()

    def pulse_text(self, text: str, color: str = None, pulses: int = 3):
        """Pulsing text effect"""
        if color is None:
            color = self.colors.CYAN

        for _ in range(pulses):
            print(f"\r{color}{self.colors.BOLD}{text}{self.colors.RESET}", end='', flush=True)
            time.sleep(0.3)
            print(f"\r{color}{self.colors.DIM}{text}{self.colors.RESET}", end='', flush=True)
            time.sleep(0.3)
        print(f"\r{color}{self.colors.BOLD}{text}{self.colors.RESET}")

    def wave_banner(self):
        """Animated wave banner"""
        banner_lines = [
            "███╗   ███╗███████╗███████╗██████╗ ██╗   ██╗",
            "████╗ ████║██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝",
            "██╔████╔██║█████╗  █████╗  ██████╔╝ ╚████╔╝ ",
            "██║╚██╔╝██║██╔══╝  ██╔══╝  ██╔══██╗  ╚██╔╝  ",
            "██║ ╚═╝ ██║███████╗███████╗██║  ██║   ██║   ",
            "╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   "
        ]

        self.clear_screen()
        print("\n")
        for line in banner_lines:
            print(f"{self.colors.RED}{self.colors.BOLD}{line}{self.colors.RESET}")
            time.sleep(0.1)

        # Subtitle with type effect
        time.sleep(0.3)
        subtitle = "ADVANCED SECURITY RESEARCH FRAMEWORK"
        print(f"\n{self.colors.CYAN}", end='')
        for char in subtitle.center(self.width):
            print(char, end='', flush=True)
            time.sleep(0.02)
        print(self.colors.RESET)

    def success_animation(self, message: str):
        """Animated success message"""
        # Build up effect
        for i in range(1, 4):
            print(f"\r{self.colors.GREEN}{'.' * i}{self.colors.RESET}", end='', flush=True)
            time.sleep(0.2)

        # Final success
        print(f"\r{self.colors.SUCCESS} {self.colors.GREEN}{self.colors.BOLD}{message}{self.colors.RESET}")
        time.sleep(0.5)

    def error_animation(self, message: str):
        """Animated error message"""
        # Flash effect
        for _ in range(2):
            print(f"\r{self.colors.BG_RED}{self.colors.WHITE} ERROR {self.colors.RESET} {message}", end='', flush=True)
            time.sleep(0.2)
            print(f"\r{' ' * (len(message) + 10)}", end='', flush=True)
            time.sleep(0.1)

        # Final error
        print(f"\r{self.colors.ERROR} {self.colors.RED}{self.colors.BOLD}{message}{self.colors.RESET}")

    def matrix_effect(self, duration: float = 2.0):
        """Matrix-style falling characters effect"""
        import random
        import string

        chars = string.ascii_letters + string.digits
        width = min(self.width, 80)

        # Clear screen
        self.clear_screen()

        # Create columns
        columns = [random.randint(0, 20) for _ in range(width)]

        start_time = time.time()
        while time.time() - start_time < duration:
            line = ""
            for i in range(width):
                if random.random() > 0.95:
                    columns[i] = 0

                if columns[i] == 0:
                    line += f"{self.colors.GREEN}{random.choice(chars)}{self.colors.RESET}"
                else:
                    line += " "

                columns[i] += 1
                if columns[i] > 20:
                    columns[i] = 0

            print(line)
            time.sleep(0.05)

    def countdown(self, seconds: int, message: str = "Starting in"):
        """Animated countdown"""
        for i in range(seconds, 0, -1):
            print(f"\r{self.colors.YELLOW}{message}: {self.colors.BOLD}{i}{self.colors.RESET}  ", end='', flush=True)
            time.sleep(1)
        print(f"\r{self.colors.GREEN}{message}: {self.colors.BOLD}GO!{self.colors.RESET}  ")

    def show_capabilities_animated(self):
        """Show capabilities with animations"""
        self.clear_screen()
        self.wave_banner()

        print(f"\n{self.colors.CYAN}{self.colors.BOLD}═" * self.width + f"{self.colors.RESET}\n")

        capabilities = [
            ("🎯 Command & Control", "Control compromised systems remotely via 6 different channels"),
            ("💥 Exploitation", "Attack vulnerable systems with 7+ real exploits"),
            ("🔒 Persistence", "Survive reboots and stay hidden on target systems"),
            ("📡 Data Theft", "Steal passwords, files, and sensitive information"),
            ("👻 Stealth", "Hide from antivirus and security tools"),
            ("🗑️ Anti-Forensics", "Erase all traces and evidence"),
            ("🌐 Lateral Movement", "Spread across networks automatically"),
            ("⚡ Supply Chain", "Backdoor software packages (npm, PyPI, Maven)")
        ]

        for icon, description in capabilities:
            # Animated entry
            print(f"{self.colors.GREEN}●{self.colors.RESET} ", end='', flush=True)
            time.sleep(0.1)

            print(f"{self.colors.BOLD}{icon}{self.colors.RESET}", end='', flush=True)
            time.sleep(0.1)

            print(f" - {description}")
            time.sleep(0.2)

        print(f"\n{self.colors.CYAN}{self.colors.BOLD}═" * self.width + f"{self.colors.RESET}\n")

    def show_warning_animated(self):
        """Animated warning screen"""
        self.clear_screen()

        # Pulsing warning
        warning_text = "⚠ WARNING ⚠"
        for _ in range(3):
            print(f"\r{self.colors.YELLOW}{self.colors.BOLD}{warning_text.center(self.width)}{self.colors.RESET}", end='', flush=True)
            time.sleep(0.3)
            print(f"\r{' ' * self.width}", end='', flush=True)
            time.sleep(0.2)

        print(f"\r{self.colors.RED}{self.colors.BOLD}{warning_text.center(self.width)}{self.colors.RESET}\n")

        warnings = [
            "This framework contains EXTREMELY DANGEROUS capabilities",
            "Unauthorized use is ILLEGAL and may result in prosecution",
            "ONLY use in authorized, isolated testing environments",
            "Ensure you have proper legal authorization"
        ]

        for warning in warnings:
            time.sleep(0.3)
            print(f"{self.colors.YELLOW}  ▸ {warning}{self.colors.RESET}")

        print()

    def display_module_status(self, modules: List[tuple]):
        """Animated module status display"""
        print(f"\n{self.colors.BOLD}Checking Module Status...{self.colors.RESET}\n")

        for module_name, status, description in modules:
            # Loading effect
            print(f"{self.colors.DIM}Checking {module_name}...{self.colors.RESET}", end='', flush=True)
            time.sleep(0.2)

            # Status
            if status == "operational":
                icon = self.colors.SUCCESS
                color = self.colors.GREEN
            elif status == "warning":
                icon = self.colors.WARNING
                color = self.colors.YELLOW
            else:
                icon = self.colors.ERROR
                color = self.colors.RED

            print(f"\r{icon} {color}{module_name.ljust(30)}{self.colors.RESET} {self.colors.DIM}{description}{self.colors.RESET}")
            time.sleep(0.1)


def demo_animations():
    """Demo all animations"""
    ui = AnimatedUI()

    # 1. Animated banner
    ui.wave_banner()
    time.sleep(1)

    # 2. Show capabilities
    ui.show_capabilities_animated()
    ui.pause()

    # 3. Loading bar
    ui.clear_screen()
    ui.loading_bar_animated(2.0, "Initializing framework")
    time.sleep(0.5)

    # 4. Spinner
    ui.start_spinner("Loading modules")
    time.sleep(3)
    ui.stop_spinner()
    ui.success_animation("Modules loaded successfully!")
    time.sleep(1)

    # 5. Module status
    ui.clear_screen()
    modules = [
        ("C2 Infrastructure", "operational", "6 channels ready"),
        ("Exploit Library", "operational", "7+ CVEs loaded"),
        ("Persistence", "operational", "All platforms supported"),
        ("Data Exfiltration", "operational", "Ready for deployment"),
    ]
    ui.display_module_status(modules)
    ui.pause()

    # 6. Warning
    ui.show_warning_animated()
    ui.pause()

    # 7. Success/Error animations
    ui.clear_screen()
    ui.success_animation("Connection established!")
    time.sleep(1)
    ui.error_animation("Failed to connect to target")
    ui.pause()

    print(f"\n{ui.colors.GREEN}Animation demo complete!{ui.colors.RESET}\n")


if __name__ == "__main__":
    demo_animations()
