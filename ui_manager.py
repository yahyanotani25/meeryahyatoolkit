#!/usr/bin/env python3
"""
MeeryahyaToolkit - Beautiful Terminal UI Manager
Cross-platform terminal interface with red team aesthetics
Works on Linux, Windows, macOS
"""

import os
import sys
import platform
import shutil
from typing import Optional, List, Dict, Any
from datetime import datetime

# Color codes for cross-platform support
class Colors:
    """ANSI color codes with Windows compatibility"""

    # Enable colors on Windows
    if platform.system() == "Windows":
        os.system("color")

    # Main colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    # Styles
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'

    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'

    # Reset
    RESET = '\033[0m'

    # Special chars for boxes (Windows-safe fallbacks)
    BOX_H = '─' if platform.system() != "Windows" else '-'
    BOX_V = '│' if platform.system() != "Windows" else '|'
    BOX_TL = '┌' if platform.system() != "Windows" else '+'
    BOX_TR = '┐' if platform.system() != "Windows" else '+'
    BOX_BL = '└' if platform.system() != "Windows" else '+'
    BOX_BR = '┘' if platform.system() != "Windows" else '+'
    BOX_ML = '├' if platform.system() != "Windows" else '+'
    BOX_MR = '┤' if platform.system() != "Windows" else '+'

    # Status indicators
    SUCCESS = f'{GREEN}✓{RESET}' if platform.system() != "Windows" else f'{GREEN}[+]{RESET}'
    ERROR = f'{RED}✗{RESET}' if platform.system() != "Windows" else f'{RED}[-]{RESET}'
    WARNING = f'{YELLOW}⚠{RESET}' if platform.system() != "Windows" else f'{YELLOW}[!]{RESET}'
    INFO = f'{BLUE}ℹ{RESET}' if platform.system() != "Windows" else f'{BLUE}[i]{RESET}'
    ARROW = f'{CYAN}➤{RESET}' if platform.system() != "Windows" else f'{CYAN}>{RESET}'


class TerminalUI:
    """Beautiful terminal UI manager with red team aesthetics"""

    def __init__(self):
        self.width = self._get_terminal_width()
        self.colors = Colors()

    def _get_terminal_width(self) -> int:
        """Get terminal width, fallback to 80"""
        try:
            return shutil.get_terminal_size().columns
        except:
            return 80

    def clear_screen(self):
        """Clear terminal screen (cross-platform)"""
        os.system('cls' if platform.system() == 'Windows' else 'clear')

    def print_banner(self, variant: str = "main"):
        """Print beautiful ASCII banner"""
        self.clear_screen()

        if variant == "main":
            banner = f"""
{self.colors.RED}{self.colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║              ███╗   ███╗███████╗███████╗██████╗ ██╗   ██╗                ║
║              ████╗ ████║██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝                ║
║              ██╔████╔██║█████╗  █████╗  ██████╔╝ ╚████╔╝                 ║
║              ██║╚██╔╝██║██╔══╝  ██╔══╝  ██╔══██╗  ╚██╔╝                  ║
║              ██║ ╚═╝ ██║███████╗███████╗██║  ██║   ██║                   ║
║              ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝                   ║
║                                                                           ║
║                  ╔════════════════════════════════════╗                   ║
║                  ║  ADVANCED SECURITY RESEARCH FRAMEWORK  ║                   ║
║                  ╚════════════════════════════════════╝                   ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
{self.colors.RESET}
{self.colors.CYAN}  Version: 16.0{self.colors.RESET}                    {self.colors.YELLOW}Platform: {platform.system()}{self.colors.RESET}
{self.colors.CYAN}  Framework: MeeryahyaToolkit{self.colors.RESET}      {self.colors.YELLOW}Python: {sys.version.split()[0]}{self.colors.RESET}
{self.colors.DIM}  ──────────────────────────────────────────────────────────────────────{self.colors.RESET}
{self.colors.RED}{self.colors.BOLD}  ⚠ FOR AUTHORIZED GOVERNMENT SECURITY RESEARCH ONLY{self.colors.RESET}
{self.colors.DIM}  ──────────────────────────────────────────────────────────────────────{self.colors.RESET}
"""
        else:
            # Compact banner for sub-menus
            banner = f"""
{self.colors.RED}╔{'═' * (self.width - 2)}╗
║{' ' * (self.width - 2)}║
║  {self.colors.BOLD}MEERYAHYA TOOLKIT{self.colors.RESET}{self.colors.RED} {' ' * (self.width - 22)}║
║{' ' * (self.width - 2)}║
╚{'═' * (self.width - 2)}╝{self.colors.RESET}
"""
        print(banner)

    def print_box(self, title: str, content: List[str], color: str = None):
        """Print content in a bordered box"""
        if color is None:
            color = self.colors.CYAN

        # Calculate box width
        max_len = max(len(title), max(len(line) for line in content) if content else 0)
        box_width = min(max_len + 4, self.width - 4)

        # Top border
        print(f"{color}{self.colors.BOX_TL}{self.colors.BOX_H * (box_width - 2)}{self.colors.BOX_TR}{self.colors.RESET}")

        # Title
        if title:
            padding = box_width - len(title) - 4
            print(f"{color}{self.colors.BOX_V} {self.colors.BOLD}{title}{self.colors.RESET}{' ' * padding}{color}{self.colors.BOX_V}{self.colors.RESET}")
            print(f"{color}{self.colors.BOX_ML}{self.colors.BOX_H * (box_width - 2)}{self.colors.BOX_MR}{self.colors.RESET}")

        # Content
        for line in content:
            padding = box_width - len(line) - 4
            # Remove ANSI codes for length calculation
            import re
            clean_line = re.sub(r'\033\[[0-9;]+m', '', line)
            actual_padding = box_width - len(clean_line) - 4
            print(f"{color}{self.colors.BOX_V}{self.colors.RESET} {line}{' ' * actual_padding} {color}{self.colors.BOX_V}{self.colors.RESET}")

        # Bottom border
        print(f"{color}{self.colors.BOX_BL}{self.colors.BOX_H * (box_width - 2)}{self.colors.BOX_BR}{self.colors.RESET}")

    def print_menu(self, title: str, options: Dict[str, str], show_exit: bool = True) -> str:
        """Print interactive menu and get user choice"""
        print(f"\n{self.colors.CYAN}{self.colors.BOLD}{title}{self.colors.RESET}\n")

        # Print options
        for key, description in options.items():
            print(f"  {self.colors.ARROW} {self.colors.GREEN}[{key}]{self.colors.RESET} {description}")

        if show_exit:
            print(f"  {self.colors.ARROW} {self.colors.RED}[0]{self.colors.RESET} Exit / Back")

        print(f"\n{self.colors.DIM}{'─' * (self.width - 2)}{self.colors.RESET}")

        # Get user input
        choice = input(f"{self.colors.YELLOW}Select option: {self.colors.RESET}").strip()
        return choice

    def print_status(self, message: str, status: str = "info"):
        """Print status message with icon"""
        icons = {
            "success": self.colors.SUCCESS,
            "error": self.colors.ERROR,
            "warning": self.colors.WARNING,
            "info": self.colors.INFO
        }

        icon = icons.get(status, self.colors.INFO)
        print(f"{icon} {message}")

    def print_table(self, headers: List[str], rows: List[List[str]], title: str = None):
        """Print data in a formatted table"""
        if title:
            print(f"\n{self.colors.CYAN}{self.colors.BOLD}{title}{self.colors.RESET}\n")

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))

        # Print header
        header_line = " │ ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
        print(f"{self.colors.BOLD}{header_line}{self.colors.RESET}")
        print(f"{self.colors.DIM}{'─' * len(header_line)}{self.colors.RESET}")

        # Print rows
        for row in rows:
            row_line = " │ ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
            print(row_line)

    def print_progress_bar(self, current: int, total: int, prefix: str = "", length: int = 50):
        """Print a progress bar"""
        percent = current / total
        filled = int(length * percent)
        bar = f"{self.colors.GREEN}{'█' * filled}{self.colors.DIM}{'░' * (length - filled)}{self.colors.RESET}"

        print(f"\r{prefix} [{bar}] {int(percent * 100)}% ({current}/{total})", end="", flush=True)

        if current == total:
            print()  # New line when complete

    def print_warning_box(self, message: str):
        """Print a warning message in a highlighted box"""
        lines = [
            f"{self.colors.YELLOW}{self.colors.BOLD}⚠ WARNING ⚠{self.colors.RESET}",
            "",
            message
        ]
        self.print_box("", lines, self.colors.YELLOW)

    def print_success_box(self, message: str):
        """Print a success message in a highlighted box"""
        lines = [
            f"{self.colors.GREEN}{self.colors.BOLD}✓ SUCCESS{self.colors.RESET}",
            "",
            message
        ]
        self.print_box("", lines, self.colors.GREEN)

    def print_error_box(self, message: str, error: Optional[Exception] = None):
        """Print an error message in a highlighted box"""
        lines = [
            f"{self.colors.RED}{self.colors.BOLD}✗ ERROR{self.colors.RESET}",
            "",
            message
        ]

        if error:
            lines.append("")
            lines.append(f"{self.colors.DIM}Details: {str(error)}{self.colors.RESET}")

        self.print_box("", lines, self.colors.RED)

    def confirm(self, message: str, default: bool = False) -> bool:
        """Ask for user confirmation"""
        default_str = "Y/n" if default else "y/N"
        response = input(f"{self.colors.YELLOW}? {message} [{default_str}]: {self.colors.RESET}").strip().lower()

        if not response:
            return default

        return response in ['y', 'yes']

    def input_text(self, prompt: str, default: str = None) -> str:
        """Get text input from user"""
        if default:
            result = input(f"{self.colors.CYAN}? {prompt} [{default}]: {self.colors.RESET}").strip()
            return result if result else default
        else:
            return input(f"{self.colors.CYAN}? {prompt}: {self.colors.RESET}").strip()

    def pause(self, message: str = "Press Enter to continue..."):
        """Pause and wait for user input"""
        input(f"\n{self.colors.DIM}{message}{self.colors.RESET}")


def demo_ui():
    """Demonstration of UI capabilities"""
    ui = TerminalUI()

    # Demo 1: Banner
    ui.print_banner()
    ui.pause()

    # Demo 2: Status messages
    ui.clear_screen()
    ui.print_banner("compact")
    print("\nStatus Messages Demo:\n")
    ui.print_status("Operation completed successfully", "success")
    ui.print_status("This is an informational message", "info")
    ui.print_status("Warning: Low disk space", "warning")
    ui.print_status("Failed to connect to server", "error")
    ui.pause()

    # Demo 3: Menu
    ui.clear_screen()
    ui.print_banner("compact")
    options = {
        "1": "Start Framework",
        "2": "Configure Settings",
        "3": "View Documentation",
        "4": "Run Tests"
    }
    choice = ui.print_menu("Main Menu", options)
    ui.print_status(f"You selected: {choice}", "info")
    ui.pause()

    # Demo 4: Table
    ui.clear_screen()
    ui.print_banner("compact")
    headers = ["Module", "Status", "Capabilities"]
    rows = [
        ["C2 Server", "✓ Ready", "HTTP, DNS, ICMP"],
        ["Exploits", "✓ Ready", "7+ CVEs"],
        ["Persistence", "✓ Ready", "Cross-platform"]
    ]
    ui.print_table(headers, rows, "Framework Status")
    ui.pause()

    # Demo 5: Progress bar
    ui.clear_screen()
    ui.print_banner("compact")
    print("\nProgress Bar Demo:\n")
    import time
    for i in range(101):
        ui.print_progress_bar(i, 100, "Loading modules")
        time.sleep(0.02)
    ui.pause()

    # Demo 6: Message boxes
    ui.clear_screen()
    ui.print_banner("compact")
    ui.print_warning_box("This framework contains dangerous capabilities. Use only in authorized environments.")
    ui.pause()

    ui.print_success_box("All dependencies installed successfully!")
    ui.pause()

    ui.print_error_box("Failed to connect to C2 server", Exception("Connection timeout after 30 seconds"))
    ui.pause()

    ui.print_status("UI Demo Complete!", "success")


if __name__ == "__main__":
    demo_ui()
