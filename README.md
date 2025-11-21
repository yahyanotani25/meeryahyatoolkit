# MeeryahyaToolkit - Advanced Security Research Framework

**⚠️ FOR AUTHORIZED GOVERNMENT SECURITY RESEARCH ONLY ⚠️**

---

## Overview

MeeryahyaToolkit is an advanced offensive security framework designed for authorized penetration testing, red team operations, and defensive security research. This framework demonstrates nation-state level APT (Advanced Persistent Threat) capabilities.

**Classification:** For Official Use Only
**Status:** Production-Ready
**Danger Level:** EXTREME (10/10)

---

## ⚠️ CRITICAL WARNINGS

### Legal Notice:
- This framework contains capabilities that are **ILLEGAL to use without proper authorization**
- Deployment on unauthorized systems is a **federal crime** under CFAA and international cybercrime laws
- **ONLY** use in isolated, air-gapped lab environments with explicit written authorization

### Authorized Use Cases:
- ✅ Government-sponsored offensive security research
- ✅ Authorized penetration testing with client consent
- ✅ Red team exercises for defensive training
- ✅ Security research in isolated lab environments
- ✅ Capture The Flag (CTF) competitions

### Prohibited Activities:
- ❌ Unauthorized access to computer systems
- ❌ Deployment on production networks without authorization
- ❌ Mass exploitation or supply chain attacks
- ❌ Data theft or ransomware deployment
- ❌ Any malicious activity

---

## Framework Capabilities

### 1. Command & Control (C2) Infrastructure
- **6 Covert Channels:** HTTP/HTTPS, DNS tunneling, ICMP, Twitter, Email, AI-driven
- **Encrypted Communications:** AES-256-GCM, polymorphic beacons
- **Autonomous Operations:** AI-driven C2 with GPT-4 integration

### 2. Exploit Library
- **7+ CVE Implementations:** BlueKeep, SMBGhost, PrintNightmare, Log4Shell, ProxyLogon, Follina, vCenter RCE
- **Auto-Exploit Fetcher:** Downloads new exploits from remote repositories
- **Multi-platform:** Windows, Linux, macOS, VMware

### 3. Persistence Mechanisms
- **Cross-platform:** systemd, cron, Registry, Scheduled Tasks, WMI Events
- **Firmware-level:** UEFI bootkit, BIOS/MBR bootkit (survives OS reinstall)
- **Kernel-level:** Windows driver rootkit, Linux eBPF rootkit

### 4. Data Exfiltration
- **Cloud Credentials:** AWS IMDSv2, Azure Managed Identity, GCP metadata
- **Credential Harvesting:** LSASS dumps, browser passwords, SSH keys
- **Steganography:** LSB encoding in images
- **Monitoring:** Keylogger, camera, audio capture

### 5. Evasion & Anti-Analysis
- **VM Detection:** CPUID, registry keys, MAC addresses, resource checks
- **Debugger Detection:** IsDebuggerPresent, PEB checks, timing attacks
- **API Unhooking:** Defeats EDR solutions
- **Polymorphic Obfuscation:** Daily key rotation, multi-layer encryption

### 6. Anti-Forensics
- **Log Wiping:** Windows Event Logs, Linux syslog, macOS unified logs
- **Secure Deletion:** 7-pass DoD 5220.22-M file wiping
- **Process Hiding:** Kernel-level concealment

### 7. Lateral Movement
- **Automated Exploitation:** SSH, RDP, SMB propagation
- **Network Scanning:** nmap integration
- **Credential Dumping:** impacket secretsdump

### 8. Supply Chain Attacks
- **Package Poisoning:** npm, PyPI, Maven
- **CI/CD Compromise:** GitHub Actions, GitLab CI

---

## Installation

### System Requirements:
- **Operating System:** Linux (Kali/Ubuntu recommended), Windows 10+, macOS 11+
- **Python:** 3.9 or higher
- **RAM:** Minimum 4GB, recommended 8GB+
- **Storage:** 5GB free space
- **Network:** Isolated environment (air-gapped recommended)

### Dependencies Installation:

```bash
# Install system dependencies (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y python3-dev python3-pip python3-cffi \
    libffi-dev libssl-dev build-essential nmap

# Install Python dependencies
pip3 install -r requirements.txt
```

### Optional Dependencies:
```bash
# For advanced features
pip3 install openai transformers torch  # AI-driven C2
pip3 install opencv-python pyaudio      # Camera/audio capture
pip3 install pwntools capstone         # Exploit development
```

---

## Usage

### Main Entry Points:

1. **monolika.py** (Recommended - Most Comprehensive)
   ```bash
   python3 monolika.py --help
   ```

2. **6.py** (Specialized - Advanced Windows Features)
   ```bash
   python3 6.py --help
   ```

3. **Individual Modules**
   ```bash
   python3 -m modules.persistence_ext
   python3 -m modules.lateral_movement
   python3 tools/c2_server.py
   ```

### Configuration:

1. **Generate Encryption Keys:**
   ```bash
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key())"
   ```

2. **Edit Configuration:**
   ```bash
   # Copy example config
   cp config.yaml.example config.yaml

   # Edit with your settings
   nano config.yaml
   ```

3. **Set Environment Variables:**
   ```bash
   export AUTHORIZED_TESTING=true
   export C2_SERVER=https://your-c2-server.com
   export ENCRYPTION_KEY=your-generated-key
   ```

---

## Testing Checklist

### Before Running in Isolated Lab:

- [ ] **Isolated Environment:** Confirm air-gapped or isolated VLAN
- [ ] **Authorization:** Obtain written authorization from legal authority
- [ ] **Backups:** Create snapshots of all test systems
- [ ] **Monitoring:** Setup network/system monitoring
- [ ] **Dependencies:** Install all required packages from requirements.txt
- [ ] **Configuration:** Set proper encryption keys and C2 endpoints

### Test Sequence:

1. **Basic Functionality:**
   ```bash
   # Test imports
   python3 -c "import modules.config; print('Config OK')"

   # Test C2 server
   python3 tools/c2_server.py --test-mode
   ```

2. **C2 Channels (in isolated environment):**
   - Start with HTTP/HTTPS C2 (easiest)
   - Test DNS tunnel C2 (requires DNS server)
   - Test ICMP C2 (requires root)
   - Test Email/Twitter C2 (requires API keys)

3. **Exploits (against vulnerable VMs ONLY):**
   - Setup vulnerable test targets
   - Run exploits one at a time
   - Document results

4. **Persistence (in test VMs):**
   - Test each persistence mechanism
   - Verify survival after reboot
   - Document cleanup procedures

---

## Project Structure

```
meeryahyatoolkit/
├── monolika.py                 # Main framework (most comprehensive)
├── 6.py                        # Alternative entry point (Windows-focused)
├── bootkit_template.py         # UEFI bootkit template
├── requirements.txt            # Python dependencies
├── config.yaml.enc             # Encrypted configuration
│
├── modules/                    # Core modules
│   ├── config.py              # Configuration management
│   ├── logger.py              # Encrypted logging
│   ├── obfuscation.py         # Code obfuscation
│   ├── persistence_ext.py     # Persistence mechanisms
│   ├── stealth_ext.py         # Evasion techniques
│   ├── anti_forensics_ext.py  # Log wiping
│   ├── lateral_movement.py    # Network propagation
│   ├── supply_chain.py        # Package poisoning
│   ├── cloud_api_compromise.py # Cloud credential theft
│   ├── icmp_c2.py             # ICMP C2 channel
│   ├── ai_c2.py               # AI-driven C2
│   └── exploit_lib/           # Exploit implementations
│       ├── cve_2019_0708_bluekeep.py
│       ├── cve_2020_0796.py (SMBGhost)
│       ├── cve_2021_44228_log4j.py
│       └── [7+ more CVEs]
│
├── tools/                      # Standalone tools
│   ├── c2_server.py           # HTTP/HTTPS C2 server
│   ├── dns_c2_server.py       # DNS tunnel C2
│   ├── shellcode_gen.py       # Shellcode generator
│   └── mitm_sslstrip.py       # SSL stripping MITM
│
├── payloads/                   # Compiled payloads
│   ├── windows_payloads/      # Windows exploits (C source)
│   ├── macos_payloads/        # macOS exploits (C source)
│   ├── kernel_rootkit/        # Linux kernel rootkit
│   └── uefi_bootkit/          # UEFI bootkit (C source)
│
├── tests/                      # Test suites
│   ├── test_exploits.py
│   ├── test_persistence.py
│   └── testc2.py
│
└── plugins/                    # Extension plugins
    ├── example_plugin.py
    └── template_plugin.py
```

---

## Documentation

- **SECURITY_ASSESSMENT_REPORT.md** - Comprehensive capability analysis
- **TESTING_RESULTS.md** - Detailed testing results and cleanup report
- **requirements.txt** - All Python dependencies
- **config_schema.yaml** - Configuration file schema

---

## Safety Mechanisms

### Built-in Safeguards:
- Configuration validation before execution
- Encrypted logging with remote syslog
- Environment variable authorization checks

### Recommended Additional Safeguards:
1. **Killswitch:** Implement remote shutdown capability
2. **Time-based Expiration:** Auto-disable after test window
3. **Network Whitelist:** Restrict C2 to authorized IPs only
4. **Audit Logging:** Tamper-evident logging to remote server

---

## Defensive Mitigation

### For Blue Team / Defenders:

**Detection Strategies:**
- Monitor for C2 beacon patterns (regular intervals, encrypted payloads)
- DNS tunneling detection (high-entropy TXT records, unusual query volumes)
- ICMP anomaly detection (large ping payloads)
- Behavioral analytics for credential dumping (LSASS access patterns)
- File integrity monitoring on system directories

**Prevention Strategies:**
- Network segmentation with VLANs
- Principle of least privilege (POLP)
- Multi-factor authentication (MFA) for all access
- Application whitelisting (AppLocker, WDAC)
- Endpoint Detection and Response (EDR) with behavioral analysis

**See SECURITY_ASSESSMENT_REPORT.md for comprehensive mitigation strategies.**

---

## Known Limitations

### Non-Functional Components:
- Some mobile exploit modules are stubs/placeholders
- Satellite communication (satcom_ext.py) is experimental
- UEFI/BIOS bootkits require compilation and kernel privileges
- Some exploits require specific vulnerable software versions

### Platform-Specific Limitations:
- Windows-only: WMI events, Registry persistence, LSASS dumping
- Linux-only: systemd, cron, eBPF rootkit
- macOS-only: LaunchDaemon, TCC.db manipulation

---

## Troubleshooting

### Common Issues:

**Import Errors:**
```bash
# ModuleNotFoundError: No module named '_cffi_backend'
pip3 install --upgrade cryptography cffi

# Import error for pypykatz
pip3 install pypykatz
```

**Permission Errors:**
```bash
# ICMP C2 requires root
sudo python3 monolika.py

# Or grant CAP_NET_RAW capability
sudo setcap cap_net_raw+ep /usr/bin/python3.9
```

**Cryptography Errors:**
```bash
# Reinstall cryptography from source
pip3 uninstall cryptography
pip3 install --no-binary :all: cryptography
```

---

## Contributing

This framework is for authorized government security research. External contributions are not accepted.

---

## License

This framework is provided for authorized security research purposes only. No license is granted for redistribution or modification.

**Copyright © 2025 - Authorized Security Research**

---

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS" FOR AUTHORIZED SECURITY RESEARCH ONLY. THE AUTHORS ASSUME NO LIABILITY FOR MISUSE, DAMAGES, OR LEGAL CONSEQUENCES RESULTING FROM UNAUTHORIZED USE OF THIS SOFTWARE.

USE OF THIS SOFTWARE FOR ILLEGAL ACTIVITIES IS STRICTLY PROHIBITED AND MAY RESULT IN CRIMINAL PROSECUTION.

---

## Contact

For authorized government inquiries only.

**DO NOT use this framework without proper legal authorization.**

---

*Last Updated: 2025-11-21*
*Framework Version: 16.0*
*Status: Production-Ready*
