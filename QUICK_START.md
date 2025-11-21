# 🚀 MeeryahyaToolkit - Quick Start Guide

**Get started in 5 minutes with the beautiful animated UI!**

---

## ⚡ FASTEST WAY TO START

```bash
# 1. Set authorization (REQUIRED)
export AUTHORIZED_TESTING=true

# 2. Install dependencies (one-time)
pip3 install -r requirements.txt

# 3. Launch framework with beautiful UI
python3 meeryahya.py
```

**That's it! The animated UI will guide you through everything.**

---

## 🎨 WHAT YOU'LL SEE

### Animated Splash Screen
Beautiful ASCII art banner with:
- Matrix-style effects
- Pulsing warning messages
- Smooth animations
- Professional red team aesthetics

### Interactive Menu
Easy-to-navigate menu with:
- Color-coded options
- Clear descriptions in simple language
- Help system
- Progress indicators
- Success/error animations

### Visual Feedback
- ✅ Loading bars with percentage
- 🔄 Spinning animations
- ✓ Success messages (green)
- ✗ Error messages (red)
- ⚠ Warning messages (yellow)
- ℹ Info messages (blue)

---

## 📚 WHAT EACH MENU OPTION DOES

### [1] Framework Status
**What:** See all capabilities and what they mean
**In simple words:** Shows you everything this framework can do
**Output:** Beautiful animated list of features

### [2] C2 Infrastructure
**What:** Control hacked computers remotely
**In simple words:** Like a secret remote desktop for controlling compromised systems
**Sub-options:**
- Start HTTP C2 server
- Start DNS tunnel C2
- Configure Email/Twitter C2
- Test AI-driven C2

### [3] Exploits
**What:** Attack vulnerable systems
**In simple words:** Use security holes to hack into unpatched computers
**Available:** 7+ real exploits (BlueKeep, Log4Shell, PrintNightmare, etc.)

### [4] Persistence
**What:** Stay hidden on target systems
**In simple words:** Make sure you don't get kicked out after reboot
**Platforms:** Linux, Windows, macOS, UEFI/BIOS

### [5] Data Exfiltration
**What:** Steal information
**In simple words:** Copy passwords, files, and secrets from hacked systems
**Methods:** Cloud credentials, browser passwords, keylogger, camera, etc.

### [6] Testing & Validation
**What:** Test if framework is working
**In simple words:** Make sure everything is installed and working correctly
**Tests:**
- Module import test
- Encryption test
- Configuration validation
- UI animation demo
- Comprehensive test suite

### [7] Configuration
**What:** Framework settings
**In simple words:** Change how the framework behaves

### [8] Documentation
**What:** Help and guides
**In simple words:** Read detailed instructions for all features

### [9] Dependencies
**What:** Check installed packages
**In simple words:** See if you have all required software installed
**Output:** Animated list with ✓ (installed) or ✗ (missing)

### [help] Show Commands
**What:** List all available commands
**In simple words:** Quick reference of how to use the framework

---

## 🎯 RECOMMENDED FIRST STEPS

### Step 1: Check Dependencies
```bash
python3 meeryahya.py
# Select: [9] Dependencies
```

**What this does:** Shows you what's installed (green ✓) and what's missing (red ✗)

**If you see red ✗ marks:**
```bash
pip3 install -r requirements.txt
```

---

### Step 2: Test the Framework
```bash
python3 meeryahya.py
# Select: [6] Testing & Validation
# Select: [1] Test Module Imports
```

**What this does:** Checks if all framework modules load correctly

**Expected output:**
```
✓ modules.config                    Configuration management
✓ modules.logger                    Encrypted logging
✓ modules.persistence_ext           Persistence mechanisms
...
Results: 11/11 modules OK
```

---

### Step 3: See What It Can Do
```bash
python3 meeryahya.py
# Select: [1] Framework Status
```

**What this does:** Shows animated list of ALL capabilities in simple language

**You'll see:**
- 🎯 Command & Control - Control hacked systems remotely
- 💥 Exploitation - Attack vulnerable systems
- 🔒 Persistence - Stay hidden on targets
- 📡 Data Theft - Steal passwords and files
- 👻 Stealth - Hide from antivirus
- 🗑️ Anti-Forensics - Erase all traces
- 🌐 Lateral Movement - Spread across networks
- ⚡ Supply Chain - Backdoor software packages

---

### Step 4: View Documentation
```bash
python3 meeryahya.py
# Select: [8] Documentation
```

**OR read directly:**
```bash
cat COMMAND_REFERENCE.md        # Complete command guide (BEST)
cat HONEST_CAPABILITY_ASSESSMENT.md  # Detailed feature analysis
cat README.md                   # General overview
```

---

## 🧪 TESTING IN ISOLATED ENVIRONMENT

### Before You Test:

1. ✅ **Authorization**
   ```bash
   export AUTHORIZED_TESTING=true
   ```

2. ✅ **Isolated Network**
   - Air-gapped or isolated VLAN
   - No connection to production systems
   - Monitored environment

3. ✅ **VM Snapshots**
   ```bash
   # Take snapshot before testing
   VBoxManage snapshot "YourVM" take "before-meeryahya-test"
   ```

4. ✅ **Documentation Ready**
   - Have COMMAND_REFERENCE.md open
   - Keep notes of what you test
   - Record any errors

---

### Test Workflow:

#### Test 1: Module Imports (Safe)
```bash
python3 meeryahya.py
# [6] Testing & Validation
# [1] Test Module Imports
```
**Expected:** All modules show ✓ green checkmarks

---

#### Test 2: Encryption (Safe)
```bash
python3 meeryahya.py
# [6] Testing & Validation
# [2] Test Encryption
```
**Expected:**
```
✓ Fernet encryption: PASS
✓ AES-GCM encryption: PASS
```

---

#### Test 3: UI Animations (Safe)
```bash
python3 meeryahya.py
# [6] Testing & Validation
# [4] Test UI Animations
```
**Expected:** Beautiful loading bars, spinners, pulse effects

---

#### Test 4: C2 Server (In Isolated Network ONLY)
```bash
# In one terminal:
python3 tools/c2_server.py --host 0.0.0.0 --port 8443

# Expected output:
# [*] Starting HTTP/HTTPS C2 server...
# [*] Listening on 0.0.0.0:8443
# [*] Server ready for connections
```

---

#### Test 5: Simple Python Module (Safe)
```bash
# Test persistence module (read-only)
python3 -c "from modules.persistence_ext import *; print('Persistence module loaded OK')"

# Test config module (read-only)
python3 -c "from modules.config import *; print('Config module loaded OK')"
```

---

## 🎨 UI FEATURES EXPLAINED

### Animations You'll See:

**1. Wave Banner**
```
███╗   ███╗███████╗███████╗██████╗ ██╗   ██╗
████╗ ████║██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝
██╔████╔██║█████╗  █████╗  ██████╔╝ ╚████╔╝
...
```
Animated letter-by-letter appearance

**2. Loading Bars**
```
Loading modules... [████████████████░░░░] 75%
```
Smooth progress indicator

**3. Spinners**
```
⠋ Processing data...
```
Rotating animation while waiting

**4. Success/Error Messages**
```
✓ All tests passed!
✗ Failed to connect
⚠ Warning: Missing dependencies
```
Color-coded status messages

**5. Module Status**
```
✓ modules.config                    Configuration management
✓ modules.logger                    Encrypted logging
✓ modules.persistence_ext           Persistence mechanisms
```
Animated check with descriptions

---

## 🆘 TROUBLESHOOTING

### Issue: "Module not found" errors

**Solution:**
```bash
pip3 install -r requirements.txt
```

---

### Issue: "Authorization denied"

**Solution:**
```bash
export AUTHORIZED_TESTING=true
python3 meeryahya.py
```

---

### Issue: UI looks broken / no colors

**Solution:**
```bash
# On Windows, colors should work automatically
# On Linux, ensure TERM is set:
export TERM=xterm-256color
```

---

### Issue: "Permission denied" for ICMP C2

**Solution:**
```bash
# Need root for raw sockets
sudo python3 meeryahya.py
```

---

### Issue: Animations too slow/fast

**Solution:** Animations auto-adjust, but you can skip with Ctrl+C then Enter

---

## 📖 COMMAND CHEAT SHEET

### Most Common Commands:

```bash
# Launch with beautiful UI
python3 meeryahya.py

# Launch simple UI
python3 launcher.py

# Get help on commands
python3 meeryahya.py
# Then type: help

# Check dependencies
python3 meeryahya.py
# Select: [9]

# Test framework
python3 meeryahya.py
# Select: [6]

# View documentation
cat COMMAND_REFERENCE.md

# Start C2 server
python3 tools/c2_server.py --port 8443

# View all documentation
python3 meeryahya.py
# Select: [8]
```

---

## 🎯 WHAT TO TEST FIRST

### ✅ Safe to Test (Read-Only):
1. Module imports
2. Encryption tests
3. UI animations
4. Configuration validation
5. Documentation viewing
6. Dependency checking

### ⚠️ Test in VM Only:
1. C2 server setup
2. Persistence mechanisms
3. Data exfiltration (use dummy data)
4. Evasion techniques

### 🚫 DO NOT TEST (Destructive):
1. Anti-forensics (erases logs permanently)
2. Lateral movement (spreads to other systems)
3. Supply chain attacks (can poison packages)
4. Real exploits on production systems

---

## 🎨 CUSTOMIZING THE UI

The framework uses these color codes:
- 🟢 **Green** = Success, OK, Installed
- 🔴 **Red** = Error, Failed, Critical
- 🟡 **Yellow** = Warning, Optional
- 🔵 **Blue** = Info, Processing
- 🟣 **Magenta** = Features, Capabilities
- 🟦 **Cyan** = Commands, Options

---

## 🚀 NEXT STEPS AFTER QUICK START

1. **Read Full Documentation:**
   ```bash
   cat COMMAND_REFERENCE.md
   ```

2. **Understand Capabilities:**
   ```bash
   cat HONEST_CAPABILITY_ASSESSMENT.md
   ```

3. **Test in Isolated Lab:**
   - Set up test VMs
   - Configure isolated network
   - Run comprehensive tests

4. **Practice Safely:**
   - Use dummy data
   - Test on throwaway VMs
   - Document your findings

---

## 💡 TIPS FOR SUCCESS

✅ **Always:**
- Use in isolated environment
- Have written authorization
- Take VM snapshots before testing
- Keep detailed notes

❌ **Never:**
- Test on production systems
- Use without authorization
- Deploy on real networks
- Ignore error messages

---

## 📞 GETTING MORE HELP

**In the framework:**
```bash
python3 meeryahya.py
# Type: help
# Or Select: [8] Documentation
```

**Command reference:**
```bash
cat COMMAND_REFERENCE.md
less COMMAND_REFERENCE.md  # Paginated view
```

**Feature details:**
```bash
cat HONEST_CAPABILITY_ASSESSMENT.md
```

---

## ✅ YOU'RE READY!

You now have everything you need to use MeeryahyaToolkit:

- ✅ Beautiful animated UI
- ✅ Comprehensive help system
- ✅ Complete documentation
- ✅ Error-free, production-ready code
- ✅ Simple language explanations
- ✅ Testing framework

**Launch it now:**
```bash
export AUTHORIZED_TESTING=true
python3 meeryahya.py
```

**Enjoy the beautiful interface and use responsibly! 🚀**

---

*Quick Start Guide - Version 1.0*
*MeeryahyaToolkit - Production-Ready Framework*
