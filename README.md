# 👻 GhostSecure

### Active Directory Attack Detector for Windows

![GitHub stars](https://img.shields.io/github/stars/Egyan07/GhostSecure_v2.1?style=social)
![GitHub forks](https://img.shields.io/github/forks/Egyan07/GhostSecure_v2.1?style=social)
![GitHub issues](https://img.shields.io/github/issues/Egyan07/GhostSecure_v2.1)
![GitHub last commit](https://img.shields.io/github/last-commit/Egyan07/GhostSecure_v2.1)
![License](https://img.shields.io/github/license/Egyan07/GhostSecure_v2.1)
![CI](https://github.com/Egyan07/GhostSecure_v2.1/actions/workflows/ci.yml/badge.svg)

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)

**Coded by Egyan | Red Parrot Accounting Ltd**

GhostSecure monitors your Windows Security Event Log in real time and fires an alert the moment it detects a live Active Directory attack — Kerberoasting, Pass-the-Hash, DCSync, Golden Ticket, and more. Runs silently as a Windows service with zero user interaction required.

---

# 🧰 Technology

| Component      | Description                              |
| -------------- | ---------------------------------------- |
| Language       | Python 3.10+                             |
| Event Source   | Windows Security Event Log (pywin32)     |
| Detection      | 7 real-time AD attack detectors          |
| Alerts         | Desktop popup + email + structured log   |
| AD Integration | LDAP/GSSAPI for DC enumeration           |
| GUI            | Tkinter dark-mode status dashboard       |
| Tests          | 53 unit tests, CI on Python 3.10/11/12   |

---

# 🚨 Attacks Detected

| Attack | Event IDs | Description |
|---|---|---|
| **Kerberoasting** | 4769 | RC4 Kerberos service ticket requests — attacker harvesting crackable hashes offline |
| **Pass-the-Hash** | 4624 | NTLM network logon without prior interactive session — stolen hash in use |
| **DCSync (Mimikatz)** | 4662 | Replication rights invoked by non-DC account — full credential dump in progress |
| **Golden Ticket** | 4768, 4769 | TGT with abnormal encryption or options — forged Kerberos ticket detected |
| **LDAP Recon / BloodHound** | 1644 | Burst of LDAP queries — attacker mapping attack paths via BloodHound |
| **AS-REP Roasting** | 4768 | Pre-auth disabled on account — crackable AS-REP hash exposed |
| **Skeleton Key** | 4673 | Sensitive privilege use on DC — possible master-password malware implant |
| **Audit Log Cleared** | 1102 | Security log wiped — attacker covering their tracks |

---

# ✨ Features

| Feature | Description |
|---|---|
| 🔁 Real-Time Detection | Monitors Security Event Log continuously, no polling delay |
| 🪟 Windows Service | Starts automatically on boot, survives reboots, no window |
| 🚨 Instant Alerts | Desktop popup via `msg.exe` to admin workstation |
| 📧 Email Alerts | Optional SMTP — password from environment variable, never hardcoded |
| 🔕 Alert Deduplication | Same attack suppressed for 5 minutes — no alert storms |
| 🛡 Thread-Safe Detectors | All shared state protected with locks — safe under concurrent events |
| 🖥 Status Dashboard | Live detection counts, service status, recent alert history |
| ⚙ Configurable | Account whitelisting, thresholds, cooldowns all in `config.py` |
| 🧪 Automated Tests | 53 unit tests across all 7 detectors and core modules |
| 🔄 CI Pipeline | Python 3.10 / 3.11 / 3.12, flake8 lint, pytest with coverage |

---

# 🚀 Installation

**Requirements:**
- Windows Server 2016+ or Windows 10/11 (domain-joined)
- Python 3.10+
- Domain Administrator rights
- Windows Advanced Audit Policy logging enabled (see below)

```bash
pip install pywin32 ldap3
```

1. Copy this folder to the Domain Controller or a domain-joined machine
2. Open `config.py` and set:
   - `ADMIN_HOSTNAME` — workstation name where alert popups should appear
   - `KNOWN_DOMAIN_CONTROLLERS` — your DC names e.g. `["DC01", "DC02"]`
   - `DOMAIN_NAME` — your domain e.g. `"REDPARROT"`
3. Right-click `Install.bat` → **Run as administrator**
4. Done — service starts automatically

**Verify it's running:**
```cmd
sc query GhostSecure2ADDetector
```
Should show `STATE: RUNNING`.

---

# 🔐 Enabling Windows Audit Logging

GhostSecure reads from the Windows Security Event Log. Without audit logging enabled it has nothing to monitor.

1. Open **Group Policy Management** on the Domain Controller
2. Edit **Default Domain Controllers Policy**
3. Navigate to: `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration`
4. Enable **Success and Failure** for:

| Category | Policy |
|---|---|
| Account Logon | Audit Kerberos Authentication Service |
| Account Logon | Audit Kerberos Service Ticket Operations |
| DS Access | Audit Directory Service Access |
| Logon/Logoff | Audit Logon |
| Privilege Use | Audit Sensitive Privilege Use |
| System | Audit Security State Change |

5. Run: `gpupdate /force`

---

# 📧 Email Alerts

1. Set `ENABLE_EMAIL_ALERTS = True` in `config.py`
2. Fill in your SMTP server details in `config.py`
3. Store your password as a system environment variable — **never hardcode it**:

```powershell
# Run PowerShell as Administrator
[System.Environment]::SetEnvironmentVariable(
  'GHOSTSECURE_SMTP_PASSWORD', 'YourPasswordHere', 'Machine')
```

4. Restart the service after setting the variable

---

# 🖥 Dashboard

```cmd
python main.py --gui
```

Dark-mode monitoring dashboard showing live detection stats, service status, and recent alert history.

---

# ⚡ CLI Reference

```cmd
python main.py --gui          # Launch status dashboard
python main.py --service      # Run as Windows service (called by Install.bat)
python main.py --run          # Run detection loop directly (foreground)
python main.py --status       # Print current service status
```

---

# 🧪 Testing

GhostSecure ships with **53 unit tests** covering all 7 detectors, alert manager, time helpers, and AD helpers.

```bash
pip install pytest pytest-cov
pytest tests/ -v
```

---

# 🏗 Architecture

```
GhostSecure/
│
├── Windows Service Layer (main.py)
│
├── Detector Engine (core/detector_engine.py)
│   Routes every event through all 7 detectors
│
├── Detectors (detectors/)
│   ├── kerberoasting.py    Event 4769 — RC4 ticket requests
│   ├── pass_the_hash.py    Event 4624 — NTLM without interactive logon
│   ├── dcsync.py           Event 4662 — Replication GUID access
│   ├── golden_ticket.py    Event 4768/4769 — Anomalous TGT
│   ├── ldap_recon.py       Event 1644 — High-frequency LDAP queries
│   ├── asrep_roasting.py   Event 4768 — No pre-auth required
│   └── skeleton_key.py     Event 4673/1102 — Privilege use / log clear
│
├── Alert System (core/alert_manager.py)
│   ├── Desktop popup via msg.exe
│   ├── Email via SMTP/TLS
│   ├── Structured log file
│   └── Alert deduplication (5-min cooldown)
│
├── Event Reader (core/event_reader.py)
│   └── Windows Security Event Log (pywin32)
│
└── AD Helpers (utils/ad_helpers.py)
    └── LDAP/GSSAPI DC enumeration
```

---

# 📂 Project Structure

```
GhostSecure/
├── main.py
├── config.py                  ← edit this before deploying
├── Install.bat
├── Uninstall.bat
├── build.bat
├── core/
│   ├── alert_manager.py
│   ├── detector_engine.py
│   └── event_reader.py
├── detectors/
│   ├── kerberoasting.py
│   ├── pass_the_hash.py
│   ├── dcsync.py
│   ├── golden_ticket.py
│   ├── ldap_recon.py
│   ├── asrep_roasting.py
│   └── skeleton_key.py
├── utils/
│   ├── ad_helpers.py
│   └── time_helpers.py
├── gui/
│   └── status_dashboard.py
└── tests/
    ├── test_detectors.py
    ├── test_alert_manager.py
    ├── test_time_helpers.py
    └── test_ad_helpers.py
```

---

# 🛣 Roadmap

- False positive whitelist / tuning engine
- Daily digest email with detection summary
- Per-detector enable/disable toggles in GUI
- Slack / Teams webhook alerts
- Web dashboard for remote monitoring

---

# 📋 Changelog

**v2.1.2** *(current — thread safety & reliability fixes)*

- Fixed: `detectors/golden_ticket.py` — write to `_tgt_issuance` outside `_tgt_lock` was a race condition under concurrent events; wrapped in lock
- Fixed: `core/alert_manager.py` — SMTP connection leaked on exception before `quit()`; replaced with `with smtplib.SMTP(...) as server:` context manager
- Fixed: `core/alert_manager.py` — email thread joined with `timeout=30` blocked the detection loop 30s per alert; now fire-and-forget daemon thread
- Fixed: 6 module headers still said `GhostSecure 2.0` — updated to `2.1`
- Added: `.gitignore` — excludes `__pycache__`, logs, DB files, credential patterns

**v2.1.1**

- Fixed: Smart quotes causing `SyntaxError` on Python 3.10+
- Fixed: `starttls()` without SSL context — MITM vulnerability — now uses `ssl.create_default_context()`
- Fixed: 53 unit tests added across all 7 detectors, alert manager, time helpers, AD helpers
- Added: CI pipeline on Python 3.10 / 3.11 / 3.12

**v2.1**

- Fixed: SMTP password moved to environment variable — never hardcoded
- Fixed: Golden Ticket and Pass-the-Hash thread safety — `threading.Lock()` added
- Fixed: LDAP Windows auth using SASL/GSSAPI instead of broken NTLM empty-password bind
- Fixed: GUI dashboard showed frozen stats — DetectorEngine now runs in background thread
- Fixed: Event reader re-processed same events — `EventRecordID` now tracked

**v2.0**

- Initial release — 7 AD attack detectors, Windows service architecture

---

# ⚠ Disclaimer

GhostSecure is an **early warning system**, not a complete security solution. It detects known attack patterns from Windows event logs — it does not block attacks or replace a full EDR/SIEM.

Any **CRITICAL alert should be treated as an immediate security incident.**

Under GDPR/ICO guidelines, security logs should be retained for at least 12 months.

---

# 👨‍💻 Author

**Egyan07**

Developed for **Red Parrot Accounting Ltd**

---

# 👻 GhostSecure

**Real-Time Active Directory Attack Detection. Zero Blind Spots.**
