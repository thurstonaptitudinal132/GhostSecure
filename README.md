# GhostSecure 2.1

**Active Directory Attack Detector for Windows**  
Runs as a background Windows service and alerts your team the moment it detects a live AD attack — Kerberoasting, Pass-the-Hash, DCSync, Golden Ticket, and more.

> Built by Egyan | Red Parrot Accounting Ltd

---

## What It Does

GhostSecure monitors your Windows Security Event Log in real time and fires an alert the moment it spots a known Active Directory attack pattern. It runs silently as a Windows service — no window, no interaction needed. When it detects something, a popup appears on the admin's screen immediately.

---

## Attacks Detected

| Attack | Event IDs Monitored | Description |
|---|---|---|
| **Kerberoasting** | 4769 | Unusual Kerberos service ticket requests — attacker harvesting crackable tickets offline |
| **Pass-the-Hash** | 4624 | NTLM logon without a matching prior interactive session — stolen hash being used |
| **DCSync (Mimikatz)** | 4662 | Replication privileges invoked by a non-DC account — attacker dumping all password hashes |
| **Golden Ticket** | 4768, 4769 | TGT issued with abnormal lifetime or encryption — forged Kerberos ticket in use |
| **LDAP Recon / BloodHound** | 1644 | Burst of LDAP queries — network mapping tool scanning for attack paths |
| **AS-REP Roasting** | 4768 | Pre-auth not required on an account — attacker grabbing crackable AS-REP hashes |
| **Skeleton Key** | 4673 | Sensitive privilege use on DC — malware implant allowing master-password login |
| **Audit Log Cleared** | 1102 | Security log wiped — attacker covering their tracks |

---

## Features

- Runs as a **Windows Service** — starts automatically, survives reboots
- **Real-time detection** — monitors Security Event Log continuously
- **Desktop popup alerts** via `msg.exe` to the admin workstation
- **Email alerts** (optional SMTP — password stored in environment variable, never hardcoded)
- **Alert deduplication** — same attack only fires once every 5 minutes, not 100 times
- **Status dashboard** — `python main.py --gui` shows live detection stats
- **Configurable exclusions** — whitelist accounts for false positive suppression
- **Structured logging** to `C:\SecurityLogs\ad_attack_log.txt`

---

## Requirements

- Windows Server 2016+ or Windows 10/11 (domain-joined)
- Python 3.10+
- Domain Administrator rights for installation
- Windows Advanced Audit Policy logging enabled (see below)
- `pywin32` for Windows service support

---

## Installation

```bash
pip install pywin32 ldap3
```

1. Copy this folder to the Domain Controller or a domain-joined machine
2. Open `config.py` and configure:
   - `ADMIN_HOSTNAME` — computer name where alert popups should appear
   - `KNOWN_DOMAIN_CONTROLLERS` — your DC hostnames e.g. `["DC01", "DC02"]`
   - `DOMAIN_NAME` — your domain e.g. `"REDPARROT"`
3. Right-click `Install.bat` → **Run as administrator**
4. Done — service starts automatically

**Verify it's running:**
```cmd
sc query GhostSecure2ADDetector
```
Should show `STATE: RUNNING`.

---

## Enabling Windows Audit Logging (Required)

GhostSecure needs Windows to record security events. Without this it has nothing to monitor.

1. Open **Group Policy Management** on the Domain Controller
2. Edit **Default Domain Controllers Policy**
3. Navigate to: `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies`
4. Enable **Success and Failure** for:
   - Account Logon → Audit Kerberos Authentication Service
   - Account Logon → Audit Kerberos Service Ticket Operations
   - DS Access → Audit Directory Service Access
   - Logon/Logoff → Audit Logon
   - Privilege Use → Audit Sensitive Privilege Use
   - System → Audit Security State Change
5. Run: `gpupdate /force`

---

## Email Alerts (Optional)

1. Set `ENABLE_EMAIL_ALERTS = True` in `config.py`
2. Fill in your SMTP server details
3. Store your password as a system environment variable — **never hardcode it**:

```powershell
# Run PowerShell as Administrator
[System.Environment]::SetEnvironmentVariable(
  'GHOSTSECURE_SMTP_PASSWORD', 'YourPasswordHere', 'Machine')
```

Restart the service after setting the variable.

---

## Dashboard

```cmd
python main.py --gui
```

Shows live detection counts, service status, and recent alerts.

---

## Project Structure

```
GhostSecure/
├── main.py                    # Entry point — service + CLI + GUI launcher
├── config.py                  # All settings ← edit this before deploying
├── Install.bat                # Installs and starts the Windows service
├── Uninstall.bat              # Stops and removes the service
├── build.bat                  # Packages into standalone exe
├── core/
│   ├── alert_manager.py       # Alert dispatch, deduplication, logging
│   ├── detector_engine.py     # Orchestrates all detectors
│   └── event_reader.py        # Windows Security Event Log reader
├── detectors/
│   ├── kerberoasting.py
│   ├── pass_the_hash.py
│   ├── dcsync.py
│   ├── golden_ticket.py
│   ├── ldap_recon.py
│   ├── asrep_roasting.py
│   └── skeleton_key.py
├── utils/
│   ├── ad_helpers.py          # LDAP helpers (GSSAPI auth)
│   └── time_helpers.py
└── gui/
    └── status_dashboard.py    # Live status dashboard
```

---

## Uninstall

Right-click `Uninstall.bat` → **Run as administrator**.  
Stops and removes the service. Log files at `C:\SecurityLogs\` are preserved.

---

## Changelog

**v2.1** *(current)*
- Fixed: SMTP password now read from `GHOSTSECURE_SMTP_PASSWORD` env var — never hardcoded
- Fixed: `alerts_triggered` counter was always 0 — now correctly tracked and shown in dashboard
- Fixed: Golden Ticket `_tgt_issuance` dict was not thread-safe — added `threading.Lock()`
- Fixed: Pass-the-Hash logon tracking was not thread-safe — added `threading.Lock()`
- Fixed: LDAP Windows auth now uses SASL/GSSAPI instead of broken NTLM empty-password bind
- Fixed: GUI dashboard showed frozen stats — DetectorEngine now runs in background thread
- Fixed: Pass-the-Hash false positives in office hours — window extended to 8 hours (28800s)
- Fixed: Event reader re-processed same events on each cycle — `EventRecordID` now tracked
- Fixed: Audit log clear had no account exclusions — `AUDIT_LOG_CLEAR_EXCLUDED_ACCOUNTS` added
- Fixed: LDAP bind password also moved to `GHOSTSECURE_LDAP_PASSWORD` env var

**v2.0**
- Initial release — 8 AD attack detectors, Windows service architecture

---

## Disclaimer

GhostSecure is an **early warning system**, not a complete security solution. It detects known attack patterns from Windows event logs — it does not block attacks or replace a full EDR/SIEM. Always investigate and respond when an alert fires.

Under GDPR/ICO guidelines, security logs should be retained for at least 12 months.

---

## License

MIT License — free to use, modify, and distribute.

---

*Built by Egyan | Red Parrot Accounting Ltd*
