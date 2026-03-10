================================================================================
  GHOSTSECURE 2.1 - ACTIVE DIRECTORY ATTACK DETECTOR
  Red Parrot Accounting Ltd | Coded by Egyan
================================================================================

WHAT IS THIS?
  GhostSecure watches your company's login system (Active Directory) in the
  background and sends an alert if it spots someone trying to break in or
  steal account passwords.

  It works silently as a Windows service - you don't need to open anything.
  If it detects an attack, a pop-up appears on the admin's screen immediately.

--------------------------------------------------------------------------------
WHAT ATTACKS DOES IT DETECT?
--------------------------------------------------------------------------------

  KERBEROASTING
  Someone is trying to steal and crack a staff account's password offline.
  GhostSecure spots the unusual login request that gives this away.

  PASS-THE-HASH
  An attacker is pretending to be a staff member without knowing their actual
  password - using a stolen password "fingerprint" instead.

  DCSYNC (Mimikatz)
  Someone is trying to secretly copy ALL passwords from your company's
  login server (the Domain Controller). This is very serious.

  GOLDEN TICKET
  An attacker has forged a master login pass that lets them access anything
  in the company. GhostSecure detects the unusual patterns these create.

  LDAP RECON / BLOODHOUND
  Someone is running a scanning tool to map out your entire company network
  and find weak points. Hundreds of queries in seconds gives it away.

  AS-REP ROASTING
  A staff account has been set up without a security check, letting attackers
  grab a crackable version of their password without even logging in.

  SKELETON KEY
  An attacker has installed secret software on the login server that lets
  them log in as ANY user with a single master password.

  AUDIT LOG CLEARED
  Someone has deleted the security logs - a classic sign that an attacker
  is trying to cover their tracks.

--------------------------------------------------------------------------------
HOW TO INSTALL (IT STAFF ONLY)
--------------------------------------------------------------------------------

  1. Copy this folder to the server
  2. Open config.py in Notepad and fill in:
       - ADMIN_HOSTNAME: the computer name where alerts should appear
       - KNOWN_DOMAIN_CONTROLLERS: your server names (e.g. "DC01", "DC02")
       - DOMAIN_NAME: your company domain (e.g. "REDPARROT")
  3. Right-click Install.bat and choose "Run as administrator"
  4. Done - GhostSecure starts automatically and runs in the background

  To check it is running:
    Open Command Prompt and type: sc query GhostSecure2ADDetector
    It should say: STATE: RUNNING

  To open the dashboard:
    python main.py --gui

--------------------------------------------------------------------------------
ENABLING AUDIT LOGGING ON YOUR SERVER (REQUIRED)
--------------------------------------------------------------------------------

  GhostSecure needs Windows to record security events. Without this step,
  it has nothing to monitor. Ask your IT person to:

  1. Open "Group Policy Management" on the Domain Controller
  2. Edit the Default Domain Controllers Policy
  3. Go to: Computer Configuration > Policies > Windows Settings >
            Security Settings > Advanced Audit Policy Configuration >
            Audit Policies
  4. Enable "Success and Failure" for:
       - Account Logon > Audit Kerberos Authentication Service
       - Account Logon > Audit Kerberos Service Ticket Operations
       - DS Access > Audit Directory Service Access
       - Logon/Logoff > Audit Logon
       - Privilege Use > Audit Sensitive Privilege Use
       - System > Audit Security State Change
  5. Run: gpupdate /force

--------------------------------------------------------------------------------
WHAT HAPPENS WHEN AN ATTACK IS DETECTED?
--------------------------------------------------------------------------------

  GhostSecure will:
    1. Write the alert to: C:\SecurityLogs\ad_attack_log.txt
    2. Show a pop-up on the admin's screen (the ADMIN_HOSTNAME you set)
    3. Send an email (if you set up email alerts in config.py)

  Each alert includes:
    - What type of attack was detected
    - Which account was involved
    - Which computer it came from
    - What to do about it

  Alerts for the same attack are grouped - you will not get 100 pop-ups for
  the same incident. Each unique attack only alerts once every 5 minutes.

--------------------------------------------------------------------------------
EMAIL ALERTS (OPTIONAL)
--------------------------------------------------------------------------------

  To get email alerts when an attack is detected:

  1. Open config.py in Notepad
  2. Change: ENABLE_EMAIL_ALERTS = False  →  True
  3. Fill in your SMTP server details (ask your IT person if unsure)
  4. For the email password, DO NOT type it into config.py directly.
     Instead, open PowerShell as Administrator and run:

     [System.Environment]::SetEnvironmentVariable(
       'GHOSTSECURE_SMTP_PASSWORD', 'YourPasswordHere', 'Machine')

     Then restart the service.

--------------------------------------------------------------------------------
UNINSTALLING
--------------------------------------------------------------------------------

  Right-click Uninstall.bat and choose "Run as administrator".
  This stops and removes the service. Your log files are kept.

--------------------------------------------------------------------------------
IMPORTANT NOTES
--------------------------------------------------------------------------------

  - GhostSecure is an early warning system, not a complete security solution.
    It alerts you to attacks - you still need to investigate and respond.

  - It only works if Windows audit logging is enabled (see section above).

  - Under GDPR/ICO guidelines, security logs must be kept for at least
    12 months. The log file is at C:\SecurityLogs\ad_attack_log.txt.

  - If you want to ignore certain accounts for audit log alerts (for example
    a backup tool that clears logs automatically), add them to:
    AUDIT_LOG_CLEAR_EXCLUDED_ACCOUNTS in config.py

================================================================================
  Version 2.1 | Coded by Egyan | Red Parrot Accounting Ltd
================================================================================
