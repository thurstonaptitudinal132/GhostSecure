# =============================================================================
# GhostSecure 2.1  -  Active Directory Attack Detector
# Configuration File
# Coded by Egyan
# =============================================================================
# All configurable variables are defined here at the TOP of the project.
# Modify these values to match your environment before deployment.
# =============================================================================

import os

# -----------------------------------------------------------------------------
# GENERAL SETTINGS
# -----------------------------------------------------------------------------
APP_NAME = "GhostSecure 2.1"
APP_DISPLAY_NAME = "GhostSecure 2.1 - AD Attack Detector"
APP_VERSION = "2.1.0"
APP_AUTHOR = "Egyan"
SERVICE_NAME = "GhostSecure2ADDetector"
SERVICE_DESCRIPTION = (
    "Monitors Active Directory event logs for advanced attacks including "
    "Kerberoasting, Pass-the-Hash, DCSync, Golden Ticket, LDAP Recon, "
    "AS-REP Roasting, and Skeleton Key."
)

# -----------------------------------------------------------------------------
# PATHS
# -----------------------------------------------------------------------------
LOG_DIRECTORY = r"C:\SecurityLogs"
LOG_FILE = os.path.join(LOG_DIRECTORY, "ad_attack_log.txt")
STATE_FILE = os.path.join(LOG_DIRECTORY, "ghostsecure_state.json")
PID_FILE = os.path.join(LOG_DIRECTORY, "ghostsecure.pid")

# -----------------------------------------------------------------------------
# ADMIN / ALERT TARGETS
# -----------------------------------------------------------------------------
ADMIN_HOSTNAME = "ADMINPC"
ADDITIONAL_ALERT_HOSTS = []

# -----------------------------------------------------------------------------
# EMAIL ALERT SETTINGS (using smtplib  -  free SMTP server required)
# -----------------------------------------------------------------------------
ENABLE_EMAIL_ALERTS = False
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USE_TLS = True
SMTP_USERNAME = ""
# NEVER put your password here. Set a Windows environment variable instead:
#   [System.Environment]::SetEnvironmentVariable('GHOSTSECURE_SMTP_PASSWORD', 'yourpassword', 'Machine')
SMTP_PASSWORD = os.environ.get("GHOSTSECURE_SMTP_PASSWORD", "")
EMAIL_FROM = "ghostsecure@redparrotaccounting.co.uk"
EMAIL_TO = ["admin@redparrotaccounting.co.uk"]
EMAIL_SUBJECT_PREFIX = "[GhostSecure 2.1 CRITICAL]"

# -----------------------------------------------------------------------------
# DOMAIN SETTINGS
# -----------------------------------------------------------------------------
DOMAIN_NAME = "REDPARROT"
DOMAIN_FQDN = "redparrot.local"
KNOWN_DOMAIN_CONTROLLERS = ["DC01", "DC02"]
LDAP_SERVER = "ldap://dc01.redparrot.local"
LDAP_BASE_DN = "DC=redparrot,DC=local"
LDAP_USE_WINDOWS_AUTH = True
LDAP_BIND_USER = ""
# NEVER put your password here. Set a Windows environment variable instead:
#   [System.Environment]::SetEnvironmentVariable('GHOSTSECURE_LDAP_PASSWORD', 'yourpassword', 'Machine')
LDAP_BIND_PASSWORD = os.environ.get("GHOSTSECURE_LDAP_PASSWORD", "")

# -----------------------------------------------------------------------------
# DETECTION THRESHOLDS
# -----------------------------------------------------------------------------
KERB_WEAK_ENCRYPTION_TYPE = "0x17"
KERB_SAFE_ENCRYPTION_TYPES = ["0x12", "0x11"]

# How long after an interactive logon to suppress PtH alerts for that user.
# Set to a full working day (8h) to avoid false positives from mapped drives,
# printers, and file servers accessed throughout the day.
PTH_INTERACTIVE_WINDOW_SECONDS = 28800
PTH_USER_WORKSTATION_MAP = {}

GOLDEN_TICKET_MAX_LIFETIME_SECONDS = 10 * 3600

LDAP_RECON_THRESHOLD = 500
LDAP_RECON_WINDOW_SECONDS = 60

ASREP_NOPREAUTH_FLAGS = ["0x0", "0"]

SKELETON_KEY_SERVICE_NAMES = ["mimidrv", "mimikatz"]
SKELETON_KEY_SUSPICIOUS_PRIVS = [
    "SeTcbPrivilege",
    "SeDebugPrivilege",
    "SeLoadDriverPrivilege"
]

# -----------------------------------------------------------------------------
# EVENT LOG SETTINGS
# -----------------------------------------------------------------------------
EVENT_LOG_CHANNEL = "Security"
EVENT_POLL_INTERVAL_SECONDS = 5
MAX_EVENTS_PER_CYCLE = 1000
INITIAL_LOOKBACK_SECONDS = 3600

MONITORED_EVENT_IDS = [
    4769, 4768, 4624, 4662, 4673, 7045, 1102,
]

ENABLE_LDAP_MONITORING = True
LDAP_MONITOR_PORT = 389

# Accounts allowed to clear audit logs without triggering an alert.
# Add backup tool service accounts or known admin accounts here.
# Example: ["svc_backup", "Administrator"]
AUDIT_LOG_CLEAR_EXCLUDED_ACCOUNTS = []

# -----------------------------------------------------------------------------
# COOLDOWN SETTINGS
# -----------------------------------------------------------------------------
ALERT_COOLDOWN_SECONDS = 300

# -----------------------------------------------------------------------------
# POPUP SETTINGS
# -----------------------------------------------------------------------------
ENABLE_DESKTOP_POPUP = True
POPUP_DURATION_SECONDS = 30

# -----------------------------------------------------------------------------
# LOGGING LEVELS
# -----------------------------------------------------------------------------
CONSOLE_LOG_LEVEL = "INFO"
FILE_LOG_LEVEL = "DEBUG"
