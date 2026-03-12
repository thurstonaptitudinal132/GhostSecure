# =============================================================================
# GhostSecure 2.1 - Pass-the-Hash Detector
# Coded by Egyan
# =============================================================================
# Event ID 4624: Flag NTLM network logons (type 3) without recent interactive logon.
# =============================================================================

import logging
import os
import sys
import time
import threading
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger("GhostSecure2.Detectors.PassTheHash")

_interactive_logons = defaultdict(list)
_logon_lock = threading.Lock()
_CLEANUP_THRESHOLD = 28800


def _record_interactive_logon(username, timestamp):
    """Record that a user performed an interactive logon."""
    with _logon_lock:
        _interactive_logons[username].append(timestamp)
        cutoff = time.time() - _CLEANUP_THRESHOLD
        _interactive_logons[username] = [
            t for t in _interactive_logons[username] if t > cutoff
        ]


def _has_recent_interactive_logon(username, window_seconds):
    """Check if user had an interactive logon within window."""
    with _logon_lock:
        if username not in _interactive_logons:
            return False
        cutoff = time.time() - window_seconds
        return any(t > cutoff for t in _interactive_logons[username])


def detect(event, alert_manager):
    """Examine a ParsedEvent for Pass-the-Hash indicators."""
    try:
        if event.EventID != 4624:
            return

        logon_type = (event.LogonType or "").strip()
        auth_pkg = (event.AuthenticationPackageName or "").strip()
        account_name = (event.TargetUserName or "").strip()
        account_domain = (event.TargetDomainName or "").strip()
        workstation = (event.WorkstationName or "Unknown").strip()
        source_ip = (event.IpAddress or "Unknown").strip()

        current_time = time.time()

        if not account_name or account_name in ("SYSTEM", "ANONYMOUS LOGON", "-", ""):
            return
        if account_name.endswith("$"):
            return

        # Record interactive logons for correlation
        if logon_type in ("2", "10", "11"):
            _record_interactive_logon(account_name, current_time)
            return

        # Detect: network logon + NTLM + no recent interactive
        if logon_type == "3" and auth_pkg.upper() == "NTLM":
            if not _has_recent_interactive_logon(
                account_name, config.PTH_INTERACTIVE_WINDOW_SECONDS
            ):
                detail_parts = [
                    f"NTLM network logon (type 3) for '{account_name}' "
                    f"without interactive logon in last "
                    f"{config.PTH_INTERACTIVE_WINDOW_SECONDS}s.",
                    f"Auth Package: {auth_pkg}.",
                ]

                # Check workstation mismatch
                if config.PTH_USER_WORKSTATION_MAP:
                    expected = config.PTH_USER_WORKSTATION_MAP.get(account_name.lower())
                    if expected and workstation.upper() != expected.upper():
                        detail_parts.append(
                            f"WORKSTATION MISMATCH: Expected '{expected}', "
                            f"got '{workstation}'."
                        )

                detail_parts.append(
                    "Pass-the-Hash uses stolen NTLM hashes to authenticate "
                    "without knowing the password."
                )

                attacker = f"{account_name} ({account_domain}\\{account_name})"
                logger.warning(
                    f"Pass-the-Hash detected: {account_name} "
                    f"from {workstation} ({source_ip})"
                )
                alert_manager.send_alert(
                    attack_type="PASS-THE-HASH",
                    attacker=attacker,
                    source_machine=workstation,
                    source_ip=source_ip,
                    target=f"Network logon to {event.Computer}",
                    event_id=4624,
                    details=" ".join(detail_parts),
                    severity="CRITICAL"
                )

    except AttributeError as e:
        logger.error(f"PtH detector - missing attribute: {e}")
    except Exception as e:
        logger.error(f"PtH detector - unexpected error: {e}")
