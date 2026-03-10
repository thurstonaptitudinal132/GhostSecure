# =============================================================================
# GhostSecure 2.0 â€” AS-REP Roasting Detector
# Coded by Egyan
# =============================================================================
# Event ID 4768: Flag accounts where pre-authentication is not required.
# =============================================================================

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger("GhostSecure2.Detectors.ASREPRoasting")


def detect(event, alert_manager):
    """Examine a ParsedEvent for AS-REP Roasting indicators."""
    try:
        if event.EventID != 4768:
            return

        account_name = (event.TargetUserName or "").strip()
        account_domain = (event.TargetDomainName or "").strip()
        pre_auth_type = (event.PreAuthType or "").strip()
        enc_type = (event.TicketEncryptionType or "").strip()
        source_ip = (event.IpAddress or "Unknown").strip()
        workstation = (event.WorkstationName or "Unknown").strip()

        if not account_name or account_name.endswith("$"):
            return

        if pre_auth_type in config.ASREP_NOPREAUTH_FLAGS:
            attacker = f"{account_name} ({account_domain}\\{account_name})"
            logger.warning(
                f"AS-REP Roasting: '{account_name}' has no pre-auth. Hash exposed to {source_ip}."
            )
            alert_manager.send_alert(
                attack_type="AS-REP ROASTING",
                attacker=attacker,
                source_machine=workstation,
                source_ip=source_ip,
                target=f"{account_name} (password hash exposed)",
                event_id=4768,
                details=(
                    f"Account '{account_name}' has 'Do not require Kerberos "
                    f"preauthentication' enabled. TGT requested without pre-auth â€” "
                    f"AS-REP can be cracked offline. Pre-auth: {pre_auth_type}. "
                    f"Encryption: {enc_type}. "
                    f"REMEDIATION: Enable pre-auth in AD Users & Computers, "
                    f"then reset the password immediately."
                ),
                severity="CRITICAL"
            )

    except AttributeError as e:
        logger.error(f"AS-REP detector â€” missing attribute: {e}")
    except Exception as e:
        logger.error(f"AS-REP detector â€” unexpected error: {e}")
