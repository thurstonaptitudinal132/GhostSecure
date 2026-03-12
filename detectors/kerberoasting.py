# =============================================================================
# GhostSecure 2.1 - Kerberoasting Detector
# Coded by Egyan
# =============================================================================
# Event ID 4769: Flag RC4 (0x17) ticket requests for non-machine service accounts.
# =============================================================================

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.ad_helpers import is_machine_account

logger = logging.getLogger("GhostSecure2.Detectors.Kerberoasting")


def detect(event, alert_manager):
    """Examine a ParsedEvent for Kerberoasting indicators."""
    try:
        if event.EventID != 4769:
            return

        service_name = (event.ServiceName or "").strip()
        enc_type = (event.TicketEncryptionType or "").strip()
        account_name = (event.TargetUserName or "").strip()
        account_domain = (event.TargetDomainName or "").strip()
        source_ip = (event.IpAddress or "Unknown").strip()
        workstation = (event.WorkstationName or "Unknown").strip()

        if not service_name or not enc_type:
            return

        # Skip machine accounts and krbtgt
        if is_machine_account(service_name):
            return
        if service_name.lower() == "krbtgt":
            return

        # RC4 encryption = weak, used by Kerberoasting tools
        if enc_type.lower() == config.KERB_WEAK_ENCRYPTION_TYPE.lower():
            logger.warning(
                f"Kerberoasting detected: RC4 ticket for {service_name} by {account_name}"
            )
            attacker = f"{account_name} ({account_domain}\\{account_name})"
            alert_manager.send_alert(
                attack_type="KERBEROASTING",
                attacker=attacker,
                source_machine=workstation,
                source_ip=source_ip,
                target=f"{service_name} (service account)",
                event_id=4769,
                details=(
                    f"RC4-encrypted (0x17) Kerberos service ticket requested for "
                    f"service account '{service_name}'. Strong indicator of "
                    f"Kerberoasting - attacker will crack this ticket offline. "
                    f"Encryption type: {enc_type}. Expected: AES (0x12 or 0x11)."
                ),
                severity="CRITICAL"
            )

    except AttributeError as e:
        logger.error(f"Kerberoasting detector - missing attribute: {e}")
    except Exception as e:
        logger.error(f"Kerberoasting detector - unexpected error: {e}")
