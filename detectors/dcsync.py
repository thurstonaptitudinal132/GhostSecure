# =============================================================================
# GhostSecure 2.0 â€” DCSync Attack Detector
# Coded by Egyan
# =============================================================================
# Event ID 4662: Flag replication GUIDs requested by non-DC accounts.
# =============================================================================

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.ad_helpers import get_domain_controllers

logger = logging.getLogger("GhostSecure2.Detectors.DCSync")

REPLICATION_GUIDS = {
    "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}": "DS-Replication-Get-Changes",
    "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}": "DS-Replication-Get-Changes-All",
    "{89e95b76-444d-4c62-991a-0facbeda640c}": "DS-Replication-Get-Changes-In-Filtered-Set",
}
CRITICAL_GUID = "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"


def detect(event, alert_manager):
    """Examine a ParsedEvent for DCSync attack indicators."""
    try:
        if event.EventID != 4662:
            return

        subject_user = (event.SubjectUserName or "").strip()
        subject_domain = (event.SubjectDomainName or "").strip()
        properties = (event.Properties or "").strip()
        access_mask = (event.AccessMask or "").strip()
        object_type = (event.ObjectType or "").strip()

        if not subject_user or not properties:
            return

        # Skip known domain controllers
        clean_subject = subject_user.rstrip("$")
        known_dcs = get_domain_controllers()
        if clean_subject.upper() in [dc.upper() for dc in known_dcs]:
            return

        # Check for replication GUIDs
        props_lower = properties.lower()
        found_guids = []
        for guid, name in REPLICATION_GUIDS.items():
            if guid.lower() in props_lower:
                found_guids.append(name)

        if not found_guids:
            return

        has_critical = CRITICAL_GUID.lower() in props_lower
        severity = "CRITICAL" if has_critical else "HIGH"
        attacker = f"{subject_user} ({subject_domain}\\{subject_user})"
        repl_rights = ", ".join(found_guids)

        logger.warning(
            f"DCSync detected: {subject_user} performing replication ({repl_rights})"
        )
        alert_manager.send_alert(
            attack_type="DCSYNC ATTACK",
            attacker=attacker,
            source_machine=event.Computer or "Unknown",
            source_ip=event.IpAddress or "Unknown",
            target=f"Active Directory Domain ({config.DOMAIN_NAME})",
            event_id=4662,
            details=(
                f"{subject_user} requesting AD replication â€” possible DCSync/Mimikatz. "
                f"Rights used: {repl_rights}. Access mask: {access_mask}. "
                f"Object type: {object_type}. NOT a known DC. "
                f"Known DCs: {', '.join(known_dcs)}. "
                f"If new DC, add to KNOWN_DOMAIN_CONTROLLERS in config.py."
            ),
            severity=severity
        )

    except AttributeError as e:
        logger.error(f"DCSync detector â€” missing attribute: {e}")
    except Exception as e:
        logger.error(f"DCSync detector â€” unexpected error: {e}")
