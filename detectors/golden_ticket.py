# =============================================================================
# GhostSecure 2.1 - Golden Ticket Detector
# Coded by Egyan
# =============================================================================
# Event IDs 4768/4769: Flag forged TGTs with excessive lifetime or RC4 downgrade.
# =============================================================================

import logging
import os
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger("GhostSecure2.Detectors.GoldenTicket")

_tgt_issuance = {}
_tgt_lock = threading.Lock()


def detect(event, alert_manager):
    """Examine a ParsedEvent for Golden Ticket indicators."""
    try:
        if event.EventID not in (4768, 4769):
            return

        account_name = (event.TargetUserName or "").strip()
        account_domain = (event.TargetDomainName or "").strip()
        enc_type = (event.TicketEncryptionType or "").strip()
        ticket_options = (event.TicketOptions or "").strip()
        service_name = (event.ServiceName or "").strip()
        source_ip = (event.IpAddress or "Unknown").strip()
        workstation = (event.WorkstationName or "Unknown").strip()
        status = (event.Status or "").strip()

        if not account_name or account_name.endswith("$"):
            return

        attacker = f"{account_name} ({account_domain}\\{account_name})"
        current_time = time.time()

        # --- TGT Request anomalies (4768) ---
        if event.EventID == 4768:
            alerts = []

            if enc_type.lower() == config.KERB_WEAK_ENCRYPTION_TYPE.lower():
                alerts.append(
                    "TGT with RC4 encryption (0x17) instead of AES - "
                    "may be Golden Ticket forged with NTLM hash."
                )

            if status == "0x6":
                alerts.append(
                    f"TGT for non-existent account '{account_name}'. "
                    "Attackers sometimes forge tickets with fake names."
                )

            _tgt_issuance[account_name] = current_time

            if alerts:
                logger.warning(f"Golden Ticket TGT indicators: {account_name}")
                alert_manager.send_alert(
                    attack_type="GOLDEN TICKET",
                    attacker=attacker,
                    source_machine=workstation,
                    source_ip=source_ip,
                    target=f"krbtgt ({config.DOMAIN_NAME} TGT)",
                    event_id=4768,
                    details=" | ".join(alerts),
                    severity="CRITICAL"
                )

        # --- TGS Request anomalies (4769) ---
        elif event.EventID == 4769:
            alerts = []

            if ticket_options:
                try:
                    opts_int = int(ticket_options, 16)
                    is_forwardable = bool(opts_int & 0x40000000)

                    with _tgt_lock:
                        tgt_time = _tgt_issuance.get(account_name)
                    if tgt_time is not None:
                        ticket_age = current_time - tgt_time
                        if ticket_age > config.GOLDEN_TICKET_MAX_LIFETIME_SECONDS:
                            hours = ticket_age / 3600
                            max_h = config.GOLDEN_TICKET_MAX_LIFETIME_SECONDS / 3600
                            alerts.append(
                                f"Ticket lifetime {hours:.1f}h exceeds max {max_h:.0f}h. "
                                "Golden Tickets have very long lifetimes."
                            )

                    if (is_forwardable and
                            enc_type.lower() == config.KERB_WEAK_ENCRYPTION_TYPE.lower()):
                        alerts.append(
                            "Forwardable TGS with RC4 - common in Golden Ticket usage."
                        )

                except (ValueError, TypeError):
                    logger.debug(f"Could not parse ticket options: {ticket_options}")

            if (enc_type.lower() == config.KERB_WEAK_ENCRYPTION_TYPE.lower()
                    and service_name.lower() == "krbtgt"):
                alerts.append(
                    "Service ticket for krbtgt with RC4 - "
                    "possible TGT renewal using forged Golden Ticket."
                )

            if alerts:
                logger.warning(f"Golden Ticket TGS indicators: {account_name}")
                alert_manager.send_alert(
                    attack_type="GOLDEN TICKET",
                    attacker=attacker,
                    source_machine=workstation,
                    source_ip=source_ip,
                    target=f"{service_name} (service ticket)",
                    event_id=4769,
                    details=" | ".join(alerts),
                    severity="CRITICAL"
                )

        # Clean up old TGT records
        cutoff = current_time - 86400
        with _tgt_lock:
            for k in [k for k, v in _tgt_issuance.items() if v < cutoff]:
                del _tgt_issuance[k]

    except AttributeError as e:
        logger.error(f"Golden Ticket detector - missing attribute: {e}")
    except Exception as e:
        logger.error(f"Golden Ticket detector - unexpected error: {e}")
