# =============================================================================
# GhostSecure 2.0 â€” Skeleton Key Detector
# Coded by Egyan
# =============================================================================
# Event ID 7045: Suspicious service installation
# Event ID 4673: Sensitive privilege use by non-SYSTEM accounts
# Event ID 1102: Audit log cleared
# =============================================================================

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger("GhostSecure2.Detectors.SkeletonKey")


def detect(event, alert_manager):
    """Examine a ParsedEvent for Skeleton Key attack indicators."""
    try:
        # --- Suspicious Service Installation (7045) ---
        if event.EventID == 7045:
            svc_name = (event.ServiceName or "").strip()
            svc_file = (event.ServiceFileName or "").strip()
            subject_user = (event.SubjectUserName or "").strip()
            subject_domain = (event.SubjectDomainName or "").strip()

            if not svc_name:
                svc_name = event.EventData.get("ServiceName", "")
            if not svc_file:
                svc_file = event.EventData.get("ImagePath", "")

            combined = (svc_name + " " + svc_file).lower()
            matched = ""

            for indicator in config.SKELETON_KEY_SERVICE_NAMES:
                if indicator.lower() in combined:
                    matched = indicator
                    break

            if not matched:
                patterns = [
                    "\\temp\\", "\\tmp\\", "appdata\\local\\temp",
                    "mimikatz", "mimidrv", "mimilib", "sekurlsa",
                    "lsadump", "kerberos::golden", "misc::skeleton",
                    "privilege::debug"
                ]
                for p in patterns:
                    if p.lower() in combined:
                        matched = p
                        break

            if matched:
                attacker = f"{subject_user} ({subject_domain}\\{subject_user})"
                logger.warning(
                    f"Skeleton Key: suspicious service '{svc_name}' at '{svc_file}' "
                    f"(matched: {matched})"
                )
                alert_manager.send_alert(
                    attack_type="SKELETON KEY",
                    attacker=attacker,
                    source_machine=event.Computer or "Unknown",
                    source_ip=event.IpAddress or "Unknown",
                    target=f"LSASS on {event.Computer} (Domain Controller)",
                    event_id=7045,
                    details=(
                        f"Suspicious service on DC: Name='{svc_name}', "
                        f"Path='{svc_file}'. Matched: '{matched}'. "
                        f"Skeleton Key injects a master password into LSASS. "
                        f"ACTION: Restart the DC to clear, then investigate."
                    ),
                    severity="CRITICAL"
                )

        # --- Sensitive Privilege Use (4673) ---
        elif event.EventID == 4673:
            subject_user = (event.SubjectUserName or "").strip()
            subject_domain = (event.SubjectDomainName or "").strip()
            priv_list = (event.PrivilegeList or "").strip()
            proc_name = (event.ProcessName or "").strip()

            if subject_user.upper() in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                return
            if subject_user.endswith("$"):
                return

            for priv in config.SKELETON_KEY_SUSPICIOUS_PRIVS:
                if priv.lower() in priv_list.lower():
                    proc_lower = proc_name.lower()
                    suspicious = any(
                        p in proc_lower for p in [
                            "mimikatz", "mimi", "procdump", "lsass",
                            "powershell", "cmd.exe", "wscript", "cscript"
                        ]
                    )

                    if priv == "SeDebugPrivilege" or suspicious:
                        attacker = f"{subject_user} ({subject_domain}\\{subject_user})"
                        logger.warning(
                            f"Skeleton Key indicator: {subject_user} used "
                            f"{priv} via {proc_name}"
                        )
                        alert_manager.send_alert(
                            attack_type="SKELETON KEY",
                            attacker=attacker,
                            source_machine=event.Computer or "Unknown",
                            source_ip=event.IpAddress or "Unknown",
                            target=f"LSASS on {event.Computer}",
                            event_id=4673,
                            details=(
                                f"'{subject_user}' used privilege '{priv}' "
                                f"via '{proc_name}'. Common precursor to "
                                f"Skeleton Key injection. "
                                f"Full privileges: {priv_list}."
                            ),
                            severity="HIGH"
                        )
                        break

        # --- Audit Log Cleared (1102) ---
        elif event.EventID == 1102:
            subject_user = (event.SubjectUserName or "").strip()
            subject_domain = (event.SubjectDomainName or "").strip()

            # Skip accounts that are allowed to clear logs (backup tools, known admins)
            excluded = [a.lower() for a in config.AUDIT_LOG_CLEAR_EXCLUDED_ACCOUNTS]
            if subject_user.lower() in excluded:
                logger.debug(f"Audit log cleared by excluded account '{subject_user}' — suppressed.")
                return

            attacker = f"{subject_user} ({subject_domain}\\{subject_user})"
            logger.warning(
                f"Audit log cleared by {subject_user} â€” evidence destruction"
            )
            alert_manager.send_alert(
                attack_type="AUDIT LOG CLEARED",
                attacker=attacker,
                source_machine=event.Computer or "Unknown",
                source_ip=event.IpAddress or "Unknown",
                target=f"Security Event Log on {event.Computer}",
                event_id=1102,
                details=(
                    f"Security audit log cleared by '{subject_user}'. "
                    f"Strong indicator of attacker covering tracks. "
                    f"Under GDPR/ICO, security logs must be preserved. "
                    f"IMMEDIATE ACTION: Investigate all activity from this account."
                ),
                severity="CRITICAL"
            )

    except AttributeError as e:
        logger.error(f"Skeleton Key detector â€” missing attribute: {e}")
    except Exception as e:
        logger.error(f"Skeleton Key detector â€” unexpected error: {e}")
