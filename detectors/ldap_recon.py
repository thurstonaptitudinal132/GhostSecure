# =============================================================================
# GhostSecure 2.1 - LDAP Reconnaissance Detector
# Coded by Egyan
# =============================================================================
# Detects LDAP recon (BloodHound/SharpHound) by monitoring query rate per source.
# =============================================================================

import logging
import os
import sys
import time
import threading
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger("GhostSecure2.Detectors.LDAPRecon")

_ldap_counter = defaultdict(list)
_counter_lock = threading.Lock()
_alerted_sources = {}
_CLEANUP_INTERVAL = 120
_last_cleanup = time.time()


def _cleanup_old_entries():
    """Purge old timestamp entries to prevent memory leaks."""
    global _last_cleanup
    current_time = time.time()
    if (current_time - _last_cleanup) < _CLEANUP_INTERVAL:
        return

    cutoff = current_time - config.LDAP_RECON_WINDOW_SECONDS - 10
    with _counter_lock:
        for src in list(_ldap_counter.keys()):
            _ldap_counter[src] = [t for t in _ldap_counter[src] if t > cutoff]
            if not _ldap_counter[src]:
                del _ldap_counter[src]

        alert_cutoff = current_time - config.ALERT_COOLDOWN_SECONDS
        for k in [k for k, v in _alerted_sources.items() if v < alert_cutoff]:
            del _alerted_sources[k]

    _last_cleanup = current_time


def record_ldap_query(source_ip):
    """Record an LDAP query. Returns True if threshold exceeded."""
    if not source_ip or source_ip in ("-", "::1", "127.0.0.1"):
        return False

    current_time = time.time()
    with _counter_lock:
        _ldap_counter[source_ip].append(current_time)
        window_start = current_time - config.LDAP_RECON_WINDOW_SECONDS
        recent = [t for t in _ldap_counter[source_ip] if t > window_start]
        _ldap_counter[source_ip] = recent
        return len(recent) > config.LDAP_RECON_THRESHOLD


def detect(event, alert_manager):
    """Examine a ParsedEvent for LDAP recon indicators."""
    try:
        _cleanup_old_entries()

        if event.EventID != 4662:
            return

        source_ip = (event.IpAddress or "").strip()
        subject_user = (event.SubjectUserName or "").strip()
        subject_domain = (event.SubjectDomainName or "").strip()

        source_id = source_ip if source_ip and source_ip != "-" else subject_user
        if not source_id or source_id in ("-", "SYSTEM"):
            return

        threshold_exceeded = record_ldap_query(source_id)

        if threshold_exceeded:
            current_time = time.time()
            with _counter_lock:
                last_alert = _alerted_sources.get(source_id, 0)
                if (current_time - last_alert) < config.ALERT_COOLDOWN_SECONDS:
                    return
                _alerted_sources[source_id] = current_time

                window_start = current_time - config.LDAP_RECON_WINDOW_SECONDS
                query_count = len([
                    t for t in _ldap_counter.get(source_id, [])
                    if t > window_start
                ])

            attacker = f"{subject_user} ({subject_domain}\\{subject_user})"
            logger.warning(
                f"LDAP Recon detected: {source_id} made {query_count} queries "
                f"in {config.LDAP_RECON_WINDOW_SECONDS}s"
            )

            from utils.ad_helpers import resolve_ip_to_hostname
            hostname = resolve_ip_to_hostname(source_id) if source_ip else source_id

            alert_manager.send_alert(
                attack_type="LDAP RECON",
                attacker=attacker,
                source_machine=hostname,
                source_ip=source_id,
                target=f"Active Directory LDAP ({config.DOMAIN_FQDN})",
                event_id=4662,
                details=(
                    f"{source_id} made {query_count} directory queries in "
                    f"{config.LDAP_RECON_WINDOW_SECONDS}s "
                    f"(threshold: {config.LDAP_RECON_THRESHOLD}). "
                    f"Strong indicator of BloodHound/SharpHound domain enumeration."
                ),
                severity="CRITICAL"
            )

    except AttributeError as e:
        logger.error(f"LDAP Recon detector - missing attribute: {e}")
    except Exception as e:
        logger.error(f"LDAP Recon detector - unexpected error: {e}")


def get_query_stats():
    """Return current LDAP query stats for dashboard."""
    current_time = time.time()
    window_start = current_time - config.LDAP_RECON_WINDOW_SECONDS
    stats = {}
    with _counter_lock:
        for src, timestamps in _ldap_counter.items():
            recent = [t for t in timestamps if t > window_start]
            if recent:
                stats[src] = len(recent)
    return stats
