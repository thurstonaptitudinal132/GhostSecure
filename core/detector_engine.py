# =============================================================================
# GhostSecure 2.0 â€” Detector Engine (Orchestrator)
# Coded by Egyan
# =============================================================================

import logging
import os
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.alert_manager import AlertManager
from core.event_reader import EventLogReader
from detectors import kerberoasting
from detectors import pass_the_hash
from detectors import dcsync
from detectors import golden_ticket
from detectors import ldap_recon
from detectors import asrep_roasting
from detectors import skeleton_key

logger = logging.getLogger("GhostSecure2.DetectorEngine")


class DetectorEngine:
    """Central engine that routes events through all registered detectors."""

    def __init__(self):
        self.alert_manager = AlertManager()
        self.event_reader = EventLogReader()
        self._stop_event = threading.Event()
        self._stats = {
            "events_processed": 0,
            "alerts_triggered": 0,
            "start_time": time.time(),
            "last_event_time": None,
        }

        self._detectors = [
            ("kerberoasting", kerberoasting.detect),
            ("pass_the_hash", pass_the_hash.detect),
            ("dcsync", dcsync.detect),
            ("golden_ticket", golden_ticket.detect),
            ("ldap_recon", ldap_recon.detect),
            ("asrep_roasting", asrep_roasting.detect),
            ("skeleton_key", skeleton_key.detect),
        ]

        logger.info(
            f"{config.APP_NAME} v{config.APP_VERSION} â€” Engine initialized. "
            f"{len(self._detectors)} detectors loaded."
        )

    def process_events(self, events):
        """Route a batch of ParsedEvent objects through all detectors."""
        for event in events:
            try:
                self._stats["events_processed"] += 1
                self._stats["last_event_time"] = time.time()

                for det_name, detect_func in self._detectors:
                    try:
                        detect_func(event, self.alert_manager)
                    except Exception as e:
                        logger.error(
                            f"Detector '{det_name}' error on "
                            f"EventID {event.EventID}: {e}"
                        )
            except Exception as e:
                logger.error(f"Error processing event: {e}")

        logger.debug(
            f"Batch of {len(events)} events processed. "
            f"Total: {self._stats['events_processed']}"
        )

    def run(self):
        """Start the main detection loop. Blocks until stop() is called."""
        logger.info(f"Starting {config.APP_NAME} detection engine...")
        self._log_startup_banner()

        try:
            self.event_reader.read_events_continuous(
                callback=self.process_events,
                stop_event=self._stop_event
            )
        except Exception as e:
            logger.critical(f"Detection engine crashed: {e}")
            raise

        logger.info("Detection engine stopped.")

    def stop(self):
        """Signal the engine to stop."""
        logger.info("Shutdown signal received.")
        self._stop_event.set()

    def is_running(self):
        return not self._stop_event.is_set()

    def get_stats(self):
        uptime = time.time() - self._stats["start_time"]
        return {
            **self._stats,
            "alerts_triggered": self.alert_manager.get_alert_count(),
            "uptime_seconds": uptime,
            "uptime_human": self._format_uptime(uptime),
        }

    def _format_uptime(self, seconds):
        d = int(seconds // 86400)
        h = int((seconds % 86400) // 3600)
        m = int((seconds % 3600) // 60)
        s = int(seconds % 60)
        parts = []
        if d > 0: parts.append(f"{d}d")
        if h > 0: parts.append(f"{h}h")
        if m > 0: parts.append(f"{m}m")
        parts.append(f"{s}s")
        return " ".join(parts)

    def _log_startup_banner(self):
        det_names = ", ".join([n for n, _ in self._detectors])
        banner = (
            f"\n{'='*70}\n"
            f"  {config.APP_NAME} v{config.APP_VERSION}\n"
            f"  Active Directory Attack Detector\n"
            f"  Coded by {config.APP_AUTHOR}\n"
            f"  Red Parrot Accounting Ltd\n\n"
            f"  Monitoring: {config.EVENT_LOG_CHANNEL} Event Log\n"
            f"  Detectors:  {det_names}\n"
            f"  Log File:   {config.LOG_FILE}\n"
            f"  Alert Host: {config.ADMIN_HOSTNAME}\n"
            f"  Started:    {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"{'='*70}\n"
        )
        logger.info(banner)
        try:
            os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
            with open(config.LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(banner + "\n")
        except (IOError, OSError) as e:
            logger.error(f"Failed to write startup banner: {e}")
