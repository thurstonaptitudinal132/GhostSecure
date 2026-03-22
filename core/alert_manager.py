# =============================================================================
# GhostSecure 2.1 - Alert Manager
# Coded by Egyan
# =============================================================================

import logging
import os
import ssl
import sys
import subprocess
import threading
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from utils.time_helpers import now_timestamp

logger = logging.getLogger("GhostSecure2.AlertManager")


class AlertManager:
    """
    Centralized alert handler. Dispatches alerts to log file,
    Windows msg.exe, desktop popup, and email.
    """

    def __init__(self):
        self._cooldown_tracker = defaultdict(float)
        self._lock = threading.Lock()
        self._alerts_triggered = 0
        try:
            os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
            logger.info(f"Log directory verified: {config.LOG_DIRECTORY}")
        except OSError as e:
            logger.error(f"Failed to create log directory: {e}")

    def send_alert(self, attack_type, attacker, source_machine, source_ip,
                   target, event_id, details="", severity="CRITICAL"):
        """Send an alert through all configured channels."""
        cooldown_key = (attack_type, attacker, source_machine)
        with self._lock:
            last_time = self._cooldown_tracker.get(cooldown_key, 0)
            if (time.time() - last_time) < config.ALERT_COOLDOWN_SECONDS:
                logger.debug(f"Alert suppressed (cooldown): {attack_type} from {attacker}")
                return
            self._cooldown_tracker[cooldown_key] = time.time()
            self._alerts_triggered += 1

        timestamp = now_timestamp()
        alert_text = self._format_alert(
            attack_type, timestamp, attacker, source_machine,
            source_ip, target, event_id, details, severity
        )

        logger.warning(f"ALERT: {attack_type} - {attacker} from {source_machine}")

        # FIX: separate fast (fire-and-wait) threads from the email thread.
        # Joining the email thread with a 30-second timeout blocked the
        # detection loop on every alert.  Email is dispatched as a true
        # daemon thread: started but never joined, so it cannot stall the
        # detector engine.  Log and msg.exe are fast (<1 s) and are still
        # joined so the caller sees a coherent log before returning.
        fast_threads = []
        t1 = threading.Thread(target=self._write_log, args=(alert_text,), daemon=True)
        fast_threads.append(t1)

        t2 = threading.Thread(target=self._send_msg_exe, args=(alert_text,), daemon=True)
        fast_threads.append(t2)

        if config.ENABLE_DESKTOP_POPUP:
            t3 = threading.Thread(
                target=self._show_popup, args=(attack_type, alert_text,), daemon=True
            )
            fast_threads.append(t3)

        if config.ENABLE_EMAIL_ALERTS:
            t4 = threading.Thread(
                target=self._send_email,
                args=(attack_type, alert_text, severity,),
                daemon=True
            )
            t4.start()  # fire-and-forget — do NOT join

        for t in fast_threads:
            t.start()
        for t in fast_threads:
            t.join(timeout=10)

    def _format_alert(self, attack_type, timestamp, attacker, source_machine,
                      source_ip, target, event_id, details, severity):
        """Build the standardized alert text block."""
        sep = "=" * 70
        return (
            f"\n{sep}\n"
            f"[{severity} - AD ATTACK DETECTED]\n"
            f"{sep}\n"
            f"Attack Type:    {attack_type}\n"
            f"Time:           {timestamp}\n"
            f"Attacker:       {attacker}\n"
            f"Source Machine: {source_machine} ({source_ip})\n"
            f"Target:         {target}\n"
            f"Event ID:       {event_id}\n"
            f"Details:        {details}\n"
            f"Action:         Alert sent to {config.ADMIN_HOSTNAME}. "
            f"Manual investigation required.\n"
            f"Log:            {config.LOG_FILE}\n"
            f"{sep}"
        )

    def _write_log(self, alert_text):
        """Append the alert to the log file."""
        try:
            os.makedirs(config.LOG_DIRECTORY, exist_ok=True)
            with open(config.LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(alert_text + "\n\n")
            logger.debug(f"Alert written to {config.LOG_FILE}")
        except (IOError, OSError) as e:
            logger.error(f"Failed to write alert to log file: {e}")

    def _send_msg_exe(self, alert_text):
        """Send alert to ADMINPC using Windows msg.exe."""
        short_msg = alert_text[:500] if len(alert_text) > 500 else alert_text
        targets = [config.ADMIN_HOSTNAME] + config.ADDITIONAL_ALERT_HOSTS

        for hostname in targets:
            try:
                cmd = [
                    "msg.exe", "*",
                    f"/SERVER:{hostname}",
                    f"/TIME:{config.POPUP_DURATION_SECONDS}",
                    short_msg
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if result.returncode == 0:
                    logger.debug(f"msg.exe alert sent to {hostname}")
                else:
                    logger.warning(
                        f"msg.exe to {hostname} returned {result.returncode}: "
                        f"{result.stderr.strip()}"
                    )
            except subprocess.TimeoutExpired:
                logger.warning(f"msg.exe to {hostname} timed out.")
            except FileNotFoundError:
                logger.warning("msg.exe not found. May be Windows Home edition.")
            except Exception as e:
                logger.error(f"Failed to send msg.exe alert to {hostname}: {e}")

    def _show_popup(self, attack_type, alert_text):
        """Show a desktop popup using ctypes MessageBoxW."""
        try:
            import ctypes
            flags = 0x00000000 | 0x00000010 | 0x00001000 | 0x00040000
            title = f"\u26a0 {config.APP_NAME} - {attack_type} DETECTED"
            ctypes.windll.user32.MessageBoxW(0, alert_text, title, flags)
        except Exception as e:
            logger.debug(f"Desktop popup failed: {e}")

    def _send_email(self, attack_type, alert_text, severity):
        """Send alert email using smtplib."""
        try:
            msg = MIMEMultipart()
            msg['From'] = config.EMAIL_FROM
            msg['To'] = ", ".join(config.EMAIL_TO)
            msg['Subject'] = f"{config.EMAIL_SUBJECT_PREFIX} {attack_type} - {severity}"

            html_body = (
                f"<html><body style='font-family:Consolas,monospace;"
                f"background:#1a1a1a;color:#ff4444;padding:20px;'>"
                f"<h2 style='color:#ff0000;'>\u26a0 {config.APP_NAME} - ATTACK DETECTED</h2>"
                f"<pre style='color:#fff;background:#2a2a2a;padding:15px;"
                f"border-left:4px solid #ff0000;'>{alert_text}</pre>"
                f"<hr style='border-color:#ff0000;'>"
                f"<p style='color:#888;'>Automated alert from {config.APP_NAME} "
                f"v{config.APP_VERSION}  -  Red Parrot Accounting Ltd. "
                f"Investigate under GDPR/ICO obligations.</p></body></html>"
            )
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))
            msg.attach(MIMEText(alert_text, 'plain', 'utf-8'))

            # FIX: use smtplib.SMTP as a context manager so the connection is
            # always closed — even if login() or sendmail() raises an exception.
            # Previously, any exception between SMTP() and server.quit() would
            # leave the TCP connection open indefinitely.
            with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT, timeout=30) as server:
                server.ehlo()
                if config.SMTP_USE_TLS:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()

                if config.SMTP_USERNAME and config.SMTP_PASSWORD:
                    server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)

                server.sendmail(config.EMAIL_FROM, config.EMAIL_TO, msg.as_string())

            logger.debug(f"Alert email sent to {config.EMAIL_TO}")

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP auth failed: {e}")
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
        except ConnectionRefusedError:
            logger.error(f"SMTP connection refused: {config.SMTP_SERVER}:{config.SMTP_PORT}")
        except Exception as e:
            logger.error(f"Failed to send email: {e}")

    def get_alert_count(self):
        """Return total number of alerts dispatched (not suppressed by cooldown)."""
        with self._lock:
            return self._alerts_triggered

    def clear_cooldowns(self):
        """Reset all cooldown timers."""
        with self._lock:
            self._cooldown_tracker.clear()
            logger.info("All alert cooldowns cleared.")
