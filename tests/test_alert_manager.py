# =============================================================================
# GhostSecure 2.1 - Tests: core/alert_manager.py
# =============================================================================

import sys
import os
import time
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
from core.alert_manager import AlertManager


def test_alert_manager_initializes():
    with patch("os.makedirs"):
        am = AlertManager()
    assert am.get_alert_count() == 0


def test_format_alert_contains_fields():
    with patch("os.makedirs"):
        am = AlertManager()
    text = am._format_alert(
        "KERBEROASTING", "2026-01-01 12:00:00", "hacker", "WS01",
        "10.0.0.1", "svc_sql", 4769, "details here", "CRITICAL"
    )
    assert "KERBEROASTING" in text
    assert "hacker" in text
    assert "WS01" in text
    assert "10.0.0.1" in text
    assert "4769" in text
    assert "CRITICAL" in text
    assert "details here" in text


def test_format_alert_no_mojibake():
    with patch("os.makedirs"):
        am = AlertManager()
    text = am._format_alert(
        "TEST", "2026-01-01 12:00:00", "user", "PC",
        "1.2.3.4", "target", 1234, "detail", "HIGH"
    )
    # Ensure no encoding corruption bytes remain in the output
    assert "\xe2\x80\x94" not in text
    assert "\xc3\xa2" not in text


def test_alert_count_increments():
    with patch("os.makedirs"):
        am = AlertManager()

    def noop(*a, **kw):
        pass

    with patch.object(am, "_write_log", noop), \
         patch.object(am, "_send_msg_exe", noop), \
         patch.object(am, "_show_popup", noop), \
         patch.object(am, "_send_email", noop), \
         patch.object(config, "ENABLE_DESKTOP_POPUP", False), \
         patch.object(config, "ENABLE_EMAIL_ALERTS", False):
        am.send_alert(
            attack_type="TEST",
            attacker="hacker",
            source_machine="WS01",
            source_ip="10.0.0.1",
            target="target",
            event_id=1234,
        )

    assert am.get_alert_count() == 1


def test_cooldown_suppresses_duplicate():
    with patch("os.makedirs"):
        am = AlertManager()
    am._cooldown_tracker[("TEST", "hacker", "WS01")] = time.time()

    with patch.object(am, "_write_log") as mock_log:
        am.send_alert(
            attack_type="TEST",
            attacker="hacker",
            source_machine="WS01",
            source_ip="10.0.0.1",
            target="target",
            event_id=1234,
        )
    mock_log.assert_not_called()
    assert am.get_alert_count() == 0


def test_clear_cooldowns():
    with patch("os.makedirs"):
        am = AlertManager()
    am._cooldown_tracker[("A", "B", "C")] = time.time()
    am.clear_cooldowns()
    assert len(am._cooldown_tracker) == 0
