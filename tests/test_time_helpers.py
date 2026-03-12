# =============================================================================
# GhostSecure 2.1 - Tests: utils/time_helpers.py
# =============================================================================

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.time_helpers import (
    now_timestamp,
    now_epoch,
    epoch_to_str,
    seconds_between,
    is_within_window,
    filetime_to_epoch,
)


def test_now_timestamp_format():
    ts = now_timestamp()
    assert len(ts) == 19
    parts = ts.split(" ")
    assert len(parts) == 2
    date_parts = parts[0].split("-")
    assert len(date_parts) == 3
    assert int(date_parts[0]) >= 2024


def test_now_epoch_is_float():
    epoch = now_epoch()
    assert isinstance(epoch, float)
    assert epoch > 1_700_000_000


def test_epoch_to_str_valid():
    result = epoch_to_str(0)
    assert isinstance(result, str)
    assert len(result) > 0


def test_epoch_to_str_invalid():
    assert epoch_to_str(None) == "UNKNOWN"
    assert epoch_to_str("bad") == "UNKNOWN"


def test_epoch_to_str_recent():
    now = time.time()
    result = epoch_to_str(now)
    assert "2025" in result or "2026" in result or "2027" in result


def test_seconds_between():
    assert seconds_between(100.0, 200.0) == 100.0
    assert seconds_between(200.0, 100.0) == 100.0
    assert seconds_between(0, 0) == 0.0


def test_seconds_between_invalid():
    result = seconds_between(None, 100)
    assert result == float('inf')


def test_is_within_window_true():
    recent = time.time() - 10
    assert is_within_window(recent, 60) is True


def test_is_within_window_false():
    old = time.time() - 200
    assert is_within_window(old, 60) is False


def test_is_within_window_invalid():
    assert is_within_window(None, 60) is False


def test_filetime_to_epoch_known():
    # Windows FILETIME for Unix epoch (1970-01-01 00:00:00 UTC)
    filetime_at_unix_epoch = 116444736000000000
    result = filetime_to_epoch(filetime_at_unix_epoch)
    assert abs(result - 0.0) < 0.001


def test_filetime_to_epoch_invalid():
    assert filetime_to_epoch(None) == 0.0
    assert filetime_to_epoch("bad") == 0.0
