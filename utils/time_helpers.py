# =============================================================================
# GhostSecure 2.1 - Time Utility Functions
# Coded by Egyan
# =============================================================================

import datetime
import time


def now_timestamp():
    """Return current datetime formatted as a human-readable string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def now_epoch():
    """Return current time as Unix epoch float."""
    return time.time()


def epoch_to_str(epoch_val):
    """Convert a Unix epoch float to a human-readable datetime string."""
    try:
        dt = datetime.datetime.fromtimestamp(epoch_val)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError, TypeError):
        return "UNKNOWN"


def seconds_between(epoch_start, epoch_end):
    """Return the absolute number of seconds between two epoch timestamps."""
    try:
        return abs(epoch_end - epoch_start)
    except TypeError:
        return float('inf')


def is_within_window(epoch_timestamp, window_seconds):
    """Check if epoch_timestamp is within window_seconds of current time."""
    try:
        return (time.time() - epoch_timestamp) <= window_seconds
    except TypeError:
        return False


def filetime_to_epoch(filetime):
    """
    Convert a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    to a Unix epoch timestamp.
    """
    try:
        FILETIME_UNIX_DIFF = 116444736000000000
        return (filetime - FILETIME_UNIX_DIFF) / 10000000.0
    except (TypeError, ValueError):
        return 0.0
