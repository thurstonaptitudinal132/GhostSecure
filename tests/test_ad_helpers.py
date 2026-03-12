# =============================================================================
# GhostSecure 2.1 - Tests: utils/ad_helpers.py
# =============================================================================

import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ad_helpers import is_machine_account, resolve_ip_to_hostname


def test_is_machine_account_true():
    assert is_machine_account("DC01$") is True
    assert is_machine_account("WORKSTATION$") is True
    assert is_machine_account("  SERVER$ ") is True


def test_is_machine_account_false():
    assert is_machine_account("john") is False
    assert is_machine_account("Administrator") is False
    assert is_machine_account("svc_backup") is False


def test_is_machine_account_empty():
    assert is_machine_account("") is False
    assert is_machine_account(None) is False


def test_resolve_ip_to_hostname_success():
    with patch("socket.gethostbyaddr", return_value=("dc01.redparrot.local", [], ["192.168.1.1"])):
        result = resolve_ip_to_hostname("192.168.1.1")
    assert result == "dc01.redparrot.local"


def test_resolve_ip_to_hostname_failure():
    import socket
    with patch("socket.gethostbyaddr", side_effect=socket.herror):
        result = resolve_ip_to_hostname("10.0.0.99")
    assert result == "10.0.0.99"


def test_get_domain_controllers_returns_static_list():
    """When LDAP is unavailable, should fall back to static config list."""
    from utils.ad_helpers import get_domain_controllers
    import config
    with patch("ldap3.Server", side_effect=ImportError):
        dcs = get_domain_controllers()
    for dc in config.KNOWN_DOMAIN_CONTROLLERS:
        assert dc in dcs
