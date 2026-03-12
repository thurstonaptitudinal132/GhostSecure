# =============================================================================
# GhostSecure 2.1 - Tests: All Detectors
# =============================================================================

import sys
import os
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.event_reader import ParsedEvent
from detectors import (
    kerberoasting,
    pass_the_hash,
    dcsync,
    golden_ticket,
    ldap_recon,
    asrep_roasting,
    skeleton_key,
)


def _make_event(**kwargs):
    """Build a ParsedEvent with defaults overridden by kwargs."""
    e = ParsedEvent()
    for k, v in kwargs.items():
        setattr(e, k, v)
    return e


def _mock_alert_manager():
    am = MagicMock()
    am.send_alert = MagicMock()
    return am


# ---------------------------------------------------------------------------
# Kerberoasting
# ---------------------------------------------------------------------------

class TestKerberoasting:
    def test_detects_rc4_ticket(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4769,
            ServiceName="svc_sql",
            TicketEncryptionType="0x17",
            TargetUserName="jsmith",
            TargetDomainName="REDPARROT",
            IpAddress="192.168.1.50",
            WorkstationName="WS01",
        )
        kerberoasting.detect(event, am)
        am.send_alert.assert_called_once()
        call_kwargs = am.send_alert.call_args[1]
        assert call_kwargs["attack_type"] == "KERBEROASTING"
        assert call_kwargs["severity"] == "CRITICAL"

    def test_ignores_machine_account(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4769,
            ServiceName="DC01$",
            TicketEncryptionType="0x17",
            TargetUserName="jsmith",
        )
        kerberoasting.detect(event, am)
        am.send_alert.assert_not_called()

    def test_ignores_krbtgt(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4769,
            ServiceName="krbtgt",
            TicketEncryptionType="0x17",
            TargetUserName="jsmith",
        )
        kerberoasting.detect(event, am)
        am.send_alert.assert_not_called()

    def test_ignores_aes_ticket(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4769,
            ServiceName="svc_sql",
            TicketEncryptionType="0x12",
            TargetUserName="jsmith",
        )
        kerberoasting.detect(event, am)
        am.send_alert.assert_not_called()

    def test_ignores_wrong_event_id(self):
        am = _mock_alert_manager()
        event = _make_event(EventID=4624)
        kerberoasting.detect(event, am)
        am.send_alert.assert_not_called()

    def test_handles_missing_fields_gracefully(self):
        am = _mock_alert_manager()
        event = _make_event(EventID=4769)
        # Should not raise; missing ServiceName/EncType means early return
        kerberoasting.detect(event, am)
        am.send_alert.assert_not_called()


# ---------------------------------------------------------------------------
# Pass-the-Hash
# ---------------------------------------------------------------------------

class TestPassTheHash:
    def test_detects_ntlm_network_logon(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4624,
            LogonType="3",
            AuthenticationPackageName="NTLM",
            TargetUserName="jsmith",
            TargetDomainName="REDPARROT",
            WorkstationName="WS01",
            IpAddress="192.168.1.50",
            Computer="DC01",
        )
        # No prior interactive logon for jsmith — should alert
        pass_the_hash.detect(event, am)
        am.send_alert.assert_called_once()
        assert am.send_alert.call_args[1]["attack_type"] == "PASS-THE-HASH"

    def test_ignores_system_accounts(self):
        am = _mock_alert_manager()
        for name in ("SYSTEM", "ANONYMOUS LOGON", "-", ""):
            event = _make_event(
                EventID=4624,
                LogonType="3",
                AuthenticationPackageName="NTLM",
                TargetUserName=name,
            )
            pass_the_hash.detect(event, am)
        am.send_alert.assert_not_called()

    def test_ignores_machine_accounts(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4624,
            LogonType="3",
            AuthenticationPackageName="NTLM",
            TargetUserName="WORKSTATION$",
        )
        pass_the_hash.detect(event, am)
        am.send_alert.assert_not_called()

    def test_interactive_logon_suppresses_alert(self):
        am = _mock_alert_manager()
        # First: record interactive logon
        interactive = _make_event(
            EventID=4624,
            LogonType="2",
            TargetUserName="alice",
            TargetDomainName="REDPARROT",
            WorkstationName="WS02",
            IpAddress="10.0.0.1",
        )
        pass_the_hash.detect(interactive, am)
        am.send_alert.assert_not_called()

        # Then: network logon with NTLM — should be suppressed
        network = _make_event(
            EventID=4624,
            LogonType="3",
            AuthenticationPackageName="NTLM",
            TargetUserName="alice",
            TargetDomainName="REDPARROT",
            WorkstationName="WS02",
            IpAddress="10.0.0.1",
            Computer="DC01",
        )
        pass_the_hash.detect(network, am)
        am.send_alert.assert_not_called()

    def test_ignores_kerberos_auth(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4624,
            LogonType="3",
            AuthenticationPackageName="Kerberos",
            TargetUserName="jsmith",
        )
        pass_the_hash.detect(event, am)
        am.send_alert.assert_not_called()


# ---------------------------------------------------------------------------
# DCSync
# ---------------------------------------------------------------------------

class TestDCSync:
    def test_detects_replication_guid(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4662,
            SubjectUserName="hacker",
            SubjectDomainName="REDPARROT",
            Properties="{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
            AccessMask="0x100",
            ObjectType="domainDNS",
            IpAddress="10.0.0.5",
            Computer="DC01",
        )
        with patch("utils.ad_helpers.get_domain_controllers", return_value=["DC01", "DC02"]):
            dcsync.detect(event, am)
        am.send_alert.assert_called_once()
        assert am.send_alert.call_args[1]["attack_type"] == "DCSYNC ATTACK"

    def test_ignores_known_dc(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4662,
            SubjectUserName="DC01",
            SubjectDomainName="REDPARROT",
            Properties="{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
        )
        with patch("utils.ad_helpers.get_domain_controllers", return_value=["DC01", "DC02"]):
            dcsync.detect(event, am)
        am.send_alert.assert_not_called()

    def test_ignores_no_replication_guid(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4662,
            SubjectUserName="hacker",
            Properties="{some-other-guid}",
        )
        with patch("utils.ad_helpers.get_domain_controllers", return_value=["DC01"]):
            dcsync.detect(event, am)
        am.send_alert.assert_not_called()

    def test_critical_guid_raises_severity(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4662,
            SubjectUserName="hacker",
            SubjectDomainName="REDPARROT",
            # This is DS-Replication-Get-Changes-All (the critical one)
            Properties="{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
            AccessMask="0x100",
            ObjectType="domainDNS",
            IpAddress="10.0.0.5",
            Computer="DC01",
        )
        with patch("utils.ad_helpers.get_domain_controllers", return_value=["DC01"]):
            dcsync.detect(event, am)
        am.send_alert.assert_called_once()
        assert am.send_alert.call_args[1]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# AS-REP Roasting
# ---------------------------------------------------------------------------

class TestASREPRoasting:
    def test_detects_no_preauth(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4768,
            TargetUserName="victim",
            TargetDomainName="REDPARROT",
            PreAuthType="0x0",
            TicketEncryptionType="0x17",
            IpAddress="192.168.1.10",
            WorkstationName="ATTACKER",
        )
        asrep_roasting.detect(event, am)
        am.send_alert.assert_called_once()
        assert am.send_alert.call_args[1]["attack_type"] == "AS-REP ROASTING"

    def test_ignores_preauth_required(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4768,
            TargetUserName="victim",
            PreAuthType="0x2",
        )
        asrep_roasting.detect(event, am)
        am.send_alert.assert_not_called()

    def test_ignores_machine_account(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4768,
            TargetUserName="WORKSTATION$",
            PreAuthType="0x0",
        )
        asrep_roasting.detect(event, am)
        am.send_alert.assert_not_called()


# ---------------------------------------------------------------------------
# Skeleton Key
# ---------------------------------------------------------------------------

class TestSkeletonKey:
    def test_detects_mimidrv_service(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=7045,
            ServiceName="mimidrv",
            ServiceFileName="C:\\Windows\\Temp\\mimidrv.sys",
            SubjectUserName="attacker",
            SubjectDomainName="REDPARROT",
            Computer="DC01",
            IpAddress="10.0.0.1",
        )
        skeleton_key.detect(event, am)
        am.send_alert.assert_called_once()
        assert am.send_alert.call_args[1]["attack_type"] == "SKELETON KEY"

    def test_detects_audit_log_cleared(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=1102,
            SubjectUserName="hacker",
            SubjectDomainName="REDPARROT",
            Computer="DC01",
            IpAddress="10.0.0.5",
        )
        skeleton_key.detect(event, am)
        am.send_alert.assert_called_once()
        assert am.send_alert.call_args[1]["attack_type"] == "AUDIT LOG CLEARED"

    def test_audit_log_suppressed_for_excluded_account(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=1102,
            SubjectUserName="svc_backup",
            SubjectDomainName="REDPARROT",
            Computer="DC01",
        )
        import config
        original = config.AUDIT_LOG_CLEAR_EXCLUDED_ACCOUNTS
        config.AUDIT_LOG_CLEAR_EXCLUDED_ACCOUNTS = ["svc_backup"]
        try:
            skeleton_key.detect(event, am)
        finally:
            config.AUDIT_LOG_CLEAR_EXCLUDED_ACCOUNTS = original
        am.send_alert.assert_not_called()

    def test_privilege_use_sedebuglprivilege(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4673,
            SubjectUserName="jsmith",
            SubjectDomainName="REDPARROT",
            PrivilegeList="SeDebugPrivilege",
            ProcessName="C:\\Windows\\mimikatz.exe",
            Computer="DC01",
            IpAddress="10.0.0.2",
        )
        skeleton_key.detect(event, am)
        am.send_alert.assert_called_once()
        assert am.send_alert.call_args[1]["attack_type"] == "SKELETON KEY"

    def test_ignores_system_privilege_use(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4673,
            SubjectUserName="SYSTEM",
            PrivilegeList="SeDebugPrivilege",
            ProcessName="services.exe",
        )
        skeleton_key.detect(event, am)
        am.send_alert.assert_not_called()


# ---------------------------------------------------------------------------
# Golden Ticket
# ---------------------------------------------------------------------------

class TestGoldenTicket:
    def test_detects_rc4_tgt(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4768,
            TargetUserName="jsmith",
            TargetDomainName="REDPARROT",
            TicketEncryptionType="0x17",
            TicketOptions="0x40810010",
            IpAddress="10.0.0.1",
            WorkstationName="WS01",
            Status="0x0",
        )
        golden_ticket.detect(event, am)
        am.send_alert.assert_called_once()
        assert am.send_alert.call_args[1]["attack_type"] == "GOLDEN TICKET"

    def test_ignores_aes_tgt(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4768,
            TargetUserName="jsmith",
            TicketEncryptionType="0x12",
            Status="0x0",
            TicketOptions="0x40810010",
        )
        golden_ticket.detect(event, am)
        am.send_alert.assert_not_called()

    def test_ignores_machine_accounts(self):
        am = _mock_alert_manager()
        event = _make_event(
            EventID=4768,
            TargetUserName="DC01$",
            TicketEncryptionType="0x17",
        )
        golden_ticket.detect(event, am)
        am.send_alert.assert_not_called()


# ---------------------------------------------------------------------------
# LDAP Recon
# ---------------------------------------------------------------------------

class TestLDAPRecon:
    def test_no_alert_below_threshold(self):
        am = _mock_alert_manager()
        import config
        original = config.LDAP_RECON_THRESHOLD
        config.LDAP_RECON_THRESHOLD = 10
        try:
            for _ in range(5):
                event = _make_event(
                    EventID=4662,
                    IpAddress="10.0.0.200",
                    SubjectUserName="scanner",
                    SubjectDomainName="REDPARROT",
                )
                ldap_recon.detect(event, am)
        finally:
            config.LDAP_RECON_THRESHOLD = original
        am.send_alert.assert_not_called()

    def test_ignores_wrong_event_id(self):
        am = _mock_alert_manager()
        event = _make_event(EventID=4624, IpAddress="10.0.0.100")
        ldap_recon.detect(event, am)
        am.send_alert.assert_not_called()

    def test_ignores_localhost(self):
        am = _mock_alert_manager()
        import config
        original = config.LDAP_RECON_THRESHOLD
        config.LDAP_RECON_THRESHOLD = 1
        try:
            event = _make_event(
                EventID=4662,
                IpAddress="127.0.0.1",
                SubjectUserName="",
            )
            ldap_recon.detect(event, am)
        finally:
            config.LDAP_RECON_THRESHOLD = original
        am.send_alert.assert_not_called()
