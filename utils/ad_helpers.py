# =============================================================================
# GhostSecure 2.1 - Active Directory Helper Functions
# Coded by Egyan
# =============================================================================
# BUG FIX: LDAP Windows auth now uses SASL/GSSAPI instead of NTLM with an
# empty password, which never bound successfully. Falls back gracefully to
# the static DC list if GSSAPI is unavailable.
# =============================================================================

import logging
import sys
import os
import time
import socket

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger("GhostSecure2.ADHelpers")

_dc_cache = None
_dc_cache_time = 0
DC_CACHE_TTL = 300


def _make_ldap_connection(server, AUTO_BIND_NO_TLS):
    """Create an LDAP connection using Windows auth (GSSAPI) or bind credentials."""
    if config.LDAP_USE_WINDOWS_AUTH:
        try:
            from ldap3 import SASL, GSSAPI, Connection
            return Connection(
                server,
                authentication=SASL,
                sasl_mechanism=GSSAPI,
                auto_bind=AUTO_BIND_NO_TLS,
                raise_exceptions=False
            )
        except Exception as e:
            logger.warning(f"GSSAPI Windows auth failed: {e}. LDAP DC discovery unavailable.")
            return None
    else:
        from ldap3 import Connection
        return Connection(
            server,
            user=config.LDAP_BIND_USER,
            password=config.LDAP_BIND_PASSWORD,
            auto_bind=AUTO_BIND_NO_TLS,
            raise_exceptions=False
        )


def get_domain_controllers():
    """
    Return a list of domain controller account names.
    Uses static config first, then queries AD via LDAP. Cached for DC_CACHE_TTL seconds.
    """
    global _dc_cache, _dc_cache_time

    if _dc_cache is not None and (time.time() - _dc_cache_time) < DC_CACHE_TTL:
        return _dc_cache

    dc_list = list(config.KNOWN_DOMAIN_CONTROLLERS)

    try:
        from ldap3 import Server, SUBTREE, AUTO_BIND_NO_TLS

        server = Server(config.LDAP_SERVER, get_info=None)
        conn = _make_ldap_connection(server, AUTO_BIND_NO_TLS)

        if conn and conn.bound:
            search_filter = (
                "(&(objectCategory=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            )
            conn.search(
                search_base=config.LDAP_BASE_DN,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["cn", "sAMAccountName"]
            )
            for entry in conn.entries:
                cn = str(entry.cn) if hasattr(entry, 'cn') else None
                sam = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else None
                if cn and cn not in dc_list:
                    dc_list.append(cn)
                if sam:
                    clean_sam = sam.rstrip("$")
                    if clean_sam not in dc_list:
                        dc_list.append(clean_sam)
            conn.unbind()
            logger.debug(f"Queried AD for DCs. Found: {dc_list}")
        else:
            logger.warning("Could not bind to LDAP for DC enumeration. Using static list.")

    except ImportError:
        logger.warning("ldap3 not installed. Using static DC list.")
    except Exception as e:
        logger.warning(f"Failed to query AD for DCs: {e}. Using static list.")

    _dc_cache = dc_list
    _dc_cache_time = time.time()
    return dc_list


def is_machine_account(account_name):
    """Check if an account name is a machine/computer account (ends with $)."""
    if not account_name:
        return False
    return account_name.strip().endswith("$")


def get_account_info(account_name):
    """Query AD for basic info about an account. Returns dict or None."""
    try:
        from ldap3 import Server, SUBTREE, AUTO_BIND_NO_TLS

        server = Server(config.LDAP_SERVER, get_info=None)
        conn = _make_ldap_connection(server, AUTO_BIND_NO_TLS)

        if conn and conn.bound:
            search_filter = f"(sAMAccountName={account_name})"
            conn.search(
                search_base=config.LDAP_BASE_DN,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["displayName", "mail", "department", "description"]
            )
            if conn.entries:
                entry = conn.entries[0]
                result = {
                    "displayName": str(entry.displayName) if hasattr(entry, 'displayName') else "N/A",
                    "mail": str(entry.mail) if hasattr(entry, 'mail') else "N/A",
                    "department": str(entry.department) if hasattr(entry, 'department') else "N/A",
                    "description": str(entry.description) if hasattr(entry, 'description') else "N/A",
                }
                conn.unbind()
                return result
            conn.unbind()

    except ImportError:
        logger.debug("ldap3 not installed - cannot query account info.")
    except Exception as e:
        logger.debug(f"Failed to get account info for {account_name}: {e}")

    return None


def resolve_ip_to_hostname(ip_address):
    """Resolve IP to hostname via reverse DNS. Returns hostname or original IP."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ip_address
