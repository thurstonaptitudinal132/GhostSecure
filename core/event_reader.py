# =============================================================================
# GhostSecure 2.1 - Windows Event Log Reader
# Coded by Egyan
# =============================================================================

import logging
import time
import json
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger("GhostSecure2.EventReader")

try:
    import win32evtlog
    import win32con
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    logger.error("pywin32 is not installed. Event log reading will not function.")


class ParsedEvent:
    """Represents a parsed Windows Security Event with extracted fields."""

    def __init__(self):
        self.EventID = 0
        self.TimeCreated = ""
        self.Computer = ""
        self.Channel = ""
        self.AccountName = ""
        self.AccountDomain = ""
        self.SubjectUserName = ""
        self.SubjectDomainName = ""
        self.SubjectUserSid = ""
        self.TargetUserName = ""
        self.TargetDomainName = ""
        self.ServiceName = ""
        self.TicketEncryptionType = ""
        self.TicketOptions = ""
        self.LogonType = ""
        self.AuthenticationPackageName = ""
        self.WorkstationName = ""
        self.IpAddress = ""
        self.IpPort = ""
        self.ObjectType = ""
        self.Properties = ""
        self.AccessMask = ""
        self.PreAuthType = ""
        self.Status = ""
        self.ServiceFileName = ""
        self.ServiceType = ""
        self.PrivilegeList = ""
        self.ProcessName = ""
        self.ObjectName = ""
        self.RawXml = ""
        self.EventData = {}

    def __repr__(self):
        return (
            f"<ParsedEvent ID={self.EventID} Time={self.TimeCreated} "
            f"Account={self.AccountName or self.SubjectUserName}>"
        )


class EventLogReader:
    """
    Reads Windows Security Event Log and yields ParsedEvent objects.
    Tracks last-read position so only new events are processed per cycle.
    """

    def __init__(self):
        self._last_record_id = 0
        self._state_file = config.STATE_FILE
        self._channel = config.EVENT_LOG_CHANNEL
        self._monitored_ids = set(config.MONITORED_EVENT_IDS)
        self._load_state()

    def _load_state(self):
        """Load last processed record ID from state file."""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file, 'r') as f:
                    state = json.load(f)
                    self._last_record_id = state.get("last_record_id", 0)
                    logger.info(f"Loaded state: last_record_id={self._last_record_id}")
            else:
                logger.info("No state file found. Starting fresh.")
                self._last_record_id = 0
        except (json.JSONDecodeError, IOError, OSError) as e:
            logger.warning(f"Failed to load state file: {e}. Starting fresh.")
            self._last_record_id = 0

    def _save_state(self):
        """Persist the last processed record ID to disk."""
        try:
            os.makedirs(os.path.dirname(self._state_file), exist_ok=True)
            with open(self._state_file, 'w') as f:
                json.dump({"last_record_id": self._last_record_id}, f)
        except (IOError, OSError) as e:
            logger.error(f"Failed to save state file: {e}")

    def _parse_event_xml(self, xml_string):
        """Parse raw XML of a Windows Event Log entry into a ParsedEvent."""
        event = ParsedEvent()
        event.RawXml = xml_string

        try:
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            root = ET.fromstring(xml_string)

            # --- System section ---
            system = root.find('e:System', ns)
            if system is not None:
                eid_elem = system.find('e:EventID', ns)
                if eid_elem is not None:
                    event.EventID = int(eid_elem.text or 0)

                time_elem = system.find('e:TimeCreated', ns)
                if time_elem is not None:
                    event.TimeCreated = time_elem.get('SystemTime', '')

                comp_elem = system.find('e:Computer', ns)
                if comp_elem is not None:
                    event.Computer = comp_elem.text or ''

                chan_elem = system.find('e:Channel', ns)
                if chan_elem is not None:
                    event.Channel = chan_elem.text or ''

            # --- EventData section ---
            event_data = root.find('e:EventData', ns)
            if event_data is not None:
                for data_elem in event_data.findall('e:Data', ns):
                    name = data_elem.get('Name', '')
                    value = data_elem.text or ''
                    event.EventData[name] = value

                field_map = {
                    'TargetUserName': 'TargetUserName',
                    'TargetDomainName': 'TargetDomainName',
                    'SubjectUserName': 'SubjectUserName',
                    'SubjectDomainName': 'SubjectDomainName',
                    'SubjectUserSid': 'SubjectUserSid',
                    'ServiceName': 'ServiceName',
                    'TicketEncryptionType': 'TicketEncryptionType',
                    'TicketOptions': 'TicketOptions',
                    'LogonType': 'LogonType',
                    'AuthenticationPackageName': 'AuthenticationPackageName',
                    'LmPackageName': 'AuthenticationPackageName',
                    'WorkstationName': 'WorkstationName',
                    'IpAddress': 'IpAddress',
                    'IpPort': 'IpPort',
                    'ObjectType': 'ObjectType',
                    'Properties': 'Properties',
                    'AccessMask': 'AccessMask',
                    'PreAuthType': 'PreAuthType',
                    'Status': 'Status',
                    'ServiceFileName': 'ServiceFileName',
                    'ServiceType': 'ServiceType',
                    'PrivilegeList': 'PrivilegeList',
                    'ProcessName': 'ProcessName',
                    'ObjectName': 'ObjectName',
                }
                for xml_name, attr_name in field_map.items():
                    if xml_name in event.EventData:
                        setattr(event, attr_name, event.EventData[xml_name])

                event.AccountName = event.TargetUserName or event.SubjectUserName
                event.AccountDomain = event.TargetDomainName or event.SubjectDomainName

        except ET.ParseError as e:
            logger.error(f"Failed to parse event XML: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing event XML: {e}")

        return event

    def read_new_events(self):
        """Read new events matching monitored IDs. Returns list of ParsedEvent."""
        if not HAS_WIN32:
            logger.error("pywin32 not available  -  cannot read event logs.")
            return []

        events = []
        try:
            id_filters = " or ".join(
                [f"EventID={eid}" for eid in self._monitored_ids]
            )
            # BUG FIX: Include EventRecordID filter so only NEW events are
            # returned each poll cycle, not the same recent 1000 events repeatedly.
            record_filter = (
                f"EventRecordID&gt;{self._last_record_id}"
                if self._last_record_id > 0 else ""
            )
            system_filter = (
                f"({id_filters}) and {record_filter}"
                if record_filter else f"({id_filters})"
            )
            query = (
                f"<QueryList><Query Id='0' Path='{self._channel}'>"
                f"<Select Path='{self._channel}'>"
                f"*[System[{system_filter}]]"
                f"</Select></Query></QueryList>"
            )

            try:
                handle = win32evtlog.EvtQuery(
                    self._channel,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                    query,
                    None
                )
            except Exception as e:
                logger.warning(f"Structured query failed ({e}), using simple query.")
                handle = win32evtlog.EvtQuery(
                    self._channel,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                    "*",
                    None
                )

            events_processed = 0

            while events_processed < config.MAX_EVENTS_PER_CYCLE:
                try:
                    event_batch = win32evtlog.EvtNext(handle, 100, -1, 0)
                    if not event_batch:
                        break
                except StopIteration:
                    break
                except Exception:
                    break

                for evt_handle in event_batch:
                    try:
                        xml_string = win32evtlog.EvtRender(
                            evt_handle,
                            win32evtlog.EvtRenderEventXml
                        )
                        parsed = self._parse_event_xml(xml_string)
                        if parsed.EventID in self._monitored_ids:
                            events.append(parsed)
                        # Track highest record ID seen so next cycle skips these
                        try:
                            record_id = int(parsed.EventData.get("EventRecordID", 0) or 0)
                            if record_id > self._last_record_id:
                                self._last_record_id = record_id
                        except (ValueError, TypeError):
                            pass
                        events_processed += 1
                    except Exception as e:
                        logger.debug(f"Error rendering event: {e}")
                        events_processed += 1
                        continue

                if events_processed >= config.MAX_EVENTS_PER_CYCLE:
                    break

            try:
                win32evtlog.EvtClose(handle)
            except Exception:
                pass

            if events:
                self._save_state()

            logger.debug(f"Read {len(events)} relevant events from Security log.")

        except Exception as e:
            logger.error(f"Failed to read event log: {e}")

        return events

    def read_events_continuous(self, callback, stop_event=None):
        """Continuously poll the event log and call callback(event_list)."""
        logger.info(
            f"Starting continuous event log monitoring on '{self._channel}'."
        )

        while True:
            if stop_event and stop_event.is_set():
                logger.info("Stop event received. Ending monitoring.")
                break

            try:
                new_events = self.read_new_events()
                if new_events:
                    callback(new_events)
            except Exception as e:
                logger.error(f"Error during event log poll cycle: {e}")

            if stop_event:
                stop_event.wait(timeout=config.EVENT_POLL_INTERVAL_SECONDS)
            else:
                time.sleep(config.EVENT_POLL_INTERVAL_SECONDS)
