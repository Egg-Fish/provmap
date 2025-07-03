import dateutil.parser
import dateutil.tz

from Evtx.Evtx import Evtx
import xmltodict

from provmap.events.event import Event
from provmap.events import sysmon
from provmap.parsers.parser import Parser


def xml_to_dict(xml_str: str) -> dict:
    event_dict = xmltodict.parse(xml_str)["Event"]

    try:
        event_id = int(event_dict["System"]["EventID"]["#text"])
    except:
        event_id = int(event_dict["System"]["EventID"])

    event_data = {
        d["@Name"]: d.get("#text", "") for d in event_dict["EventData"]["Data"]
    }

    return {
        "EventID": event_id,
        "EventData": event_data,
    }


def evtx_to_dicts(evtx_filepath: str):
    with Evtx(evtx_filepath) as log:
        for record in log.records():
            xml_str = record.xml()

            try:
                yield xml_to_dict(xml_str)

            except Exception as e:
                raise ValueError("Could not parse event")


def lines_to_dicts(lines_filepath: str):
    with open(lines_filepath, "r") as f:
        for xml_str in f:
            try:
                yield xml_to_dict(xml_str)

            except Exception as e:
                raise ValueError("Could not parse event")


def parse_utc_time(utc_time: str) -> float:
    dt = dateutil.parser.parse(utc_time)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=dateutil.tz.UTC)
    else:
        dt = dt.astimezone(dateutil.tz.UTC)
    return dt.timestamp()


def parse_hashes(hash_str: str) -> dict[str, str]:
    return dict(kv.split("=", 1) for kv in hash_str.split(",") if "=" in kv)


def parse_process_create(event_dict: dict) -> sysmon.ProcessCreate:
    ed = event_dict["EventData"]
    return sysmon.ProcessCreate(
        utc_time=parse_utc_time(ed["UtcTime"]),
        process_guid=ed["ProcessGuid"],
        process_id=int(ed["ProcessId"]),
        image=ed["Image"].lower(),
        file_version=ed.get("FileVersion", ""),
        description=ed.get("Description", ""),
        product=ed.get("Product", ""),
        company=ed.get("Company", ""),
        original_file_name=ed.get("OriginalFileName", "").lower(),
        command_line=ed["CommandLine"],
        current_directory=ed["CurrentDirectory"].lower(),
        user=ed["User"],
        logon_guid=ed["LogonGuid"],
        logon_id=ed["LogonId"],
        terminal_session_id=int(ed["TerminalSessionId"]),
        integrity_level=ed.get("IntegrityLevel", ""),
        hashes=parse_hashes(ed["Hashes"]),
        parent_process_guid=ed["ParentProcessGuid"],
        parent_process_id=int(ed["ParentProcessId"]),
        parent_image=ed["ParentImage"].lower(),
        parent_command_line=ed["ParentCommandLine"],
        parent_user=ed.get("ParentUser", ""),
    )


def parse_network_connection(event_dict: dict) -> sysmon.NetworkConnection:
    ed = event_dict["EventData"]

    return sysmon.NetworkConnection(
        utc_time=parse_utc_time(ed["UtcTime"]),
        process_guid=ed["ProcessGuid"],
        process_id=int(ed["ProcessId"]),
        image=ed["Image"].lower(),
        user=ed.get("User", ""),
        protocol=ed["Protocol"],
        initiated=ed["Initiated"].lower() == "true",
        source_is_ipv6=ed["SourceIsIpv6"].lower() == "true",
        source_ip=ed["SourceIp"],
        source_hostname=ed["SourceHostname"],
        source_port=int(ed["SourcePort"]),
        source_port_name=ed["SourcePortName"],
        destination_is_ipv6=ed["DestinationIsIpv6"].lower() == "true",
        destination_ip=ed["DestinationIp"],
        destination_hostname=ed["DestinationHostname"],
        destination_port=int(ed["DestinationPort"]),
        destination_port_name=ed["DestinationPortName"],
    )


def parse_image_loaded(event_dict: dict) -> sysmon.ImageLoaded:
    ed = event_dict["EventData"]

    return sysmon.ImageLoaded(
        utc_time=parse_utc_time(ed["UtcTime"]),
        process_guid=ed["ProcessGuid"],
        process_id=int(ed["ProcessId"]),
        image=ed["Image"].lower(),
        image_loaded=ed["ImageLoaded"].lower(),
    )


def parse_file_create(event_dict: dict) -> sysmon.FileCreate:
    ed = event_dict["EventData"]

    return sysmon.FileCreate(
        utc_time=parse_utc_time(ed["UtcTime"]),
        process_guid=ed["ProcessGuid"],
        process_id=int(ed["ProcessId"]),
        image=ed["Image"].lower(),
        target_filename=ed["TargetFilename"].lower(),
        creation_utc_time=parse_utc_time(ed["CreationUtcTime"]),
        user=ed.get("User", ""),
    )


class SysmonParser(Parser):
    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self._parsed: bool = False
        self._events: list[Event] = []

    def parse(self) -> list[Event]:
        if self._parsed:
            return self._events

        dict_func = evtx_to_dicts if self.filepath.endswith(".evtx") else lines_to_dicts

        event_dicts = dict_func(self.filepath)

        for event_dict in event_dicts:
            try:
                event_id = event_dict["EventID"]

                if event_id == 1:
                    event = parse_process_create(event_dict)
                    self._events.append(event)

                elif event_id == 3:
                    event = parse_network_connection(event_dict)
                    self._events.append(event)

                # elif event_id == 7:
                #     event = parse_image_loaded(event_dict)
                #     self._events.append(event)

                elif event_id == 11:
                    event = parse_file_create(event_dict)
                    self._events.append(event)

            except:
                pass

        self._parsed = True
        return self._events
