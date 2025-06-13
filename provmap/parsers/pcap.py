import os


import pyshark


from provmap.events.event import Event
from provmap.events import pcap
from provmap.parsers.parser import Parser


PCAP_DISPLAY_FILTERS = "(http.request or http.response) or ftp"


def pcap_to_packets(pcap_filepath: str):
    cap = pyshark.FileCapture(
        pcap_filepath,
        keep_packets=False,
        display_filter=PCAP_DISPLAY_FILTERS,
        custom_parameters={
            "-j": "ip tcp udp http ftp",
            "-o": "http.desegment_body:FALSE",
        },
    )

    for pkt in cap:
        yield pkt


def parse_ip(pkt) -> tuple[str, str]:
    return (pkt.ip.src, pkt.ip.dst)


def parse_tcp(pkt) -> tuple[int, int]:
    return (pkt.tcp.srcport, pkt.tcp.dstport)


def parse_udp(pkt) -> tuple[int, int]:
    return (pkt.udp.srcport, pkt.udp.dstport)


def parse_l3_l4(pkt) -> tuple[str, int, str, int]:
    source_ip, destination_ip = parse_ip(pkt)
    source_port, destination_port = (
        parse_tcp(pkt) if "TCP" in str(pkt.layers) else parse_udp(pkt)
    )

    return (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
    )


def parse_http(pkt) -> tuple[str | int, str]:
    http = pkt.http

    uri = http.request_full_uri

    top_line: str = getattr(http, "").strip().replace("\\r\\n", "")

    if "request" in http.field_names:
        request_method, _, _ = top_line.split(" ", maxsplit=2)

        return (request_method, uri)

    elif "response" in http.field_names:
        _, response_code, _ = top_line.split(" ", maxsplit=2)
        return (int(response_code), uri)

    else:
        raise ValueError("Could not parse HTTP layer")


def parse_http_transaction(req, res) -> pcap.HttpTransaction:
    request_timestamp = float(req.sniff_timestamp)
    response_timestamp = float(res.sniff_timestamp)

    client_ip, client_port, server_ip, server_port = parse_l3_l4(req)

    request_method, uri = parse_http(req)
    response_code, _ = parse_http(res)

    return pcap.HttpTransaction(
        request_timestamp=request_timestamp,
        response_timestamp=response_timestamp,
        client_ip=client_ip,
        client_port=client_port,
        server_ip=server_ip,
        server_port=server_port,
        request_uri=uri,
        request_method=str(request_method),
        response_code=int(response_code),
    )


def parse_ftp(pkt) -> tuple[str | int, str]:
    ftp = pkt.ftp

    top_line: str = getattr(ftp, "").replace("\\r\\n", "")
    args = top_line.split(" ", maxsplit=1)

    is_request = ftp.request.lower() == "true"

    if len(args) == 1:
        args = top_line.split("-", maxsplit=1)

    if len(args) == 1:
        ftp_arg1 = args[0] if is_request else 0
        ftp_arg2 = "" if is_request else args[0]

    else:
        ftp_arg1, ftp_arg2 = args

    if is_request:
        return (str(ftp_arg1), ftp_arg2)

    else:
        return (int(ftp_arg1 if ftp_arg1 else 0), ftp_arg2)


def parse_ftp_transaction(req, res) -> pcap.FtpTransaction:
    request_timestamp = float(req.sniff_timestamp)
    response_timestamp = float(res.sniff_timestamp)

    client_ip, client_port, server_ip, server_port = parse_l3_l4(req)

    command, arg = parse_ftp(req)
    response_code, _ = parse_ftp(res)

    return pcap.FtpTransaction(
        request_timestamp=request_timestamp,
        response_timestamp=response_timestamp,
        client_ip=client_ip,
        client_port=client_port,
        server_ip=server_ip,
        server_port=server_port,
        command=str(command),
        arg=arg,
        response_code=int(response_code),
    )


def is_request_response(req, res) -> bool:
    (
        req_source_ip,
        req_source_port,
        req_destination_ip,
        req_destination_port,
    ) = parse_l3_l4(req)

    (
        res_source_ip,
        res_source_port,
        res_destination_ip,
        res_destination_port,
    ) = parse_l3_l4(res)

    return all(
        [
            req_source_ip == res_destination_ip,
            req_source_port == res_destination_port,
            req_destination_ip == res_source_ip,
            req_destination_port == res_source_port,
        ]
    )


class PcapParser(Parser):
    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self._parsed: bool = False
        self._events: list[Event] = []
        self._http_packets = []
        self._ftp_packets = []

    def parse(self) -> list[Event]:
        if self._parsed:
            return self._events

        self._http_packets = []
        self._ftp_packets = []

        packets = pcap_to_packets(self.filepath)

        for pkt in packets:
            http = getattr(pkt, "http", None)

            if http:
                self._http_packets.append(pkt)

                continue

            ftp = getattr(pkt, "ftp", None)

            if ftp:
                self._ftp_packets.append(pkt)

                continue

        q = []
        for pkt in self._http_packets:
            x, uri = parse_http(pkt)

            if type(x) == str:
                q.append(pkt)

            elif type(x) == int:
                if len(q) == 0:  # No matching request packet
                    continue

                res = pkt
                req = q.pop(0)

                if not is_request_response(req, res):
                    continue

                _, req_uri = parse_http(req)

                if req_uri == uri:
                    event = parse_http_transaction(req, res)
                    self._events.append(event)

        q = []
        for pkt in self._ftp_packets:
            x, _ = parse_ftp(pkt)

            if type(x) == str:
                q.append(pkt)

            elif type(x) == int:
                if len(q) == 0:  # No matching request packet
                    continue

                res = pkt
                req = q.pop(0)

                if not is_request_response(req, res):
                    continue

                command, arg = parse_ftp(req)
                response_code, _ = parse_ftp(res)

                if response_code == 0:
                    continue

                if arg == "":
                    continue

                event = parse_ftp_transaction(req, res)
                self._events.append(event)

        self._parsed = True
        return self._events
