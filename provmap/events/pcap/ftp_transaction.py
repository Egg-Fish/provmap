import re
import os
from dataclasses import dataclass


from provmap.events.event import Event
from provmap.graph.edge import Edge
from provmap.graph.entities.file import File
from provmap.graph.entities.socket import Socket
from provmap.graph.graph import Graph
from provmap.graph.entities.ftp_transaction import FtpTransaction as TX

WINDOWS_PATH_REGEX = re.compile(
    r"((?:[A-Za-z]:(?:/|\\)+)(?:(?:[^<>:\"/\\|?*\n]+(?:/|\\)+)+)(?:[^<>:\"/\\|?*\n]+(?:\w+)))"
)


@dataclass
class FtpTransaction(Event):
    request_timestamp: float
    response_timestamp: float
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    command: str
    arg: str
    response_code: int

    def to_graph(self) -> Graph:
        graph = Graph()

        if self.command != "STOR":
            return graph

        client_socket = Socket(socket_ip=self.client_ip, socket_port=self.client_port)
        server_socket = Socket(socket_ip=self.server_ip, socket_port=self.server_port)

        graph.add_entity(client_socket)
        graph.add_entity(server_socket)

        tx = TX(self.command, self.arg, self.response_code)

        graph.add_entity(tx)

        graph.add_edge(
            Edge(
                source=client_socket,
                destination=tx,
                relation="requests",
                timestamp=self.request_timestamp,
            )
        )

        graph.add_edge(
            Edge(
                source=server_socket,
                destination=tx,
                relation="responds_to",
                timestamp=self.response_timestamp,
            )
        )

        matches = WINDOWS_PATH_REGEX.findall(self.arg)
        if matches:
            filepath = os.path.normpath(matches[0]).lower()

            file = File(file_path=filepath)

            graph.add_entity(file)

            graph.add_edge(
                Edge(
                    source=tx,
                    destination=file,
                    relation="reads",
                    timestamp=self.request_timestamp,
                )
            )

        return graph
