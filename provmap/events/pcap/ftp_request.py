import os
from dataclasses import dataclass


from provmap.events.event import Event
from provmap.graph.edge import Edge
from provmap.graph.entities.file import File
from provmap.graph.entities.socket import Socket
from provmap.graph.graph import Graph


@dataclass
class FtpRequest(Event):
    timestamp: float
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    ftp_command: str
    ftp_arg: str

    def to_graph(self) -> Graph:
        graph = Graph()

        client_socket = Socket(socket_ip=self.client_ip, socket_port=self.client_port)
        server_socket = Socket(socket_ip=self.server_ip, socket_port=self.server_port)

        graph.add_entity(client_socket)
        graph.add_entity(server_socket)

        if self.ftp_command.upper() == "STOR":
            file = File(file_path=os.path.normpath(self.ftp_arg).lower())

            graph.add_entity(file)

            graph.add_edge(
                Edge(
                    source=client_socket,
                    destination=file,
                    relation="ftp_stor",
                    timestamp=self.timestamp,
                )
            )

        return graph
