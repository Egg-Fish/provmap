from dataclasses import dataclass

from provmap.events.event import Event
from provmap.graph.edge import Edge
from provmap.graph.entities.file import File
from provmap.graph.entities.socket import Socket
from provmap.graph.graph import Graph
from provmap.graph.entities.http_transaction import HttpTransaction as TX


@dataclass
class HttpTransaction(Event):
    request_timestamp: float
    response_timestamp: float
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    request_uri: str
    request_method: str
    response_code: int

    def to_graph(self) -> Graph:
        graph = Graph()

        client_socket = Socket(socket_ip=self.client_ip, socket_port=self.client_port)
        server_socket = Socket(socket_ip=self.server_ip, socket_port=self.server_port)

        graph.add_entity(client_socket)
        graph.add_entity(server_socket)

        tx = TX(self.request_uri, self.request_method, self.response_code)

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

        return graph
