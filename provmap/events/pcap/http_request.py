from dataclasses import dataclass

from provmap.events.event import Event
from provmap.graph.edge import Edge
from provmap.graph.entities.http_resource import HttpResource
from provmap.graph.entities.socket import Socket
from provmap.graph.graph import Graph


@dataclass
class HttpRequest(Event):
    timestamp: float
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    request_uri: str
    request_method: str

    def to_graph(self) -> Graph:
        graph = Graph()

        client_socket = Socket(socket_ip=self.client_ip, socket_port=self.client_port)
        server_socket = Socket(socket_ip=self.server_ip, socket_port=self.server_port)

        graph.add_entity(client_socket)
        graph.add_entity(server_socket)

        http_resource = HttpResource(uri=self.request_uri)

        relation = f"http_{self.request_method}".lower()

        graph.add_entity(http_resource)
        graph.add_edge(
            Edge(
                source=client_socket,
                destination=http_resource,
                relation=relation,
                timestamp=self.timestamp,
            )
        )

        return graph
