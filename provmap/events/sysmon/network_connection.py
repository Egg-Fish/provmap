import os
from dataclasses import dataclass


from provmap.events.event import Event
from provmap.graph.edge import Edge
from provmap.graph.entities.file import File
from provmap.graph.entities.process import Process
from provmap.graph.entities.socket import Socket
from provmap.graph.graph import Graph


@dataclass
class NetworkConnection(Event):
    utc_time: float
    process_guid: str
    process_id: int
    image: str
    user: str
    protocol: str
    initiated: bool
    source_is_ipv6: bool
    source_ip: str
    source_hostname: str
    source_port: int
    source_port_name: str
    destination_is_ipv6: bool
    destination_ip: str
    destination_hostname: str
    destination_port: int
    destination_port_name: str

    def to_graph(self) -> Graph:
        graph = Graph()

        process = Process(
            process_id=self.process_id,
            process_name=os.path.basename(self.image),
            entity_id=self.process_guid,
        )
        process_image = File(file_path=self.image)

        graph.add_entity(process)
        graph.add_entity(process_image)
        graph.add_edge(
            Edge(
                source=process,
                destination=process_image,
                relation="loads",
                timestamp=self.utc_time,
            )
        )

        source_socket = Socket(
            socket_ip=self.source_ip,
            socket_port=self.source_port,
        )

        destination_socket = Socket(
            socket_ip=self.destination_ip,
            socket_port=self.destination_port,
        )

        graph.add_entity(source_socket)
        graph.add_entity(destination_socket)

        graph.add_edge(
            Edge(
                source=process,
                destination=source_socket,
                relation="binds_to" if self.initiated else "connects_to",
                timestamp=self.utc_time,
            )
        )

        graph.add_edge(
            Edge(
                source=process,
                destination=destination_socket,
                relation="connects_to" if self.initiated else "binds_to",
                timestamp=self.utc_time,
            )
        )

        return graph
