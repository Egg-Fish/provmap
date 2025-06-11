import os
from dataclasses import dataclass

from provmap.events.event import Event
from provmap.graph.edge import Edge
from provmap.graph.graph import Graph
from provmap.graph.entities.process import Process
from provmap.graph.entities.file import File


@dataclass
class FileCreate(Event):
    utc_time: float
    process_guid: str
    process_id: int
    image: str
    target_filename: str
    creation_utc_time: float
    user: str

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

        new_file = File(file_path=self.target_filename)

        graph.add_entity(new_file)

        graph.add_edge(
            Edge(
                source=process,
                destination=new_file,
                relation=(
                    "creates"
                    if self.creation_utc_time == self.utc_time
                    else "writes_to"
                ),
                timestamp=self.utc_time,
            )
        )

        return graph
