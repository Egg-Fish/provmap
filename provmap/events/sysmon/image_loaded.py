import os
from pathlib import Path
from dataclasses import dataclass

from provmap.events.event import Event
from provmap.graph.edge import Edge
from provmap.graph.graph import Graph
from provmap.graph.entities.process import Process
from provmap.graph.entities.file import File


@dataclass
class ImageLoaded(Event):
    utc_time: float
    process_guid: str
    process_id: int
    image: str
    image_loaded: str

    def to_graph(self) -> Graph:
        graph = Graph()

        process = Process(
            process_id=self.process_id,
            process_name=Path(self.image).name,
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

        loaded_image = File(file_path=self.image_loaded)

        graph.add_entity(loaded_image)

        graph.add_edge(
            Edge(
                source=process,
                destination=loaded_image,
                relation="loads",
                timestamp=self.utc_time,
            )
        )

        return graph
