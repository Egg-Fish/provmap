from dataclasses import dataclass

from provmap.graph.graph import Graph


@dataclass
class Event:
    def to_graph(self) -> Graph:
        raise NotImplementedError()
