import logging
from datetime import datetime


from provmap.graph.entities.entity import Entity


logger = logging.getLogger(__name__)


class Edge:
    def __init__(
        self,
        source: Entity,
        destination: Entity,
        relation: str,
        timestamp: float,
    ) -> None:
        self.source = source
        self.destination = destination
        self.relation = relation
        self.timestamp = timestamp

    def to_graphviz(self) -> str:
        src = self.source.entity_id
        dst = self.destination.entity_id

        dt = datetime.fromtimestamp(self.timestamp)
        label = (
            f"{self.relation} @ {dt.strftime("%H:%M:%S")}.{dt.microsecond // 1000:03d}"
        )

        return f'"{src}" -> "{dst}" [label="{label}", relation="{self.relation}", timestamp={self.timestamp}];'

    def to_prolog(self) -> str:
        src = self.source.entity_id
        dst = self.destination.entity_id

        return f"edge('{src}', '{dst}', {self.relation}, {self.timestamp})."

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Edge):
            return False

        return all(
            [
                self.source == value.source,
                self.destination == value.destination,
                self.relation == value.relation,
                # self.timestamp == value.timestamp, # Intentionally left out
            ]
        )
