import logging


import networkx as nx


from provmap.graph.edge import Edge
from provmap.graph.entities.entity import Entity


logger = logging.getLogger(__name__)


class Graph:
    def __init__(self) -> None:
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()

    def add_entity(self, entity: Entity) -> None:
        logger.debug(f"Adding entity {entity}")
        entity_id = entity.entity_id

        new: Entity = entity

        if entity_id in self.G.nodes:
            old: Entity = self.G.nodes[entity_id]["obj"]
            logger.debug(f"Found existing entity {old}")

            new = old.combine(entity)

        self.G.add_node(entity_id, obj=new)

    @property
    def number_of_entities(self) -> int:
        return self.G.number_of_nodes()

    @property
    def number_of_edges(self) -> int:
        return self.G.number_of_edges()

    def add_edge(self, edge: Edge) -> None:
        source: Entity = edge.source
        destination: Entity = edge.destination
        relation: str = edge.relation
        timestamp: float = edge.timestamp

        if source.entity_id not in self.G.nodes:
            raise ValueError()

        if destination.entity_id not in self.G.nodes:
            raise ValueError()

        # TODO duplicate edges should not overwrite

        self.G.add_edge(
            source.entity_id,
            destination.entity_id,
            relation,
            obj=edge,
            timestamp=timestamp,
        )

    def combine(self, other: "Graph") -> "Graph":
        new = self

        for _, n in other.G.nodes(data=True):
            e: Entity = n["obj"]

            new.add_entity(e)

        for u, v, r, data in other.G.edges(keys=True, data=True):
            edge: Edge = data["obj"]

            new.add_edge(edge)

        return new

    def trace(self, source_id: str) -> "Graph":
        prev_nodes: set = nx.ancestors(self.G, source_id)
        next_nodes: set = nx.descendants(self.G, source_id)

        nodes = prev_nodes.union(next_nodes)
        nodes.add(source_id)

        G = self.G.subgraph(nodes).copy()

        new = Graph()
        new.G = G

        return new

    def to_graphviz(self) -> str:
        res = "digraph{\n\toverlap=false;\n"

        for _, n in self.G.nodes(data=True):
            entity: Entity = n["obj"]

            res += "\t" + entity.to_graphviz() + "\n"

        for _, _, _, e in self.G.edges(keys=True, data=True):
            edge: Edge = e["obj"]

            res += "\t" + edge.to_graphviz() + "\n"

        res += "}"

        return res

    def to_prolog(self) -> str:
        entities = []

        for _, n in self.G.nodes(data=True):
            entity: Entity = n["obj"]

            entities.extend(entity.to_prolog().split("\n"))

        edges = []

        for _, _, _, e in self.G.edges(keys=True, data=True):
            edge: Edge = e["obj"]

            edges.append(edge.to_prolog())

        entities.sort()
        edges.sort()

        return "\n".join(entities + edges)

    def __str__(self) -> str:
        return f"Graph(|V| = {self.number_of_entities}, |E| = {self.number_of_edges})"
