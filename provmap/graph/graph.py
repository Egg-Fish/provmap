import logging
import pickle


import networkx as nx


from provmap.graph.edge import Edge
from provmap.graph.entities.entity import Entity


logger = logging.getLogger(__name__)


class Graph:
    def __init__(self) -> None:
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()

    @property
    def number_of_entities(self) -> int:
        return self.G.number_of_nodes()

    @property
    def number_of_edges(self) -> int:
        return self.G.number_of_edges()

    def add_entity(self, entity: Entity) -> None:
        logger.debug(f"Adding entity {entity}")
        entity_id = entity.entity_id

        new: Entity = entity

        if entity_id in self.G.nodes:
            old: Entity = self.G.nodes[entity_id]["obj"]
            logger.debug(f"Found existing entity {old}")

            new = old.combine(entity)

        self.G.add_node(entity_id, obj=new)

    def get_entity(self, entity_id: str) -> Entity:
        return self.G.nodes[entity_id]["obj"]

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

    def subgraph(self, entities: list[Entity]) -> "Graph":
        G = self.G.subgraph([e.entity_id for e in entities]).copy()

        new = Graph()
        new.G = G

        return new

    def trace(self, source_id: str) -> "Graph":
        prev_nodes: set = nx.ancestors(self.G, source_id)
        next_nodes: set = nx.descendants(self.G, source_id)

        nodes = prev_nodes.union(next_nodes)
        nodes.add(source_id)

        new = self.subgraph([self.get_entity(e) for e in nodes])

        return new

    def get_roots(self) -> list[str]:
        roots = [
            node
            for node in self.G.nodes()
            if self.G.in_degree(node) == 0 and self.G.out_degree(node) > 0
        ]

        return roots

    def get_leaves(self) -> list[str]:
        terminals = [
            node
            for node in self.G.nodes()
            if self.G.in_degree(node) > 0 and self.G.out_degree(node) == 0
        ]

        return terminals

    def to_walks(self, label: bool = False) -> list[list[str]]:
        roots = self.get_roots()
        leaves = self.get_leaves()

        walks = []

        for root in roots:
            for leaf in leaves:
                edge_paths = nx.all_simple_edge_paths(self.G, root, leaf)

                for path in edge_paths:
                    walk = []
                    for tpl in path:
                        source = tpl[0]
                        relation = tpl[2]

                        if label:
                            source = self.G.nodes[source]["obj"].label

                        walk.extend([source, relation])

                    walk.append(leaf if not label else self.G.nodes[leaf]["obj"].label)
                    walks.append(walk)

        return walks

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

    def to_triples(
        self,
        include_timestamp=True,
    ) -> list[tuple[str, str, str] | tuple[str, str, str, float]]:
        triples = []

        for h, t, r, edge in self.G.edges(keys=True, data=True):
            if include_timestamp:
                triple = (h, r, t, edge["timestamp"])

            else:
                triple = (h, r, t)

            triples.append(triple)

        return triples

    def to_pickle(self) -> bytes:
        return pickle.dumps(self.G)

    @staticmethod
    def from_pickle(pkl: bytes) -> "Graph":
        graph = Graph()

        graph.G = pickle.loads(pkl)

        return graph

    def __str__(self) -> str:
        return f"Graph(|V| = {self.number_of_entities}, |E| = {self.number_of_edges})"
