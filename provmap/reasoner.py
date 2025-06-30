import logging
import os
import tempfile


from pyswip import Prolog
from pyswip.utils import resolve_path

"""
Pyswip Monkey Patch

When running on Windows, the pathlib library will automatically revert to using
backslashes regardless of the user input. For example, an input "test/123" will
become the unescaped output "test\123".

Issue: https://github.com/yuce/pyswip/issues/195
"""


def consult_patch(cls, path, *, catcherrors=False, relative_to="") -> None:
    path = resolve_path(path, relative_to)
    next(
        cls.query(
            str(path).replace("\\", "/").join(["consult('", "')"]),
            catcherrors=catcherrors,
        )
    )


Prolog.consult = classmethod(consult_patch)  # type: ignore


from provmap.graph.entities.entity import Entity
from provmap.graph.graph import Graph


logger = logging.getLogger(__name__)


class Reasoner:
    def __init__(self, graph: Graph, schema_filepath: str, rules_filepath: str) -> None:
        logger.info("Initialising reasoner")
        self.graph = graph
        self.prolog = Prolog()

        self.prolog.consult(schema_filepath)
        self.prolog.consult(rules_filepath)

        with tempfile.TemporaryFile(mode="w", suffix=".pl", delete=False) as f:
            f.write(self.graph.to_prolog())
            graph_filepath = f.name

        self.prolog.consult(graph_filepath)

    def get_malicious_entities(self) -> list[Entity]:
        logger.info("Searching for malicious entities")

        query = "malicious(EntityId); contaminated(EntityId)"

        logger.debug(f"Sending query: {query}")

        results = list(self.prolog.query(query))

        entity_ids = set([r["EntityId"] for r in results])
        logger.info(f"Found {len(entity_ids)} malicious entities")

        entities = []

        for entity_id in entity_ids:
            logger.debug(f"malicious('{entity_id}').")

            entity: Entity = self.graph.G.nodes[entity_id]["obj"]

            logger.debug(f"Found entity {entity} with entity id '{entity_id}'")

            entities.append(entity)

        return entities

    def get_tags(self, entity: Entity) -> list[str]:
        logger.debug(f"Searching for tags of entity {entity}")

        query = f"tag('{entity.entity_id}', Tag)"

        logger.debug(f"Sending query: {query}")

        results = list(self.prolog.query(query))

        tags = list(set([r["Tag"] for r in results]))
        logger.debug(f"Found {len(tags)} tags")

        return tags