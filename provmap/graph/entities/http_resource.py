from hashlib import sha256

from provmap.graph.entities.entity import Entity


class HttpResource(Entity):
    def __init__(self, uri: str, entity_id: str | None = None) -> None:
        self.uri = uri

        entity_id = entity_id if entity_id else self.generate_entity_id()
        super().__init__(entity_id)

    def generate_entity_id(self) -> str:
        return "http_" + sha256(self.uri.encode()).hexdigest()

    def to_graphviz(self) -> str:
        attributes = ", ".join(
            [
                f'label="{self.uri}"',
                f'http_resource_uri="{self.uri}"',
            ]
        )

        return " ".join(
            [
                f'"{self.entity_id}"',
                f"[{attributes}]",
                ";",
            ]
        )

    def to_prolog(self) -> str:
        return "\n".join(
            [
                f"http_resource('{self.entity_id}').",
                f"http_resource_uri('{self.entity_id}', '{self.uri}').",
            ]
        )
