from hashlib import sha256

from provmap.graph.entities.entity import Entity


class File(Entity):
    def __init__(
        self,
        file_path: str,
        entity_id: str | None = None,
    ) -> None:
        self.file_path = file_path

        entity_id = entity_id if entity_id else self.generate_entity_id()
        super().__init__(entity_id)

    @property
    def escaped_file_path(self) -> str:
        return self.file_path.replace("\\", "\\\\")

    def generate_entity_id(self) -> str:
        return "file_" + sha256(self.file_path.encode()).hexdigest()

    def to_graphviz(self) -> str:
        attributes = ", ".join(
            [
                "shape=note",
                f'label="{self.escaped_file_path}"',
                f'file_path="{self.escaped_file_path}"',
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
                f"file('{self.entity_id}').",
                f"file_path('{self.entity_id}', '{self.escaped_file_path.replace("'", "\\'")}').",
            ]
        )
