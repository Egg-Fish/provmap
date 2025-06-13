from provmap.graph.entities.entity import Entity


class Socket(Entity):
    def __init__(
        self, socket_ip: str, socket_port: int, entity_id: str | None = None
    ) -> None:
        self.socket_ip = socket_ip
        self.socket_port = socket_port

        entity_id = entity_id if entity_id else self.generate_entity_id()
        super().__init__(entity_id)

    def generate_entity_id(self) -> str:
        return f"{self.socket_ip}_{self.socket_port}".replace(":", ".")

    @property
    def label(self) -> str:
        return f"{self.socket_ip}:{self.socket_port}"

    def to_graphviz(self) -> str:
        attributes = ", ".join(
            [
                "shape=diamond",
                f'label="{self.label}"',
                f'socket_ip="{self.socket_ip}"',
                f"socket_port={self.socket_port}",
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
                f"socket('{self.entity_id}').",
                f"socket_ip('{self.entity_id}', '{self.socket_ip}').",
                f"socket_port('{self.entity_id}', {self.socket_port}).",
            ]
        )
