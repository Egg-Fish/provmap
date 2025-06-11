import logging


logger = logging.getLogger(__name__)


class Entity:
    def __init__(self, entity_id: str) -> None:
        self.entity_id = entity_id

    def generate_entity_id(self) -> str:
        raise NotImplementedError()

    def combine(self, other: "Entity") -> "Entity":
        if self.entity_id != other.entity_id:
            raise ValueError()

        logger.debug("Default combine operation returning self")
        return self

    def to_graphviz(self) -> str:
        attributes = ", ".join(
            [
                f'label="{self.entity_id}"',
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
                f"entity('{self.entity_id}').",
            ]
        )

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Entity):
            return False

        return self.entity_id == value.entity_id
