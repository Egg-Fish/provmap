import logging


from provmap.graph.entities.entity import Entity


logger = logging.getLogger(__name__)


class Process(Entity):
    def __init__(
        self,
        process_id: int,
        process_name: str,
        process_cmd: str = "",
        entity_id: str | None = None,
    ) -> None:
        self.process_id = process_id
        self.process_name = process_name
        self.process_cmd = process_cmd

        entity_id = entity_id if entity_id else self.generate_entity_id()
        super().__init__(entity_id)

    @property
    def encoded_process_cmd(self) -> str:
        return self.process_cmd.encode().hex().upper()

    def generate_entity_id(self) -> str:
        return f"{self.process_id}_{self.process_name}"

    def combine(self, other: "Entity") -> "Process":
        if self.entity_id != other.entity_id:
            raise ValueError()

        if not isinstance(other, Process):
            raise ValueError()

        o: "Process" = other

        new = Process(self.process_id, self.process_name, entity_id=self.entity_id)

        # Overwrite cmd if other.cmd is longer
        new.process_cmd = (
            self.process_cmd
            if len(self.process_cmd) > len(o.process_cmd)
            else o.process_cmd
        )

        logger.debug(f"Old: {self}")
        logger.debug(f"New: {new}")
        return new

    def to_graphviz(self) -> str:
        attributes = ", ".join(
            [
                f'label="{self.process_id}:{self.process_name}"',
                f"process_id={self.process_id}",
                f'process_name="{self.process_name}"',
                f'process_cmd="{self.encoded_process_cmd}"',
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
                f"process('{self.entity_id}').",
                f"process_id('{self.entity_id}', {self.process_id}).",
                f"process_name('{self.entity_id}', '{self.process_name}').",
                f"process_cmd('{self.entity_id}', '{self.encoded_process_cmd}').",
            ]
        )
