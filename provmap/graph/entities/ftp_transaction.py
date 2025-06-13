from uuid import uuid4

from provmap.graph.entities.entity import Entity


class FtpTransaction(Entity):
    def __init__(
        self,
        command: str,
        arg: str | None,
        response_code: int,
        entity_id: str | None = None,
    ) -> None:
        self.command = command
        self.arg = arg
        self.response_code = response_code

        entity_id = entity_id if entity_id else self.generate_entity_id()
        super().__init__(entity_id)

    def generate_entity_id(self) -> str:
        return f"ftp_tx_{uuid4().hex}"

    @property
    def label(self) -> str:
        return f"{self.command} {self.arg}" 

    def to_graphviz(self) -> str:
        attributes = ", ".join(
            [
                "shape=hexagon",
                f'label="{self.label}"',
                f'ftp_transaction_command="{self.command}"',
                f'ftp_transaction_arg="{self.arg}"',
                f"ftp_transaction_response_code={self.response_code}",
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
                f"ftp_transaction('{self.entity_id}').",
                f"ftp_transaction_command('{self.entity_id}', '{self.command}').",
                f"ftp_transaction_arg('{self.entity_id}', '{self.arg}').",
                f"ftp_transaction_response_code('{self.entity_id}', {self.response_code}).",
            ]
        )
