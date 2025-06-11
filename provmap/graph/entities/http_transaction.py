import urllib.parse
from uuid import uuid4

from provmap.graph.entities.entity import Entity


class HttpTransaction(Entity):
    def __init__(
        self,
        uri: str,
        request_method: str,
        response_code: int,
        entity_id: str | None = None,
    ) -> None:
        self.uri = uri
        self.request_method = request_method
        self.response_code = response_code

        entity_id = entity_id if entity_id else self.generate_entity_id()
        super().__init__(entity_id)

    def generate_entity_id(self) -> str:
        return f"http_tx_{uuid4().hex}"

    def to_graphviz(self) -> str:
        url = urllib.parse.urlparse(self.uri)

        attributes = ", ".join(
            [
                "shape=hexagon",
                f'label="{self.request_method} {url.path}"',
                f'http_transaction_uri="{self.uri}"',
                f'http_transaction_request_method="{self.request_method}"',
                f"http_transaction_response_code={self.response_code}",
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
                f"http_transaction('{self.entity_id}').",
                f"http_transaction_uri('{self.entity_id}', '{self.uri}').",
                f"http_transaction_request_method('{self.entity_id}', '{self.request_method}').",
                f"http_transaction_response_code('{self.entity_id}', {self.response_code}).",
            ]
        )
