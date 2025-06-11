import os
import re
import shlex
from dataclasses import dataclass


from provmap.events.event import Event
from provmap.graph.edge import Edge
from provmap.graph.entities.file import File
from provmap.graph.entities.process import Process
from provmap.graph.graph import Graph


WINDOWS_PATH_REGEX = re.compile(
    r"((?:[A-Za-z]:(?:/|\\)+)(?:(?:[^<>:\"/\\|?*\n]+(?:/|\\)+)+)(?:[^<>:\"/\\|?*\n]+(?:\w+)))"
)


def extract_filepaths(command_line: str) -> list[str]:
    tokens = shlex.split(command_line, posix=False)

    matches = []

    for token in tokens:
        matches.extend(WINDOWS_PATH_REGEX.findall(token))

    return [os.path.normpath(m.lower().strip()) for m in matches]


@dataclass
class ProcessCreate(Event):
    utc_time: float
    process_guid: str
    process_id: int
    image: str
    file_version: str
    description: str
    product: str
    company: str
    original_file_name: str
    command_line: str
    current_directory: str
    user: str
    logon_guid: str
    logon_id: str
    terminal_session_id: int
    integrity_level: str
    hashes: dict[str, str]
    parent_process_guid: str
    parent_process_id: int
    parent_image: str
    parent_command_line: str
    parent_user: str

    def to_graph(self) -> Graph:
        graph = Graph()

        parent_process = Process(
            process_id=self.parent_process_id,
            process_name=os.path.basename(self.parent_image),
            process_cmd=self.parent_command_line,
            entity_id=self.parent_process_guid,
        )

        parent_process_image = File(file_path=self.parent_image)

        child_process = Process(
            process_id=self.process_id,
            process_name=os.path.basename(self.image),
            process_cmd=self.command_line,
            entity_id=self.process_guid,
        )

        child_process_image = File(file_path=self.image)

        graph.add_entity(parent_process)
        graph.add_entity(parent_process_image)
        graph.add_entity(child_process)
        graph.add_entity(child_process_image)

        graph.add_edge(
            Edge(
                source=parent_process,
                destination=parent_process_image,
                relation="loads",
                timestamp=self.utc_time,
            )
        )

        graph.add_edge(
            Edge(
                source=child_process,
                destination=child_process_image,
                relation="loads",
                timestamp=self.utc_time,
            )
        )
        graph.add_edge(
            Edge(
                source=parent_process,
                destination=child_process,
                relation="executes",
                timestamp=self.utc_time,
            )
        )

        process_cmd_filepaths = extract_filepaths(self.command_line)
        parent_cmd_filepaths = extract_filepaths(self.parent_command_line)

        for filepath in process_cmd_filepaths:
            f = File(file_path=filepath)
            if f != child_process_image:
                graph.add_entity(f)
                graph.add_edge(
                    Edge(
                        source=child_process,
                        destination=f,
                        relation="reads",
                        timestamp=self.utc_time,
                    )
                )

        for filepath in parent_cmd_filepaths:
            f = File(file_path=filepath)
            if f != parent_process_image:
                graph.add_entity(f)
                graph.add_edge(
                    Edge(
                        source=parent_process,
                        destination=f,
                        relation="reads",
                        timestamp=self.utc_time,
                    )
                )

        return graph
