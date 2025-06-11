import logging
import os


from provmap.events.event import Event
from provmap.graph.graph import Graph
from provmap.parsers import SysmonParser
from provmap.parsers.parser import Parser
from provmap.parsers.pcap import PcapParser


logger = logging.getLogger(__name__)

LOG_PARSERS: dict[str, type[Parser]] = {
    "sysmon": SysmonParser,
    "pcap": PcapParser,
}


class Loader:
    def __init__(self, config: dict) -> None:
        self.config = config

        self.verify_config()

        logger.info(f"Loaded config [{self.config["name"]}]")

    def verify_config(self) -> None:
        if "name" not in self.config:
            logger.warning("Missing name in config")

            self.config["name"] = "<NAMELESS>"

        if "dir" not in self.config:
            raise ValueError("Directory not specified")

        if "logs" not in self.config:
            raise ValueError("No logs specified")

        valid_logs = list(LOG_PARSERS.keys())

        for log_type in self.config["logs"]:
            if log_type not in valid_logs:
                raise ValueError(
                    f"No parser for log type '{log_type}'. Valid log types are {valid_logs}"
                )

            for log_filename in self.config["logs"][log_type]:
                if not log_filename.strip():
                    raise ValueError("Empty log filename found")

    def events_to_graph(self, events: list[Event]) -> Graph:
        graph = Graph()

        # Older records have precedence
        event_graphs = reversed([e.to_graph() for e in events])

        for eg in event_graphs:
            graph = graph.combine(eg)

        return graph

    def construct_graph(self) -> Graph:
        logger.info("Constructing graph")
        graph = Graph()

        logs: dict[str, list[str]] = self.config["logs"]

        for log_type, log_files in logs.items():
            logger.info(f"Found {len(log_files)} {log_type} file(s)")
            parser = LOG_PARSERS[log_type]

            for filepath in log_files:
                logger.info(f"Parsing {log_type} file {filepath}")

                complete_filepath = os.path.join(self.config["dir"], filepath)

                events = parser(complete_filepath).parse()

                logger.info(f"# of events = {len(events)}")

                event_graph = self.events_to_graph(events)

                graph = graph.combine(event_graph)

        logger.info(
            f"Graph construction complete (|V| = {graph.number_of_entities}, |E| = {graph.number_of_edges})"
        )

        return graph
