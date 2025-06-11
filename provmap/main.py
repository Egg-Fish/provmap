import logging
from functools import reduce

from provmap.loader import Loader
from provmap.reasoner import Reasoner
from provmap.graph.graph import Graph


logger = logging.getLogger(__name__)
logger.debug("Application start")


CONFIG_APT17 = {
    "name": "ProvCon APT17 Scenario",
    "dir": "examples/APT17",
    "logs": {
        "sysmon": [
            "Sysmon_1_3_11.evtx",
        ],
        "pcap": [
            "capture.pcap",
        ],
    },
}

CONFIG_T1059_005 = {
    "name": "Splunk T1059.005 Scenario",
    "dir": "examples/T1059.005",
    "logs": {
        "sysmon": [
            "Sysmon.txt",
        ],
    },
}

CONFIG_APT32 = {
    "name": "ProvCon APT32-B Scenario",
    "dir": "examples/APT32",
    "logs": {
        "sysmon": [
            "sysmon/victim_1_3_11.evtx",
        ],
    },
}

CONFIG_SHARPHOUND = {
    "name": "Splunk T1059.001 SharpHound Scenario",
    "dir": "examples/SharpHound",
    "logs": {
        "sysmon": [
            "windows-sysmon.txt",
        ],
    },
}


def save_as_graphviz(graph: Graph, outpath: str):
    logger.info(f"Saving graph {graph} as Graphviz file {outpath}")

    gv: str = graph.to_graphviz()

    with open(outpath, "w") as f:
        f.write(gv)


def save_as_prolog(graph: Graph, outpath: str):
    logger.info(f"Saving graph {graph} as Prolog file {outpath}")

    gv: str = graph.to_prolog()

    with open(outpath, "w") as f:
        f.write(gv)


def main():
    logger.info("Main started")

    loader = Loader(CONFIG_APT17)
    graph: Graph = loader.construct_graph()

    save_as_graphviz(graph, "out/graph.gv")
    save_as_prolog(graph, "out/graph.pl")

    reasoner = Reasoner(graph, "rules/schema.pl", "rules/rules.pl")

    malicious_entities = reasoner.get_malicious_entities()

    for e in malicious_entities:
        tags = reasoner.get_tags(e)

        print(tags)

    malicious_traces = [graph.trace(e.entity_id) for e in malicious_entities]
    malicious_traces += [Graph(), Graph()]  # Prevent reduce() from crashing

    malicious_graph = reduce(lambda acc, x: acc.combine(x), malicious_traces)

    save_as_graphviz(malicious_graph, "out/malicious_graph.gv")
