import logging
import os
from functools import reduce


from provmap.embedder import Embedder
from provmap.loader import Loader
from provmap.reasoner import Reasoner
from provmap.graph.graph import Graph
import argparse


logger = logging.getLogger(__name__)
logger.debug("Application start")


CONFIG_APT17 = {
    "name": "ProvCon APT17 Scenario",
    "dir": "examples/APT17",
    "outdir": "out/APT17",
    "logs": {
        "sysmon": [
            # "Sysmon.evtx",
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
    "outdir": "out/T1059.005",
    "logs": {
        "sysmon": [
            "Sysmon.txt",
        ],
    },
}

CONFIG_APT32 = {
    "name": "ProvCon APT32-B Scenario",
    "dir": "examples/APT32",
    "outdir": "out/APT32",
    "logs": {
        "sysmon": [
            "sysmon/victim_1_3_11.evtx",
        ],
    },
}

CONFIG_APT33 = {
    "name": "ProvCon APT33 Scenario",
    "dir": "examples/APT33",
    "outdir": "out/APT33",
    "logs": {
        "sysmon": [
            # "sysmon/aviation.evtx",
            # "sysmon/energy.evtx",
            "sysmon/aviation_1_3_11.evtx",
            "sysmon/energy_1_3_11.evtx",
        ],
        "pcap": [
            "pcap/APT33_combined.pcap",
            # "pcap/EnergySectorServer_combined.pcap",
            # "pcap/AviationSectorServer_combined.pcap",
        ],
    },
}

CONFIG_SHARPHOUND = {
    "name": "Splunk T1059.001 SharpHound Scenario",
    "dir": "examples/SharpHound",
    "outdir": "out/SharpHound",
    "logs": {
        "sysmon": [
            "windows-sysmon.txt",
        ],
    },
}

CONFIG_MIXTURE = {
    "name": "A collection of various Sysmon logs",
    "dir": "examples",
    "outdir": "out/mixture",
    "logs": {
        "sysmon": [
            "APT17/Sysmon.evtx",
            "APT32/sysmon/victim.evtx",
            "EvtxAttackSamples/Exec_sysmon_meterpreter_reversetcp_msipackage.evtx",
            "SharpHound/windows-sysmon.txt",
            "T1059.005/Sysmon.txt",
        ]
    },
}


def save_graph_as_graphviz(graph: Graph, outpath: str):
    logger.info(f"Saving graph {graph} as Graphviz file {outpath}")

    gv: str = graph.to_graphviz()

    with open(outpath, "w") as f:
        f.write(gv)


def save_graph_as_prolog(graph: Graph, outpath: str):
    logger.info(f"Saving graph {graph} as Prolog file {outpath}")

    prolog: str = graph.to_prolog()

    with open(outpath, "w") as f:
        f.write(prolog)


def save_graph_as_triples(graph: Graph, outpath: str):
    logger.info(f"Saving graph {graph} as triples {outpath}")

    triples: list = graph.to_triples()

    with open(outpath, "w") as f:
        for t in triples:
            f.write("\t".join(map(str, t)) + "\n")


def save_graph_as_pickle(graph: Graph, outpath: str):
    logger.info(f"Saving graph {graph} as pickle {outpath}")

    pkl: bytes = graph.to_pickle()

    with open(outpath, "wb") as f:
        f.write(pkl)


def load_graph_from_pickle(inpath: str) -> Graph:
    logger.info(f"Loading graph from pickle {inpath}")

    with open(inpath, "rb") as f:
        pkl = f.read()

    return Graph.from_pickle(pkl)


def save_embedder_as_pickle(embedder: Embedder, outpath: str):
    logger.info(f"Saving embedder as pickle {outpath}")

    pkl: bytes = embedder.to_pickle()

    with open(outpath, "wb") as f:
        f.write(pkl)


def load_embedder_from_pickle(inpath: str) -> Embedder:
    logger.info(f"Loading embedder from pickle {inpath}")

    with open(inpath, "rb") as f:
        pkl = f.read()

    return Embedder.from_pickle(pkl)


def load_graph(config: dict, force_rebuild: bool = False, include_pcap: bool = False):
    loader = Loader(config)

    outdir = config["outdir"]

    try:
        assert force_rebuild == False
        pickle_inpath = os.path.join(outdir, "graph.pkl")
        graph = load_graph_from_pickle(pickle_inpath)
        logger.info(f"Loaded existing graph from {pickle_inpath}")

    except:
        logger.info("Constructing graph from scratch")

        graph: Graph = loader.construct_graph(include_pcap=include_pcap)

        outdir = config["outdir"]
        os.makedirs(outdir, exist_ok=True)

        save_graph_as_graphviz(graph, os.path.join(outdir, "graph.gv"))
        save_graph_as_prolog(graph, os.path.join(outdir, "graph.pl"))
        save_graph_as_triples(graph, os.path.join(outdir, "graph.txt"))

        save_graph_as_pickle(graph, os.path.join(outdir, "graph.pkl"))

    return graph


def load_embedder(
    config: dict, graph: Graph, reasoner: Reasoner | None, force_retrain=False
) -> Embedder:
    outdir = config["outdir"]

    try:
        assert force_retrain == False
        embedder_inpath = os.path.join(outdir, "embedder.pkl")
        embedder = load_embedder_from_pickle(embedder_inpath)

    except:
        logger.info("Could not find existing embedder. Training embedder from scratch")

        embedder = Embedder(graph, reasoner=reasoner)

        embedder.train(embedding_dim=32, num_epochs=3000)

        logger.info(f"Metrics: {embedder.metrics}")

        save_embedder_as_pickle(embedder, os.path.join(outdir, "embedder.pkl"))

    return embedder


PROVCON_DATASET_DIR = os.getenv("PROVCON_DATASET_DIR")


def load_from_provcon(scenario: str, date: str, time: str) -> dict:
    dir = f"{PROVCON_DATASET_DIR}/{scenario}/{date}/{time}"
    outdir = f"./out/{scenario}/{date}/{time}"

    os.makedirs(outdir, exist_ok=True)

    os.makedirs(outdir + "/sysmon", exist_ok=True)
    os.makedirs(outdir + "/pcap", exist_ok=True)

    sysmon_zips = os.listdir(dir + "/logs")

    sysmon_zips = [s for s in sysmon_zips if "_events_" in s]

    sysmon_files = []
    pcap_files = []

    for z in sysmon_zips:
        instance_name = z.split("_")[0]

        zip_path = f"{dir}/logs/{z}"
        sysmon_file = f"sysmon/{instance_name}.evtx"

        os.system(f'unzip -o {zip_path} "*Sysmon*.evtx" -d {outdir}/sysmon')
        os.system(f"mv {outdir}/sysmon/**/*Sysmon*.evtx {outdir}/{sysmon_file}")

        sysmon_files.append(sysmon_file)

    for p in [p for p in os.listdir(dir + "/network") if p.endswith(".pcap")]:
        instance_name = p.split("_")[0]

        pcap_path = dir + "/network/" + p
        pcap_file = f"pcap/{instance_name}.pcap"

        os.system(f"cp {pcap_path} {outdir}/{pcap_file}")

        pcap_files.append(pcap_file)

    return {
        "name": f"PROVCON {scenario} {date} {time}",
        "dir": outdir,
        "outdir": outdir,
        "logs": {
            "sysmon": sysmon_files,
            "pcap": pcap_files,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="provmap")
    parser.add_argument(
        "--scenario", type=str, required=True, help="Scenario name (e.g. APT33)"
    )
    parser.add_argument("--date", type=str, required=True, help="Date (YYYY-MM-DD)")
    parser.add_argument("--time", type=str, required=True, help="Time (HHMM)")
    parser.add_argument(
        "--force-rebuild", action="store_true", help="Force rebuild of the graph"
    )
    parser.add_argument(
        "--include-pcap", action="store_true", help="Include packet captures in graph"
    )

    args = parser.parse_args()

    logger.info("Main started")

    config = load_from_provcon(args.scenario, args.date, args.time)
    outdir = config["outdir"]
    graph = load_graph(
        config,
        force_rebuild=args.force_rebuild,
        include_pcap=args.include_pcap,
    )

    reasoner = Reasoner(graph, "rules/schema.pl", "rules/rules.pl")

    malicious_entities = reasoner.get_malicious_entities()
    malicious_graph = graph.subgraph(malicious_entities)

    save_graph_as_graphviz(malicious_graph, os.path.join(outdir, "malicious_graph.gv"))

    for entity_id in malicious_graph.G.nodes():
        tags = reasoner.get_tags(malicious_graph.get_entity(entity_id))
        logger.info(f"Tags for {entity_id}: \n{"\n".join(tags)}")

    exit()

    # terminals = malicious_graph.get_leaves()

    # for terminal in terminals:
    #     trace = malicious_graph.trace(terminal)

    #     walks = trace.to_walks(label=True)

    #     for walk in walks:
    #         print(" ".join(f"[{n}]" for n in walk))

    # exit()

    # embedder = load_embedder(config, graph, reasoner, force_retrain=True)

    # embedder.plot(os.path.join(outdir, "entity_embedding.html"))
    # embedder.to_csv(
    #     os.path.join(outdir, "entity_embeddings.csv"),
    #     os.path.join(outdir, "relation_embeddings.csv"),
    # )

    # # Tail prediction

    # entity_id = "file_42e889d3558c5e0efa1508784f3e2e15f5b9b6256075d4d3cfdb062e6478c36a"
    # scores = embedder.score_t(entity_id, "has_tag", sort=True)

    # for row in scores[:10]:
    #     i, score = row
    #     print(f"Entity: {embedder.entities[int(i)]}, Score: {score}")
