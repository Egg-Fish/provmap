import logging


import numpy as np
import pandas as pd
import plotly.express as px
import torch
from pykeen.models import ERModel
from pykeen.triples import TriplesFactory
from pykeen.pipeline import pipeline

from sklearn.decomposition import PCA

from provmap.graph.graph import Graph


logger = logging.getLogger(__name__)


class Embedder:
    def __init__(self, graph: Graph) -> None:
        logger.info("Initialising embedder")
        self.graph = graph
        self._model: ERModel | None = None

        triples = [w.strip().split("\t") for w in open("out/graph.txt", "r")]

        triples_array = np.array(triples, dtype=str)

        tf = TriplesFactory.from_labeled_triples(triples_array)
        training, testing, validation = tf.split([0.8, 0.1, 0.1])

        self.data = {"training": training, "testing": testing, "validation": validation}

        self._entity_embedding_tensor: np.ndarray | None = None
        self._relation_embedding_tensor: np.ndarray | None = None

    @property
    def model(self) -> ERModel:
        if not self._model:
            raise ValueError("Retrieving model before calling train()")

        return self._model

    @property
    def entities(self) -> np.ndarray:
        return np.array(list(self.data["training"].entity_to_id.keys()), dtype=str)

    @property
    def relations(self) -> np.ndarray:
        return np.array(list(self.data["training"].relation_to_id.keys()), dtype=str)

    def train(self) -> None:
        logger.info("Training embedder using TransE")

        result = pipeline(
            training=self.data["training"],
            testing=self.data["testing"],
            validation=self.data["validation"],
            model="TransE",
            model_kwargs=dict(embedding_dim=100),
        )

        self._model = result.model
        assert isinstance(self.model, ERModel)

        entity_representation_modules = self.model.entity_representations
        relation_representation_modules = self.model.relation_representations

        entity_embeddings = entity_representation_modules[0]
        relation_embeddings = relation_representation_modules[0]

        entity_embedding_tensor = entity_embeddings().detach().cpu().numpy()
        relation_embedding_tensor = relation_embeddings().detach().cpu().numpy()

        self.entity_embedding_tensor = entity_embedding_tensor
        self.relation_embedding_tensor = relation_embedding_tensor

        logger.info(
            f"Learned {entity_embedding_tensor.shape[1]}-dimensional embeddings for {entity_embedding_tensor.shape[0]} entities"
        )

        logger.info(
            f"Learned {relation_embedding_tensor.shape[1]}-dimensional embeddings for {relation_embedding_tensor.shape[0]} relations"
        )

    def get_entity_embedding(self, entity_id: str) -> np.ndarray:
        logger.debug(f"Extracting embeddings for entity {entity_id}")

        if not self.model:
            raise ValueError("Embedding tensor accessed before train()")

        data = self.data["training"]

        if entity_id not in self.entities:
            raise ValueError(f"Entity {entity_id} has no embedding")

        i = data.entity_to_id[entity_id]

        embedding = self.entity_embedding_tensor[i]

        return embedding

    def score_hrt(self, head: str, relation: str, tail: str) -> float:
        logger.debug(f"Scoring triple ({head}, {relation}, {tail})")

        if not self.model:
            raise ValueError("Scoring triple before train()")

        data = self.data["training"]

        if head not in self.entities:
            raise ValueError(f"Entity {head} not found")

        if tail not in self.entities:
            raise ValueError(f"Entity {tail} not found")

        if relation not in data.relation_to_id:
            raise ValueError(f"Relation {relation} not found")

        hrt = torch.tensor(
            [
                (
                    np.argwhere(self.entities == head)[0][0],
                    np.argwhere(self.relations == relation)[0][0],
                    np.argwhere(self.entities == tail)[0][0],
                )
            ]
        )

        return self.model.score_hrt(hrt)[0][0].item()

    def score_t(self, head: str, relation: str, sort: bool = False) -> np.ndarray:
        logger.debug(f"Scoring tails for ({head}, {relation}, <tail>)")

        if not self.model:
            raise ValueError("Scoring tails before train()")

        data = self.data["training"]

        if head not in self.entities:
            raise ValueError(f"Entity {head} not found")

        if relation not in self.relations:
            raise ValueError(f"Relation {relation} not found")

        hr = torch.tensor(
            [
                (
                    np.argwhere(self.entities == head)[0][0],
                    np.argwhere(self.relations == relation)[0][0],
                )
            ]
        )

        tail_scores = self.model.score_t(hr)[0].detach().numpy()
        result = np.column_stack((np.arange(tail_scores.shape[0]), tail_scores))

        if sort:
            result = result[result[:, 1].argsort()[::-1]]

        return result

    def plot(self, html_outpath: str | None = None) -> None:
        logger.info("Plotting entity embeddings")

        if not self.model:
            raise ValueError("Plotting embeddings before train()")

        data = self.data["training"]

        entity_df = pd.DataFrame(self.entity_embedding_tensor)

        logger.info("Running 2-component PCA")
        pca = PCA(n_components=2)
        reduced = pca.fit_transform(entity_df)

        entity_ids = [data.entity_id_to_label[i] for i in entity_df.index]
        entities = [self.graph.G.nodes[i]["obj"] for i in entity_ids]

        plot_df = pd.DataFrame(
            {
                "entity_id": entity_ids,
                "entity_type": [str(type(e)) for e in entities],
                "label": [e.label for e in entities],
                "idx": entity_df.index,
                "pca_1": reduced[:, 0],
                "pca_2": reduced[:, 1],
            }
        )

        fig = px.scatter(
            plot_df,
            x="pca_1",
            y="pca_2",
            color="entity_type",
            hover_data=["entity_id", "label"],
            title="Entity Embeddings (PCA 2D)",
        )

        fig.show()

        if html_outpath:
            html = fig.to_html()

            with open(html_outpath, "w") as f:
                f.write(html)

    def to_csv(self, entity_outpath: str, relation_outpath: str):
        data = self.data["training"]
        entity_embedding_tensor = self.entity_embedding_tensor
        relation_embedding_tensor = self.relation_embedding_tensor

        if not entity_embedding_tensor or not relation_embedding_tensor:
            raise ValueError("Embedding tensors not found")

        entity_labels = [
            data.entity_id_to_label[i] for i in range(entity_embedding_tensor.shape[0])
        ]

        relation_labels = [
            data.relation_id_to_label[i]
            for i in range(relation_embedding_tensor.shape[0])
        ]

        entity_df = pd.DataFrame(entity_embedding_tensor, index=entity_labels)
        relation_df = pd.DataFrame(relation_embedding_tensor, index=relation_labels)

        entity_df.columns = [f"dim_{i}" for i in range(entity_df.shape[1])]

        relation_df.columns = [f"dim_{i}" for i in range(relation_df.shape[1])]

        entity_df.to_csv(entity_outpath)
        relation_df.to_csv(relation_outpath)
