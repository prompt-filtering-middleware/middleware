from __future__ import annotations
import numpy as np
from sentence_transformers import SentenceTransformer

class LocalEmbedder:
    def __init__(self, model_name: str):
        self.model = SentenceTransformer(model_name)

    def encode(self, texts):
        if not texts:
            return np.empty((0, 384))
        return self.model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)