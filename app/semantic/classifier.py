from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Dict
import numpy as np

from app.semantic.models import LocalEmbedder
from app.semantic.rules_loader import load_rules

@dataclass
class SemanticResult:
    label: str         # "sensitive" | "non_sensitive"
    category: str      # "adversarial" | "health" | "address" | ...
    score: float       # pozitif - alpha*negatif (0..1 arası normalize değil)
    pos_top: List[Tuple[str, float]]
    neg_top: List[Tuple[str, float]]

class SemanticClassifier:
    def __init__(self, model_name: str, threshold: float = 0.45, alpha: float = 0.30, topk: int = 3):
        self.embedder = LocalEmbedder(model_name)
        self.rules = load_rules()
        self.threshold = threshold
        self.alpha = alpha
        self.topk = topk

        self.ref: Dict[str, Dict[str, object]] = {}
        for cat, spec in self.rules["categories"].items():
            pos = spec.get("positives", []) or []
            neg = spec.get("negatives", []) or []
            self.ref[cat] = {
                "pos_texts": pos,
                "neg_texts": neg,
                "pos_embeds": self.embedder.encode(pos) if pos else np.empty((0, 384)),
                "neg_embeds": self.embedder.encode(neg) if neg else np.empty((0, 384)),
            }

    def _topk(self, sims: np.ndarray, texts: List[str], k: int):
        if sims.size == 0:
            return [], 0.0
        idx = np.argsort(-sims)[:k]
        return [(texts[i], float(sims[i])) for i in idx], float(np.max(sims))

    def classify(self, text: str) -> SemanticResult:
        t = (text or "").strip()
        if not t:
            return SemanticResult("non_sensitive", "general", 0.0, [], [])

        q = self.embedder.encode([t])[0]  # normalized (cosine=dot)

        best_cat, best_score = "general", 0.0
        best_pos, best_neg = [], []

        for cat, bank in self.ref.items():
            posE = bank["pos_embeds"]; negE = bank["neg_embeds"]
            pos_pairs, pos_max = ([], 0.0)
            neg_pairs, neg_max = ([], 0.0)
            if isinstance(posE, np.ndarray) and posE.size:
                pos_pairs, pos_max = self._topk(posE @ q, bank["pos_texts"], self.topk)
            if isinstance(negE, np.ndarray) and negE.size:
                neg_pairs, neg_max = self._topk(negE @ q, bank["neg_texts"], self.topk)

            score = pos_max - self.alpha * neg_max
            if score > best_score:
                best_score, best_cat = score, cat
                best_pos, best_neg = pos_pairs, neg_pairs

        if best_cat != "general" and best_score >= self.threshold:
            return SemanticResult("sensitive", best_cat, best_score, best_pos, best_neg)
        return SemanticResult("non_sensitive", "general", best_score, best_pos, best_neg)