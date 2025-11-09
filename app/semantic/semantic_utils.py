from typing import Tuple
from app.semantic.classifier import SemanticClassifier, SemanticResult

def load_semantic_model(enabled: bool, model_name: str, threshold: float, alpha: float):
    # Load the semantic model safely, return None if it fails
    if not enabled:
        return None
    try:
        return SemanticClassifier(model_name=model_name, threshold=threshold, alpha=alpha)
    except Exception as e:
        print(f"[warn] semantic model load failed: {e}")
        return None

def semantic_debug_info(res: SemanticResult | None) -> Tuple[str, str, float, list]:
    # Debug output and return default values
    if not res:
        return "non_sensitive", "general", 0.0, []
    sem_warn = [f"[SEM] cat={res.category} score={res.score:.2f} label={res.label}"]
    return res.label, res.category, res.score, sem_warn