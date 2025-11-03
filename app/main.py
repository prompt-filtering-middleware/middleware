from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional

from app.detectors.patterns import detect_all
from app.actions.masker import mask_all
from app.actions.policy import decide_actions, ENFORCEMENT

app = FastAPI(title="LLM Security Gateway", version="0.2.0")


class ModerateIn(BaseModel):
    text: str


class ModerateOut(BaseModel):
    action: str             
    text: str
    hits: List[Dict]
    warnings: Optional[List[str]] = None


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": app.version}


@app.post("/moderate", response_model=ModerateOut)
def moderate(payload: ModerateIn):
    text = (payload.text or "").strip()
    hits = detect_all(text)  
    if not hits:
        return {"action": "allow", "text": text, "hits": [], "warnings": []}

    # policy kararı
    action, warnings = decide_actions(hits)

    if action == "block":
        masked = mask_all(text, hits)
        raise HTTPException(
            status_code=422,
            detail={
                "msg": "Sensitive data detected.",
                "enforcement": ENFORCEMENT,
                "suggested_text": masked,
                "hits": hits,
                "warnings": warnings,
            },
        )

    if action == "mask":
        return {
            "action": "mask",
            "text": mask_all(text, hits),
            "hits": hits,
            "warnings": warnings,
        }

    if action == "warn":
        return {
            "action": "warn",
            "text": text,
            "hits": hits,
            "warnings": warnings or ["Low-confidence entity detected"],
        }

    return {"action": "allow", "text": text, "hits": hits, "warnings": warnings}