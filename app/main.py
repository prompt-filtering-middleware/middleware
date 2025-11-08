from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional

from app.detectors.patterns import detect_all
from app.actions.masker import mask_all
from app.actions.policy import decide_actions, ENFORCEMENT, POLICY

app = FastAPI(title="LLM Security Gateway", version="0.3.0")


DATASET_CATEGORY_MAP: Dict[str, str] = {
    # PII
    "credit_card": "credit_card",
    "iban": "bank_account",
    "tckn": "tckn",
    "email": "email",
    "phone": "phone",
    "dob": "dob",
    "ipv4": "ip",
    "mac": "mac",
    "imei": "imei",
    "passport": "passport",
    "driver_license": "driver_license",
    "ssn": "ssn",
    "health": "health",

    # Secrets 
    "api_key": "api_key",
    "api_key.aws_access_key": "api_key",
    "api_key.potential_secret": "api_key",
    "api_key.hex": "api_key",
    "api_key.jwt": "jwt",

}

def _map_category(htype: str) -> Optional[str]:

    if htype in DATASET_CATEGORY_MAP:
        return DATASET_CATEGORY_MAP[htype]

    base = htype.split(".")[0]
    return DATASET_CATEGORY_MAP.get(base)

def _compute_label_category(hits: List[Dict]) -> Dict[str, str]:
    """
    hits -> {"label": "...", "category": "..."}
    """
    if not hits:
        return {"label": "non_sensitive", "category": "general"}


    block_types = {k for k, v in POLICY.items() if v == "block"}
    for h in hits:
        if h["type"] in block_types or h["type"].split(".")[0] in block_types:
            cat = _map_category(h["type"])
            if cat:
                return {"label": "sensitive", "category": cat}


    for h in hits:
        cat = _map_category(h["type"])
        if cat:
            return {"label": "sensitive", "category": cat}


    return {"label": "sensitive", "category": "other"}


class ModerateIn(BaseModel):
    text: str

class ModerateOut(BaseModel):
    action: str              # allow | warn | mask | block
    label: str               # sensitive | non_sensitive
    category: str            
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


    cls = _compute_label_category(hits)

    if not hits:
        return {
            "action": "allow",
            "label": cls["label"],
            "category": cls["category"],
            "text": text,
            "hits": [],
            "warnings": [],
        }


    action, warnings = decide_actions(hits)

    if action == "block":
        masked = mask_all(text, hits)

        raise HTTPException(
            status_code=422,
            detail={
                "msg": "Sensitive data detected.",
                "enforcement": ENFORCEMENT,
                "label": cls["label"],
                "category": cls["category"],
                "suggested_text": masked,
                "hits": hits,
                "warnings": warnings,
            },
        )

    if action == "mask":
        return {
            "action": "mask",
            "label": cls["label"],
            "category": cls["category"],
            "text": mask_all(text, hits),
            "hits": hits,
            "warnings": warnings,
        }

    if action == "warn":
        return {
            "action": "warn",
            "label": cls["label"],
            "category": cls["category"],
            "text": text,
            "hits": hits,
            "warnings": warnings or ["Low-confidence entity detected"],
        }


    return {
        "action": "allow",
        "label": cls["label"],
        "category": cls["category"],
        "text": text,
        "hits": hits,
        "warnings": warnings,
    }