from __future__ import annotations
import os
from typing import List, Dict, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.detectors.patterns import detect_all
from app.actions.masker import mask_all
from app.actions.policy import decide_actions, ENFORCEMENT, POLICY

from app.semantic.heuristics import is_adversarial, is_address_like
from app.semantic.semantic_utils import load_semantic_model, semantic_debug_info

from dotenv import load_dotenv
load_dotenv()

SEMANTIC_ENABLED = os.getenv("SEMANTIC_ENABLED", "1") not in {"0", "false", "False"}
SEMANTIC_MODEL = os.getenv("SEMANTIC_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
SEMANTIC_THRESHOLD = float(os.getenv("SEMANTIC_THRESHOLD", "0.45"))
SEMANTIC_ALPHA = float(os.getenv("SEMANTIC_ALPHA", "0.30"))
SEMANTIC_DEBUG = os.getenv("SEMANTIC_DEBUG", "1") not in {"0", "false", "False"}

_semantic = load_semantic_model(
    enabled=SEMANTIC_ENABLED,
    model_name=SEMANTIC_MODEL,
    threshold=SEMANTIC_THRESHOLD,
    alpha=SEMANTIC_ALPHA,
)


app = FastAPI(title="LLM Security Gateway", version="0.4.3")

# Match type to dataset category
DATASET_CATEGORY_MAP: Dict[str, str] = {
    # PII / IDs
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
    "address": "address",
    "medical_record_number": "medical_record_number",
    "vehicle_registration": "vehicle_registration",
    "password": "password",
    "qr_code": "qr_code",
    "cryptocurrency_wallet": "cryptocurrency_wallet",
    "2fa_link": "2fa_link",
    "employment_id": "employment_id",
    "serial_number": "serial_number",
    "pin": "pin",
    "national_insurance": "national_insurance",
    "api_key": "api_key",
    "api_key.aws_access_key": "api_key",
    "api_key.potential_secret": "api_key",
    "api_key.hex": "api_key",
    "api_key.jwt": "jwt",
}

def _map_category(htype: str) -> Optional[str]:
    if htype in DATASET_CATEGORY_MAP:
        return DATASET_CATEGORY_MAP[htype]
    return DATASET_CATEGORY_MAP.get(htype.split(".")[0])

PRIORITY_ORDER = [
    "api_key",        
    "ssn",
    "credit_card",
    "bank_account",
    "tckn",
    "passport",
    "driver_license",
    "medical_record_number",
    "cryptocurrency_wallet",
    "2fa_link",
    "password",
    "pin",
    "vehicle_registration",
    "employment_id",
    "serial_number",
    "email",
    "phone",
    "address",
    "health",
    "other",
]

def _compute_label_category(hits):
    if not hits:
        return {"label":"non_sensitive","category":"general"}

    # map types -> simple base name if dotted
    mapped = []
    for h in hits:
        base = h["type"].split(".")[0]
        cat = _map_category(h["type"]) or _map_category(base)
        mapped.append((base, cat, h))

    # if any api_key.stripe -> choose api_key immediately
    for base, cat, h in mapped:
        if base == "api_key" or "stripe" in h.get("type",""):
            return {"label":"sensitive","category":"api_key"}

    # enforce explicit priority
    for p in PRIORITY_ORDER:
        for base, cat, h in mapped:
            if cat == p:
                return {"label":"sensitive","category":cat}

    # fallback
    return {"label":"sensitive","category":"other"}

class ModerateIn(BaseModel):
    text: str

class ModerateOut(BaseModel):
    action: str               # allow | warn | mask | block
    label: str                # sensitive | non_sensitive
    category: str           
    text: str
    hits: List[Dict]
    warnings: Optional[List[str]] = None


# Endpoints
@app.get("/healthz")
def healthz():
    return {
        "ok": True,
        "version": app.version,
        "semantic_enabled": bool(_semantic is not None and SEMANTIC_ENABLED),
    }


@app.post("/moderate", response_model=ModerateOut)
def moderate(payload: ModerateIn):
    text = (payload.text or "").strip()

    # Regex 
    hits = detect_all(text)
    cls = _compute_label_category(hits)  # {"label": ..., "category": ...}

    # Semantic (embedding) 
    sem_label, sem_category, sem_score, sem_warn = "non_sensitive", "general", 0.0, []
    if SEMANTIC_ENABLED and _semantic:
        sem_label, sem_category, sem_score, sem_warn = semantic_debug_info(
            _semantic.classify(text)
        )

    # Heuristic (semantic + text-based)
    if not hits:
        
        if is_adversarial(text):
            if sem_category == "adversarial" and sem_score >= 0.70:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "msg": "Adversarial content detected.",
                        "enforcement": ENFORCEMENT,
                        "label": "sensitive",
                        "category": "adversarial",
                        "suggested_text": text,
                        "hits": [],
                        "warnings": sem_warn + ["Adversarial (heuristic, high confidence)"],
                    },
                )
            return {
                "action": "warn",
                "label": "sensitive",
                "category": "adversarial",
                "text": text,
                "hits": [],
                "warnings": sem_warn + ["Adversarial (heuristic)"],
            }


        if is_address_like(text):
            return {
                "action": "warn",
                "label": "sensitive",
                "category": "address",
                "text": text,
                "hits": [],
                "warnings": sem_warn + ["Address-like (heuristic)"],
            }


        if sem_label == "sensitive":
            if sem_category == "adversarial" and sem_score >= 0.70:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "msg": "Adversarial content detected.",
                        "enforcement": ENFORCEMENT,
                        "label": sem_label,
                        "category": sem_category,
                        "suggested_text": text,
                        "hits": [],
                        "warnings": sem_warn + [f"Semantic risk: {sem_category} ({sem_score:.2f})"],
                    },
                )
            return {
                "action": "warn",
                "label": sem_label,
                "category": sem_category,
                "text": text,
                "hits": [],
                "warnings": sem_warn + [f"Semantic risk: {sem_category} ({sem_score:.2f})"],
            }


        return {
            "action": "allow",
            "label": "non_sensitive",
            "category": "general",
            "text": text,
            "hits": [],
            "warnings": sem_warn,
        }


    action, warnings = decide_actions(hits)
    warnings = (warnings or []) + sem_warn


    category_override = None
    if is_adversarial(text):
        category_override = "adversarial"

        if sem_category == "adversarial" and sem_score >= 0.70:
            action = "block"
            warnings.append(f"Adversarial (semantic {sem_score:.2f})")
        else:

            if action == "allow":
                action = "warn"
            warnings.append("Adversarial (heuristic)")


    if action == "allow" and sem_label == "sensitive":
        action = "warn"
        warnings.append(f"Semantic suspicious: {sem_category} ({sem_score:.2f})")


    out_label = cls["label"]
    out_category = category_override or cls["category"]
    if category_override == "adversarial":
        out_label = "sensitive"


    if action == "block":
        masked = mask_all(text, hits)
        raise HTTPException(
            status_code=422,
            detail={
                "msg": "Sensitive or adversarial content detected.",
                "enforcement": ENFORCEMENT,
                "label": out_label,
                "category": out_category,
                "suggested_text": masked,
                "hits": hits,
                "warnings": warnings,
            },
        )

    if action == "mask":
        return {
            "action": "mask",
            "label": out_label,
            "category": out_category,
            "text": mask_all(text, hits),
            "hits": hits,
            "warnings": warnings,
        }

    if action == "warn":
        return {
            "action": "warn",
            "label": out_label,
            "category": out_category,
            "text": text,
            "hits": hits,
            "warnings": warnings or ["Low-confidence entity detected"],
        }

    # allow
    return {
        "action": "allow",
        "label": out_label,
        "category": out_category,
        "text": text,
        "hits": hits,
        "warnings": warnings,
    }