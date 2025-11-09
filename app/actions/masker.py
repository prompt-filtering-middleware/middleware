import re
from typing import List, Dict

def _mask_value(hit_type: str, val: str) -> str:
    s = str(val)

    if hit_type.startswith("api_key"):
        s_compact = re.sub(r"\s+", "", s)
        return f"{s_compact[:4]}...{s_compact[-4:]}" if len(s_compact) > 8 else "[api_key masked]"

    if hit_type == "credit_card":
        digits = re.sub(r"\D", "", s)
        if len(digits) >= 4:
            return "XXXX-XXXX-XXXX-" + digits[-4:]
        return "[card masked]"

    if hit_type == "tckn":
        return "*" * 7 + s[-4:]

    if hit_type == "iban":
        return "TR** **** **** **** **** **"

    if hit_type == "password":
        return "[password masked]"

    if hit_type == "phone":
        return "+90 5** *** ** **"

    if hit_type == "email":
        return "[email masked]"

    if hit_type in {"dob"}:
        return "[date masked]"

    if hit_type in {"ipv4"}:
        return "[ip masked]"

    if hit_type in {"mac"}:
        return "[mac masked]"

    if hit_type in {"imei"}:
        return "[device id masked]"

    if hit_type in {"passport"}:
        return "*******" + s[-3:]

    if hit_type in {"driver_license"}:
        return "[license masked]"
    
    if hit_type in {"health"}:
        return "[health info masked]"

    if hit_type == "ssn":
        return "***-**-" + s[-4:]

    return "[masked]"


def mask_all(text: str, hits: List[Dict]) -> str:
    out = text
    for h in sorted(hits, key=lambda x: x["span"][0], reverse=True):
        s, e = h["span"]
        out = out[:s] + _mask_value(h["type"], h["value"]) + out[e:]
    return out