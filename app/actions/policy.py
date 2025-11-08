from typing import Dict, List, Tuple

# Basit enforcement map (PoC):
#  - block: critic leak (api_key, card, TCKN, IBAN, password etc.)
#  - mask : personal but not critic (email, phone, dob, ip, mac etc.)
#  - warn : high FP risk - just a warning
POLICY: Dict[str, str] = {
    "api_key": "block",
    "api_key.aws_access_key": "block",
    "api_key.potential_secret": "block",
    "api_key.hex": "block",
    "api_key.jwt": "block",

    "credit_card": "block",
    "tckn": "block",
    "iban": "block",
    "password": "block",

    "email": "mask",
    "phone": "mask",
    "dob": "mask",
    "ssn": "block",
    "health": "mask",
    

    "ipv4": "mask",
    "mac": "mask",
    "imei": "mask",

    "passport": "mask",
    "driver_license": "mask",
}

ENFORCEMENT = {
    "block": [k for k, v in POLICY.items() if v == "block"],
    "mask": [k for k, v in POLICY.items() if v == "mask"],
    "warn": [k for k, v in POLICY.items() if v == "warn"],
}


def decide_actions(hits: List[Dict]) -> Tuple[str, List[str]]:
    """
    hits: {"type": "...", "span": (s,e), "value": "..."} list
    output: (action, warnings[])
    Hardest action is taken if multiple types are detected.
    """
    has_block = False
    has_mask = False
    has_warn = False
    warnings = []

    for h in hits:
        htype = h["type"]
        decision = POLICY.get(htype) or POLICY.get(htype.split(".")[0]) or "allow"
        if decision == "block":
            has_block = True
        elif decision == "mask":
            has_mask = True
        elif decision == "warn":
            has_warn = True
            warnings.append(f"Detected {htype} with low/medium confidence")

    if has_block:
        return "block", warnings
    if has_mask:
        return "mask", warnings
    if has_warn:
        return "warn", warnings
    return "allow", warnings