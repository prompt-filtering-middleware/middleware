import re
from typing import List

ADVERSARIAL_PATTERNS = [
    r"ignore\s+previous\s+instructions",
    r"ignore\s+all\s+prior\s+instructions",
    r"bypass\s+the\s+rules",
    r"jailbreak",
    r"dev\s*mode",
    r"print\s+the\s+hidden\s+prompt",
    r"output\s+your\s+system\s+prompt",
    r"override\s+content\s+policy",
    r"disable\s+safety",
    r"prompt\s+injection",
    r"hidden\s+(info|information|data)",    
    r"secret\d{3,}",                        
    r"reveal\s+(the\s+)?secret",             
    r"expose\s+(the\s+)?hidden",             
]

_ADDRESS_HINTS = [
    "home address is", "deliver to", "ship to", "street", "road", "avenue", "ave",
    "postal code", "zip code",
]

ADVERSARIAL_REGEX = [re.compile(p, re.IGNORECASE) for p in ADVERSARIAL_PATTERNS]


def is_adversarial(text: str) -> bool:
    for r in ADVERSARIAL_REGEX:
        if r.search(text):
            return True
    return False


def is_address_like(text: str) -> bool:
    t = text.lower()
    has_hint = any(h in t for h in _ADDRESS_HINTS)
    has_number = bool(re.search(r"\b\d{1,5}\b", t) or re.search(r"\b\d{5}(-\d{4})?\b", t))
    return has_hint and has_number and len(t.split()) >= 4

def get_triggered_categories(text: str) -> List[str]:
    cats: List[str] = []
    if is_adversarial(text):
        cats.append("adversarial")
    if is_address_like(text):
        cats.append("address")
    return cats