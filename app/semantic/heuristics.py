import re
from typing import List

_ADVERSARIAL_PATTERNS = [
    "ignore previous instructions", "ignore all prior instructions",
    "ignore instructions",  
    "bypass the rules", "jailbreak the model", "reveal the system prompt",
    "show system prompt", "leak the prompt", "disable safety", "override the policy",
    "önceki talimatları görmezden gel", "kuralları yok say", "güvenlik kontrollerini atla",
    "sistem yönergesini göster",
]

_ADDRESS_HINTS = [
    "home address is", "deliver to", "ship to", "street", "road", "avenue", "ave",
    "postal code", "zip code",
    "ev adresim", "teslimat adresi", "posta kodu", "mahalle", "cadde", "sokak",
]

def is_adversarial(text: str) -> bool:
    t = text.lower()
    return any(p in t for p in _ADVERSARIAL_PATTERNS)

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