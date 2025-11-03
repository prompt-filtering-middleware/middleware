import re
from typing import List, Dict, Tuple


def normalize_whitespace(s: str) -> str:
    return re.sub(r"[ \t]+", " ", s)

def compact_digits(s: str) -> str:
    return re.sub(r"[ \-_.:;/\\\n\r\t]", "", s)

# -----------------------
# Core regex patterns
# -----------------------
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
GLOBAL_PHONE = re.compile(r"\+?[1-9]\d{7,14}")
GLOBAL_IBAN = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b", re.IGNORECASE)
CC_CANDIDATE = re.compile(r"\b(?:\d[ \-]*?){13,19}\b")
TCKN = re.compile(r"\b\d{11}\b")

# Birth date (yyyy-mm-dd / dd.mm.yyyy vb.)
DOB1 = re.compile(r"\b(19|20)\d{2}[-/.](0[1-9]|1[0-2])[-/.](0[1-9]|[12]\d|3[01])\b")
DOB2 = re.compile(r"\b(0[1-9]|[12]\d|3[01])[-/.](0[1-9]|1[0-2])[-/.](19|20)\d{2}\b")

# Network / Device IDs
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b")
IMEI = re.compile(r"\b\d{15}\b")

# Identities (heuristic – might be changed per country)
PASSPORT = re.compile(r"\b([A-PR-WY][0-9][0-9A-Z][0-9A-Z]{5,7})\b")  # FP risk
DRIVER_LICENSE = re.compile(r"\b([A-Z0-9]{5,15})\b")  # context-dependent

# -----------------------
# API keys / Secrets
# -----------------------
API_KEY_WORDS = re.compile(
    r"\b(api[_-]?key|secret|token|access[_-]?key|private[_-]?key|secret[_-]?key|bearer|authorization)\b",
    re.IGNORECASE,
)
AWS_ACCESS_KEY = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
AWS_SECRET_KEY_40 = re.compile(r"\b[0-9a-zA-Z/+]{40}\b")  # high FP risk
HEX_32_64 = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
JWT_CANDIDATE = re.compile(r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")

# -----------------------
# Helpers
# -----------------------
def luhn_ok(s: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", s)]
    if not (13 <= len(digits) <= 19):
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def find_api_secrets(text: str) -> List[Dict]:
    hits: List[Dict] = []

    # 1) AWS Access Key
    for m in AWS_ACCESS_KEY.finditer(text):
        hits.append({"type": "api_key.aws_access_key", "span": m.span(), "value": m.group()})

    # 2) 40-char secret-ish (heuristic)
    for m in AWS_SECRET_KEY_40.finditer(text):
        s, e = m.span()
        window = text[max(0, s - 60) : min(len(text), e + 60)]
        if API_KEY_WORDS.search(window):
            hits.append({"type": "api_key.potential_secret", "span": (s, e), "value": m.group()})

    # 3) Hex blob (32–64) → sadece anahtar kelime yakınsa işaretleyelim
    for m in HEX_32_64.finditer(text):
        s, e = m.span()
        window = text[max(0, s - 60) : min(len(text), e + 60)]
        if API_KEY_WORDS.search(window):
            hits.append({"type": "api_key.hex", "span": (s, e), "value": m.group()})

    # 4) JWT adayı → Authorization/Bearer/keywords yakınsa
    for m in JWT_CANDIDATE.finditer(text):
        s, e = m.span()
        window = text[max(0, s - 80) : min(len(text), e + 80)]
        if API_KEY_WORDS.search(window):
            hits.append({"type": "api_key.jwt", "span": (s, e), "value": m.group()})

    return hits


def _append_hits(hits: List[Dict], regex: re.Pattern, text: str, htype: str):
    for m in regex.finditer(text):
        hits.append({"type": htype, "span": m.span(), "value": m.group()})


def detect_all(raw_text: str) -> List[Dict]:
    """
    Combine all pattern detectors to find PII/sensitive data in the input text.
    """
    # normalize (light)
    text = normalize_whitespace(raw_text)

    hits: List[Dict] = []

    # Basic PII
    _append_hits(hits, EMAIL, text, "email")
    _append_hits(hits, GLOBAL_PHONE, text, "phone")
    _append_hits(hits, GLOBAL_IBAN, text, "iban")
    _append_hits(hits, TCKN, text, "tckn")

    # Credit card (validate with Luhn)
    for m in CC_CANDIDATE.finditer(text):
        val = m.group()
        if luhn_ok(val):
            hits.append({"type": "credit_card", "span": m.span(), "value": val})

    # Birth date
    _append_hits(hits, DOB1, text, "dob")
    _append_hits(hits, DOB2, text, "dob")

    #  Network / Device IDs
    _append_hits(hits, IPV4, text, "ipv4")
    _append_hits(hits, MAC, text, "mac")
    _append_hits(hits, IMEI, text, "imei")

    # Identities (heuristic)

    _append_hits(hits, PASSPORT, text, "passport")

    # context-dependent for driver license
    for m in DRIVER_LICENSE.finditer(text):
        s, e = m.span()
        window = text[max(0, s - 30) : min(len(text), e + 30)].lower()
        if any(k in window for k in ["ehliyet", "license", "dl#"]):
            hits.append({"type": "driver_license", "span": (s, e), "value": m.group()})

    # API Keys / Secrets
    hits.extend(find_api_secrets(text))

    # Deduplication
    # Prefer the more specific one if they fall into the same span
    deduped: List[Dict] = []
    used_spans: List[Tuple[int, int]] = []
    for h in sorted(hits, key=lambda x: (x["span"][0], -(x["span"][1] - x["span"][0]))):
        s, e = h["span"]
        if any(s < ue and e > us for (us, ue) in used_spans):
            # overlaps with an existing span
            continue
        used_spans.append((s, e))
        deduped.append(h)

    return deduped