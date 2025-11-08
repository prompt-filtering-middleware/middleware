import re


CATEGORY_REGEX = {
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "phone": re.compile(r"\+?\d[\d\-\s]{7,}\d"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "tckn": re.compile(r"\b[1-9]\d{10}\b"),
    "jwt": re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "api_key": re.compile(r"\b(api[_-]?key|secret|token|access[_-]?key|private[_-]?key|secret[_-]?key|bearer|authorization)[\s:=]+[A-Za-z0-9-_./+]{16,}\b", re.IGNORECASE),
}

def test_mask_removes_sensitive_surface_patterns(dataset, client, supported_categories):
    failures = []

    for row in dataset:
        prompt = row.get("prompt", "")
        category = row.get("category", "").lower()
        if category not in supported_categories:
            continue

        res = client.post("/moderate", json={"text": prompt})
        if res.status_code != 200:
            continue

        body = res.json()
        if body.get("action") != "mask":
            continue

        masked_text = body.get("text", "")
        rx = CATEGORY_REGEX.get(category)
        if rx and rx.search(masked_text):
            failures.append((row.get("id"), category, masked_text))

    assert not failures, f"After masking, found sensitive patterns: {failures}"