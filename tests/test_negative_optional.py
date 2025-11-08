import pytest

NON_SENSITIVE_LABELS = {"non_sensitive", "benign", "public"}

def test_non_sensitive_not_flagged(dataset, client):
    samples = [r for r in dataset if (r.get("label","").lower() in NON_SENSITIVE_LABELS)]
    if not samples:
        pytest.skip("No non_sensitive samples in dataset")

    flagged = []
    for row in samples:
        prompt = row.get("prompt", "")
        res = client.post("/moderate", json={"text": prompt})
        if res.status_code == 422:
            flagged.append((row.get("id"), "blocked"))
        else:
            action = res.json().get("action")
            if action not in {"allow", "warn"}:
                flagged.append((row.get("id"), action))

    assert not flagged, f"False positives: {flagged}"