import pytest
import json



SENSITIVE_ACTIONS = {"warn", "mask", "block"}
NON_SENSITIVE_ACTIONS = {"allow", "warn"}

def test_moderate_endpoint_respects_labels(dataset, client, sensitive_labels, non_sensitive_labels, category_map, supported_categories, strict_mode, case_logger):
    missing_sensitive = []
    wrong_nonsensitive = []
    unsupported = []

    for row in dataset:
        prompt = row.get("prompt", "")
        label = row.get("label", "").lower()
        category = row.get("category", "").lower()


        if (category_map.get(category) is None) or (category not in supported_categories):
            unsupported.append((row.get("id"), category))
            continue

        res = client.post("/moderate", json={"text": prompt})
        http_status = res.status_code
        if res.status_code == 422:
            action = "block"
        else:
            assert res.status_code == 200, f"Unexpected status code: {res.status_code}, body={res.text}"
            action = res.json().get("action")

        case_logger({
            "test": "test_moderate_endpoint_respects_labels",
            "id": row.get("id"),
            "prompt": prompt,
            "expected_label": ("sensitive" if label in sensitive_labels else
                               "non_sensitive" if label in non_sensitive_labels else "unknown"),
            "expected_category": category,
            "http_status": http_status,
            "response": res.json(),
        })

        assert action in {"allow", "warn", "mask", "block"}

        if label in sensitive_labels:
            if action not in SENSITIVE_ACTIONS:
                missing_sensitive.append((row.get("id"), label, category, action))
        elif label in non_sensitive_labels:
            if action not in NON_SENSITIVE_ACTIONS:
                wrong_nonsensitive.append((row.get("id"), label, category, action))
        else:
            continue

    if unsupported and strict_mode:
        pytest.fail(f"Unsupported categories found (STRICT=1): {unsupported}")

    assert not missing_sensitive, f"Expected hit(s) missing: {missing_sensitive}"
    assert not wrong_nonsensitive, f"Expected hit(s) missing: {wrong_nonsensitive}"