import pytest

def _match_any_expected_type(hits, expected_types: set[str]) -> bool:
    return any(h.get("type") in expected_types for h in hits)

def test_detector_hits_align_with_dataset(dataset, category_map, supported_categories, sensitive_labels, detector_func, strict_mode, case_logger):
    """
    In dataset, for rows with label==sensitive and SUPPORTED categories,
    we expect at least one of the expected types to be hit.
    For unsupported categories:
      - STRICT=0 -> skip
      - STRICT=1 -> test failure
    """

    missing = []
    unsupported = []

    for row in dataset:
        prompt = row.get("prompt", "")
        label = row.get("label", "").lower()
        category = row.get("category", "").lower()

        if label not in sensitive_labels:
            continue

        expected_types = category_map.get(category)
        if not expected_types or category not in supported_categories:
            unsupported.append((row.get("id"), category))
            continue

        hits = detector_func(prompt)

        case_logger({
            "test": "test_detector_hits_align_with_dataset",
            "id": row.get("id"),
            "prompt": prompt,
            "expected_category": category,
            "hits": hits,
        })

        if not _match_any_expected_type(hits, expected_types):
            missing.append((row.get("id"), category, hits))
        

    if unsupported and strict_mode:
        pytest.fail(f"Unsupported categories found (STRICT=1): {unsupported}")


    assert not missing, f"Expected hit(s) missing: {missing}"