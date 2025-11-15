import json
from pathlib import Path
import pytest
import requests

DATASET_PATH = Path("").resolve()
API_URL = "http://localhost:8000/moderate"

LOG_PATH = Path(__file__).resolve().parent.parent / "artifacts" / "mismatches.jsonl"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def load_dataset():
    with DATASET_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


CASES = [pytest.param(case, id=str(case["id"])) for case in load_dataset()]


def extract_label_category(data: dict):

    if "label" in data and "category" in data:
        return data.get("label"), data.get("category")

    detail = data.get("detail")
    if isinstance(detail, dict):
        return detail.get("label"), detail.get("category")


    return None, None


@pytest.mark.parametrize("case", CASES)
def test_compare_backend_results(case):
    i = 0
    expected_label = case["label"]
    expected_category = case["category"]

    resp = requests.post(API_URL, json={"text": case["prompt"]})

    try:
        data = resp.json()
    except Exception:
        data = {}

    actual_label, actual_category = extract_label_category(data)

    if actual_label != expected_label:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps({
                "id": case["id"],
                "expected_label": expected_label,
                "actual_label": actual_label,

                "expected_category": expected_category,
                "actual_category": actual_category,
            }, ensure_ascii=False))
            f.write("\n")


        pytest.fail(
            f"Mismatch for id={case['id']}: "
            f"expected=({expected_label}, {expected_category}), "
            f"actual=({actual_label}, {actual_category})"
        )
    i += 1

    if i == 10000:
        return


