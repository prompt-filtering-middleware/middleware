import json
import os
from pathlib import Path
import pytest
import logging
import time


from fastapi.testclient import TestClient

from app.main import app
from app.detectors.patterns import detect_all

DATASET_ENV = "TEST_DATASET"
DEFAULT_DATASET_PATH = Path(__file__).parent / "data" / "synthetic_prompt_dataset_crop.json"


CATEGORY_TO_DETECTOR = {
    "credit_card": {"card", "credit_card"},
    "phone": {"phone", "tel"},
    "email": {"email"},
    "iban": {"iban"},
    "tckn": {"tckn"},
    "jwt": {"jwt", "token"},
    "api_key": {"api_key", "secret", "aws_key"},
}

SUPPORTED_CATEGORIES = {k for k, v in CATEGORY_TO_DETECTOR.items() if v}

SENSITIVE_LABELS = {"sensitive", "high_risk", "private"}
NON_SENSITIVE_LABELS = {"non_sensitive", "benign", "public"}

@pytest.fixture(scope="session")
def dataset_path() -> Path:
    custom = os.environ.get(DATASET_ENV)
    return Path(custom) if custom else DEFAULT_DATASET_PATH

@pytest.fixture(scope="session")
def dataset(dataset_path: Path):
    assert dataset_path.exists(), f"Dataset bulunamadı: {dataset_path}"
    with open(dataset_path, "r", encoding="utf-8") as f:
        return json.load(f)

@pytest.fixture(scope="session")
def client():
    return TestClient(app)

@pytest.fixture(scope="session")
def category_map():
    return CATEGORY_TO_DETECTOR

@pytest.fixture(scope="session")
def supported_categories():
    return SUPPORTED_CATEGORIES

@pytest.fixture(scope="session")
def sensitive_labels():
    return SENSITIVE_LABELS

@pytest.fixture(scope="session")
def non_sensitive_labels():
    return NON_SENSITIVE_LABELS

@pytest.fixture(scope="session")
def strict_mode():
    return os.environ.get("TEST_STRICT", "0") == "1"

@pytest.fixture(scope="session")
def detector_func():
    return detect_all

logger = logging.getLogger("cases")

@pytest.fixture(scope="session")
def cases_log_path(tmp_path_factory):

    logs_dir = Path("tests/logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    return logs_dir / f"run-{ts}.jsonl"

@pytest.fixture(scope="session")
def case_logger(cases_log_path):
    def _write(event: dict):
        event = {**event, "_ts": time.time()}
        with open(cases_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        
        logging.getLogger("cases").info(
            "%s | id=%s | cat=%s | action=%s | exp=%s",
            event.get("test"),
            event.get("id"),
            event.get("expected_category"),
            event.get("response", {}).get("action") or event.get("http_status"),
            event.get("expected_label"),
        )
    return _write