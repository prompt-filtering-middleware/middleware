import os
import pytest
from collections import Counter
from datasets import load_dataset

from app.detectors.patterns import detect_all
from app.actions.masker import mask_all
from tests.utils.logger import (
    save_metric, save_sample, save_counters, text_digest, excerpt
)

# Config
DATASET_NAME = os.getenv("HF_DATASET", "gretelai/synthetic_pii_finance_multilingual")
SAMPLE_TRIES = [int(x) for x in os.getenv("HF_SAMPLE_TRIES", "1000,3000,7000").split(",")]
RUN_NAME = os.getenv("RUN_NAME", "hf_live_test")
MIN_ACCURACY = float(os.getenv("MIN_ACCURACY", "0.5"))
LOG_SAMPLES_LIMIT = int(os.getenv("LOG_SAMPLES_LIMIT", "200"))  # at most this many samples will be logged
LOG_ALL_SAMPLES = os.getenv("LOG_ALL_SAMPLES", "0") == "1"      # if 1, log all samples even if no label

ENTITY_MAP = {
    "email_address": "email", "email":"email", "EMAIL":"email",
    "phone_number":"phone","telephone":"phone","mobile":"phone","PHONE":"phone",
    "iban":"iban","bank_account":"iban","IBAN":"iban",
    "credit_card":"credit_card","card_number":"credit_card","CREDIT_CARD":"credit_card",
    "ssn":"tckn","passport":"passport",
    "person_name": None, "name": None, "NAME": None,
    "location": None, "address": None,
}

def _extract_text(row):
    for key in ("text", "sentence", "utterance", "content", "document"):
        if key in row and isinstance(row[key], str) and row[key].strip():
            return row[key]
    return str(row)

def _extract_raw_labels(row):
    for key in ("entities", "labels", "spans"):
        if key in row:
            raw = row[key]
            break
    else:
        return []

    labs = []
    if isinstance(raw, list):
        for it in raw:
            if isinstance(it, str):
                labs.append(it)
            elif isinstance(it, dict):
                lab = it.get("label") or it.get("entity") or it.get("type")
                if lab: labs.append(lab)
            elif isinstance(it, tuple) and len(it) >= 3:
                labs.append(str(it[2]))
    return labs

def _map_labels(raw_labs):
    mapped = []
    for lab in raw_labs:
        ml = ENTITY_MAP.get(lab)
        if ml:
            mapped.append(ml)
    return list(set(mapped))

def _normalize_detect_types(hits):
    return sorted({h["type"].split(".")[0] for h in hits})

def _load_any_labeled_split():
    last_samples = []
    for n in SAMPLE_TRIES:
        ds = load_dataset(DATASET_NAME, split=f"train[:{n}]")
        samples = []
        for row in ds:
            text = _extract_text(row)
            raw_labs = _extract_raw_labels(row)
            mapped = _map_labels(raw_labs)
            samples.append({"text": text, "raw_labels": raw_labs, "labels": mapped})
        if any(s["labels"] for s in samples):
            return samples
        last_samples = samples
    return last_samples

@pytest.fixture(scope="session")
def hf_samples():
    return _load_any_labeled_split()

def test_detection_against_hf_dataset(hf_samples):
    raw_label_counter = Counter()
    mapped_label_counter = Counter()
    detected_counter = Counter()
    intersection_counter = Counter()

    matches = 0
    total = 0
    sample_logs_written = 0

    for idx, sample in enumerate(hf_samples):
        text = sample["text"]
        raw_labs = sample.get("raw_labels", [])
        mapped_labs = sample.get("labels", [])
        for rl in raw_labs:
            raw_label_counter[rl] += 1
        for ml in mapped_labs:
            mapped_label_counter[ml] += 1

        hits = detect_all(text)
        detected = _normalize_detect_types(hits)
        for dt in detected:
            detected_counter[dt] += 1

        if mapped_labs:
            total += 1
            inter = sorted(set(mapped_labs) & set(detected))
            if inter:
                matches += 1
                for it in inter:
                    intersection_counter[it] += 1

        if LOG_ALL_SAMPLES or mapped_labs or detected:
            if sample_logs_written < LOG_SAMPLES_LIMIT:
                masked_excerpt = mask_all(text, hits) if hits else None
                save_sample({
                    "i": idx,
                    "text_sha1": text_digest(text),
                    "text_excerpt": excerpt(text, 160),
                    "text": text,
                    "raw_labels": raw_labs,
                    "labels_mapped": mapped_labs,
                    "detected": detected,
                    "intersection": sorted(set(mapped_labs) & set(detected)),
                    "hits_count": len(hits),
                    "masked_excerpt": excerpt(masked_excerpt, 160) if masked_excerpt else None,
                })
                sample_logs_written += 1

    # Result & assertions
    if total == 0:
        # No labeled samples found → write counters/clusters to understand why
        save_counters(RUN_NAME, {
            "raw_labels_seen": raw_label_counter,
            "mapped_labels_seen": mapped_label_counter,
            "detected_seen": detected_counter,
            "intersection_seen": intersection_counter,
            "hf_samples_total": len(hf_samples),
        })
        save_metric(RUN_NAME, None, 0, 0, note="no_label_found_in_slice", extra={
            "hf_samples_total": len(hf_samples),
            "raw_label_keys_count": len(raw_label_counter),
            "mapped_label_keys_count": len(mapped_label_counter),
            "detected_keys_count": len(detected_counter),
        })
        pytest.skip("No mappable labels found in HF slice (total==0).")

    accuracy = matches / total
    print(f"\nAccuracy: {accuracy:.3f} (matches {matches}/{total})")

    save_counters(RUN_NAME, {
        "raw_labels_seen": raw_label_counter,
        "mapped_labels_seen": mapped_label_counter,
        "detected_seen": detected_counter,
        "intersection_seen": intersection_counter,
        "hf_samples_total": len(hf_samples),
    })
    save_metric(RUN_NAME, accuracy, matches, total, extra={
        "hf_samples_total": len(hf_samples),
        "raw_label_keys_count": len(raw_label_counter),
        "mapped_label_keys_count": len(mapped_label_counter),
        "detected_keys_count": len(detected_counter),
    })

    assert accuracy >= MIN_ACCURACY, f"Accuracy {accuracy:.3f} < {MIN_ACCURACY}"