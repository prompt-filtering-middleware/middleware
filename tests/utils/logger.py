import os, json, csv, datetime, hashlib
from collections import Counter

RESULTS_DIR = "test_results"
os.makedirs(RESULTS_DIR, exist_ok=True)

def _path(name): 
    return os.path.join(RESULTS_DIR, name)

def save_metric(run_name, accuracy, matched, total, note=None, extra=None):
    ts = datetime.datetime.utcnow().isoformat()
    record = {
        "timestamp": ts,
        "run_name": run_name,
        "accuracy": None if accuracy is None else float(accuracy),
        "matched": int(matched),
        "total": int(total),
        "note": note or "",
    }
    if isinstance(extra, dict):
        record.update(extra)

    with open(_path("results.jsonl"), "a") as f:
        f.write(json.dumps(record) + "\n")

    csv_file = _path("results.csv")
    new = not os.path.exists(csv_file)
    with open(csv_file, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(record.keys()))
        if new:
            writer.writeheader()
        writer.writerow(record)

    print(f"Results saved → {csv_file}")

def save_sample(record: dict, filename="samples.jsonl"):
    """Detailed log per sample (JSONL)."""
    with open(_path(filename), "a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def save_counters(run_name, counters: dict, filename="counters.json"):
    """Counter -> JSON (total counts)."""

    out = {"run_name": run_name, "counters": {}}
    for k, c in counters.items():
        if isinstance(c, Counter):
            out["counters"][k] = dict(c.most_common())
        else:
            out["counters"][k] = c
    with open(_path(filename), "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"Counters saved → {filename}")

def text_digest(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def excerpt(s: str, n=160) -> str:
    s = s.replace("\n", " ")
    return s[:n] + ("…" if len(s) > n else "")