import argparse, json, os, sys, time
from pathlib import Path

import requests

DEF_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8000")
MODERATE_URL = f"{DEF_URL.rstrip('/')}/moderate"

def load_dataset(path_or_json: str):
    p = Path(path_or_json)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))

    if path_or_json == "-":
        return json.load(sys.stdin)

    return json.loads(path_or_json)

def call_moderate(prompt: str):
    try:
        r = requests.post(MODERATE_URL, json={"text": prompt}, timeout=30)
    except Exception as e:
        return {
            "status_code": None,
            "error": f"request_error: {e}",
            "action": None,
            "label": None,
            "category": None,
            "hits": [],
            "warnings": [str(e)],
        }

    if r.status_code == 200:
        body = r.json()
        return {
            "status_code": 200,
            "action": body.get("action"),
            "label": body.get("label"),
            "category": body.get("category"),
            "text": body.get("text"),
            "hits": body.get("hits", []),
            "warnings": body.get("warnings", []),
        }

    if r.status_code == 422:
        detail = r.json().get("detail", {})
        return {
            "status_code": 422,
            "action": "block",
            "label": detail.get("label"),
            "category": detail.get("category"),
            "text": detail.get("suggested_text"),
            "hits": detail.get("hits", []),
            "warnings": detail.get("warnings", []),
            "enforcement": detail.get("enforcement"),
            "msg": detail.get("msg"),
        }

    return {
        "status_code": r.status_code,
        "error": f"unexpected_status: {r.status_code}",
        "raw": r.text,
        "action": None,
        "label": None,
        "category": None,
        "hits": [],
        "warnings": [],
    }

def format_txt_line(row_id, prompt, expected_label, expected_cat, res):
    sc = res.get("status_code")
    action = res.get("action")
    label = res.get("label")
    category = res.get("category")
    warn = res.get("warnings") or []
    wtxt = "; ".join(warn) if warn else "-"
    return (
        f"[{row_id:>3}] status={sc} | action={action} | label={label} | cat={category} "
        f"| expected=({expected_label},{expected_cat})\n"
        f"     prompt: {prompt}\n"
        f"     warnings: {wtxt}\n"
    )

def main():
    ap = argparse.ArgumentParser(description="Run dataset prompts against /moderate and save results.")
    ap.add_argument("dataset", help="JSON path, '-' for stdin, or raw JSON string")
    ap.add_argument("--out", default="results.txt", help="TXT output path (default: results.txt)")
    ap.add_argument("--jsonl", default="results.jsonl", help="JSONL output path (default: results.jsonl)")
    ap.add_argument("--url", default=DEF_URL, help=f"Gateway base URL (default: {DEF_URL})")
    ap.add_argument("--sleep", type=float, default=0.0, help="Sleep seconds between requests")
    args = ap.parse_args()

    global MODERATE_URL
    MODERATE_URL = f"{args.url.rstrip('/')}/moderate"

    data = load_dataset(args.dataset)
    if not isinstance(data, list):
        print("Dataset bir liste olmalı.", file=sys.stderr)
        sys.exit(1)

    out_txt = Path(args.out)
    out_jsonl = Path(args.jsonl)

    out_txt.write_text("", encoding="utf-8")
    out_jsonl.write_text("", encoding="utf-8")

    with out_txt.open("a", encoding="utf-8") as ftxt, out_jsonl.open("a", encoding="utf-8") as fjl:
        for row in data:
            row_id = row.get("id")
            prompt = row.get("prompt", "")
            exp_label = row.get("label")
            exp_cat = row.get("category")

            res = call_moderate(prompt)

            ftxt.write(format_txt_line(row_id, prompt, exp_label, exp_cat, res))
            ftxt.write("-" * 120 + "\n")

            record = {
                "id": row_id,
                "prompt": prompt,
                "expected_label": exp_label,
                "expected_category": exp_cat,
                "result": res,
            }
            fjl.write(json.dumps(record, ensure_ascii=False) + "\n")

            if args.sleep > 0:
                time.sleep(args.sleep)

    print(f"{out_txt} and {out_jsonl}")

if __name__ == "__main__":
    main()