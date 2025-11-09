from __future__ import annotations
import pathlib
import yaml

def load_rules():
    p = pathlib.Path(__file__).with_name("rules.yaml")
    return yaml.safe_load(p.read_text(encoding="utf-8"))