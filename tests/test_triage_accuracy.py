"""Accuracy regression guard for the rule-based classifier.

Three hand-labelled sets live in tests/data:
* triage_eval.jsonl    (99)  - development set the rules were tuned on
* triage_holdout.jsonl (50)  - held out at first, then used for one round of error analysis
* triage_test.jsonl    (40)  - written last; its first, untuned score was 70% fully correct

The thresholds are floors, not targets: they stop a rule change from silently regressing.
They are intentionally not 100% on the test set, which keeps it honest as a generalisation check.
"""

import json
from pathlib import Path

import pytest

from triage.classifier import classify

DATA = Path(__file__).parent / "data"


def load(name: str) -> list[dict]:
    return [json.loads(line) for line in (DATA / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def accuracy(rows: list[dict]) -> tuple[float, float]:
    results = [classify(r["text"]) for r in rows]
    category = sum(o["category"] == r["category"] for o, r in zip(results, rows)) / len(rows)
    both = sum(o["category"] == r["category"] and o["urgency"] == r["urgency"] for o, r in zip(results, rows)) / len(rows)
    return category, both


@pytest.mark.parametrize("name,min_category,min_both", [
    ("triage_eval.jsonl", 0.95, 0.95),
    ("triage_holdout.jsonl", 0.95, 0.95),
    ("triage_test.jsonl", 0.70, 0.70),
])
def test_accuracy_floor(name, min_category, min_both):
    category, both = accuracy(load(name))
    assert category >= min_category, f"{name}: category accuracy {category:.0%} < {min_category:.0%}"
    assert both >= min_both, f"{name}: category+urgency accuracy {both:.0%} < {min_both:.0%}"


def test_labels_are_valid():
    for name in ("triage_eval.jsonl", "triage_holdout.jsonl", "triage_test.jsonl"):
        for row in load(name):
            assert row["category"] in {"billing", "technical", "account", "general"}
            assert row["urgency"] in {"high", "low"}
