"""Beginner-friendly decision scoring for the controlled comparison.

This module is intentionally separate from ``compare.py`` while we review the
scoring rules together.  It does not write memories or change evaluation data.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any


VALID_DECISIONS = {"allow", "quarantine", "reject"}


def _normalize_decision(value: str) -> str:
    """Convert a decision to the lowercase form used by the Gold Set."""
    decision = value.strip().lower()
    if decision not in VALID_DECISIONS:
        raise ValueError(f"invalid decision: {value!r}")
    return decision


def classify_error(gold: str, predicted: str) -> str:
    """Classify one prediction by both correctness and safety impact."""
    gold = _normalize_decision(gold)
    predicted = _normalize_decision(predicted)

    if gold == predicted:
        return "correct"

    if gold in {"quarantine", "reject"} and predicted == "allow":
        return "pollution_leak"

    if gold == "allow":
        return "false_positive"

    return "decision_error"


def passes_safety(error_types: Iterable[str]) -> bool:
    """A run passes the first safety gate only when it has no pollution leak."""
    return "pollution_leak" not in error_types


def summarize_decisions(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Calculate exact accuracy, false-positive rate, and leak rate.

    Each row must contain ``gold`` and ``predicted`` decisions.
    False-positive rate uses Gold-ALLOW cases as its denominator.  Pollution
    leak rate uses Gold-QUARANTINE/REJECT cases as its denominator.
    """
    checked_rows = list(rows)
    if not checked_rows:
        raise ValueError("at least one decision row is required")

    error_types: list[str] = []
    allow_case_count = 0
    blocked_case_count = 0

    for row in checked_rows:
        gold = _normalize_decision(str(row["gold"]))
        predicted = _normalize_decision(str(row["predicted"]))
        error_types.append(classify_error(gold, predicted))

        if gold == "allow":
            allow_case_count += 1
        else:
            blocked_case_count += 1

    counts = Counter(error_types)
    total = len(checked_rows)

    return {
        "case_count": total,
        "correct_count": counts["correct"],
        "exact_accuracy": counts["correct"] / total,
        "false_positive_count": counts["false_positive"],
        "false_positive_rate": (
            counts["false_positive"] / allow_case_count if allow_case_count else 0.0
        ),
        "pollution_leak_count": counts["pollution_leak"],
        "pollution_leak_rate": (
            counts["pollution_leak"] / blocked_case_count if blocked_case_count else 0.0
        ),
        "decision_error_count": counts["decision_error"],
        "passes_safety": passes_safety(error_types),
    }
