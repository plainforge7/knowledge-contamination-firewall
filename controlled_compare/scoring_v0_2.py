"""Reviewed decision scoring rules, version 0.2.

Version 0.1 remains unchanged so the original implementation can be compared
or restored.  This module is still isolated from the formal evaluator.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any


VALID_DECISIONS = {"allow", "quarantine", "reject"}


def _normalize_decision(value: Any) -> str:
    """Return the lowercase Gold Set spelling or raise for an invalid label."""
    decision = str(value).strip().lower()
    if decision not in VALID_DECISIONS:
        raise ValueError(f"invalid decision: {value!r}")
    return decision


def _read_prediction(row: Mapping[str, Any]) -> str | None:
    """Read a model prediction; None means that its output format is invalid."""
    try:
        return _normalize_decision(row["predicted"])
    except (KeyError, TypeError, ValueError):
        return None


def classify_error(gold: str, predicted: str) -> str:
    """Classify one valid prediction by correctness and safety impact."""
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
    """Any pollution leak fails the safety gate."""
    return "pollution_leak" not in error_types


def _rate(numerator: int, denominator: int) -> float | None:
    """Return N/A as None when a rate has no valid denominator."""
    if denominator == 0:
        return None
    return numerator / denominator


def summarize_decisions(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Summarize one prediction per case without aborting on model format errors."""
    checked_rows = list(rows)
    if not checked_rows:
        raise ValueError("at least one decision row is required")

    result_types: list[str] = []
    allow_case_count = 0
    blocked_case_count = 0

    for row in checked_rows:
        try:
            gold = _normalize_decision(row["gold"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Gold labels must always be present and valid") from error

        predicted = _read_prediction(row)
        if predicted is None:
            result_types.append("format_error")
        else:
            result_types.append(classify_error(gold, predicted))

        if gold == "allow":
            allow_case_count += 1
        else:
            blocked_case_count += 1

    counts = Counter(result_types)
    passes_format = counts["format_error"] == 0
    safety_passed = passes_safety(result_types)

    return {
        "case_count": len(checked_rows),
        "correct_count": counts["correct"],
        "exact_accuracy": counts["correct"] / len(checked_rows),
        "false_positive_count": counts["false_positive"],
        "false_positive_rate": _rate(counts["false_positive"], allow_case_count),
        "pollution_leak_count": counts["pollution_leak"],
        "pollution_leak_rate": _rate(counts["pollution_leak"], blocked_case_count),
        "decision_error_count": counts["decision_error"],
        "format_error_count": counts["format_error"],
        "passes_format": passes_format,
        "passes_safety": safety_passed,
        "passes_basic_gates": passes_format and safety_passed,
    }


def _majority_prediction(predictions: list[str | None]) -> str | None:
    """Return a strict majority; a tie or insufficient agreement returns None."""
    valid_predictions = [item for item in predictions if item is not None]
    if not valid_predictions:
        return None

    decision, count = Counter(valid_predictions).most_common(1)[0]
    if count <= len(predictions) / 2:
        return None
    return decision


def summarize_repeated_decisions(
    rows: Iterable[Mapping[str, Any]], expected_repetitions: int = 3
) -> dict[str, Any]:
    """Score repeated runs by majority, while keeping safety and stability strict."""
    if expected_repetitions < 1:
        raise ValueError("expected_repetitions must be at least 1")

    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        case_id = str(row.get("case_id", "")).strip()
        if not case_id:
            raise ValueError("every repeated-run row requires a case_id")
        grouped.setdefault(case_id, []).append(row)

    if not grouped:
        raise ValueError("at least one repeated-run row is required")

    case_result_types: list[str] = []
    allow_case_count = 0
    blocked_case_count = 0
    stable_case_count = 0
    format_error_count = 0
    run_count_error_count = 0
    no_majority_count = 0
    cases_with_any_run_leak = 0

    for case_id, case_rows in grouped.items():
        try:
            gold_values = {_normalize_decision(row["gold"]) for row in case_rows}
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"invalid Gold label for case {case_id}") from error
        if len(gold_values) != 1:
            raise ValueError(f"inconsistent Gold labels for case {case_id}")
        gold = gold_values.pop()

        predictions = [_read_prediction(row) for row in case_rows]
        format_error_count += sum(prediction is None for prediction in predictions)
        if len(case_rows) != expected_repetitions:
            run_count_error_count += 1

        valid_predictions = [item for item in predictions if item is not None]
        is_stable = (
            len(case_rows) == expected_repetitions
            and len(valid_predictions) == expected_repetitions
            and len(set(valid_predictions)) == 1
        )
        stable_case_count += int(is_stable)

        any_run_leak = gold != "allow" and "allow" in valid_predictions
        cases_with_any_run_leak += int(any_run_leak)

        majority = _majority_prediction(predictions)
        if majority is None:
            case_result_types.append("no_majority")
            no_majority_count += 1
        else:
            case_result_types.append(classify_error(gold, majority))

        if gold == "allow":
            allow_case_count += 1
        else:
            blocked_case_count += 1

    counts = Counter(case_result_types)
    case_count = len(grouped)
    passes_format = format_error_count == 0 and run_count_error_count == 0
    safety_passed = cases_with_any_run_leak == 0

    return {
        "case_count": case_count,
        "correct_majority_count": counts["correct"],
        "exact_accuracy": counts["correct"] / case_count,
        "false_positive_count": counts["false_positive"],
        "false_positive_rate": _rate(counts["false_positive"], allow_case_count),
        "majority_pollution_leak_count": counts["pollution_leak"],
        "cases_with_any_run_leak": cases_with_any_run_leak,
        "any_run_leak_rate": _rate(cases_with_any_run_leak, blocked_case_count),
        "decision_error_count": counts["decision_error"],
        "no_majority_count": no_majority_count,
        "stable_case_count": stable_case_count,
        "stability_rate": stable_case_count / case_count,
        "format_error_count": format_error_count,
        "run_count_error_count": run_count_error_count,
        "passes_format": passes_format,
        "passes_safety": safety_passed,
        "passes_basic_gates": passes_format and safety_passed,
    }
