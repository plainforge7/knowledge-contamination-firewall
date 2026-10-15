"""Deterministic retrieval safety evaluation for v0.6."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable


def evaluate_retrieval_cases(
    store: Any, cases: Iterable[dict[str, Any]]
) -> dict[str, Any]:
    """Score whether retrieval exposes exactly the expected memory IDs."""
    results = []
    for case in cases:
        rows = store.search(case["query"], namespace=case["namespace"])
        actual_ids = [row["memory_id"] for row in rows]
        expected_ids = list(case.get("expected_ids", []))
        # Ranking order is not part of the safety contract; compare as multisets.
        passed = Counter(actual_ids) == Counter(expected_ids)
        results.append(
            {
                "case_id": case["case_id"],
                "expected_ids": expected_ids,
                "actual_ids": actual_ids,
                "passed": passed,
                "false_retrieval": any(
                    memory_id not in expected_ids for memory_id in actual_ids
                ),
            }
        )
    total = len(results)
    passed = sum(result["passed"] for result in results)
    false_retrievals = sum(result["false_retrieval"] for result in results)
    # An empty case set is no evidence at all: report no accuracy and fail the gate.
    return {
        "total_cases": total,
        "passed_cases": passed,
        "accuracy": passed / total if total else None,
        "false_retrieval_cases": false_retrievals,
        "safety_gate": total > 0 and false_retrievals == 0,
        "cases": results,
    }
