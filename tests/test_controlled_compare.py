from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from controlled_compare.compare import (
    DryRunAdapter,
    _execute_in_transaction_sandbox,
    _public_case,
    load_cases,
    run_comparison,
    select_architecture,
    validate_cases,
)


class ControlledCompareTests(unittest.TestCase):
    def test_case_counts_distribution_and_synthetic_policy(self) -> None:
        cases = load_cases()
        validate_cases(cases)
        self.assertEqual(sum(case["layer"] == "semantic" for case in cases), 20)
        self.assertEqual(sum(case["layer"] == "system" for case in cases), 11)

    def test_gold_is_removed_before_model_call(self) -> None:
        case = load_cases()[0]
        public = _public_case(case)
        self.assertNotIn("gold", public)
        self.assertNotIn("provenance", public)

    def test_dry_run_source_labels_are_bound_to_evidence_ids(self) -> None:
        case = load_cases()[0]
        output = DryRunAdapter()._final(case)
        self.assertEqual(output["source_labels"][0]["evidence_id"], "utterance")
        self.assertEqual(output["source_labels"][0]["source_type"], "user_direct")

    def test_polluted_allow_causes_real_sandbox_hard_failure(self) -> None:
        case = next(case for case in load_cases() if case["case_id"] == "PM-020")
        unsafe_output = {
            "decision": "allow",
            "memory_patch": case["input"]["proposed_memory_patch"],
            "action_codes": [],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            result = _execute_in_transaction_sandbox(case, unsafe_output, Path(temp_dir))
        self.assertTrue(result["state_changed"])
        self.assertTrue(result["dangerous_write"])
        self.assertIn("memory_write", result["executed_mutations"])

    def test_dry_run_exercises_both_tracks_and_arms_but_is_invalid(self) -> None:
        result = run_comparison(DryRunAdapter(), equal_token_budget=4096, per_call_output_limit=1024)
        self.assertFalse(result["evaluation_valid"])
        self.assertEqual(set(result["scores"]), {"equal_budget", "natural_budget"})
        self.assertEqual(set(result["scores"]["equal_budget"]), {"single", "multi"})
        self.assertEqual(len(result["raw_runs"]["equal_budget"]), 31 * 3 * 2)

    def test_selection_never_picks_relative_best_when_both_fail(self) -> None:
        failing = {
            "single": {"qualifies": False, "semantic": {"exact_decisions": 15, "false_positives": 1, "stable_cases": 20}},
            "multi": {"qualifies": False, "semantic": {"exact_decisions": 16, "false_positives": 0, "stable_cases": 20}},
        }
        result = select_architecture(failing, failing)
        self.assertEqual(result["status"], "no_qualified_architecture")

    def test_multi_candidate_requires_two_equal_budget_cases(self) -> None:
        equal = {
            "single": {"qualifies": True, "semantic": {"exact_decisions": 17, "false_positives": 1, "stable_cases": 18}},
            "multi": {"qualifies": True, "semantic": {"exact_decisions": 19, "false_positives": 1, "stable_cases": 19}},
        }
        natural = json.loads(json.dumps(equal))
        result = select_architecture(equal, natural)
        self.assertEqual(result["status"], "multi_candidate_cost_review_required")

    def test_result_can_be_serialized(self) -> None:
        result = run_comparison(DryRunAdapter(), equal_token_budget=4096, per_call_output_limit=1024)
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "result.json"
            path.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
            self.assertTrue(path.stat().st_size > 0)


if __name__ == "__main__":
    unittest.main()
