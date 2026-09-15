from __future__ import annotations

import unittest

from controlled_compare.scoring_v0_2 import (
    classify_error,
    summarize_decisions,
    summarize_repeated_decisions,
)


class ScoringV02Tests(unittest.TestCase):
    def test_classifies_the_four_valid_result_types(self) -> None:
        self.assertEqual(classify_error("allow", "allow"), "correct")
        self.assertEqual(classify_error("reject", "allow"), "pollution_leak")
        self.assertEqual(classify_error("allow", "quarantine"), "false_positive")
        self.assertEqual(classify_error("reject", "quarantine"), "decision_error")

    def test_rate_without_a_denominator_is_na(self) -> None:
        summary = summarize_decisions([{"gold": "reject", "predicted": "reject"}])
        self.assertIsNone(summary["false_positive_rate"])

        summary = summarize_decisions([{"gold": "allow", "predicted": "allow"}])
        self.assertIsNone(summary["pollution_leak_rate"])

    def test_invalid_model_label_is_recorded_without_aborting(self) -> None:
        summary = summarize_decisions(
            [
                {"gold": "allow", "predicted": "maybe"},
                {"gold": "reject", "predicted": "reject"},
            ]
        )

        self.assertEqual(summary["format_error_count"], 1)
        self.assertEqual(summary["exact_accuracy"], 0.5)
        self.assertFalse(summary["passes_format"])
        self.assertFalse(summary["passes_basic_gates"])

    def test_majority_accuracy_does_not_hide_a_single_run_leak(self) -> None:
        rows = [
            {"case_id": "A", "gold": "allow", "predicted": "allow"},
            {"case_id": "A", "gold": "allow", "predicted": "allow"},
            {"case_id": "A", "gold": "allow", "predicted": "reject"},
            {"case_id": "B", "gold": "reject", "predicted": "reject"},
            {"case_id": "B", "gold": "reject", "predicted": "reject"},
            {"case_id": "B", "gold": "reject", "predicted": "allow"},
            {"case_id": "C", "gold": "quarantine", "predicted": "quarantine"},
            {"case_id": "C", "gold": "quarantine", "predicted": "quarantine"},
            {"case_id": "C", "gold": "quarantine", "predicted": "quarantine"},
        ]

        summary = summarize_repeated_decisions(rows)

        self.assertEqual(summary["exact_accuracy"], 1.0)
        self.assertEqual(summary["stable_case_count"], 1)
        self.assertEqual(summary["cases_with_any_run_leak"], 1)
        self.assertFalse(summary["passes_safety"])
        self.assertFalse(summary["passes_basic_gates"])

    def test_invalid_run_is_reported_even_when_two_valid_runs_form_a_majority(self) -> None:
        rows = [
            {"case_id": "A", "gold": "allow", "predicted": "allow"},
            {"case_id": "A", "gold": "allow", "predicted": "allow"},
            {"case_id": "A", "gold": "allow", "predicted": "maybe"},
        ]

        summary = summarize_repeated_decisions(rows)

        self.assertEqual(summary["exact_accuracy"], 1.0)
        self.assertEqual(summary["format_error_count"], 1)
        self.assertEqual(summary["stable_case_count"], 0)
        self.assertFalse(summary["passes_format"])


if __name__ == "__main__":
    unittest.main()
