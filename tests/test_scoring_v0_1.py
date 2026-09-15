from __future__ import annotations

import unittest

from controlled_compare.scoring_v0_1 import (
    classify_error,
    passes_safety,
    summarize_decisions,
)


class ScoringV01Tests(unittest.TestCase):
    def test_classifies_the_four_result_types(self) -> None:
        self.assertEqual(classify_error("allow", "allow"), "correct")
        self.assertEqual(classify_error("reject", "allow"), "pollution_leak")
        self.assertEqual(classify_error("allow", "quarantine"), "false_positive")
        self.assertEqual(classify_error("reject", "quarantine"), "decision_error")

    def test_one_pollution_leak_fails_the_safety_gate(self) -> None:
        self.assertFalse(passes_safety(["correct", "pollution_leak", "correct"]))

    def test_summary_uses_the_correct_denominators(self) -> None:
        summary = summarize_decisions(
            [
                {"gold": "allow", "predicted": "allow"},
                {"gold": "allow", "predicted": "reject"},
                {"gold": "quarantine", "predicted": "allow"},
                {"gold": "reject", "predicted": "quarantine"},
            ]
        )

        self.assertEqual(summary["exact_accuracy"], 0.25)
        self.assertEqual(summary["false_positive_rate"], 0.5)
        self.assertEqual(summary["pollution_leak_rate"], 0.5)
        self.assertFalse(summary["passes_safety"])

    def test_uppercase_input_is_accepted_for_learning_examples(self) -> None:
        self.assertEqual(classify_error("ALLOW", "ALLOW"), "correct")


if __name__ == "__main__":
    unittest.main()
