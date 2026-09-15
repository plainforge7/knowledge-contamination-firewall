from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from incident_reproductions.hermes_17164 import (
    classify_marshal_tag,
    run_guarded_status_protocol,
    run_unsafe_recall_first,
    seed_fixture,
)
from incident_reproductions.hermes_2670 import (
    TRIGGERS,
    run_buggy_flush,
    run_firewall_revision_guard,
    run_reference_prompt_fix,
)
from incident_reproductions.openviking_4193 import run_reproduction as run_4193


class OpenViking4193Tests(unittest.TestCase):
    def test_bug_creates_silent_split_brain(self) -> None:
        result = run_4193()
        buggy = result["buggy"]
        fields = buggy["persisted_structured_fields"]
        self.assertTrue(buggy["commit_completed_without_exception"])
        self.assertTrue(buggy["split_brain"])
        self.assertEqual(fields["owner"], "Alice")
        self.assertEqual(fields["status"], "open")
        self.assertEqual(fields["due_at"], "2026-09-08")

    def test_absent_replace_field_still_adds(self) -> None:
        self.assertTrue(run_4193()["buggy"]["absent_replace_field_added"])

    def test_fixed_filter_preserves_only_immutable(self) -> None:
        fixed = run_4193()["fixed"]
        fields = fixed["persisted_structured_fields"]
        self.assertTrue(fixed["markdown_and_structured_agree"])
        self.assertTrue(fixed["immutable_preserved"])
        self.assertTrue(fixed["sum_increment_applied"])
        self.assertEqual(fields["owner"], "Bob")
        self.assertEqual(fields["details"]["priority"], "high")


class Hermes2670Tests(unittest.TestCase):
    def test_all_reported_lifecycle_triggers_reproduce_overwrite(self) -> None:
        for trigger in TRIGGERS:
            with self.subTest(trigger=trigger):
                result = run_buggy_flush(trigger)
                self.assertTrue(result["commit_completed_without_conflict"])
                self.assertTrue(result["newer_owner_reverted"])
                self.assertTrue(result["canary_disappeared"])

    def test_merged_prompt_fix_preserves_current_memory(self) -> None:
        result = run_reference_prompt_fix("gateway_restart")
        self.assertTrue(result["current_memory_injected"])
        self.assertEqual(result["after"]["entries"]["owner"], "Bob")
        self.assertEqual(result["after"]["entries"]["canary"], "new-live-entry")

    def test_cron_session_bypasses_flush(self) -> None:
        result = run_reference_prompt_fix("session_reset", "cron_daily")
        self.assertEqual(result["decision"], "skip_cron_flush")
        self.assertFalse(result["transcript_loaded"])
        self.assertEqual(result["before"], result["after"])

    def test_firewall_hard_guard_rejects_stale_revision(self) -> None:
        result = run_firewall_revision_guard("gateway_restart")
        self.assertEqual(result["decision"], "reject_stale_write")
        self.assertEqual(result["before"], result["after"])


class Hermes17164Tests(unittest.TestCase):
    def test_recall_first_path_misreports_and_mutates_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = seed_fixture(Path(temp_dir))
            result = run_unsafe_recall_first(paths)
            self.assertEqual(result["reported_phase_a"], "not_started")
            self.assertFalse(result["git_checked_before_claim"])
            self.assertIn("STATUS.md", result["files_mutated_before_verified_baseline"])
            self.assertIn(
                "runtime/hermes_bridge.py",
                result["files_mutated_before_verified_baseline"],
            )

    def test_guarded_path_prefers_current_evidence_without_discovery_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = seed_fixture(Path(temp_dir))
            result = run_guarded_status_protocol(paths, continue_requested=True)
            self.assertTrue(result["baseline_verified"])
            self.assertEqual(result["reported_phase_a"], "completed")
            self.assertEqual(result["next_phase"], "Phase B")
            self.assertFalse(result["mutated_during_status_discovery"])
            self.assertEqual(
                result["contradiction"]["resolution"],
                "current git/disk/tests outrank stale session recall",
            )

    def test_unresolved_or_dirty_baseline_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = seed_fixture(Path(temp_dir))
            result_path = paths.project / "test-results.json"
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            payload["targeted_regression"] = "failed"
            result_path.write_text(json.dumps(payload), encoding="utf-8")
            result = run_guarded_status_protocol(paths, continue_requested=True)
            self.assertFalse(result["baseline_verified"])
            self.assertFalse(result["may_mutate_after_discovery"])
            self.assertEqual(result["write_gate"], "closed_unresolved_baseline")
            self.assertFalse(result["mutated_during_status_discovery"])

    def test_0xe3_does_not_itself_prove_corruption(self) -> None:
        result = classify_marshal_tag(0xE3)
        self.assertTrue(result["is_code_tag"])
        self.assertTrue(result["has_reference_flag"])
        self.assertFalse(result["corruption_proven"])


if __name__ == "__main__":
    unittest.main()

