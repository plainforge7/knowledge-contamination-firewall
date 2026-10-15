"""Regression tests for the v0.3.1 safety fixes.

Covers: audit key collisions, denied-memory terminality, memory search matching,
fail-closed decisions that must never soften a deny, null-field contract checks,
and the single-HTTP-attempt transport contract.
"""

from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from controlled_compare import bailian_adapter_v0_3 as bailian_v0_3
from controlled_compare import compare_v0_3 as runner_v0_3
from controlled_compare import firewall_v0_3 as firewall
from controlled_compare.audit_store import import_jsonl, init_db
from controlled_compare.memory_store_v0_5 import MemoryStore
from controlled_compare.review_queue_v0_7 import ReviewQueue


def _audit_record(*, evaluation_valid: bool, execution_id: str, final: str) -> dict:
    return {
        "protocol_version": "0.3",
        "execution_id": execution_id,
        "dataset": "semantic-gold",
        "evaluation_valid": evaluation_valid,
        "case_id": "PM-001",
        "repetition": 1,
        "arm": "single",
        "response_usable": True,
        "audit_trace": {
            "trace_version": "0.4.0-audit-trace",
            "route": "single",
            "decision": {"base": "permit", "final": final, "audit_status": "complete"},
            "failure": {"category": "none", "retriable": False},
            "execution": {
                "planned_destination": "sandbox",
                "actual_destination": "sandbox",
                "attempted": True,
                "committed": True,
            },
            "operations": {
                "total_tokens": 10,
                "successful_calls": 1,
                "cost_cny": 0.0,
                "cost_cny_known": True,
            },
        },
    }


def _write_jsonl(path: Path, *records: dict) -> Path:
    path.write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n",
        encoding="utf-8",
    )
    return path


def _deny_case() -> dict:
    return {
        "case_id": "T-DENY",
        "layer": "semantic",
        "provenance": {"data_policy": "synthetic_only"},
        "input": {
            "utterance": "x",
            "context": "测试文本",
            "existing_memory": {},
            "proposed_memory_patch": {"a": 1},
            "source_type": "untrusted_instruction",
            "explicit_memory_request": False,
            "risk_signals": ["prompt_injection"],
            "evidence": [{"id": "e1", "source_type": "untrusted_instruction"}],
        },
    }


def _valid_hold_proposal() -> dict:
    return {
        "write_decision": "hold",
        "evidence_ids": ["e1"],
        "source_labels": [{"evidence_id": "e1", "source_type": "untrusted_instruction"}],
        "recommended_actions": [],
        "false_positive_risk": "误判风险",
        "release_condition": "补充直接证据",
        "rollback_action": "恢复写入前版本",
        "uncertainty": "不确定",
        "patch": {
            "operation": "add",
            "target": "/",
            "value": {"k": 1},
            "scope": "test-only",
            "evidence_ids": ["e1"],
            "supersedes": [],
            "valid_from": None,
            "expires_at": None,
            "status": "proposed",
        },
    }


class AuditKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _row_count(self, db: Path) -> int:
        connection = sqlite3.connect(db)
        try:
            return connection.execute("SELECT COUNT(*) FROM audit_runs").fetchone()[0]
        finally:
            connection.close()

    def test_real_and_smoke_runs_do_not_overwrite_each_other(self) -> None:
        db = self.dir / "audit.db"
        real = _write_jsonl(
            self.dir / "real.jsonl",
            _audit_record(evaluation_valid=True, execution_id="paid", final="permit"),
        )
        smoke = _write_jsonl(
            self.dir / "smoke.jsonl",
            _audit_record(evaluation_valid=False, execution_id="dry", final="hold"),
        )
        self.assertEqual(import_jsonl(real, db), 1)
        self.assertEqual(import_jsonl(smoke, db), 1)
        self.assertEqual(self._row_count(db), 2)

    def test_reimporting_same_export_adds_nothing(self) -> None:
        db = self.dir / "audit.db"
        export = _write_jsonl(
            self.dir / "run.jsonl",
            _audit_record(evaluation_valid=True, execution_id="paid", final="permit"),
        )
        self.assertEqual(import_jsonl(export, db), 1)
        with self.assertWarns(UserWarning):
            self.assertEqual(import_jsonl(export, db), 0)
        self.assertEqual(self._row_count(db), 1)

    def test_pre_execution_id_database_is_refused(self) -> None:
        db = self.dir / "old.db"
        connection = sqlite3.connect(db)
        connection.executescript("CREATE TABLE audit_runs (id INTEGER PRIMARY KEY, x TEXT);")
        connection.commit()
        connection.close()
        with self.assertRaises(RuntimeError):
            init_db(db)


class MemoryLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = MemoryStore(Path(self._tmp.name) / "m.db")
        self.queue = ReviewQueue(self.store)
        self.namespace = "test-only/lifecycle"

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def test_denied_memory_cannot_be_approved(self) -> None:
        memory_id = self.store.add({"fields": {"summary": "x"}}, namespace=self.namespace)
        self.queue.reject(memory_id, reviewer="r1", reason="bad")
        with self.assertRaises(ValueError):
            self.queue.approve(memory_id, reviewer="r2", reason="oops")
        self.assertEqual(self.store.get(memory_id)["status"], "denied")
        self.assertEqual(self.store.search("x", namespace=self.namespace), [])

    def test_quarantine_can_be_approved_then_revoked(self) -> None:
        memory_id = self.store.add({"fields": {"summary": "x"}}, namespace=self.namespace)
        self.queue.approve(memory_id, reviewer="r1", reason="ok")
        self.assertEqual(self.store.get(memory_id)["status"], "confirmed")
        self.store.transition(memory_id, "quarantine", reason="re-review")
        self.assertEqual(self.store.get(memory_id)["status"], "quarantine")


class MemorySearchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = MemoryStore(Path(self._tmp.name) / "s.db")
        self.namespace = "test-only/search"
        for memory_id, text in [
            ("m-coffee", "喜欢咖啡"),
            ("m-axb", "axb 测试"),
            ("m-percent", "100% 纯净"),
        ]:
            self.store.add(
                {"fields": {"summary": text}},
                namespace=self.namespace,
                status="confirmed",
                memory_id=memory_id,
            )

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    def _ids(self, query: str) -> list[str]:
        return [row["memory_id"] for row in self.store.search(query, namespace=self.namespace)]

    def test_wildcards_are_literal(self) -> None:
        self.assertEqual(self._ids("a_b"), [])
        self.assertEqual(self._ids("%"), ["m-percent"])

    def test_json_keys_are_not_matched(self) -> None:
        self.assertEqual(self._ids("summary"), [])
        self.assertEqual(self._ids("fields"), [])

    def test_content_matches_case_insensitively(self) -> None:
        self.assertEqual(self._ids("咖啡"), ["m-coffee"])
        self.assertEqual(self._ids("AXB"), ["m-axb"])


class FailClosedDecisionTests(unittest.TestCase):
    def test_contract_error_keeps_deterministic_deny(self) -> None:
        result = firewall.apply_firewall(
            _deny_case(), ai_proposal={"write_decision": "permit"}, arm="single"
        )
        self.assertEqual(result["rule_decision"]["base_decision"], "deny")
        self.assertEqual(result["write_decision"], "deny")
        self.assertIsNone(result["hold_retention"])

    def test_contract_error_still_holds_a_permit_candidate(self) -> None:
        case = _deny_case()
        case["input"]["risk_signals"] = []
        case["input"]["source_type"] = "user_direct"
        case["input"]["evidence"] = [{"id": "e1", "source_type": "user_direct"}]
        result = firewall.apply_firewall(
            case, ai_proposal={"write_decision": "permit"}, arm="single"
        )
        self.assertEqual(result["write_decision"], "hold")

    def test_policy_hold_does_not_downgrade_deny(self) -> None:
        result = firewall.apply_firewall(_deny_case(), arm="baseline")
        runner_v0_3._force_policy_hold(result, "candidate_deadline_exceeded", "blocked_policy_budget_or_deadline")
        self.assertEqual(result["write_decision"], "deny")
        self.assertEqual(result["effective_actions"], list(firewall.DENY_ACTIONS))
        self.assertIsNone(result["hold_retention"])
        self.assertIn("candidate_deadline_exceeded", result["errors"]["policy"])

    def test_policy_hold_still_escalates_permit_to_hold(self) -> None:
        case = _deny_case()
        case["input"]["risk_signals"] = []
        case["input"]["source_type"] = "user_direct"
        case["input"]["evidence"] = [{"id": "e1", "source_type": "user_direct"}]
        result = firewall.apply_firewall(case, arm="baseline")
        self.assertEqual(result["write_decision"], "permit")
        runner_v0_3._force_policy_hold(result, "candidate_deadline_exceeded", "blocked_policy_budget_or_deadline")
        self.assertEqual(result["write_decision"], "hold")
        self.assertEqual(result["effective_actions"], list(firewall.HOLD_ACTIONS))
        self.assertIsNotNone(result["hold_retention"])


class ContractNullFieldTests(unittest.TestCase):
    def test_valid_fixture_has_no_errors(self) -> None:
        _, errors = firewall.validate_ai_proposal(_valid_hold_proposal(), _deny_case())
        self.assertEqual(errors, [])

    def test_null_text_field_is_rejected(self) -> None:
        proposal = _valid_hold_proposal()
        proposal["false_positive_risk"] = None
        _, errors = firewall.validate_ai_proposal(proposal, _deny_case())
        self.assertIn("false_positive_risk must be non-empty", errors)

    def test_null_target_on_writing_patch_is_rejected(self) -> None:
        proposal = _valid_hold_proposal()
        proposal["patch"]["target"] = None
        _, errors = firewall.validate_ai_proposal(proposal, _deny_case())
        self.assertIn("writing patch requires a target", errors)

    def test_unhashable_decision_is_a_contract_error_not_a_crash(self) -> None:
        proposal = _valid_hold_proposal()
        proposal["write_decision"] = ["hold"]
        _, errors = firewall.validate_ai_proposal(proposal, _deny_case())
        self.assertIn("invalid write_decision", errors)


class SingleHttpAttemptTests(unittest.TestCase):
    def _request(self) -> dict:
        return {
            "timeout_seconds": 10,
            "max_output_tokens": 100,
            "messages": [{"role": "user", "content": "hi"}],
            "metadata": {"stage": "single_final"},
            "model_config": {
                "model_id": "synthetic-model",
                "temperature": 0.2,
                "enable_thinking": False,
                "preserve_thinking": False,
                "pricing_cny_per_million_tokens": {"input": 1.0, "output": 1.0},
            },
        }

    def _environment(self) -> dict:
        return {
            "DASHSCOPE_API_KEY": "sk-ws-synthetic",
            "DASHSCOPE_BASE_URL": "https://x.ap-northeast-1.maas.aliyuncs.com/compatible-mode/v1",
        }

    def _assert_single_attempt(self, error: Exception) -> None:
        calls = {"n": 0}

        def failing_urlopen(req, timeout=None):
            calls["n"] += 1
            raise error

        with patch(
            "controlled_compare.bailian_adapter_v0_3.urllib.request.urlopen",
            side_effect=failing_urlopen,
        ):
            with self.assertRaises(type(error)):
                bailian_v0_3.call_bailian_once(self._request(), self._environment())
        self.assertEqual(calls["n"], 1)

    def test_http_401_is_not_retried(self) -> None:
        self._assert_single_attempt(urllib.error.HTTPError("https://x", 401, "Unauthorized", {}, None))

    def test_http_503_is_not_retried_inside_the_budgeted_call(self) -> None:
        self._assert_single_attempt(urllib.error.HTTPError("https://x", 503, "Unavailable", {}, None))

    def test_network_error_is_not_retried_inside_the_budgeted_call(self) -> None:
        self._assert_single_attempt(urllib.error.URLError("simulated network failure"))


class MetricsLayerTests(unittest.TestCase):
    def test_injected_failure_restores_the_live_object_in_place(self) -> None:
        memory = {"fields": {"summary": "old", "tags": ["kept"]}}
        live = memory
        candidate = {
            "operation": "replace",
            "target": "/fields/summary",
            "value": "new",
            "scope": "personal_long_term_memory",
            "evidence_ids": ["e1"],
            "supersedes": [],
            "valid_from": None,
            "expires_at": None,
            "status": "effective",
        }
        result = firewall.simulate_transaction(memory, candidate, inject_write_failure=True)
        self.assertIs(memory, live)
        self.assertTrue(result["snapshot_taken"])
        self.assertTrue(result["rolled_back"])
        self.assertEqual(memory, {"fields": {"summary": "old", "tags": ["kept"]}})

    def test_single_repetition_makes_stability_unevaluable_and_blocks_qualification(self) -> None:
        config = runner_v0_3.load_config()
        config["repetitions"] = 1
        with patch("controlled_compare.compare_v0_3.load_config", return_value=config):
            result = runner_v0_3.run_comparison(runner_v0_3.V03DryRunAdapter(), dataset="semantic-gold")
        for arm, score in result["scores"].items():
            with self.subTest(arm=arm):
                self.assertFalse(score["quality"]["stability_evaluable"])
                self.assertIsNone(score["quality"]["stability_rate"])
                self.assertFalse(score["qualifies"])
                self.assertEqual(score["hard_gates"]["dangerous_writes"], 0)
                self.assertIn("budget_noncompliant_runs", score["hard_gates"])
                self.assertNotIn("token_ceiling_violations", score["hard_gates"])

    def test_two_repetitions_make_stability_evaluable(self) -> None:
        self.assertGreaterEqual(runner_v0_3.load_config()["repetitions"], 2)
        result = runner_v0_3.run_comparison(runner_v0_3.V03DryRunAdapter(), dataset="semantic-gold")
        for arm, score in result["scores"].items():
            with self.subTest(arm=arm):
                self.assertTrue(score["quality"]["stability_evaluable"])
                self.assertIsNotNone(score["quality"]["stability_rate"])

    def test_single_arm_short_circuits_deterministic_deny_without_model_calls(self) -> None:
        class CountingAdapter(runner_v0_3.V03DryRunAdapter):
            calls = 0

            def invoke(self, request):
                CountingAdapter.calls += 1
                return super().invoke(request)

        config = runner_v0_3.load_config()
        deny_case = next(
            case for case in runner_v0_3.load_dataset("semantic-gold")
            if firewall.deterministic_recommendation(case)["decision"] == "deny"
        )
        run = runner_v0_3.run_arm(CountingAdapter(), config, deny_case, "single")
        self.assertEqual(CountingAdapter.calls, 0)
        self.assertEqual(run["route"], "deterministic_deny_short_circuit")
        self.assertEqual(run["firewall"]["write_decision"], "deny")

    def test_empty_retrieval_evaluation_does_not_pass_the_safety_gate(self) -> None:
        from controlled_compare.evaluation_v0_6 import evaluate_retrieval_cases

        class EmptyStore:
            def search(self, query, namespace):
                return []

        result = evaluate_retrieval_cases(EmptyStore(), [])
        self.assertFalse(result["safety_gate"])
        self.assertIsNone(result["accuracy"])

    def test_retrieval_order_is_not_part_of_the_expected_result(self) -> None:
        from controlled_compare.evaluation_v0_6 import evaluate_retrieval_cases

        class FixedStore:
            def search(self, query, namespace):
                return [{"memory_id": "b"}, {"memory_id": "a"}]

        result = evaluate_retrieval_cases(
            FixedStore(),
            [{"case_id": "c", "query": "q", "namespace": "test-only/x", "expected_ids": ["a", "b"]}],
        )
        self.assertTrue(result["cases"][0]["passed"])


class SummaryExportTests(unittest.TestCase):
    def test_summary_drops_raw_model_content_and_keeps_gates(self) -> None:
        result = runner_v0_3.run_comparison(runner_v0_3.V03DryRunAdapter(), dataset="semantic-gold", smoke=True)
        summary = runner_v0_3.summary_view(result)
        self.assertNotIn("raw_runs", summary)
        self.assertEqual(summary["raw_runs_omitted"], len(result["raw_runs"]))
        self.assertNotIn("raw_content", json.dumps(summary, ensure_ascii=False))
        self.assertIn("hard_gates", summary["scores"]["single"])


if __name__ == "__main__":
    unittest.main()
