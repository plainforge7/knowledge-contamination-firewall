from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch, MagicMock

from controlled_compare.compare import CallResult
from controlled_compare.bailian_adapter_v0_3 import call_bailian_once
from controlled_compare.compare_v0_3 import (
    _execute_route,
    V03BailianAdapter,
    V03DryRunAdapter,
    compact_expired_hold_run,
    load_config,
    load_dataset,
    DATASET_PATHS,
    minimize_denied_run,
    public_case,
    run_arm,
    run_comparison,
)
from controlled_compare.firewall_v0_3 import (
    DuplicateEvidenceError,
    _case_evidence,
    _target_is_allowed,
    action_bundle_complete,
    apply_firewall,
    build_reopened_candidate,
    candidate_patch,
    detect_multi_triggers,
    deterministic_recommendation,
    empty_patch,
    compact_expired_hold,
    is_nonwriting_patch,
    patch_digest,
    purge_expired_hold_audit,
    purge_expired_deny_audit,
    simulate_transaction,
    validate_patch_admission,
)


class CountingAdapter(V03DryRunAdapter):
    def __init__(self) -> None:
        self.call_count = 0

    def invoke(self, request):
        self.call_count += 1
        return super().invoke(request)


class FailFirstAdapter(V03DryRunAdapter):
    def __init__(self) -> None:
        self.call_count = 0

    def invoke(self, request):
        self.call_count += 1
        if self.call_count == 1:
            raise RuntimeError("synthetic network failure")
        return super().invoke(request)


class MalformedAdapter(V03DryRunAdapter):
    def invoke(self, request):
        result = super().invoke(request)
        if request["metadata"]["stage"] in {"single_recommendation", "arbiter"}:
            result.content = {"write_decision": "permit"}
        return result


class OverBudgetAdapter(V03DryRunAdapter):
    def invoke(self, request):
        result = super().invoke(request)
        result.output_tokens = 20000
        return result


class MultiOverBudgetAdapter(V03DryRunAdapter):
    def __init__(self) -> None:
        self.call_count = 0

    def invoke(self, request):
        self.call_count += 1
        result = super().invoke(request)
        result.output_tokens = 20000
        return result


class FirewallV03Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.semantic = load_dataset("semantic-gold")
        cls.config = load_config()

    def case(self, case_id: str):
        return next(case for case in self.semantic if case["case_id"] == case_id)

    def test_frozen_semantic_distribution_is_10_6_4(self) -> None:
        counts = {label: 0 for label in ("allow", "quarantine", "reject")}
        for case in self.semantic:
            counts[case["gold"]["decision"]] += 1
        self.assertEqual(counts, {"allow": 10, "quarantine": 6, "reject": 4})

    def test_gold_and_label_metadata_are_hidden_from_model(self) -> None:
        visible = public_case(self.case("PM-020"))
        self.assertNotIn("gold", visible)
        self.assertNotIn("provenance", visible)

    def test_generic_rules_match_all_frozen_semantic_labels(self) -> None:
        mapping = {"allow": "permit", "quarantine": "hold", "reject": "deny"}
        for case in self.semantic:
            with self.subTest(case=case["case_id"]):
                self.assertEqual(
                    deterministic_recommendation(case)["decision"],
                    mapping[case["gold"]["decision"]],
                )

    def test_evaluation_permits_route_to_sandbox_and_blocks_route_to_none(self) -> None:
        for case in self.semantic:
            result = apply_firewall(case)
            with self.subTest(case=case["case_id"]):
                expected_destination = (
                    "sandbox" if case["gold"]["decision"] == "allow" else "none"
                )
                self.assertEqual(
                    result["execution"]["destination"], expected_destination
                )
                self.assertNotEqual(result["execution"]["destination"], "production")
                self.assertTrue(action_bundle_complete(result))

    def test_real_low_risk_write_requires_all_direct_write_conditions(self) -> None:
        case = {
            "case_id": "REAL-001",
            "layer": "production_candidate",
            "input": {
                "source_type": "user_direct",
                "explicit_memory_request": True,
                "risk_signals": [],
                "existing_memory": {},
                "proposed_memory_patch": {"preferences": {"language": "zh"}},
                "evidence": [{"id": "u1", "source_type": "user_direct"}],
                "write_context": {
                    "current_version": "v1", "expected_version": "v1",
                    "patch_scope": "personal_long_term_memory",
                    "patch_target": "/fields/summary",
                },
            },
            "provenance": {"data_policy": "production_candidate"},
        }
        result = apply_firewall(case)
        self.assertEqual(result["write_decision"], "permit")
        self.assertEqual(result["execution"]["destination"], "production")
        self.assertFalse(is_nonwriting_patch(result["patch"]))

    def test_missing_version_keeps_permit_as_proposal_only(self) -> None:
        case = {
            "case_id": "REAL-002",
            "layer": "production_candidate",
            "input": {
                "source_type": "user_direct",
                "explicit_memory_request": True,
                "risk_signals": [],
                "proposed_memory_patch": {"preferences": {"language": "zh"}},
                "evidence": [{"id": "u1", "source_type": "user_direct"}],
                # Scope/target are valid so this continues to isolate VERSION failure.
                "write_context": {
                    "patch_scope": "personal_long_term_memory",
                    "patch_target": "/fields/summary",
                },
            },
            "provenance": {"data_policy": "production_candidate"},
        }
        result = apply_firewall(case)
        self.assertEqual(result["write_decision"], "permit")
        self.assertEqual(result["execution"]["destination"], "none")
        self.assertIn(
            "current_version_missing",
            result["rule_decision"]["write_eligibility_failures"],
        )

    def test_sensitive_memory_requires_separate_itemized_confirmation(self) -> None:
        case = {
            "case_id": "REAL-SENSITIVE-001",
            "layer": "production_candidate",
            "input": {
                "source_type": "user_direct",
                "explicit_memory_request": True,
                "risk_signals": ["sensitive_health_data"],
                "existing_memory": {},
                "proposed_memory_patch": {
                    "health": {"allergies": {"peanut": "severe"}},
                    "recommendation_constraints": {"avoid_foods": ["peanut"]},
                },
                "evidence": [{"id": "u1", "source_type": "user_direct"}],
                "write_context": {
                    "current_version": "v1", "expected_version": "v1",
                    "patch_scope": "personal_long_term_memory",
                    "patch_target": "/fields/summary",
                },
            },
            "provenance": {"data_policy": "production_candidate"},
        }
        without_review = apply_firewall(case)
        self.assertEqual(without_review["write_decision"], "permit")
        self.assertEqual(without_review["execution"]["destination"], "none")
        self.assertEqual(
            without_review["rule_decision"]["storage_class"], "sensitive_storable"
        )

        patch = candidate_patch(case)
        case["human_confirmation"] = {
            "status": "approved",
            "confirmation_type": "sensitive_memory_review",
            "confirmed_by": "user",
            "confirmation_id": "confirm-001",
            "verification_status": "verified_by_host",
            "approved_scope": ["fields"],
            "purpose": "avoid unsafe food recommendations",
            "retention": "until_revoked",
            "patch_sha256": patch_digest(patch),
        }
        approved = apply_firewall(case)
        self.assertEqual(approved["execution"]["destination"], "production")
        self.assertEqual(
            approved["provenance_channels"]["human_confirmation"],
            case["human_confirmation"],
        )

        case["human_confirmation"]["patch_sha256"] = "wrong-hash"
        changed_after_review = apply_firewall(case)
        self.assertEqual(changed_after_review["execution"]["destination"], "none")
        self.assertIn(
            "sensitive_confirmation_patch_hash_mismatch",
            changed_after_review["rule_decision"]["write_eligibility_failures"],
        )

    def test_prohibited_storage_has_no_human_override(self) -> None:
        case = {
            "case_id": "REAL-PROHIBITED-001",
            "layer": "production_candidate",
            "input": {
                "source_type": "user_direct",
                "explicit_memory_request": True,
                "risk_signals": ["prompt_injection", "financial_claim"],
                "existing_memory": {},
                "proposed_memory_patch": {"finance": {"fabricated_debt": 100000}},
                "evidence": [{"id": "u1", "source_type": "user_direct"}],
                "write_context": {"current_version": "v1", "expected_version": "v1"},
            },
            "provenance": {"data_policy": "production_candidate"},
        }
        patch = candidate_patch(case)
        case["human_confirmation"] = {
            "status": "approved",
            "confirmation_type": "sensitive_memory_review",
            "confirmed_by": "user",
            "confirmation_id": "confirm-002",
            "verification_status": "verified_by_host",
            "approved_scope": ["finance"],
            "purpose": "synthetic attempt",
            "retention": "until_revoked",
            "patch_sha256": patch_digest(patch),
        }
        result = apply_firewall(case, evaluated_at="2026-09-14T00:00:00Z")
        self.assertEqual(result["write_decision"], "deny")
        self.assertEqual(result["rule_decision"]["storage_class"], "prohibited")
        self.assertEqual(result["execution"]["destination"], "none")
        self.assertTrue(is_nonwriting_patch(result["patch"]))
        self.assertEqual(
            result["audit_summary"]["original_patch_sha256"], patch_digest(patch)
        )
        self.assertEqual(
            result["deny_retention"]["minimized_at"], "2026-09-14T00:00:00Z"
        )
        kept = purge_expired_deny_audit(
            result, current_time="2026-12-12T23:59:59Z"
        )
        self.assertFalse(kept["delete_record"])
        purged = purge_expired_deny_audit(
            result, current_time="2026-12-13T00:00:00Z"
        )
        self.assertTrue(purged["delete_record"])
        self.assertEqual(
            purged["aggregate_delta"], {"expired_deny_audit_summaries": 1}
        )

    def test_synthetic_deny_keeps_diagnostics_until_explicit_minimization(self) -> None:
        denied = apply_firewall(self.case("PM-020"))
        self.assertFalse(is_nonwriting_patch(denied["patch"]))
        self.assertNotIn("deny_retention", denied)
        run = {
            "firewall": denied,
            "ai_raw_output": {"synthetic": "diagnostic"},
            "calls": [{"raw_content": {"synthetic": "diagnostic"}}],
        }
        minimized = minimize_denied_run(
            run, minimized_at="2026-09-14T00:00:00Z"
        )
        self.assertTrue(is_nonwriting_patch(minimized["firewall"]["patch"]))
        self.assertIsNone(minimized["ai_raw_output"])
        self.assertIsNone(minimized["calls"][0]["raw_content"])

    def test_contract_failure_and_infrastructure_failure_both_fail_closed(self) -> None:
        case = self.case("PM-001")
        malformed = apply_firewall(case, ai_proposal={}, arm="single")
        unavailable = apply_firewall(
            case,
            ai_proposal=None,
            arm="single",
            infrastructure_errors=["synthetic timeout"],
        )
        self.assertEqual(malformed["write_decision"], "hold")
        self.assertEqual(malformed["audit_status"], "blocked_model_contract")
        self.assertEqual(unavailable["write_decision"], "hold")
        self.assertEqual(unavailable["audit_status"], "n_a_infrastructure")
        self.assertEqual(malformed["execution"]["destination"], "none")
        self.assertEqual(unavailable["execution"]["destination"], "none")

    def test_hold_expires_after_30_days_to_audit_summary_only(self) -> None:
        case = deepcopy(self.case("PM-003"))
        case["user_feedback"] = [{"text": "synthetic sensitive feedback"}]
        held = apply_firewall(case, evaluated_at="2026-09-14T00:00:00Z")
        original_patch_hash = held["execution"]["patch_sha256"]
        self.assertEqual(held["hold_retention"]["expires_at"], "2026-10-14T00:00:00Z")
        self.assertIn(
            "schedule_hold_expiry_and_data_minimization",
            held["effective_actions"],
        )

        still_active = compact_expired_hold(
            held, current_time="2026-10-13T23:59:59Z"
        )
        self.assertIsNone(still_active["hold_retention"]["compacted_at"])
        expired = compact_expired_hold(held, current_time="2026-10-14T00:00:00Z")
        self.assertEqual(
            expired["hold_retention"]["compacted_at"], "2026-10-14T00:00:00Z"
        )
        self.assertFalse(expired["hold_retention"]["raw_candidate_retained"])
        self.assertTrue(is_nonwriting_patch(expired["patch"]))
        self.assertEqual(expired["execution"]["destination"], "none")
        self.assertEqual(expired["provenance_channels"]["user_feedback"], [])
        self.assertEqual(
            expired["audit_summary"]["original_patch_sha256"], original_patch_hash
        )
        self.assertFalse(expired["hold_retention"]["automatic_write_on_expiry"])
        self.assertFalse(is_nonwriting_patch(held["patch"]))

        kept = purge_expired_hold_audit(
            expired, current_time="2027-01-11T23:59:59Z"
        )
        self.assertFalse(kept["delete_record"])
        purged = purge_expired_hold_audit(
            expired, current_time="2027-01-12T00:00:00Z"
        )
        self.assertTrue(purged["delete_record"])
        self.assertIsNone(purged["record"])
        self.assertEqual(
            purged["aggregate_delta"], {"expired_hold_audit_summaries": 1}
        )

    def test_expired_hold_run_removes_raw_model_content(self) -> None:
        held = apply_firewall(
            deepcopy(self.case("PM-003")),
            evaluated_at="2026-09-14T00:00:00Z",
        )
        run = {
            "firewall": held,
            "ai_raw_output": {"synthetic": "raw model content"},
            "calls": [
                {
                    "raw_content": {"synthetic": "raw model content"},
                    "input_tokens": 1,
                    "output_tokens": 1,
                }
            ],
        }
        expired = compact_expired_hold_run(
            run, current_time="2026-10-14T00:00:00Z"
        )
        self.assertIsNone(expired["ai_raw_output"])
        self.assertIsNone(expired["calls"][0]["raw_content"])
        self.assertTrue(
            expired["content_retention"]["operational_usage_metadata_retained"]
        )
        self.assertEqual(expired["calls"][0]["input_tokens"], 1)

    def test_reopen_always_creates_fresh_linked_candidate(self) -> None:
        held = apply_firewall(
            deepcopy(self.case("PM-003")),
            evaluated_at="2026-09-14T00:00:00Z",
        )
        compacted = compact_expired_hold(
            held, current_time="2026-10-14T00:00:00Z"
        )
        prior_summary = compacted["audit_summary"]
        new_candidate = {
            "case_id": "REOPEN-001",
            "layer": "production_candidate",
            "input": {
                "source_type": "user_direct",
                "explicit_memory_request": True,
                "risk_signals": ["explicit_correction"],
                "existing_memory": {},
                "proposed_memory_patch": {
                    "communication_preferences": {"language": "zh"}
                },
                "evidence": [
                    {"id": "new-correction", "source_type": "user_direct"}
                ],
            },
            "provenance": {"data_policy": "production_candidate"},
            "human_confirmation": {"status": "old-confirmation-must-not-survive"},
        }
        reopened = build_reopened_candidate(
            prior_summary,
            new_candidate,
            basis_type="explicit_user_correction",
            basis_evidence_ids=["new-correction"],
            reopened_at="2026-11-01T00:00:00Z",
        )
        self.assertEqual(reopened["case_id"], "REOPEN-001")
        self.assertNotIn("human_confirmation", reopened)
        self.assertEqual(
            reopened["reopen_context"]["prior_candidate_id"], "PM-003"
        )
        self.assertFalse(reopened["reopen_context"]["inherits_prior_patch"])
        self.assertFalse(reopened["reopen_context"]["inherits_prior_decision"])
        self.assertFalse(reopened["reopen_context"]["inherits_prior_confirmation"])
        reviewed = apply_firewall(reopened)
        self.assertEqual(
            reviewed["provenance_channels"]["reopen_context"],
            reopened["reopen_context"],
        )
        self.assertEqual(
            reviewed["patch"]["value"],
            new_candidate["input"]["proposed_memory_patch"],
        )
        with self.assertRaisesRegex(ValueError, "expired"):
            build_reopened_candidate(
                prior_summary,
                new_candidate,
                basis_type="new_evidence",
                basis_evidence_ids=["new-correction"],
                reopened_at="2027-01-12T00:00:00Z",
            )

    def test_source_type_mixing_is_rejected_without_repair(self) -> None:
        case = self.case("PM-001")
        proposal = {
            "write_decision": "permit",
            "evidence_ids": ["utterance"],
            "source_labels": [
                {"evidence_id": "utterance", "source_type": "human_confirmation"}
            ],
            "recommended_actions": [],
            "false_positive_risk": "synthetic",
            "release_condition": "synthetic",
            "rollback_action": "synthetic",
            "uncertainty": "synthetic",
            "patch": candidate_patch(case),
        }
        result = apply_firewall(case, ai_proposal=proposal, arm="single")
        self.assertEqual(result["write_decision"], "hold")
        self.assertTrue(
            any(
                error.startswith("provenance:")
                for error in result["errors"]["model_contract"]
            )
        )

    def test_multi_routing_is_conditional(self) -> None:
        low_risk = self.case("PM-007")
        high_risk = self.case("PM-006")
        split_brain = load_dataset("system-dev")[0]
        self.assertEqual(detect_multi_triggers(low_risk), [])
        self.assertIn("high_impact_information", detect_multi_triggers(high_risk))
        self.assertIn(
            "unresolved_trustworthy_source_conflict",
            detect_multi_triggers(split_brain),
        )

        adapter = CountingAdapter()
        low_run = run_arm(adapter, self.config, low_risk, "multi")
        self.assertEqual(low_run["usage"]["successful_calls"], 1)
        self.assertEqual(low_run["route"], "single")

        high_run = run_arm(adapter, self.config, high_risk, "multi")
        self.assertEqual(high_run["usage"]["successful_calls"], 4)
        self.assertEqual(high_run["route"], "multi_escalated")

    def test_multi_explicit_deny_short_circuits_all_model_calls(self) -> None:
        adapter = CountingAdapter()
        run = run_arm(adapter, self.config, self.case("PM-020"), "multi")
        self.assertEqual(adapter.call_count, 0)
        self.assertEqual(run["usage"]["successful_calls"], 0)
        self.assertEqual(run["route"], "deterministic_deny_short_circuit")
        self.assertEqual(run["firewall"]["write_decision"], "deny")
        self.assertEqual(run["firewall"]["execution"]["destination"], "none")

    def test_multi_budget_overrun_stops_before_auditors(self) -> None:
        adapter = MultiOverBudgetAdapter()
        run = run_arm(adapter, self.config, self.case("PM-006"), "multi")
        self.assertEqual(adapter.call_count, 1)
        self.assertEqual(run["usage"]["successful_calls"], 1)
        self.assertFalse(run["budget_compliant"])
        self.assertEqual(run["firewall"]["audit_status"], "blocked_token_budget")
        self.assertEqual(run["firewall"]["execution"]["destination"], "none")

    def test_baseline_single_and_multi_call_limits(self) -> None:
        case = self.case("PM-006")
        adapter = CountingAdapter()
        baseline = run_arm(adapter, self.config, case, "baseline")
        single = run_arm(adapter, self.config, case, "single")
        multi = run_arm(adapter, self.config, case, "multi")
        self.assertEqual(baseline["usage"]["successful_calls"], 0)
        self.assertEqual(single["usage"]["successful_calls"], 1)
        self.assertEqual(multi["usage"]["successful_calls"], 4)

    def test_permit_patch_executes_only_in_test_namespace(self) -> None:
        permitted = run_arm(
            V03DryRunAdapter(), self.config, self.case("PM-001"), "single"
        )
        blocked = run_arm(
            V03DryRunAdapter(), self.config, self.case("PM-020"), "single"
        )
        self.assertEqual(
            permitted["firewall"]["execution"]["destination"], "sandbox"
        )
        self.assertTrue(permitted["execution_result"]["committed"])
        self.assertEqual(
            permitted["execution_result"]["namespace"], "test-only/PM-001"
        )
        self.assertFalse(permitted["execution_result"]["formal_memory_touched"])
        self.assertEqual(blocked["firewall"]["execution"]["destination"], "none")
        self.assertFalse(blocked["execution_result"]["attempted"])

    def test_bailian_final_stages_request_structured_json_mode(self) -> None:
        adapter = V03BailianAdapter(["synthetic-command"], self.config)
        request = {
            "messages": [{"role": "user", "content": "synthetic"}],
            "max_output_tokens": 10,
            "metadata": {"stage": "single_recommendation"},
        }
        translated = adapter.provider_request(request)
        self.assertEqual(translated["metadata"]["stage"], "single_final")
        self.assertEqual(
            translated["metadata"]["protocol_stage"], "single_recommendation"
        )
        self.assertEqual(request["metadata"]["stage"], "single_recommendation")

    def test_bailian_transport_retries_on_transport_error_then_succeeds(self) -> None:
        import urllib.error
        from controlled_compare.bailian_adapter_v0_3 import call_bailian_once

        real_config = load_config()
        model_config = dict(real_config["model"])
        model_config["pricing_cny_per_million_tokens"] = real_config["pricing_cny_per_million_tokens"]
        request = {
            "timeout_seconds": 10,
            "max_output_tokens": 100,
            "messages": [{"role": "user", "content": "hi"}],
            "metadata": {"stage": "single_final"},
            "model_config": model_config,
        }
        environment = {"DASHSCOPE_API_KEY": "sk-ws-test", "DASHSCOPE_BASE_URL": "https://x.ap-northeast-1.maas.aliyuncs.com/compatible-mode/v1"}

        call_count = {"n": 0}

        class FakeResponse:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps({
                    "id": "synthetic-response",
                    "model": "synthetic-model",
                    "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                }).encode("utf-8")

        def flaky_urlopen(req, timeout=None):
            call_count["n"] += 1
            if call_count["n"] < 3:
                raise urllib.error.URLError("simulated transient failure")
            return FakeResponse()

        with patch(
            "controlled_compare.bailian_adapter_v0_3.urllib.request.urlopen",
            side_effect=flaky_urlopen,
        ), patch("controlled_compare.bailian_adapter_v0_3.time") as mock_time:
            mock_time.monotonic.side_effect = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7]
            result = call_bailian_once(request, environment)
        self.assertEqual(call_count["n"], 3)
        self.assertEqual(result["http_attempts"], 3)

    def test_bailian_transport_does_not_retry_contract_errors(self) -> None:
        from controlled_compare.bailian_adapter_v0_3 import call_bailian_once

        request = {
            "timeout_seconds": 10,
            "messages": [{"role": "user", "content": "hi"}],
            "model_config": {"pricing_cny_per_million_tokens": {"input": 1.0, "output": 1.0}},
        }
        environment = {"DASHSCOPE_API_KEY": "sk-sp-not-allowed"}

        with self.assertRaises(ValueError):
            call_bailian_once(request, environment)

    def test_v03_bailian_transport_makes_one_http_attempt(self) -> None:
        class FakeResponse:
            headers = {"x-request-id": "synthetic-request"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "id": "synthetic-response",
                        "model": "synthetic-model",
                        "choices": [
                            {
                                "message": {"content": "{}"},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {"prompt_tokens": 3, "completion_tokens": 2},
                    }
                ).encode()

        request = {
            "messages": [{"role": "user", "content": "synthetic"}],
            "max_output_tokens": 10,
            "timeout_seconds": 3,
            "metadata": {"stage": "single_recommendation"},
            "model_config": {
                "model_id": "synthetic-model",
                "temperature": 0.0,
                "enable_thinking": False,
                "preserve_thinking": False,
                "pricing_cny_per_million_tokens": {"input": 1, "output": 1},
            },
        }
        environment = {
            "DASHSCOPE_API_KEY": "pay-as-you-go-test-key",
            "DASHSCOPE_BASE_URL": (
                "https://synthetic.ap-northeast-1.maas.aliyuncs.com/compatible-mode/v1"
            ),
        }
        with patch(
            "controlled_compare.bailian_adapter_v0_3.urllib.request.urlopen",
            return_value=FakeResponse(),
        ) as opener:
            result = call_bailian_once(request, environment)
        self.assertEqual(opener.call_count, 1)
        self.assertEqual(result["http_attempts"], 1)

    def test_untrusted_source_pair_does_not_trigger_trustworthy_conflict(self) -> None:
        case = deepcopy(self.case("PM-003"))
        case["input"]["evidence"] = [
            {"id": "a", "source_type": "third_party"},
            {"id": "b", "source_type": "user_inference"},
        ]
        self.assertNotIn(
            "unresolved_trustworthy_source_conflict",
            detect_multi_triggers(case),
        )

    def test_case_evidence_rejects_duplicate_ids(self) -> None:
        case = deepcopy(self.case("PM-001"))
        case["input"]["evidence"] = [
            {"id": "utterance", "source_type": "user_direct"},
            {"id": "utterance", "source_type": "third_party"},
        ]
        with self.assertRaises(DuplicateEvidenceError):
            _case_evidence(case)

    def test_apply_firewall_denies_duplicate_evidence(self) -> None:
        case = deepcopy(self.case("PM-001"))
        case["input"]["evidence"] = [
            {"id": "utterance", "source_type": "user_direct"},
            {"id": "utterance", "source_type": "third_party"},
        ]
        result = apply_firewall(case)
        self.assertEqual(result["write_decision"], "deny")
        self.assertEqual(result["audit_status"], "duplicate_evidence_id")

    def test_load_dataset_rejects_duplicate_evidence_in_gold_file(self) -> None:
        case = deepcopy(self.case("PM-001"))
        case["input"]["evidence"] = [
            {"id": "utterance", "source_type": "user_direct"},
            {"id": "utterance", "source_type": "third_party"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            bad_file = Path(directory) / "bad_gold.jsonl"
            bad_file.write_text(json.dumps(case, ensure_ascii=False), encoding="utf-8")
            with patch.dict(DATASET_PATHS, {"semantic-gold": bad_file}):
                with self.assertRaisesRegex(ValueError, "duplicate evidence id"):
                    load_dataset("semantic-gold")

    def test_token_ceiling_forces_hold(self) -> None:
        run = run_arm(
            OverBudgetAdapter(), self.config, self.case("PM-001"), "single"
        )
        self.assertFalse(run["budget_compliant"])
        self.assertEqual(run["firewall"]["write_decision"], "hold")
        self.assertEqual(run["firewall"]["audit_status"], "blocked_token_budget")
        self.assertEqual(run["firewall"]["execution"]["destination"], "none")
        self.assertEqual(
            run["audit_trace"]["failure"]["category"],
            "policy_budget_or_deadline",
        )

    def test_audit_trace_summarizes_successful_sandbox_write(self) -> None:
        run = run_arm(
            V03DryRunAdapter(), self.config, self.case("PM-001"), "single"
        )
        trace = run["audit_trace"]
        self.assertEqual(trace["trace_version"], "0.4.0-audit-trace")
        self.assertEqual(trace["decision"]["final"], "permit")
        self.assertEqual(trace["failure"]["category"], "none")
        self.assertEqual(trace["execution"]["planned_destination"], "sandbox")
        self.assertTrue(trace["execution"]["attempted"])
        self.assertTrue(trace["execution"]["committed"])
        self.assertEqual(trace["operations"]["successful_calls"], 1)
        self.assertEqual(trace["model_calls"][0]["stage"], "single_recommendation")

    def test_audit_trace_marks_infrastructure_failure_retriable(self) -> None:
        run = run_arm(
            FailFirstAdapter(), self.config, self.case("PM-001"), "single"
        )
        trace = run["audit_trace"]
        self.assertEqual(trace["failure"]["category"], "infrastructure")
        self.assertTrue(trace["failure"]["retriable"])
        self.assertEqual(trace["decision"]["final"], "hold")
        self.assertEqual(trace["execution"]["planned_destination"], "none")

    def test_audit_trace_marks_model_contract_failure_non_retriable(self) -> None:
        run = run_arm(
            MalformedAdapter(), self.config, self.case("PM-001"), "single"
        )
        trace = run["audit_trace"]
        self.assertEqual(trace["failure"]["category"], "model_contract")
        self.assertFalse(trace["failure"]["retriable"])
        self.assertEqual(trace["decision"]["audit_status"], "blocked_model_contract")

    def test_injected_transaction_failure_restores_snapshot(self) -> None:
        patch = candidate_patch(self.case("PM-001"))
        patch["status"] = "effective"
        result = simulate_transaction(
            {"existing": "kept"}, patch, inject_write_failure=True
        )
        self.assertTrue(result["snapshot_taken"])
        self.assertTrue(result["rolled_back"])
        self.assertEqual(result["before"], result["after"])

    def test_resume_reuses_success_and_reruns_only_infrastructure_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.jsonl"
            first = run_comparison(
                FailFirstAdapter(),
                dataset="semantic-gold",
                smoke=True,
                checkpoint_path=checkpoint,
            )
            self.assertEqual(
                sum(bool(run["infrastructure_errors"]) for run in first["raw_runs"]),
                1,
            )
            resumed = run_comparison(
                V03DryRunAdapter(),
                dataset="semantic-gold",
                smoke=True,
                checkpoint_path=checkpoint,
                resume=True,
            )
            self.assertEqual(resumed["checkpoint"]["resumed_records"], 2)
            self.assertEqual(resumed["checkpoint"]["rerun_infrastructure_records"], 1)
            self.assertTrue(all(not run["infrastructure_errors"] for run in resumed["raw_runs"]))

    def test_contract_failure_is_preserved_and_not_silently_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.jsonl"
            run_comparison(
                MalformedAdapter(),
                dataset="semantic-gold",
                smoke=True,
                checkpoint_path=checkpoint,
            )
            resumed = run_comparison(
                V03DryRunAdapter(),
                dataset="semantic-gold",
                smoke=True,
                checkpoint_path=checkpoint,
                resume=True,
            )
            self.assertEqual(resumed["checkpoint"]["resumed_records"], 3)
            self.assertEqual(resumed["checkpoint"]["rerun_infrastructure_records"], 0)

    def test_full_dry_run_is_safe_but_not_an_evaluative_model_result(self) -> None:
        result = run_comparison(V03DryRunAdapter(), dataset="semantic-gold")
        self.assertFalse(result["evaluation_valid"])
        self.assertEqual(result["selection"]["status"], "dry_run_only")
        for arm in ("baseline", "single", "multi"):
            self.assertTrue(result["scores"][arm]["hard_gates"]["all_pass"])
            self.assertEqual(
                result["scores"][arm]["hard_gates"]["test_content_production_routes"],
                0,
            )
            self.assertEqual(
                result["scores"][arm]["hard_gates"]["sandbox_execution_failures"],
                0,
            )


class PatchWhitelistBoundaryTests(unittest.TestCase):
    """User-defined engineering cases A–F; these are NOT Gold row numbers."""

    def setUp(self) -> None:
        self.config = load_config()
        self.case = {
            "case_id": "SYNTHETIC-BOUNDARY",
            "layer": "system",
            "provenance": {"data_policy": "synthetic_only"},
            "input": {"existing_memory": {"old_synthetic_field": "old"}},
        }

    def make_patch(self, scope, target):
        candidate = empty_patch()
        candidate.update({
            "operation": "replace",
            "scope": scope,
            "target": target,
            "value": {"synthetic_summary": "new"},
            "evidence_ids": ["synthetic-evidence"],
        })
        return candidate

    def execute(self, candidate, expected_hash):
        return _execute_route(self.config, self.case, {
            "write_decision": "permit",
            "patch": candidate,
            "execution": {"destination": "sandbox", "patch_sha256": expected_hash},
        })

    def assert_rejected_before_hash(self, candidate, *, step, reason):
        # Real digest computed BEFORE spies: no fake hash can mask a scope bug.
        expected_hash = patch_digest(candidate)
        original_case, original_patch = deepcopy(self.case), deepcopy(candidate)
        with patch(
            "controlled_compare.firewall_v0_3.patch_digest", wraps=patch_digest
        ) as hash_check, patch(
            "controlled_compare.compare_v0_3.patch_digest", wraps=patch_digest
        ) as legacy_hash_check, patch(
            "controlled_compare.firewall_v0_3._target_is_allowed", wraps=_target_is_allowed
        ) as target_check, patch(
            "controlled_compare.compare_v0_3.simulate_transaction"
        ) as transaction:
            result = self.execute(candidate, expected_hash)
        self.assertFalse(result["attempted"])
        self.assertFalse(result["committed"])
        self.assertEqual(result["destination"], "none")
        self.assertEqual(result["failed_step"], step)
        self.assertEqual(result["error"], reason)
        self.assertEqual(result["validation_trace"], ["scope", "target"][:step])
        self.assertFalse(result["patch_hash_verified"])
        self.assertFalse(result["formal_memory_touched"])
        hash_check.assert_not_called()
        legacy_hash_check.assert_not_called()
        if step == 1:
            target_check.assert_not_called()
        else:
            target_check.assert_called_once()
        transaction.assert_not_called()
        self.assertEqual(self.case, original_case)
        self.assertEqual(candidate, original_patch)

    def test_A_production_root_rejected_at_step_2(self) -> None:
        """User boundary 8: a valid hash cannot authorize a production root."""
        self.assert_rejected_before_hash(
            self.make_patch("personal_long_term_memory", "/"),
            step=2, reason="patch_target_not_allowed",
        )

    def test_B_test_only_root_replaces_only_isolated_sandbox(self) -> None:
        """User boundary 9: legitimate sandbox root replacement stays usable."""
        candidate = self.make_patch("test-only", "/")
        original_case = deepcopy(self.case)
        result = self.execute(candidate, patch_digest(candidate))
        self.assertTrue(result["attempted"])
        self.assertTrue(result["committed"])
        self.assertEqual(result["validation_trace"], ["scope", "target", "patch_sha256"])
        self.assertIsNone(result["failed_step"])
        self.assertTrue(result["patch_hash_verified"])
        self.assertEqual(result["destination"], "sandbox")
        self.assertEqual(result["namespace"], "test-only/SYNTHETIC-BOUNDARY")
        self.assertEqual(result["after"], candidate["value"])
        self.assertFalse(result["formal_memory_touched"])
        self.assertEqual(self.case, original_case)

    def test_C_valid_hash_cannot_authorize_internal_debug(self) -> None:
        """User boundary 11: illegal target stops before integrity checking."""
        self.assert_rejected_before_hash(
            self.make_patch("personal_long_term_memory", "/fields/internal_debug"),
            step=2, reason="patch_target_not_allowed",
        )

    def test_D_unknown_scope_stops_at_step_1(self) -> None:
        self.assert_rejected_before_hash(
            self.make_patch("some_unknown_scope", "/"),
            step=1, reason="patch_scope_not_allowed",
        )

    def test_E_missing_or_null_scope_has_no_default(self) -> None:
        for missing in (True, False):
            with self.subTest(missing=missing):
                candidate = self.make_patch(None, "/fields/summary")
                if missing:
                    del candidate["scope"]
                self.assert_rejected_before_hash(
                    candidate, step=1, reason="patch_scope_not_allowed"
                )

    def test_F_target_cannot_cross_scope_whitelists(self) -> None:
        self.assert_rejected_before_hash(
            self.make_patch("test-only", "/fields/summary"),
            step=2, reason="patch_target_not_allowed",
        )

    def test_valid_production_paths_pass_all_three_admission_steps(self) -> None:
        for target in ("/fields/summary", "/fields/tags", "/fields/confidence"):
            with self.subTest(target=target):
                candidate = self.make_patch("personal_long_term_memory", target)
                admission = validate_patch_admission(candidate, patch_digest(candidate))
                self.assertTrue(admission["allowed"])
                self.assertTrue(admission["hash_verified"])
                self.assertEqual(admission["trace"], ["scope", "target", "patch_sha256"])

    def test_valid_location_tampered_content_stops_at_hash_before_transaction(self) -> None:
        candidate = self.make_patch("test-only", "/")
        expected_hash = patch_digest(candidate)
        candidate["value"]["synthetic_summary"] = "tampered"
        with patch("controlled_compare.compare_v0_3.simulate_transaction") as transaction:
            result = self.execute(candidate, expected_hash)
        self.assertEqual(result["failed_step"], 3)
        self.assertEqual(result["validation_trace"], ["scope", "target", "patch_sha256"])
        self.assertEqual(result["error"], "patch_hash_mismatch")
        self.assertFalse(result["attempted"])
        self.assertFalse(result["patch_hash_verified"])
        transaction.assert_not_called()

    def test_paths_are_exact_not_prefix_or_normalized_matches(self) -> None:
        for target in (
            "/fields/summary/child", "/fields/summary/", "/fields/Summary",
            "/fields/summary/../internal_debug", "/fields/%73ummary",
            "/fields/summary ", "//fields/summary", None, ["/fields/summary"],
        ):
            with self.subTest(target=target):
                self.assert_rejected_before_hash(
                    self.make_patch("personal_long_term_memory", target),
                    step=2, reason="patch_target_not_allowed",
                )

    def test_production_candidate_has_no_implicit_scope_or_root(self) -> None:
        case = {
            "case_id": "SYNTHETIC-PRODUCTION-SHAPE",
            "layer": "production_candidate",
            "input": {
                "source_type": "user_direct", "explicit_memory_request": True,
                "risk_signals": [], "evidence": [{"id": "s", "source_type": "user_direct"}],
                "proposed_memory_patch": {"synthetic": "value"},
                "write_context": {"current_version": "v1", "expected_version": "v1"},
            },
        }
        result = apply_firewall(case)
        self.assertIsNone(result["patch"]["scope"])
        self.assertIsNone(result["patch"]["target"])
        self.assertEqual(result["write_decision"], "hold")
        self.assertEqual(result["execution"]["destination"], "none")
        self.assertEqual(result["patch_location_check"]["failed_step"], 1)

    def test_invalid_ai_patch_is_blocked_before_execution_and_kept_for_review(self) -> None:
        class IllegalPatchAdapter(V03DryRunAdapter):
            def invoke(self, request):
                response = super().invoke(request)
                response.content["patch"]["scope"] = "personal_long_term_memory"
                response.content["patch"]["target"] = "/fields/internal_debug"
                return response

        case = load_dataset("semantic-gold")[0]
        with patch("controlled_compare.compare_v0_3.simulate_transaction") as transaction:
            run = run_arm(IllegalPatchAdapter(), self.config, case, "single")
        self.assertEqual(run["firewall"]["write_decision"], "hold")
        self.assertEqual(run["firewall"]["patch_location_check"]["failed_step"], 2)
        self.assertEqual(run["firewall"]["execution"]["destination"], "none")
        self.assertEqual(run["ai_raw_output"]["patch"]["target"], "/fields/internal_debug")
        self.assertFalse(run["execution_result"]["attempted"])
        transaction.assert_not_called()

    def test_test_only_root_cannot_be_promoted_to_production(self) -> None:
        case = deepcopy(load_dataset("semantic-gold")[0])
        case["layer"] = "production_candidate"
        case.pop("provenance")
        case["input"]["context"] = "synthetic fixture for routing logic only"
        case["input"]["explicit_memory_request"] = True
        case["input"]["write_context"] = {
            "current_version": "v1", "expected_version": "v1",
            "patch_scope": "test-only", "patch_target": "/",
        }
        firewall = apply_firewall(case)
        self.assertFalse(firewall["rule_decision"]["production_write_eligible"])
        self.assertEqual(firewall["execution"]["destination"], "sandbox")
        firewall["execution"]["destination"] = "production"
        with patch("controlled_compare.compare_v0_3.simulate_transaction") as transaction:
            result = _execute_route(self.config, case, firewall)
        self.assertEqual(result["destination"], "none")
        self.assertFalse(result["attempted"])
        transaction.assert_not_called()

    def test_legal_field_changes_preserve_other_fields_in_sandbox(self) -> None:
        self.case["input"]["existing_memory"] = {
            "fields": {"summary": "old", "tags": ["kept"], "confidence": 0.4},
            "unrelated": "kept",
        }
        original_case = deepcopy(self.case)
        for operation in ("add", "replace", "delete"):
            with self.subTest(operation=operation):
                candidate = self.make_patch("personal_long_term_memory", "/fields/summary")
                candidate["operation"] = operation
                candidate["value"] = None if operation == "delete" else "new"
                result = self.execute(candidate, patch_digest(candidate))
                self.assertTrue(result["committed"])
                self.assertEqual(result["after"]["fields"]["tags"], ["kept"])
                self.assertEqual(result["after"]["fields"]["confidence"], 0.4)
                self.assertEqual(result["after"]["unrelated"], "kept")
                if operation == "delete":
                    self.assertNotIn("summary", result["after"]["fields"])
                else:
                    self.assertEqual(result["after"]["fields"]["summary"], "new")
        self.assertEqual(self.case, original_case)

    def test_legal_field_write_failure_rolls_back_without_partial_change(self) -> None:
        memory = {"fields": {"summary": "old", "tags": ["kept"]}}
        candidate = self.make_patch("personal_long_term_memory", "/fields/summary")
        self.assertTrue(validate_patch_admission(candidate, patch_digest(candidate))["allowed"])
        result = simulate_transaction(memory, candidate, inject_write_failure=True)
        self.assertFalse(result["committed"])
        self.assertTrue(result["rolled_back"])
        self.assertEqual(result["after"], result["before"])
        self.assertEqual(memory, {"fields": {"summary": "old", "tags": ["kept"]}})


if __name__ == "__main__":
    unittest.main()
