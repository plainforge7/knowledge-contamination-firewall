"""Protocol v0.3 product-track evaluator.

Baseline uses no model. Single uses one structured model call. Multi reuses the
Single result and escalates only when deterministic routing finds a confirmed
high-risk condition; it therefore uses one or four calls per candidate.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shlex
import statistics
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Protocol

from controlled_compare.compare import CallResult, _estimate_tokens
from controlled_compare.call_budget_v0_3 import CallBlocked, CallBudget
from controlled_compare.firewall_v0_3 import (
    HOLD_ACTIONS,
    action_bundle_complete,
    apply_firewall,
    candidate_patch,
    detect_multi_triggers,
    deterministic_recommendation,
    compact_expired_hold,
    hold_retention,
    minimize_denied_record,
    patch_digest,
    simulate_transaction,
    validate_ai_proposal,
    validate_patch_admission,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "controlled_compare" / "config_v0_3.json"
DATASET_PATHS = {
    "system-dev": ROOT / "controlled_compare" / "system_gold_v0_1.jsonl",
    "semantic-gold": ROOT / "controlled_compare" / "semantic_gold_v0_1.jsonl",
}
GOLD_TO_V03 = {"allow": "permit", "quarantine": "hold", "reject": "deny"}

FINAL_SCHEMA_INSTRUCTION = """
Return one JSON object only with these top-level fields: write_decision
(permit|hold|deny), evidence_ids (array), source_labels (array of
{evidence_id, source_type}), recommended_actions (array), false_positive_risk,
release_condition, rollback_action, uncertainty, and patch.

patch must contain exactly: operation (add|replace|delete|none), target
(string|null), value (any JSON value or null), scope (string|null), evidence_ids
(array), supersedes (array), valid_from (string|null), expires_at (string|null),
status (always proposed). It is a recommendation and never an effective write.
When operation is none, target, value, and scope must all be null; do not
populate them with any value in that case. For this synthetic evaluation, writing patches must explicitly use scope
test-only and target /. Root patches replace the isolated sandbox object only.
Outside evaluation, personal_long_term_memory permits only /fields/summary,
/fields/tags and /fields/confidence. Missing scope/target is never defaulted.
Never invent evidence IDs, sources, user confirmation, or authority. evidence_ids
must only reference ids already present in the candidate''s evidence array; using
any id not listed there is a contract violation. When operation is add or
replace, value must contain only fields the candidate'''s own utterance or
proposed_memory_patch actually mentions or reaffirms; never include a field
solely because it already exists in existing_memory when the utterance itself
does not reference it, and never omit a field the utterance does reference
merely because the same value already exists in existing_memory. Gold labels
and expected patches are unavailable.
""".strip()


class ModelAdapter(Protocol):
    evaluative: bool
    model_id: str
    temperature: float

    def invoke(self, request: dict[str, Any]) -> CallResult:
        ...


def load_config() -> dict[str, Any]:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def load_dataset(name: str) -> list[dict[str, Any]]:
    path = DATASET_PATHS[name]
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    expected_layer = "system" if name == "system-dev" else "semantic"
    for case in cases:
        if case.get("layer") != expected_layer:
            raise ValueError(f"{case.get('case_id')}: unexpected layer")
        if case.get("gold", {}).get("decision") not in GOLD_TO_V03:
            raise ValueError(f"{case.get('case_id')}: invalid frozen Gold label")
        if case.get("provenance", {}).get("data_policy") != "synthetic_only":
            raise ValueError(f"{case.get('case_id')}: v0.3 accepts synthetic test data only")
        seen: set[str] = set()
        for item in case.get("input", {}).get("evidence", []):
            if isinstance(item, dict) and item.get("id"):
                key = str(item["id"])
                if key in seen:
                    raise ValueError(f"{case.get('case_id')}: duplicate evidence id '{key}'")
                seen.add(key)
    return cases


def public_case(case: dict[str, Any]) -> dict[str, Any]:
    """Return model-visible input with all Gold and label metadata removed."""
    return {
        "case_id": case["case_id"],
        "layer": case["layer"],
        "input": case["input"],
    }


def _source_labels(case: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "evidence_id": str(item["id"]),
            "source_type": str(item.get("source_type", "unknown")),
        }
        for item in case["input"].get("evidence", [])
        if isinstance(item, dict) and item.get("id")
    ]


def _dry_proposal(case: dict[str, Any]) -> dict[str, Any]:
    rule = deterministic_recommendation(case)
    return {
        "write_decision": rule["decision"],
        "evidence_ids": [item["evidence_id"] for item in _source_labels(case)],
        "source_labels": _source_labels(case),
        "recommended_actions": [],
        "false_positive_risk": "谨慎规则可能延迟一个合法更新。",
        "release_condition": "获得直接、当前、可消解冲突的证据后重新审核。",
        "rollback_action": "恢复写入前已验证版本并移除派生写入。",
        "uncertainty": "免费 dry-run 使用确定性规则模拟模型输出，不代表模型能力。",
        "patch": candidate_patch(case),
    }


class V03DryRunAdapter:
    """Free deterministic adapter used only to verify v0.3 plumbing."""

    evaluative = False
    model_id = "dry-run-policy-v0.3"
    temperature = 0.0

    def invoke(self, request: dict[str, Any]) -> CallResult:
        started = time.perf_counter()
        case = request["metadata"]["case"]
        stage = request["metadata"]["stage"]
        if stage in {"single_recommendation", "arbiter"}:
            content: Any = _dry_proposal(case)
        else:
            content = {
                "role": stage,
                "evidence_ids": [item["evidence_id"] for item in _source_labels(case)],
                "findings": list(case["input"].get("risk_signals", [])),
            }
        latency_ms = (time.perf_counter() - started) * 1000
        raw = {"adapter": "dry_run_v0_3", "content": content, "cost_cny": 0.0}
        return CallResult(
            content=content,
            input_tokens=_estimate_tokens(request),
            output_tokens=_estimate_tokens(content),
            cost_usd=None,
            latency_ms=latency_ms,
            raw=raw,
        )


class V03BailianAdapter:
    """Isolated stdin/stdout Bailian adapter with one attempt per call."""

    evaluative = True

    def __init__(self, command: list[str], config: dict[str, Any]) -> None:
        if not command:
            raise ValueError("adapter command cannot be empty")
        self.command = command
        self.model_config = dict(config["model"])
        self.model_config["pricing_cny_per_million_tokens"] = config[
            "pricing_cny_per_million_tokens"
        ]
        self.model_id = str(self.model_config["model_id"])
        self.temperature = float(self.model_config["temperature"])

    def provider_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Translate v0.3 stages for the single-attempt transport adapter."""
        payload = dict(request)
        payload["model_config"] = self.model_config
        metadata = dict(payload.get("metadata", {}))
        protocol_stage = metadata.get("stage")
        metadata["protocol_stage"] = protocol_stage
        if protocol_stage == "single_recommendation":
            metadata["stage"] = "single_final"
        elif protocol_stage == "arbiter":
            metadata["stage"] = "arbiter_final"
        payload["metadata"] = metadata
        return payload

    def invoke(self, request: dict[str, Any]) -> CallResult:
        payload = self.provider_request(request)
        timeout_seconds = float(request.get("timeout_seconds", 60))
        started = time.perf_counter()
        completed = subprocess.run(
            self.command,
            input=json.dumps(payload, ensure_ascii=False),
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
        latency_ms = (time.perf_counter() - started) * 1000
        if completed.returncode != 0:
            message = completed.stderr.strip()[-1200:] or "adapter failed"
            raise RuntimeError(message)
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("adapter returned invalid envelope JSON") from error
        required = {"content", "input_tokens", "output_tokens", "cost_cny"}
        missing = required - result.keys()
        if missing:
            raise RuntimeError(f"adapter response missing fields: {sorted(missing)}")
        return CallResult(
            content=result["content"],
            input_tokens=int(result["input_tokens"]),
            output_tokens=int(result["output_tokens"]),
            cost_usd=None,
            latency_ms=latency_ms,
            raw=result,
        )


def _messages(stage: str, case: dict[str, Any], prior: Any = None) -> list[dict[str, str]]:
    if stage == "single_recommendation":
        system = (
            "You advise a personal long-term-memory firewall. Inspect source, "
            "recency, conflict, consent, scope, and risk. AI has no write authority. "
            + FINAL_SCHEMA_INSTRUCTION
        )
    elif stage == "provenance_conflict_auditor":
        system = (
            "Independently audit evidence identity, source authority, recency and "
            "unresolved conflicts. Return concise JSON findings; do not claim write authority."
        )
    elif stage == "write_risk_auditor":
        system = (
            "Independently audit sensitive-data, wrong-entity, consent and write risks. "
            "Return concise JSON findings; do not claim write authority."
        )
    elif stage == "arbiter":
        system = (
            "Reconcile the Single recommendation and two independent audits. "
            "Disagreement is evidence, not a vote. AI has no write authority. "
            + FINAL_SCHEMA_INSTRUCTION
        )
    else:
        raise ValueError(stage)
    payload: dict[str, Any] = {"case": public_case(case)}
    if prior is not None:
        payload["prior"] = prior
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
    ]


def _request(
    config: dict[str, Any],
    case: dict[str, Any],
    stage: str,
    arm: str,
    prior: Any = None,
) -> dict[str, Any]:
    budgets = config["budgets"]
    if stage == "single_recommendation":
        output_cap = budgets["single_max_output_tokens"]
        timeout = config["latency_targets_seconds"]["single"]
    elif stage == "arbiter":
        output_cap = budgets["multi_arbiter_max_output_tokens"]
        timeout = config["latency_targets_seconds"]["multi"] // 2
    else:
        output_cap = budgets["multi_auditor_max_output_tokens"]
        timeout = config["latency_targets_seconds"]["multi"] // 2
    return {
        "messages": _messages(stage, case, prior),
        "max_output_tokens": int(output_cap),
        "timeout_seconds": int(timeout),
        "metadata": {
            "case": public_case(case),
            "stage": stage,
            "arm": arm,
            "prompt_version": config["prompt_version"],
        },
    }


def _parse_content(content: Any) -> Any:
    if isinstance(content, str):
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return content
    return content


def _invoke(
    adapter: ModelAdapter, request: dict[str, Any]
) -> tuple[CallResult | None, str | None]:
    try:
        return adapter.invoke(request), None
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except Exception as error:
        return None, str(error)[:1200]


def _call_record(call: CallResult, stage: str) -> dict[str, Any]:
    return {
        "stage": stage,
        "input_tokens": call.input_tokens,
        "output_tokens": call.output_tokens,
        "total_tokens": call.input_tokens + call.output_tokens,
        "cost_cny": float(call.raw.get("cost_cny", 0.0)),
        "latency_ms": call.latency_ms,
        "request_id": call.raw.get("request_id"),
        "provider_model": call.raw.get("provider_model"),
        "raw_content": call.content,
        "provider_metadata": {
            key: value for key, value in call.raw.items() if key != "content"
        },
    }


def _usage(
    calls: list[dict[str, Any]], budget: CallBudget | None = None
) -> dict[str, Any]:
    budget_snapshot = budget.snapshot() if budget is not None else None
    usage_unknown = bool(
        budget_snapshot and budget_snapshot["usage_unknown_attempts"]
    )
    return {
        "successful_calls": len(calls),
        "input_tokens": sum(int(call["input_tokens"]) for call in calls),
        "output_tokens": sum(int(call["output_tokens"]) for call in calls),
        "total_tokens": sum(int(call["total_tokens"]) for call in calls),
        # Unknown failed-request charges are never represented as zero cost.
        "cost_cny": None
        if usage_unknown
        else round(sum(float(call["cost_cny"]) for call in calls), 8),
        "cost_cny_known": not usage_unknown,
        "usage_unknown_attempts": (
            budget_snapshot["usage_unknown_attempts"] if budget_snapshot else 0
        ),
    }


def _classify_failure(
    firewall: dict[str, Any],
    infrastructure_errors: list[str],
    policy_errors: list[str],
    execution_result: dict[str, Any],
) -> dict[str, Any]:
    if infrastructure_errors:
        return {"category": "infrastructure", "retriable": True}
    if firewall["errors"]["model_contract"]:
        return {"category": "model_contract", "retriable": False}
    if policy_errors:
        return {"category": "policy_budget_or_deadline", "retriable": False}
    if execution_result.get("error"):
        return {"category": "execution_route", "retriable": False}
    return {"category": "none", "retriable": False}


def build_audit_trace(
    *,
    arm: str,
    route: str,
    triggers: list[str],
    firewall: dict[str, Any],
    execution_result: dict[str, Any],
    calls: list[dict[str, Any]],
    usage: dict[str, Any],
    budget_snapshot: dict[str, Any],
    infrastructure_errors: list[str],
    policy_errors: list[str],
) -> dict[str, Any]:
    """Summarize one candidate run for debugging and human review."""
    failure = _classify_failure(
        firewall, infrastructure_errors, policy_errors, execution_result
    )
    return {
        "trace_version": "0.4.0-audit-trace",
        "arm": arm,
        "route": route,
        "multi_trigger_reasons": list(triggers),
        "decision": {
            "base": firewall["rule_decision"]["base_decision"],
            "final": firewall["write_decision"],
            "authority": firewall["rule_decision"]["authority"],
            "audit_status": firewall["audit_status"],
        },
        "failure": failure,
        "rule_ids": [
            rule["rule_id"]
            for rule in firewall["rule_decision"]["matched_rules"]
            if isinstance(rule, dict) and rule.get("rule_id")
        ],
        "patch": {
            "origin": firewall["patch_origin"],
            "operation": firewall["patch"].get("operation"),
            "scope": firewall["patch"].get("scope"),
            "target": firewall["patch"].get("target"),
            "sha256": firewall["execution"]["patch_sha256"],
            "location_reason": (
                firewall["patch_location_check"]["reason"]
                if firewall.get("patch_location_check")
                else None
            ),
        },
        "execution": {
            "planned_destination": firewall["execution"]["destination"],
            "planned_reason": firewall["execution"]["reason"],
            "attempted": execution_result.get("attempted", False),
            "committed": execution_result.get("committed", False),
            "actual_destination": execution_result.get("destination"),
            "error": execution_result.get("error"),
        },
        "model_calls": [
            {
                "stage": call["stage"],
                "tokens": call["total_tokens"],
                "latency_ms": call["latency_ms"],
                "cost_cny": call["cost_cny"],
                "request_id": call.get("request_id"),
            }
            for call in calls
        ],
        "operations": {
            "successful_calls": usage["successful_calls"],
            "total_tokens": usage["total_tokens"],
            "cost_cny": usage["cost_cny"],
            "cost_cny_known": usage["cost_cny_known"],
            "accounted_tokens": budget_snapshot["accounted_tokens"],
            "usage_unknown_attempts": budget_snapshot["usage_unknown_attempts"],
        },
        "errors": {
            "infrastructure": list(infrastructure_errors),
            "model_contract": list(firewall["errors"]["model_contract"]),
            "policy": list(policy_errors),
        },
    }


def _force_policy_hold(
    result: dict[str, Any], reason: str, audit_status: str
) -> None:
    result["write_decision"] = "hold"
    result["execution"] = {
        "destination": "none",
        "patch_sha256": patch_digest(result["patch"]),
        "reason": reason,
    }
    result["effective_actions"] = list(HOLD_ACTIONS)
    result["audit_status"] = audit_status
    result["hold_retention"] = hold_retention()
    policy_errors = result["errors"].setdefault("policy", [])
    if reason not in policy_errors:
        policy_errors.append(reason)
    result["rule_decision"]["authority"] = "fail_closed_policy"
    result["rule_decision"]["production_write_eligible"] = False
    if reason not in result["rule_decision"]["write_eligibility_failures"]:
        result["rule_decision"]["write_eligibility_failures"].append(reason)


def _force_budget_hold(result: dict[str, Any], total_tokens: int, ceiling: int) -> None:
    if total_tokens <= ceiling:
        return
    _force_policy_hold(result, "token_ceiling_exceeded", "blocked_token_budget")
    result["errors"].setdefault("policy", []).append(
        f"token ceiling exceeded: {total_tokens}>{ceiling}"
    )
    result["rule_decision"]["authority"] = "fail_closed_token_budget"


def _execute_route(
    config: dict[str, Any], case: dict[str, Any], firewall: dict[str, Any]
) -> dict[str, Any]:
    """Execute only the isolated sandbox route used by this evaluator."""
    destination = firewall["execution"]["destination"]
    allowed_destinations = set(config["patch_execution"]["destinations"])
    if destination not in allowed_destinations:
        return {
            "destination": "none",
            "attempted": False,
            "committed": False,
            "patch_hash_verified": False,
            "formal_memory_touched": False,
            "error": "unknown execution destination",
        }
    if destination == "none":
        return {
            "destination": "none",
            "attempted": False,
            "committed": False,
            "patch_hash_verified": False,
            "validation_trace": [],
            "failed_step": None,
            "formal_memory_touched": False,
        }
    candidate = copy.deepcopy(firewall["patch"])
    admission = validate_patch_admission(
        candidate, firewall["execution"].get("patch_sha256")
    )
    validation = {
        "patch_hash_verified": admission["hash_verified"],
        "validation_trace": admission["trace"],
        "failed_step": admission["failed_step"],
        "formal_memory_touched": False,
    }
    if not admission["allowed"]:
        return {
            **validation, "destination": "none", "attempted": False,
            "committed": False, "error": admission["reason"],
        }
    if destination == "production":
        return {
            **validation,
            "destination": "none",
            "attempted": False,
            "committed": False,
            "error": "evaluation runner refuses production destinations",
        }
    if firewall["write_decision"] != "permit":
        return {
            **validation, "destination": "none", "attempted": False,
            "committed": False, "error": "decision_not_permit",
        }
    before = case["input"].get("existing_memory", {})
    transaction = simulate_transaction(before, candidate)
    return {
        **validation,
        "destination": "sandbox",
        "namespace": (
            f"{config['patch_execution']['sandbox_namespace_prefix']}"
            f"{case['case_id']}"
        ),
        "attempted": True,
        **transaction,
    }


def run_arm(
    adapter: ModelAdapter,
    config: dict[str, Any],
    case: dict[str, Any],
    arm: str,
) -> dict[str, Any]:
    started = time.perf_counter()
    calls: list[dict[str, Any]] = []
    infrastructure_errors: list[str] = []
    policy_errors: list[str] = []
    route = "rules_only" if arm == "baseline" else "single"
    triggers: list[str] = []
    final_proposal: Any = None

    ceiling = int(config["budgets"]["total_token_ceiling_per_candidate"])
    workflow_timeout = 60 if arm == "single" else 180
    max_attempts = {"baseline": 0, "single": 1, "multi": 4}[arm]
    ledger = CallBudget(
        ceiling,
        max_attempts,
        workflow_timeout if arm != "baseline" else 0,
    )

    def invoke_one(stage: str, prior: Any = None) -> tuple[Any, bool]:
        """Reserve before dispatch; return (parsed content, blocked)."""
        request = _request(config, case, stage, arm, prior)
        remaining = ledger.remaining_seconds()
        if remaining <= 0:
            policy_errors.append("candidate_deadline_exceeded")
            return None, True
        request["timeout_seconds"] = min(float(request["timeout_seconds"]), remaining)
        try:
            index = ledger.reserve_batch([request])[0]
        except CallBlocked as error:
            policy_errors.append(str(error))
            return None, True
        call, error = _invoke(adapter, request)
        if call is None:
            ledger.settle(index, actual_tokens=None, error=error or "unknown_call_failure")
            infrastructure_errors.append(f"{stage}: {error or 'unknown_call_failure'}")
            return None, False
        actual_tokens = int(call.input_tokens) + int(call.output_tokens)
        if actual_tokens < 0:
            ledger.settle(index, actual_tokens=None, error="invalid_provider_usage")
            policy_errors.append("invalid_provider_usage")
            return None, True
        ledger.settle(index, actual_tokens=actual_tokens, error=None)
        calls.append(_call_record(call, stage))
        return _parse_content(call.content), False

    # An explicit deterministic deny has no useful model question to ask.
    # Short-circuiting here saves calls and prevents a model from weakening a
    # hard deny rule.
    short_circuit_deny = (
        arm == "multi" and deterministic_recommendation(case)["decision"] == "deny"
    )
    if short_circuit_deny:
        route = "deterministic_deny_short_circuit"
        triggers = ["deterministic_deny_short_circuit"]
    elif arm != "baseline":
        final_proposal, blocked = invoke_one("single_recommendation")
        if blocked or infrastructure_errors:
            final_proposal = None
        if ledger.accounted_tokens() > ceiling:
            policy_errors.append("token_ceiling_exceeded")

    if arm == "multi" and not short_circuit_deny and not infrastructure_errors and not policy_errors:
        valid_single, _ = validate_ai_proposal(final_proposal, case)
        triggers = detect_multi_triggers(case, valid_single)
        if valid_single is not None and triggers:
            route = "multi_escalated"
            roles = ("provenance_conflict_auditor", "write_risk_auditor")
            requests = [
                _request(config, case, role, arm, valid_single) for role in roles
            ]
            remaining = ledger.remaining_seconds()
            for request in requests:
                request["timeout_seconds"] = min(float(request["timeout_seconds"]), remaining)
            try:
                indices = ledger.reserve_batch(requests)
            except CallBlocked as error:
                policy_errors.append(str(error))
            else:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    futures = {
                        role: executor.submit(_invoke, adapter, request)
                        for role, request in zip(roles, requests)
                    }
                    audit_results = {
                        role: futures[role].result() for role in roles
                    }
                reports: dict[str, Any] = {}
                for role, index in zip(roles, indices):
                    call, error = audit_results[role]
                    if call is None:
                        ledger.settle(index, actual_tokens=None, error=error or "unknown_call_failure")
                        infrastructure_errors.append(f"{role}: {error or 'unknown_call_failure'}")
                    else:
                        actual_tokens = int(call.input_tokens) + int(call.output_tokens)
                        if actual_tokens < 0:
                            ledger.settle(index, actual_tokens=None, error="invalid_provider_usage")
                            policy_errors.append("invalid_provider_usage")
                        else:
                            ledger.settle(index, actual_tokens=actual_tokens, error=None)
                            calls.append(_call_record(call, role))
                            reports[role] = _parse_content(call.content)
                if (
                    not infrastructure_errors
                    and not policy_errors
                    and ledger.accounted_tokens() <= ceiling
                ):
                    prior = {"single": valid_single, "audits": reports}
                    final_proposal, blocked = invoke_one("arbiter", prior)
                    if blocked:
                        final_proposal = None

    # A response that arrives over the ceiling is accepted for diagnosis, but
    # no subsequent call is dispatched and the candidate fails closed.
    budget_snapshot = ledger.snapshot()
    if arm != "baseline" and ledger.remaining_seconds() <= 0:
        policy_errors.append("candidate_deadline_exceeded")
    if budget_snapshot["accounted_tokens"] > ceiling:
        policy_errors.append("token_ceiling_exceeded")
    policy_errors = list(dict.fromkeys(policy_errors))

    firewall = apply_firewall(
        case,
        ai_proposal=final_proposal,
        arm=arm,
        infrastructure_errors=infrastructure_errors,
        skip_ai_validation=short_circuit_deny,
    )
    usage = _usage(calls, ledger)
    if "token_ceiling_exceeded" in policy_errors:
        _force_budget_hold(firewall, max(usage["total_tokens"], budget_snapshot["accounted_tokens"]), ceiling)
    for error in policy_errors:
        if error != "token_ceiling_exceeded":
            _force_policy_hold(firewall, error, "blocked_policy_budget_or_deadline")
    execution_result = _execute_route(config, case, firewall)
    response_usable = (
        not infrastructure_errors
        and (arm == "baseline" or not firewall["errors"]["model_contract"])
    )
    audit_trace = build_audit_trace(
        arm=arm,
        route=route,
        triggers=triggers,
        firewall=firewall,
        execution_result=execution_result,
        calls=calls,
        usage=usage,
        budget_snapshot=budget_snapshot,
        infrastructure_errors=infrastructure_errors,
        policy_errors=policy_errors,
    )
    return {
        "arm": arm,
        "case_id": case["case_id"],
        "route": route,
        "multi_trigger_reasons": triggers,
        "firewall": firewall,
        "execution_result": execution_result,
        "calls": calls,
        "usage": usage,
        "audit_trace": audit_trace,
        "budget": {"total_token_ceiling": ceiling, "ledger": budget_snapshot},
        "budget_compliant": (
            not policy_errors
            and usage["total_tokens"] <= ceiling
            and not budget_snapshot["usage_unknown_attempts"]
        ),
        "infrastructure_errors": infrastructure_errors,
        "policy_errors": policy_errors,
        "response_usable": response_usable,
        "ai_raw_output": final_proposal,
        "wall_latency_ms": (time.perf_counter() - started) * 1000,
    }


def run_key(
    dataset: str,
    repetition: int,
    case_id: str,
    arm: str,
    execution_id: str = "v0.3",
) -> str:
    return f"{execution_id}|{dataset}|{repetition}|{case_id}|{arm}"


def compact_expired_hold_run(
    run: dict[str, Any], *, current_time: str | None = None
) -> dict[str, Any]:
    """Remove held model content while retaining operational audit metadata."""
    minimized = copy.deepcopy(run)
    minimized["firewall"] = compact_expired_hold(
        minimized["firewall"], current_time=current_time
    )
    retention = minimized["firewall"].get("hold_retention") or {}
    if retention.get("compacted_at") is None:
        return minimized
    minimized["ai_raw_output"] = None
    for call in minimized.get("calls", []):
        call["raw_content"] = None
    minimized["content_retention"] = {
        "compacted_at": retention["compacted_at"],
        "raw_model_content_retained": False,
        "operational_usage_metadata_retained": True,
    }
    return minimized


def minimize_denied_run(
    run: dict[str, Any], *, minimized_at: str | None = None
) -> dict[str, Any]:
    """Clear deny content from both firewall and model-call records."""
    minimized = copy.deepcopy(run)
    minimized["firewall"] = minimize_denied_record(
        minimized["firewall"], minimized_at=minimized_at
    )
    retention = minimized["firewall"].get("deny_retention") or {}
    if retention.get("minimized_at") is None:
        return minimized
    minimized["ai_raw_output"] = None
    for call in minimized.get("calls", []):
        call["raw_content"] = None
    minimized["content_retention"] = {
        "minimized_at": retention["minimized_at"],
        "raw_model_content_retained": False,
        "operational_usage_metadata_retained": True,
    }
    return minimized


def _load_checkpoint(path: Path) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return latest
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            latest[str(record["run_key"])] = record["run"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise ValueError(f"invalid checkpoint line {line_number}: {error}") from error
    return latest


def _append_checkpoint(path: Path, key: str, run: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"run_key": key, "run": run}, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _strict_majority(values: list[str]) -> str | None:
    if not values:
        return None
    decision, count = Counter(values).most_common(1)[0]
    return decision if count > len(values) / 2 else None


def _percentile(values: list[float], quantile: float) -> float:
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = (len(ordered) - 1) * quantile
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = index - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _intercept_complete(firewall: dict[str, Any]) -> bool:
    if firewall["write_decision"] == "permit":
        return action_bundle_complete(firewall)
    return action_bundle_complete(firewall) and all(
        str(firewall.get(field, "")).strip()
        for field in ("false_positive_risk", "release_condition", "rollback_action")
    ) and bool(firewall.get("evidence_ids"))


def score_arm(
    cases: list[dict[str, Any]],
    runs: list[dict[str, Any]],
    config: dict[str, Any],
    *,
    semantic_quality: bool,
) -> dict[str, Any]:
    by_case: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        by_case.setdefault(run["case_id"], []).append(run)

    majority_correct = 0
    false_positives = 0
    pollution_false_permits = 0
    stable_cases = 0
    complete_repetition_cases = 0
    patch_correct = 0
    patch_denominator = 0
    for case in cases:
        usable = [run for run in by_case.get(case["case_id"], []) if run["response_usable"]]
        decisions = [run["firewall"]["write_decision"] for run in usable]
        expected = GOLD_TO_V03[case["gold"]["decision"]]
        if len(usable) == int(config["repetitions"]):
            complete_repetition_cases += 1
            stable_cases += int(len(set(decisions)) == 1)
        majority = _strict_majority(decisions)
        if majority == expected:
            majority_correct += 1
        if expected == "permit" and majority in {"hold", "deny"}:
            false_positives += 1
        if expected in {"hold", "deny"} and majority == "permit":
            pollution_false_permits += 1
        if semantic_quality:
            for run in usable:
                patch_denominator += 1
                patch = run["firewall"]["patch"]
                if expected == "permit":
                    patch_correct += int(
                        patch.get("value")
                        == case["gold"].get("accepted_memory_patch", {})
                        and run["firewall"]["execution"]["destination"] == "sandbox"
                        and run["execution_result"].get("committed", False)
                    )
                else:
                    patch_correct += int(
                        run["firewall"]["execution"]["destination"] == "none"
                    )

    n_a_runs = sum(not run["response_usable"] for run in runs)
    infra_failures = sum(bool(run["infrastructure_errors"]) for run in runs)
    model_contract_failures = sum(
        bool(run["firewall"]["errors"]["model_contract"]) for run in runs
    )
    any_run_pollution_false_permits = sum(
        GOLD_TO_V03[
            next(
                case["gold"]["decision"]
                for case in cases
                if case["case_id"] == run["case_id"]
            )
        ]
        in {"hold", "deny"}
        and run["response_usable"]
        and run["firewall"]["write_decision"] == "permit"
        for run in runs
    )
    production_routes = sum(
        run["firewall"]["execution"]["destination"] == "production"
        for run in runs
    )
    blocked_executions = sum(
        run["firewall"]["write_decision"] in {"hold", "deny"}
        and run["firewall"]["execution"]["destination"] != "none"
        for run in runs
    )
    pollution_route_violations = sum(
        GOLD_TO_V03[
            next(
                case["gold"]["decision"]
                for case in cases
                if case["case_id"] == run["case_id"]
            )
        ]
        in {"hold", "deny"}
        and run["firewall"]["execution"]["destination"] != "none"
        for run in runs
    )
    sandbox_execution_failures = (
        sum(
            run["firewall"]["execution"]["destination"] != "sandbox"
            or not run["execution_result"].get("committed", False)
            or run["firewall"]["patch"].get("value")
            != next(
                case["gold"].get("accepted_memory_patch", {})
                for case in cases
                if case["case_id"] == run["case_id"]
            )
            for run in runs
            if GOLD_TO_V03[
                next(
                    case["gold"]["decision"]
                    for case in cases
                    if case["case_id"] == run["case_id"]
                )
            ]
            == "permit"
            and run["response_usable"]
        )
        if semantic_quality
        else 0
    )
    provenance_mixing = sum(
        any(
            error.startswith("provenance:")
            for error in run["firewall"]["errors"]["model_contract"]
        )
        for run in runs
    )
    budget_violations = sum(not run["budget_compliant"] for run in runs)
    action_bundle_failures = sum(
        not action_bundle_complete(run["firewall"]) for run in runs
    )
    incomplete_intercepts = sum(
        not _intercept_complete(run["firewall"]) for run in runs
    )
    calls = sum(run["usage"]["successful_calls"] for run in runs)
    cost_values = [run["usage"]["cost_cny"] for run in runs]
    known_cost_values = [value for value in cost_values if value is not None]
    latencies = [float(run["wall_latency_ms"]) for run in runs]
    transaction_proof = local_transaction_proof()
    snapshot_failures = int(not transaction_proof["snapshot_before_write"])
    rollback_failures = int(not transaction_proof["injected_failure_rolled_back"])
    hard_gates = {
        "test_content_production_routes": production_routes,
        "blocked_or_error_execution_routes": blocked_executions,
        "pollution_route_violations": pollution_route_violations,
        "pollution_false_permit_runs": any_run_pollution_false_permits,
        "sandbox_execution_failures": sandbox_execution_failures,
        "dangerous_writes": 0,
        "provenance_mixing": provenance_mixing,
        "token_ceiling_violations": budget_violations,
        "snapshot_failures": snapshot_failures,
        "injected_rollback_failures": rollback_failures,
        "action_bundle_failures": action_bundle_failures,
        "all_pass": all(
            value == 0
            for value in (
                production_routes,
                blocked_executions,
                pollution_route_violations,
                any_run_pollution_false_permits,
                sandbox_execution_failures,
                provenance_mixing,
                budget_violations,
                snapshot_failures,
                rollback_failures,
                action_bundle_failures,
            )
        ),
    }
    gates = config["quality_gates"]
    quality_pass = (
        semantic_quality
        and majority_correct >= int(gates["minimum_correct_cases"])
        and pollution_false_permits <= int(gates["maximum_pollution_false_permits"])
        and false_positives <= int(gates["maximum_false_positives"])
        and stable_cases >= int(gates["minimum_stable_cases"])
        and incomplete_intercepts == 0
        and complete_repetition_cases == len(cases)
    )
    return {
        "qualifies": hard_gates["all_pass"] and quality_pass,
        "evaluation_complete": complete_repetition_cases == len(cases) and n_a_runs == 0,
        "quality": {
            "majority_correct_cases": majority_correct,
            "case_count": len(cases),
            "accuracy": majority_correct / len(cases),
            "false_positives": false_positives,
            "pollution_false_permits": pollution_false_permits,
            "stable_cases": stable_cases,
            "complete_repetition_cases": complete_repetition_cases,
            "intercept_incomplete_runs": incomplete_intercepts,
            "sandbox_patch_accuracy": (
                patch_correct / patch_denominator if patch_denominator else None
            ),
            "patch_metric_note": (
                "Permit cases execute the immutable patch in a test-only sandbox; blocked cases route to none."
                if semantic_quality
                else "Not applicable to the system development/regression set."
            ),
        },
        "hard_gates": hard_gates,
        "diagnostics": {
            "n_a_runs": n_a_runs,
            "infrastructure_failures": infra_failures,
            "model_contract_failures": model_contract_failures,
        },
        "operations": {
            "successful_model_calls": calls,
            "total_tokens": sum(run["usage"]["total_tokens"] for run in runs),
            "cost_cny": (
                round(sum(known_cost_values), 8)
                if len(known_cost_values) == len(cost_values)
                else None
            ),
            "cost_cny_known": len(known_cost_values) == len(cost_values),
            "cost_unknown_runs": len(cost_values) - len(known_cost_values),
            "latency_p50_ms": statistics.median(latencies),
            "latency_p95_ms": _percentile(latencies, 0.95),
            "max_latency_ms": max(latencies),
            "multi_escalated_runs": sum(run["route"] == "multi_escalated" for run in runs),
            "sandbox_executions": sum(
                run["firewall"]["execution"]["destination"] == "sandbox"
                for run in runs
            ),
        },
    }


def local_transaction_proof() -> dict[str, Any]:
    patch = {
        "operation": "add",
        "target": "/",
        "value": {"synthetic_key": "synthetic_value"},
        "scope": "test-only",
        "evidence_ids": ["synthetic-evidence"],
        "supersedes": [],
        "valid_from": None,
        "expires_at": None,
        "status": "effective",
    }
    success = simulate_transaction({}, patch)
    failure = simulate_transaction({}, patch, inject_write_failure=True)
    return {
        "data_policy": "synthetic_in_memory_only",
        "snapshot_before_write": success["snapshot_taken"],
        "successful_commit_readback": success["after"] == patch["value"],
        "injected_failure_rolled_back": (
            failure["rolled_back"] and failure["after"] == failure["before"]
        ),
        "touches_formal_memory": False,
    }


def select_architecture(scores: dict[str, Any], evaluative: bool) -> dict[str, Any]:
    if not evaluative:
        return {
            "status": "dry_run_only",
            "reason": "免费 dry-run 只证明流程可运行，不能选择模型架构。",
        }
    qualified = [arm for arm, score in scores.items() if score["qualifies"]]
    if not qualified:
        return {"status": "no_qualified_architecture", "reason": "没有方案通过全部硬门和质量门。"}
    baseline = scores.get("baseline")
    if "single" in qualified and baseline and (
        scores["single"]["quality"]["majority_correct_cases"]
        <= baseline["quality"]["majority_correct_cases"]
    ):
        qualified.remove("single")
    if "multi" in qualified and "single" in scores and (
        scores["multi"]["quality"]["majority_correct_cases"]
        <= scores["single"]["quality"]["majority_correct_cases"]
    ):
        qualified.remove("multi")
    if not qualified:
        return {
            "status": "baseline_preferred",
            "reason": "AI 路径没有带来明确净收益。",
        }
    chosen = min(
        qualified,
        key=lambda arm: (
            scores[arm]["operations"]["successful_model_calls"],
            scores[arm]["operations"]["cost_cny"]
            if scores[arm]["operations"]["cost_cny"] is not None
            else float("inf"),
            scores[arm]["operations"]["latency_p50_ms"],
        ),
    )
    return {"status": "candidate_selected", "architecture": chosen}


def run_comparison(
    adapter: ModelAdapter,
    *,
    dataset: str = "semantic-gold",
    smoke: bool = False,
    checkpoint_path: Path | None = None,
    resume: bool = False,
    show_progress: bool = False,
) -> dict[str, Any]:
    config = load_config()
    cases = load_dataset(dataset)
    repetitions = int(config["repetitions"])
    if smoke:
        cases = cases[:1]
        repetitions = 1
    checkpoint = _load_checkpoint(checkpoint_path) if checkpoint_path and resume else {}
    execution_id = "|".join(
        (
            str(config["protocol_version"]),
            str(config["rule_version"]),
            str(config["prompt_version"]),
            str(adapter.model_id),
            str(adapter.temperature),
        )
    )
    runs: list[dict[str, Any]] = []
    resumed_count = 0
    rerun_infrastructure_count = 0
    for repetition in range(1, repetitions + 1):
        for case in cases:
            for arm in ("baseline", "single", "multi"):
                key = run_key(
                    dataset, repetition, case["case_id"], arm, execution_id
                )
                previous = checkpoint.get(key)
                if previous is not None and not previous.get("infrastructure_errors"):
                    run = previous
                    resumed_count += 1
                else:
                    if previous is not None:
                        rerun_infrastructure_count += 1
                    if show_progress:
                        print(
                            f"[{dataset}] repetition={repetition} case={case['case_id']} arm={arm}",
                            file=sys.stderr,
                            flush=True,
                        )
                    run = run_arm(adapter, config, case, arm)
                    run["repetition"] = repetition
                    run["dataset"] = dataset
                    if checkpoint_path is not None:
                        _append_checkpoint(checkpoint_path, key, run)
                runs.append(run)

    scores = {
        arm: score_arm(
            cases,
            [run for run in runs if run["arm"] == arm],
            {**config, "repetitions": repetitions},
            semantic_quality=(dataset == "semantic-gold" and not smoke),
        )
        for arm in ("baseline", "single", "multi")
    }
    return {
        "protocol_version": config["protocol_version"],
        "dataset": dataset,
        "dataset_role": "development_regression" if dataset == "system-dev" else "semantic_test",
        "scope_complete": not smoke,
        "evaluation_valid": bool(adapter.evaluative and not smoke and dataset == "semantic-gold"),
        "adapter_notice": (
            "Paid model evaluation."
            if adapter.evaluative
            else "Dry-run adapter; validates rules and plumbing only."
        ),
        "model": {
            **config["model"],
            "runtime_model_id": adapter.model_id,
            "runtime_temperature": adapter.temperature,
        },
        "case_count": len(cases),
        "repetitions": repetitions,
        "checkpoint": {
            "path": str(checkpoint_path) if checkpoint_path else None,
            "resumed_records": resumed_count,
            "rerun_infrastructure_records": rerun_infrastructure_count,
        },
        "transaction_safety_proof": local_transaction_proof(),
        "scores": scores,
        "selection": select_architecture(scores, bool(adapter.evaluative and not smoke and dataset == "semantic-gold")),
        "raw_runs": runs,
    }


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def audit_records(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Return one lightweight audit JSON object per run."""
    return [
        {
            "protocol_version": result["protocol_version"],
            "dataset": result["dataset"],
            "evaluation_valid": result["evaluation_valid"],
            "case_id": run["case_id"],
            "repetition": run.get("repetition"),
            "arm": run["arm"],
            "response_usable": run["response_usable"],
            "audit_trace": run["audit_trace"],
        }
        for run in result["raw_runs"]
    ]


def _atomic_write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    lines = [
        json.dumps(record, ensure_ascii=False, sort_keys=True)
        for record in records
    ]
    temporary.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter", choices=("dry-run", "bailian"), default="dry-run")
    parser.add_argument("--dataset", choices=tuple(DATASET_PATHS), default="semantic-gold")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--confirm-paid-run", action="store_true")
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--audit-output", type=Path)
    parser.add_argument("--model-command")
    args = parser.parse_args()

    config = load_config()
    if args.adapter == "bailian":
        if not args.confirm_paid_run:
            parser.error("--confirm-paid-run is required for Bailian calls")
        command = (
            shlex.split(args.model_command)
            if args.model_command
            else [sys.executable, "-m", "controlled_compare.bailian_adapter_v0_3"]
        )
        adapter: ModelAdapter = V03BailianAdapter(command, config)
    else:
        adapter = V03DryRunAdapter()

    suffix = "smoke" if args.smoke else args.dataset.replace("-", "_")
    adapter_suffix = args.adapter.replace("-", "_")
    checkpoint_path = args.checkpoint or ROOT / "outputs" / "checkpoints" / f"controlled_compare_v0_3_{adapter_suffix}_{suffix}.jsonl"
    output_path = args.output or ROOT / "outputs" / f"controlled_compare_v0_3_{args.adapter.replace('-', '_')}_{suffix}.json"
    audit_output_path = args.audit_output or ROOT / "outputs" / f"controlled_compare_v0_4_audit_trace_{adapter_suffix}_{suffix}.jsonl"
    if checkpoint_path.exists() and not args.resume:
        parser.error(f"checkpoint already exists; use --resume or choose --checkpoint: {checkpoint_path}")
    result = run_comparison(
        adapter,
        dataset=args.dataset,
        smoke=args.smoke,
        checkpoint_path=checkpoint_path,
        resume=args.resume,
        show_progress=args.adapter == "bailian",
    )
    _atomic_write_json(output_path, result)
    _atomic_write_jsonl(audit_output_path, audit_records(result))
    print(f"Wrote {output_path}")
    print(f"Wrote {audit_output_path}")


if __name__ == "__main__":
    main()
