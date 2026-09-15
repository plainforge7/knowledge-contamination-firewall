"""Deterministic write firewall for protocol v0.3.

The model may recommend a decision and one immutable patch. This module owns
the final decision, safety actions, and execution destination. Evaluation
patches can run only in an isolated in-memory sandbox.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any


RULE_VERSION = "0.3.1-scope-target"
HOLD_RETENTION_DAYS = 30
HOLD_AUDIT_RETENTION_DAYS = 90
WRITE_DECISIONS = {"permit", "hold", "deny"}
REOPEN_BASIS_TYPES = {
    "new_evidence",
    "explicit_user_correction",
    "verified_human_review",
}
DECISION_SEVERITY = {"permit": 0, "hold": 1, "deny": 2}
PATCH_FIELDS = {
    "operation",
    "target",
    "value",
    "scope",
    "evidence_ids",
    "supersedes",
    "valid_from",
    "expires_at",
    "status",
}

# Exact, scope-specific matches only. No prefix matching, path normalization,
# default scope or fallback from one scope's targets to another scope's targets.
SCOPE_TARGET_WHITELIST = {
    "personal_long_term_memory": [
        "/fields/summary",
        "/fields/tags",
        "/fields/confidence",
    ],
    "test-only": ["/"],
}


def _target_is_allowed(scope: str, target: Any) -> bool:
    return isinstance(target, str) and target in SCOPE_TARGET_WHITELIST[scope]


def validate_patch_location(patch: Mapping[str, Any]) -> dict[str, Any]:
    """Admission steps 1–2. Invalid scope never reaches the target lookup."""
    trace = ["scope"]
    scope = patch.get("scope")
    if not isinstance(scope, str) or scope not in SCOPE_TARGET_WHITELIST:
        return {"allowed": False, "failed_step": 1,
                "reason": "patch_scope_not_allowed", "trace": trace}
    trace.append("target")
    if not _target_is_allowed(scope, patch.get("target")):
        return {"allowed": False, "failed_step": 2,
                "reason": "patch_target_not_allowed", "trace": trace}
    return {"allowed": True, "failed_step": None,
            "reason": "patch_location_allowed", "trace": trace}


def validate_patch_admission(
    patch: Mapping[str, Any], expected_sha256: str | None
) -> dict[str, Any]:
    """Check scope, then target, THEN the host-held digest; never modify patch.

    The digest is external (execution.patch_sha256), avoiding a self-hash.
    Passing this gate does not itself grant consent or production write authority.
    """
    result = validate_patch_location(patch)
    result["hash_verified"] = False
    if not result["allowed"]:
        return result
    result["trace"].append("patch_sha256")
    if not isinstance(expected_sha256, str) or patch_digest(patch) != expected_sha256:
        result.update(allowed=False, failed_step=3, reason="patch_hash_mismatch")
        return result
    result.update(hash_verified=True, reason="patch_admission_passed")
    return result

PERMIT_ACTIONS = (
    "validate_candidate_and_patch",
    "snapshot_current_memory",
    "verify_memory_version",
    "transactional_commit_if_eligible",
    "read_back_and_compare",
    "rollback_and_hold_on_failure",
)
HOLD_ACTIONS = (
    "isolate_candidate_and_derived_patches",
    "close_write_gate",
    "preserve_review_record",
    "await_human_confirmation_or_new_evidence",
    "schedule_hold_expiry_and_data_minimization",
)
DENY_ACTIONS = (
    "reject_candidate_and_derived_patches",
    "preserve_current_memory",
    "record_denial_and_reopen_conditions",
    "disable_automatic_write_retry",
    "minimize_denied_content_immediately",
)

DENY_MALICIOUS = {"prompt_injection", "forged_authorization"}
DENY_OUT_OF_SCOPE = {"out_of_scope_world_claim"}
DENY_STALE_AUTOMATION = {"stale_background_replace", "cron_session"}
HOLD_UNCERTAINTY = {
    "uncertain_language",
    "hypothetical_future",
    "not_decided",
    "recent_behavior",
    "possible_emerging_preference",
    "unmet_condition",
    "conflicting_definitions",
    "user_uncertain",
    "third_party_old_health_claim",
    "current_inference",
    "unsupported_forensic_claim",
    "unresolved_baseline",
    "failed_regression",
    "split_brain_memory",
}
EXPLICIT_RESOLUTION = {"explicit_replacement", "explicit_correction"}
HIGH_IMPACT_SIGNALS = {
    "sensitive_health_data",
    "health_context",
    "third_party_old_health_claim",
    "high_stakes",
    "identity_data",
    "financial_claim",
    "meta_memory_policy",
    "privacy_data",
    "address_data",
}
AMBIGUOUS_ENTITY_SIGNALS = {
    "ambiguous_entity_ownership",
    "entity_ownership_unknown",
    "possible_wrong_person",
}
PROHIBITED_STORAGE_SIGNALS = (
    DENY_MALICIOUS
    | DENY_OUT_OF_SCOPE
    | DENY_STALE_AUTOMATION
    | {"third_party_unverified", "comparison_based_inference"}
)

# Source labels are provenance, not trust by themselves.  This allowlist is a
# conservative default for frozen cases; a case may override it with an
# explicit evidence-level trust_status of verified/unverified.
TRUSTED_SOURCE_TYPES = {
    "user_direct",
    "human_confirmed",
    "stored_memory",
    "persisted_structured_fields",
    "rendered_content",
    "system_observation",
    "document_verified",
}


def empty_patch(*, status: str = "proposed") -> dict[str, Any]:
    """Return a complete, explicitly non-writing patch object."""
    return {
        "operation": "none",
        "target": None,
        "value": None,
        "scope": None,
        "evidence_ids": [],
        "supersedes": [],
        "valid_from": None,
        "expires_at": None,
        "status": status,
    }


def candidate_patch(case: Mapping[str, Any]) -> dict[str, Any]:
    """Convert the case's non-executable candidate into the v0.3 patch schema."""
    case_input = case.get("input", {})
    raw_patch = case_input.get("proposed_memory_patch")
    if not isinstance(raw_patch, Mapping) or not raw_patch:
        return empty_patch(status="proposed")
    evidence_ids = [
        item.get("id")
        for item in case_input.get("evidence", [])
        if isinstance(item, Mapping) and item.get("id")
    ]
    operation = "replace" if case_input.get("existing_memory") else "add"
    write_context = case_input.get("write_context", {})
    write_context = write_context if isinstance(write_context, Mapping) else {}
    # Frozen Gold contains legacy VALUES rather than executable patches. This
    # adapter explicitly creates a test-only patch; it never repairs AI patches.
    # Production callers must supply both fields; missing values remain missing.
    if _is_test_case(case) and not (
        "patch_scope" in write_context or "patch_target" in write_context
    ):
        scope, target = "test-only", "/"
    else:
        scope = write_context.get("patch_scope")
        target = write_context.get("patch_target")
    return {
        "operation": operation,
        "target": target,
        "value": copy.deepcopy(dict(raw_patch)),
        "scope": scope,
        "evidence_ids": evidence_ids,
        "supersedes": [],
        "valid_from": None,
        "expires_at": None,
        "status": "proposed",
    }


class DuplicateEvidenceError(ValueError):
    """Raised when a case declares two evidence items with the same id."""


def _case_evidence(case: Mapping[str, Any]) -> dict[str, str]:
    evidence: dict[str, str] = {}
    for item in case.get("input", {}).get("evidence", []):
        if isinstance(item, Mapping) and item.get("id"):
            key = str(item["id"])
            if key in evidence:
                raise DuplicateEvidenceError(key)
            evidence[key] = str(item.get("source_type", "unknown"))
    return evidence


def _trusted_evidence_ids(case: Mapping[str, Any]) -> set[str]:
    """Return evidence explicitly trusted or conservatively allowlisted."""
    trusted: set[str] = set()
    for item in case.get("input", {}).get("evidence", []):
        if not isinstance(item, Mapping) or not item.get("id"):
            continue
        status = item.get("trust_status")
        if status is not None:
            if str(status).lower() in {"verified", "trusted", "confirmed"}:
                trusted.add(str(item["id"]))
            continue
        if str(item.get("source_type", "unknown")) in TRUSTED_SOURCE_TYPES:
            trusted.add(str(item["id"]))
    return trusted


def _intercept_detail(
    rule_id: str,
    evidence_ids: list[str],
    reason: str,
    false_positive_risk: str,
    release_condition: str,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "evidence_ids": evidence_ids,
        "reason": reason,
        "false_positive_risk": false_positive_risk,
        "release_condition": release_condition,
        "rollback_action": "保留或恢复到写入前已验证版本，并移除该候选的派生写入。",
    }


def deterministic_recommendation(case: Mapping[str, Any]) -> dict[str, Any]:
    """Classify a candidate with generic, case-independent safety rules."""
    case_input = case.get("input", {})
    risks = {str(item) for item in case_input.get("risk_signals", [])}
    evidence_ids = list(_case_evidence(case))
    source_type = str(case_input.get("source_type", "unknown"))

    if risks & DENY_MALICIOUS:
        detail = _intercept_detail(
            "R-DENY-FORGED-AUTHORITY",
            evidence_ids,
            "候选包含提示注入或伪造授权，不能取得记忆写入资格。",
            "真实的管理员说明可能被误判为伪造文本。",
            "由用户在可信交互中逐项确认内容和来源后，创建新候选重新审核。",
        )
        return {"decision": "deny", "matched_rules": [detail]}

    if risks & DENY_OUT_OF_SCOPE:
        detail = _intercept_detail(
            "R-DENY-NONPERSONAL-CLAIM",
            evidence_ids,
            "泛化的外部世界主张不属于个人长期记忆。",
            "与用户确有长期用途的个人背景可能被当作外部主张。",
            "将内容缩小为可核验、与用户直接相关且经确认的个人事实。",
        )
        return {"decision": "deny", "matched_rules": [detail]}

    if risks & DENY_STALE_AUTOMATION:
        detail = _intercept_detail(
            "R-DENY-STALE-AUTOMATION",
            evidence_ids,
            "旧会话或后台自动任务不得覆盖当前已验证状态。",
            "合法的后台同步可能被阻止。",
            "取得当前版本、重新计算变更并由当前会话确认后再建候选。",
        )
        return {"decision": "deny", "matched_rules": [detail]}

    if {"temporary_past_window", "conditional_preference"} <= risks:
        detail = _intercept_detail(
            "R-DENY-TRANSIENT-CONDITIONAL",
            evidence_ids,
            "短期且由暂时状态造成的行为不能升级为稳定偏好。",
            "短期行为后来可能确实成为稳定偏好。",
            "用户在状态结束后明确确认这是持续偏好，并说明是否需要记住。",
        )
        return {"decision": "deny", "matched_rules": [detail]}

    if {"third_party_unverified", "comparison_based_inference"} & risks:
        detail = _intercept_detail(
            "R-DENY-THIRD-PARTY-INFERENCE",
            evidence_ids,
            "第三方转述或比较推断不能被当作用户自身事实。",
            "第三方描述可能碰巧准确。",
            "由用户直接确认需要保存的自身事实，且不保留无关第三方内容。",
        )
        return {"decision": "deny", "matched_rules": [detail]}

    unresolved_conflict = (
        "conflict_with_existing" in risks and not risks & EXPLICIT_RESOLUTION
    )
    if unresolved_conflict or risks & HOLD_UNCERTAINTY:
        detail = _intercept_detail(
            "R-HOLD-UNRESOLVED-EVIDENCE",
            evidence_ids,
            "来源、时效、冲突或不确定性尚未解决。",
            "谨慎隔离可能延迟一个真实更新。",
            "获得直接、当前且能消解冲突的证据，或由用户明确更正。",
        )
        return {"decision": "hold", "matched_rules": [detail]}

    if risks & EXPLICIT_RESOLUTION and source_type == "user_direct":
        return {
            "decision": "permit",
            "matched_rules": [
                {
                    "rule_id": "R-PERMIT-EXPLICIT-RESOLUTION",
                    "evidence_ids": evidence_ids,
                    "reason": "用户直接、明确地更正或替换现有记忆。",
                }
            ],
        }

    if "clean_control" in risks or risks & {
        "stale_memory_conflicts_with_current_evidence",
        "stale_memory_conflict_resolved_by_current_evidence",
    }:
        return {
            "decision": "permit",
            "matched_rules": [
                {
                    "rule_id": "R-PERMIT-VERIFIED-SYSTEM-STATE",
                    "evidence_ids": evidence_ids,
                    "reason": "当前结构化证据已形成无冲突的验证结果。",
                }
            ],
        }

    if source_type in {"user_direct", "human_confirmed"}:
        return {
            "decision": "permit",
            "matched_rules": [
                {
                    "rule_id": "R-PERMIT-DIRECT-SOURCE",
                    "evidence_ids": evidence_ids,
                    "reason": "候选来自用户直接陈述，且未命中阻断条件。",
                }
            ],
        }

    detail = _intercept_detail(
        "R-HOLD-UNKNOWN",
        evidence_ids,
        "规则无法确认候选来源或写入资格。",
        "信息不足时默认隔离会延迟合法写入。",
        "补充直接来源、用途、时效与冲突信息后重新审核。",
    )
    return {"decision": "hold", "matched_rules": [detail]}


def validate_ai_proposal(
    proposal: Any, case: Mapping[str, Any]
) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate the AI contract and provenance without repairing model output."""
    if not isinstance(proposal, Mapping):
        return None, ["AI output must be an object"]
    output = copy.deepcopy(dict(proposal))
    required = {
        "write_decision",
        "evidence_ids",
        "source_labels",
        "recommended_actions",
        "false_positive_risk",
        "release_condition",
        "rollback_action",
        "uncertainty",
        "patch",
    }
    errors = [f"missing field: {field}" for field in sorted(required - output.keys())]
    if output.get("write_decision") not in WRITE_DECISIONS:
        errors.append("invalid write_decision")

    evidence = _case_evidence(case)
    evidence_ids = output.get("evidence_ids")
    if not isinstance(evidence_ids, list):
        errors.append("evidence_ids must be an array")
        evidence_ids = []
    elif not set(map(str, evidence_ids)).issubset(evidence):
        errors.append("provenance: unknown evidence ID")

    labels = output.get("source_labels")
    if not isinstance(labels, list):
        errors.append("source_labels must be an array")
    else:
        labelled_ids: set[str] = set()
        for label in labels:
            if not isinstance(label, Mapping):
                errors.append("source_labels entries must be objects")
                continue
            evidence_id = str(label.get("evidence_id", ""))
            labelled_ids.add(evidence_id)
            if evidence_id not in evidence:
                errors.append("provenance: source label uses unknown evidence ID")
            elif str(label.get("source_type", "")) != evidence[evidence_id]:
                errors.append("provenance: source type does not match original evidence")
        if set(map(str, evidence_ids)) != labelled_ids:
            errors.append("provenance: source labels must match declared evidence IDs")

    if not isinstance(output.get("recommended_actions"), list):
        errors.append("recommended_actions must be an array")
    for field in ("false_positive_risk", "release_condition", "rollback_action"):
        if not str(output.get(field, "")).strip():
            errors.append(f"{field} must be non-empty")

    patch = output.get("patch")
    if not isinstance(patch, Mapping):
        errors.append("patch must be an object")
    elif set(patch) != PATCH_FIELDS:
        errors.append("patch must contain exactly the v0.3 patch fields")
    else:
        if patch.get("operation") not in {"add", "replace", "delete", "none"}:
            errors.append("invalid patch operation")
        if patch.get("status") != "proposed":
            errors.append("patch status must be proposed")
        if not isinstance(patch.get("evidence_ids"), list):
            errors.append("patch evidence_ids must be an array")
        elif not set(map(str, patch["evidence_ids"])).issubset(evidence):
            errors.append("provenance: patch contains unknown evidence ID")
        elif not set(map(str, patch["evidence_ids"])).issubset(
            set(map(str, evidence_ids))
        ):
            errors.append("provenance: patch evidence is not declared at top level")
        if not isinstance(patch.get("supersedes"), list):
            errors.append("patch supersedes must be an array")
        if patch.get("operation") == "none" and (
            patch.get("target") is not None or patch.get("value") is not None
        ):
            errors.append("operation none cannot include target or value")
        if patch.get("operation") != "none" and not str(patch.get("target", "")).strip():
            errors.append("writing patch requires a target")
        if patch.get("operation") != "none" and not patch.get("evidence_ids"):
            errors.append("writing patch requires evidence_ids")
    return (output if not errors else None), errors


def detect_multi_triggers(
    case: Mapping[str, Any],
    single_proposal: Mapping[str, Any] | None = None,
) -> list[str]:
    """Return the confirmed product-track escalation reasons."""
    case_input = case.get("input", {})
    risks = {str(item) for item in case_input.get("risk_signals", [])}
    triggers: list[str] = []
    evidence = _case_evidence(case)
    trusted_ids = _trusted_evidence_ids(case)
    unresolved_conflict = (
        (
            "conflict_with_existing" in risks
            or "conflicting_definitions" in risks
            or "split_brain_memory" in risks
        )
        and not risks & EXPLICIT_RESOLUTION
        # Two distinct trusted evidence items are required.  Merely having
        # two source labels (e.g. third-party + inference) is not enough.
        and len(trusted_ids & set(evidence)) >= 2
    )
    if unresolved_conflict:
        triggers.append("unresolved_trustworthy_source_conflict")
    if risks & HIGH_IMPACT_SIGNALS:
        triggers.append("high_impact_information")
    if risks & AMBIGUOUS_ENTITY_SIGNALS:
        triggers.append("ambiguous_entity_ownership")
    if single_proposal is not None:
        rule_decision = deterministic_recommendation(case)["decision"]
        model_decision = single_proposal.get("write_decision")
        if model_decision in WRITE_DECISIONS and model_decision != rule_decision:
            triggers.append("single_recommendation_conflicts_with_rules")
    return list(dict.fromkeys(triggers))


def _fallback_explanations(
    decision: str, matched_rules: list[dict[str, Any]]
) -> dict[str, str]:
    first = matched_rules[0] if matched_rules else {}
    if decision == "permit":
        return {
            "false_positive_risk": "候选通过规则后仍可能因来源或版本变化而失效。",
            "release_condition": "继续通过 Patch、快照、版本与事务校验。",
            "rollback_action": "提交失败或证据被推翻时恢复写入前版本。",
        }
    return {
        "false_positive_risk": str(
            first.get("false_positive_risk", "谨慎拦截可能延迟合法写入。")
        ),
        "release_condition": str(
            first.get("release_condition", "取得新的直接证据后重新审核。")
        ),
        "rollback_action": str(
            first.get(
                "rollback_action", "保留或恢复写入前版本，并移除派生写入。"
            )
        ),
    }


def _is_test_case(case: Mapping[str, Any]) -> bool:
    provenance = case.get("provenance", {})
    data_policy = str(provenance.get("data_policy", ""))
    context = str(case.get("input", {}).get("context", ""))
    return (
        case.get("layer") in {"semantic", "system"}
        or data_policy in {"synthetic_only", "desensitized_only", "test_only"}
        or "测试文本" in context
    )


def _patch_scopes(patch: Mapping[str, Any]) -> set[str]:
    value = patch.get("value")
    if patch.get("target") == "/" and isinstance(value, Mapping):
        return {str(key) for key in value}
    target = str(patch.get("target", "")).strip("/")
    return {target.split("/", 1)[0]} if target else set()


def _sensitive_confirmation_errors(
    case: Mapping[str, Any], patch: Mapping[str, Any]
) -> list[str]:
    confirmation = case.get("human_confirmation")
    if not isinstance(confirmation, Mapping):
        return ["sensitive_human_confirmation_missing"]
    errors: list[str] = []
    if confirmation.get("status") != "approved":
        errors.append("sensitive_human_confirmation_not_approved")
    if confirmation.get("confirmation_type") != "sensitive_memory_review":
        errors.append("sensitive_confirmation_type_invalid")
    if confirmation.get("confirmed_by") != "user":
        errors.append("sensitive_confirmation_actor_invalid")
    if not str(confirmation.get("confirmation_id", "")).strip():
        errors.append("sensitive_confirmation_id_missing")
    if confirmation.get("verification_status") != "verified_by_host":
        errors.append("sensitive_confirmation_not_host_verified")
    if not str(confirmation.get("purpose", "")).strip():
        errors.append("sensitive_confirmation_purpose_missing")
    if not str(confirmation.get("retention", "")).strip():
        errors.append("sensitive_confirmation_retention_missing")
    approved_scope = confirmation.get("approved_scope")
    if not isinstance(approved_scope, list) or not approved_scope:
        errors.append("sensitive_confirmation_scope_missing")
    elif not _patch_scopes(patch).issubset({str(item) for item in approved_scope}):
        errors.append("sensitive_confirmation_scope_mismatch")
    if confirmation.get("patch_sha256") != patch_digest(patch):
        errors.append("sensitive_confirmation_patch_hash_mismatch")
    return errors


def storage_class(case: Mapping[str, Any]) -> str:
    risks = {str(item) for item in case.get("input", {}).get("risk_signals", [])}
    if risks & PROHIBITED_STORAGE_SIGNALS:
        return "prohibited"
    if risks & HIGH_IMPACT_SIGNALS:
        return "sensitive_storable"
    return "low_risk"


def _production_write_eligible(
    case: Mapping[str, Any], decision: str, patch: Mapping[str, Any]
) -> tuple[bool, list[str], str]:
    case_input = case.get("input", {})
    reasons: list[str] = []
    risks = {str(item) for item in case_input.get("risk_signals", [])}
    write_context = case_input.get("write_context", {})
    classification = storage_class(case)
    location = validate_patch_location(patch)
    if not location["allowed"]:
        # Includes sensitive-confirmation hashing: no hash check on illegal paths.
        return False, [location["reason"]], classification
    if patch.get("scope") != "personal_long_term_memory":
        reasons.append("test_only_scope_cannot_route_to_production")
    if decision != "permit":
        reasons.append("decision_not_permit")
    if _is_test_case(case):
        reasons.append("evaluation_content_routes_to_sandbox")
    if not case_input.get("explicit_memory_request", False):
        reasons.append("explicit_memory_request_missing")
    if case_input.get("source_type") not in {"user_direct", "human_confirmed"}:
        reasons.append("source_not_direct_or_human_confirmed")
    if classification == "prohibited":
        reasons.append("storage_class_prohibited")
    elif classification == "sensitive_storable":
        reasons.extend(_sensitive_confirmation_errors(case, patch))
    if risks & HOLD_UNCERTAINTY:
        reasons.append("unresolved_risk")
    if "conflict_with_existing" in risks and not risks & EXPLICIT_RESOLUTION:
        reasons.append("unresolved_conflict")
    if patch.get("operation") == "none":
        reasons.append("no_candidate_patch")
    if not isinstance(write_context, Mapping) or not write_context.get("current_version"):
        reasons.append("current_version_missing")
    elif write_context.get("current_version") != write_context.get("expected_version"):
        reasons.append("version_mismatch")
    return not reasons, list(dict.fromkeys(reasons)), classification


def patch_digest(patch: Mapping[str, Any]) -> str:
    """Bind the execution decision to one immutable patch value."""
    canonical = json.dumps(patch, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_utc(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("lifecycle timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def hold_retention(evaluated_at: str | None = None) -> dict[str, Any]:
    created = _parse_utc(evaluated_at)
    expires = created + timedelta(days=HOLD_RETENTION_DAYS)
    return {
        "retention_days": HOLD_RETENTION_DAYS,
        "created_at": _iso_utc(created),
        "expires_at": _iso_utc(expires),
        "on_expiry": "retain_audit_summary_only",
        "automatic_write_on_expiry": False,
        "audit_summary_format": "structured_jsonl",
        "audit_summary_retention_days": HOLD_AUDIT_RETENTION_DAYS,
        "compacted_at": None,
    }


def apply_firewall(
    case: Mapping[str, Any],
    *,
    ai_proposal: Any = None,
    arm: str = "baseline",
    infrastructure_errors: list[str] | None = None,
    skip_ai_validation: bool = False,
    evaluated_at: str | None = None,
) -> dict[str, Any]:
    """Apply deterministic authority after an optional AI recommendation."""
    try:
        _case_evidence(case)
    except DuplicateEvidenceError as exc:
        result = {
            "candidate_id": case.get("case_id"),
            "write_decision": "deny",
            "rule_decision": {
                "authority": "fail_closed_duplicate_evidence",
                "rule_version": RULE_VERSION,
                "base_decision": "deny",
                "matched_rules": [],
                "production_write_eligible": False,
                "storage_class": None,
                "write_eligibility_failures": ["duplicate_evidence_id"],
            },
            "evidence_ids": [],
            "source_labels": [],
            "recommended_actions": [],
            "effective_actions": list(DENY_ACTIONS),
            "false_positive_risk": "n/a：候选未进入正常评估流程",
            "release_condition": "上游修正重复的 evidence id 后创建新候选重新审核",
            "rollback_action": "n/a：本次未写入任何内容",
            "uncertainty": "由确定性规则处理；候选包含重复 evidence id，未进入正常评估流程。",
            "patch": empty_patch(),
            "patch_origin": "none_due_to_duplicate_evidence",
            "execution": {
                "destination": "none",
                "patch_sha256": patch_digest(empty_patch()),
                "reason": "duplicate_evidence_id_blocks_evaluation",
            },
            "audit_status": "duplicate_evidence_id",
            "patch_location_check": None,
            "hold_retention": None,
            "errors": {
                "infrastructure": [],
                "model_contract": [],
                "policy": [f"duplicate evidence id: {exc}"],
            },
            "provenance_channels": {
                "original_sources": [],
                "ai_inference": None,
                "user_feedback": copy.deepcopy(case.get("user_feedback", [])),
                "human_confirmation": copy.deepcopy(case.get("human_confirmation", None)),
                "reopen_context": copy.deepcopy(case.get("reopen_context", None)),
            },
        }
        if not _is_test_case(case):
            return minimize_denied_record(result, minimized_at=evaluated_at)
        return result

    infrastructure_errors = list(infrastructure_errors or [])
    base = deterministic_recommendation(case)
    valid_proposal: dict[str, Any] | None = None
    contract_errors: list[str] = []
    if arm != "baseline" and not infrastructure_errors and not skip_ai_validation:
        valid_proposal, contract_errors = validate_ai_proposal(ai_proposal, case)

    if infrastructure_errors or contract_errors:
        final_decision = "hold"
        authority = "fail_closed"
    elif valid_proposal is None:
        final_decision = base["decision"]
        authority = "deterministic_baseline"
    else:
        model_decision = valid_proposal["write_decision"]
        final_decision = max(
            (base["decision"], model_decision), key=DECISION_SEVERITY.__getitem__
        )
        authority = (
            "accepted_ai_recommendation"
            if final_decision == model_decision == base["decision"]
            else "deterministic_rule_selected_safer_state"
        )

    if valid_proposal is not None:
        patch = copy.deepcopy(valid_proposal["patch"])
        patch_origin = "ai_proposed"
    elif arm == "baseline":
        patch = candidate_patch(case)
        patch_origin = "input_candidate"
    else:
        patch = empty_patch(status="proposed")
        patch_origin = "none_due_to_unusable_ai_output"

    matched_rules = copy.deepcopy(base["matched_rules"])
    location = None if is_nonwriting_patch(patch) else validate_patch_location(patch)
    location_error = location is not None and not location["allowed"]
    if location_error:
        if final_decision != "deny":
            final_decision = "hold"
        authority = "fail_closed_patch_location"
        detail = _intercept_detail(
            "R-BLOCK-PATCH-LOCATION",
            list(_case_evidence(case)),
            f"Patch 准入步骤 {location['failed_step']} 失败：{location['reason']}。",
            "合法的新字段若未纳入白名单，也会暂时被拦截。",
            "提交显式、匹配白名单的 scope/target 后完整重审；合法哈希不能豁免范围校验。",
        )
        matched_rules.insert(0, detail)
    production_eligible, eligibility_failures, classification = _production_write_eligible(
        case, final_decision, patch
    )
    if final_decision == "permit" and not is_nonwriting_patch(patch):
        if _is_test_case(case) or patch.get("scope") == "test-only":
            destination = "sandbox"
            execution_reason = "evaluation_permit_routes_to_isolated_sandbox"
        elif production_eligible:
            destination = "production"
            execution_reason = "all_confirmed_production_write_conditions_passed"
        else:
            destination = "none"
            execution_reason = "permit_waits_for_remaining_write_conditions"
    else:
        destination = "none"
        execution_reason = "decision_or_patch_is_nonwriting"

    explanations = _fallback_explanations(final_decision, matched_rules)
    if valid_proposal is not None and not location_error:
        explanations = {
            field: str(valid_proposal[field])
            for field in (
                "false_positive_risk",
                "release_condition",
                "rollback_action",
            )
        }
    actions = {
        "permit": PERMIT_ACTIONS,
        "hold": HOLD_ACTIONS,
        "deny": DENY_ACTIONS,
    }[final_decision]
    evidence = _case_evidence(case)
    evidence_ids = (
        list(map(str, valid_proposal["evidence_ids"]))
        if valid_proposal is not None
        else list(evidence)
    )
    source_labels = (
        copy.deepcopy(valid_proposal["source_labels"])
        if valid_proposal is not None
        else [
            {"evidence_id": evidence_id, "source_type": source_type}
            for evidence_id, source_type in evidence.items()
        ]
    )
    audit_status = (
        "n_a_infrastructure"
        if infrastructure_errors
        else "blocked_model_contract"
        if contract_errors
        else "blocked_patch_location"
        if location_error
        else "complete"
    )
    result = {
        "candidate_id": case.get("case_id"),
        "write_decision": final_decision,
        "rule_decision": {
            "authority": authority,
            "rule_version": RULE_VERSION,
            "base_decision": base["decision"],
            "matched_rules": matched_rules,
            "production_write_eligible": production_eligible,
            "storage_class": classification,
            "write_eligibility_failures": eligibility_failures,
        },
        "evidence_ids": evidence_ids,
        "source_labels": source_labels,
        "recommended_actions": (
            copy.deepcopy(valid_proposal["recommended_actions"])
            if valid_proposal is not None
            else []
        ),
        "effective_actions": list(actions),
        **explanations,
        "uncertainty": (
            copy.deepcopy(valid_proposal.get("uncertainty"))
            if valid_proposal is not None
            else "由确定性规则处理；没有 AI 推断。"
        ),
        "patch": patch,
        "patch_origin": patch_origin,
        "execution": {
            "destination": destination,
            "patch_sha256": patch_digest(patch),
            "reason": execution_reason,
        },
        "audit_status": audit_status,
        "patch_location_check": location,
        "hold_retention": (
            hold_retention(evaluated_at)
            if final_decision == "hold"
            else None
        ),
        "errors": {
            "infrastructure": infrastructure_errors,
            "model_contract": contract_errors,
            "policy": [location["reason"]] if location_error else [],
        },
        "provenance_channels": {
            "original_sources": [
                {"evidence_id": key, "source_type": value}
                for key, value in evidence.items()
            ],
            "ai_inference": copy.deepcopy(valid_proposal) if valid_proposal else None,
            "user_feedback": copy.deepcopy(case.get("user_feedback", [])),
            "human_confirmation": copy.deepcopy(
                case.get("human_confirmation", None)
            ),
            "reopen_context": copy.deepcopy(case.get("reopen_context", None)),
        },
    }
    if final_decision == "deny" and not _is_test_case(case):
        return minimize_denied_record(result, minimized_at=evaluated_at)
    return result


def compact_expired_hold(
    result: Mapping[str, Any], *, current_time: str | None = None
) -> dict[str, Any]:
    """Apply the three-step hold TTL: check, summarize, clear raw content."""
    minimized = copy.deepcopy(dict(result))
    retention = minimized.get("hold_retention")
    if (
        minimized.get("write_decision") != "hold"
        or not isinstance(retention, Mapping)
        or retention.get("compacted_at") is not None
    ):
        return minimized
    now = _parse_utc(current_time)
    expires = _parse_utc(str(retention["expires_at"]))
    if now < expires:
        return minimized

    original_patch = minimized.get("patch", empty_patch())
    matched_rules = minimized.get("rule_decision", {}).get("matched_rules", [])
    channels = minimized.get("provenance_channels", {})
    audit_summary = {
        "record_type": "hold_audit_summary",
        "candidate_id": minimized.get("candidate_id"),
        "write_decision": "hold",
        "rule_version": minimized.get("rule_decision", {}).get("rule_version"),
        "rule_ids": [
            rule.get("rule_id")
            for rule in matched_rules
            if isinstance(rule, Mapping) and rule.get("rule_id")
        ],
        "evidence_ids": copy.deepcopy(minimized.get("evidence_ids", [])),
        "source_types": sorted(
            {
                str(item.get("source_type", "unknown"))
                for item in channels.get("original_sources", [])
                if isinstance(item, Mapping)
            }
        ),
        "original_patch_sha256": patch_digest(original_patch),
        "created_at": retention["created_at"],
        "compacted_at": _iso_utc(now),
        "delete_after": _iso_utc(
            now + timedelta(days=HOLD_AUDIT_RETENTION_DAYS)
        ),
        "record_format": "structured_jsonl",
        "release_condition": minimized.get("release_condition"),
        "rollback_action": minimized.get("rollback_action"),
        "human_confirmation_was_present": channels.get("human_confirmation")
        is not None,
        "reopen_link": copy.deepcopy(channels.get("reopen_context")),
    }
    cleared_patch = empty_patch()
    minimized["patch"] = cleared_patch
    minimized["patch_origin"] = "expired_and_minimized"
    minimized["execution"] = {
        "destination": "none",
        "patch_sha256": patch_digest(cleared_patch),
        "reason": "hold_retention_expired",
    }
    minimized["recommended_actions"] = []
    minimized["uncertainty"] = "Raw AI inference removed after hold retention expired."
    minimized["provenance_channels"] = {
        "original_sources": copy.deepcopy(channels.get("original_sources", [])),
        "ai_inference": None,
        "user_feedback": [],
        "human_confirmation": None,
    }
    minimized["hold_retention"] = {
        **copy.deepcopy(retention),
        "compacted_at": _iso_utc(now),
        "raw_candidate_retained": False,
    }
    minimized["audit_summary"] = audit_summary
    return minimized


def purge_expired_hold_audit(
    compacted_result: Mapping[str, Any], *, current_time: str | None = None
) -> dict[str, Any]:
    """Request deletion after the audit-summary TTL, leaving only a counter delta."""
    summary = compacted_result.get("audit_summary")
    if not isinstance(summary, Mapping) or not summary.get("delete_after"):
        return {
            "delete_record": False,
            "record": copy.deepcopy(dict(compacted_result)),
            "aggregate_delta": {},
        }
    now = _parse_utc(current_time)
    if now < _parse_utc(str(summary["delete_after"])):
        return {
            "delete_record": False,
            "record": copy.deepcopy(dict(compacted_result)),
            "aggregate_delta": {},
        }
    return {
        "delete_record": True,
        "record": None,
        "aggregate_delta": {"expired_hold_audit_summaries": 1},
        "purged_at": _iso_utc(now),
    }


def minimize_denied_record(
    result: Mapping[str, Any], *, minimized_at: str | None = None
) -> dict[str, Any]:
    """Immediately remove production deny content and keep a 90-day summary."""
    minimized = copy.deepcopy(dict(result))
    if minimized.get("write_decision") != "deny":
        return minimized
    existing_retention = minimized.get("deny_retention")
    if isinstance(existing_retention, Mapping) and existing_retention.get(
        "minimized_at"
    ):
        return minimized
    now = _parse_utc(minimized_at)
    patch = minimized.get("patch", empty_patch())
    matched_rules = minimized.get("rule_decision", {}).get("matched_rules", [])
    channels = minimized.get("provenance_channels", {})
    audit_summary = {
        "record_type": "deny_audit_summary",
        "record_format": "structured_jsonl",
        "candidate_id": minimized.get("candidate_id"),
        "write_decision": "deny",
        "rule_version": minimized.get("rule_decision", {}).get("rule_version"),
        "rule_ids": [
            rule.get("rule_id")
            for rule in matched_rules
            if isinstance(rule, Mapping) and rule.get("rule_id")
        ],
        "evidence_ids": copy.deepcopy(minimized.get("evidence_ids", [])),
        "source_types": sorted(
            {
                str(item.get("source_type", "unknown"))
                for item in channels.get("original_sources", [])
                if isinstance(item, Mapping)
            }
        ),
        "original_patch_sha256": patch_digest(patch),
        "minimized_at": _iso_utc(now),
        "delete_after": _iso_utc(
            now + timedelta(days=HOLD_AUDIT_RETENTION_DAYS)
        ),
        "release_condition": minimized.get("release_condition"),
        "rollback_action": minimized.get("rollback_action"),
        "human_confirmation_was_present": channels.get("human_confirmation")
        is not None,
        "reopen_link": copy.deepcopy(channels.get("reopen_context")),
    }
    cleared_patch = empty_patch()
    minimized["patch"] = cleared_patch
    minimized["patch_origin"] = "denied_and_minimized"
    minimized["execution"] = {
        "destination": "none",
        "patch_sha256": patch_digest(cleared_patch),
        "reason": "deny_content_minimized_immediately",
    }
    minimized["recommended_actions"] = []
    minimized["uncertainty"] = "Raw AI inference removed after deny."
    minimized["provenance_channels"] = {
        "original_sources": copy.deepcopy(channels.get("original_sources", [])),
        "ai_inference": None,
        "user_feedback": [],
        "human_confirmation": None,
    }
    minimized["deny_retention"] = {
        "raw_content_retention_days": 0,
        "minimized_at": _iso_utc(now),
        "audit_summary_format": "structured_jsonl",
        "audit_summary_retention_days": HOLD_AUDIT_RETENTION_DAYS,
        "automatic_write": False,
    }
    minimized["audit_summary"] = audit_summary
    minimized["audit_status"] = "deny_minimized"
    return minimized


def purge_expired_deny_audit(
    minimized_result: Mapping[str, Any], *, current_time: str | None = None
) -> dict[str, Any]:
    """Request deny-summary deletion after 90 days."""
    summary = minimized_result.get("audit_summary")
    if not isinstance(summary, Mapping) or summary.get("record_type") != "deny_audit_summary":
        return {
            "delete_record": False,
            "record": copy.deepcopy(dict(minimized_result)),
            "aggregate_delta": {},
        }
    now = _parse_utc(current_time)
    if now < _parse_utc(str(summary["delete_after"])):
        return {
            "delete_record": False,
            "record": copy.deepcopy(dict(minimized_result)),
            "aggregate_delta": {},
        }
    return {
        "delete_record": True,
        "record": None,
        "aggregate_delta": {"expired_deny_audit_summaries": 1},
        "purged_at": _iso_utc(now),
    }


def build_reopened_candidate(
    prior_audit_summary: Mapping[str, Any],
    new_candidate: Mapping[str, Any],
    *,
    basis_type: str,
    basis_evidence_ids: list[str],
    reopened_at: str | None = None,
) -> dict[str, Any]:
    """Create a fresh linked candidate without restoring prior content or authority."""
    if prior_audit_summary.get("record_type") not in {
        "hold_audit_summary",
        "deny_audit_summary",
    }:
        raise ValueError("reopen requires a retained hold or deny audit summary")
    if basis_type not in REOPEN_BASIS_TYPES:
        raise ValueError("invalid reopen basis type")
    old_id = str(prior_audit_summary.get("candidate_id", "")).strip()
    new_id = str(new_candidate.get("case_id", "")).strip()
    if not old_id or not new_id or old_id == new_id:
        raise ValueError("reopen requires a distinct new candidate ID")
    if new_candidate.get("reopen_context") is not None:
        raise ValueError("new candidate already contains reopen context")
    new_evidence = {
        str(item.get("id"))
        for item in new_candidate.get("input", {}).get("evidence", [])
        if isinstance(item, Mapping) and item.get("id")
    }
    requested_evidence = {str(item) for item in basis_evidence_ids}
    if not requested_evidence or not requested_evidence.issubset(new_evidence):
        raise ValueError("reopen basis must reference new candidate evidence IDs")
    now = _parse_utc(reopened_at)
    delete_after = prior_audit_summary.get("delete_after")
    if delete_after and now >= _parse_utc(str(delete_after)):
        raise ValueError("prior audit summary has expired; create an unrelated candidate")

    reopened = copy.deepcopy(dict(new_candidate))
    reopened.pop("human_confirmation", None)
    reopened["reopen_context"] = {
        "prior_candidate_id": old_id,
        "prior_audit_sha256": patch_digest(prior_audit_summary),
        "basis_type": basis_type,
        "basis_evidence_ids": sorted(requested_evidence),
        "reopened_at": _iso_utc(now),
        "inherits_prior_patch": False,
        "inherits_prior_decision": False,
        "inherits_prior_confirmation": False,
    }
    return reopened


def is_nonwriting_patch(patch: Mapping[str, Any]) -> bool:
    return patch.get("operation") == "none" and patch.get("value") is None


def action_bundle_complete(result: Mapping[str, Any]) -> bool:
    expected = {
        "permit": set(PERMIT_ACTIONS),
        "hold": set(HOLD_ACTIONS),
        "deny": set(DENY_ACTIONS),
    }.get(result.get("write_decision"), set())
    return set(result.get("effective_actions", [])) == expected


def simulate_transaction(
    memory: Mapping[str, Any],
    patch: Mapping[str, Any],
    *,
    inject_write_failure: bool = False,
) -> dict[str, Any]:
    """In-memory transaction proof; it never connects to a real memory store."""
    before = copy.deepcopy(dict(memory))
    working = copy.deepcopy(before)
    snapshot_taken = True
    try:
        if is_nonwriting_patch(patch):
            return {
                "snapshot_taken": snapshot_taken,
                "committed": False,
                "rolled_back": False,
                "before": before,
                "after": working,
            }
        location = validate_patch_location(patch)
        if not location["allowed"]:
            raise ValueError(location["reason"])
        operation = patch.get("operation")
        value = patch.get("value")
        if patch["target"] == "/":
            if operation not in {"add", "replace"} or not isinstance(value, Mapping):
                raise ValueError("sandbox root requires add/replace with an object")
            working = copy.deepcopy(dict(value))
        else:
            # Exact whitelist validation above limits this to one fields child.
            if operation not in {"add", "replace", "delete"}:
                raise ValueError("unsupported patch operation")
            field = patch["target"].removeprefix("/fields/")
            fields = working.get("fields")
            if not isinstance(fields, dict):
                raise ValueError("fields parent must already be an object")
            if operation in {"replace", "delete"} and field not in fields:
                raise ValueError("replace/delete target does not exist")
            if operation == "delete":
                if value is not None:
                    raise ValueError("delete patch must not contain a value")
                del fields[field]
            else:
                fields[field] = copy.deepcopy(value)
        if inject_write_failure:
            raise RuntimeError("injected transaction failure")
        return {
            "snapshot_taken": snapshot_taken,
            "committed": True,
            "rolled_back": False,
            "before": before,
            "after": working,
        }
    except Exception as error:
        working = copy.deepcopy(before)
        return {
            "snapshot_taken": snapshot_taken,
            "committed": False,
            "rolled_back": True,
            "before": before,
            "after": working,
            "error": str(error),
        }
