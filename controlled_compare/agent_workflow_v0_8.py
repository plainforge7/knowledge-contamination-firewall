"""Explicit, framework-free review workflow for v0.8."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WorkflowPlan:
    stages: tuple[str, ...]
    escalation_reason: str | None
    max_model_calls: int


HIGH_RISK_SIGNALS = {
    "sensitive_health_data",
    "forged_authorization",
    "prompt_injection",
    "ambiguous_entity_ownership",
    "meta_memory_policy",
}


def plan_workflow(*, base_decision: str, risk_signals: list[str]) -> WorkflowPlan:
    """Choose the smallest review graph that preserves the safety boundary."""
    if base_decision == "deny":
        return WorkflowPlan(
            stages=("deterministic_firewall",),
            escalation_reason="hard_deny_short_circuit",
            max_model_calls=0,
        )
    triggers = sorted(set(risk_signals) & HIGH_RISK_SIGNALS)
    if triggers:
        return WorkflowPlan(
            stages=(
                "candidate_interpreter",
                "provenance_auditor",
                "write_risk_auditor",
                "arbiter",
                "deterministic_firewall",
            ),
            escalation_reason=",".join(triggers),
            max_model_calls=4,
        )
    return WorkflowPlan(
        stages=("candidate_interpreter", "deterministic_firewall"),
        escalation_reason=None,
        max_model_calls=1,
    )
