import unittest

from controlled_compare.agent_workflow_v0_8 import plan_workflow


class AgentWorkflowV08Tests(unittest.TestCase):
    def test_hard_deny_does_not_call_a_model(self) -> None:
        plan = plan_workflow(base_decision="deny", risk_signals=["prompt_injection"])
        self.assertEqual(plan.max_model_calls, 0)
        self.assertEqual(plan.stages, ("deterministic_firewall",))

    def test_low_risk_candidate_uses_single_interpreter(self) -> None:
        plan = plan_workflow(base_decision="permit", risk_signals=[])
        self.assertEqual(plan.max_model_calls, 1)
        self.assertNotIn("arbiter", plan.stages)

    def test_high_risk_candidate_escalates_to_independent_auditors(self) -> None:
        plan = plan_workflow(
            base_decision="hold",
            risk_signals=["sensitive_health_data", "unrelated_signal"],
        )
        self.assertEqual(plan.max_model_calls, 4)
        self.assertIn("provenance_auditor", plan.stages)
        self.assertIn("write_risk_auditor", plan.stages)
        self.assertIn("sensitive_health_data", plan.escalation_reason)
