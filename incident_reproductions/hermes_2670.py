from __future__ import annotations

import json
from copy import deepcopy
from typing import Any


TRIGGERS = ("session_reset", "inactivity_timeout", "gateway_restart")


def _fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    old_transcript = {
        "session_id": "chat_primary",
        "captured_revision": 1,
        "captured_at": "2026-09-08T09:00:00Z",
        "memory_snapshot": {
            "owner": "Alice",
            "status": "open",
            "due_at": "2026-09-08",
        },
    }
    live_memory = {
        "revision": 2,
        "modified_at": "2026-09-10T09:00:00Z",
        "entries": {
            "owner": "Bob",
            "status": "completed",
            "due_at": "2026-09-10",
            "canary": "new-live-entry",
        },
    }
    return old_transcript, live_memory


def run_buggy_flush(trigger: str) -> dict[str, Any]:
    if trigger not in TRIGGERS:
        raise ValueError(f"unsupported trigger: {trigger}")
    transcript, live_memory = _fixture()
    before = deepcopy(live_memory)

    # The temporary flush agent sees the old conversation and performs a
    # replace without a recency/conflict gate.
    write_attempt = {
        "action": "replace",
        "base_revision": transcript["captured_revision"],
        "entries": deepcopy(transcript["memory_snapshot"]),
    }
    after = {
        "revision": before["revision"] + 1,
        "modified_at": "2026-09-10T09:01:00Z",
        "entries": deepcopy(write_attempt["entries"]),
    }
    return {
        "trigger": trigger,
        "before": before,
        "write_attempt": write_attempt,
        "after": after,
        "commit_completed_without_conflict": True,
        "newer_owner_reverted": after["entries"]["owner"] == "Alice",
        "canary_disappeared": "canary" not in after["entries"],
    }


def run_reference_prompt_fix(
    trigger: str,
    session_id: str = "chat_primary",
) -> dict[str, Any]:
    if trigger not in TRIGGERS:
        raise ValueError(f"unsupported trigger: {trigger}")
    transcript, live_memory = _fixture()
    before = deepcopy(live_memory)

    if session_id.startswith("cron_"):
        return {
            "trigger": trigger,
            "session_id": session_id,
            "decision": "skip_cron_flush",
            "transcript_loaded": False,
            "current_memory_injected": False,
            "before": before,
            "after": deepcopy(before),
        }

    # This mirrors the merged PR's intended behavior: put current MEMORY.md and
    # USER.md beside the old transcript so the model can preserve newer state.
    flush_prompt = {
        "old_transcript": deepcopy(transcript),
        "current_memory": deepcopy(live_memory),
        "instruction": "Only save genuinely new facts; preserve current memory on conflict.",
    }
    simulated_agent_output = deepcopy(flush_prompt["current_memory"]["entries"])
    return {
        "trigger": trigger,
        "session_id": session_id,
        "decision": "preserve_current",
        "transcript_loaded": True,
        "current_memory_injected": True,
        "prompt": flush_prompt,
        "before": before,
        "after": deepcopy(before) | {"entries": simulated_agent_output},
        "note": "Prompt-level mitigation, not a hard revision invariant.",
    }


def run_firewall_revision_guard(trigger: str) -> dict[str, Any]:
    if trigger not in TRIGGERS:
        raise ValueError(f"unsupported trigger: {trigger}")
    transcript, live_memory = _fixture()
    before = deepcopy(live_memory)
    stale_base = transcript["captured_revision"]
    current_revision = live_memory["revision"]
    reject = stale_base < current_revision
    return {
        "trigger": trigger,
        "decision": "reject_stale_write" if reject else "allow_write",
        "evidence": {
            "candidate_base_revision": stale_base,
            "current_revision": current_revision,
        },
        "false_positive_risk": "A legitimate replacement derived from an old session may be blocked.",
        "release_condition": "Re-read current memory, reconcile the conflict, and create a new write based on revision 2.",
        "rollback_action": "Restore revision 2 and remove facts derived only from the stale flush.",
        "before": before,
        "after": deepcopy(before),
    }


def run_reproduction() -> dict[str, Any]:
    return {
        "incident": "NousResearch/hermes-agent#2670",
        "source_url": "https://github.com/NousResearch/hermes-agent/issues/2670",
        "simulation_scope": "flush lifecycle and stale overwrite mechanism; no gateway/systemd",
        "buggy_by_trigger": {trigger: run_buggy_flush(trigger) for trigger in TRIGGERS},
        "upstream_reference_fix": run_reference_prompt_fix("gateway_restart"),
        "cron_bypass": run_reference_prompt_fix("session_reset", "cron_daily"),
        "firewall_hard_guard": run_firewall_revision_guard("gateway_restart"),
    }


if __name__ == "__main__":
    print(json.dumps(run_reproduction(), ensure_ascii=False, indent=2))

