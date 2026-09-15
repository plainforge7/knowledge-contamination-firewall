from __future__ import annotations

import json
from copy import deepcopy
from enum import Enum
from typing import Any


class MergeOp(str, Enum):
    IMMUTABLE = "immutable"
    REPLACE = "replace"
    SUM = "sum"
    PATCH = "patch"


def _resolve_buggy(
    old_fields: dict[str, Any],
    extracted_fields: dict[str, Any],
    merge_ops: dict[str, MergeOp],
) -> dict[str, Any]:
    """Mirror the issue's faulty pre-merge filter: every non-PATCH field is old."""
    resolved = deepcopy(extracted_fields)
    wrongly_named_immutable_fields = {
        name for name, merge_op in merge_ops.items() if merge_op != MergeOp.PATCH
    }
    for field_name in wrongly_named_immutable_fields:
        if field_name in old_fields:
            resolved[field_name] = deepcopy(old_fields[field_name])
    return resolved


def _resolve_fixed(
    old_fields: dict[str, Any],
    extracted_fields: dict[str, Any],
    merge_ops: dict[str, MergeOp],
) -> dict[str, Any]:
    """Mirror the merged fix: restore only fields explicitly marked IMMUTABLE."""
    resolved = deepcopy(extracted_fields)
    immutable_fields = {
        name for name, merge_op in merge_ops.items() if merge_op == MergeOp.IMMUTABLE
    }
    for field_name in immutable_fields:
        if field_name in old_fields:
            resolved[field_name] = deepcopy(old_fields[field_name])
    return resolved


def _apply_merge_ops(
    old_fields: dict[str, Any],
    resolved_fields: dict[str, Any],
    merge_ops: dict[str, MergeOp],
) -> dict[str, Any]:
    persisted = deepcopy(old_fields)
    for field_name, supplied_value in resolved_fields.items():
        merge_op = merge_ops[field_name]
        if merge_op == MergeOp.IMMUTABLE:
            persisted.setdefault(field_name, deepcopy(supplied_value))
        elif merge_op == MergeOp.REPLACE:
            persisted[field_name] = deepcopy(supplied_value)
        elif merge_op == MergeOp.SUM:
            persisted[field_name] = old_fields.get(field_name, 0) + supplied_value
        elif merge_op == MergeOp.PATCH:
            old_value = persisted.get(field_name, {})
            if isinstance(old_value, dict) and isinstance(supplied_value, dict):
                persisted[field_name] = {**old_value, **deepcopy(supplied_value)}
            else:
                persisted[field_name] = deepcopy(supplied_value)
    return persisted


def _render_markdown(extracted_fields: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"owner: {extracted_fields['owner']}",
            f"status: {extracted_fields['status']}",
            f"due_at: {extracted_fields['due_at']}",
        ]
    )


def run_reproduction() -> dict[str, Any]:
    old_fields = {
        "action_key": "test_action",
        "owner": "Alice",
        "status": "open",
        "due_at": "2026-09-08",
        "progress_points": 5,
        "details": {"priority": "normal"},
    }
    newly_extracted_fields = {
        "action_key": "attempted_new_key",
        "owner": "Bob",
        "status": "completed",
        "due_at": "2026-09-10",
        "progress_points": 2,
        "details": {"priority": "high"},
        "location": "remote",
    }
    merge_ops = {
        "action_key": MergeOp.IMMUTABLE,
        "owner": MergeOp.REPLACE,
        "status": MergeOp.REPLACE,
        "due_at": MergeOp.REPLACE,
        "progress_points": MergeOp.SUM,
        "details": MergeOp.PATCH,
        "location": MergeOp.REPLACE,
    }

    buggy_input = _resolve_buggy(old_fields, newly_extracted_fields, merge_ops)
    buggy_persisted = _apply_merge_ops(old_fields, buggy_input, merge_ops)
    fixed_input = _resolve_fixed(old_fields, newly_extracted_fields, merge_ops)
    fixed_persisted = _apply_merge_ops(old_fields, fixed_input, merge_ops)
    markdown = _render_markdown(newly_extracted_fields)

    return {
        "incident": "volcengine/OpenViking#4193",
        "source_url": "https://github.com/volcengine/OpenViking/issues/4193",
        "simulation_scope": "merge-resolution mechanism; no OpenViking installation",
        "setup": {
            "same_page_id": True,
            "old_structured_fields": old_fields,
            "newly_extracted_fields": newly_extracted_fields,
            "merge_ops": {key: value.value for key, value in merge_ops.items()},
        },
        "buggy": {
            "commit_completed_without_exception": True,
            "rendered_markdown": markdown,
            "persisted_structured_fields": buggy_persisted,
            "split_brain": (
                "owner: Bob" in markdown and buggy_persisted["owner"] == "Alice"
            ),
            "absent_replace_field_added": buggy_persisted["location"] == "remote",
        },
        "fixed": {
            "persisted_structured_fields": fixed_persisted,
            "markdown_and_structured_agree": (
                fixed_persisted["owner"] == "Bob"
                and fixed_persisted["status"] == "completed"
                and fixed_persisted["due_at"] == "2026-09-10"
            ),
            "immutable_preserved": fixed_persisted["action_key"] == "test_action",
            "sum_increment_applied": fixed_persisted["progress_points"] == 7,
        },
    }


if __name__ == "__main__":
    print(json.dumps(run_reproduction(), ensure_ascii=False, indent=2))

