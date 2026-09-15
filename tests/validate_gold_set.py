from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GOLD_PATH = ROOT / "gold_set" / "gold_set_v0.jsonl"
KNOWLEDGE_PATH = ROOT / "data" / "flask_versioned_knowledge.jsonl"

EXPECTED_COUNTS = {
    "clean_allow": 4,
    "incorrect_information": 4,
    "stale_information": 4,
    "post_correction_old_information": 4,
    "stale_snapshot_overwrite": 2,
    "realtime_evidence_priority": 2,
}

CATEGORY_DECISION = {
    "clean_allow": "allow",
    "incorrect_information": "quarantine",
    "stale_information": "exclude_as_stale",
    "post_correction_old_information": "replace_with_correction",
    "stale_snapshot_overwrite": "reject_stale_write",
    "realtime_evidence_priority": "prefer_realtime",
}


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise AssertionError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
    return rows


def available_evidence_ids(case: dict, clean_ids: set[str]) -> set[str]:
    result = set(clean_ids)
    result.update(item["id"] for item in case["setup"]["injected_items"])
    result.update(item["event_id"] for item in case["setup"]["events"])
    result.update(item["id"] for item in case["setup"]["realtime_evidence"])
    return result


def main() -> None:
    gold = load_jsonl(GOLD_PATH)
    knowledge = load_jsonl(KNOWLEDGE_PATH)
    clean_ids = {row["id"] for row in knowledge}

    assert len(gold) == 20, f"expected 20 cases, got {len(gold)}"
    case_ids = [row["case_id"] for row in gold]
    assert len(case_ids) == len(set(case_ids)), "duplicate case_id"
    assert case_ids == [f"GS-{index:03d}" for index in range(1, 21)], "case IDs are not sequential"

    counts = Counter(row["category"] for row in gold)
    assert dict(counts) == EXPECTED_COUNTS, f"unexpected category distribution: {dict(counts)}"

    # 相同问题可以跨类别复用，以便只改变污染条件进行受控对比；
    # 但同一类别内不应出现重复问题。
    query_category_pairs = [(row["category"], row["query"]) for row in gold]
    assert len(query_category_pairs) == len(set(query_category_pairs)), "duplicate query within category"

    for case in gold:
        expected = case["expected"]
        setup = case["setup"]
        assert expected["decision"] == CATEGORY_DECISION[case["category"]], case["case_id"]
        assert set(setup["clean_knowledge_ids"]).issubset(clean_ids), case["case_id"]
        known_ids = available_evidence_ids(case, clean_ids)
        assert set(expected["required_evidence_ids"]).issubset(known_ids), case["case_id"]
        assert set(expected["forbidden_evidence_ids"]).issubset(known_ids), case["case_id"]
        assert not set(expected["required_evidence_ids"]) & set(expected["forbidden_evidence_ids"]), case["case_id"]
        assert all(item.get("values") for item in expected["answer_assertions"]), case["case_id"]
        assert math.isclose(sum(case["scoring"].values()), 1.0), case["case_id"]

        if case["category"] == "clean_allow":
            assert not setup["injected_items"], case["case_id"]
            assert not expected["forbidden_evidence_ids"], case["case_id"]
        elif case["category"] == "stale_snapshot_overwrite":
            assert any(event["type"] == "background_write_attempt" for event in setup["events"]), case["case_id"]
        elif case["category"] == "realtime_evidence_priority":
            assert setup["realtime_evidence"], case["case_id"]
        else:
            assert setup["injected_items"] or setup["stale_candidate_ids"], case["case_id"]

    print(json.dumps({"status": "ok", "cases": len(gold), "category_counts": dict(counts)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
