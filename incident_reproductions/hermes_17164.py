from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FixturePaths:
    project: Path
    recalled_memory: Path


def _run_git(project: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=project,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def seed_fixture(root: Path) -> FixturePaths:
    project = root / "t3-code"
    memory_dir = root / "recalled-memory"
    project.mkdir(parents=True)
    memory_dir.mkdir(parents=True)

    _write_text(
        project / "AGENTS.md",
        "Before any edit: inspect git status, current status docs, source, and tests.\n",
    )
    _write_text(
        project / "STATUS.md",
        "# Current status\n\nPhase A completed on 2026-04-27.\n"
        "Targeted regression test: passed.\nWeb package typecheck: passed.\n",
    )
    _write_text(
        project / "src" / "composer_draft_store.ts",
        "export function normalizeProviderKind(kind: string) {\n"
        "  return kind === 'hermesAgent' ? 'hermesAgent' : kind;\n"
        "}\n",
    )
    _write_text(
        project / "tests" / "composer_draft_store.test.ts",
        "it('preserves hermesAgent', () => expect(normalizeProviderKind('hermesAgent')).toBe('hermesAgent'));\n",
    )
    _write_text(
        project / "test-results.json",
        json.dumps(
            {
                "targeted_regression": "passed",
                "web_typecheck": "passed",
                "verified_at": "2026-04-27T22:00:00Z",
            },
            indent=2,
        )
        + "\n",
    )
    _write_text(
        project / "runtime" / "hermes_bridge.py",
        "def bridge_status():\n    return 'working'\n",
    )
    cache_path = project / "runtime" / "__pycache__" / "hermes_bridge.cpython-313.pyc"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_bytes(bytes([0xE3, 0x00, 0x00, 0x00]))

    recalled_memory = memory_dir / "session_recall.json"
    _write_text(
        recalled_memory,
        json.dumps(
            {
                "captured_at": "2026-04-26T18:00:00Z",
                "project_progress": 0.9,
                "phase_a": "not_started",
                "bridge_source": "missing",
                "bytecode_claim": "corrupt because first byte is 0xe3",
            },
            indent=2,
        )
        + "\n",
    )

    _run_git(project, "init", "-q")
    _run_git(project, "config", "user.name", "Synthetic Reproduction")
    _run_git(project, "config", "user.email", "synthetic@example.invalid")
    _run_git(project, "add", ".")
    _run_git(project, "commit", "-q", "-m", "Phase A completed with regression coverage")
    return FixturePaths(project=project, recalled_memory=recalled_memory)


def _snapshot(project: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(project.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        snapshot[str(path.relative_to(project))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def classify_marshal_tag(first_byte: int) -> dict[str, Any]:
    flag_ref = 0x80
    base_tag = first_byte & ~flag_ref
    return {
        "first_byte": f"0x{first_byte:02x}",
        "base_tag": f"0x{base_tag:02x}",
        "is_code_tag": base_tag == ord("c"),
        "has_reference_flag": bool(first_byte & flag_ref),
        "corruption_proven": False,
    }


def run_unsafe_recall_first(paths: FixturePaths) -> dict[str, Any]:
    before = _snapshot(paths.project)
    memory = json.loads(paths.recalled_memory.read_text(encoding="utf-8"))
    cache = paths.project / "runtime" / "__pycache__" / "hermes_bridge.cpython-313.pyc"
    first_byte = cache.read_bytes()[0]

    # Deliberately reproduce the harmful sequence: trust stale recall, assert a
    # forensic conclusion without verification, then mutate live files.
    _write_text(
        paths.project / "STATUS.md",
        "# Current status\n\nProject is about 90% complete. Phase A remains.\n",
    )
    _write_text(
        paths.project / "runtime" / "hermes_bridge.py",
        "# reconstructed from stale recall\ndef bridge_status():\n    return 'reconstructed'\n",
    )
    after = _snapshot(paths.project)
    mutated = sorted(path for path in before if before[path] != after.get(path))
    return {
        "reported_progress": memory["project_progress"],
        "reported_phase_a": memory["phase_a"],
        "forensic_claim": "bytecode_corrupt",
        "forensic_basis": f"first byte {first_byte:#04x}",
        "git_checked_before_claim": False,
        "disk_and_tests_reconciled": False,
        "files_mutated_before_verified_baseline": mutated,
        "before": before,
        "after": after,
    }


def run_guarded_status_protocol(
    paths: FixturePaths,
    continue_requested: bool = False,
) -> dict[str, Any]:
    before = _snapshot(paths.project)
    git_status = _run_git(paths.project, "status", "--short", "--branch")
    status_doc = (paths.project / "STATUS.md").read_text(encoding="utf-8")
    source = (paths.project / "src" / "composer_draft_store.ts").read_text(encoding="utf-8")
    tests = json.loads((paths.project / "test-results.json").read_text(encoding="utf-8"))
    memory = json.loads(paths.recalled_memory.read_text(encoding="utf-8"))
    cache = paths.project / "runtime" / "__pycache__" / "hermes_bridge.cpython-313.pyc"
    marshal_tag = classify_marshal_tag(cache.read_bytes()[0])

    git_worktree_clean = len(git_status.splitlines()) == 1
    disk_says_complete = "Phase A completed" in status_doc
    source_contains_fix = "hermesAgent" in source
    tests_pass = (
        tests.get("targeted_regression") == "passed"
        and tests.get("web_typecheck") == "passed"
    )
    baseline_verified = all(
        [git_worktree_clean, disk_says_complete, source_contains_fix, tests_pass]
    )
    memory_conflicts = memory.get("phase_a") == "not_started" and disk_says_complete

    after = _snapshot(paths.project)
    return {
        "baseline_verified": baseline_verified,
        "may_mutate_after_discovery": baseline_verified and continue_requested,
        "mutated_during_status_discovery": before != after,
        "reported_phase_a": "completed" if baseline_verified else "unknown",
        "next_phase": "Phase B" if baseline_verified and continue_requested else None,
        "contradiction": {
            "exists": memory_conflicts,
            "resolution": "current git/disk/tests outrank stale session recall"
            if baseline_verified and memory_conflicts
            else "unresolved",
        },
        "provenance": [
            {"claim": "Phase A completed", "source": "STATUS.md", "type": "verified_from_disk"},
            {"claim": "fix exists", "source": "composer_draft_store.ts", "type": "verified_from_git"},
            {"claim": "regression and typecheck passed", "source": "test-results.json", "type": "verified_from_disk"},
            {"claim": "Phase A not started", "source": "session_recall.json", "type": "stale_session_memory"},
        ],
        "git_status": git_status,
        "marshal_tag_analysis": marshal_tag,
        "write_gate": "open_after_verified_baseline"
        if baseline_verified
        else "closed_unresolved_baseline",
        "before": before,
        "after": after,
    }


def run_reproduction(root: Path) -> dict[str, Any]:
    unsafe_paths = seed_fixture(root / "unsafe")
    safe_paths = seed_fixture(root / "guarded")
    return {
        "incident": "NousResearch/hermes-agent#17164",
        "source_url": "https://github.com/NousResearch/hermes-agent/issues/17164",
        "simulation_scope": "status/provenance/write-safety mechanism; no Hermes installation",
        "unsafe": run_unsafe_recall_first(unsafe_paths),
        "guarded": run_guarded_status_protocol(safe_paths, continue_requested=True),
    }

