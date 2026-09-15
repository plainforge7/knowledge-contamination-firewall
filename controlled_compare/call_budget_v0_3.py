"""Candidate-wide reservation ledger. No network calls and no hidden retries."""

from __future__ import annotations

import copy
import json
import math
import time
from typing import Any, Callable


class CallBlocked(RuntimeError):
    """A call must not be dispatched (or its late response must not be used)."""


def estimate_input_tokens(request: dict[str, Any]) -> int:
    """Conservative character estimate plus framing allowance, not a tokenizer proof."""
    # Counting UTF-8 bytes over-reserves Chinese prompts by roughly 3x and can
    # reject a valid four-call run before it starts. Four characters per token is
    # still intentionally conservative without pretending to be a provider tokenizer.
    text = json.dumps(request["messages"], ensure_ascii=False)
    return max(1, math.ceil(len(text) / 4)) + 256


class CallBudget:
    def __init__(
        self,
        token_ceiling: int,
        max_attempts: int,
        timeout_seconds: float,
        *,
        clock: Callable[[], float] | None = None,
        previous: dict[str, Any] | None = None,
    ) -> None:
        self.clock = clock or time.monotonic
        self.started = self.clock()
        self.token_ceiling = token_ceiling
        self.max_attempts = max_attempts
        previous = previous or {}
        self.previous_elapsed = float(previous.get("elapsed_seconds", 0))
        self.deadline = self.started + max(0, timeout_seconds - self.previous_elapsed)
        self.attempts = copy.deepcopy(previous.get("attempts", []))
        # An interrupted request has unknown usage, never a free reservation.
        for attempt in self.attempts:
            if attempt["status"] == "reserved":
                attempt["status"] = "usage_unknown"
                attempt["error"] = "interrupted_request"

    def remaining_seconds(self) -> float:
        return max(0.0, self.deadline - self.clock())

    def accounted_tokens(self) -> int:
        return sum(
            row["actual_tokens"]
            if row.get("actual_tokens") is not None
            else row["reserved_tokens"]
            for row in self.attempts
        )

    def check(self) -> None:
        if self.remaining_seconds() <= 0:
            raise CallBlocked("candidate_deadline_exceeded")
        if self.accounted_tokens() > self.token_ceiling:
            raise CallBlocked("token_ceiling_exceeded")

    def reserve_batch(self, requests: list[dict[str, Any]]) -> list[int]:
        """Reserve both parallel auditors together before either can be sent."""
        self.check()
        if len(self.attempts) + len(requests) > self.max_attempts:
            raise CallBlocked("call_attempt_limit_exhausted")
        reservations = [
            estimate_input_tokens(request) + int(request["max_output_tokens"])
            for request in requests
        ]
        if any(value <= 0 for value in reservations):
            raise CallBlocked("invalid_token_reservation")
        if self.accounted_tokens() + sum(reservations) > self.token_ceiling:
            raise CallBlocked("insufficient_token_budget_before_call")
        indices = []
        for request, reservation in zip(requests, reservations):
            indices.append(len(self.attempts))
            self.attempts.append({
                "stage": request["metadata"]["stage"],
                "reserved_tokens": reservation,
                "actual_tokens": None,
                "status": "reserved",
            })
        return indices

    def settle(self, index: int, *, actual_tokens: int | None, error: str | None) -> None:
        row = self.attempts[index]
        if actual_tokens is not None and actual_tokens < 0:
            raise ValueError("actual token usage cannot be negative")
        row["actual_tokens"] = actual_tokens
        row["status"] = "response_received" if actual_tokens is not None else "usage_unknown"
        if error:
            row["error"] = error

    def snapshot(self) -> dict[str, Any]:
        return {
            "token_ceiling": self.token_ceiling,
            "max_attempts": self.max_attempts,
            "attempts": copy.deepcopy(self.attempts),
            "accounted_tokens": self.accounted_tokens(),
            "usage_unknown_attempts": sum(
                row["status"] == "usage_unknown" for row in self.attempts
            ),
            "unknown_usage_reserved_tokens": sum(
                row["reserved_tokens"] for row in self.attempts
                if row["status"] == "usage_unknown"
            ),
            "elapsed_seconds": self.previous_elapsed + self.clock() - self.started,
            "input_estimation": "utf8_bytes_plus_256; conservative_estimate_not_exact",
        }
