"""Up to 3 HTTP attempts per invocation on transport errors only, bounded
by the v0.3 runner's deadline.

Reuses only payload/response helpers; the v0.2 retrying transport is untouched.
Retries are limited to network-layer failures (URLError, socket/SSL errors).
Contract or validation errors (ValueError) are never retried, since retrying
a deterministic failure only wastes budget without changing the outcome.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Mapping

from controlled_compare.bailian_adapter import (
    build_chat_payload,
    parse_bailian_response,
    resolve_endpoint,
)

MAX_TRANSPORT_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 2.0


def call_bailian_once(request: Mapping[str, Any], environment: Mapping[str, str]) -> dict[str, Any]:
    key = environment.get("DASHSCOPE_API_KEY", "").strip()
    if not key or key.startswith("sk-sp-"):
        raise ValueError("a pay-as-you-go workspace API key is required")
    timeout = float(request["timeout_seconds"])
    if timeout <= 0:
        raise ValueError("request deadline exhausted")
    payload = build_chat_payload(request)
    http_request = urllib.request.Request(
        resolve_endpoint(environment),
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    for attempt in range(1, MAX_TRANSPORT_ATTEMPTS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("request deadline exhausted") from last_error
        try:
            with urllib.request.urlopen(http_request, timeout=remaining) as response:
                result = parse_bailian_response(
                    json.loads(response.read().decode("utf-8")),
                    dict(response.headers.items()),
                    request["model_config"]["pricing_cny_per_million_tokens"],
                )
            if result["input_tokens"] < 0 or result["output_tokens"] < 0:
                raise ValueError("invalid provider usage")
            result["http_attempts"] = attempt
            return result
        except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
            last_error = error
            if attempt < MAX_TRANSPORT_ATTEMPTS and (deadline - time.monotonic()) > RETRY_BACKOFF_SECONDS:
                time.sleep(RETRY_BACKOFF_SECONDS)
                continue
            raise
    raise last_error  # pragma: no cover - loop always returns or raises above


def main() -> None:
    try:
        print(json.dumps(call_bailian_once(json.loads(sys.stdin.read()), os.environ), ensure_ascii=False))
    except Exception as error:
        # Do not echo a provider body, endpoint, prompt or credential into logs.
        print(f"Bailian single-attempt error: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
