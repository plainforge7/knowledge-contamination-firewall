"""Single HTTP attempt per invocation, bounded by the v0.3 runner's deadline.

Reuses only payload/response helpers; the v0.2 retrying transport is untouched.
There are no hidden transport retries: one budget reservation maps to at most
one HTTP request. A transport or HTTP error is reported as a failed attempt
(usage unknown, counted as reserved) and the runner records it as an
infrastructure error. Reruns go through the checkpoint --resume path, where
each rerun gets its own reservation.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Mapping
import urllib.request

from controlled_compare.bailian_adapter import (
    build_chat_payload,
    parse_bailian_response,
    resolve_endpoint,
)


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
    with urllib.request.urlopen(http_request, timeout=timeout) as response:
        result = parse_bailian_response(
            json.loads(response.read().decode("utf-8")),
            dict(response.headers.items()),
            request["model_config"]["pricing_cny_per_million_tokens"],
        )
    if result["input_tokens"] < 0 or result["output_tokens"] < 0:
        raise ValueError("invalid provider usage")
    result["http_attempts"] = 1
    return result


def main() -> None:
    try:
        print(json.dumps(call_bailian_once(json.loads(sys.stdin.read()), os.environ), ensure_ascii=False))
    except Exception as error:
        # Do not echo a provider body, endpoint, prompt or credential into logs.
        print(f"Bailian single-attempt error: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
