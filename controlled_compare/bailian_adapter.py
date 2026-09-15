"""Secure stdin/stdout adapter for Alibaba Cloud Model Studio (Bailian).

The API key is read only from ``DASHSCOPE_API_KEY``.  It is never included in
the adapter response, logs, prompts, or result files.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal
from typing import Any, Mapping


DEFAULT_REGION = "ap-northeast-1"
DEFAULT_TIMEOUT_SECONDS = 180
RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def resolve_endpoint(environment: Mapping[str, str]) -> str:
    """Resolve the Tokyo OpenAI-compatible Chat Completions endpoint."""
    base_url = environment.get("DASHSCOPE_BASE_URL", "").strip().rstrip("/")
    if not base_url:
        workspace_id = environment.get("DASHSCOPE_WORKSPACE_ID", "").strip()
        region = environment.get("DASHSCOPE_REGION", DEFAULT_REGION).strip()
        if not workspace_id:
            raise ValueError(
                "set DASHSCOPE_BASE_URL to the API Host copied from the Bailian workspace"
            )
        if not re.fullmatch(r"[A-Za-z0-9-]+", workspace_id):
            raise ValueError("DASHSCOPE_WORKSPACE_ID contains invalid characters")
        if region != DEFAULT_REGION:
            raise ValueError("protocol v0.2 is frozen to the Tokyo region ap-northeast-1")
        base_url = (
            f"https://{workspace_id}.{region}.maas.aliyuncs.com/compatible-mode/v1"
        )

    allow_localhost = environment.get("BAILIAN_ALLOW_INSECURE_LOCALHOST") == "1"
    is_local_test = base_url.startswith("http://127.0.0.1:") and allow_localhost
    if not base_url.startswith("https://") and not is_local_test:
        raise ValueError("DASHSCOPE_BASE_URL must use https")
    if not base_url.endswith("/compatible-mode/v1") and not is_local_test:
        raise ValueError("DASHSCOPE_BASE_URL must end with /compatible-mode/v1")
    if ".ap-northeast-1.maas.aliyuncs.com/" not in base_url and not is_local_test:
        raise ValueError("protocol v0.2 requires a Tokyo ap-northeast-1 API Host")
    return base_url + "/chat/completions"


def build_chat_payload(adapter_request: Mapping[str, Any]) -> dict[str, Any]:
    """Translate the evaluator request into Bailian's OpenAI-compatible body."""
    model_config = _require_mapping(adapter_request.get("model_config"), "model_config")
    metadata = _require_mapping(adapter_request.get("metadata"), "metadata")
    messages = adapter_request.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty array")

    payload: dict[str, Any] = {
        "model": model_config["model_id"],
        "messages": messages,
        "max_tokens": int(adapter_request["max_output_tokens"]),
        "temperature": float(model_config["temperature"]),
        "enable_thinking": bool(model_config["enable_thinking"]),
        "preserve_thinking": bool(model_config["preserve_thinking"]),
        "stream": False,
    }
    if metadata.get("stage") in {"single_final", "arbiter_final"}:
        payload["response_format"] = {"type": "json_object"}
    return payload


def _text_content(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = [item.get("text", "") for item in value if isinstance(item, Mapping)]
        return "".join(parts)
    raise ValueError("Bailian response content is not text")


def parse_bailian_response(
    response: Mapping[str, Any],
    headers: Mapping[str, str] | None,
    pricing: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the provider-neutral response required by the evaluator."""
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("Bailian response has no choices")
    first_choice = _require_mapping(choices[0], "choices[0]")
    message = _require_mapping(first_choice.get("message"), "choices[0].message")
    usage = _require_mapping(response.get("usage"), "usage")

    input_tokens = usage.get("prompt_tokens", usage.get("input_tokens"))
    output_tokens = usage.get("completion_tokens", usage.get("output_tokens"))
    if input_tokens is None or output_tokens is None:
        raise ValueError("Bailian response is missing input/output token usage")
    input_tokens = int(input_tokens)
    output_tokens = int(output_tokens)

    input_price = Decimal(str(pricing["input"]))
    output_price = Decimal(str(pricing["output"]))
    cost_cny = (
        Decimal(input_tokens) * input_price + Decimal(output_tokens) * output_price
    ) / Decimal(1_000_000)

    header_request_id = None
    if headers:
        header_request_id = headers.get("x-request-id") or headers.get("X-Request-Id")

    return {
        "content": _text_content(message.get("content")),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost_usd": None,
        "cost_cny": float(cost_cny),
        "request_id": response.get("request_id") or response.get("id") or header_request_id,
        "provider_model": response.get("model"),
        "finish_reason": first_choice.get("finish_reason"),
    }


def _provider_error_message(body: bytes) -> str:
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
        error = payload.get("error", payload)
        if isinstance(error, Mapping):
            code = str(error.get("code", "provider_error"))
            message = str(error.get("message", "request failed"))
            return f"{code}: {message[:500]}"
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return "provider request failed"


def call_bailian(
    adapter_request: Mapping[str, Any], environment: Mapping[str, str]
) -> dict[str, Any]:
    api_key = environment.get("DASHSCOPE_API_KEY", "").strip()
    if not api_key:
        raise ValueError("DASHSCOPE_API_KEY is not set")
    if api_key.startswith("sk-sp-"):
        raise ValueError(
            "Token Plan keys cannot be used by this custom evaluation script; use a pay-as-you-go workspace key"
        )

    endpoint = resolve_endpoint(environment)
    payload = build_chat_payload(adapter_request)
    model_config = _require_mapping(adapter_request.get("model_config"), "model_config")
    pricing = _require_mapping(model_config.get("pricing_cny_per_million_tokens"), "pricing")
    timeout_seconds = int(
        environment.get("BAILIAN_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS))
    )

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response_handle:
                response_body = response_handle.read()
                response_json = json.loads(response_body.decode("utf-8"))
                return parse_bailian_response(
                    _require_mapping(response_json, "response"),
                    dict(response_handle.headers.items()),
                    pricing,
                )
        except urllib.error.HTTPError as error:
            error_body = error.read(4096)
            if error.code in RETRYABLE_HTTP_CODES and attempt < 2:
                time.sleep(2**attempt)
                continue
            raise RuntimeError(
                f"Bailian HTTP {error.code}: {_provider_error_message(error_body)}"
            ) from None
        except urllib.error.URLError as error:
            if attempt < 2:
                time.sleep(2**attempt)
                continue
            raise RuntimeError(f"Bailian network error: {str(error.reason)[:300]}") from None
        except http.client.RemoteDisconnected:
            if attempt < 2:
                time.sleep(2**attempt)
                continue
            raise RuntimeError(
                "Bailian network error: remote end closed connection after 3 attempts"
            ) from None

    raise RuntimeError("Bailian request exhausted retries")


def main() -> None:
    api_key = os.environ.get("DASHSCOPE_API_KEY", "")
    try:
        raw_request = sys.stdin.read()
        adapter_request = _require_mapping(json.loads(raw_request), "adapter request")
        result = call_bailian(adapter_request, os.environ)
        print(json.dumps(result, ensure_ascii=False))
    except Exception as error:  # The parent evaluator records this as a format failure.
        safe_message = str(error)
        if api_key:
            safe_message = safe_message.replace(api_key, "[REDACTED]")
        print(f"Bailian adapter error: {safe_message}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
