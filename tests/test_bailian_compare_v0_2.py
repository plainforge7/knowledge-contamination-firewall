from __future__ import annotations

import http.client
import unittest
from unittest.mock import patch

from controlled_compare.bailian_adapter import (
    build_chat_payload,
    call_bailian,
    parse_bailian_response,
    resolve_endpoint,
)
from controlled_compare.compare_v0_2 import (
    V02DryRunAdapter,
    empty_memory_patch,
    load_config_v02,
    output_cap,
    run_comparison_v02,
)


class BailianAdapterV02Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config_v02()
        self.request = {
            "messages": [{"role": "user", "content": "synthetic test"}],
            "max_output_tokens": 2048,
            "metadata": {"stage": "arbiter_final"},
            "model_config": {
                **self.config["model"],
                "pricing_cny_per_million_tokens": self.config[
                    "pricing_cny_per_million_tokens"
                ],
            },
        }

    def test_tokyo_endpoint_is_built_without_a_key(self) -> None:
        endpoint = resolve_endpoint(
            {
                "DASHSCOPE_WORKSPACE_ID": "llm-test123",
                "DASHSCOPE_REGION": "ap-northeast-1",
            }
        )
        self.assertEqual(
            endpoint,
            "https://llm-test123.ap-northeast-1.maas.aliyuncs.com/compatible-mode/v1/chat/completions",
        )

    def test_non_tokyo_host_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Tokyo"):
            resolve_endpoint(
                {
                    "DASHSCOPE_BASE_URL": "https://llm-test.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"
                }
            )

    def test_token_plan_key_is_rejected_before_network_access(self) -> None:
        with self.assertRaisesRegex(ValueError, "Token Plan"):
            call_bailian(
                self.request,
                {
                    "DASHSCOPE_API_KEY": "sk-sp-synthetic-secret",
                    "DASHSCOPE_BASE_URL": "https://llm-test.ap-northeast-1.maas.aliyuncs.com/compatible-mode/v1",
                },
            )

    @patch("controlled_compare.bailian_adapter.time.sleep")
    @patch("controlled_compare.bailian_adapter.urllib.request.urlopen")
    def test_remote_disconnect_is_retried_three_times(
        self, mock_urlopen, mock_sleep
    ) -> None:
        mock_urlopen.side_effect = http.client.RemoteDisconnected(
            "Remote end closed connection without response"
        )
        with self.assertRaisesRegex(RuntimeError, "after 3 attempts"):
            call_bailian(
                self.request,
                {
                    "DASHSCOPE_API_KEY": "sk-synthetic-secret",
                    "DASHSCOPE_BASE_URL": "https://llm-test.ap-northeast-1.maas.aliyuncs.com/compatible-mode/v1",
                },
            )
        self.assertEqual(mock_urlopen.call_count, 3)
        self.assertEqual([call.args[0] for call in mock_sleep.call_args_list], [1, 2])

    def test_payload_uses_the_frozen_model_and_parameters(self) -> None:
        payload = build_chat_payload(self.request)
        self.assertEqual(payload["model"], "qwen3.7-max-2026-05-20")
        self.assertEqual(payload["temperature"], 0.2)
        self.assertTrue(payload["enable_thinking"])
        self.assertFalse(payload["preserve_thinking"])
        self.assertNotIn("top_p", payload)
        self.assertNotIn("tools", payload)
        self.assertEqual(payload["response_format"], {"type": "json_object"})

    def test_response_reports_tokens_request_id_and_cny_cost(self) -> None:
        result = parse_bailian_response(
            {
                "id": "request-1",
                "model": "qwen3.7-max-2026-05-20",
                "choices": [
                    {
                        "message": {"content": '{"decision":"reject"}'},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1000, "completion_tokens": 500},
            },
            {},
            {"input": 1.65, "output": 4.951},
        )
        self.assertEqual(result["input_tokens"], 1000)
        self.assertEqual(result["output_tokens"], 500)
        self.assertEqual(result["cost_cny"], 0.0041255)
        self.assertEqual(result["request_id"], "request-1")


class BailianRunnerV02Tests(unittest.TestCase):
    def test_confirmed_budget_allocation(self) -> None:
        config = load_config_v02()
        self.assertEqual(output_cap(config, "equal_budget", "single"), 4096)
        self.assertEqual(output_cap(config, "equal_budget", "multi"), 2048)
        self.assertEqual(output_cap(config, "natural_budget", "single"), 2048)
        self.assertEqual(output_cap(config, "natural_budget", "multi"), 2048)

    def test_empty_patch_is_proposed_and_non_writing(self) -> None:
        patch = empty_memory_patch()
        self.assertEqual(patch["operation"], "none")
        self.assertEqual(patch["status"], "proposed")
        self.assertIsNone(patch["value"])

    def test_dry_smoke_exercises_twelve_calls_but_is_not_evaluative(self) -> None:
        result = run_comparison_v02(V02DryRunAdapter(), smoke=True)
        self.assertFalse(result["evaluation_valid"])
        self.assertEqual(result["case_count"], 1)
        self.assertEqual(result["repetitions"], 1)
        self.assertEqual(result["expected_model_calls"], 12)
        successful_calls = sum(
            result["scores"][track][arm]["operations"]["successful_model_calls"]
            for track in ("equal_budget", "natural_budget")
            for arm in ("single", "multi")
        )
        self.assertEqual(successful_calls, 12)
        self.assertEqual(result["selection"]["status"], "connectivity_smoke_only")

    def test_full_dry_run_uses_all_system_assertions_and_396_calls(self) -> None:
        result = run_comparison_v02(V02DryRunAdapter())
        self.assertEqual(result["case_count"], 11)
        self.assertEqual(result["repetitions"], 3)
        self.assertEqual(result["expected_model_calls"], 396)
        self.assertFalse(result["evaluation_valid"])


if __name__ == "__main__":
    unittest.main()
