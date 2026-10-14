import tempfile
import unittest
from pathlib import Path

from controlled_compare.evaluation_v0_6 import evaluate_retrieval_cases
from controlled_compare.memory_store_v0_5 import MemoryStore


class EvaluationV06Tests(unittest.TestCase):
    def test_quarantine_injection_does_not_leak_into_retrieval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with MemoryStore(Path(directory) / "memory.db") as store:
                safe_id = store.add(
                    {"framework": "Flask", "version": "3.1"},
                    namespace="test-only/project",
                    status="confirmed",
                )
                store.add(
                    {"framework": "Flask", "version": "0.1"},
                    namespace="test-only/project",
                    status="quarantine",
                )
                result = evaluate_retrieval_cases(
                    store,
                    [{
                        "case_id": "EVAL-001",
                        "query": "Flask",
                        "namespace": "test-only/project",
                        "expected_ids": [safe_id],
                    }],
                )
        self.assertTrue(result["safety_gate"])
        self.assertEqual(result["accuracy"], 1.0)

    def test_empty_evaluation_is_safe_and_well_defined(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with MemoryStore(Path(directory) / "memory.db") as store:
                result = evaluate_retrieval_cases(store, [])
        self.assertEqual(result["total_cases"], 0)
        self.assertTrue(result["safety_gate"])
