import tempfile
import unittest
from pathlib import Path

from controlled_compare.memory_store_v0_5 import MemoryStore
from controlled_compare.review_queue_v0_7 import ReviewQueue


class ReviewQueueV07Tests(unittest.TestCase):
    def test_approval_promotes_candidate_and_is_audited(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with MemoryStore(Path(directory) / "memory.db") as store:
                memory_id = store.add(
                    {"preference": "dark mode"},
                    namespace="test-only/profile",
                )
                queue = ReviewQueue(store)
                self.assertEqual([item["memory_id"] for item in queue.pending(namespace="test-only/profile")], [memory_id])
                queue.approve(memory_id, reviewer="user", reason="confirmed directly")
                self.assertEqual(queue.pending(namespace="test-only/profile"), [])
                self.assertEqual(store.get(memory_id)["status"], "confirmed")
                self.assertIn("human_approval", store.events(memory_id)[-1]["detail"]["reason"])

    def test_rejection_removes_candidate_from_retrievable_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with MemoryStore(Path(directory) / "memory.db") as store:
                memory_id = store.add(
                    {"fact": "unsafe"},
                    namespace="test-only/profile",
                )
                ReviewQueue(store).reject(memory_id, reviewer="user", reason="not mine")
                self.assertEqual(store.search("unsafe", namespace="test-only/profile"), [])
                self.assertEqual(store.get(memory_id)["status"], "denied")
