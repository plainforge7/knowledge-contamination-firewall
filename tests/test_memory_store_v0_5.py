import tempfile
import unittest
from pathlib import Path

from controlled_compare.memory_store_v0_5 import MemoryStore


class MemoryStoreV05Tests(unittest.TestCase):
    def test_only_confirmed_memories_are_retrievable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with MemoryStore(Path(directory) / "memory.db") as store:
                quarantined = store.add(
                    {"language": "Python", "version": "3.13"},
                    namespace="test-only/profile",
                    source_ids=["candidate-1"],
                )
                confirmed = store.add(
                    {"language": "Python", "version": "3.12"},
                    namespace="test-only/profile",
                    status="confirmed",
                    source_ids=["user-1"],
                )
                results = store.search("Python", namespace="test-only/profile")
                self.assertEqual([item["memory_id"] for item in results], [confirmed])
                self.assertEqual(store.get(quarantined)["status"], "quarantine")

    def test_transition_is_audited_and_makes_memory_retrievable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with MemoryStore(Path(directory) / "memory.db") as store:
                memory_id = store.add(
                    {"preference": "dark mode"},
                    namespace="test-only/profile",
                )
                self.assertEqual(store.search("dark", namespace="test-only/profile"), [])
                store.transition(memory_id, "confirmed", reason="human_review_approved")
                self.assertEqual(len(store.search("dark", namespace="test-only/profile")), 1)
                events = store.events(memory_id)
                self.assertEqual([event["event_type"] for event in events], ["created", "status_changed"])
                self.assertEqual(events[-1]["to_status"], "confirmed")

    def test_production_namespace_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with MemoryStore(Path(directory) / "memory.db") as store:
                with self.assertRaises(ValueError):
                    store.add({"fact": "x"}, namespace="personal_long_term_memory")
                with self.assertRaises(ValueError):
                    store.search("x", namespace="production")

    def test_denied_memory_is_stored_for_audit_but_never_retrieved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with MemoryStore(Path(directory) / "memory.db") as store:
                memory_id = store.add(
                    {"fact": "forged"},
                    namespace="test-only/profile",
                    status="denied",
                )
                self.assertEqual(store.search("forged", namespace="test-only/profile"), [])
                self.assertEqual(len(store.events(memory_id)), 1)


if __name__ == "__main__":
    unittest.main()
