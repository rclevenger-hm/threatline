from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from threatline.attention import queue, score_work_item, today
from threatline.domain import WorkItem


class AttentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)

    def test_high_unassigned_stale_item_ranks_first(self) -> None:
        urgent = WorkItem(
            "OPS-1", "Checkout failing", "open", "high", updated_at=self.now - timedelta(days=4), created_at=self.now - timedelta(days=20)
        )
        normal = WorkItem(
            "OPS-2", "Routine cleanup", "open", "low", updated_at=self.now - timedelta(hours=1), assignee="Alex"
        )
        ranked = today([normal, urgent], now=self.now)
        self.assertEqual(ranked[0].work_item.id, "OPS-1")
        self.assertIn("unassigned", ranked[0].reasons)
        self.assertIn("no update for 4d", ranked[0].reasons)

    def test_waiting_status_reduces_attention(self) -> None:
        active = WorkItem("OPS-1", "Active", "open", "medium", updated_at=self.now)
        waiting = WorkItem("OPS-2", "Waiting", "Waiting on requester", "medium", updated_at=self.now)
        self.assertGreater(score_work_item(active, now=self.now).score, score_work_item(waiting, now=self.now).score)

    def test_queue_filters_unassigned_and_query(self) -> None:
        items = [
            WorkItem("OPS-1", "Checkout latency", "open", "high", assignee=None),
            WorkItem("OPS-2", "Kafka lag", "open", "high", assignee="Morgan"),
        ]
        values = queue(items, query="checkout", ownership="unassigned", now=self.now)
        self.assertEqual([value.work_item.id for value in values], ["OPS-1"])

    def test_queue_can_sort_oldest(self) -> None:
        older = WorkItem("OPS-1", "Older", "open", created_at=self.now - timedelta(days=10))
        newer = WorkItem("OPS-2", "Newer", "open", created_at=self.now - timedelta(days=1))
        values = queue([newer, older], sort="oldest", now=self.now)
        self.assertEqual([value.work_item.id for value in values], ["OPS-1", "OPS-2"])


if __name__ == "__main__":
    unittest.main()
