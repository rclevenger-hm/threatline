from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from threatline.domain import WorkItem
from threatline.handoff import build_handoff
from threatline.journal import WorkspaceJournal
from threatline.providers.base import HealthStatus, ProviderHealth, ProviderKind


class WorkProvider:
    name = "work"
    kind = ProviderKind.WORK

    def capabilities(self): return frozenset()
    def health(self): return ProviderHealth(HealthStatus.HEALTHY, "ok")
    def services(self): return []
    def alerts(self): return []
    def changes(self): return []
    def runbooks(self): return []
    def meetings(self): return []
    def decisions(self): return []
    def work_items(self):
        return [
            WorkItem(
                "OPS-42",
                "Checkout latency elevated",
                "Investigating",
                "high",
                assignee="Alex",
            )
        ]


class HandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.journal = WorkspaceJournal(Path(self.temp.name) / "journal.json", timezone_name="UTC")
        self.now = datetime(2026, 9, 16, 14, 30, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_handoff_uses_touched_work_and_notes(self) -> None:
        self.journal.record_activity(
            "investigation_opened",
            work_item_id="OPS-42",
            summary="Opened investigation",
            at=self.now,
        )
        self.journal.add_note(
            "Connection saturation dropped after rollback.",
            work_item_id="OPS-42",
            at=self.now,
        )
        self.journal.add_note("Watch the queue through end of shift.", at=self.now)

        handoff = build_handoff(self.journal, WorkProvider(), "2026-09-16")
        markdown = handoff["markdown"]
        self.assertEqual(handoff["work_item_ids"], ["OPS-42"])
        self.assertIn("OPS-42 — Checkout latency elevated", markdown)
        self.assertIn("Status: Investigating", markdown)
        self.assertIn("Owner: Alex", markdown)
        self.assertIn("Connection saturation dropped after rollback.", markdown)
        self.assertIn("Watch the queue through end of shift.", markdown)
        self.assertIn("Opened investigation", markdown)

    def test_handoff_without_activity_is_explicit(self) -> None:
        handoff = build_handoff(self.journal, WorkProvider(), "2026-09-16")
        self.assertIn("No work items were recorded", handoff["markdown"])
        self.assertIn("No general notes recorded", handoff["markdown"])


if __name__ == "__main__":
    unittest.main()
