from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatline.journal import WorkspaceJournal


class JournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "journal.json"
        self.journal = WorkspaceJournal(self.path, timezone_name="UTC")
        self.now = datetime(2026, 9, 16, 14, 30, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_note_persists_across_instances(self) -> None:
        note = self.journal.add_note("Watching connection saturation.", work_item_id="OPS-42", at=self.now)
        reopened = WorkspaceJournal(self.path, timezone_name="UTC")
        notes = reopened.notes("2026-09-16")
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["id"], note["id"])
        self.assertEqual(notes[0]["work_item_id"], "OPS-42")
        self.assertEqual(notes[0]["text"], "Watching connection saturation.")

    def test_day_scoping_uses_configured_timezone(self) -> None:
        journal = WorkspaceJournal(self.path, timezone_name="America/Chicago")
        journal.add_note("Late local note", at=datetime(2026, 9, 17, 2, 30, tzinfo=timezone.utc))
        self.assertEqual(len(journal.notes("2026-09-16")), 1)
        self.assertEqual(journal.notes("2026-09-17"), [])

    def test_investigation_activity_is_deduplicated_for_ten_minutes(self) -> None:
        first = self.journal.record_activity("investigation_opened", work_item_id="OPS-42", at=self.now)
        second = self.journal.record_activity(
            "investigation_opened", work_item_id="OPS-42", at=self.now + timedelta(minutes=5)
        )
        third = self.journal.record_activity(
            "investigation_opened", work_item_id="OPS-42", at=self.now + timedelta(minutes=11)
        )
        self.assertEqual(first["id"], second["id"])
        self.assertNotEqual(first["id"], third["id"])
        self.assertEqual(len(self.journal.activities("2026-09-16")), 2)

    def test_malformed_file_recovers_to_empty_state(self) -> None:
        self.path.write_text("not json", encoding="utf-8")
        self.assertEqual(self.journal.notes("2026-09-16"), [])
        self.assertEqual(self.journal.activities("2026-09-16"), [])


if __name__ == "__main__":
    unittest.main()
