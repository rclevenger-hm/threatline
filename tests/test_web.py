from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from threatline.journal import WorkspaceJournal
from threatline.web import create_server


class WebTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        journal = WorkspaceJournal(Path(self.temp.name) / "journal.json", timezone_name="UTC")
        self.server = create_server("127.0.0.1", 0, journal=journal)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=2) as response:
            return json.load(response)

    def test_health(self) -> None:
        with urlopen(f"{self.base_url}/healthz", timeout=2) as response:
            payload = json.load(response)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["providers"][0]["name"], "demo")
        self.assertEqual(payload["providers"][0]["health"]["status"], "healthy")

    def test_provider_diagnostics_api(self) -> None:
        with urlopen(f"{self.base_url}/api/providers", timeout=2) as response:
            payload = json.load(response)
        self.assertEqual(payload["providers"][0]["name"], "demo")
        self.assertIn("read_work_items", payload["providers"][0]["capabilities"])

    def test_context_api(self) -> None:
        with urlopen(f"{self.base_url}/api/work-items/OPS-142", timeout=2) as response:
            payload = json.load(response)
        self.assertEqual(payload["work_item"]["id"], "OPS-142")
        self.assertEqual(payload["service"]["id"], "checkout-api")

    def test_today_api_returns_attention_reasons(self) -> None:
        with urlopen(f"{self.base_url}/api/today", timeout=2) as response:
            payload = json.load(response)
        self.assertGreaterEqual(len(payload["items"]), 1)
        self.assertIn("score", payload["items"][0])
        self.assertIn("reasons", payload["items"][0])
        self.assertIn("work_item", payload["items"][0])

    def test_queue_api_filters_unassigned(self) -> None:
        with urlopen(f"{self.base_url}/api/queue?ownership=unassigned&q=checkout", timeout=2) as response:
            payload = json.load(response)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["items"][0]["work_item"]["id"], "OPS-142")

    def test_investigation_api_includes_timeline_and_context(self) -> None:
        with urlopen(f"{self.base_url}/api/investigations/OPS-142", timeout=2) as response:
            payload = json.load(response)
        self.assertEqual(payload["work_item"]["id"], "OPS-142")
        self.assertGreaterEqual(len(payload["timeline"]), 1)
        self.assertGreaterEqual(payload["counts"]["alerts"], 1)
        self.assertGreaterEqual(payload["counts"]["changes"], 1)
        self.assertGreaterEqual(payload["counts"]["runbooks"], 1)

    def test_notes_and_activity_feed_handoff(self) -> None:
        self._post(
            "/api/activity",
            {"kind": "investigation_opened", "work_item_id": "OPS-142", "summary": "Opened investigation"},
        )
        note_response = self._post(
            "/api/notes",
            {"text": "Rollback is holding; watch connection saturation.", "work_item_id": "OPS-142"},
        )
        created_day = note_response["note"]["day"]
        with urlopen(f"{self.base_url}/api/notes?date={created_day}", timeout=2) as response:
            notes_payload = json.load(response)
        self.assertEqual(len(notes_payload["notes"]), 1)
        with urlopen(f"{self.base_url}/api/handoff?date={created_day}", timeout=2) as response:
            handoff = json.load(response)
        self.assertIn("OPS-142", handoff["work_item_ids"])
        self.assertIn("Rollback is holding", handoff["markdown"])
        self.assertIn("Opened investigation", handoff["markdown"])


if __name__ == "__main__":
    unittest.main()
