from __future__ import annotations

import json
import threading
import unittest
from urllib.request import urlopen

from threatline.web import create_server


class WebTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = create_server("127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

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


if __name__ == "__main__":
    unittest.main()
