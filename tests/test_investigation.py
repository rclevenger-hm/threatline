from __future__ import annotations

import unittest

from threatline.context import ContextEngine
from threatline.investigation import build_investigation
from threatline.providers.demo import DemoProvider


class InvestigationTests(unittest.TestCase):
    def test_investigation_collects_related_context(self) -> None:
        context = ContextEngine(DemoProvider()).work_item_context("OPS-142")
        self.assertIsNotNone(context)
        assert context is not None
        investigation = build_investigation(context)
        self.assertEqual(investigation["work_item"]["id"], "OPS-142")
        self.assertEqual(investigation["service"]["id"], "checkout-api")
        self.assertGreaterEqual(investigation["counts"]["alerts"], 1)
        self.assertGreaterEqual(investigation["counts"]["changes"], 1)
        self.assertGreaterEqual(investigation["counts"]["runbooks"], 1)
        self.assertGreaterEqual(investigation["counts"]["meetings"], 1)
        self.assertGreaterEqual(investigation["counts"]["decisions"], 1)

    def test_timeline_is_reverse_chronological(self) -> None:
        context = ContextEngine(DemoProvider()).work_item_context("OPS-142")
        assert context is not None
        timeline = build_investigation(context)["timeline"]
        timestamps = [event["timestamp"] for event in timeline]
        self.assertEqual(timestamps, sorted(timestamps, reverse=True))
        kinds = {event["kind"] for event in timeline}
        self.assertIn("alert", kinds)
        self.assertIn("change", kinds)
        self.assertIn("meeting", kinds)
        self.assertIn("decision", kinds)

    def test_invalid_context_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_investigation({})


if __name__ == "__main__":
    unittest.main()
