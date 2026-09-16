from __future__ import annotations

import unittest

from threatline.context import ContextEngine
from threatline.providers.demo import DemoProvider


class ContextEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = ContextEngine(DemoProvider())

    def test_snapshot_contains_normalized_context(self) -> None:
        snapshot = self.engine.snapshot()
        self.assertEqual(snapshot["provider"], "demo")
        self.assertGreaterEqual(len(snapshot["work_items"]), 1)
        self.assertGreaterEqual(len(snapshot["services"]), 1)

    def test_work_item_context_correlates_related_objects(self) -> None:
        context = self.engine.work_item_context("OPS-142")
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(context["service"]["id"], "checkout-api")
        self.assertEqual(context["alerts"][0]["service_id"], "checkout-api")
        self.assertEqual(context["meetings"][0]["id"], "MTG-12")
        self.assertEqual(context["decisions"][0]["id"], "DEC-3")

    def test_missing_work_item_returns_none(self) -> None:
        self.assertIsNone(self.engine.work_item_context("MISSING-1"))


if __name__ == "__main__":
    unittest.main()
