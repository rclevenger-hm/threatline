from __future__ import annotations

from datetime import datetime, timedelta, timezone

from threatline.domain import Alert, Change, Decision, Meeting, Runbook, Service, Severity, WorkItem


class DemoProvider:
    name = "demo"

    def __init__(self) -> None:
        now = datetime.now(timezone.utc)
        self._services = [
            Service("checkout-api", "Checkout API", "Payments Platform", "Processes checkout requests."),
            Service("event-pipeline", "Event Pipeline", "Data Platform", "Processes asynchronous product events."),
        ]
        self._work_items = [
            WorkItem("OPS-142", "Checkout latency elevated", "investigating", "high", "checkout-api", "demo", now - timedelta(minutes=18)),
            WorkItem("DATA-88", "Consumer lag above normal", "open", "medium", "event-pipeline", "demo", now - timedelta(minutes=41)),
        ]
        self._alerts = [
            Alert("ALT-14", "p95 checkout latency > 900ms", Severity.HIGH, "checkout-api", "demo", now - timedelta(minutes=22)),
        ]
        self._changes = [
            Change("CHG-91", "Increase database connection pool", "checkout-api", "alex", "demo", now - timedelta(hours=2)),
        ]
        self._runbooks = [Runbook("RB-7", "Checkout latency", "checkout-api", "docs/runbooks/checkout-latency.md")]
        self._meetings = [
            Meeting("MTG-12", "Checkout incident room", ("Alex", "Morgan", "Sam"), ("OPS-142",), now - timedelta(minutes=15)),
        ]
        self._decisions = [
            Decision("DEC-3", "Rollback the connection-pool change if saturation remains above 90%.", "OPS-142", "MTG-12", now - timedelta(minutes=6)),
        ]

    def services(self) -> list[Service]: return list(self._services)
    def work_items(self) -> list[WorkItem]: return list(self._work_items)
    def alerts(self) -> list[Alert]: return list(self._alerts)
    def changes(self) -> list[Change]: return list(self._changes)
    def runbooks(self) -> list[Runbook]: return list(self._runbooks)
    def meetings(self) -> list[Meeting]: return list(self._meetings)
    def decisions(self) -> list[Decision]: return list(self._decisions)
