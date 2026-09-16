from __future__ import annotations

from datetime import datetime, timedelta, timezone

from threatline.domain import Alert, Change, Decision, Meeting, Runbook, Service, Severity, WorkItem
from threatline.providers.base import HealthStatus, ProviderCapability, ProviderHealth, ProviderKind


class DemoProvider:
    name = "demo"
    kind = ProviderKind.DEMO

    def __init__(self) -> None:
        now = datetime.now(timezone.utc)
        self._services = [
            Service("checkout-api", "Checkout API", "Payments Platform", "Processes checkout requests."),
            Service("event-pipeline", "Event Pipeline", "Data Platform", "Processes asynchronous product events."),
        ]
        self._work_items = [
            WorkItem(
                "OPS-142",
                "Checkout latency elevated",
                "investigating",
                "high",
                "checkout-api",
                "demo",
                now - timedelta(minutes=18),
                assignee=None,
                reporter="Support",
                created_at=now - timedelta(hours=2),
            ),
            WorkItem(
                "DATA-88",
                "Consumer lag above normal",
                "open",
                "medium",
                "event-pipeline",
                "demo",
                now - timedelta(days=4),
                assignee="Morgan",
                reporter="Monitoring",
                created_at=now - timedelta(days=16),
            ),
            WorkItem(
                "OPS-131",
                "Confirm requester after cache cleanup",
                "Waiting on requester",
                "low",
                "checkout-api",
                "demo",
                now - timedelta(days=2),
                assignee="Alex",
                reporter="Customer Success",
                created_at=now - timedelta(days=8),
            ),
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

    def capabilities(self) -> frozenset[ProviderCapability]:
        return frozenset(
            {
                ProviderCapability.READ_SERVICES,
                ProviderCapability.READ_WORK_ITEMS,
                ProviderCapability.READ_ALERTS,
                ProviderCapability.READ_CHANGES,
                ProviderCapability.READ_RUNBOOKS,
                ProviderCapability.READ_MEETINGS,
                ProviderCapability.READ_DECISIONS,
            }
        )

    def health(self) -> ProviderHealth:
        return ProviderHealth(HealthStatus.HEALTHY, "Demo data is available")

    def services(self) -> list[Service]: return list(self._services)
    def work_items(self) -> list[WorkItem]: return list(self._work_items)
    def alerts(self) -> list[Alert]: return list(self._alerts)
    def changes(self) -> list[Change]: return list(self._changes)
    def runbooks(self) -> list[Runbook]: return list(self._runbooks)
    def meetings(self) -> list[Meeting]: return list(self._meetings)
    def decisions(self) -> list[Decision]: return list(self._decisions)
