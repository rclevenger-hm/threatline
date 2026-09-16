from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from threatline.domain import WorkItem

_PRIORITY_SCORES = {
    "critical": 70,
    "highest": 70,
    "urgent": 70,
    "p0": 70,
    "p1": 60,
    "high": 50,
    "p2": 40,
    "medium": 25,
    "normal": 20,
    "low": 8,
    "lowest": 2,
}
_PAUSED_TERMS = ("blocked", "on hold", "on-hold", "waiting", "pending requester", "pending customer")


@dataclass(frozen=True, slots=True)
class AttentionScore:
    work_item: WorkItem
    score: int
    reasons: tuple[str, ...]


def score_work_item(item: WorkItem, *, now: datetime | None = None) -> AttentionScore:
    now = now or datetime.now(timezone.utc)
    score = _PRIORITY_SCORES.get(item.priority.strip().lower(), 15)
    reasons: list[str] = []

    priority = item.priority.strip().lower() or "normal"
    if score >= 50:
        reasons.append(f"{priority} priority")

    if not item.assignee:
        score += 18
        reasons.append("unassigned")

    updated_age = max(0.0, (now - item.updated_at.astimezone(timezone.utc)).total_seconds() / 86400)
    if updated_age >= 7:
        score += 25
        reasons.append(f"no update for {int(updated_age)}d")
    elif updated_age >= 3:
        score += 15
        reasons.append(f"no update for {int(updated_age)}d")
    elif updated_age >= 1:
        score += 8
        reasons.append("no update today")

    if item.created_at is not None:
        created_age = max(0.0, (now - item.created_at.astimezone(timezone.utc)).total_seconds() / 86400)
        if created_age >= 30:
            score += 15
            reasons.append(f"open for {int(created_age)}d")
        elif created_age >= 14:
            score += 8
            reasons.append(f"open for {int(created_age)}d")

    status = item.status.strip().lower()
    if any(term in status for term in _PAUSED_TERMS):
        score = max(0, score - 20)
        reasons.append("paused/waiting")

    if not reasons:
        reasons.append("active work")
    return AttentionScore(item, score, tuple(reasons))


def today(items: Iterable[WorkItem], *, now: datetime | None = None, limit: int = 20) -> list[AttentionScore]:
    scored = [score_work_item(item, now=now) for item in items]
    return sorted(scored, key=lambda value: (-value.score, value.work_item.updated_at, value.work_item.id))[: max(limit, 0)]


def queue(
    items: Iterable[WorkItem],
    *,
    query: str = "",
    priority: str = "",
    status: str = "",
    ownership: str = "any",
    sort: str = "attention",
    now: datetime | None = None,
) -> list[AttentionScore]:
    query_text = query.strip().lower()
    priority_text = priority.strip().lower()
    status_text = status.strip().lower()
    ownership_text = ownership.strip().lower()
    values: list[AttentionScore] = []

    for item in items:
        if query_text and query_text not in f"{item.id} {item.title} {' '.join(item.tags)}".lower():
            continue
        if priority_text and item.priority.strip().lower() != priority_text:
            continue
        if status_text and item.status.strip().lower() != status_text:
            continue
        if ownership_text == "unassigned" and item.assignee:
            continue
        if ownership_text == "assigned" and not item.assignee:
            continue
        values.append(score_work_item(item, now=now))

    if sort == "updated":
        return sorted(values, key=lambda value: (value.work_item.updated_at, value.work_item.id), reverse=True)
    if sort == "oldest":
        return sorted(values, key=lambda value: (value.work_item.created_at or value.work_item.updated_at, value.work_item.id))
    if sort == "priority":
        return sorted(values, key=lambda value: (-_PRIORITY_SCORES.get(value.work_item.priority.lower(), 15), value.work_item.id))
    return sorted(values, key=lambda value: (-value.score, value.work_item.updated_at, value.work_item.id))
