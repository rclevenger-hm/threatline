from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _parse_timestamp(value: object) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _source_url(value: dict[str, Any]) -> str | None:
    source_ref = value.get("source_ref")
    if isinstance(source_ref, dict):
        url = source_ref.get("url")
        return str(url) if url else None
    return None


def _event(kind: str, timestamp: object, title: str, value: dict[str, Any], detail: str = "") -> dict[str, Any] | None:
    parsed = _parse_timestamp(timestamp)
    if parsed is None:
        return None
    source_ref = value.get("source_ref") if isinstance(value.get("source_ref"), dict) else {}
    return {
        "kind": kind,
        "timestamp": parsed.isoformat(),
        "title": title,
        "detail": detail,
        "source": source_ref.get("provider") or value.get("source") or "threatline",
        "url": _source_url(value),
    }


def build_investigation(context: dict[str, Any]) -> dict[str, Any]:
    work_item = context.get("work_item") or {}
    if not isinstance(work_item, dict) or not work_item.get("id"):
        raise ValueError("Investigation requires a work item")

    timeline: list[dict[str, Any]] = []
    created = _event(
        "work_created",
        work_item.get("created_at"),
        f"{work_item['id']} created",
        work_item,
        str(work_item.get("title") or ""),
    )
    if created:
        timeline.append(created)
    updated = _event(
        "work_updated",
        work_item.get("updated_at"),
        f"{work_item['id']} updated",
        work_item,
        str(work_item.get("status") or ""),
    )
    if updated:
        timeline.append(updated)

    for alert in context.get("alerts") or []:
        if not isinstance(alert, dict):
            continue
        event = _event(
            "alert",
            alert.get("started_at"),
            str(alert.get("title") or alert.get("id") or "Alert"),
            alert,
            str(alert.get("severity") or ""),
        )
        if event:
            timeline.append(event)

    for change in context.get("changes") or []:
        if not isinstance(change, dict):
            continue
        event = _event(
            "change",
            change.get("occurred_at"),
            str(change.get("title") or change.get("id") or "Change"),
            change,
            str(change.get("author") or ""),
        )
        if event:
            timeline.append(event)

    for meeting in context.get("meetings") or []:
        if not isinstance(meeting, dict):
            continue
        participants = meeting.get("participants") or []
        detail = ", ".join(str(value) for value in participants[:4])
        event = _event(
            "meeting",
            meeting.get("started_at"),
            str(meeting.get("title") or meeting.get("id") or "Meeting"),
            meeting,
            detail,
        )
        if event:
            timeline.append(event)

    for decision in context.get("decisions") or []:
        if not isinstance(decision, dict):
            continue
        event = _event(
            "decision",
            decision.get("decided_at"),
            "Decision recorded",
            decision,
            str(decision.get("summary") or ""),
        )
        if event:
            timeline.append(event)

    timeline.sort(key=lambda item: item["timestamp"], reverse=True)
    service = context.get("service") if isinstance(context.get("service"), dict) else None

    return {
        "work_item": work_item,
        "service": service,
        "ownership": {
            "assignee": work_item.get("assignee"),
            "reporter": work_item.get("reporter"),
            "service_owner": service.get("owner") if service else None,
        },
        "timeline": timeline,
        "alerts": context.get("alerts") or [],
        "changes": context.get("changes") or [],
        "runbooks": context.get("runbooks") or [],
        "meetings": context.get("meetings") or [],
        "decisions": context.get("decisions") or [],
        "relationships": context.get("relationships") or [],
        "counts": {
            "alerts": len(context.get("alerts") or []),
            "changes": len(context.get("changes") or []),
            "runbooks": len(context.get("runbooks") or []),
            "meetings": len(context.get("meetings") or []),
            "decisions": len(context.get("decisions") or []),
        },
    }
