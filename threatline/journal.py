from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

JOURNAL_VERSION = 1


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: object) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _timezone(name: str):
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return timezone.utc


class WorkspaceJournal:
    """Small local journal for notes and explicit operator activity."""

    def __init__(self, path: Path | None = None, *, timezone_name: str | None = None) -> None:
        data_dir = Path(os.environ.get("THREATLINE_DATA_DIR", ".runtime"))
        self.path = path or data_dir / "journal.json"
        self.timezone_name = timezone_name or os.environ.get("THREATLINE_TIMEZONE", "UTC") or "UTC"
        self.tz = _timezone(self.timezone_name)
        self._lock = threading.RLock()

    def add_note(
        self,
        text: str,
        *,
        work_item_id: str | None = None,
        at: datetime | None = None,
    ) -> dict[str, Any]:
        body = text.strip()
        if not body:
            raise ValueError("Note cannot be empty")
        timestamp = (at or _utc_now()).astimezone(timezone.utc)
        note = {
            "id": f"note-{uuid.uuid4().hex}",
            "text": body,
            "work_item_id": work_item_id.strip() if work_item_id and work_item_id.strip() else None,
            "created_at": timestamp.isoformat(),
            "day": timestamp.astimezone(self.tz).date().isoformat(),
        }
        with self._lock:
            state = self._load()
            state["notes"].append(note)
            self._save(state)
        self.record_activity(
            "note_added",
            work_item_id=note["work_item_id"],
            summary="Added an operational note",
            at=timestamp,
            dedupe=False,
        )
        return note

    def notes(self, day: date | str) -> list[dict[str, Any]]:
        day_text = day.isoformat() if isinstance(day, date) else str(day)
        with self._lock:
            state = self._load()
            return [dict(note) for note in state["notes"] if note.get("day") == day_text]

    def record_activity(
        self,
        kind: str,
        *,
        work_item_id: str | None = None,
        summary: str = "",
        at: datetime | None = None,
        dedupe: bool = True,
    ) -> dict[str, Any]:
        activity_kind = kind.strip()
        if not activity_kind:
            raise ValueError("Activity kind cannot be empty")
        timestamp = (at or _utc_now()).astimezone(timezone.utc)
        normalized_work_item = work_item_id.strip() if work_item_id and work_item_id.strip() else None
        day_text = timestamp.astimezone(self.tz).date().isoformat()
        with self._lock:
            state = self._load()
            if dedupe:
                for existing in reversed(state["activities"][-50:]):
                    if existing.get("kind") != activity_kind or existing.get("work_item_id") != normalized_work_item:
                        continue
                    existing_time = _parse_time(existing.get("created_at"))
                    if existing_time and timestamp - existing_time <= timedelta(minutes=10):
                        return dict(existing)
                    break
            activity = {
                "id": f"activity-{uuid.uuid4().hex}",
                "kind": activity_kind,
                "work_item_id": normalized_work_item,
                "summary": summary.strip(),
                "created_at": timestamp.isoformat(),
                "day": day_text,
            }
            state["activities"].append(activity)
            self._save(state)
            return dict(activity)

    def activities(self, day: date | str) -> list[dict[str, Any]]:
        day_text = day.isoformat() if isinstance(day, date) else str(day)
        with self._lock:
            state = self._load()
            return [dict(activity) for activity in state["activities"] if activity.get("day") == day_text]

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": JOURNAL_VERSION, "notes": [], "activities": []}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"version": JOURNAL_VERSION, "notes": [], "activities": []}
        if not isinstance(raw, dict):
            return {"version": JOURNAL_VERSION, "notes": [], "activities": []}
        notes = raw.get("notes") if isinstance(raw.get("notes"), list) else []
        activities = raw.get("activities") if isinstance(raw.get("activities"), list) else []
        return {"version": JOURNAL_VERSION, "notes": notes, "activities": activities}

    def _save(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(payload, encoding="utf-8")
        temp.replace(self.path)
