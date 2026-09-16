from __future__ import annotations

from datetime import date
from typing import Any

from threatline.journal import WorkspaceJournal
from threatline.providers.base import ContextReader


def build_handoff(journal: WorkspaceJournal, provider: ContextReader, day: date | str) -> dict[str, Any]:
    day_text = day.isoformat() if isinstance(day, date) else str(day)
    notes = journal.notes(day_text)
    activities = journal.activities(day_text)

    touched_ids: list[str] = []
    for entry in [*activities, *notes]:
        work_item_id = entry.get("work_item_id")
        if work_item_id and work_item_id not in touched_ids:
            touched_ids.append(str(work_item_id))

    current_items = {item.id: item for item in provider.work_items()}
    lines = [f"# Shift handoff — {day_text}", ""]

    lines.extend(["## Touched work", ""])
    if not touched_ids:
        lines.extend(["No work items were recorded in Threatline for this day.", ""])
    else:
        for work_item_id in touched_ids:
            item = current_items.get(work_item_id)
            if item is None:
                lines.extend([f"### {work_item_id}", "", "Current source state is unavailable.", ""])
            else:
                owner = item.assignee or "Unassigned"
                lines.extend(
                    [
                        f"### {item.id} — {item.title}",
                        "",
                        f"- Status: {item.status}",
                        f"- Priority: {item.priority}",
                        f"- Owner: {owner}",
                    ]
                )
                if item.source_ref and item.source_ref.url:
                    lines.append(f"- Source: {item.source_ref.url}")
                linked_notes = [note for note in notes if note.get("work_item_id") == work_item_id]
                if linked_notes:
                    lines.extend(["", "Notes:"])
                    lines.extend(f"- {note['text']}" for note in linked_notes)
                lines.append("")

    general_notes = [note for note in notes if not note.get("work_item_id")]
    lines.extend(["## General notes", ""])
    if general_notes:
        lines.extend(f"- {note['text']}" for note in general_notes)
        lines.append("")
    else:
        lines.extend(["No general notes recorded.", ""])

    lines.extend(["## Activity", ""])
    meaningful = [activity for activity in activities if activity.get("kind") != "note_added"]
    if meaningful:
        for activity in meaningful:
            timestamp = str(activity.get("created_at") or "")
            clock = timestamp[11:16] if len(timestamp) >= 16 else timestamp
            work_item = f" — {activity['work_item_id']}" if activity.get("work_item_id") else ""
            summary = activity.get("summary") or str(activity.get("kind") or "activity").replace("_", " ").title()
            lines.append(f"- {clock} — {summary}{work_item}")
        lines.append("")
    else:
        lines.extend(["No additional operator activity recorded.", ""])

    return {
        "day": day_text,
        "work_item_ids": touched_ids,
        "notes": notes,
        "activities": activities,
        "markdown": "\n".join(lines).rstrip() + "\n",
    }
