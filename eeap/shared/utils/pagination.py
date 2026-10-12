from __future__ import annotations

import base64
import json

from fastapi import HTTPException


def encode_cursor(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> dict | None:
    if not cursor:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(400, detail="invalid cursor") from exc


def page(items: list, limit: int, cursor_of) -> dict:
    """Builds a keyset page; callers fetch limit + 1 rows to detect a next page."""
    has_more = len(items) > limit
    items = items[:limit]
    return {"items": items, "next_cursor": encode_cursor(cursor_of(items[-1])) if has_more and items else None}
