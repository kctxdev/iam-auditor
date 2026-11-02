from __future__ import annotations

from datetime import datetime, timezone

_EMPTY = {"", "N/A", "no_information", "not_supported", "None"}


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def parse_dt(v) -> datetime | None:
    """Aceita datetime, ISO-8601 ou os valores especiais do credential report."""
    if v is None or (isinstance(v, str) and v in _EMPTY):
        return None
    if isinstance(v, datetime):
        dt = v
    else:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def principal_index(snapshot: dict) -> dict:
    """'user:alice' -> ARN (usuarios, grupos e roles)."""
    idx = {}
    for kind in ("users", "groups", "roles"):
        for p in snapshot.get(kind, []):
            idx[f"{kind[:-1]}:{p['name']}"] = p["arn"]
    return idx
