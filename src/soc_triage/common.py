"""Small shared helpers: timestamps, safe dict access, stable ordering."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

_FRACTION = re.compile(r"\.(\d+)")


def parse_ts(value: str | None) -> datetime | None:
    """Parse Graph/Sentinel timestamps (7-digit fractions, 'Z', or 'YYYY-MM-DD HH:MM:SSZ')."""
    if not value:
        return None
    s = value.strip().replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), s, count=1)
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def to_epoch_ms(value: str | None) -> int | None:
    """OCSF timestamp_t: milliseconds since the Unix epoch."""
    dt = parse_ts(value)
    return int(dt.timestamp() * 1000) if dt else None


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def maybe_json(value: Any) -> Any:
    """Sentinel puts JSON arrays inside string fields (e.g. 'Data Sources'). Decode when possible."""
    if isinstance(value, str) and value[:1] in "[{":
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def odata_type(evidence: dict) -> str:
    """'#microsoft.graph.security.userEvidence' -> 'userEvidence'."""
    return (evidence.get("@odata.type") or "").rsplit(".", 1)[-1]


def unique(items: Iterable[Any]) -> list[Any]:
    """Order-preserving de-duplication (keeps output deterministic)."""
    seen, out = set(), []
    for item in items:
        key = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else item
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def drop_empty(obj: Any) -> Any:
    """Recursively remove None, empty strings, empty lists and empty dicts."""
    if isinstance(obj, dict):
        cleaned = {k: drop_empty(v) for k, v in obj.items()}
        return {k: v for k, v in cleaned.items() if v not in (None, "", [], {})}
    if isinstance(obj, list):
        return [v for v in (drop_empty(i) for i in obj) if v not in (None, "", [], {})]
    return obj


def unwrap_alert(payload: Any) -> dict:
    """Accept a single alert, a one-element list, or a Graph {'value': [...]} page."""
    if isinstance(payload, dict) and isinstance(payload.get("value"), list):
        payload = payload["value"]
    if isinstance(payload, list):
        if len(payload) != 1:
            raise ValueError(f"Expected exactly one alert, got {len(payload)}")
        payload = payload[0]
    if not isinstance(payload, dict):
        raise ValueError("Alert payload must be a JSON object")
    return payload
