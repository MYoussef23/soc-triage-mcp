"""VirusTotal v3 and AbuseIPDB v2 clients (read-only lookups) with a shared SQLite cache and a
per-provider rate limiter. Responses are reduced to the fields the triage needs."""
from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import time
from pathlib import Path

import httpx

VT = "https://www.virustotal.com/api/v3"
ABUSE = "https://api.abuseipdb.com/api/v2"


_GUI = {"ip": "ip-address", "domain": "domain", "hash": "file", "url": "url"}


def _vt_gui_url(ioc_type: str, value: str, api_path: str) -> str:
    ident = api_path.split("/", 1)[1] if ioc_type == "url" else value
    return f"https://www.virustotal.com/gui/{_GUI[ioc_type]}/{ident}"


class Cache:
    def __init__(self, path: str, ttl_hours: int):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS osint (k TEXT PRIMARY KEY, v TEXT, t REAL)")
        self.ttl = ttl_hours * 3600

    def get(self, key: str):
        row = self.db.execute("SELECT v, t FROM osint WHERE k = ?", (key,)).fetchone()
        if row and time.time() - row[1] < self.ttl:
            return json.loads(row[0])
        return None

    def put(self, key: str, value) -> None:
        self.db.execute("INSERT OR REPLACE INTO osint VALUES (?, ?, ?)", (key, json.dumps(value), time.time()))
        self.db.commit()


class RateLimiter:
    def __init__(self, per_minute: int):
        self.interval = 60.0 / max(per_minute, 1)
        self.next_at = 0.0
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self.lock:
            delay = self.next_at - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self.next_at = time.monotonic() + self.interval


class VirusTotal:
    def __init__(self, api_key: str, cache: Cache, per_minute: int = 4):
        self.key, self.cache, self.limit = api_key, cache, RateLimiter(per_minute)

    async def lookup(self, ioc_type: str, value: str) -> dict:
        ck = f"vt:{ioc_type}:{value}"
        if (hit := self.cache.get(ck)) is not None:
            return {**hit, "cached": True}
        path = {"ip": f"ip_addresses/{value}", "domain": f"domains/{value}", "hash": f"files/{value}",
                "url": "urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")}[ioc_type]
        await self.limit.wait()
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(f"{VT}/{path}", headers={"x-apikey": self.key})
        if r.status_code == 404:
            result = {"provider": "virustotal", "type": ioc_type, "value": value, "found": False}
        elif r.status_code == 429:
            return {"provider": "virustotal", "type": ioc_type, "value": value, "error": "rate_limited"}
        else:
            r.raise_for_status()
            a = r.json().get("data", {}).get("attributes", {})
            stats = a.get("last_analysis_stats") or {}
            result = {
                "provider": "virustotal", "type": ioc_type, "value": value, "found": True,
                "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0),
                "reputation": a.get("reputation"), "asn": a.get("asn"), "as_owner": a.get("as_owner"),
                "country": a.get("country"), "network": a.get("network"), "tags": a.get("tags") or [],
                "last_analysis_date": a.get("last_analysis_date"),
                "categories": sorted(set((a.get("categories") or {}).values()))[:5],
                "meaningful_name": a.get("meaningful_name"), "type_description": a.get("type_description"),
                "flagging_engines": sorted(k for k, v in (a.get("last_analysis_results") or {}).items()
                                           if v.get("category") in ("malicious", "suspicious"))[:10],
                "src_url": _vt_gui_url(ioc_type, value, path),
            }
        self.cache.put(ck, result)
        return result


class AbuseIPDB:
    def __init__(self, api_key: str, cache: Cache, max_age_days: int = 90):
        self.key, self.cache, self.max_age = api_key, cache, max_age_days
        self.limit = RateLimiter(60)

    async def check(self, ip: str) -> dict:
        ck = f"abuse:{ip}:{self.max_age}"
        if (hit := self.cache.get(ck)) is not None:
            return {**hit, "cached": True}
        await self.limit.wait()
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(f"{ABUSE}/check", headers={"Key": self.key, "Accept": "application/json"},
                            params={"ipAddress": ip, "maxAgeInDays": self.max_age})
        if r.status_code == 429:
            return {"provider": "abuseipdb", "type": "ip", "value": ip, "error": "rate_limited"}
        r.raise_for_status()
        d = r.json().get("data", {})
        result = {
            "provider": "abuseipdb", "type": "ip", "value": ip, "found": True,
            "abuse_confidence_score": d.get("abuseConfidenceScore"), "total_reports": d.get("totalReports"),
            "distinct_reporters": d.get("numDistinctUsers"), "last_reported_at": d.get("lastReportedAt"),
            "country": d.get("countryCode"), "isp": d.get("isp"), "domain": d.get("domain"),
            "usage_type": d.get("usageType"), "is_tor": d.get("isTor"), "is_whitelisted": d.get("isWhitelisted"),
            "src_url": f"https://www.abuseipdb.com/check/{ip}",
        }
        self.cache.put(ck, result)
        return result
