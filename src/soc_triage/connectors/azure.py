"""Microsoft Graph Security, Defender XDR advanced hunting, and Sentinel rule metadata (ARM).

Auth: OAuth2 client credentials per customer tenant (app registration needs, as application
permissions / RBAC):
  - Graph:            SecurityAlert.Read.All, SecurityIncident.Read.All, ThreatHunting.Read.All
  - Sentinel (ARM):   Microsoft Sentinel Reader on the workspace resource group
All calls here are read-only.
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import httpx

from ..common import iso_utc, parse_ts
from ..config import Customer, settings

GRAPH = "https://graph.microsoft.com"
ARM = "https://management.azure.com"
_SCOPES = {"graph": f"{GRAPH}/.default", "arm": f"{ARM}/.default"}

_tokens: dict[tuple[str, str], tuple[str, float]] = {}


async def _token(client: httpx.AsyncClient, cust: Customer, api: str) -> str:
    key = (cust.key, api)
    tok = _tokens.get(key)
    if tok and tok[1] - 120 > time.time():
        return tok[0]
    r = await client.post(
        f"https://login.microsoftonline.com/{cust.tenant_id}/oauth2/v2.0/token",
        data={"grant_type": "client_credentials", "client_id": cust.client_id,
              "client_secret": cust.client_secret, "scope": _SCOPES[api]},
    )
    r.raise_for_status()
    body = r.json()
    _tokens[key] = (body["access_token"], time.time() + int(body.get("expires_in", 3600)))
    return body["access_token"]


class HuntingQueryError(RuntimeError):
    def __init__(self, status: int, code: str, message: str):
        self.status = status
        self.code = code
        self.message = message
        super().__init__(f"Graph hunting HTTP {status} [{code}]: {message}")


@dataclass
class AzureClient:
    cust: Customer
    timeout: float = 60.0

    async def _req(self, api: str, method: str, url: str, **kw) -> Any:
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            headers = {"Authorization": f"Bearer {await _token(c, self.cust, api)}"}
            for attempt in range(4):
                r = await c.request(method, url, headers=headers, **kw)
                if r.status_code in (429, 503) and attempt < 3:
                    await asyncio.sleep(min(int(r.headers.get("Retry-After", 2 ** attempt)), 30))
                    continue
                r.raise_for_status()
                return r.json() if r.content else {}

    # ---- Graph Security: alerts & incidents -------------------------------------------------
    async def list_active_alerts(self, top: int = 50, min_severity: str | None = None) -> list[dict]:
        flt = "status ne 'resolved'"
        if min_severity:
            sev = ["informational", "low", "medium", "high"]
            keep = sev[sev.index(min_severity.lower()):]
            flt += " and (" + " or ".join(f"severity eq '{s}'" for s in keep) + ")"
        data = await self._req("graph", "GET", f"{GRAPH}/v1.0/security/alerts_v2",
                               params={"$filter": flt, "$top": top, "$orderby": "createdDateTime desc"})
        return data.get("value", [])

    async def list_active_incidents(self, top: int = 25) -> list[dict]:
        data = await self._req("graph", "GET", f"{GRAPH}/v1.0/security/incidents",
                               params={"$filter": "status eq 'active' or status eq 'inProgress'",
                                       "$top": top, "$orderby": "createdDateTime desc"})
        return data.get("value", [])

    async def get_alert(self, alert_id: str) -> dict:
        return await self._req("graph", "GET", f"{GRAPH}/v1.0/security/alerts_v2/{alert_id}")

    async def get_incident(self, incident_id: str) -> dict:
        return await self._req("graph", "GET", f"{GRAPH}/v1.0/security/incidents/{incident_id}",
                               params={"$expand": "alerts"})

    async def run_hunting_query(self, kql: str, timespan: str | None = None) -> list[dict]:
        """Run KQL against the unified hunting schema through Microsoft Graph."""
        body: dict = {"Query": kql}
        if timespan:
            body["Timespan"] = timespan
        try:
            data = await self._req("graph", "POST", f"{GRAPH}/v1.0/security/runHuntingQuery", json=body)
        except httpx.HTTPStatusError as exc:
            try:
                error = exc.response.json().get("error") or {}
            except (ValueError, AttributeError):
                error = {}
            if not isinstance(error, dict):
                error = {}
            code = str(error.get("code") or "Unknown")
            message = str(error.get("message") or "No Graph error message")
            raise HuntingQueryError(exc.response.status_code, code, message) from exc
        rows = data.get("results")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise RuntimeError("Graph hunting response did not contain a results array of objects")
        return rows

    # ---- Sentinel: analytic rule (full detection query) --------------------------------------
    async def get_alert_rule(self, rule_id: str) -> dict:
        c = self.cust
        if not (c.subscription_id and c.resource_group and c.workspace_name):
            raise RuntimeError(f"customer {c.key}: subscription_id/resource_group/workspace_name required")
        url = (f"{ARM}/subscriptions/{c.subscription_id}/resourceGroups/{c.resource_group}"
               f"/providers/Microsoft.OperationalInsights/workspaces/{c.workspace_name}"
               f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}")
        return await self._req("arm", "GET", url, params={"api-version": settings().sentinel_api_version})

    async def run_kql(self, kql: str, timespan: str | None = None) -> list[dict]:
        """Compatibility entry point for KQL callers."""
        return await self.run_hunting_query(kql, timespan)


def rule_query_window(alert: dict, rule: dict | None = None) -> tuple[str, str]:
    """Timespan ('start/end' ISO-8601) that reproduces the scheduled rule run that fired.
    Uses Sentinel's 'Query Start/End Time UTC'; falls back to the rule's queryPeriod."""
    extra = alert.get("additionalData") or {}
    start, end = parse_ts(extra.get("Query Start Time UTC")), parse_ts(extra.get("Query End Time UTC"))
    if not (start and end):
        end = parse_ts(alert.get("lastActivityDateTime") or alert.get("createdDateTime"))
        period = ((rule or {}).get("properties") or {}).get("queryPeriod", "P1D")
        start = end - _iso_duration(period)
    return iso_utc(start), iso_utc(end)


def _iso_duration(value: str) -> timedelta:
    """Minimal ISO-8601 duration parser for Sentinel rule periods (PT5H, P14D, P1DT2H)."""
    m = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", value or "")
    if not m:
        return timedelta(days=1)
    d, h, mi, s = (int(x or 0) for x in m.groups())
    return timedelta(days=d, hours=h, minutes=mi, seconds=s)
