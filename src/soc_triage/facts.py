"""Deterministic facts computed from the alert and event results. These are handed to the agent
so its summaries rest on counted numbers rather than on the model re-reading raw rows."""
from __future__ import annotations

from collections import Counter

from .common import maybe_json, odata_type, unwrap_alert

# Entra sign-in result codes worth naming in a summary (subset; extend as needed)
ENTRA_RESULT = {
    "0": "success", "50126": "invalid username or password", "50053": "account locked (smart lockout)",
    "50055": "password expired", "50057": "account disabled", "50034": "user not found",
    "50074": "strong auth (MFA) required", "50076": "MFA required (location/condition)",
    "50079": "MFA registration required", "500121": "MFA failed/denied", "50158": "external challenge not satisfied",
    "53003": "blocked by Conditional Access", "50173": "fresh auth token needed", "50140": "KMSI interrupt",
    "50125": "password reset interrupt", "530032": "blocked by security defaults", "50199": "CmsiInterrupt",
    "16000": "account selection required", "65001": "consent required", "90095": "admin consent required",
}


def alert_facts(alert_payload) -> dict:
    alert = unwrap_alert(alert_payload)
    extra = alert.get("additionalData") or {}
    ev_types = Counter(odata_type(e) for e in alert.get("evidence") or [])
    users = [e.get("userAccount") or {} for e in alert.get("evidence") or [] if odata_type(e) == "userEvidence"]
    return {
        "title": alert.get("title"),
        "severity": alert.get("severity"),
        "status": alert.get("status"),
        "incident_id": alert.get("incidentId"),
        "categories": alert.get("categories"),
        "alert_mitre_techniques": alert.get("mitreTechniques"),
        "activity_window": {"first": alert.get("firstActivityDateTime"), "last": alert.get("lastActivityDateTime")},
        "created": alert.get("createdDateTime"),
        "evidence_counts": dict(ev_types),
        "users_in_alert": len(users),
        "critical_asset_users": [u.get("userPrincipalName") for u, e in zip(
            users, [e for e in alert.get("evidence") or [] if odata_type(e) == "userEvidence"])
            if "Critical asset" in (e.get("tags") or [])],
        "rule": {"name": extra.get("Analytic Rule Name"), "query_period": extra.get("Query Period"),
                 "trigger": f"{extra.get('Trigger Operator')} {extra.get('Trigger Threshold')}",
                 "result_rows": extra.get("Search Query Results Overall Count"),
                 "data_sources": maybe_json(extra.get("Data Sources"))},
        "system_tags": alert.get("systemTags"),
    }


def event_facts(events: dict | None) -> dict:
    """Roll-ups from the identity drill-downs (other domains report row counts per query)."""
    if not events:
        return {"available": False}
    res = events.get("results") or {}
    out: dict = {"available": True, "row_counts": {k: len(v or []) for k, v in res.items()},
                 "errors": events.get("errors") or {}}
    if "by_signin_type" in res:
        out["signin_type_breakdown"] = [
            {
                "type": row["SignInType"],
                "source_table": row["SourceTable"],
                "scope": "incident_ip" if row["FromIncidentIP"] else "account_match_other_ip",
                "rows": row["Attempts"],
                "failures": row["Failures"],
                "successes": row["Successes"],
            }
            for row in res["by_signin_type"]
        ]
    signins = res.get("signin_events") or []
    by_ip = res.get("by_source_ip") or []
    by_user = res.get("by_user") or []
    if signins or by_ip:
        rc = Counter(str(r.get("ResultType")) for r in signins)
        out["identity"] = {
            "result_types": [{"code": c, "meaning": ENTRA_RESULT.get(c, "see Entra error code reference"), "count": n}
                             for c, n in rc.most_common(10)],
            "source_ips": len(by_ip),
            "users_targeted": len(by_user),
            "max_users_per_ip": max((r.get("Users") or 0 for r in by_ip), default=0),
            "ips_with_successes": [r["IPAddress"] for r in by_ip if (r.get("Successes") or 0) > 0][:20],
            "users_with_successes": [r["UserPrincipalName"] for r in by_user if (r.get("Successes") or 0) > 0][:20],
            "successful_signins_from_incident_ips": len(res.get("success_from_incident_ips") or []),
            "apps": sorted({str(r.get("AppDisplayName")) for r in signins if r.get("AppDisplayName")})[:10],
            "client_apps": Counter(str(r.get("ClientAppUsed")) for r in signins).most_common(5),
            "user_agents": Counter(str(r.get("UserAgent")) for r in signins).most_common(3),
            "countries": Counter(str(r.get("Country")) for r in signins).most_common(5),
            "asns": Counter(str(r.get("AutonomousSystemNumber")) for r in signins).most_common(5),
            "pattern_hint": _spray_hint(by_ip, by_user),
        }
    return out


def _spray_hint(by_ip: list[dict], by_user: list[dict]) -> str:
    """Deterministic shape label: many users per IP -> spray; many attempts on few users -> guessing."""
    if not by_ip or not by_user:
        return "insufficient data"
    users_per_ip = sorted((r.get("Users") or 0) for r in by_ip)
    median_upi = users_per_ip[len(users_per_ip) // 2]
    attempts_per_user = sorted((r.get("Attempts") or 0) for r in by_user)
    median_apu = attempts_per_user[len(attempts_per_user) // 2]
    if len(by_user) >= 5 and median_upi >= 2 and median_apu <= 10:
        return "many accounts, few attempts each, sources shared across accounts (password-spray shape)"
    if len(by_user) <= 3 and median_apu > 10:
        return "few accounts, many attempts each (password-guessing shape)"
    return "mixed / no clear brute-force shape"
