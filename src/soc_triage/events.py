"""Detection query retrieval, rule replay and domain-specific event drill-down (KQL builders are
deterministic; same alert + entities -> same query text)."""
from __future__ import annotations

import json
import re
from difflib import unified_diff
from pathlib import Path
from typing import Awaitable, Callable

from .common import maybe_json, unwrap_alert
from .connectors.azure import AzureClient, HuntingQueryError, rule_query_window

FAILURE_EXCLUDE = '"0", "50125", "50140"'
SIGNIN_OPTIONAL_PROJECTION = "ResultDescription, ClientAppUsed, "
SIGNIN_OPTIONAL_COLUMNS = ("ResultDescription", "ClientAppUsed")
RepairApproval = Callable[[str], Awaitable[bool]]



def rule_id_of(alert: dict) -> str | None:
    extra = alert.get("additionalData") or {}
    ids = maybe_json(extra.get("Analytic Rule Ids")) or []
    return alert.get("alertPolicyId") or (ids[0] if ids else None)


async def get_detection_query(client: AzureClient | None, alert_payload) -> dict:
    """Read the detection query snapshot from the Graph alert, including incident-expanded alerts."""
    alert = unwrap_alert(alert_payload)
    extra = alert.get("additionalData") or {}
    snapshot = extra.get("Query")
    rid = rule_id_of(alert)
    result = {"rule_id": rid, "rule_name": extra.get("Analytic Rule Name"), "source": "alert_snapshot",
              "query": snapshot, "truncated": bool(snapshot and snapshot.rstrip().endswith("...")),
              "trigger": {"operator": extra.get("Trigger Operator"), "threshold": extra.get("Trigger Threshold"),
                          "query_period": extra.get("Query Period")},
              "window": dict(zip(("start", "end"), rule_query_window(alert)))}
    return result


def replay_query(detection: dict) -> str | None:
    """Rule query pinned to the run that fired (query_now = Query End), for Advanced Hunting."""
    q = detection.get("query")
    if not q or detection.get("truncated"):
        return None
    if "set query_now" not in q:
        q = f"set query_now = datetime({detection['window']['end']});\n{q}"
    return q


def _kql_list(values) -> str:
    return "dynamic(" + json.dumps(sorted({v for v in values if v})) + ")"


def drilldown_queries(domain: str, iocs: dict, window: dict, limit: int = 200) -> dict[str, str]:
    """Raw-event and summary KQL for the incident's entities, per domain."""
    start, end = window["start"], window["end"]
    between = f"| where TimeGenerated between (datetime({start}) .. datetime({end}))"
    users = [u["upn"] for u in iocs.get("users", []) if u.get("upn")]
    ips = [i["value"] for i in iocs.get("ips", [])]
    hosts = [h["value"] for h in iocs.get("hosts", [])]
    hashes = [h["value"] for h in iocs.get("hashes", [])]
    q: dict[str, str] = {}

    if domain == "identity":
        base = (f"let upns = {_kql_list(users)};\nlet ips = {_kql_list(ips)};\n"
                "union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs\n"
                f"{between}\n| where UserPrincipalName in~ (upns) or IPAddress in (ips)\n"
                "| extend Loc = todynamic(column_ifexists('LocationDetails', '{}')), "
                "Dev = todynamic(column_ifexists('DeviceDetail', '{}'))\n")
        q["signin_events"] = base + (
            "| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, "
            + SIGNIN_OPTIONAL_PROJECTION + "UserAgent, Country = tostring(Loc.countryOrRegion), "
            "City = tostring(Loc.city), AutonomousSystemNumber, ConditionalAccessStatus, "
            "AuthenticationRequirement, IsInteractive, OS = tostring(Dev.operatingSystem), Type\n"
            f"| order by TimeGenerated asc\n| take {limit}")
        q["by_signin_type"] = base + (
            "| extend SignInType = case("
            "Type =~ 'AADNonInteractiveUserSignInLogs', 'non_interactive', "
            "Type =~ 'SigninLogs' and IsInteractive == true, 'interactive', "
            "Type =~ 'SigninLogs' and IsInteractive == false, 'non_interactive', "
            "'unknown')\n"
            "| extend FromIncidentIP = IPAddress in (ips)\n"
            f"| summarize Attempts = count(), Failures = countif(ResultType !in ({FAILURE_EXCLUDE})), "
            'Successes = countif(ResultType == "0") by SignInType, FromIncidentIP, SourceTable = Type'
        )
        q["by_source_ip"] = base + (
            f"| summarize Attempts = count(), Failures = countif(ResultType !in ({FAILURE_EXCLUDE})), "
            f"Successes = countif(ResultType == \"0\"), Users = dcount(UserPrincipalName), "
            "ResultTypes = make_set(ResultType, 10), Apps = make_set(AppDisplayName, 5), "
            "Countries = make_set(tostring(Loc.countryOrRegion), 5), ASN = take_any(AutonomousSystemNumber), "
            "UserAgents = make_set(UserAgent, 3), First = min(TimeGenerated), Last = max(TimeGenerated) by IPAddress\n"
            "| order by Attempts desc")
        q["by_user"] = base + (
            f"| summarize Attempts = count(), Failures = countif(ResultType !in ({FAILURE_EXCLUDE})), "
            "Successes = countif(ResultType == \"0\"), SourceIPs = dcount(IPAddress), "
            "ResultTypes = make_set(ResultType, 10), LastSuccess = maxif(TimeGenerated, ResultType == \"0\"), "
            "First = min(TimeGenerated), Last = max(TimeGenerated) by UserPrincipalName\n| order by Attempts desc")
        q["success_from_incident_ips"] = base + (
            "| where IPAddress in (ips) and ResultType == \"0\"\n"
            "| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, "
            "AuthenticationRequirement, ConditionalAccessStatus, IsInteractive, Type\n| order by TimeGenerated asc")
    elif domain == "network":
        q["network_events"] = (
            f"let ips = {_kql_list(ips)};\nunion isfuzzy=true CommonSecurityLog, AZFWNetworkRule, AZFWApplicationRule\n"
            f"{between}\n| where SourceIP in (ips) or DestinationIP in (ips)\n"
            "| project TimeGenerated, DeviceVendor, DeviceProduct, SourceIP, SourcePort, DestinationIP, "
            "DestinationPort, Protocol, DeviceAction, Activity, RequestURL\n"
            f"| order by TimeGenerated asc\n| take {limit}")
    elif domain == "endpoint":
        q["process_events"] = (
            f"let hosts = {_kql_list(hosts)};\nlet hashes = {_kql_list(hashes)};\nDeviceProcessEvents\n"
            "| extend TimeGenerated = Timestamp\n"
            f"{between}\n| where DeviceName in~ (hosts) or SHA256 in (hashes)\n"
            "| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, SHA256, "
            "ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine\n"
            f"| order by TimeGenerated asc\n| take {limit}")
    elif domain == "cloud":
        q["control_plane_events"] = (
            f"let upns = {_kql_list(users)};\nlet ips = {_kql_list(ips)};\nAzureActivity\n"
            f"{between}\n| where Caller in~ (upns) or CallerIpAddress in (ips)\n"
            "| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, "
            "ResourceGroup, _ResourceId\n"
            f"| order by TimeGenerated asc\n| take {limit}")
    elif domain == "appsec":
        q["waf_events"] = (
            f"let ips = {_kql_list(ips)};\nunion isfuzzy=true AGWFirewallLogs, AzureDiagnostics\n"
            f"{between}\n| extend ClientIp = coalesce(column_ifexists('ClientIp', ''), column_ifexists('clientIp_s', ''), "
            "column_ifexists('clientIP_s', ''))\n| where ClientIp in (ips)\n"
            "| project TimeGenerated, ClientIp, RequestUri = coalesce(column_ifexists('RequestUri',''), "
            "column_ifexists('requestUri_s','')), RuleId = coalesce(column_ifexists('RuleId',''), "
            "column_ifexists('ruleId_s','')), Action = coalesce(column_ifexists('Action',''), column_ifexists('action_s',''))\n"
            f"| order by TimeGenerated asc\n| take {limit}")
    return q


async def get_incident_events(client: AzureClient, alert_payload, detection: dict, domain: str,
                              iocs: dict, limit: int = 200, *,
                              approve_repair: RepairApproval | None = None) -> dict:
    """Run the rule replay (what the rule saw) and the domain drill-downs (raw events)."""
    alert = unwrap_alert(alert_payload)
    window = detection["window"]
    out: dict = {"window": window, "results": {}, "errors": {}, "queries": {}}
    timespan = f"{window['start']}/{window['end']}"

    rq = replay_query(detection)
    if rq:
        out["queries"]["rule_replay"] = rq
        try:
            out["results"]["rule_replay"] = (await client.run_kql(rq, timespan))[:limit]
        except Exception as exc:
            out["errors"]["rule_replay"] = f"{type(exc).__name__}: {exc}"
    else:
        out["errors"]["rule_replay"] = "full detection query unavailable (truncated snapshot)"

    sys_id = (alert.get("additionalData") or {}).get("SystemAlertId")
    if sys_id and re.fullmatch(r"[0-9a-fA-F-]{36}", sys_id):
        sq = (f'SecurityAlert | where SystemAlertId == "{sys_id}" | take 1 '
              "| project TimeGenerated, AlertName, Entities, ExtendedProperties, Tactics, Techniques")
        out["queries"]["security_alert_record"] = sq
        try:
            out["results"]["security_alert_record"] = await client.run_kql(sq, "P30D")
        except Exception as exc:
            out["errors"]["security_alert_record"] = f"{type(exc).__name__}: {exc}"

    for name, kql in drilldown_queries(domain, iocs, window, limit).items():
        out["queries"][name] = kql
        try:
            out["results"][name] = await client.run_kql(kql, timespan)
        except Exception as exc:
            out["errors"][name] = f"{type(exc).__name__}: {exc}"
            if name == "signin_events" and isinstance(exc, HuntingQueryError) and approve_repair:
                await _repair_signin_projection(client, kql, timespan, exc, approve_repair, out)
    return out


async def _repair_signin_projection(client, kql, timespan, error, approve_repair, out):
    """Retry one optional projection change admitted by the local allowlist."""
    if error.status != 400:
        return
    match = re.search(r"(?:named|expression)\s+['\"]([A-Za-z][A-Za-z0-9_]*)['\"]",
                      error.message)
    if not match or match[1] not in SIGNIN_OPTIONAL_COLUMNS:
        return
    column = match[1]
    repair = {"query": "signin_events", "column": column, "status": "proposed"}
    out.setdefault("repairs", []).append(repair)
    replacement = SIGNIN_OPTIONAL_PROJECTION.replace(
        f"{column}, ", f"{column} = tostring(column_ifexists('{column}', '')), ", 1)
    if kql.count(SIGNIN_OPTIONAL_PROJECTION) != 1:
        repair["status"] = "template_mismatch"
        return
    try:
        if not await approve_repair(column):
            repair["status"] = "declined"
            return
        repaired_query = kql.replace(SIGNIN_OPTIONAL_PROJECTION, replacement, 1)
        out["results"]["signin_events"] = await client.run_kql(repaired_query, timespan)
    except Exception as exc:
        repair["status"] = "failed"
        repair["error"] = f"{type(exc).__name__}: {exc}"
        return
    out["queries"]["signin_events"] = repaired_query
    repair["original_error"] = out["errors"].pop("signin_events")
    repair["status"] = "recovered"
    source_path = "src/soc_triage/events.py"
    try:
        source = Path(__file__).read_text(encoding="utf-8")
    except OSError:
        return
    declaration = f"SIGNIN_OPTIONAL_PROJECTION = {json.dumps(SIGNIN_OPTIONAL_PROJECTION)}"
    if source.count(declaration) == 1:
        updated = source.replace(
            declaration, f"SIGNIN_OPTIONAL_PROJECTION = {json.dumps(replacement)}", 1)
        repair["source_diff"] = "".join(unified_diff(
            source.splitlines(keepends=True), updated.splitlines(keepends=True),
            fromfile=f"a/{source_path}", tofile=f"b/{source_path}"))
