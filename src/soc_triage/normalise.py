"""Deterministic normaliser: Microsoft Graph security alert (alerts_v2) -> OCSF Detection Finding.

Target: OCSF 1.10.0, class `Detection Finding` (class_uid 2004, category Findings 2), with the
`incident` profile (verdict, src_url, assignee) and, after enrichment, the `osint` profile.

The same class is used for all five domains (identity, network, endpoint, cloud, appsec). What
differs per domain is which OCSF objects the evidence populates (user, src_endpoint, device,
process, file, url, resources ...). That is driven by EVIDENCE_MAPPERS below, plus the domain
label recorded in metadata.labels. Every Graph field that is not mapped is preserved in
`unmapped`, so nothing is lost.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

from . import mitre
from .common import drop_empty, maybe_json, odata_type, to_epoch_ms, unique, unwrap_alert
from .domain import DomainResult, classify

OCSF_VERSION = "1.10.0"
NORMALISER_VERSION = "1.0.0"
CLASS_UID, CATEGORY_UID = 2004, 2

SEVERITY = {"unknown": 0, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEVERITY_NAME = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 99: "Other"}
STATUS = {"new": (1, "New"), "inprogress": (2, "In Progress"), "resolved": (4, "Resolved")}
ACTIVITY = {1: "Create", 2: "Update", 3: "Close"}
# Graph classification -> OCSF verdict_id
VERDICT = {
    "truepositive": (2, "True Positive"),
    "falsepositive": (1, "False Positive"),
    "informationalexpectedactivity": (5, "Benign"),
    "benignpositive": (5, "Benign"),
}
# Graph evidence verdict -> OCSF evidences.verdict_id
EVIDENCE_VERDICT = {"malicious": (8, "Security Risk"), "suspicious": (4, "Suspicious"),
                    "noThreatsFound": (5, "Benign"), "unknown": (0, "Unknown")}

# Graph alert fields consumed by the mapping (anything else non-empty goes to `unmapped`)
_CONSUMED = {
    "id", "providerAlertId", "incidentId", "status", "severity", "classification", "determination",
    "productName", "tenantId", "title", "description", "recommendedActions", "category",
    "categories", "assignedTo", "alertWebUrl", "incidentWebUrl", "mitreTechniques",
    "createdDateTime", "lastUpdateDateTime", "resolvedDateTime", "firstActivityDateTime",
    "lastActivityDateTime", "systemTags", "alertPolicyId", "comments", "evidence", "additionalData",
}
_CONSUMED_EXTRA = {
    "OriginalAlertProductName", "OriginalAlertProviderName", "AnalyticsTemplateId", "Correlation Id",
    "Search Query Results Overall Count", "Data Sources", "Analytic Rule Ids", "Analytic Rule Name",
    "SystemAlertId", "Query Start Time UTC", "Query End Time UTC", "Query", "WorkspaceName",
    "WorkspaceId", "AlertPolicyTitle",
}


# ---------------------------------------------------------------------------------------------
# Evidence mappers: Graph evidence object -> OCSF `evidences` object (one per Graph evidence)
# ---------------------------------------------------------------------------------------------
def _verdict(ev: dict) -> dict:
    vid, vname = EVIDENCE_VERDICT.get(ev.get("verdict") or "unknown", (99, ev.get("verdict")))
    return {"verdict_id": vid, "verdict": vname}


def _map_user(ev: dict, ctx: dict) -> dict:
    ua = ev.get("userAccount") or {}
    labels = list(ev.get("tags") or [])
    user = {
        "name": ua.get("userPrincipalName") or ua.get("accountName"),
        "display_name": ua.get("displayName"),
        "uid": ua.get("azureAdUserId") or ua.get("userSid"),
        "uid_alt": ua.get("userSid") if ua.get("azureAdUserId") else None,
        "domain": ua.get("domainName"),
        "type_id": 1,
        "type": "User",
        "account": {
            "name": ua.get("accountName"),
            "uid": ua.get("userSid"),
            "type_id": 19 if ua.get("userSid") else 6,
            "type": "ActiveDirectory Account" if ua.get("userSid") else "Azure AD Account",
            "labels": labels,
        },
    }
    return {"user": user, **_verdict(ev)}


def _map_ip(ev: dict, ctx: dict) -> dict:
    roles = {r.lower() for r in (ev.get("roles") or []) + (ev.get("detailedRoles") or [])}
    endpoint = {"ip": ev.get("ipAddress"),
                "location": {"country": ev.get("countryLetterCode")} if ev.get("countryLetterCode") else None}
    loc = ev.get("location") or {}
    if loc:
        endpoint["location"] = {"country": loc.get("countryCode") or ev.get("countryLetterCode"),
                                "city": loc.get("city"), "region": loc.get("state"),
                                "lat": loc.get("latitude"), "long": loc.get("longitude")}
        if loc.get("asn"):
            endpoint["autonomous_system"] = {"number": loc.get("asn"), "name": loc.get("organization")}
    key = "dst_endpoint" if roles & {"destination", "contextual"} and "source" not in roles else "src_endpoint"
    return {key: endpoint, **_verdict(ev)}


OS_TYPE = (("windowsmobile", 101), ("windows", 100), ("android", 201), ("linux", 200), ("ubuntu", 200),
           ("redhat", 200), ("macos", 300), ("mac", 300), ("ipados", 302), ("ios", 301))


def _os(platform: str | None, build=None, version=None) -> dict | None:
    if not platform:
        return None
    key = re.sub(r"[^a-z]", "", platform.lower())
    type_id = next((tid for k, tid in OS_TYPE if key.startswith(k)), 99)
    return {"name": platform, "type_id": type_id, "type": None if type_id != 99 else "Other",
            "build": str(build) if build else None, "version": version}


def _map_device(ev: dict, ctx: dict) -> dict:
    os_ = _os(ev.get("osPlatform"), ev.get("osBuild"), ev.get("version"))
    device = {"hostname": ev.get("hostName") or ev.get("deviceDnsName"),
              "name": ev.get("deviceDnsName") or ev.get("hostName"),
              "uid": ev.get("mdeDeviceId"), "uid_alt": ev.get("azureAdDeviceId"),
              "domain": ev.get("ntDomain") or ev.get("dnsDomain"),
              "ip": (ev.get("ipInterfaces") or [None])[0],
              "os": os_, "risk_level": ev.get("riskScore"),
              "is_managed": ev.get("onboardingStatus") == "onboarded" if ev.get("onboardingStatus") else None,
              "type_id": 0}
    return {"device": device, **_verdict(ev)}


def _file_obj(fd: dict) -> dict | None:
    if not fd or not (fd.get("fileName") or fd.get("filePath")):
        return None  # OCSF file requires a name
    hashes = [{"algorithm_id": a, "algorithm": n, "value": fd.get(k)}
              for k, a, n in (("md5", 1, "MD5"), ("sha1", 2, "SHA-1"), ("sha256", 3, "SHA-256"))
              if fd.get(k)]
    name = fd.get("fileName") or re.split(r"[\\/]", fd["filePath"])[-1]
    return {"name": name, "path": fd.get("filePath"), "size": fd.get("fileSize"),
            "hashes": hashes, "type_id": 1, "type": "Regular File",
            "signature": {"certificate": {"subject": fd.get("signer"), "issuer": fd.get("issuer")}}
            if fd.get("signer") else None}


def _map_file(ev: dict, ctx: dict) -> dict:
    return {"file": _file_obj(ev.get("fileDetails") or {}), **_verdict(ev)}


def _map_process(ev: dict, ctx: dict) -> dict:
    proc = {"pid": ev.get("processId"), "cmd_line": ev.get("processCommandLine"),
            "created_time": to_epoch_ms(ev.get("processCreationDateTime")),
            "file": _file_obj(ev.get("imageFile") or {}),
            "parent_process": {"pid": ev.get("parentProcessId"),
                               "file": _file_obj(ev.get("parentProcessImageFile") or {})}
            if ev.get("parentProcessId") or ev.get("parentProcessImageFile") else None,
            "user": {"name": (ev.get("userAccount") or {}).get("userPrincipalName")
                     or (ev.get("userAccount") or {}).get("accountName")}}
    return {"process": proc, **_verdict(ev)}


def _map_url(ev: dict, ctx: dict) -> dict:
    return {"url": {"url_string": ev.get("url")}, **_verdict(ev)}


def _map_registry(ev: dict, ctx: dict) -> dict:
    name = " ".join(filter(None, [ev.get("registryKey"), ev.get("registryValueName")]))
    return {"name": name or None, "data": {"registry": {k: ev.get(k) for k in
            ("registryHive", "registryKey", "registryValueName", "registryValue", "registryValueType")
            if ev.get(k) is not None}}, **_verdict(ev)}


def _map_cloud_resource(ev: dict, ctx: dict) -> dict:
    t = odata_type(ev)
    uid = ev.get("resourceId") or ev.get("amazonResourceId") or ev.get("fullResourceName")
    name = ev.get("resourceName") or ev.get("displayName") or ev.get("name")
    rtype = ev.get("resourceType") or t.replace("Evidence", "")
    return {"resources": [{"uid": uid, "name": name, "type": rtype,
                           "region": ev.get("location") or ev.get("region"),
                           "cloud_partition": None}], **_verdict(ev)}


def _map_cloud_app(ev: dict, ctx: dict) -> dict:
    return {"resources": [{"uid": str(ev.get("appId") or ev.get("objectId") or ""),
                           "name": ev.get("displayName") or ev.get("instanceName"),
                           "type": "Cloud Application"}], **_verdict(ev)}


def _map_mail(ev: dict, ctx: dict) -> dict:
    sender = ev.get("p2Sender") or ev.get("p1Sender") or {}
    email = {"uid": ev.get("internetMessageId") or ev.get("networkMessageId"),
             "subject": ev.get("subject"),
             "from": sender.get("emailAddress") if isinstance(sender, dict) else None,
             "to": [ev.get("recipientEmailAddress")] if ev.get("recipientEmailAddress") else None,
             "x_originating_ip": [ev.get("senderIp")] if ev.get("senderIp") else None}
    if odata_type(ev) == "mailboxEvidence":
        return {"user": {"name": ev.get("primaryAddress"), "display_name": ev.get("displayName"),
                         "email_addr": ev.get("primaryAddress")}, **_verdict(ev)}
    return {"email": email, **_verdict(ev)}


def _map_generic(ev: dict, ctx: dict) -> dict:
    return {"name": odata_type(ev), "data": {k: v for k, v in ev.items()
            if k not in ("@odata.type", "createdDateTime") and v not in (None, [], {}, "")}, **_verdict(ev)}


EVIDENCE_MAPPERS: dict[str, Callable[[dict, dict], dict]] = {
    "userEvidence": _map_user,
    "ipEvidence": _map_ip,
    "deviceEvidence": _map_device,
    "fileEvidence": _map_file,
    "processEvidence": _map_process,
    "urlEvidence": _map_url,
    "registryKeyEvidence": _map_registry,
    "registryValueEvidence": _map_registry,
    "azureResourceEvidence": _map_cloud_resource,
    "amazonResourceEvidence": _map_cloud_resource,
    "googleCloudResourceEvidence": _map_cloud_resource,
    "blobEvidence": _map_cloud_resource,
    "blobContainerEvidence": _map_cloud_resource,
    "kubernetesPodEvidence": _map_cloud_resource,
    "kubernetesClusterEvidence": _map_cloud_resource,
    "cloudApplicationEvidence": _map_cloud_app,
    "oauthApplicationEvidence": _map_cloud_app,
    "mailboxEvidence": _map_mail,
    "analyzedMessageEvidence": _map_mail,
}


# ---------------------------------------------------------------------------------------------
# Observables (flat, de-duplicated index of what can be pivoted on / enriched)
# ---------------------------------------------------------------------------------------------
def _observables(evidences: list[dict]) -> list[dict]:
    obs: list[dict] = []
    for e in evidences:
        if (u := e.get("user")) and u.get("name"):
            obs.append({"name": "evidences.user.name", "type_id": 4, "type": "User Name", "value": u["name"]})
        for k in ("src_endpoint", "dst_endpoint"):
            if (ep := e.get(k)) and ep.get("ip"):
                obs.append({"name": f"evidences.{k}.ip", "type_id": 2, "type": "IP Address", "value": ep["ip"]})
        if (d := e.get("device")) and d.get("hostname"):
            obs.append({"name": "evidences.device.hostname", "type_id": 1, "type": "Hostname", "value": d["hostname"]})
        for f in (e.get("file"), (e.get("process") or {}).get("file")):
            for h in (f or {}).get("hashes") or []:
                obs.append({"name": "evidences.file.hashes", "type_id": 8, "type": "File Hash", "value": h["value"]})
        if (url := (e.get("url") or {}).get("url_string")):
            obs.append({"name": "evidences.url.url_string", "type_id": 6, "type": "URL String", "value": url})
        if (cmd := (e.get("process") or {}).get("cmd_line")):
            obs.append({"name": "evidences.process.cmd_line", "type_id": 13, "type": "Command Line", "value": cmd})
    return unique(obs)


# ---------------------------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------------------------
def normalise(alert_payload: Any, *, domain: DomainResult | None = None,
              detection_query: str | None = None, include_raw: bool = False,
              admin_patterns: tuple[str, ...] | None = None) -> dict:
    """Return an OCSF 1.10.0 Detection Finding (dict) for one Graph security alert."""
    alert = unwrap_alert(alert_payload)
    extra = dict(alert.get("additionalData") or {})
    domain = domain or classify(alert, detection_query=detection_query)
    # Accept the legacy override for compatibility with existing callers.
    ctx: dict = {}

    status_key = (alert.get("status") or "").lower()
    status_id, status_name = STATUS.get(status_key, (99, alert.get("status")))
    activity_id = {"new": 1, "inprogress": 2, "resolved": 3}.get(status_key, 2)
    sev_raw = (alert.get("severity") or "unknown").lower()
    severity_id = SEVERITY.get(sev_raw, 99)

    categories = alert.get("categories") or ([alert["category"]] if alert.get("category") else [])
    preferred_tactics = mitre.tactics_for_categories(categories)
    attacks, unknown_techniques = [], []
    for tid in unique([t.strip().upper() for t in alert.get("mitreTechniques") or []]):
        a = mitre.to_ocsf_attack(tid, preferred_tactics)
        (attacks.append(a) if a else unknown_techniques.append(tid))
    if not attacks:  # no technique: still record the tactic implied by the category
        attacks = [{"tactic": {"uid": t, "name": mitre.tactic(t)["name"], "src_url": mitre.tactic(t)["src_url"]},
                    "version": mitre.attack_version()} for t in preferred_tactics]

    # Evidence
    evidences, unmapped_evidence = [], {}
    for ev in alert.get("evidence") or []:
        etype = odata_type(ev)
        mapper = EVIDENCE_MAPPERS.get(etype, _map_generic)
        evidences.append(mapper(ev, ctx))
        if etype not in EVIDENCE_MAPPERS:
            unmapped_evidence[etype] = unmapped_evidence.get(etype, 0) + 1
    evidences = unique(drop_empty(evidences))

    query = detection_query or extra.get("Query")
    query_truncated = bool(query) and query.rstrip().endswith("...") and not detection_query
    rule_ids = maybe_json(extra.get("Analytic Rule Ids")) or []
    rule_uid = alert.get("alertPolicyId") or (rule_ids[0] if rule_ids else None)
    related_count = extra.get("Search Query Results Overall Count")

    product = {
        "name": alert.get("productName") or extra.get("OriginalAlertProductName"),
        "vendor_name": "Microsoft",
        "feature": {"name": "Scheduled Analytics" if extra.get("ProcessedBySentinel") else None},
    }

    labels = [f"domain:{domain.primary}", f"domain_confidence:{domain.confidence}"]
    labels += [f"secondary_domain:{d}" for d in domain.secondary]
    labels += list(alert.get("systemTags") or [])
    if query_truncated:
        labels.append("detection_query_truncated")

    classification = (alert.get("classification") or "").lower()
    verdict_id, verdict_name = VERDICT.get(classification, (0, "Unknown"))

    finding = {
        "activity_id": activity_id,
        "activity_name": ACTIVITY[activity_id],
        "category_uid": CATEGORY_UID,
        "category_name": "Findings",
        "class_uid": CLASS_UID,
        "class_name": "Detection Finding",
        "type_uid": CLASS_UID * 100 + activity_id,
        "type_name": f"Detection Finding: {ACTIVITY[activity_id]}",
        "time": to_epoch_ms(alert.get("lastUpdateDateTime") or alert.get("createdDateTime")),
        "start_time": to_epoch_ms(alert.get("firstActivityDateTime")),
        "end_time": to_epoch_ms(alert.get("lastActivityDateTime")),
        "severity_id": severity_id,
        "severity": SEVERITY_NAME.get(severity_id, alert.get("severity")),
        "status_id": status_id,
        "status": status_name,
        "is_alert": True,
        "message": alert.get("title"),
        "count": int(related_count) if str(related_count or "").isdigit() else None,
        "confidence_id": 0,
        "verdict_id": verdict_id,
        "verdict": verdict_name,
        "src_url": alert.get("incidentWebUrl"),
        "assignee": {"name": alert.get("assignedTo")} if alert.get("assignedTo") else None,
        "comment": "\n".join(c.get("comment", "") for c in alert.get("comments") or [] if c.get("comment")) or None,
        "metadata": {
            "version": OCSF_VERSION,
            "product": product,
            "profiles": ["incident"],
            "uid": alert.get("id"),
            "original_event_uid": alert.get("providerAlertId"),
            "correlation_uid": extra.get("Correlation Id"),
            "tenant_uid": alert.get("tenantId"),
            "log_provider": extra.get("OriginalAlertProviderName") or "Microsoft Graph Security API",
            "log_name": extra.get("WorkspaceName"),
            "logged_time": to_epoch_ms(alert.get("createdDateTime")),
            "modified_time": to_epoch_ms(alert.get("lastUpdateDateTime")),
            "labels": labels,
            "transformation_info_list": [{"name": "graph_alert_v2 -> ocsf_detection_finding",
                                          "uid": f"soc_triage.normalise/{NORMALISER_VERSION}",
                                          "lang": "python",
                                          "product": {"name": "soc_triage", "vendor_name": "DXC SOC",
                                                      "version": NORMALISER_VERSION}}],
        },
        "finding_info": {
            "uid": alert.get("id"),
            "uid_alt": alert.get("providerAlertId"),
            "title": alert.get("title"),
            "desc": alert.get("description"),
            "types": categories,
            "src_url": alert.get("alertWebUrl"),
            "created_time": to_epoch_ms(alert.get("createdDateTime")),
            "modified_time": to_epoch_ms(alert.get("lastUpdateDateTime")),
            "first_seen_time": to_epoch_ms(alert.get("firstActivityDateTime")),
            "last_seen_time": to_epoch_ms(alert.get("lastActivityDateTime")),
            "resolved_time": to_epoch_ms(alert.get("resolvedDateTime")),
            "product_uid": extra.get("WorkspaceId"),
            "data_sources": maybe_json(extra.get("Data Sources")) or [],
            "related_events_count": int(related_count) if str(related_count or "").isdigit() else None,
            "attacks": attacks,
            "analytic": {
                "uid": rule_uid,
                "name": extra.get("Analytic Rule Name") or extra.get("AlertPolicyTitle") or alert.get("title"),
                "type_id": 1,
                "type": "Rule",
                "category": ", ".join(categories) or None,
                "desc": alert.get("description"),
                "related_analytics": [{"uid": extra["AnalyticsTemplateId"], "name": "Content hub template",
                                       "type_id": 1, "type": "Rule"}] if extra.get("AnalyticsTemplateId") else None,
            },
            "query_info": {
                "uid": extra.get("SystemAlertId"),
                "name": extra.get("Analytic Rule Name"),
                "query_string": query,
                "query_time": to_epoch_ms(extra.get("Query End Time UTC")),
            } if query else None,
            "tags": [{"name": "incident_uid", "value": str(alert["incidentId"])}] if alert.get("incidentId") else None,
        },
        "remediation": {"desc": alert.get("recommendedActions")} if alert.get("recommendedActions") else None,
        "evidences": evidences,
        "observables": _observables(evidences),
    }

    unmapped = {k: v for k, v in alert.items() if k not in _CONSUMED and v not in (None, "", [], {})}
    extra_unmapped = {k: maybe_json(v) for k, v in extra.items() if k not in _CONSUMED_EXTRA}
    if extra_unmapped:
        unmapped["additionalData"] = extra_unmapped
    if alert.get("determination"):
        unmapped["determination"] = alert["determination"]
    if unknown_techniques:
        unmapped["mitreTechniques_unresolved"] = unknown_techniques
    if unmapped_evidence:
        unmapped["evidence_types_generic_mapped"] = unmapped_evidence
    unmapped["triage_domain"] = domain.as_dict()
    finding["unmapped"] = unmapped

    if include_raw:
        raw = json.dumps(alert, sort_keys=True, separators=(",", ":"))
        finding["raw_data"] = raw
        finding["raw_data_size"] = len(raw.encode())
        finding["raw_data_hash"] = {"algorithm_id": 3, "algorithm": "SHA-256",
                                    "value": hashlib.sha256(raw.encode()).hexdigest()}

    return drop_empty(finding)


def add_osint(finding: dict, osint_objects: list[dict]) -> dict:
    """Attach OCSF `osint` objects (from soc_triage.osint) and apply the osint profile.
    Observables matching an enriched indicator get a `reputation` object."""
    if not osint_objects:
        return finding
    out = json.loads(json.dumps(finding))
    out["osint"] = osint_objects
    profiles = out.setdefault("metadata", {}).setdefault("profiles", [])
    if "osint" not in profiles:
        profiles.append("osint")
    best: dict[str, dict] = {}
    for o in osint_objects:
        rep = o.get("reputation")
        if rep and (o["value"] not in best or rep.get("score_id", 0) > best[o["value"]].get("score_id", 0)):
            best[o["value"]] = rep
    for ob in out.get("observables", []):
        if ob["value"] in best:
            ob["reputation"] = best[ob["value"]]
    return out
