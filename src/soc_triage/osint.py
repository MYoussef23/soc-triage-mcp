"""OSINT orchestration: budgeted lookups, deterministic per-indicator verdicts, OCSF `osint` objects.

Verdict rules (fixed, worst provider wins):
  VirusTotal  malicious >= 3                     -> malicious
              malicious >= 1 or suspicious >= 2  -> suspicious
              found, no detections               -> clean
  AbuseIPDB   confidence >= 75                   -> malicious
              confidence >= 25 or Tor exit       -> suspicious
              otherwise (found)                  -> clean
  Neither provider has data                      -> unknown
"""
from __future__ import annotations

import asyncio
from collections import Counter, defaultdict

from .config import settings
from .connectors.threatintel import AbuseIPDB, Cache, VirusTotal
from .ioc import ip_group, select_osint_targets

RANK = {"unknown": 0, "clean": 1, "suspicious": 2, "malicious": 3}
SCORE_ID = {"unknown": (0, "Unknown"), "clean": (3, "Probably Safe"),
            "suspicious": (7, "Suspicious/Risky"), "malicious": (9, "Probably Malicious")}
OSINT_TYPE = {"ip": (1, "IP Address"), "domain": (2, "Domain"), "hash": (4, "Hash"), "url": (5, "URL")}


def vt_verdict(r: dict | None) -> str:
    if not r or r.get("error") or not r.get("found"):
        return "unknown"
    if r.get("malicious", 0) >= 3:
        return "malicious"
    if r.get("malicious", 0) >= 1 or r.get("suspicious", 0) >= 2:
        return "suspicious"
    return "clean"


def abuse_verdict(r: dict | None) -> str:
    if not r or r.get("error") or not r.get("found"):
        return "unknown"
    score = r.get("abuse_confidence_score") or 0
    if score >= 75:
        return "malicious"
    if score >= 25 or r.get("is_tor"):
        return "suspicious"
    return "clean"


def combine(*verdicts: str) -> str:
    return max(verdicts, key=lambda v: RANK[v]) if verdicts else "unknown"


def to_ocsf_osint(indicator: dict) -> dict:
    """One OCSF `osint` object per indicator (both providers folded into one reputation)."""
    vt, ab = indicator.get("virustotal") or {}, indicator.get("abuseipdb") or {}
    verdict = indicator["verdict"]
    score_id, score_name = SCORE_ID[verdict]
    if ab.get("found"):
        base = float(ab.get("abuse_confidence_score") or 0)
    elif vt.get("found"):
        total = sum(vt.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")) or 1
        base = round(100.0 * vt.get("malicious", 0) / total, 1)
    else:
        base = 0.0
    type_id, type_name = OSINT_TYPE[indicator["type"]]
    labels = list(vt.get("tags") or []) + ([ab["usage_type"]] if ab.get("usage_type") else [])
    if ab.get("is_tor"):
        labels.append("tor")
    comment = []
    if vt.get("found"):
        comment.append(f"VT {vt.get('malicious', 0)} malicious / {vt.get('suspicious', 0)} suspicious")
    if ab.get("found"):
        comment.append(f"AbuseIPDB {ab.get('abuse_confidence_score')}% ({ab.get('total_reports')} reports)")
    obj = {
        "value": indicator["value"], "type_id": type_id, "type": type_name,
        "vendor_name": ", ".join(p for p, r in (("VirusTotal", vt), ("AbuseIPDB", ab)) if r.get("found")) or None,
        "reputation": {"base_score": base, "score_id": score_id, "score": score_name,
                       "provider": "soc_triage (VirusTotal+AbuseIPDB)"},
        "confidence_id": 3 if vt.get("found") and ab.get("found") else 2 if (vt.get("found") or ab.get("found")) else 0,
        "labels": sorted(set(labels)) or None,
        "comment": "; ".join(comment) or None,
        "src_url": vt.get("src_url") or ab.get("src_url"),
    }
    if vt.get("asn") or ab.get("isp"):
        obj["autonomous_system"] = {"number": vt.get("asn"), "name": vt.get("as_owner") or ab.get("isp")}
        obj["autonomous_system"] = {k: v for k, v in obj["autonomous_system"].items() if v is not None}
    if vt.get("country") or ab.get("country"):
        obj["location"] = {"country": vt.get("country") or ab.get("country")}
    return {k: v for k, v in obj.items() if v not in (None, [], {})}


async def enrich(iocs: dict, *, vt: VirusTotal | None = None, abuse: AbuseIPDB | None = None,
                 budget: int | None = None) -> dict:
    """Look up the selected indicators and return verdicts, group roll-ups and OCSF osint objects."""
    s = settings()
    if vt is None and s.vt_api_key:
        vt = VirusTotal(s.vt_api_key, Cache(s.cache_path, s.cache_ttl_hours), s.vt_requests_per_minute)
    if abuse is None and s.abuseipdb_api_key:
        abuse = AbuseIPDB(s.abuseipdb_api_key, Cache(s.cache_path, s.cache_ttl_hours), s.abuseipdb_max_age_days)

    plan = select_osint_targets(iocs, budget or s.osint_budget, s.ipv4_group_prefix, s.ipv6_group_prefix,
                                s.abuseipdb_budget)
    errors: list[str] = []
    if not vt:
        errors.append("VirusTotal not configured (VT_API_KEY)")
    if not abuse:
        errors.append("AbuseIPDB not configured (ABUSEIPDB_API_KEY)")

    async def safe(coro, label):
        try:
            return await coro
        except Exception as exc:
            errors.append(f"{label}: {type(exc).__name__}: {exc}")
            return None

    vt_results: dict[str, dict] = {}
    if vt:
        for t in plan["selected"]:   # sequential: the rate limiter spaces the calls
            vt_results[t["value"]] = await safe(vt.lookup(t["type"], t["value"]), f"vt {t['value']}")
    ab_results: dict[str, dict] = {}
    if abuse:
        rs = await asyncio.gather(*(safe(abuse.check(ip), f"abuseipdb {ip}") for ip in plan["abuseipdb_ips"]))
        ab_results = dict(zip(plan["abuseipdb_ips"], rs))

    indicators: list[dict] = []
    seen = set()
    for t in plan["selected"]:
        v = t["value"]
        seen.add(v)
        ind = {"type": t["type"], "value": v, "group": t.get("group"), "group_size": t.get("group_size"),
               "virustotal": vt_results.get(v), "abuseipdb": ab_results.get(v)}
        ind["verdict"] = combine(vt_verdict(ind["virustotal"]), abuse_verdict(ind["abuseipdb"]))
        indicators.append(ind)
    for ip in plan["abuseipdb_ips"]:
        if ip in seen:
            continue
        ind = {"type": "ip", "value": ip, "group": ip_group(ip, s.ipv4_group_prefix, s.ipv6_group_prefix),
               "virustotal": None, "abuseipdb": ab_results.get(ip)}
        ind["verdict"] = abuse_verdict(ind["abuseipdb"])
        indicators.append(ind)

    groups: dict[str, dict] = defaultdict(lambda: {"checked": 0, "verdicts": Counter(), "max_abuse_score": 0,
                                                    "isps": Counter(), "countries": Counter(), "usage_types": Counter()})
    for ind in indicators:
        if ind["type"] != "ip":
            continue
        g = groups[ind["group"]]
        g["checked"] += 1
        g["verdicts"][ind["verdict"]] += 1
        ab = ind.get("abuseipdb") or {}
        vtr = ind.get("virustotal") or {}
        g["max_abuse_score"] = max(g["max_abuse_score"], ab.get("abuse_confidence_score") or 0)
        for key, val in (("isps", ab.get("isp") or vtr.get("as_owner")), ("countries", ab.get("country") or vtr.get("country")),
                         ("usage_types", ab.get("usage_type"))):
            if val:
                g[key][val] += 1
    group_rollup = []
    for prefix, members in plan["groups"].items():
        g = groups.get(prefix)
        group_rollup.append({
            "prefix": prefix, "addresses_in_incident": len(members), "checked": g["checked"] if g else 0,
            "verdicts": dict(g["verdicts"]) if g else {}, "max_abuse_score": g["max_abuse_score"] if g else None,
            "isp": g["isps"].most_common(1)[0][0] if g and g["isps"] else None,
            "country": g["countries"].most_common(1)[0][0] if g and g["countries"] else None,
            "usage_type": g["usage_types"].most_common(1)[0][0] if g and g["usage_types"] else None,
        })

    counts = Counter(i["verdict"] for i in indicators)
    return {
        "overall_verdict": combine(*(i["verdict"] for i in indicators)) if indicators else "unknown",
        "verdict_counts": dict(counts),
        "plan": {"stats": plan["stats"], "skipped": plan["skipped"]},
        "ip_groups": group_rollup,
        "indicators": indicators,
        "ocsf_osint": [to_ocsf_osint(i) for i in indicators if i["verdict"] != "unknown" or i.get("virustotal")],
        "errors": errors,
    }
