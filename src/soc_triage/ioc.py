"""Deterministic IOC extraction and OSINT target selection.

Sources: Graph alert evidence (authoritative) plus, optionally, values found in event rows.
Selection for OSINT is budgeted, because incidents like password sprays carry dozens of
rotating IPv6 addresses and the VirusTotal public API allows ~4 requests/minute.
"""
from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict

from .common import odata_type, unwrap_alert

IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.IGNORECASE)
URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)

# Columns whose values are scanned in event rows (avoid scanning free text like descriptions)
EVENT_IP_COLUMNS = {"IPAddress", "SourceIP", "DestinationIP", "CallerIpAddress", "ClientIp", "RemoteIP",
                    "clientIp_s", "IPAddresses", "LocalIP"}
EVENT_HASH_COLUMNS = {"SHA256", "SHA1", "MD5", "InitiatingProcessSHA256"}
EVENT_URL_COLUMNS = {"RequestURL", "RemoteUrl", "Url", "RequestUri", "requestUri_s"}


def classify_ip(value: str) -> dict | None:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    scope = "public" if ip.is_global else (
        "private" if ip.is_private else "loopback" if ip.is_loopback else
        "link_local" if ip.is_link_local else "multicast" if ip.is_multicast else "reserved")
    return {"value": ip.compressed, "version": ip.version, "scope": scope}


def ip_group(ip: str, v4_prefix: int, v6_prefix: int) -> str:
    addr = ipaddress.ip_address(ip)
    prefix = v4_prefix if addr.version == 4 else v6_prefix
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def extract_iocs(alert_payload, events: dict | None = None, *, own_domains: tuple[str, ...] = ()) -> dict:
    """Return {'users','ips','hosts','hashes','urls','domains'} with source attribution.
    `own_domains` (e.g. ('example.invalid',)) are excluded from domain/URL IOCs."""
    alert = unwrap_alert(alert_payload)
    users: OrderedDict = OrderedDict()
    ips: OrderedDict = OrderedDict()
    hosts: OrderedDict = OrderedDict()
    hashes: OrderedDict = OrderedDict()
    urls: OrderedDict = OrderedDict()
    domains: OrderedDict = OrderedDict()

    def add_ip(v: str, src: str):
        c = classify_ip(v)
        if c:
            ips.setdefault(c["value"], {**c, "sources": []})
            if src not in ips[c["value"]]["sources"]:
                ips[c["value"]]["sources"].append(src)

    def add_hash(v: str, src: str):
        v = v.lower()
        algo = {64: "sha256", 40: "sha1", 32: "md5"}.get(len(v))
        if algo:
            hashes.setdefault(v, {"value": v, "algorithm": algo, "sources": []})
            if src not in hashes[v]["sources"]:
                hashes[v]["sources"].append(src)

    def own(host: str) -> bool:
        h = host.lower()
        return any(h == d or h.endswith("." + d) for d in own_domains)

    for ev in alert.get("evidence") or []:
        t = odata_type(ev)
        if t == "userEvidence":
            ua = ev.get("userAccount") or {}
            key = (ua.get("userPrincipalName") or ua.get("accountName") or "").lower()
            if key:
                users[key] = {"upn": ua.get("userPrincipalName"), "account": ua.get("accountName"),
                              "display_name": ua.get("displayName"), "aad_id": ua.get("azureAdUserId"),
                              "sid": ua.get("userSid"), "tags": ev.get("tags") or [], "verdict": ev.get("verdict")}
        elif t == "ipEvidence" and ev.get("ipAddress"):
            add_ip(ev["ipAddress"], "alert_evidence")
        elif t == "deviceEvidence":
            h = ev.get("deviceDnsName") or ev.get("hostName")
            if h:
                hosts[h.lower()] = {"value": h, "mde_id": ev.get("mdeDeviceId"), "sources": ["alert_evidence"]}
            for ip in ev.get("ipInterfaces") or []:
                add_ip(ip, "device_interface")
        elif t in ("fileEvidence", "processEvidence"):
            fd = ev.get("fileDetails") or ev.get("imageFile") or {}
            for k in ("sha256", "sha1", "md5"):
                if fd.get(k):
                    add_hash(fd[k], "alert_evidence")
        elif t == "urlEvidence" and ev.get("url"):
            urls.setdefault(ev["url"], {"value": ev["url"], "sources": ["alert_evidence"]})
        elif t == "analyzedMessageEvidence":
            for u in ev.get("urls") or []:
                urls.setdefault(u, {"value": u, "sources": ["email"]})
            if ev.get("senderIp"):
                add_ip(ev["senderIp"], "email_sender")

    for name, rows in ((events or {}).get("results") or {}).items():
        for row in rows or []:
            for col, val in row.items():
                if val in (None, ""):
                    continue
                sval = val if isinstance(val, str) else str(val)
                if col in EVENT_IP_COLUMNS:
                    for m in IPV4.findall(sval) + IPV6.findall(sval):
                        add_ip(m, f"events:{name}")
                elif col in EVENT_HASH_COLUMNS:
                    for m in SHA256.findall(sval) or SHA1.findall(sval) or MD5.findall(sval):
                        add_hash(m, f"events:{name}")
                elif col in EVENT_URL_COLUMNS:
                    for m in URL.findall(sval):
                        urls.setdefault(m, {"value": m, "sources": [f"events:{name}"]})

    for u in list(urls):
        host = re.sub(r"^https?://", "", u, flags=re.IGNORECASE).split("/")[0].split(":")[0]
        if own(host):
            urls.pop(u)
        elif DOMAIN.fullmatch(host):
            domains.setdefault(host.lower(), {"value": host.lower(), "sources": ["url"]})

    return {"users": list(users.values()), "ips": list(ips.values()), "hosts": list(hosts.values()),
            "hashes": list(hashes.values()), "urls": list(urls.values()), "domains": list(domains.values())}


def select_osint_targets(iocs: dict, budget: int, v4_prefix: int = 32, v6_prefix: int = 32,
                         abuseipdb_budget: int = 100) -> dict:
    """Pick which indicators to send to OSINT, deterministically.

    - Only public IPs. IPs are grouped by prefix (default IPv6 /32, roughly one provider
      allocation); one representative per group (first seen in alert order) goes to
      VirusTotal, and the group size is reported.
    - VirusTotal order: hashes, IP groups (largest first), domains, URLs, until `budget`.
    - AbuseIPDB (IPs only, higher quota): every public IP, group by group, up to
      `abuseipdb_budget`, so per-address reputation inside a rotating range is still seen.
    """
    public = [i for i in iocs.get("ips", []) if i["scope"] == "public"]
    groups: OrderedDict[str, list[str]] = OrderedDict()
    for i in public:
        groups.setdefault(ip_group(i["value"], v4_prefix, v6_prefix), []).append(i["value"])
    ip_groups = sorted(groups.items(), key=lambda kv: (-len(kv[1]), list(groups).index(kv[0])))

    targets: list[dict] = []
    for h in iocs.get("hashes", []):
        targets.append({"type": "hash", "value": h["value"]})
    for prefix, members in ip_groups:
        targets.append({"type": "ip", "value": members[0], "group": prefix, "group_size": len(members)})
    for d in iocs.get("domains", []):
        targets.append({"type": "domain", "value": d["value"]})
    for u in iocs.get("urls", []):
        targets.append({"type": "url", "value": u["value"]})

    selected, skipped = targets[:budget], targets[budget:]
    abuse = [ip for _, members in ip_groups for ip in members][:abuseipdb_budget]
    return {
        "selected": selected,
        "abuseipdb_ips": abuse,
        "skipped": [{"type": t["type"], "value": t["value"], "group": t.get("group")} for t in skipped],
        "stats": {"public_ips": len(public), "ip_groups": len(groups),
                  "non_public_ips": len(iocs.get("ips", [])) - len(public), "budget": budget,
                  "abuseipdb_budget": abuseipdb_budget},
        "groups": {p: m for p, m in ip_groups},
    }
