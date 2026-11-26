"""MITRE ATT&CK lookups backed by the bundled table (scripts/build_attack_table.py refreshes it).

Used deterministically by the normaliser (alert techniques -> OCSF attacks) and as a guardrail
on the agent's MITRE mapping (any technique ID not in ATT&CK is rejected, never shown).
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources

TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")

# Graph security alert `category` / `categories` values -> ATT&CK tactic IDs.
# Non-tactic categories (Malware, Ransomware, SuspiciousActivity, Exploit, ...) map to nothing.
GRAPH_CATEGORY_TO_TACTIC = {
    "reconnaissance": "TA0043",
    "resourcedevelopment": "TA0042",
    "initialaccess": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilegeescalation": "TA0004",
    "defenseevasion": "TA0005",   # renamed "Stealth" in ATT&CK v19+, same ID
    "stealth": "TA0005",
    "defenseimpairment": "TA0112",
    "credentialaccess": "TA0006",
    "discovery": "TA0007",
    "lateralmovement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "commandandcontrol": "TA0011",
    "impact": "TA0040",
}


@lru_cache(maxsize=1)
def attack_table() -> dict:
    data = resources.files("soc_triage.data").joinpath("attack_enterprise.json").read_text("utf-8")
    return json.loads(data)


def attack_version() -> str:
    return attack_table()["attack_version"]


def technique(tid: str) -> dict | None:
    return attack_table()["techniques"].get(tid.strip().upper())


def tactic(taid: str) -> dict | None:
    return attack_table()["tactics"].get(taid.strip().upper())


def tactics_for_categories(categories: list[str]) -> list[str]:
    out = []
    for c in categories or []:
        t = GRAPH_CATEGORY_TO_TACTIC.get(re.sub(r"[^a-z]", "", (c or "").lower()))
        if t and t not in out:
            out.append(t)
    return out


def tactic_uid_from_name(name: str) -> str | None:
    """Accept 'TA0006', 'Credential Access', 'credential-access' or 'CredentialAccess'."""
    if not name:
        return None
    n = name.strip()
    if tactic(n):
        return n.upper()
    key = re.sub(r"[^a-z]", "", n.lower())
    if key in GRAPH_CATEGORY_TO_TACTIC:
        return GRAPH_CATEGORY_TO_TACTIC[key]
    for uid, t in attack_table()["tactics"].items():
        if re.sub(r"[^a-z]", "", t["name"].lower()) == key:
            return uid
    return None


def to_ocsf_attack(tid: str, preferred_tactics: list[str] | None = None) -> dict | None:
    """Build an OCSF `attack` object. When a technique belongs to several tactics, the tactic that
    matches the alert's category wins; otherwise all tactics are listed in `tactics`."""
    tid = tid.strip().upper()
    if not TECHNIQUE_ID.match(tid):
        return None
    t = technique(tid)
    if not t:
        return None
    obj: dict = {"version": attack_version()}
    if "." in tid:
        parent_id = tid.split(".")[0]
        parent = technique(parent_id) or {}
        obj["technique"] = {"uid": parent_id, "name": parent.get("name"), "src_url": parent.get("src_url")}
        obj["sub_technique"] = {"uid": tid, "name": t["name"], "src_url": t["src_url"]}
    else:
        obj["technique"] = {"uid": tid, "name": t["name"], "src_url": t["src_url"]}

    candidates = t["tactics"]
    chosen = [x for x in (preferred_tactics or []) if x in candidates] or candidates
    as_objs = [{"uid": x, "name": tactic(x)["name"], "src_url": tactic(x)["src_url"]} for x in chosen]
    if len(as_objs) == 1:
        obj["tactic"] = as_objs[0]
    elif as_objs:
        obj["tactics"] = as_objs
    return obj


def validate_mapping(items: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split agent-proposed mappings into (valid, rejected). Valid entries get the canonical name
    and URL from ATT&CK; the tactic must be one the technique actually belongs to."""
    valid, rejected = [], []
    for item in items:
        tid = str(item.get("technique_id", "")).strip().upper()
        t = technique(tid) if TECHNIQUE_ID.match(tid) else None
        if not t:
            rejected.append({**item, "reason": "unknown ATT&CK technique ID"})
            continue
        ta = tactic_uid_from_name(str(item.get("tactic", "")))
        if ta not in t["tactics"]:
            ta_fixed = t["tactics"][0] if len(t["tactics"]) == 1 else None
            if ta_fixed is None:
                rejected.append({**item, "reason": f"tactic not valid for {tid}; expected one of {t['tactics']}"})
                continue
            ta = ta_fixed
        valid.append({**item, "technique_id": tid, "technique_name": t["name"], "tactic_id": ta,
                      "tactic_name": tactic(ta)["name"], "src_url": t["src_url"]})
    return valid, rejected
