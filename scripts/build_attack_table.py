"""Build the compact ATT&CK lookup table bundled with soc_triage.

Usage:
    curl -L -o enterprise-attack.json \
      https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    python scripts/build_attack_table.py enterprise-attack.json src/soc_triage/data/attack_enterprise.json
"""
import json
import sys


def main(src: str, dst: str) -> None:
    bundle = json.load(open(src, encoding="utf-8"))
    objs = bundle["objects"]
    version = next(o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection")

    tactics = {}
    for o in objs:
        if o["type"] == "x-mitre-tactic" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            ext = next(r for r in o["external_references"] if r.get("source_name") == "mitre-attack")
            tactics[o["x_mitre_shortname"]] = {"uid": ext["external_id"], "name": o["name"], "src_url": ext["url"]}

    techniques = {}
    for o in objs:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o["external_references"] if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tac = [tactics[p["phase_name"]]["uid"] for p in o.get("kill_chain_phases", [])
               if p.get("kill_chain_name") == "mitre-attack" and p["phase_name"] in tactics]
        techniques[ext["external_id"]] = {"name": o["name"], "tactics": sorted(tac), "src_url": ext["url"]}

    out = {
        "attack_version": version,
        "tactics": {v["uid"]: {"name": v["name"], "shortname": k, "src_url": v["src_url"]} for k, v in tactics.items()},
        "techniques": dict(sorted(techniques.items())),
    }
    json.dump(out, open(dst, "w", encoding="utf-8"), separators=(",", ":"))
    print(f"ATT&CK v{version}: {len(out['tactics'])} tactics, {len(techniques)} techniques -> {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
