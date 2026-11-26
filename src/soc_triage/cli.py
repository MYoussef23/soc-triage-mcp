"""Command line runner.

  soc-triage classify  --file alert.json
  soc-triage normalise --file alert.json [--raw] > finding.ocsf.json
  soc-triage triage    --file alert.json [--no-llm] [--own-domain example.invalid] --out output/
  soc-triage triage    --customer example --alert-id sn24370ae7-... --out output/
  soc-triage triage    --customer example --incident-id 24017 --out output/
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .agent.pipeline import render_markdown, triage_alert, triage_incident
from .domain import classify
from .normalise import normalise


def _load(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(out: Path, stem: str, report: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{stem}.report.md").write_text(render_markdown(report), encoding="utf-8")
    (out / f"{stem}.ocsf.json").write_text(json.dumps(report["ocsf_finding"], indent=2), encoding="utf-8")
    (out / f"{stem}.triage.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out / stem}.report.md, .ocsf.json, .triage.json", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="soc-triage")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("classify", "normalise", "triage"):
        p = sub.add_parser(name)
        p.add_argument("--file", help="Graph alerts_v2 JSON (object, list of one, or {'value': [...]})")
        if name == "normalise":
            p.add_argument("--raw", action="store_true", help="include raw_data")
        if name == "triage":
            p.add_argument("--customer")
            p.add_argument("--alert-id")
            p.add_argument("--incident-id")
            p.add_argument("--no-llm", action="store_true")
            p.add_argument("--own-domain", action="append", default=[])
            p.add_argument("--out", default="output")
    a = ap.parse_args(argv)

    if a.cmd == "classify":
        print(json.dumps(classify(_load(a.file)).as_dict(), indent=2))
    elif a.cmd == "normalise":
        print(json.dumps(normalise(_load(a.file), include_raw=a.raw), indent=2))
    else:
        out = Path(a.out)
        kw = {"use_llm": not a.no_llm, "own_domains": tuple(a.own_domain)}
        if a.incident_id:
            r = asyncio.run(triage_incident(a.customer, a.incident_id, **kw))
            for rep in r["alert_reports"]:
                _write(out, f"incident_{a.incident_id}_{rep['alert_id']}", rep)
        else:
            payload = _load(a.file) if a.file else None
            rep = asyncio.run(triage_alert(payload, customer=a.customer, alert_id=a.alert_id, **kw))
            _write(out, f"incident_{rep.get('incident_id') or 'na'}", rep)
    return 0


if __name__ == "__main__":
    sys.exit(main())
