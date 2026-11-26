"""End-to-end triage agent.

Deterministic steps (code):   fetch alert -> classify domain -> normalise to OCSF -> detection query
                              -> events (rule replay + drill-downs) -> IOCs -> OSINT -> facts
Agent steps (OpenAI):         OSINT summary -> MITRE ATT&CK mapping -> incident summary

Each agent step gets only compact, pre-counted inputs and must answer through a forced tool call
(schemas in prompts.py). ATT&CK IDs returned by the model are validated against the bundled
ATT&CK table; anything invalid is dropped and reported, never shown as a finding.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

from .. import mitre
from ..common import unwrap_alert
from ..config import customer as get_customer, settings
from ..connectors.azure import AzureClient
from ..domain import classify
from ..events import get_detection_query, get_incident_events
from ..facts import alert_facts, event_facts
from ..ioc import extract_iocs
from ..normalise import add_osint, normalise
from ..osint import enrich
from . import prompts
from .pseudonymise import Pseudonymiser

QUERY_CHAR_LIMIT = 8000
REGISTRATION_AUTHORIZATION_GAP = (
    "The replay shows successful same-account security-info registration. "
    "Whether the activity was expected remains unverified."
)


class LLM:
    """Structured LLM output using OpenAI, Anthropic, or Ollama."""

    def __init__(self, model: str | None = None, client: Any = None, *, provider: str | None = None):
        self.provider = (provider or os.environ.get("SOC_TRIAGE_LLM_PROVIDER") or "openai").strip().lower()
        if self.provider == "openai":
            if client is None:
                from openai import AsyncOpenAI

                client = AsyncOpenAI()
            self.model = model or os.environ.get("SOC_TRIAGE_MODEL") or "gpt-4.1-mini"
        elif self.provider == "anthropic":
            self.model = model or os.environ.get("SOC_TRIAGE_ANTHROPIC_MODEL", "").strip()
            if not self.model:
                raise ValueError("Set SOC_TRIAGE_ANTHROPIC_MODEL when using Anthropic")
            if client is None:
                from anthropic import AsyncAnthropic

                client = AsyncAnthropic()
        elif self.provider == "ollama":
            self.model = model or os.environ.get("SOC_TRIAGE_OLLAMA_MODEL") or "gemma4:26b"
            port = int(os.environ.get("SOC_TRIAGE_OLLAMA_PORT", "11434"))
            if not 1 <= port <= 65535:
                raise ValueError("SOC_TRIAGE_OLLAMA_PORT must be between 1 and 65535")
            self.ollama_url = f"http://127.0.0.1:{port}/api/generate"
        else:
            raise ValueError("SOC_TRIAGE_LLM_PROVIDER must be openai, anthropic, or ollama")
        self.client = client

    async def structured(self, tool: dict, task: str, payload: dict, max_tokens: int = 1200) -> dict:
        from jsonschema import validate

        name = tool["name"]
        schema = tool["input_schema"]
        if self.provider == "ollama":
            result = await self._ollama_structured(schema, task, payload, max_tokens)
            validate(instance=result, schema=schema)
            return result

        if self.provider == "anthropic":
            message = await self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=prompts.SYSTEM,
                messages=[{
                    "role": "user",
                    "content": f"{task}\n\n<data>\n{json.dumps(payload, default=str)}\n</data>",
                }],
                tools=[tool],
                tool_choice={"type": "tool", "name": name, "disable_parallel_tool_use": True},
            )
            calls = [block for block in message.content if block.type == "tool_use"]
            if message.stop_reason != "tool_use" or len(calls) != 1 or calls[0].name != name:
                raise RuntimeError(f"{name}: expected one complete Anthropic tool response")
            result = calls[0].input
            validate(instance=result, schema=schema)
            return result

        response = await self.client.responses.create(
            model=self.model,
            max_output_tokens=max_tokens,
            instructions=prompts.SYSTEM,
            input=[
                {"role": "user", "content": f"{task}\n\n<data>\n{json.dumps(payload, default=str)}\n</data>"}
            ],
            tools=[{
                "type": "function",
                "name": name,
                "description": tool["description"],
                "parameters": schema,
                "strict": False,
            }],
            tool_choice={"type": "function", "name": name},
            parallel_tool_calls=False,
            store=False,
        )
        if response.status != "completed":
            raise RuntimeError(f"{name}: OpenAI response status is {response.status}")
        calls = [item for item in response.output if item.type == "function_call"]
        if len(calls) != 1 or calls[0].name != name:
            raise RuntimeError(f"{name}: expected one matching structured output")
        result = json.loads(calls[0].arguments)
        validate(instance=result, schema=schema)
        return result


    async def _ollama_structured(self, schema: dict, task: str, payload: dict, max_tokens: int) -> dict:
        import httpx

        body = {
            "model": self.model,
            "system": prompts.SYSTEM,
            "prompt": f"{task}\n\n<data>\n{json.dumps(payload, default=str)}\n</data>",
            "format": schema,
            "stream": False,
            "think": False,
            "keep_alive": "2m",
            "options": {"temperature": 0, "num_ctx": 4096, "num_predict": max_tokens},
        }
        if self.client is None:
            async with httpx.AsyncClient(timeout=180, trust_env=False) as client:
                response = await client.post(self.ollama_url, json=body)
        else:
            response = await self.client.post(self.ollama_url, json=body)
        response.raise_for_status()
        data = response.json()
        if data.get("done") is not True or data.get("done_reason") == "length":
            raise RuntimeError("Ollama did not complete the structured response")
        return json.loads(data["response"])


@dataclass
class Step:
    name: str
    status: str = "pending"
    seconds: float = 0.0
    detail: str | None = None


@dataclass
class Run:
    steps: list[Step] = field(default_factory=list)

    def step(self, name: str):
        s = Step(name)
        self.steps.append(s)
        return _Timer(s)


class _Timer:
    def __init__(self, s: Step):
        self.s = s

    def __enter__(self):
        self.t = time.monotonic()
        return self.s

    def __exit__(self, exc_type, exc, tb):
        self.s.seconds = round(time.monotonic() - self.t, 2)
        if exc:
            self.s.status, self.s.detail = "error", f"{exc_type.__name__}: {exc}"
            return True  # record and continue; later steps work with what exists
        if self.s.status == "pending":
            self.s.status = "ok"
        return False


def _compact_osint(o: dict) -> dict:
    flagged = [i for i in o.get("indicators", []) if i["verdict"] in ("malicious", "suspicious")]
    def brief(i):
        vt, ab = i.get("virustotal") or {}, i.get("abuseipdb") or {}
        return {"type": i["type"], "value": i["value"], "verdict": i["verdict"], "range": i.get("group"),
                "vt": {k: vt.get(k) for k in ("malicious", "suspicious", "as_owner", "country", "tags")} if vt else None,
                "abuseipdb": {k: ab.get(k) for k in ("abuse_confidence_score", "total_reports", "isp",
                                                     "usage_type", "country", "is_tor")} if ab else None}
    return {"overall_verdict": o.get("overall_verdict"), "verdict_counts": o.get("verdict_counts"),
            "ip_ranges": o.get("ip_groups"), "flagged": [brief(i) for i in flagged[:15]],
            "non_ip_indicators": [brief(i) for i in o.get("indicators", []) if i["type"] != "ip"][:10],
            "lookup_plan": o.get("plan", {}).get("stats"), "errors": o.get("errors")}


def _compact_events(events: dict | None, limit: int = 25) -> dict:
    if not events:
        return {}
    res = events.get("results") or {}
    keep = ("by_source_ip", "by_user", "success_from_incident_ips", "rule_replay")
    return {k: (res.get(k) or [])[:limit] for k in keep if k in res}


def _audit_replay_facts(events: dict | None, limit: int = 10) -> list[dict]:
    """Extract audit-shaped rows from the original rule replay."""
    replay = ((events or {}).get("results") or {}).get("rule_replay") or []
    facts = []
    for row in replay:
        actions = row.get("Actions")
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list) or not row.get("Target") or not row.get("Result"):
            continue
        actions = [action for action in actions if isinstance(action, str) and action.strip()]
        if not actions:
            continue
        initiator = row.get("InitiatingUserPrincipalName")
        target = row["Target"]
        facts.append({
            "source": "rule_replay",
            "actions": actions,
            "start": row.get("Start"),
            "end": row.get("End"),
            "initiator": initiator,
            "target": target,
            "application": row.get("InitiatingAppName"),
            "result": row["Result"],
            "initiator_matches_target": (
                initiator.casefold() == target.casefold()
                if isinstance(initiator, str) and isinstance(target, str) else None
            ),
        })
        if len(facts) == limit:
            break
    return facts


def _registration_summary(audit_replay: list[dict], events: dict) -> str:
    row = audit_replay[0]
    count = len(audit_replay)
    if count == 1:
        timestamp = f" at {row['start']}" if row["start"] else ""
        application = f" through {row['application']}" if row["application"] else ""
        outcome = (
            f"Entra recorded a successful security-info registration for {row['target']}"
            f"{timestamp}{application}. Entra recorded the same account as initiator and target, "
            "consistent with self-service registration."
        )
    else:
        outcome = (
            f"The rule replay returned {count} successful security-info registration rows, "
            "each with the same account recorded as initiator and target."
        )

    results = events.get("results") or {}
    signins = results.get("signin_events")
    if signins is not None:
        source_ips = {row["IPAddress"] for row in signins if row.get("IPAddress")}
        outcome += (
            f" The sign-in sample returned {len(signins)} rows "
            f"with {len(source_ips)} distinct recorded source IPs."
        )

    successes = results.get("success_from_incident_ips")
    if successes is not None:
        outcome += (
            f" The successful sign-in query returned {len(successes)} matching rows "
            "for the IPs it checked during the incident window."
        )
    else:
        outcome += " Successful sign-ins from the queried IPs could not be verified."
    return outcome


def _local_account_signals(users: list[dict]) -> dict[str, dict]:
    signals = {}
    for user in users:
        upn = user.get("upn") or ""
        alias = (user.get("account") or upn).partition("@")[0]
        if not alias:
            continue
        signals[f"ACCOUNT_{len(signals) + 1:02d}"] = {
            "account": upn or alias,
            "alias": alias,
        }
        if len(signals) == 10:
            break
    return signals


def _ground_account_assessments(proposals: list[dict], signals: dict[str, dict]) -> list[dict]:
    choices: dict[str, set[tuple[str, str]]] = {}
    for item in proposals:
        ref = item["account_ref"]
        if ref in signals:
            choices.setdefault(ref, set()).add((item["classification"], item.get("evidence", "").strip()))

    assessments = []
    for ref, facts in signals.items():
        proposed = choices.get(ref, set())
        classification, evidence = next(iter(proposed)) if len(proposed) == 1 else ("unknown", "")
        if classification == "unknown" or not evidence:
            classification = "unknown"
            evidence = "Account type remains unverified."
        assessments.append({
            "account_ref": ref, "account": facts["account"], "classification": classification,
            "evidence": " ".join(evidence.split()), "verified": False,
        })
    return assessments


async def triage_alert(alert_payload: Any = None, *, customer: str | None = None, alert_id: str | None = None,
                       use_llm: bool = True, llm: LLM | None = None, azure: AzureClient | None = None,
                       own_domains: tuple[str, ...] = (), vt=None, abuse=None) -> dict:
    run = Run()
    s = settings()
    if azure is None and customer:
        azure = AzureClient(get_customer(customer))

    # fetching the alert is the one step that must succeed, so it is not wrapped
    t0 = time.monotonic()
    if alert_payload is None:
        if not (azure and alert_id):
            raise ValueError("Provide alert_payload, or customer + alert_id")
        alert_payload = await azure.get_alert(alert_id)
    alert = unwrap_alert(alert_payload)
    run.steps.append(Step("fetch_alert", "ok", round(time.monotonic() - t0, 2), alert.get("id")))

    detection: dict = {}
    with run.step("detection_query") as st:
        detection = await get_detection_query(azure, alert)
        st.detail = f"source={detection['source']} truncated={detection['truncated']}"
        if detection.get("rule_fetch_error"):
            st.status, st.detail = "partial", st.detail + f"; {detection['rule_fetch_error']}"

    full_query = detection.get("query") if detection.get("source") == "analytic_rule" else None
    domain = classify(alert, detection_query=full_query)
    with run.step("classify_domain") as st:
        st.detail = f"{domain.primary} ({domain.confidence})"

    iocs = extract_iocs(alert, own_domains=own_domains)
    events = None

    async def approve_repair(column: str) -> bool:
        nonlocal llm
        llm = llm or LLM()
        result = await llm.structured(
            {
                "name": "review_optional_projection",
                "description": "Decide whether this optional projection may default to an empty string.",
                "input_schema": {
                    "type": "object",
                    "properties": {"approve": {"type": "boolean"}},
                    "required": ["approve"],
                    "additionalProperties": False,
                },
            },
            "Review the proposed fallback. Approve only if this field can be absent without "
            "changing the time window, entity predicates, or interpretation of the required results.",
            {"tables": ["SigninLogs", "AADNonInteractiveUserSignInLogs"],
             "column": column, "failure": "optional projection column unavailable",
             "proposed_default": "", "usage": "optional display field only"},
        )
        return result["approve"]

    with run.step("incident_events") as st:
        if azure and detection.get("window") and domain.primary != "unknown":
            events = await get_incident_events(
                azure, alert, detection, domain.primary, iocs, s.max_event_rows,
                approve_repair=approve_repair if use_llm else None,
            )
            iocs = extract_iocs(alert, events, own_domains=own_domains)
            if events.get("errors"):
                st.status, st.detail = "partial", "; ".join(f"{k}: {v}" for k, v in events["errors"].items())
        else:
            st.status, st.detail = "skipped", "no customer/workspace configured"

    with run.step("extract_iocs") as st:
        st.detail = ", ".join(f"{k}={len(v)}" for k, v in iocs.items())

    osint: dict = {}
    with run.step("osint") as st:
        osint = await enrich(iocs, vt=vt, abuse=abuse)
        st.detail = f"overall={osint['overall_verdict']} counts={osint['verdict_counts']}"
        if osint["errors"]:
            st.status = "partial"

    finding = normalise(alert, domain=domain, detection_query=full_query)
    finding = add_osint(finding, osint.get("ocsf_osint", []))
    with run.step("normalise_ocsf") as st:
        st.detail = f"class_uid={finding['class_uid']} evidences={len(finding.get('evidences', []))}"

    facts = {"alert": alert_facts(alert), "events": event_facts(events), "domain": domain.as_dict()}

    audit_replay = _audit_replay_facts(events)
    facts["audit_replay"] = audit_replay
    replay_rows = ((events or {}).get("results") or {}).get("rule_replay") or []
    registration_review_required = bool(audit_replay) and len(audit_replay) == len(replay_rows) and all(
        row["initiator_matches_target"] is True
        and str(row["result"]).strip().casefold() == "success"
        and {action.strip().casefold() for action in row["actions"]} == {"user registered security info"}
        for row in audit_replay
    )
    if registration_review_required:
        facts["registration_authorization"] = "unverified"

    agent: dict = {}
    if use_llm:
        llm = llm or LLM()
        p = Pseudonymiser()
        if s.llm_pseudonymise:
            users = list(iocs["users"])
            registered = {u["upn"].casefold() for u in users if u.get("upn")}
            for row in audit_replay:
                for identity in (row["initiator"], row["target"]):
                    if isinstance(identity, str) and identity and identity.casefold() not in registered:
                        users.append({"upn": identity})
                        registered.add(identity.casefold())
            p.register_users(users)
            p.register_hosts(iocs["hosts"])

        osint_in = _compact_osint(osint)
        with run.step("agent_osint_summary"):
            agent["osint_summary"] = p.restore(await llm.structured(
                prompts.OSINT_SUMMARY, prompts.OSINT_TASK, p.apply(osint_in)))

        query_text = (detection.get("query") or "")[:QUERY_CHAR_LIMIT]
        mitre_in = {"incident": facts["alert"], "domain": domain.primary,
                    "detection": {"rule": detection.get("rule_name"), "query": query_text,
                                  "query_truncated": detection.get("truncated"), "trigger": detection.get("trigger")},
                    "event_facts": facts["events"], "audit_replay": audit_replay,
                    "events_sample": _compact_events(events),
                    "event_query_failures": sorted((events or {}).get("errors", {})),
                    "event_queries_completed": sorted((events or {}).get("results", {})),
                    "osint_summary": agent.get("osint_summary")}
        if audit_replay:
            mitre_in["events_sample"].pop("rule_replay", None)

        with run.step("agent_mitre_mapping") as st:
            if registration_review_required:
                raw = {"techniques": [], "not_observed": REGISTRATION_AUTHORIZATION_GAP}
                st.status = "skipped"
                st.detail = "Same-account registration only; no confirmed ATT&CK mapping"
            else:
                raw = await llm.structured(prompts.MITRE_MAPPING, prompts.MITRE_TASK, p.apply(mitre_in))
            valid, rejected = mitre.validate_mapping(raw.get("techniques", []))
            mapping = {"techniques": valid, "not_observed": raw.get("not_observed"),
                       "rejected": rejected, "attack_version": mitre.attack_version()}
            if registration_review_required and valid:
                mapping["techniques"] = []
                mapping["candidates"] = [
                    {**item, "confidence": "low", "reason": REGISTRATION_AUTHORIZATION_GAP}
                    for item in valid
                ]
                mapping["not_observed"] = REGISTRATION_AUTHORIZATION_GAP
            agent["mitre_mapping"] = p.restore(mapping)
            if rejected:
                st.status, st.detail = "partial", f"{len(rejected)} invalid technique(s) dropped"

        summary_in = {**mitre_in, "mitre_mapping": [
            {k: t[k] for k in ("technique_id", "technique_name", "tactic_name", "confidence", "evidence")}
            for t in agent.get("mitre_mapping", {}).get("techniques", [])]}
        summary_in.pop("events_sample", None)
        if registration_review_required:
            summary_in["registration_authorization"] = "unverified"
        summary_in["detection"]["query"] = query_text[:4000]
        # Explicit opt-in applies only to the loopback Ollama adapter.
        account_signals = {}
        if (getattr(llm, "provider", None) == "ollama"
                and os.environ.get("SOC_TRIAGE_LOCAL_ACCOUNT_INFERENCE", "").strip().lower() == "true"):
            account_signals = _local_account_signals(iocs["users"])
        model_payload = p.apply(summary_in)
        if account_signals:
            # Add only the alias after standard pseudonymisation. Do not send the UPN or display name here.
            model_payload["account_signals"] = [
                {"account_ref": ref, "alias": signal["alias"]}
                for ref, signal in account_signals.items()
            ]
        with run.step("agent_incident_summary"):
            agent["incident_summary"] = p.restore(await llm.structured(
                prompts.INCIDENT_SUMMARY, prompts.SUMMARY_TASK, model_payload))
            summary = agent["incident_summary"]
            proposals = summary.pop("account_assessments", [])
            if account_signals:
                summary["account_assessments"] = _ground_account_assessments(proposals, account_signals)
            if registration_review_required:
                summary["why_triggered"] = (
                    "The detection rule matched successful "
                    "security-info registration in the Entra audit logs."
                )
                summary["what_happened"] = _registration_summary(audit_replay, events or {})
                if summary["assessment"] == "likely_benign":
                    summary["assessment"] = "insufficient_data"
                if summary["assessment"] in ("suspicious_needs_investigation", "insufficient_data"):
                    summary["assessment_reason"] = (
                        "Entra recorded the same account as initiator and target. Whether the "
                        "account owner performed the registration and whether it was expected "
                        "remain unverified."
                    )

    return {
        "alert_id": alert.get("id"),
        "incident_id": alert.get("incidentId"),
        "title": alert.get("title"),
        "domain": domain.as_dict(),
        "ocsf_finding": finding,
        "detection": detection,
        "events": events,
        "iocs": iocs,
        "osint": osint,
        "facts": facts,
        "agent": agent,
        "steps": [vars(x) for x in run.steps],
    }


async def triage_incident(customer: str, incident_id: str, max_alerts: int = 5, **kw) -> dict:
    azure = AzureClient(get_customer(customer))
    inc = await azure.get_incident(incident_id)
    reports = [await triage_alert(a, customer=customer, azure=azure, **kw)
               for a in (inc.get("alerts") or [])[:max_alerts]]
    return {"incident_id": incident_id, "incident_title": inc.get("displayName"),
            "incident_severity": inc.get("severity"), "incident_url": inc.get("incidentWebUrl"),
            "alerts_total": len(inc.get("alerts") or []), "alert_reports": reports}


def render_markdown(r: dict) -> str:
    a, d = r.get("agent") or {}, r["domain"]
    lines = [f"# Incident {r.get('incident_id')} — {r.get('title')}", "",
             f"**Domain:** {d['primary_domain']} ({d['confidence']})"
             + (f", secondary: {', '.join(d.get('secondary_domains') or [])}" if d.get("secondary_domains") else ""), ""]
    if s := a.get("incident_summary"):
        lines += ["## Summary", f"**Why it triggered:** {s['why_triggered']}", "",
                  f"**What happened:** {s['what_happened']}", "",
                  f"**Assessment:** {s['assessment'].replace('_', ' ')} — {s.get('assessment_reason', '')}", ""]
        if s.get("account_assessments"):
            lines += ["**Account assessments (unverified)**"]
            for item in s["account_assessments"]:
                name = " ".join(item["account"].split())
                label = item["classification"].replace("_", " ")
                lines += [f"- {name}: {label}. {item['evidence']}"]
            lines.append("")
        if s.get("next_steps"):
            lines += ["**Next steps:**"] + [f"{i}. {x}" for i, x in enumerate(s["next_steps"], 1)] + [""]
    if (r.get("facts") or {}).get("registration_authorization") == "unverified":
        lines += [f"**Authorisation:** {REGISTRATION_AUTHORIZATION_GAP}", ""]
    if o := a.get("osint_summary"):
        lines += ["## OSINT", o["summary"], ""] + [f"- {k}" for k in o.get("key_findings", [])] + [""]
        if o.get("gaps"):
            lines += [f"_Gaps: {o['gaps']}_", ""]
    if m := a.get("mitre_mapping"):
        lines += ["## MITRE ATT&CK", "| Technique | Tactic | Confidence | Evidence |", "|---|---|---|---|"]
        lines += [f"| [{t['technique_id']}]({t['src_url']}) {t['technique_name']} | {t['tactic_name']} | "
                  f"{t['confidence']} | {t['evidence']} |" for t in m["techniques"]]
        if m.get("candidates"):
            lines += ["", "**Unconfirmed ATT&CK candidates**"]
            lines += [f"- {t['technique_id']} {t['technique_name']}" for t in m["candidates"]]
        if m.get("not_observed"):
            lines += ["", f"_Not observed: {m['not_observed']}_"]
        lines.append("")
    breakdown = (r.get("facts") or {}).get("events", {}).get("signin_type_breakdown")
    if breakdown is not None:
        lines += ["## Sign-in type",
                  "| Type | Source table | Scope | Rows | Failures | Successes |",
                  "|---|---|---|---|---|---|"]
        if not breakdown:
            lines += ["| No matching rows | | | 0 | 0 | 0 |"]
        for row in breakdown:
            scope = "Incident IP" if row["scope"] == "incident_ip" else "Account match, other IP"
            lines += [f"| {row['type']} | {row['source_table']} | {scope} | "
                      f"{row['rows']} | {row['failures']} | {row['successes']} |"]
        lines += ["", "Non-interactive sign-ins can include background token refresh. "
                  "Sign-in type alone leaves the specific authentication flow unverified.", ""]
    lines += ["## Pipeline", "| Step | Status | Detail |", "|---|---|---|"]
    lines += [f"| {s['name']} | {s['status']} | {(s.get('detail') or '').replace('|', '/')[:160]} |" for s in r["steps"]]
    return "\n".join(lines) + "\n"
