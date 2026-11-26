"""End-to-end pipeline test with fake Azure, VirusTotal, AbuseIPDB and OpenAI clients."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

from soc_triage.agent.pipeline import LLM, render_markdown, triage_alert
from soc_triage.connectors.azure import HuntingQueryError
from soc_triage.events import drilldown_queries, get_incident_events, replay_query
from soc_triage.ioc import classify_ip, extract_iocs, select_osint_targets
from soc_triage.osint import abuse_verdict, combine, vt_verdict

FULL_RULE_QUERY = ('let aadFunc = (tableName:string){ table(tableName) | where AppDisplayName =~ "Azure Portal" };\n'
                   'union isfuzzy=true aadFunc("SigninLogs"), aadFunc("AADNonInteractiveUserSignInLogs")')


class FakeAzure:
    def __init__(self):
        self.queries = []

    async def get_alert_rule(self, rule_id):
        return {"kind": "Scheduled", "properties": {"query": FULL_RULE_QUERY, "displayName": "Failed login attempts to Azure Portal",
                                                    "queryFrequency": "P1D", "queryPeriod": "P7D", "triggerOperator": "GreaterThan",
                                                    "triggerThreshold": 0, "tactics": ["CredentialAccess"]}}

    async def run_kql(self, kql, timespan=None):
        self.queries.append(kql)
        if "by IPAddress" in kql:
            return [{"IPAddress": "2001:db8::1", "Attempts": 14, "Failures": 14, "Successes": 0, "Users": 9},
                    {"IPAddress": "192.0.2.10", "Attempts": 3, "Failures": 3, "Successes": 0, "Users": 2}]
        if "by UserPrincipalName" in kql:
            return [{"UserPrincipalName": "analyst-one@example.invalid", "Attempts": 4, "Failures": 4, "Successes": 0},
                    {"UserPrincipalName": "analyst-two@example.invalid", "Attempts": 3, "Failures": 3, "Successes": 0},
                    {"UserPrincipalName": "analyst-three@example.invalid", "Attempts": 2, "Failures": 2, "Successes": 0},
                    {"UserPrincipalName": "analyst-four@example.invalid", "Attempts": 2, "Failures": 2, "Successes": 0},
                    {"UserPrincipalName": "operator-one@example.invalid", "Attempts": 5, "Failures": 5, "Successes": 0}]
        if "| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType" in kql:
            return [{"TimeGenerated": "2026-11-24T03:00:00Z", "UserPrincipalName": "analyst-one@example.invalid",
                     "IPAddress": "2001:db8::1", "AppDisplayName": "Azure Portal",
                     "ResultType": "50126", "Country": "US", "AutonomousSystemNumber": 400618}]
        return []


class FakeVT:
    async def lookup(self, t, v):
        return {"provider": "virustotal", "type": t, "value": v, "found": True,
                "malicious": 2 if v.startswith("2001:db8:") else 0, "suspicious": 0, "harmless": 60, "undetected": 30,
                "as_owner": "Example VPN LLC" if v.startswith("2001:db8:") else "Microsoft", "country": "US", "tags": []}


class FakeAbuse:
    async def check(self, ip):
        return {"provider": "abuseipdb", "type": "ip", "value": ip, "found": True,
                "abuse_confidence_score": 40 if ip.startswith("2001:db8:") else 0, "total_reports": 12 if ip.startswith("2001:db8:") else 0,
                "isp": "Example VPN LLC", "usage_type": "Data Center/Web Hosting/Transit", "country": "US", "is_tor": False}


class FakeResponses:
    def __init__(self):
        self.calls = []

    async def create(self, **kw):
        self.calls.append(kw)
        name = kw["tool_choice"]["name"]
        out = {
            "osint_summary": {"summary": "Sources are a VPN range with moderate AbuseIPDB reports.",
                              "overall_assessment": "suspicious", "key_findings": ["2001:db8::/32 flagged by 2 VT engines"]},
            "mitre_mapping": {"techniques": [
                {"technique_id": "T1110.003", "tactic": "Credential Access", "confidence": "high", "evidence": "USER_01 and others from one range"},
                {"technique_id": "T9999", "tactic": "Impact", "confidence": "low", "evidence": "made up"}],
                "not_observed": "No successful sign-in, so no T1078."},
            "incident_summary": {"why_triggered": "Failed Azure Portal sign-ins without later success.",
                                 "what_happened": "USER_01 was targeted from a VPN range.", "assessment": "suspicious_needs_investigation",
                                 "assessment_reason": "Spray shape, no success.", "next_steps": ["Review the synthetic source range"]},
        }[name]
        return SimpleNamespace(status="completed", output=[
            SimpleNamespace(type="function_call", name=name, arguments=json.dumps(out))
        ])


def test_verdict_rules():
    assert vt_verdict({"found": True, "malicious": 3}) == "malicious"
    assert vt_verdict({"found": True, "malicious": 1}) == "suspicious"
    assert vt_verdict({"found": True, "malicious": 0, "suspicious": 0}) == "clean"
    assert abuse_verdict({"found": True, "abuse_confidence_score": 80}) == "malicious"
    assert abuse_verdict({"found": True, "abuse_confidence_score": 5, "is_tor": True}) == "suspicious"
    assert combine("clean", "suspicious", "unknown") == "suspicious"


def _fixture_public_ip(address):
    result = classify_ip(address)
    if result and address.startswith(("192.0.2.", "2001:db8:", "3fff:")):
        return {**result, "scope": "public"}
    return result


def test_osint_selection_groups_rotating_ipv6(incident_alert):
    # Exercise public-IP grouping without putting operational IPs in the fixture.
    with patch("soc_triage.ioc.classify_ip", side_effect=_fixture_public_ip):
        plan = select_osint_targets(extract_iocs(incident_alert), budget=25)
    assert plan["stats"]["public_ips"] == 81
    assert plan["stats"]["ip_groups"] == 20          # 81 addresses -> 20 provider ranges
    assert plan["selected"][0]["group"] == "2001:db8::/32" and plan["selected"][0]["group_size"] == 31
    assert len(plan["abuseipdb_ips"]) == 81


def test_replay_query_pins_query_now():
    det = {"query": "SigninLogs | take 1", "truncated": False, "window": {"start": "a", "end": "2026-11-24T21:55:00Z"}}
    assert replay_query(det).startswith("set query_now = datetime(2026-11-24T21:55:00Z);")
    assert replay_query({**det, "truncated": True}) is None


def test_identity_drilldowns_are_deterministic(incident_alert):
    iocs = extract_iocs(incident_alert)
    w = {"start": "2026-11-17T21:55:00Z", "end": "2026-11-24T21:55:00Z"}
    assert drilldown_queries("identity", iocs, w) == drilldown_queries("identity", iocs, w)
    assert set(drilldown_queries("identity", iocs, w)) == {"signin_events", "by_source_ip", "by_user", "success_from_incident_ips", "by_signin_type"}


def test_full_pipeline(incident_alert):
    responses = FakeResponses()
    llm = LLM(model="gpt-4.1-mini", client=SimpleNamespace(responses=responses))
    azure = FakeAzure()
    alert = incident_alert[0]
    alert = {
        **alert,
        "additionalData": {**(alert.get("additionalData") or {}), "Query": FULL_RULE_QUERY},
    }
    with patch("soc_triage.ioc.classify_ip", side_effect=_fixture_public_ip):
        r = asyncio.run(triage_alert(alert, azure=azure, llm=llm, vt=FakeVT(), abuse=FakeAbuse(),
                                     own_domains=("example.invalid",)))

    assert r["detection"]["source"] == "alert_snapshot"
    assert r["detection"]["query"] == FULL_RULE_QUERY
    assert not r["detection"]["truncated"]
    assert any("set query_now" in q for q in azure.queries)          # rule replay ran
    assert r["domain"]["primary_domain"] == "identity"
    assert r["osint"]["overall_verdict"] == "suspicious"
    assert "osint" in r["ocsf_finding"]["metadata"]["profiles"]
    assert r["facts"]["events"]["identity"]["pattern_hint"].startswith("many accounts")

    # pseudonymisation: no real user identifiers reach the model; tokens restored in output
    sent = json.dumps([c["input"] for c in responses.calls])
    assert "analyst-one" not in sent and "Fixture User" not in sent and "USER_" in sent
    assert "analyst-one@example.invalid" in r["agent"]["incident_summary"]["what_happened"]

    # ATT&CK guardrail
    m = r["agent"]["mitre_mapping"]
    assert [t["technique_id"] for t in m["techniques"]] == ["T1110.003"]
    assert m["techniques"][0]["technique_name"] == "Password Spraying"
    assert m["rejected"][0]["technique_id"] == "T9999"

    md = render_markdown(r)
    assert "Why it triggered" in md and "T1110.003" in md and "| agent_mitre_mapping | partial |" in md

def test_signin_repair_retries_once_and_keeps_query_scope():
    class FailingProjection:
        def __init__(self):
            self.calls = []

        async def run_kql(self, kql, timespan):
            self.calls.append((kql, timespan))
            if "| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType," in kql:
                raise HuntingQueryError(
                    400, "BadRequest", "Failed to resolve scalar expression named 'ResultDescription'."
                )
            return []

    approvals = []

    async def approve(column):
        approvals.append(column)
        return True

    window = {"start": "2026-11-25T00:00:00Z", "end": "2026-11-25T01:00:00Z"}
    client = FailingProjection()
    result = asyncio.run(get_incident_events(
        client, {"id": "synthetic"}, {"window": window}, "identity",
        {"users": [{"upn": "demo@example.invalid"}]}, approve_repair=approve,
    ))

    initial, retry = client.calls[:2]
    fallback = "ResultDescription = tostring(column_ifexists('ResultDescription', ''))"
    assert retry == (initial[0].replace("ResultDescription", fallback, 1), initial[1])
    assert len(client.calls) == 6
    assert approvals == ["ResultDescription"]
    assert "signin_events" in result["errors"]
    assert result["repairs"][0]["status"] == "failed"
    assert "source_diff" not in result["repairs"][0]
