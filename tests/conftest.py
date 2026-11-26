import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
FIX = ROOT / "tests" / "fixtures"


def _ev(t, **kw):
    return {"@odata.type": f"#microsoft.graph.security.{t}", "createdDateTime": "2026-11-20T01:00:00Z",
            "verdict": "suspicious", "remediationStatus": "none", "roles": [], "detailedRoles": [], "tags": [], **kw}


def _alert(i, title, desc, category, techniques, evidence, query, product="Microsoft Sentinel", source="microsoftSentinel"):
    return {"id": f"sn-test-{i}", "providerAlertId": f"test-{i}", "incidentId": str(1000 + i), "status": "inProgress",
            "severity": "medium", "classification": None, "determination": None, "serviceSource": source,
            "detectionSource": "scheduledAlerts", "productName": product, "tenantId": "t", "title": title,
            "description": desc, "category": category, "categories": [category], "mitreTechniques": techniques,
            "createdDateTime": "2026-11-20T01:00:00Z", "lastUpdateDateTime": "2026-11-20T01:05:00Z",
            "firstActivityDateTime": "2026-11-20T00:00:00Z", "lastActivityDateTime": "2026-11-20T00:55:00Z",
            "alertPolicyId": f"rule-{i}", "evidence": evidence, "systemTags": [], "comments": [],
            "additionalData": {"Query": query, "Query Start Time UTC": "2026-11-19 01:00:00Z",
                               "Query End Time UTC": "2026-11-20 01:00:00Z", "Analytic Rule Name": title}}


SYNTHETIC = {
    "endpoint": _alert(1, "Suspicious PowerShell encoded command", "Encoded PowerShell launched by Office process",
                       "Execution", ["T1059.001"],
                       [_ev("deviceEvidence", hostName="ws-0142", deviceDnsName="ws-0142.corp.example", mdeDeviceId="abc",
                            osPlatform="Windows11", ipInterfaces=["10.1.2.3"]),
                        _ev("processEvidence", processId=4242, processCommandLine="powershell -enc SQBFAFgA",
                            imageFile={"fileName": "powershell.exe", "sha256": "a" * 64})],
                       "DeviceProcessEvents | where ProcessCommandLine has '-enc' | where InitiatingProcessFileName =~ 'winword.exe'"),
    "network": _alert(2, "Outbound beacon to known C2 over 443", "Periodic outbound connections detected by firewall",
                      "CommandAndControl", ["T1071.001"],
                      [_ev("ipEvidence", ipAddress="192.0.2.25", roles=["destination"]),
                       _ev("ipEvidence", ipAddress="10.0.0.15", roles=["source"])],
                      "CommonSecurityLog | where DestinationPort == 443 | summarize count() by SourceIP, DestinationIP"),
    "cloud": _alert(3, "Mass deletion of Azure resources", "Many resource delete operations in a subscription",
                    "Impact", ["T1485", "T1578"],
                    [_ev("azureResourceEvidence", resourceId="/subscriptions/s/resourceGroups/rg/providers/x/vm1",
                         resourceName="vm1", resourceType="Virtual machine"),
                     _ev("userEvidence", userAccount={"accountName": "ops", "userPrincipalName": "ops@example.com",
                                                      "azureAdUserId": "u1", "displayName": "Ops"})],
                    "AzureActivity | where OperationNameValue endswith 'DELETE' | summarize count() by Caller, ResourceGroup"),
    "appsec": _alert(4, "WAF SQL injection attempts", "Application Gateway WAF matched OWASP SQL injection rules",
                     "InitialAccess", ["T1190"],
                     [_ev("urlEvidence", url="https://shop.example.com/search?q=1'%20OR%201=1"),
                      _ev("ipEvidence", ipAddress="203.0.113.50")],
                     "AGWFirewallLogs | where RuleId startswith '942' | summarize count() by ClientIp, RequestUri"),
}


@pytest.fixture
def incident_alert():
    return json.loads((FIX / "synthetic_identity_alert.json").read_text())


@pytest.fixture
def synthetic():
    return json.loads(json.dumps(SYNTHETIC))
