"""Deterministic incident-domain classifier.

Domains: identity, network, endpoint, cloud, appsec.

Every signal is a fixed rule with a fixed weight, evaluated against the alert JSON (and,
optionally, the full detection query fetched from the analytic rule). The same input always
produces the same scores, primary domain and reasons. No ML, no LLM.

Signal sources (strongest first):
  1. Data tables referenced by the detection query (KQL)          weight 4 per table
  2. Graph evidence entity types                                  weight 1-3 per distinct type
  3. Product / serviceSource / detectionSource                    weight 3
  4. MITRE techniques on the alert                                weight 2 per technique
  5. Title keywords (2) and description keywords (1)
  6. Query field names (e.g. UserPrincipalName, ResultType)       weight 1 each, capped at 3
  7. Graph alert category                                         weight 1

Tie-break precedence (most specific first): endpoint > identity > cloud > appsec > network.
Network is last because IP addresses appear in almost every alert.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from .common import odata_type, unwrap_alert

DOMAINS = ("identity", "network", "endpoint", "cloud", "appsec")
PRECEDENCE = ("endpoint", "identity", "cloud", "appsec", "network")
CLASSIFIER_VERSION = "1.0.0"

# --- 1. KQL tables -> domain ------------------------------------------------------------------
TABLES: dict[str, tuple[str, ...]] = {
    "identity": (
        "SigninLogs", "AADNonInteractiveUserSignInLogs", "AADServicePrincipalSignInLogs",
        "AADManagedIdentitySignInLogs", "AADProvisioningLogs", "AuditLogs", "AADUserRiskEvents",
        "AADRiskyUsers", "AADRiskyServicePrincipals", "IdentityLogonEvents", "IdentityQueryEvents",
        "IdentityDirectoryEvents", "IdentityInfo", "AADSignInEventsBeta", "EntraIdSignInEvents",
        "Okta_CL", "OktaSSO", "OktaV2_CL", "Duo_CL", "CyberArk_CL",
    ),
    "network": (
        "CommonSecurityLog", "AzureFirewallNetworkRule", "AzureFirewallApplicationRule",
        "AZFWNetworkRule", "AZFWApplicationRule", "AZFWNatRule", "AZFWDnsQuery", "AZFWIdpsSignature",
        "AZFWThreatIntel", "DnsEvents", "ASimDnsActivityLogs", "ASimNetworkSessionLogs",
        "VMConnection", "AzureNetworkAnalytics_CL", "NTANetAnalytics", "NSGFlowLogs",
        "ZscalerNSS", "Fortinet", "PaloAlto", "Corelight", "Zeek", "DeviceNetworkEvents",
    ),
    "endpoint": (
        "DeviceProcessEvents", "DeviceFileEvents", "DeviceRegistryEvents", "DeviceImageLoadEvents",
        "DeviceEvents", "DeviceLogonEvents", "DeviceFileCertificateInfo", "DeviceInfo",
        "SecurityEvent", "WindowsEvent", "Event", "Sysmon", "SysmonEvent",
        "CrowdStrike_CL", "CrowdStrikeDetections", "SentinelOne_CL", "ASimProcessEventLogs",
        "ASimFileEventLogs", "ASimRegistryEventLogs",
    ),
    "cloud": (
        "AzureActivity", "AWSCloudTrail", "AWSGuardDuty", "AWSVPCFlow", "GCPAuditLogs",
        "GoogleCloudSCC", "StorageBlobLogs", "StorageFileLogs", "AzureKeyVault", "CloudAppEvents",
        "OfficeActivity", "MicrosoftGraphActivityLogs", "KubeAudit", "AKSAudit", "AKSAuditAdmin",
        "ContainerLog", "ContainerLogV2", "SecurityRecommendation", "SecurityResources",
    ),
    "appsec": (
        "AGWFirewallLogs", "AGWAccessLogs", "ApplicationGatewayFirewallLog", "ApplicationGatewayAccessLog",
        "FrontDoorWebApplicationFirewallLog", "FrontDoorAccessLog", "AFDWebApplicationFirewallLogs",
        "W3CIISLog", "AppRequests", "AppExceptions", "AppServiceHTTPLogs", "AppServiceAppLogs",
        "ASimWebSessionLogs", "ApiManagementGatewayLogs", "CloudflareV2_CL", "Imperva_CL",
    ),
}
W_TABLE = 4

# --- 2. Graph evidence @odata.type -> (domain, weight) ----------------------------------------
EVIDENCE: dict[str, tuple[tuple[str, int], ...]] = {
    "userEvidence": (("identity", 3),),
    "securityGroupEvidence": (("identity", 2),),
    "hostLogonSessionEvidence": (("identity", 2), ("endpoint", 1)),
    "oauthApplicationEvidence": (("cloud", 2), ("identity", 1)),
    "ipEvidence": (("network", 1),),
    "networkConnectionEvidence": (("network", 3),),
    "dnsEvidence": (("network", 3),),
    "urlEvidence": (("appsec", 1), ("network", 1)),
    "deviceEvidence": (("endpoint", 3),),
    "processEvidence": (("endpoint", 3),),
    "fileEvidence": (("endpoint", 3),),
    "fileHashEvidence": (("endpoint", 2),),
    "registryKeyEvidence": (("endpoint", 3),),
    "registryValueEvidence": (("endpoint", 3),),
    "azureResourceEvidence": (("cloud", 3),),
    "amazonResourceEvidence": (("cloud", 3),),
    "googleCloudResourceEvidence": (("cloud", 3),),
    "cloudApplicationEvidence": (("cloud", 3),),
    "cloudLogonSessionEvidence": (("identity", 2), ("cloud", 1)),
    "cloudLogonRequestEvidence": (("identity", 2), ("cloud", 1)),
    "blobEvidence": (("cloud", 3),),
    "blobContainerEvidence": (("cloud", 3),),
    "containerEvidence": (("cloud", 2), ("endpoint", 1)),
    "containerImageEvidence": (("cloud", 2),),
    "containerRegistryEvidence": (("cloud", 2),),
    "kubernetesClusterEvidence": (("cloud", 3),),
    "kubernetesControllerEvidence": (("cloud", 3),),
    "kubernetesNamespaceEvidence": (("cloud", 3),),
    "kubernetesPodEvidence": (("cloud", 3),),
    "kubernetesSecretEvidence": (("cloud", 3),),
    "kubernetesServiceEvidence": (("cloud", 3),),
    "kubernetesServiceAccountEvidence": (("cloud", 3),),
    # Email entities: M365/SaaS threats -> cloud, with the targeted user -> identity
    "mailboxEvidence": (("cloud", 2), ("identity", 1)),
    "analyzedMessageEvidence": (("cloud", 2), ("identity", 1)),
    "mailClusterEvidence": (("cloud", 2),),
    "submissionMailEvidence": (("cloud", 2),),
}

# --- 3. Product / service source -> (domain, weight) ------------------------------------------
PRODUCTS: dict[str, tuple[tuple[str, int], ...]] = {
    "azureadidentityprotection": (("identity", 3),),
    "microsoftentraidprotection": (("identity", 3),),
    "entraidprotection": (("identity", 3),),
    "microsoftdefenderforidentity": (("identity", 3),),
    "microsoftdefenderforendpoint": (("endpoint", 3),),
    "microsoftdefenderforcloud": (("cloud", 3),),
    "azuresecuritycenter": (("cloud", 3),),
    "microsoftdefenderforcloudapps": (("cloud", 2), ("identity", 1)),
    "microsoftappgovernance": (("cloud", 2), ("identity", 1)),
    "microsoftdefenderforoffice365": (("cloud", 2), ("identity", 1)),
    "azurewebapplicationfirewall": (("appsec", 3),),
    "azurefirewall": (("network", 3),),
}
W_PRODUCT = 1  # multiplier: weights above already encode strength

# --- 4. MITRE techniques (parent IDs) -> domain -----------------------------------------------
TECHNIQUES: dict[str, tuple[str, ...]] = {
    "identity": ("T1110", "T1078", "T1556", "T1621", "T1550", "T1558", "T1098", "T1136",
                 "T1606", "T1111", "T1539", "T1528", "T1552", "T1087", "T1484", "T1649"),
    "network": ("T1046", "T1071", "T1090", "T1095", "T1571", "T1572", "T1498", "T1048",
                "T1040", "T1557", "T1595", "T1568", "T1573", "T1205"),
    "endpoint": ("T1059", "T1055", "T1547", "T1543", "T1003", "T1486", "T1562", "T1070",
                 "T1105", "T1218", "T1112", "T1053", "T1204", "T1036", "T1569", "T1027",
                 "T1574", "T1021", "T1490", "T1497"),
    "cloud": ("T1530", "T1578", "T1580", "T1538", "T1526", "T1537", "T1535", "T1619",
              "T1648", "T1651", "T1496", "T1525", "T1610", "T1611", "T1613"),
    "appsec": ("T1190", "T1505", "T1189", "T1499", "T1212", "T1210", "T1595.002", "T1059.007"),
}
W_TECHNIQUE = 2

# --- 5. Keywords (title weight 2, description weight 1) ---------------------------------------
KEYWORDS: dict[str, tuple[str, ...]] = {
    "identity": (r"sign[- ]?ins?", r"log ?ons?", r"log ?ins?", r"password", r"\bmfa\b",
                 r"multi[- ]factor", r"brute[- ]?force", r"credential", r"impossible travel",
                 r"password spray", r"account lockout", r"privileged (account|role)", r"\btoken\b",
                 r"entra id", r"active directory", r"kerberos", r"\bntlm\b"),
    "network": (r"firewall", r"port scan", r"beacon", r"\bdns\b", r"\bc2\b",
                r"command and control", r"network traffic", r"outbound connection", r"\bproxy\b",
                r"\btor\b", r"\bddos\b", r"netflow", r"\bvpn\b"),
    "endpoint": (r"process", r"malware", r"ransomware", r"powershell", r"executable",
                 r"registry", r"\bedr\b", r"antivirus", r"\bhost\b", r"\bdevice\b", r"command line",
                 r"\blsass\b", r"scheduled task", r"\bdll\b"),
    "cloud": (r"azure portal", r"subscription", r"\baws\b", r"\bgcp\b", r"\bs3\b",
              r"storage account", r"key ?vault", r"iam role", r"cloudtrail", r"kubernetes",
              r"\baks\b", r"container", r"resource group", r"service principal", r"mailbox",
              r"sharepoint", r"onedrive"),
    "appsec": (r"\bwaf\b", r"sql injection", r"\bsqli\b", r"\bxss\b", r"cross[- ]site",
               r"web ?shell", r"owasp", r"\bhttp\b", r"\bapi\b", r"front door",
               r"application gateway", r"web application", r"path traversal", r"\bssrf\b"),
}
W_TITLE, W_DESC = 2, 1

# --- 6. Query field names -> domain (weight 1 each, cap 3 per domain) -------------------------
FIELDS: dict[str, tuple[str, ...]] = {
    "identity": ("UserPrincipalName", "ResultType", "AppDisplayName", "ConditionalAccessStatus",
                 "AuthenticationRequirement", "MfaDetail", "RiskLevelDuringSignIn", "UserDisplayName"),
    "network": ("DestinationPort", "SourcePort", "DestinationIP", "SourceIP", "Protocol",
                "DeviceAction", "RemotePort", "BytesSent"),
    "endpoint": ("ProcessCommandLine", "InitiatingProcessFileName", "FileName", "SHA256",
                 "RegistryKey", "DeviceName", "ParentProcessName"),
    "cloud": ("OperationNameValue", "ResourceGroup", "SubscriptionId", "eventSource", "awsRegion",
              "ResourceProvider", "Caller"),
    "appsec": ("requestUri_s", "ruleId_s", "httpStatusCode", "RequestUri", "csUriStem",
               "userAgent_s", "clientIp_s", "action_s"),
}
W_FIELD, FIELD_CAP = 1, 3

# --- 7. Graph alert category -> domain --------------------------------------------------------
CATEGORIES: dict[str, str] = {
    "credentialaccess": "identity",
    "execution": "endpoint",
    "persistence": "endpoint",
    "commandandcontrol": "network",
    "exfiltration": "network",
}
W_CATEGORY = 1


@dataclass
class DomainResult:
    primary: str
    confidence: str
    secondary: list[str]
    scores: dict[str, int]
    reasons: dict[str, list[str]] = field(default_factory=dict)
    version: str = CLASSIFIER_VERSION

    def as_dict(self) -> dict:
        return {"primary_domain": self.primary, "confidence": self.confidence,
                "secondary_domains": self.secondary, "scores": self.scores,
                "reasons": self.reasons, "classifier_version": self.version}


def _norm(s: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _word(term: str) -> re.Pattern:
    return re.compile(rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])", re.IGNORECASE)


_TABLE_RX = {d: [(t, _word(t)) for t in ts] for d, ts in TABLES.items()}
_FIELD_RX = {d: [(f, _word(f)) for f in fs] for d, fs in FIELDS.items()}
_KW_RX = {d: [(k, re.compile(k, re.IGNORECASE)) for k in ks] for d, ks in KEYWORDS.items()}


def classify(alert_payload, detection_query: str | None = None) -> DomainResult:
    """Classify a Graph security alert (alerts_v2 shape) into one primary domain.

    `detection_query` is the full analytic-rule query when available (Graph truncates the
    copy in additionalData.Query); it is combined with the truncated copy.
    """
    alert = unwrap_alert(alert_payload)
    scores: dict[str, int] = defaultdict(int)
    reasons: dict[str, list[str]] = defaultdict(list)

    def add(domain: str, weight: int, why: str) -> None:
        scores[domain] += weight
        reasons[domain].append(f"+{weight} {why}")

    extra = alert.get("additionalData") or {}
    query = "\n".join(q for q in (detection_query, extra.get("Query")) if q)
    title = alert.get("title") or ""
    desc = alert.get("description") or ""

    # 1. tables in the query; table names mentioned in the description count at half weight
    for d, rxs in _TABLE_RX.items():
        for name, rx in rxs:
            if query and rx.search(query):
                add(d, W_TABLE, f"query references table {name}")
            elif rx.search(desc):
                add(d, W_TABLE // 2, f"description references table {name}")

    # 2. evidence types (distinct types only, so 80 IPs do not outvote 1 user)
    for etype in sorted({odata_type(e) for e in alert.get("evidence") or []}):
        for d, w in EVIDENCE.get(etype, ()):
            add(d, w, f"evidence type {etype}")

    # 3. product / sources
    for label in (alert.get("serviceSource"), alert.get("detectionSource"), alert.get("productName"),
                  extra.get("OriginalAlertProductName")):
        for d, w in PRODUCTS.get(_norm(label), ()):
            add(d, w * W_PRODUCT, f"source {label}")

    # 4. MITRE techniques (match on parent ID unless a sub-technique is listed explicitly)
    for tid in sorted({t.strip().upper() for t in alert.get("mitreTechniques") or []}):
        parent = tid.split(".")[0]
        for d, ts in TECHNIQUES.items():
            if tid in ts or parent in ts:
                add(d, W_TECHNIQUE, f"MITRE technique {tid}")

    # 5. keywords
    for d, rxs in _KW_RX.items():
        for kw, rx in rxs:
            if rx.search(title):
                add(d, W_TITLE, f"title matches /{kw}/")
            elif rx.search(desc):
                add(d, W_DESC, f"description matches /{kw}/")

    # 6. query field names
    if query:
        for d, rxs in _FIELD_RX.items():
            hits = [f for f, rx in rxs if rx.search(query)][:FIELD_CAP]
            for f in hits:
                add(d, W_FIELD, f"query uses field {f}")

    # 7. category
    for c in sorted({_norm(c) for c in (alert.get("categories") or [alert.get("category")]) if c}):
        if c in CATEGORIES:
            add(CATEGORIES[c], W_CATEGORY, f"category {c}")

    full = {d: scores.get(d, 0) for d in DOMAINS}
    total = sum(full.values())
    if total == 0:
        return DomainResult("unknown", "none", [], full, {})

    primary = max(PRECEDENCE, key=lambda d: (full[d], -PRECEDENCE.index(d)))
    top = full[primary]
    runner_up = max(v for d, v in full.items() if d != primary)
    share = top / total
    if total < 4:
        confidence = "low"
    elif share >= 0.6 and top - runner_up >= 4:
        confidence = "high"
    elif share >= 0.4:
        confidence = "medium"
    else:
        confidence = "low"

    floor = max(3, round(top * 0.25))
    secondary = [d for d in PRECEDENCE if d != primary and full[d] >= floor]
    return DomainResult(primary, confidence, secondary, full,
                        {d: reasons[d] for d in DOMAINS if reasons.get(d)})
