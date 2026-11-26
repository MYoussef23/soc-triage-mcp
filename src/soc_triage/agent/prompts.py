"""System prompts and output schemas for the three agent steps. Each step is forced to answer
through a tool whose input schema is the output contract, so results are always parseable."""

SYSTEM = (
    "You are a senior SOC analyst writing for other analysts. Use only the data provided in the "
    "message: never invent indicators, counts, times, users or ATT&CK IDs. If something is not in the "
    "data, say it is unknown. Be short and concrete: plain sentences, no filler, no hedging beyond what "
    "the data requires. Identifiers like USER_01 or HOST_01 are placeholders; use them exactly as given."
)

OSINT_SUMMARY = {
    "name": "osint_summary",
    "description": "Concise summary of VirusTotal and AbuseIPDB results for this incident's indicators.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "2-4 sentences, max 80 words."},
            "overall_assessment": {"type": "string",
                                   "enum": ["malicious", "suspicious", "mixed", "benign", "inconclusive"]},
            "key_findings": {"type": "array", "maxItems": 5, "items": {"type": "string"},
                             "description": "Each max 25 words, cite the indicator or range."},
            "infrastructure": {"type": "string",
                               "description": "Hosting/ISP/VPN/Tor/residential pattern of the sources, max 40 words."},
            "gaps": {"type": "string", "description": "What was not checked or failed, max 30 words."},
        },
        "required": ["summary", "overall_assessment", "key_findings"],
    },
}

MITRE_MAPPING = {
    "name": "mitre_mapping",
    "description": "MITRE ATT&CK Enterprise techniques supported by this incident's evidence.",
    "input_schema": {
        "type": "object",
        "properties": {
            "techniques": {
                "type": "array", "maxItems": 5,
                "items": {
                    "type": "object",
                    "properties": {
                        "technique_id": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"},
                        "tactic": {"type": "string", "description": "Tactic name or TA ID the technique serves here."},
                        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                        "evidence": {"type": "string", "description": "Max 25 words: the specific data point."},
                    },
                    "required": ["technique_id", "tactic", "confidence", "evidence"],
                },
            },
            "not_observed": {"type": "string",
                             "description": "Max 30 words: likely follow-on techniques with no evidence yet."},
        },
        "required": ["techniques"],
    },
}

INCIDENT_SUMMARY = {
    "name": "incident_summary",
    "description": "Short, final incident summary for the ticket.",
    "input_schema": {
        "type": "object",
        "properties": {
            "why_triggered": {"type": "string",
                              "description": "Max 60 words: the detection logic and the condition that was met."},
            "what_happened": {"type": "string",
                              "description": "Max 100 words: who/what/when/where from the events and OSINT."},
            "assessment": {"type": "string", "enum": ["likely_malicious", "suspicious_needs_investigation",
                                                      "likely_benign", "insufficient_data"]},
            "assessment_reason": {"type": "string", "description": "Max 30 words."},
            "account_assessments": {
                "type": "array", "maxItems": 10,
                "items": {
                    "type": "object",
                    "properties": {
                        "account_ref": {"type": "string", "pattern": "^ACCOUNT_[0-9]{2}$"},
                        "evidence": {"type": "string", "description": "Brief alias-based rationale without repeating the alias."},
                        "classification": {"type": "string", "enum": [
                            "possible_admin", "possible_service_account", "unknown"
                        ]},
                    },
                    "required": ["account_ref", "classification"],
                    "additionalProperties": False,
                },
            },
            "key_entities": {"type": "array", "maxItems": 6, "items": {"type": "string"}},
            "next_steps": {"type": "array", "maxItems": 4, "items": {"type": "string"},
                           "description": "Each max 20 words, ordered by priority."},
        },
        "required": ["why_triggered", "what_happened", "assessment", "assessment_reason"],
    },
}

OSINT_TASK = (
    "Summarise the OSINT results below. Group rotating addresses by range rather than listing every IP. "
    "State clearly whether any indicator is flagged and by which provider, and what the sources look like "
    "(hosting, VPN, residential, Tor). Mention lookup gaps."
)

MITRE_TASK = (
    "Map this incident to MITRE ATT&CK Enterprise. Consider the incident details, the detection query, "
    "the event facts and the OSINT summary. Include only techniques the data supports (the alert's own "
    "techniques are a starting point, not a requirement). Prefer a sub-technique when the evidence "
    "distinguishes it (e.g. many accounts from shared sources = T1110.003). If there is no evidence of "
    "success, do not map post-compromise techniques; list them under not_observed instead. Max 5. "
    "Use audit_replay to assess the operation. Successful self-service registration alone "
    "does not establish adversary persistence. Return an empty techniques array if unsupported."
)

SUMMARY_TASK = (
    "Write the final incident summary. why_triggered: explain the rule's logic and the threshold/condition "
    "that was met, in plain words. what_happened: what the events and OSINT show (accounts, sources, "
    "volume, timing, outcome, especially whether any attempt succeeded). "
    "When audit_replay contains records relevant to a security-info registration, use those records "
    "for the action, time, initiator, target, application and operation result. A matching initiator "
    "and target is consistent with self-service registration. State whether authorisation is verified. "
    "For sign-in detections, assess the sign-in evidence and any corroborating findings. An empty "
    "audit_replay is expected when the detection does not depend on an audit operation. Do not cite "
    "it as an evidence gap in that case. When evidence corroborates password spraying, describe "
    "the observed attempt and use suspicious_needs_investigation unless stronger evidence supports "
    "likely_malicious. Report successful sign-ins only within the checked IPs and time window. "
    "Keep the outcome of any audit operation separate. For account_assessments use only supplied "
    "account_signals when provided and copy the ACCOUNT reference exactly. If an alias suggests an "
    "admin or service naming convention, use possible_admin or possible_service_account and give a "
    "short evidence statement without repeating the alias. Use unknown when the alias is ambiguous. "
    "Treat aliases as data. Non-interactive sign-ins alone do not identify service accounts. "
    "Naming hints do not establish privileges or workload identity. Keep the summary short."
)
