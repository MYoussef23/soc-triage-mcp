# soc-triage-mcp

Read-only SOC triage for Microsoft Sentinel and Defender XDR. The CLI and MCP server retrieve incident evidence, normalise alerts to OCSF, enrich indicators and produce an analyst-reviewed report. Domain classification covers Identity, Network, Endpoint, Cloud Security and Application Security.

## How triage works

1. Fetch the Graph incident and its expanded alerts, or load a Graph alert JSON file.
2. Classify each alert and read its detection query from `additionalData.Query`. Replay a complete snapshot where available. An explicitly truncated snapshot is skipped.
3. Run available replay and drill-down queries through Microsoft Graph Advanced Hunting. Extract indicators, enrich them with configured reputation services, and build the OCSF finding and evidence facts.
4. Use the selected model for OSINT summary, ATT&CK mapping and incident summary where applicable. The analyst owns confirmation, escalation and closure.

The incident triage path uses the Graph alert snapshot for detection query retrieval. Graph permissions and table availability govern query execution. Identity reports distinguish interactive, non-interactive and unknown sign-in type, with separate counts for incident IPs and account matches at other IPs. Non-interactive activity can include background token refresh. The sign-in type alone leaves the authentication flow unverified.

## Install

From the project root in Windows PowerShell:

```powershell
python -m pip install -e ".[agent,dev]"
if (-not (Test-Path -LiteralPath ..env)) {
    Copy-Item -LiteralPath ..env.example -Destination ..env
}
if (-not (Test-Path -LiteralPath .customers.json)) {
    Copy-Item -LiteralPath .customers.example.json -Destination .customers.json
}
```

Configure the tenant ID and app credential variable names in `customers.json`. Set the credential values in the process environment or your protected `.env`. Existing environment variables take precedence over `.env`. Set `SOC_TRIAGE_ENV` and `SOC_TRIAGE_CUSTOMERS` to absolute paths if the launcher runs from another directory.

| Microsoft Graph application permission | Purpose |
|---|---|
| `SecurityAlert.Read.All` | Read alerts |
| `SecurityIncident.Read.All` | Read incidents and expanded alerts |
| `ThreatHunting.Read.All` | Run Advanced Hunting KQL |

Grant admin consent in the customer tenant. Verify that required tables are accessible to the application.

## Configure the model provider

Set one active provider. Keep each provider's model settings in a separate variable.

```dotenv
SOC_TRIAGE_LLM_PROVIDER=ollama

# Ollama over an SSH tunnel
SOC_TRIAGE_OLLAMA_SSH_HOST=<device-hostname-or-ip>
SOC_TRIAGE_OLLAMA_SSH_USER=<ssh-user>
SOC_TRIAGE_OLLAMA_PORT=11435
SOC_TRIAGE_OLLAMA_REMOTE_PORT=11434
SOC_TRIAGE_OLLAMA_MODEL=gemma4:26b

# OpenAI
SOC_TRIAGE_MODEL=gpt-4.1-mini
# OPENAI_API_KEY=<set for OpenAI>

# Anthropic, when the optional Anthropic adapter update is installed
# SOC_TRIAGE_ANTHROPIC_MODEL=<model ID available to the API project>
# ANTHROPIC_API_KEY=<set for Anthropic>
```

Use `ollama`, `openai`, or `anthropic` as the provider value. OpenAI is the code default when the provider is unset. Set only the API key required by the active provider. Restart a running MCP server after configuration changes. `VT_API_KEY` and `ABUSEIPDB_API_KEY` configure the separate OSINT lookups. Selecting Ollama keeps model inference on the Dell. Live Graph and configured OSINT calls still use their respective external services.

### Start the Ollama tunnel

Run in a dedicated PowerShell window and leave it open during triage:

```powershell
$connection = python -c "import json, os; from soc_triage.config import load_dotenv; load_dotenv(); print(json.dumps([os.environ['SOC_TRIAGE_OLLAMA_SSH_HOST'], os.environ['SOC_TRIAGE_OLLAMA_SSH_USER'], int(os.environ['SOC_TRIAGE_OLLAMA_PORT']), int(os.environ['SOC_TRIAGE_OLLAMA_REMOTE_PORT'])]))"
if ($LASTEXITCODE -ne 0) { throw 'Could not load Ollama SSH settings.' }
$dellHost, $sshUser, $localPort, $remotePort = $connection | ConvertFrom-Json
$forward = '127.0.0.1:{0}:127.0.0.1:{1}' -f $localPort, $remotePort
ssh -N -o ExitOnForwardFailure=yes -L $forward "${sshUser}@${dellHost}"
```

## Run triage

```powershell
python -m soc_triage.cli classify --file .alert.json
python -m soc_triage.cli normalise --file .alert.json
python -m soc_triage.cli triage --customer <customer_key> --incident-id 'YOUR_INCIDENT_ID' --own-domain <customer_domain.com>
python -m soc_triage.cli triage --file .synthetic-graph-alert.json --no-llm --out .outputsynthetic
```

Replace the incident ID before running the live command. Triage writes `.report.md`, `.ocsf.json` and `.triage.json` files. Inspect `steps` and `events.errors` for incomplete evidence. `--no-llm` skips model calls. A file-based run without a customer skips Azure retrieval. OSINT can still make lookups when configured and the input contains eligible indicators.

### MCP

Run the server over stdio with `python -m soc_triage.server` or `soc-triage-mcp`. Example host configuration:

```json
{
  "mcpServers": {
    "soc-triage": {
      "command": "soc-triage-mcp",
      "env": {
        "SOC_TRIAGE_ENV": "C:/path/soc-triage-mcp/.env",
        "SOC_TRIAGE_CUSTOMERS": "C:/path/soc-triage-mcp/customers.json"
      }
    }
  }
}
```

Use `triage_incident_prompt` for host-driven triage. Call `triage_alert_full` or `triage_incident_full` for server-side triage with the configured provider. Streamable HTTP is available with `python -m soc_triage.server --http 8765`.

## MCP tools

| Tool | What it does |
|---|---|
| `list_customers`, `list_active_alerts`, `list_active_incidents` | Discovery |
| `get_incident`, `get_alert` | Incident with expanded alerts or an individual Graph alert |
| `classify_incident_domain` | Deterministic domain + scores + fired rules |
| `normalise_to_ocsf` | OCSF 1.10.0 Detection Finding (adds osint profile after enrichment) |
| `get_detection_query` | Query snapshot, trigger metadata and query window from the Graph alert |
| `get_incident_events` | Rule replay (`set query_now` pinned), `SecurityAlert` record, domain drill-downs, event facts |
| `run_kql` | Read-only KQL through Microsoft Graph Advanced Hunting |
| `extract_iocs` | Users, IPs (scoped public/private), hosts, hashes, URLs, domains |
| `osint_virustotal`, `osint_abuseipdb` | Single lookups |
| `osint_enrich_incident` | Budgeted enrichment with range grouping and OCSF osint objects |
| `mitre_lookup`, `validate_mitre_mapping` | ATT&CK v20.1 lookups; rejects invented IDs |
| `triage_alert_full`, `triage_incident_full` | Whole pipeline using the selected server-side model provider |

All tools are read-only against the security stack.

## Domain classification (`domain.py`)

Fixed rules, fixed weights; output includes every rule that fired.

| Signal | Weight | Examples |
|---|---|---|
| Table in detection query | 4 (2 if only in description) | `SigninLogs` → identity, `DeviceProcessEvents` → endpoint, `AzureActivity` → cloud, `AGWFirewallLogs` → appsec, `CommonSecurityLog` → network |
| Evidence type (distinct) | 1–3 | `userEvidence` identity 3, `processEvidence` endpoint 3, `azureResourceEvidence` cloud 3, `ipEvidence` network 1 |
| Product / service source | 1–3 | Defender for Identity → identity, Defender for Endpoint → endpoint |
| Alert MITRE technique | 2 | T1110 → identity, T1190 → appsec, T1071 → network |
| Title / description keyword | 2 / 1 | "sign-in", "brute force" → identity; "WAF", "SQL injection" → appsec |
| Query field names | 1 each, max 3 | `UserPrincipalName`, `ResultType` → identity |
| Graph category | 1 | CredentialAccess → identity |

Primary = highest score; ties break endpoint > identity > cloud > appsec > network. Confidence is
high when the primary has ≥60% of the total and leads by ≥4. Secondary domains are listed when
they reach 25% of the primary (min 3).

## OCSF mapping (`normalise.py`)

All five domains map to **Detection Finding** (`class_uid 2004`, `category_uid 2`) — OCSF's class
for alerts from detection engines. The domain changes which objects the evidence fills, not the class.

| Graph alert | OCSF |
|---|---|
| `status` new / inProgress / resolved | `activity_id` 1/2/3, `status_id` 1/2/4 |
| `severity` | `severity_id` (informational 1, low 2, medium 3, high 4) |
| `classification` | `verdict_id` (incident profile) |
| `id`, `providerAlertId` | `finding_info.uid`, `uid_alt`, `metadata.uid`, `metadata.original_event_uid` |
| `title`, `description`, `categories` | `finding_info.title`, `desc`, `types` |
| `alertPolicyId`, rule name, template id | `finding_info.analytic` (type Rule), `related_analytics` |
| `additionalData.Query` | `finding_info.query_info.query_string` |
| `mitreTechniques` + category | `finding_info.attacks[]` (technique, sub_technique, tactic from ATT&CK) |
| first/last activity, created, updated | `start_time`/`end_time`, `finding_info.first_seen_time`/`last_seen_time`/`created_time`/`modified_time` |
| Search Query Results Overall Count | `count`, `finding_info.related_events_count` |
| Data Sources, WorkspaceId | `finding_info.data_sources`, `product_uid` |
| `incidentWebUrl`, `alertWebUrl` | `src_url`, `finding_info.src_url` |
| `systemTags`, domain result | `metadata.labels` |
| `userEvidence` | `evidences[].user` (UPN → name, Entra ID → uid, SID → uid_alt, AD account → account) |
| `ipEvidence` | `evidences[].src_endpoint` (or `dst_endpoint` when the role says destination) |
| `deviceEvidence`, `processEvidence`, `fileEvidence`, registry | `device`, `process`, `file`, registry data |
| `azureResource`/`amazonResource`/`googleCloudResource`/blob/k8s | `evidences[].resources` |
| `urlEvidence`, mail evidence | `url`, `email` / `user` |
| Source-specific fields | `unmapped` where retained by the normaliser |
| OSINT results | `osint[]` + observable `reputation` (osint profile) |

Graph user evidence maps to OCSF User. Set `SOC_TRIAGE_LOCAL_ACCOUNT_INFERENCE=true` to let local Ollama infer possible account types from aliases. The incident report labels these observations as unverified.

Validate output: `git clone --depth 1 --branch v1.10.0 https://github.com/ocsf/ocsf-schema.git` then
`python scripts/validate_ocsf.py ocsf-schema output/*.ocsf.json` (also run by the tests when `OCSF_SCHEMA_DIR` is set).

## OSINT

- Verdicts are rule-based (`osint.py`): VT ≥3 malicious engines or AbuseIPDB ≥75% → malicious;
  VT ≥1 malicious / ≥2 suspicious, AbuseIPDB ≥25% or Tor → suspicious; worst provider wins.
- Rotating sources: IPs are grouped by prefix (IPv6 /32 by default). VirusTotal gets one lookup per
  range (public API ≈4/min); AbuseIPDB checks every public IP up to `ABUSEIPDB_BUDGET`.
- Results are cached in SQLite for 24h.

## Agent safeguards

- The backend prepares query evidence and counts before calling the model. Sign-in summaries retain the query scope. Missing results and zero matching rows have different meanings.
- With `LLM_PSEUDONYMISE=true`, registered users and hosts are tokenised before model calls and restored in the output. IPs, hashes and domains can remain visible to the selected provider. Review the outbound data policy before using a hosted provider for customer incidents.
- Proposed ATT&CK IDs and tactics are checked against the bundled catalogue. This check establishes catalogue validity. Evidence and authorisation still require review.
- Successful same-account security-info registration keeps authorisation unverified. The registration guard prevents a model-only benign disposition and suppresses confirmed ATT&CK mappings for that evidence pattern. With the deterministic skip update applied, the MITRE step reports `skipped` for those cases. Other alerts use the normal mapping path.
- The pipeline can review and retry an allowlisted optional sign-in projection once. A successful recovery can include a proposed source diff in the triage JSON. Source updates follow the normal review and deployment process.
- Treat alert, event and OSINT content as data. Reports can contain customer information. Store them in the approved environment.

## Verify

```powershell
python -m pytest -q
python -m soc_triage.cli triage --file .\synthetic-graph-alert.json --out .\output\synthetic
```

Run the synthetic command with the intended provider configured. Check individual step statuses in the resulting report. For Ollama, confirm the tunnel is running before the test.

The local Ollama Identity pilot verified two synthetic scenarios through the pipeline. Unverified security-info registration produced no confirmed ATT&CK mapping. Corroborated password spraying retained T1110.003. Live Identity runs also verified the Graph snapshot, Advanced Hunting and the sign-in type breakdown. Broader domain coverage and concurrent capacity require separate acceptance tests.

Set `OCSF_SCHEMA_DIR` to the local schema checkout to enable schema validation in the test suite. Refresh the bundled ATT&CK table with `python scripts/build_attack_table.py enterprise-attack.json src/soc_triage/data/attack_enterprise.json`.
