"""Configuration. Secrets come only from environment variables (never from files in the repo).

Multi-tenant (MSSP) layout: customers.json maps a customer key to its Entra tenant and Sentinel
workspace. Each customer names the *environment variables* that hold its app credentials.

customers.json
{
  "<customer_id>": {
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id_env": "<CUSTOMER_ID>_CLIENT_ID",
    "client_secret_env": "<CUSTOMER_ID>_CLIENT_SECRET",
    "subscription_id": "00000000-0000-0000-0000-000000000000",
    "resource_group": "<resource_group>",
    "workspace_name": "<workspace_name>",
    "workspace_id": "00000000-0000-0000-0000-000000000000"
  }
}
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Customer:
    key: str
    tenant_id: str
    client_id_env: str
    client_secret_env: str
    subscription_id: str | None = None
    resource_group: str | None = None
    workspace_name: str | None = None
    workspace_id: str | None = None

    @property
    def client_id(self) -> str:
        return _require(self.client_id_env)

    @property
    def client_secret(self) -> str:
        return _require(self.client_secret_env)


@dataclass(frozen=True)
class Settings:
    customers: dict[str, Customer] = field(default_factory=dict)
    vt_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-5-5"
    vt_requests_per_minute: int = 4          # VirusTotal public API default
    abuseipdb_max_age_days: int = 90
    osint_budget: int = 25                    # max indicators enriched per incident
    abuseipdb_budget: int = 100               # max IPs checked in AbuseIPDB per incident
    ipv6_group_prefix: int = 32               # rotating IPv6 sources grouped per /32 allocation
    ipv4_group_prefix: int = 32               # 32 = no grouping for IPv4
    cache_path: str = ".cache/osint.sqlite"
    cache_ttl_hours: int = 24
    sentinel_api_version: str = "2024-09-01"
    llm_pseudonymise: bool = True             # tokenise users/hosts/emails before LLM calls
    max_event_rows: int = 200


def load_dotenv(path: str | os.PathLike | None = None) -> None:
    """Load KEY=VALUE lines from .env (cwd, or SOC_TRIAGE_ENV). Real environment variables win."""
    p = Path(path or os.environ.get("SOC_TRIAGE_ENV", ".env"))
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _require(name: str) -> str:
    load_dotenv()
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"{name} is not set (add it to .env or the environment)")
    return val


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


@lru_cache(maxsize=1)
def settings() -> Settings:
    load_dotenv()
    path = Path(os.environ.get("SOC_TRIAGE_CUSTOMERS", "customers.json"))
    customers: dict[str, Customer] = {}
    if path.exists():
        for key, c in json.loads(path.read_text(encoding="utf-8")).items():
            customers[key.lower()] = Customer(key=key.lower(), **c)
    return Settings(
        customers=customers,
        vt_api_key=os.environ.get("VT_API_KEY"),
        abuseipdb_api_key=os.environ.get("ABUSEIPDB_API_KEY"),
        anthropic_model=os.environ.get("SOC_TRIAGE_MODEL", "claude-sonnet-5-5"),
        vt_requests_per_minute=_int("VT_REQUESTS_PER_MINUTE", 4),
        abuseipdb_max_age_days=_int("ABUSEIPDB_MAX_AGE_DAYS", 90),
        osint_budget=_int("OSINT_BUDGET", 25),
        abuseipdb_budget=_int("ABUSEIPDB_BUDGET", 100),
        ipv6_group_prefix=_int("IPV6_GROUP_PREFIX", 32),
        ipv4_group_prefix=_int("IPV4_GROUP_PREFIX", 32),
        cache_path=os.environ.get("OSINT_CACHE_PATH", ".cache/osint.sqlite"),
        cache_ttl_hours=_int("OSINT_CACHE_TTL_HOURS", 24),
        sentinel_api_version=os.environ.get("SENTINEL_API_VERSION", "2024-09-01"),
        llm_pseudonymise=os.environ.get("LLM_PSEUDONYMISE", "true").lower() != "false",
        max_event_rows=_int("MAX_EVENT_ROWS", 200),
    )


def customer(key: str) -> Customer:
    s = settings()
    c = s.customers.get((key or "").lower())
    if not c:
        known = ", ".join(sorted(s.customers)) or "none configured"
        raise KeyError(f"Unknown customer '{key}'. Configured: {known}")
    return c
