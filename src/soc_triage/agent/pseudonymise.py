"""Reversible tokenisation of personal identifiers before text leaves for an LLM.

Users (UPN, account name, display name, SID, Entra object ID) and hostnames become USER_01,
HOST_01 ... Public IPs, hashes and domains are left as-is because they are the indicators the
analysis is about. Tokens are restored in the model's output.
"""
from __future__ import annotations

import json
import re
from typing import Any


class Pseudonymiser:
    def __init__(self):
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}

    def register_users(self, users: list[dict]) -> None:
        for i, u in enumerate(users, 1):
            token = f"USER_{i:02d}"
            primary = u.get("upn") or u.get("account")
            if primary:
                self.reverse[token] = primary
            for v in (u.get("upn"), u.get("account"), u.get("display_name"), u.get("sid"), u.get("aad_id")):
                if v and len(v) >= 3:
                    self.forward.setdefault(v, token)

    def register_hosts(self, hosts: list[dict]) -> None:
        for i, h in enumerate(hosts, 1):
            token = f"HOST_{i:02d}"
            self.reverse[token] = h["value"]
            self.forward.setdefault(h["value"], token)

    def apply(self, obj: Any) -> Any:
        if not self.forward:
            return obj
        text = json.dumps(obj, ensure_ascii=False, default=str)
        # longest first so a UPN is replaced before its account-name prefix
        for value in sorted(self.forward, key=len, reverse=True):
            pattern = r"(?<![\w-])" + re.escape(json.dumps(value)[1:-1]) + r"(?![\w-])"
            text = re.sub(pattern, self.forward[value], text, flags=re.IGNORECASE)
        return json.loads(text)

    def restore(self, obj: Any) -> Any:
        if not self.reverse:
            return obj
        text = json.dumps(obj, ensure_ascii=False)
        text = re.sub(r"\b(USER|HOST)_\d{2}\b", lambda m: json.dumps(self.reverse.get(m.group(0), m.group(0)))[1:-1], text)
        return json.loads(text)
