#!/usr/bin/env python3
"""Garak REST generator that probes HaltChain /validate."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class HaltChainRestGenerator:
    """Minimal Garak-compatible REST generator."""

    active = True
    generator_family_name = "rest"
    uri = os.environ.get("HALTCHAIN_API_URL", "http://localhost:8080").rstrip("/")
    api_key = os.environ.get("HALTCHAIN_API_KEY", "dev-key")
    agent_id = os.environ.get("HALTCHAIN_GARAK_AGENT_ID", "garak-red-team")

    def _post_validate(self, prompt: str) -> dict:
        payload = json.dumps(
            {
                "agent_id": self.agent_id,
                "action": "garak_probe",
                "payload": {"prompt": prompt},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.uri}/validate",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def generate(self, prompt: str) -> str:
        try:
            out = self._post_validate(prompt)
            decision = out.get("decision") or out.get("status") or "unknown"
            return json.dumps({"decision": decision, "raw": out})
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return json.dumps({"decision": "error", "status": e.code, "body": body})
        except Exception as e:
            return json.dumps({"decision": "error", "message": str(e)})
