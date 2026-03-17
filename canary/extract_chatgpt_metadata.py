#!/usr/bin/env python3
"""Extract HaltChain validator metadata from a ChatGPT-style conversation.

Usage: python canary/extract_chatgpt_metadata.py [conversation.json]
If no file is provided, a demo conversation is used.

This is a lightweight heuristic extractor intended to produce the metadata
shape the validator expects (see `crates/validator/src/lib.rs`). It is not
perfect but useful for creating realistic canary inputs.
"""
from __future__ import annotations

import json
import re
import os
import sys
from typing import Any, Dict, List, Optional
from uuid import uuid4

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SDK_PYTHON_PATH = os.path.join(REPO_ROOT, "sdk", "python")
if SDK_PYTHON_PATH not in sys.path:
    sys.path.append(SDK_PYTHON_PATH)

try:
    from haltchain.metadata import build_metadata_for_check
except Exception:
    build_metadata_for_check = None

URL_RE = re.compile(r"https?://[\w./:%-]+|/[-_\w/]+")
KEYS_RE = re.compile(r"(?:fields|columns|schema|payload)\s*[:=]\s*(\[.*?\])", re.I | re.S)
BOOL_RE = re.compile(r"(gdpr|delet).*", re.I)

Message = Dict[str, Any]


def load_messages(path: Optional[str]) -> List[Message]:
    if not path:
        return demo_conversation()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Expect either {"messages": [...]} or a bare list
    if isinstance(data, dict) and "messages" in data:
        return data["messages"]
    if isinstance(data, list):
        return data
    raise SystemExit("Unsupported conversation format; provide a list of messages")


def extract_json_blocks(text: str) -> List[Any]:
    blocks = []
    # triple-backtick blocks
    for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S | re.I):
        try:
            blocks.append(json.loads(m.group(1)))
        except Exception:
            pass
    # inline JSON-like {...}
    for m in re.finditer(r"(\{\s*\"[\s\S]*?\})", text):
        try:
            blocks.append(json.loads(m.group(1)))
        except Exception:
            pass
    return blocks


def first_match_list_from_json(msgs: List[Message], key: str) -> Optional[List[str]]:
    for m in msgs:
        if not isinstance(m.get("content"), str):
            continue
        text = m["content"]
        for obj in extract_json_blocks(text):
            if key in obj and isinstance(obj[key], list):
                return [str(x) for x in obj[key]]
    return None


def find_conversation_id(msgs: List[Message]) -> str:
    # look for explicit id
    for m in msgs:
        t = m.get("content") or ""
        m1 = re.search(r"conversation[_\s-]*id\s*[:=]\s*([\w-]+)", t, re.I)
        if m1:
            return m1.group(1)
    # fallback: use a generated UUID
    return str(uuid4())


def find_declared_services(msgs: List[Message]) -> Optional[List[str]]:
    # check for explicit declared_services key in JSON blocks
    val = first_match_list_from_json(msgs, "declared_services")
    if val:
        return val
    # heuristic: look for lines like "services: a, b"
    for m in msgs:
        t = m.get("content") or ""
        m1 = re.search(r"services?\s*[:=]\s*([\w,\s-/]+)", t, re.I)
        if m1:
            parts = [p.strip() for p in re.split(r",|;", m1.group(1)) if p.strip()]
            if parts:
                return parts
    return None


def find_accessed_service(msgs: List[Message], action_endpoint: Optional[str]) -> Optional[str]:
    # prefer endpoint provided by the action
    if action_endpoint:
        return action_endpoint
    # look for URLs or internal paths in messages
    for m in msgs:
        t = m.get("content") or ""
        u = URL_RE.search(t)
        if u:
            return u.group(0)
    return None


def find_fields_and_counts(msgs: List[Message]) -> tuple[Optional[List[str]], Optional[int], Optional[int]]:
    # try to find explicit lists
    pf = first_match_list_from_json(msgs, "payload_fields")
    rsf = first_match_list_from_json(msgs, "registered_schema_fields")
    # heuristics for counts
    requested = None
    necessary = None
    for m in msgs:
        t = m.get("content") or ""
        # look for "requested_columns: N"
        m1 = re.search(r"requested[_\s-]*columns\s*[:=]\s*(\d+)", t, re.I)
        if m1:
            requested = int(m1.group(1))
        m2 = re.search(r"task[_\s-]*necessary[_\s-]*columns\s*[:=]\s*(\d+)", t, re.I)
        if m2:
            necessary = int(m2.group(1))
        # try to parse a bracketed list after keywords
        m3 = KEYS_RE.search(t)
        if m3 and not pf:
            try:
                arr = json.loads(m3.group(1))
                if isinstance(arr, list):
                    pf = [str(x) for x in arr]
            except Exception:
                pass
    return pf or None, requested, necessary


def find_gdpr_and_retention(msgs: List[Message]) -> tuple[Optional[bool], Optional[int]]:
    gdpr = None
    retention = None
    for m in msgs:
        t = (m.get("content") or "").lower()
        if "gdpr" in t and ("delete" in t or "deletion" in t):
            gdpr = True
        m1 = re.search(r"retent(?:ion)?.{0,5}?(\d{1,4})\s*days", t)
        if m1:
            retention = int(m1.group(1))
    return gdpr, retention


def extract_metadata(messages: List[Message], action: Optional[dict] = None) -> Dict[str, Any]:
    conv_id = find_conversation_id(messages)
    declared = find_declared_services(messages)
    accessed = find_accessed_service(messages, action.get("endpoint") if action else None)
    payload_fields, requested_columns, task_necessary_columns = find_fields_and_counts(messages)
    gdpr, retention = find_gdpr_and_retention(messages)

    # payload_contains_pii: naive heuristic: presence of "ssn", "passport", "credit_card"
    joined = "\n".join([str(m.get("content") or "") for m in messages]).lower()
    pii_flag = any(k in joined for k in ("ssn", "passport", "credit_card", "dob", "tax_id"))

    metadata: Dict[str, Any] = {
        "conversation_id": conv_id,
        "declared_services": declared,
        "accessed_service": accessed,
        "requested_columns": requested_columns,
        "task_necessary_columns": task_necessary_columns,
        "registered_schema_fields": None,
        "payload_fields": payload_fields,
        "payload_contains_pii": pii_flag,
        "gdpr_deletion_requested": gdpr,
        "retention_days_requested": retention,
    }
    if build_metadata_for_check is not None:
        return build_metadata_for_check(action=action or {}, metadata=metadata)
    return metadata


def demo_conversation() -> List[Message]:
    return [
        {"role": "system", "content": "You are a data-export agent allowed to call user-db and analytics"},
        {"role": "user", "content": "Export user contact info (name,email,ssn) for compliance review"},
        {"role": "assistant", "content": "Sure. registered_schema_fields: [\"name\", \"email\"]\npayload_fields: [\"name\", \"email\", \"ssn\"]"},
    ]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    msgs = load_messages(path)
    # optional action hint: look for a top-level message with action json
    action = None
    for m in msgs:
        if isinstance(m.get("content"), str) and m["content"].strip().startswith("{"):
            try:
                j = json.loads(m["content"])
                if "type" in j:
                    action = j
                    break
            except Exception:
                pass

    meta = extract_metadata(msgs, action=action or {})
    print(json.dumps({k: v for k, v in meta.items() if v is not None}, indent=2))


if __name__ == "__main__":
    main()
