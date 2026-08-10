#!/usr/bin/env python3
import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_ORG = "11111111-1111-1111-1111-111111111111"
DEFAULT_AGENT = "22222222-2222-2222-2222-222222222222"


def inspect(base_url, api_key, org_id, agent_id, tool_name, tool_args):
    payload = {
        "agent_id": agent_id,
        "org_id": org_id,
        "tool_name": tool_name,
        "tool_args": tool_args,
        "context_hash": "demo-rogue-agent",
        "timestamp": 1731700000,
    }
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/mcp/inspect",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "x-haltchain-org": org_id,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def main():
    p = argparse.ArgumentParser(description="Simulated rogue MCP agent (Kill Switch demo)")
    p.add_argument("--base-url", default="http://127.0.0.1:8787")
    p.add_argument("--api-key", default="dev-key")
    p.add_argument("--org-id", default=DEFAULT_ORG)
    p.add_argument("--agent-id", default=DEFAULT_AGENT)
    p.add_argument("--tool", default="exec_shell")
    p.add_argument("--args", default='{"cmd":"rm -rf /"}')
    ns = p.parse_args()

    if ns.args.strip().startswith("{"):
        tool_args = json.loads(ns.args)
    else:
        tool_args = {"cmd": ns.args}

    try:
        out = inspect(
            ns.base_url, ns.api_key, ns.org_id, ns.agent_id, ns.tool, tool_args
        )
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(body, file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(out, indent=2))
    if out.get("decision") in ("block", "quarantine"):
        sys.exit(0)
    print("expected block/quarantine decision", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
