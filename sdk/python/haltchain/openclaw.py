"""OpenClaw integration — HaltChain safety for OpenClaw agent workflows.

Install extras:  pip install haltchain[openclaw]

OpenClaw runs agents via gateway-based orchestration. HaltChain integrates
at two levels:

1. **Task-level** — validate agent actions before/after execution
2. **Gateway-level** — intercept all agent communications through the gateway

Usage (3 lines to add HaltChain)::

    from haltchain.openclaw import HaltChainOpenClawGuard

    guard = HaltChainOpenClawGuard(agent_id="claw-agent", api_key="key")
    guard.protect(agent)  # Wraps the agent's tool execution

For Mission Control integration (approval workflows)::

    from haltchain.openclaw import HaltChainApprovalProvider

    provider = HaltChainApprovalProvider(agent_id="claw-agent", api_key="key")
    # Register as an approval hook in Mission Control

For gateway-level protection (intercepts all agent HTTP calls)::

    from haltchain.openclaw import HaltChainGatewayMiddleware

    middleware = HaltChainGatewayMiddleware(agent_id="gw-agent", api_key="key")
    # Attach to your OpenClaw gateway configuration
"""

from __future__ import annotations

import functools
import json
from typing import Any, Callable, Dict, List, Optional, Tuple

from .client import HaltChainClient
from .async_client import AsyncHaltChainClient
from .exceptions import CircuitBreakerError, PolicyViolationError


class HaltChainOpenClawGuard:
    """Protect an OpenClaw agent with HaltChain validation.

    Wraps the agent's tool calls so every action is validated against
    HaltChain policy before execution.

    Parameters
    ----------
    agent_id : str
        Agent identifier registered with HaltChain.
    api_key : str
        HaltChain API key.
    base_url : str
        HaltChain validator URL.
    tool_action_map : dict, optional
        Maps tool/skill names to action-extraction callables.
    validate_messages : bool
        If True, also validates outgoing messages between agents.
    """

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: str,
        base_url: str = HaltChainClient.DEFAULT_BASE,
        tool_action_map: Optional[Dict[str, Callable[[dict], dict]]] = None,
        validate_messages: bool = False,
        **client_kwargs: Any,
    ) -> None:
        self._client = HaltChainClient(
            agent_id=agent_id,
            api_key=api_key,
            base_url=base_url,
            **client_kwargs,
        )
        self._async_client: Optional[AsyncHaltChainClient] = None
        self._agent_id = agent_id
        self._api_key = api_key
        self._base_url = base_url
        self._client_kwargs = client_kwargs
        self._tool_map = tool_action_map or {}
        self._validate_messages = validate_messages

    def _get_async_client(self) -> AsyncHaltChainClient:
        if self._async_client is None:
            self._async_client = AsyncHaltChainClient(
                agent_id=self._agent_id,
                api_key=self._api_key,
                base_url=self._base_url,
                **self._client_kwargs,
            )
        return self._async_client

    def protect(self, agent: Any) -> Any:
        """Wrap an OpenClaw agent's tool execution with HaltChain validation.

        Monkey-patches the agent's ``execute_tool`` or ``run_tool`` method
        to validate before execution. Compatible with OpenClaw agent objects
        that expose tool execution hooks.

        Usage::

            guard = HaltChainOpenClawGuard(agent_id="bot", api_key="key")
            guard.protect(agent)
        """
        # OpenClaw agents may expose different tool execution interfaces
        for method_name in ("execute_tool", "run_tool", "_call_tool", "invoke_tool"):
            if hasattr(agent, method_name):
                original = getattr(agent, method_name)
                wrapped = self._wrap_tool_method(original, method_name)
                setattr(agent, method_name, wrapped)
                break
        else:
            # Fallback: wrap __call__ if it exists
            if callable(agent):
                original_call = agent.__call__
                agent.__call__ = self._wrap_tool_method(original_call, "__call__")

        return agent

    def guard_tool(self, tool_name: Optional[str] = None) -> Callable:
        """Decorator to guard an individual tool/skill function.

        Usage::

            @guard.guard_tool("transfer_money")
            def transfer(amount: float, recipient: str):
                ...

            # Or auto-detect name:
            @guard.guard_tool()
            def send_email(to: str, body: str):
                ...
        """

        def decorator(fn: Callable) -> Callable:
            name = tool_name or fn.__name__

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                action = self._build_action(name, kwargs or _args_to_dict(args))
                metadata = {
                    "framework": "openclaw",
                    "tool_name": name,
                    "operation": "tool_execution",
                }

                result = self._client.check(action, metadata=metadata)
                decision = result.get("decision", "ALLOW")

                if decision in ("DENY", "CIRCUIT_BREAK"):
                    raise PolicyViolationError(
                        decision=decision,
                        reason=result.get("reason", "Policy denied"),
                        policy=result.get("policy", ""),
                    )

                return fn(*args, **kwargs)

            return wrapper

        return decorator

    def validate_action(
        self,
        action: dict,
        *,
        session_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Manually validate an action against HaltChain.

        Returns the full validation response. Useful for custom
        integration points where automatic wrapping doesn't fit.
        """
        meta = {"framework": "openclaw", **(metadata or {})}
        return self._client.check(action, metadata=meta, session_id=session_id)

    async def avalidate_action(
        self,
        action: dict,
        *,
        session_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Async version of validate_action."""
        meta = {"framework": "openclaw", **(metadata or {})}
        client = self._get_async_client()
        return await client.check(action, metadata=meta, session_id=session_id)

    # ── Internal ──────────────────────────────────────────────────────────

    def _build_action(self, tool_name: str, tool_input: dict) -> dict:
        if tool_name in self._tool_map:
            return self._tool_map[tool_name](tool_input)
        return {"type": tool_name, **tool_input}

    def _wrap_tool_method(self, original: Callable, method_name: str) -> Callable:
        @functools.wraps(original)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            # Extract tool name and input from args
            tool_name = "unknown"
            tool_input: dict = {}

            if args:
                first_arg = args[0]
                if isinstance(first_arg, str):
                    tool_name = first_arg
                    tool_input = args[1] if len(args) > 1 and isinstance(args[1], dict) else kwargs
                elif isinstance(first_arg, dict):
                    tool_name = first_arg.get("name", first_arg.get("tool", "unknown"))
                    tool_input = first_arg.get("input", first_arg.get("args", {}))

            action = self._build_action(tool_name, tool_input if isinstance(tool_input, dict) else {})
            metadata = {
                "framework": "openclaw",
                "tool_name": tool_name,
                "method": method_name,
            }

            result = self._client.check(action, metadata=metadata)
            decision = result.get("decision", "ALLOW")

            if decision in ("DENY", "CIRCUIT_BREAK"):
                raise PolicyViolationError(
                    decision=decision,
                    reason=result.get("reason", "Policy denied"),
                    policy=result.get("policy", ""),
                )

            return original(*args, **kwargs)

        return wrapped

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HaltChainOpenClawGuard":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


class HaltChainApprovalProvider:
    """Approval provider for OpenClaw Mission Control.

    Integrates with Mission Control's approval workflow by validating
    pending actions through HaltChain before approving them.

    This can be used as a webhook handler that Mission Control calls
    when an approval is requested.

    Usage::

        provider = HaltChainApprovalProvider(agent_id="mc-guard", api_key="key")

        # In your webhook handler:
        @app.post("/approve")
        async def handle_approval(request):
            return await provider.evaluate(request.json())
    """

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: str,
        base_url: str = HaltChainClient.DEFAULT_BASE,
        auto_approve_on_allow: bool = True,
        **client_kwargs: Any,
    ) -> None:
        self._client = HaltChainClient(
            agent_id=agent_id,
            api_key=api_key,
            base_url=base_url,
            **client_kwargs,
        )
        self._async_client: Optional[AsyncHaltChainClient] = None
        self._agent_id = agent_id
        self._api_key = api_key
        self._base_url = base_url
        self._client_kwargs = client_kwargs
        self._auto_approve = auto_approve_on_allow

    def _get_async_client(self) -> AsyncHaltChainClient:
        if self._async_client is None:
            self._async_client = AsyncHaltChainClient(
                agent_id=self._agent_id,
                api_key=self._api_key,
                base_url=self._base_url,
                **self._client_kwargs,
            )
        return self._async_client

    def evaluate(self, approval_request: dict) -> dict:
        """Evaluate a Mission Control approval request via HaltChain.

        Parameters
        ----------
        approval_request : dict
            The approval request payload from Mission Control, typically
            containing task_id, agent_id, action details, etc.

        Returns
        -------
        dict
            ``{"approved": bool, "reason": str, "haltchain_tx": str}``
        """
        action = {
            "type": approval_request.get("action_type", "approval_request"),
            "task_id": approval_request.get("task_id", ""),
            "agent_role": approval_request.get("agent_role", ""),
        }

        # Include any amount/financial data if present
        if "amount" in approval_request:
            action["amount"] = approval_request["amount"]
        if "recipient" in approval_request:
            action["recipient"] = approval_request["recipient"]

        metadata = {
            "framework": "openclaw_mission_control",
            "approval_type": approval_request.get("approval_type", "task"),
            "board_id": approval_request.get("board_id", ""),
        }

        try:
            result = self._client.check(action, metadata=metadata)
            decision = result.get("decision", "ALLOW")
            approved = decision == "ALLOW" and self._auto_approve

            return {
                "approved": approved,
                "reason": result.get("reason", ""),
                "decision": decision,
                "haltchain_tx": result.get("transaction_id", ""),
                "policy": result.get("policy", ""),
            }
        except Exception as e:
            return {
                "approved": False,
                "reason": f"HaltChain validation failed: {e}",
                "decision": "ERROR",
                "haltchain_tx": "",
                "policy": "",
            }

    async def aevaluate(self, approval_request: dict) -> dict:
        """Async version of evaluate."""
        action = {
            "type": approval_request.get("action_type", "approval_request"),
            "task_id": approval_request.get("task_id", ""),
            "agent_role": approval_request.get("agent_role", ""),
        }
        if "amount" in approval_request:
            action["amount"] = approval_request["amount"]
        if "recipient" in approval_request:
            action["recipient"] = approval_request["recipient"]

        metadata = {
            "framework": "openclaw_mission_control",
            "approval_type": approval_request.get("approval_type", "task"),
        }

        try:
            client = self._get_async_client()
            result = await client.check(action, metadata=metadata)
            decision = result.get("decision", "ALLOW")
            return {
                "approved": decision == "ALLOW" and self._auto_approve,
                "reason": result.get("reason", ""),
                "decision": decision,
                "haltchain_tx": result.get("transaction_id", ""),
                "policy": result.get("policy", ""),
            }
        except Exception as e:
            return {
                "approved": False,
                "reason": f"HaltChain validation failed: {e}",
                "decision": "ERROR",
                "haltchain_tx": "",
                "policy": "",
            }


class HaltChainGatewayMiddleware:
    """ASGI/WSGI middleware for OpenClaw Gateway integration.

    Intercepts HTTP requests between OpenClaw agents and validates
    them through HaltChain. Designed to sit in front of the OpenClaw
    gateway as a reverse proxy layer.

    Usage with FastAPI::

        from fastapi import FastAPI
        from haltchain.openclaw import HaltChainGatewayMiddleware

        app = FastAPI()
        middleware = HaltChainGatewayMiddleware(agent_id="gw", api_key="key")
        app.middleware("http")(middleware.asgi_middleware)

    Usage with any ASGI app::

        app = HaltChainGatewayMiddleware(
            agent_id="gw", api_key="key"
        ).wrap_asgi(your_app)
    """

    # Paths that bypass validation (health checks, static assets)
    BYPASS_PATHS = frozenset({"/healthz", "/health", "/ready", "/metrics"})

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: str,
        base_url: str = HaltChainClient.DEFAULT_BASE,
        validate_paths: Optional[List[str]] = None,
        bypass_paths: Optional[List[str]] = None,
        **client_kwargs: Any,
    ) -> None:
        self._client = HaltChainClient(
            agent_id=agent_id,
            api_key=api_key,
            base_url=base_url,
            **client_kwargs,
        )
        self._validate_paths = validate_paths  # If set, only validate these
        self._bypass = set(bypass_paths or []) | self.BYPASS_PATHS

    def should_validate(self, path: str, method: str) -> bool:
        """Determine if a request should be validated."""
        if path in self._bypass:
            return False
        if self._validate_paths:
            return any(path.startswith(p) for p in self._validate_paths)
        # Default: validate all non-GET requests (mutations)
        return method.upper() not in ("GET", "HEAD", "OPTIONS")

    def validate_request(
        self,
        *,
        method: str,
        path: str,
        body: Optional[dict] = None,
        headers: Optional[dict] = None,
        source_agent: Optional[str] = None,
    ) -> dict:
        """Validate a gateway request through HaltChain.

        Returns the HaltChain validation response.
        """
        action = {
            "type": f"gateway_{method.lower()}",
            "endpoint": path,
        }
        if body:
            if "amount" in body:
                action["amount"] = body["amount"]
            if "recipient" in body:
                action["recipient"] = body["recipient"]

        metadata = {
            "framework": "openclaw_gateway",
            "http_method": method,
            "path": path,
            "source_agent": source_agent or "",
        }

        return self._client.check(action, metadata=metadata)

    async def asgi_middleware(self, request: Any, call_next: Callable) -> Any:
        """FastAPI/Starlette middleware handler.

        Usage::

            app.middleware("http")(middleware.asgi_middleware)
        """
        path = request.url.path
        method = request.method

        if not self.should_validate(path, method):
            return await call_next(request)

        # Extract source agent from headers (OpenClaw convention)
        source_agent = request.headers.get("x-openclaw-agent-id", "")

        body = None
        if method.upper() in ("POST", "PUT", "PATCH"):
            try:
                body = await request.json()
            except Exception:
                body = None

        try:
            result = self.validate_request(
                method=method,
                path=path,
                body=body,
                source_agent=source_agent,
            )
            decision = result.get("decision", "ALLOW")

            if decision in ("DENY", "CIRCUIT_BREAK"):
                # Return 403 with reason
                from starlette.responses import JSONResponse  # type: ignore[import-untyped]

                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "HaltChain policy denied",
                        "reason": result.get("reason", ""),
                        "policy": result.get("policy", ""),
                        "transaction_id": result.get("transaction_id", ""),
                    },
                )
        except Exception:
            # Fail-open on validator unavailability
            pass

        return await call_next(request)

    def wrap_asgi(self, app: Any) -> Any:
        """Wrap an ASGI application with HaltChain validation."""
        middleware = self

        async def wrapped_app(scope: dict, receive: Callable, send: Callable) -> None:
            if scope["type"] != "http":
                return await app(scope, receive, send)

            path = scope.get("path", "")
            method = scope.get("method", "GET")

            if not middleware.should_validate(path, method):
                return await app(scope, receive, send)

            # For ASGI-level wrapping, validate and potentially short-circuit
            action = {"type": f"gateway_{method.lower()}", "endpoint": path}
            meta = {"framework": "openclaw_gateway", "http_method": method, "path": path}

            try:
                result = middleware._client.check(action, metadata=meta)
                if result.get("decision") in ("DENY", "CIRCUIT_BREAK"):
                    response_body = json.dumps({
                        "error": "HaltChain policy denied",
                        "reason": result.get("reason", ""),
                    }).encode()

                    await send({
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [[b"content-type", b"application/json"]],
                    })
                    await send({
                        "type": "http.response.body",
                        "body": response_body,
                    })
                    return
            except Exception:
                pass  # Fail-open

            return await app(scope, receive, send)

        return wrapped_app

    def close(self) -> None:
        self._client.close()


# ── Helpers ───────────────────────────────────────────────────────────────


def _args_to_dict(args: tuple) -> dict:
    """Convert positional args to a dict for action extraction."""
    if len(args) == 1 and isinstance(args[0], dict):
        return args[0]
    return {f"arg_{i}": v for i, v in enumerate(args)}
