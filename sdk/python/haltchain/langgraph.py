"""LangGraph integration — drop-in HaltChain safety for any LangGraph workflow.

Install extras:  pip install haltchain[langgraph]

Usage (3 lines to add HaltChain)::

    from haltchain.langgraph import HaltChainGuard

    guard = HaltChainGuard(agent_id="my-agent", api_key="key")
    graph = guard.wrap(graph_builder.compile())

The guard automatically intercepts tool calls and state transitions,
validating each against HaltChain policy before execution proceeds.

For finer control, use the guard as a node or interrupt::

    # As a validation node in your graph
    builder.add_node("haltchain", guard.as_node())
    builder.add_edge("agent", "haltchain")
    builder.add_edge("haltchain", "tools")

    # As a conditional gate
    builder.add_conditional_edges(
        "agent",
        guard.gate(then="tools", deny="end"),
    )
"""

from __future__ import annotations

import functools
import json
from typing import Any, Callable, Dict, Optional, Sequence, TypeVar

from .async_client import AsyncHaltChainClient
from .client import HaltChainClient
from .exceptions import CircuitBreakerError, PolicyViolationError

try:
    from langgraph.graph import StateGraph
    from langgraph.graph.graph import CompiledGraph
    from langgraph.prebuilt import ToolNode

    _LANGGRAPH_AVAILABLE = True
except ImportError:
    _LANGGRAPH_AVAILABLE = False


class HaltChainGuard:
    """Drop-in safety layer for LangGraph workflows.

    Parameters
    ----------
    agent_id : str
        Agent identifier registered with HaltChain.
    api_key : str
        HaltChain API key.
    base_url : str
        HaltChain validator URL.
    tool_action_map : dict, optional
        Maps tool names to callables that produce HaltChain action dicts
        from tool input. If omitted, ``{"type": tool_name, **input}`` is used.
    block_on_deny : bool
        If True (default), denied actions raise PolicyViolationError which
        triggers LangGraph error handling. If False, injects a deny message
        into the state instead.
    session_key : str
        State key used to store/read the session id (default: "session_id").
    """

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: str,
        base_url: str = HaltChainClient.DEFAULT_BASE,
        tool_action_map: Optional[Dict[str, Callable[[dict], dict]]] = None,
        block_on_deny: bool = True,
        session_key: str = "session_id",
        **client_kwargs: Any,
    ) -> None:
        if not _LANGGRAPH_AVAILABLE:
            raise ImportError(
                "langgraph is required: pip install haltchain[langgraph]"
            )
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
        self._block_on_deny = block_on_deny
        self._session_key = session_key

    def _get_async_client(self) -> AsyncHaltChainClient:
        if self._async_client is None:
            self._async_client = AsyncHaltChainClient(
                agent_id=self._agent_id,
                api_key=self._api_key,
                base_url=self._base_url,
                **self._client_kwargs,
            )
        return self._async_client

    # ── Public API ────────────────────────────────────────────────────────

    def wrap(self, compiled_graph: "CompiledGraph") -> "CompiledGraph":
        """Wrap a compiled LangGraph graph with HaltChain validation.

        Monkey-patches the graph's tool node (if present) to validate
        every tool call before execution. Returns the same graph object
        for chaining.

        Usage::

            graph = guard.wrap(builder.compile())
        """
        # Find and wrap ToolNode instances in the graph
        for node_name, node_fn in list(compiled_graph.nodes.items()):
            if isinstance(node_fn, ToolNode):
                compiled_graph.nodes[node_name] = self._wrap_tool_node(node_fn)
            elif hasattr(node_fn, "__wrapped_haltchain__"):
                continue  # Already wrapped
        return compiled_graph

    def as_node(self) -> Callable:
        """Return a LangGraph node function that validates the last message.

        Insert between the agent and tools node::

            builder.add_node("haltchain", guard.as_node())
        """

        async def _validate_node(state: dict) -> dict:
            messages = state.get("messages", [])
            if not messages:
                return state

            last_msg = messages[-1]
            tool_calls = getattr(last_msg, "tool_calls", None)
            if not tool_calls:
                return state

            session_id = state.get(self._session_key)

            for tc in tool_calls:
                tool_name = tc.get("name", tc.get("function", {}).get("name", "unknown"))
                tool_input = tc.get("args", tc.get("function", {}).get("arguments", {}))
                if isinstance(tool_input, str):
                    try:
                        tool_input = json.loads(tool_input)
                    except (json.JSONDecodeError, TypeError):
                        tool_input = {"input": tool_input}

                action = self._build_action(tool_name, tool_input)
                metadata = {
                    "framework": "langgraph",
                    "tool_name": tool_name,
                    "node_type": "validation_gate",
                }

                client = self._get_async_client()
                result = await client.check(action, metadata=metadata, session_id=session_id)
                decision = result.get("decision", "ALLOW")

                if decision in ("DENY", "CIRCUIT_BREAK"):
                    if self._block_on_deny:
                        raise PolicyViolationError(
                            decision=decision,
                            reason=result.get("reason", "Policy denied"),
                            policy=result.get("policy", ""),
                        )
                    # Non-blocking: return a message indicating denial
                    return {
                        "messages": [
                            {
                                "role": "system",
                                "content": f"[HaltChain DENIED] {result.get('reason', 'Policy violation')}",
                            }
                        ]
                    }

            return state

        _validate_node.__wrapped_haltchain__ = True  # type: ignore[attr-defined]
        return _validate_node

    def gate(
        self,
        *,
        then: str = "tools",
        deny: str = "__end__",
    ) -> Callable:
        """Return a conditional edge function for LangGraph.

        Routes to ``then`` on ALLOW, ``deny`` on DENY/CIRCUIT_BREAK::

            builder.add_conditional_edges("agent", guard.gate(then="tools", deny="end"))
        """

        def _route(state: dict) -> str:
            messages = state.get("messages", [])
            if not messages:
                return then

            last_msg = messages[-1]
            tool_calls = getattr(last_msg, "tool_calls", None)
            if not tool_calls:
                return then

            session_id = state.get(self._session_key)

            for tc in tool_calls:
                tool_name = tc.get("name", tc.get("function", {}).get("name", "unknown"))
                tool_input = tc.get("args", {})
                if isinstance(tool_input, str):
                    try:
                        tool_input = json.loads(tool_input)
                    except (json.JSONDecodeError, TypeError):
                        tool_input = {"input": tool_input}

                action = self._build_action(tool_name, tool_input)
                metadata = {"framework": "langgraph", "tool_name": tool_name}

                try:
                    result = self._client.check(
                        action, metadata=metadata, session_id=session_id,
                    )
                    if result.get("decision") in ("DENY", "CIRCUIT_BREAK"):
                        return deny
                except (PolicyViolationError, CircuitBreakerError):
                    return deny

            return then

        return _route

    # ── Internal helpers ──────────────────────────────────────────────────

    def _build_action(self, tool_name: str, tool_input: dict) -> dict:
        if tool_name in self._tool_map:
            return self._tool_map[tool_name](tool_input)
        return {"type": tool_name, **tool_input}

    def _wrap_tool_node(self, tool_node: "ToolNode") -> Callable:
        """Wrap a ToolNode's invoke to pre-validate each tool call."""
        original_invoke = tool_node.invoke

        @functools.wraps(original_invoke)
        def guarded_invoke(state: dict, config: Any = None) -> Any:
            messages = state.get("messages", [])
            if messages:
                last_msg = messages[-1]
                tool_calls = getattr(last_msg, "tool_calls", None)
                if tool_calls:
                    session_id = state.get(self._session_key)
                    for tc in tool_calls:
                        tool_name = tc.get("name", "unknown")
                        tool_input = tc.get("args", {})
                        action = self._build_action(tool_name, tool_input)
                        metadata = {"framework": "langgraph", "tool_name": tool_name}

                        result = self._client.check(
                            action, metadata=metadata, session_id=session_id,
                        )
                        decision = result.get("decision", "ALLOW")
                        if decision in ("DENY", "CIRCUIT_BREAK"):
                            raise PolicyViolationError(
                                decision=decision,
                                reason=result.get("reason", "Policy denied"),
                                policy=result.get("policy", ""),
                            )

            return original_invoke(state, config)

        guarded_invoke.__wrapped_haltchain__ = True  # type: ignore[attr-defined]
        return guarded_invoke

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HaltChainGuard":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
