"""Thursday: LangChain integration — callback handler that enforces HaltChain
policy on every tool call and agent action.

Install extras:  pip install haltchain[langchain]

Usage::

    from langchain.agents import initialize_agent
    from haltchain.langchain import HaltChainCallbackHandler

    handler = HaltChainCallbackHandler(
        client=HaltChainClient(agent_id="lc-agent", api_key="key"),
        # Map LangChain tool names → action dicts.
        tool_action_map={
            "transfer_money": lambda inp: {
                "type": "transfer",
                "amount": inp.get("amount", 0),
                "currency": inp.get("currency", "USD"),
            },
        },
    )

    agent = initialize_agent(tools, llm, callbacks=[handler])

If no mapping is provided for a tool, the handler sends
``{"type": tool_name}`` (still validated — will be blocked if the tool
is unknown to HaltChain policy).
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Union

from .client import HaltChainClient
from .exceptions import CircuitBreakerError, PolicyViolationError, ValidatorUnavailableError
from .metadata import build_metadata_from_langchain

# ActionStep type tag constants — mirrors Rust enum variants
_STEP_TOOL_CALL = "tool_call"
_STEP_REFLECTION = "reflect"
_STEP_FINAL_ANSWER = "answer"
_STEP_ERROR = "error"

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.agents import AgentAction, AgentFinish
    from langchain_core.outputs import LLMResult
    _LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover
    # Provide a stub so the module can be imported even without langchain.
    class BaseCallbackHandler:  # type: ignore[no-redef]
        pass
    _LANGCHAIN_AVAILABLE = False


def _parse_tool_input(raw: Union[str, dict]) -> dict:
    """Best-effort parse of tool input to a plain dict."""
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"input": raw}
    except (json.JSONDecodeError, TypeError):
        return {"input": str(raw)}


class HaltChainCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that validates every tool invocation.

    Policy violations raise :class:`PolicyViolationError` which bubbles up
    through the LangChain executor and halts the chain.

    Parameters
    ----------
    client:
        A configured :class:`~haltchain.HaltChainClient`.
    tool_action_map:
        Optional mapping ``tool_name → callable(parsed_input) → action dict``.
        If a tool is not listed, ``{"type": tool_name, **parsed_input}`` is
        used as the action.
    block_on_unavailable:
        When ``True`` (default), raise :class:`ValidatorUnavailableError` if
        the validator is unreachable and no cache hit exists.  This is the
        fail-secure mode.
    """

    raise_error = True  # tells LangChain to propagate our exceptions

    def __init__(
        self,
        client: HaltChainClient,
        tool_action_map: Optional[Dict[str, Callable[[dict], dict]]] = None,
        block_on_unavailable: bool = True,
        on_break: Optional[Callable[[dict], None]] = None,
        metadata_builder: Optional[Callable[[dict, dict[str, Any]], dict]] = None,
    ) -> None:
        if not _LANGCHAIN_AVAILABLE:  # pragma: no cover
            raise ImportError(
                "langchain-core is required: pip install haltchain[langchain]"
            )
        self._client = client
        self._tool_map = tool_action_map or {}
        self._block_on_unavailable = block_on_unavailable
        self._on_break = on_break
        self._metadata_builder = metadata_builder
        # run_id → list of step tag strings accumulated per chain run
        self._run_steps: Dict[str, List[str]] = {}

    # ── Callback hooks ────────────────────────────────────────────────────

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        if run_id is not None:
            self._run_steps[str(run_id)] = []

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called by LangChain before a tool runs."""
        tool_name = serialized.get("name") or serialized.get("id", ["unknown"])[-1]
        parsed_input = _parse_tool_input(input_str)
        action = self._build_action(tool_name, parsed_input)
        metadata = self._build_metadata(
            action=action,
            tool_name=tool_name,
            parsed_input=parsed_input,
            run_id=run_id,
            parent_run_id=parent_run_id,
        )
        self._track_step(parent_run_id, f"{_STEP_TOOL_CALL}:{tool_name}")
        self._check(action, metadata)

    def on_agent_action(
        self,
        action: "AgentAction",
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called by LangChain when the agent decides to use a tool."""
        tool_name = action.tool
        parsed_input = _parse_tool_input(action.tool_input)
        hc_action = self._build_action(tool_name, parsed_input)
        metadata = self._build_metadata(
            action=hc_action,
            tool_name=tool_name,
            parsed_input=parsed_input,
            run_id=run_id,
            parent_run_id=parent_run_id,
        )
        self._track_step(run_id, f"{_STEP_TOOL_CALL}:{tool_name}")
        self._check(hc_action, metadata)

    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        run_key = str(run_id) if run_id is not None else None
        if run_key:
            self._track_step(run_id, _STEP_FINAL_ANSWER)
            # Emit accumulated sequence for external fingerprinting consumers
            self._run_steps.pop(run_key, None)

    def on_chain_error(
        self,
        error: Any,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        self._track_step(run_id, _STEP_ERROR)
        run_key = str(run_id) if run_id is not None else None
        if run_key:
            self._run_steps.pop(run_key, None)

    # no-op hooks required by BaseCallbackHandler
    def on_llm_start(self, *a: Any, **k: Any) -> None: pass
    def on_llm_end(self, *a: Any, **k: Any) -> None: pass
    def on_llm_error(self, *a: Any, **k: Any) -> None: pass
    def on_tool_end(self, *a: Any, **k: Any) -> None: pass
    def on_tool_error(self, *a: Any, **k: Any) -> None: pass

    # ── Helpers ───────────────────────────────────────────────────────────

    def _track_step(self, run_id: Any, step: str) -> None:
        if run_id is not None:
            self._run_steps.setdefault(str(run_id), []).append(step)

    def _build_action(self, tool_name: str, parsed_input: dict) -> dict:
        if tool_name in self._tool_map:
            return self._tool_map[tool_name](parsed_input)
        # Default: merge input into action with tool name as type
        return {"type": tool_name, **parsed_input}

    def _build_metadata(
        self,
        *,
        action: dict,
        tool_name: str,
        parsed_input: dict,
        run_id: Any,
        parent_run_id: Any,
    ) -> dict:
        context = {
            "tool_name": tool_name,
            "parsed_input": parsed_input,
            "run_id": run_id,
            "parent_run_id": parent_run_id,
        }
        if self._metadata_builder is not None:
            return self._metadata_builder(action, context)
        return build_metadata_from_langchain(
            action=action,
            tool_name=tool_name,
            parsed_input=parsed_input,
            run_id=run_id,
            parent_run_id=parent_run_id,
        )

    def _check(self, action: dict, metadata: Optional[dict] = None) -> None:
        try:
            self._client.check(action, metadata=metadata)
        except (PolicyViolationError, CircuitBreakerError) as exc:
            if self._on_break is not None:
                self._on_break({"error": str(exc), "action": action})
            raise
        except ValidatorUnavailableError:
            if self._block_on_unavailable:
                raise
            # Non-blocking mode: let the chain continue (not recommended)
