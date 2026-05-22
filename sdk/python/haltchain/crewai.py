"""CrewAI integration — drop-in HaltChain safety for CrewAI workflows.

Install extras:  pip install haltchain[crewai]

Usage (3 lines to add HaltChain)::

    from haltchain.crewai import haltchain_guardrail

    task = Task(
        description="Transfer funds...",
        guardrail=haltchain_guardrail(agent_id="crew-fin", api_key="key"),
    )

Or wrap an entire Crew::

    from haltchain.crewai import HaltChainCrewGuard

    guard = HaltChainCrewGuard(agent_id="crew-bot", api_key="key")
    crew = guard.wrap(crew)
    crew.kickoff()

For Flow-based CrewAI, use the decorator::

    from haltchain.crewai import haltchain_step

    class MyFlow(Flow):
        @haltchain_step(agent_id="flow-bot", api_key="key")
        def risky_action(self):
            return do_something()
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Optional, Tuple, Union

from .client import HaltChainClient
from .exceptions import CircuitBreakerError, PolicyViolationError

try:
    from crewai import Task, Crew
    from crewai.tasks.task_output import TaskOutput

    _CREWAI_AVAILABLE = True
except ImportError:
    _CREWAI_AVAILABLE = False


def haltchain_guardrail(
    *,
    agent_id: str,
    api_key: str,
    base_url: str = HaltChainClient.DEFAULT_BASE,
    action_extractor: Optional[Callable[[TaskOutput], dict]] = None,
    **client_kwargs: Any,
) -> Callable:
    """Create a CrewAI-compatible guardrail function.

    Returns a function with signature ``(output: TaskOutput) -> Tuple[bool, Any]``
    that CrewAI calls after task completion. If HaltChain denies, returns
    ``(False, reason)`` which triggers CrewAI's retry mechanism.

    Parameters
    ----------
    agent_id : str
        Agent identifier registered with HaltChain.
    api_key : str
        HaltChain API key.
    base_url : str
        HaltChain validator URL.
    action_extractor : callable, optional
        Custom function to extract an action dict from TaskOutput.
        Default: uses the task description and raw output.

    Usage::

        task = Task(
            description="Wire $50K to vendor",
            guardrail=haltchain_guardrail(agent_id="fin-bot", api_key="key"),
        )
    """
    if not _CREWAI_AVAILABLE:
        raise ImportError("crewai is required: pip install haltchain[crewai]")

    client = HaltChainClient(
        agent_id=agent_id,
        api_key=api_key,
        base_url=base_url,
        **client_kwargs,
    )

    def _guardrail(output: "TaskOutput") -> Tuple[bool, Any]:
        if action_extractor:
            action = action_extractor(output)
        else:
            action = _extract_action_from_output(output)

        metadata = {
            "framework": "crewai",
            "task_description": _safe_get_description(output),
            "output_type": "task_completion",
        }

        try:
            result = client.check(action, metadata=metadata)
            decision = result.get("decision", "ALLOW")

            if decision == "ALLOW":
                return (True, output)
            else:
                reason = result.get("reason", "HaltChain policy denied this output")
                return (False, f"[HaltChain {decision}] {reason}")

        except (PolicyViolationError, CircuitBreakerError) as e:
            return (False, f"[HaltChain] {e}")
        except Exception:
            # Fail-open: if HaltChain is unreachable, allow through
            # (configurable via client's block_on_unavailable)
            return (True, output)

    return _guardrail


class HaltChainCrewGuard:
    """Wrap an entire CrewAI Crew with HaltChain validation.

    Validates each task's output before it's passed to the next task.
    Uses CrewAI's built-in step callback mechanism.

    Parameters
    ----------
    agent_id : str
        Agent identifier registered with HaltChain.
    api_key : str
        HaltChain API key.
    base_url : str
        HaltChain validator URL.
    tool_action_map : dict, optional
        Maps tool names to action-extraction callables.
    deny_action : str
        What to do on deny: "raise" (default) or "skip".

    Usage::

        guard = HaltChainCrewGuard(agent_id="crew-bot", api_key="key")
        crew = guard.wrap(crew)
    """

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: str,
        base_url: str = HaltChainClient.DEFAULT_BASE,
        tool_action_map: Optional[Dict[str, Callable[[dict], dict]]] = None,
        deny_action: str = "raise",
        **client_kwargs: Any,
    ) -> None:
        if not _CREWAI_AVAILABLE:
            raise ImportError("crewai is required: pip install haltchain[crewai]")

        self._client = HaltChainClient(
            agent_id=agent_id,
            api_key=api_key,
            base_url=base_url,
            **client_kwargs,
        )
        self._tool_map = tool_action_map or {}
        self._deny_action = deny_action

    def wrap(self, crew: "Crew") -> "Crew":
        """Attach HaltChain validation to a Crew's step callback.

        Wraps the existing step_callback (if any) and validates each
        agent action before it proceeds.
        """
        original_callback = crew.step_callback

        def _guarded_step(step_output: Any) -> Any:
            # Extract action info from step output
            action = self._extract_from_step(step_output)
            metadata = {"framework": "crewai", "step_type": type(step_output).__name__}

            try:
                result = self._client.check(action, metadata=metadata)
                decision = result.get("decision", "ALLOW")

                if decision in ("DENY", "CIRCUIT_BREAK"):
                    reason = result.get("reason", "Policy denied")
                    if self._deny_action == "raise":
                        raise PolicyViolationError(
                            decision=decision, reason=reason,
                            policy=result.get("policy", ""),
                        )
                    # else: skip silently, CrewAI will continue

            except (PolicyViolationError, CircuitBreakerError):
                raise
            except Exception:
                pass  # Fail-open if validator unreachable

            if original_callback:
                return original_callback(step_output)

        crew.step_callback = _guarded_step
        return crew

    def _extract_from_step(self, step_output: Any) -> dict:
        """Best-effort extraction of action info from CrewAI step output."""
        if hasattr(step_output, "tool"):
            tool_name = str(step_output.tool)
            tool_input = getattr(step_output, "tool_input", {})
            if isinstance(tool_input, str):
                tool_input = {"input": tool_input}
            if tool_name in self._tool_map:
                return self._tool_map[tool_name](tool_input)
            return {"type": tool_name, **tool_input}

        if hasattr(step_output, "text"):
            return {"type": "agent_response", "content": str(step_output.text)[:500]}

        return {"type": "crew_step"}

    def close(self) -> None:
        self._client.close()


def haltchain_step(
    *,
    agent_id: str,
    api_key: str,
    base_url: str = HaltChainClient.DEFAULT_BASE,
    action_type: str = "flow_step",
    **client_kwargs: Any,
) -> Callable:
    """Decorator for CrewAI Flow steps that validates before execution.

    Usage::

        class MyFlow(Flow):
            @haltchain_step(agent_id="flow-bot", api_key="key")
            def risky_action(self):
                return transfer_funds()
    """
    client = HaltChainClient(
        agent_id=agent_id,
        api_key=api_key,
        base_url=base_url,
        **client_kwargs,
    )

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            action = {
                "type": action_type,
                "step_name": fn.__name__,
            }
            metadata = {"framework": "crewai_flow", "step_name": fn.__name__}

            result = client.check(action, metadata=metadata)
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


# ── Helpers ───────────────────────────────────────────────────────────────


def _extract_action_from_output(output: Any) -> dict:
    """Extract a HaltChain action dict from a CrewAI TaskOutput."""
    action: Dict[str, Any] = {"type": "task_output"}

    if hasattr(output, "description"):
        action["description"] = str(output.description)[:500]
    if hasattr(output, "raw"):
        raw = str(output.raw)[:1000]
        action["content"] = raw
    if hasattr(output, "agent"):
        action["agent_role"] = str(getattr(output.agent, "role", ""))

    return action


def _safe_get_description(output: Any) -> str:
    """Safely extract task description from output."""
    if hasattr(output, "description"):
        return str(output.description)[:500]
    if hasattr(output, "task") and hasattr(output.task, "description"):
        return str(output.task.description)[:500]
    return ""
