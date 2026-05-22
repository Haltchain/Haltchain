"""HaltChain Python SDK.

The safety layer between your AI agents and the real world.

Quick start
-----------
.. code-block:: python

    import haltchain

    agent = haltchain.HaltChainClient(agent_id="trader_bot_01", api_key="key")

    @agent.validate
    def execute_trade(order: dict) -> None:
        # Only runs when HaltChain says ALLOW.
        do_the_trade(order)

    # Async version:
    async_agent = haltchain.AsyncHaltChainClient(agent_id="bot", api_key="key")

    @async_agent.validate
    async def async_trade(order: dict) -> None: ...
"""

from .admin_client import AdminClient
from .async_client import AsyncHaltChainClient
from .cache import PolicyCache
from .client import Client, HaltChainClient
from .crypto import SignatureVerifier, sign_request
from .metadata import (
    build_metadata_for_check,
    build_metadata_from_langchain,
    build_multimodal_drift_payload,
)
from .exceptions import (
    CircuitBreakerError,
    GoalClarificationRequiredError,
    HaltChainError,
    KeyRotationError,
    PolicyViolationError,
    SignatureVerificationError,
    ValidationError,
    ValidatorUnavailableError,
)
from .types import (
    FeedbackOutcome,
    MultimodalSummary,
    OutcomePayload,
    ReviewEntry,
    RiskAdvisory,
    ThresholdPatchPayload,
    VariantConfig,
)

__all__ = [
    "HaltChainClient",
    "AsyncHaltChainClient",
    "AdminClient",
    "Client",  #backward compatible
    "PolicyCache",
    "SignatureVerifier",
    "sign_request",
    "HaltChainError",
    "CircuitBreakerError",
    "GoalClarificationRequiredError",
    "KeyRotationError",
    "PolicyViolationError",
    "ValidatorUnavailableError",
    "ValidationError",
    "SignatureVerificationError",
    "build_metadata_for_check",
    "build_metadata_from_langchain",
    "build_multimodal_drift_payload",
    "FeedbackOutcome",
    "MultimodalSummary",
    "OutcomePayload",
    "ReviewEntry",
    "RiskAdvisory",
    "ThresholdPatchPayload",
    "VariantConfig",
]
__version__ = "0.4.0"
