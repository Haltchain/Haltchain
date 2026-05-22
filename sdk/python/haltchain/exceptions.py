class HaltChainError(Exception):
    """Base exception for all HaltChain SDK errors."""


class CircuitBreakerError(HaltChainError):
    """Raised when the agent's circuit breaker is active."""

    def __init__(self, reason: str, agent_id: str) -> None:
        super().__init__(f"Circuit breaker active for agent '{agent_id}': {reason}")
        self.reason = reason
        self.agent_id = agent_id


class PolicyViolationError(HaltChainError):
    """Raised when an action violates a hard policy limit."""

    def __init__(self, reason: str, policy: str) -> None:
        super().__init__(f"Policy violation [{policy}]: {reason}")
        self.reason = reason
        self.policy = policy


class GoalClarificationRequiredError(PolicyViolationError):
    """Raised when goal drift is detected and the agent must re-declare intent via POST /goals."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason=reason, policy="GOAL_CLARIFICATION_REQUIRED")


class ValidatorUnavailableError(HaltChainError):
    """Raised when the validator is unreachable and no cached policy exists.

    Fail-secure: the action is **denied** — never allowed blindly.
    """


class ValidationError(HaltChainError):
    """Raised for malformed requests or server-side 4xx/5xx responses."""


class SignatureVerificationError(HaltChainError):
    """Raised when an Ed25519 response signature is invalid or a nonce is replayed."""


class KeyRotationError(SignatureVerificationError):
    """Raised when key rotation is detected but not permitted by the client's trust policy.

    Resolve by calling ``client.trust_new_key()`` or setting ``trust_on_rotation=True``.
    """

    def __init__(self, trusted_key_id: str, received_key_id: str) -> None:
        super().__init__(
            f"Key rotation detected: trusted key_id={trusted_key_id!r}, "
            f"received key_id={received_key_id!r}. "
            "Pass trust_on_rotation=True or call trust_new_key() to accept rotation."
        )
        self.trusted_key_id = trusted_key_id
        self.received_key_id = received_key_id
