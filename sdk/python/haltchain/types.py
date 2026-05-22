"""Shared TypedDict types for requests and responses."""

from __future__ import annotations

import enum
from typing import Any, Dict, List, Literal, Optional, TypedDict


class ValidationRequest(TypedDict, total=False):
    """Shape of the JSON body sent to POST /validate."""
    agent_id: str
    api_key: str
    action: Dict[str, Any]
    metadata: Dict[str, Any]
    session_id: Optional[str]


class ValidationResponse(TypedDict, total=False):
    """Shape of the JSON body returned from POST /validate."""
    decision: Literal["ALLOW", "DENY", "CIRCUIT_BREAK", "GOAL_CLARIFICATION_REQUIRED"]
    reason: str
    policy: str
    agent_id: str
    timestamp: str


# Feedback / outcome types

class FeedbackOutcome(str, enum.Enum):
    """Valid verdict values for outcome submissions."""
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    EXPECTED_EDGE_CASE = "EXPECTED_EDGE_CASE"

    @classmethod
    def validate(cls, value: str) -> "FeedbackOutcome":
        """Parse and validate a verdict string; raises ValueError on invalid input."""
        try:
            return cls(value)
        except ValueError:
            valid = [m.value for m in cls]
            raise ValueError(f"Invalid verdict {value!r}. Must be one of: {valid}")


class OutcomePayload(TypedDict, total=False):
    """Body for POST /admin/review-queue/:tx_id/outcome."""
    verdict: str  # FeedbackOutcome value
    impact_usd: Optional[float]
    reviewer_id: Optional[str]
    notes: Optional[str]


class ReviewOutcome(TypedDict, total=False):
    """Stored outcome attached to a ReviewEntry."""
    verdict: str
    impact_usd: Optional[float]
    reviewer_id: Optional[str]
    notes: Optional[str]
    reviewed_at: str


class ReviewEntry(TypedDict, total=False):
    """A single entry from GET /admin/review-queue."""
    transaction_id: str
    agent_id: str
    decision: str
    policy_code: Optional[str]
    reason: Optional[str]
    created_at: str
    outcome: Optional[ReviewOutcome]


#Admin / threshold / variant types

class ThresholdPatchPayload(TypedDict):
    """Body for PATCH /admin/thresholds."""
    key: str
    value: float


class VariantConfig(TypedDict, total=False):
    """A/B policy variant definition for POST /admin/ab-variants."""
    name: str
    policy: str
    weight: float
    metadata: Dict[str, Any]


class MultimodalSummary(TypedDict, total=False):
    """Optional multimodal drift summary metadata."""
    text_summary: str
    code_summary: str
    tool_summary: str
    vision_summary: str


class RiskAdvisory(TypedDict, total=False):
    """Cross-agent risk advisory emitted by /risk/advisories/:agent_id."""
    id: int
    source_agent_id: str
    target_agent_id: str
    policy_code: str
    reason: str
    trigger_transaction_id: str
    created_at: str
