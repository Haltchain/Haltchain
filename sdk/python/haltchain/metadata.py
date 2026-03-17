from __future__ import annotations

from typing import Any, Optional


def _compact(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


def _coerce_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _extract_payload_fields(parsed_input: dict[str, Any], action: dict[str, Any]) -> Optional[list[str]]:
    direct = action.get("payload_fields")
    if isinstance(direct, list):
        vals = [str(x) for x in direct]
        return vals or None

    payload = action.get("payload")
    if isinstance(payload, dict):
        vals = [str(k) for k in payload.keys()]
        return vals or None

    if parsed_input:
        vals = [str(k) for k in parsed_input.keys() if k not in {"type", "endpoint", "method"}]
        return vals or None
    return None


def build_multimodal_drift_payload(
    *,
    text_summary: Optional[str] = None,
    code_summary: Optional[str] = None,
    tool_summary: Optional[str] = None,
    vision_summary: Optional[str] = None,
) -> dict[str, str]:
    """Build optional multimodal drift summary metadata."""
    return _compact(
        {
            "text_summary": text_summary,
            "code_summary": code_summary,
            "tool_summary": tool_summary,
            "vision_summary": vision_summary,
        }
    )


def build_metadata_for_check(
    *,
    action: dict[str, Any],
    metadata: Optional[dict[str, Any]] = None,
    conversation_id: Optional[str] = None,
    declared_services: Optional[list[str]] = None,
    accessed_service: Optional[str] = None,
    requested_columns: Any = None,
    task_necessary_columns: Any = None,
    registered_schema_fields: Optional[list[str]] = None,
    payload_fields: Optional[list[str]] = None,
    gdpr_deletion_requested: Optional[bool] = None,
    retention_days_requested: Any = None,
    multimodal_summary: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Builds normalized validator metadata for plain client flows.

    Explicit keyword arguments take precedence over values in `metadata`.
    """
    base = dict(metadata or {})

    eff_conversation_id = conversation_id or base.get("conversation_id")
    eff_declared_services = declared_services
    if eff_declared_services is None and isinstance(base.get("declared_services"), list):
        eff_declared_services = [str(x) for x in base["declared_services"]]

    eff_accessed_service = accessed_service or base.get("accessed_service") or action.get("endpoint")

    eff_requested = requested_columns if requested_columns is not None else base.get("requested_columns")
    eff_necessary = (
        task_necessary_columns
        if task_necessary_columns is not None
        else base.get("task_necessary_columns")
    )

    eff_registered = registered_schema_fields
    if eff_registered is None and isinstance(base.get("registered_schema_fields"), list):
        eff_registered = [str(x) for x in base["registered_schema_fields"]]

    eff_payload_fields = payload_fields
    if eff_payload_fields is None and isinstance(base.get("payload_fields"), list):
        eff_payload_fields = [str(x) for x in base["payload_fields"]]
    if eff_payload_fields is None:
        eff_payload_fields = _extract_payload_fields({}, action)

    eff_gdpr = (
        gdpr_deletion_requested
        if gdpr_deletion_requested is not None
        else base.get("gdpr_deletion_requested")
    )
    eff_retention = (
        retention_days_requested
        if retention_days_requested is not None
        else base.get("retention_days_requested")
    )
    eff_multimodal = multimodal_summary
    if eff_multimodal is None and isinstance(base.get("multimodal_summary"), dict):
        eff_multimodal = dict(base["multimodal_summary"])
    if isinstance(eff_multimodal, dict):
        eff_multimodal = build_multimodal_drift_payload(
            text_summary=eff_multimodal.get("text_summary"),
            code_summary=eff_multimodal.get("code_summary"),
            tool_summary=eff_multimodal.get("tool_summary"),
            vision_summary=eff_multimodal.get("vision_summary"),
        )

    normalized = {
        **base,
        "conversation_id": str(eff_conversation_id) if eff_conversation_id is not None else None,
        "declared_services": eff_declared_services,
        "accessed_service": str(eff_accessed_service) if eff_accessed_service is not None else None,
        "requested_columns": _coerce_int(eff_requested),
        "task_necessary_columns": _coerce_int(eff_necessary),
        "registered_schema_fields": [str(x) for x in eff_registered] if eff_registered else None,
        "payload_fields": [str(x) for x in eff_payload_fields] if eff_payload_fields else None,
        "gdpr_deletion_requested": bool(eff_gdpr) if isinstance(eff_gdpr, bool) else None,
        "retention_days_requested": _coerce_int(eff_retention),
        "multimodal_summary": eff_multimodal or None,
    }
    return _compact(normalized)


def build_metadata_from_langchain(
    *,
    action: dict[str, Any],
    tool_name: str,
    parsed_input: Optional[dict[str, Any]] = None,
    run_id: Any = None,
    parent_run_id: Any = None,
) -> dict[str, Any]:
    """Builds HaltChain metadata from LangChain callback context.

    This helper is heuristic and intentionally minimal. It only emits fields
    that can be inferred from current tool/action context.
    """
    inp = parsed_input or {}
    requested_columns = action.get("requested_columns", inp.get("requested_columns"))
    task_necessary_columns = action.get(
        "task_necessary_columns", inp.get("task_necessary_columns")
    )
    registered_schema_fields = action.get(
        "registered_schema_fields", inp.get("registered_schema_fields")
    )

    gdpr_deletion_requested = action.get(
        "gdpr_deletion_requested", inp.get("gdpr_deletion_requested")
    )
    retention_days_requested = action.get(
        "retention_days_requested", inp.get("retention_days_requested")
    )

    if not isinstance(registered_schema_fields, list):
        registered_schema_fields = None

    return build_metadata_for_check(
        action=action,
        conversation_id=str(parent_run_id or run_id) if (parent_run_id or run_id) else None,
        declared_services=action.get("declared_services") if isinstance(action.get("declared_services"), list) else None,
        accessed_service=action.get("accessed_service") or action.get("endpoint") or tool_name,
        requested_columns=requested_columns,
        task_necessary_columns=task_necessary_columns,
        registered_schema_fields=[str(x) for x in registered_schema_fields] if registered_schema_fields else None,
        payload_fields=_extract_payload_fields(inp, action),
        gdpr_deletion_requested=gdpr_deletion_requested if isinstance(gdpr_deletion_requested, bool) else None,
        retention_days_requested=retention_days_requested,
    )
