use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware,
    response::IntoResponse,
    response::sse::{Event, KeepAlive, Sse},
    routing::{delete, get, patch, post},
};
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};
use uuid::Uuid;

use crate::admin_users;
use crate::audit_log::{
    AuditQueryFilter, append_audit_event, query_audit_events, read_recent_audit_events,
};
use crate::auth::{
    check_and_insert_nonce, configured_api_keys, issue_admin_session_jwt, issue_scoped_jwt_token,
    rate_limit_middleware, require_admin_mfa, require_api_key, security_middleware,
    timestamp_fresh, validate_ingress_middleware, verify_admin_session_jwt, verify_request_sig,
};
use crate::metrics;
use crate::siem::{emit_cef, fire_webhook_if_critical, format_cef_line};
use haltchain_merkle::{DistributedMerkleVerifier, RootAttestation};
use haltchain_tendermint::{QueryRequest, TendermintBridge, TendermintBridgeConfig};
use haltchain_validator::{
    AgentVersion, AppState, ApproveRecommendationRequest, CreateVariantReq, McpInspectDecision,
    McpInspectToolCall, RejectRecommendationRequest, ReportIntentRequest,
    RevertRecommendationRequest, ThresholdPatch, ValidationRequest, VersionLineageEntry,
    review::OutcomeRequest,
};

#[derive(Debug, Deserialize)]
pub struct WireValidationRequest {
    #[serde(flatten)]
    pub req: ValidationRequest,
    pub request_nonce: String,
    pub request_timestamp: String,
    pub request_sig: String,
}

#[derive(Debug, Deserialize)]
struct GoalRequest {
    agent_id: String,
    session_id: String,
    intent: String,
}

#[derive(Debug, Deserialize)]
struct AdminLoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct RecommendationListQuery {
    status: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct LearningRunRequest {
    max_age_hours: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct RiskAdvisoryQuery {
    since_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AuditLogQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct DistributedVerifyRequest {
    root_hex: Option<String>,
    day_of_year: Option<u32>,
    attestations: Vec<RootAttestation>,
}

#[derive(Debug, Deserialize)]
struct CognitiveScanRequest {
    agent_id: String,
    trace: String,
}

#[derive(Debug, Deserialize)]
struct SnapshotVersionRequest {
    agent_id: String,
    session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SubmitImprovementRequest {
    agent_id: String,
    session_id: Option<String>,
    proposed: AgentVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestAuthMode {
    Hybrid,
    Ed25519Only,
    LegacyHmac,
}

impl RequestAuthMode {
    fn from_env() -> Self {
        match std::env::var("HALTCHAIN_REQUEST_AUTH_MODE") {
            Ok(v)
                if v.eq_ignore_ascii_case("ed25519") || v.eq_ignore_ascii_case("ed25519_only") =>
            {
                Self::Ed25519Only
            }
            Ok(v) if v.eq_ignore_ascii_case("legacy") || v.eq_ignore_ascii_case("hmac") => {
                Self::LegacyHmac
            }
            _ => Self::Hybrid,
        }
    }
}

fn has_ed25519_headers(headers: &HeaderMap) -> bool {
    headers.contains_key("x-haltchain-signature")
        && headers.contains_key("x-haltchain-timestamp")
        && headers.contains_key("x-haltchain-nonce")
        && headers.contains_key("x-haltchain-key-id")
}

pub async fn validate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(wire): Json<WireValidationRequest>,
) -> impl IntoResponse {
    let auth_mode = RequestAuthMode::from_env();
    let has_ed25519 = has_ed25519_headers(&headers);
    if auth_mode == RequestAuthMode::Ed25519Only && !has_ed25519 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "ed25519 request signature headers are required in HALTCHAIN_REQUEST_AUTH_MODE=ed25519_only"
            })),
        )
            .into_response();
    }

    let mut req = wire.req;
    if req.agent_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id is required" })),
        )
            .into_response();
    }
    if req.agent_id.len() > 256
        || !req
            .agent_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id must be <= 256 chars, alphanumeric/dash/underscore/dot only" })),
        )
            .into_response();
    }

    // api_key must travel in the X-API-Key header, never in the request body.
    let api_key = match headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        Some(k) if configured_api_keys().contains(k) => k.to_string(),
        Some(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid api_key" })),
            )
                .into_response();
        }
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "x-api-key header required" })),
            )
                .into_response();
        }
    };

    let require_legacy_hmac = match auth_mode {
        RequestAuthMode::LegacyHmac => true,
        RequestAuthMode::Hybrid => !has_ed25519,
        RequestAuthMode::Ed25519Only => false,
    };
    if require_legacy_hmac {
        // Legacy anti-replay + signature checks remain available during migration.
        if wire.request_nonce.trim().is_empty()
            || wire.request_timestamp.trim().is_empty()
            || wire.request_sig.trim().is_empty()
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "request_nonce, request_timestamp, and request_sig are required" })),
            )
                .into_response();
        }

        if !timestamp_fresh(&wire.request_timestamp) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "request_timestamp outside freshness window" })),
            )
                .into_response();
        }

        if !check_and_insert_nonce(&wire.request_nonce) {
            warn!(agent_id = %req.agent_id, nonce = %wire.request_nonce, "Replay attack detected");
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "replayed request_nonce" })),
            )
                .into_response();
        }

        if !verify_request_sig(
            &req.agent_id,
            &api_key,
            &wire.request_nonce,
            &wire.request_timestamp,
            &wire.request_sig,
        ) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid request_sig" })),
            )
                .into_response();
        }
    }

    let tenant_org = match headers
        .get("x-haltchain-org")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(raw) => match Uuid::parse_str(raw) {
            Ok(v) => Some(v),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "x-haltchain-org must be a valid UUID" })),
                )
                    .into_response();
            }
        },
        None => None,
    };

    let require_tenant_org = std::env::var("HALTCHAIN_REQUIRE_TENANT_ORG")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(true);
    if require_tenant_org && state.db.is_some() && tenant_org.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "x-haltchain-org header is required" })),
        )
            .into_response();
    }

    if !req.metadata.is_object() {
        req.metadata = json!({});
    }
    if let Some(m) = req.metadata.as_object_mut() {
        m.insert("request_nonce".to_string(), json!(wire.request_nonce));
        m.insert("request_sig".to_string(), json!(wire.request_sig));
        m.insert(
            "request_timestamp".to_string(),
            json!(wire.request_timestamp),
        );
        // Inject tier so validate_inner can gate cognitive checks.
        if let Some(tier_str) = headers
            .get("x-haltchain-tier")
            .and_then(|v| v.to_str().ok())
        {
            m.insert("scan_tier".to_string(), json!(tier_str));
        }
        if let Some(org_id) = tenant_org {
            m.insert("haltchain_org".to_string(), json!(org_id.to_string()));
        }
        if let Some(region) = headers
            .get("x-haltchain-region")
            .and_then(|v| v.to_str().ok())
        {
            m.insert("haltchain_region".to_string(), json!(region));
        }
    }

    info!(agent_id = %req.agent_id, action = %req.action.action_type, "validate request");

    let response = state.validate(&req).await;
    metrics::record_validate();
    let decision_str = response.decision.as_str();
    let intent_label = state.latest_intent_label(&req.agent_id);

    // ── Section C: SIEM integration ───────────────────────────────────────────
    // Emit a CEF line for every decision and fire a webhook for critical ones.
    let merkle_root = state.merkle.status().root_hex;
    let cef_line = format_cef_line(
        &response.transaction_id,
        &req.agent_id,
        decision_str,
        response.policy.as_deref(),
        &response.timestamp,
        merkle_root.as_deref(),
        intent_label.as_deref(),
    );
    emit_cef(&cef_line);
    fire_webhook_if_critical(
        &response.transaction_id,
        &req.agent_id,
        decision_str,
        response.policy.as_deref(),
        &response.timestamp,
    );

    if let Err(e) = append_audit_event(json!({
        "event": "validate",
        "agent_id": req.agent_id,
        "action_type": req.action.action_type,
        "decision": decision_str,
        "transaction_id": response.transaction_id,
        "request_nonce": wire.request_nonce,
        "request_sig": wire.request_sig,
    })) {
        warn!(error = %e, "failed to append audit event");
    }
    Json(response).into_response()
}

pub async fn agent_status(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    info!(agent_id = %agent_id, "status request");
    let status = state.agent_status(&agent_id).await;
    Json(status)
}

pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status":  "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "service": "haltchain-validator"
    }))
}

pub async fn health_live() -> impl IntoResponse {
    Json(json!({ "status": "ok", "check": "live" }))
}

pub async fn health_ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.readiness_check().await {
        Ok(()) => {
            // also check extension health when postgres is available
            let ext_status = state.extension_health().await;
            let all_ok = ext_status.values().all(|v| *v);
            let status_code = StatusCode::OK; // degraded still 200 for k8s
            (
                status_code,
                Json(json!({
                    "status": "ready",
                    "database": "ok",
                    "extensions": ext_status,
                    "degraded": !all_ok,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not_ready", "error": e })),
        )
            .into_response(),
    }
}

pub async fn metrics_prom(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics::prometheus_text(&state),
    )
}

pub async fn health_started(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.embedding_probe().await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "status": "started", "embedding": "ok" })),
        )
            .into_response(),
        Err(e) => {
            // HC010: emit SIEM event on embedding unavailability so operations can alert
            use crate::siem::emit_embedding_downgrade;
            let hash_dims = std::env::var("HALTCHAIN_HASH_DIMS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(384);
            emit_embedding_downgrade(&e, hash_dims);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "not_started", "error": e })),
            )
                .into_response()
        }
    }
}

async fn declare_goal(
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
    Json(req): Json<GoalRequest>,
) -> impl IntoResponse {
    if req.agent_id.trim().is_empty()
        || req.session_id.trim().is_empty()
        || req.intent.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id, session_id, and intent are required" })),
        )
            .into_response();
    }
    info!(agent_id = %req.agent_id, session_id = %req.session_id, "goal declare");

    let embedding = match state.embed_pipeline.embed_cached(&req.intent).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, agent_id = %req.agent_id, "embedding pipeline failure");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "embedding service temporarily unavailable" })),
            )
                .into_response();
        }
    };
    state
        .drift_scorer
        .lock()
        .clear(&format!("{}:{}", req.agent_id, req.session_id));
    let decl = state
        .goal_store
        .declare(&req.agent_id, &req.session_id, &req.intent, embedding);
    Json(decl).into_response()
}

pub async fn revoke_goal(
    State(state): State<Arc<AppState>>,
    Path((agent_id, session_id)): Path<(String, String)>,
) -> impl IntoResponse {
    info!(agent_id = %agent_id, session_id = %session_id, "goal revoke");
    let removed = state.goal_store.revoke(&agent_id, &session_id);
    state
        .drift_scorer
        .lock()
        .clear(&format!("{agent_id}:{session_id}"));
    if removed {
        Json(json!({ "status": "revoked" })).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "goal not found" })),
        )
            .into_response()
    }
}

pub async fn drift_status(
    State(state): State<Arc<AppState>>,
    Path((agent_id, session_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if agent_id.trim().is_empty() || session_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id and session_id are required" })),
        )
            .into_response();
    }
    info!(agent_id = %agent_id, session_id = %session_id, "drift status");
    Json(state.drift_status(&agent_id, &session_id)).into_response()
}

pub async fn public_key(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({
        "public_key_b64": state.signing.public_key_b64(),
        "key_id":         state.signing.key_id(),
        "algorithm":      "ed25519",
    }))
}

pub async fn rotate_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    let (key_id, public_key_b64) = state.signing.rotate();
    info!(key_id = %key_id, "signing key rotated");
    Json(json!({
        "status":         "rotated",
        "key_id":         key_id,
        "public_key_b64": public_key_b64,
        "algorithm":      "ed25519",
    }))
    .into_response()
}

pub async fn merkle_root(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.merkle.status())
}

pub async fn audit_chain_status() -> impl IntoResponse {
    Json(crate::audit_log::AuditChain::global().status())
}

async fn run_recommendations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<LearningRunRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    let report = state
        .run_learning_loop_once(body.max_age_hours.unwrap_or(24))
        .await;
    Json(json!({ "status": "ok", "report": report })).into_response()
}

async fn list_recommendations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<RecommendationListQuery>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = query.offset.unwrap_or(0);

    let recommendations = state.list_recommendations(query.status.as_deref()).await;
    let total = recommendations.len();
    let page = recommendations
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();

    let has_next_page = offset.saturating_add(page.len()) < total;
    let next_offset = if has_next_page {
        Some(offset + page.len())
    } else {
        None
    };

    Json(json!({
        "recommendations": page,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total_records": total,
            "has_next_page": has_next_page,
            "next_offset": next_offset
        }
    }))
    .into_response()
}

pub async fn approve_recommendation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(body): Json<ApproveRecommendationRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    match state.approve_recommendation(id, body).await {
        Ok(rec) => Json(json!({ "status": "approved", "recommendation": rec })).into_response(),
        Err(msg) => (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response(),
    }
}

pub async fn reject_recommendation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(body): Json<RejectRecommendationRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    match state.reject_recommendation(id, body).await {
        Ok(rec) => Json(json!({ "status": "rejected", "recommendation": rec })).into_response(),
        Err(msg) => (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response(),
    }
}

pub async fn revert_recommendation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(body): Json<RevertRecommendationRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    match state.revert_recommendation(id, body).await {
        Ok(rec) => Json(json!({ "status": "reverted", "recommendation": rec })).into_response(),
        Err(msg) => (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response(),
    }
}

pub async fn review_queue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    Json(json!({ "pending": state.review_pending() })).into_response()
}

pub async fn submit_outcome(
    State(state): State<Arc<AppState>>,
    Path(tx_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<OutcomeRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    if state
        .submit_review_outcome(&tx_id, body.into_outcome())
        .await
    {
        Json(json!({ "status": "recorded" })).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "transaction not found" })),
        )
            .into_response()
    }
}

async fn list_risk_advisories(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<RiskAdvisoryQuery>,
) -> impl IntoResponse {
    if let Err(err) = require_api_key(&headers) {
        return err.into_response();
    }

    let advisories = state.list_risk_advisories(&agent_id, query.since_id);
    Json(json!({ "advisories": advisories })).into_response()
}

pub async fn get_thresholds(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    let overrides: serde_json::Map<_, _> = state
        .get_thresholds()
        .into_iter()
        .map(|(k, v)| (k, json!(v)))
        .collect();
    Json(json!({ "thresholds": overrides })).into_response()
}

pub async fn patch_threshold(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ThresholdPatch>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    state.set_threshold(body.key.clone(), body.value);
    info!(key = %body.key, value = body.value, "threshold updated");
    Json(json!({ "status": "updated", "key": body.key, "value": body.value })).into_response()
}

/// SSE stream: emits new RiskAdvisory events for `agent_id` every 3 seconds.
async fn risk_advisories_stream(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    let s = stream! {
        let mut last_id: i64 = -1;
        let mut total_sent: u64 = 0;
        const MAX_SSE_EVENTS: u64 = 10_000;
        loop {
            if total_sent >= MAX_SSE_EVENTS {
                break;
            }
            let batch = state.list_risk_advisories(&agent_id, Some(last_id));
            for adv in &batch {
                if adv.id > last_id {
                    last_id = adv.id;
                }
                if let Ok(data) = serde_json::to_string(adv) {
                    total_sent += 1;
                    yield Ok::<Event, Infallible>(
                        Event::default().event("advisory").data(data),
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    };

    Sse::new(s).keep_alive(KeepAlive::default()).into_response()
}

pub async fn list_variants(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    Json(json!({ "variants": state.list_variants() })).into_response()
}

pub async fn create_variant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateVariantReq>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    if body.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "name required" })),
        )
            .into_response();
    }
    let id = Uuid::new_v4().to_string();
    info!(variant_id = %id, name = %body.name, "A/B variant created");
    state.add_variant(id.clone(), body);
    Json(json!({ "status": "created", "id": id })).into_response()
}

async fn snapshot_agent_version(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SnapshotVersionRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_api_key(&headers) {
        return err.into_response();
    }
    if req.agent_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id is required" })),
        )
            .into_response();
    }

    let version = state.snapshot_agent_version(&req.agent_id, req.session_id.as_deref());
    info!(agent_id = %req.agent_id, "snapshot agent version");
    Json(json!({ "version": version })).into_response()
}

async fn submit_agent_improvement(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SubmitImprovementRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_api_key(&headers) {
        return err.into_response();
    }
    if req.agent_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id is required" })),
        )
            .into_response();
    }
    if req.proposed.agent_id != req.agent_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "proposed.agent_id must match agent_id" })),
        )
            .into_response();
    }

    let decision = state.submit_improvement(&req.agent_id, req.proposed, req.session_id.as_deref());
    info!(agent_id = %req.agent_id, "submit agent improvement");
    Json(json!({ "decision": decision })).into_response()
}

async fn get_agent_lineage(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    let lineage: Vec<VersionLineageEntry> = state.get_version_lineage(&agent_id);
    info!(agent_id = %agent_id, entries = lineage.len(), "lineage query");
    Json(json!({ "agent_id": agent_id, "lineage": lineage })).into_response()
}

pub async fn report_intent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ReportIntentRequest>,
) -> impl IntoResponse {
    if req.agent_id.trim().is_empty() || req.goal.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id and goal required" })),
        )
            .into_response();
    }
    info!(agent_id = %req.agent_id, "intent reported");
    let record = state
        .record_intent(&req.agent_id, &req.goal, req.constraints)
        .await;
    Json(json!({
        "status": "recorded",
        "agent_id": req.agent_id,
        "intent_label": record.intent_label,
        "intent_confidence": record.intent_confidence,
        "research_score": record.research_score,
        "intent_score": record.intent_score,
    }))
    .into_response()
}

async fn cognitive_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CognitiveScanRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_api_key(&headers) {
        return err.into_response();
    }
    if req.agent_id.trim().is_empty() || req.trace.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id and trace are required" })),
        )
            .into_response();
    }
    let assessment = state.cognitive_assessment(&req.trace);
    state
        .capability
        .update_trajectory(&req.agent_id, &req.trace);
    info!(agent_id = %req.agent_id, "cognitive scan");
    Json(json!({ "agent_id": req.agent_id, "assessment": assessment })).into_response()
}

async fn capability_risk_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_api_key(&headers) {
        return err.into_response();
    }
    let risk: serde_json::Value = match state.capability_risk(&agent_id) {
        Some(r) => serde_json::to_value(r).unwrap_or(json!("Acceptable")),
        None => json!("Acceptable"),
    };
    info!(agent_id = %agent_id, "capability risk assessment");
    Json(json!({ "agent_id": agent_id, "risk": risk })).into_response()
}

async fn get_scan_result(
    State(state): State<Arc<AppState>>,
    Path(queue_id): Path<Uuid>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_api_key(&headers) {
        return err.into_response();
    }
    match state.get_scan_result(queue_id).await {
        Some(result) => Json(json!({ "queue_id": queue_id, "result": result })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "scan not completed or not found" })),
        )
            .into_response(),
    }
}

async fn capability_trajectory_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_api_key(&headers) {
        return err.into_response();
    }
    let breakdown = state.capability_trajectory(&agent_id);
    info!(agent_id = %agent_id, "capability trajectory");
    Json(json!({ "agent_id": agent_id, "trajectory": breakdown })).into_response()
}

async fn mcp_inspect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(call): Json<McpInspectToolCall>,
) -> impl IntoResponse {
    if let Err(err) = require_api_key(&headers) {
        return err.into_response();
    }

    let org_header = match headers
        .get("x-haltchain-org")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(v) => v,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "x-haltchain-org header is required" })),
            )
                .into_response();
        }
    };

    match Uuid::parse_str(org_header) {
        Ok(org_id) if org_id != call.org_id => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "x-haltchain-org must match body.org_id" })),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "x-haltchain-org must be a valid UUID" })),
            )
                .into_response();
        }
    }

    match state.inspect_mcp_tool_call(&call).await {
        Ok(out) => {
            let latency_ms = (out.latency_us as f64) / 1000.0;
            let proof = serde_json::to_value(&out.proof).unwrap_or(json!({}));
            match out.decision {
                McpInspectDecision::Allow => Json(json!({
                    "decision": "allow",
                    "result": "allow",
                    "latency_ms": latency_ms,
                    "proof": proof,
                }))
                .into_response(),
                McpInspectDecision::Block { reason, intent } => Json(json!({
                    "decision": "block",
                    "result": "block",
                    "reason": reason,
                    "intent": intent,
                    "latency_ms": latency_ms,
                    "proof": proof,
                }))
                .into_response(),
                McpInspectDecision::Quarantine {
                    review_id,
                    reason,
                    intent,
                } => Json(json!({
                    "decision": "quarantine",
                    "result": "quarantine",
                    "review_id": review_id,
                    "reason": reason,
                    "intent": intent,
                    "latency_ms": latency_ms,
                    "proof": proof,
                }))
                .into_response(),
            }
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct TokenExchangeRequest {
    #[serde(default)]
    scopes: Vec<String>,
}

async fn token_exchange(
    headers: HeaderMap,
    body: Option<Json<TokenExchangeRequest>>,
) -> impl IntoResponse {
    // Exchange a valid static API key for a short-lived JWT (15 min).
    if let Err(e) = require_api_key(&headers) {
        return e.into_response();
    }
    // Use x-api-key as part of the sub; prefer x-agent-id if present.
    let agent_id = headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("api-key-holder");
    let scopes: Vec<String> = body.map(|b| b.0.scopes).unwrap_or_default();
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    match issue_scoped_jwt_token(agent_id, &scope_refs) {
        Ok(token) => {
            if let Err(e) = append_audit_event(json!({
                "event": "token_exchange",
                "agent_id": agent_id,
                "scopes": scopes,
            })) {
                warn!(error = %e, "failed to append audit event for token exchange");
            }
            let scp_str = scopes.join(" ");
            Json(json!({ "token": token, "expires_in": 900, "scopes": scp_str })).into_response()
        }
        Err(msg) => (StatusCode::NOT_IMPLEMENTED, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn admin_read_audit_log(
    headers: HeaderMap,
    Query(query): Query<AuditLogQuery>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    match read_recent_audit_events(limit) {
        Ok(events) => Json(json!({ "events": events, "limit": limit })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

/// `POST /audit/query` — Filtered audit log search.
///
/// Accepts a JSON body:
/// ```json
/// {
///   "time_from": 1700000000,   // epoch seconds, optional
///   "time_to":   1700099999,   // epoch seconds, optional
///   "agent_id":  "agent-01",   // exact match, optional
///   "decision":  "DENY",       // case-insensitive, optional
///   "limit":     50            // max events returned, optional (default 100, max 500)
/// }
/// ```
#[derive(Debug, serde::Deserialize)]
pub(crate) struct AuditQueryRequest {
    time_from: Option<i64>,
    time_to: Option<i64>,
    agent_id: Option<String>,
    decision: Option<String>,
    limit: Option<usize>,
}

pub async fn audit_query(
    headers: HeaderMap,
    Json(body): Json<AuditQueryRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_api_key(&headers) {
        return err.into_response();
    }
    let limit = body.limit.unwrap_or(100).clamp(1, 500);
    let filter = AuditQueryFilter {
        time_from: body.time_from,
        time_to: body.time_to,
        agent_id: body.agent_id,
        decision: body.decision,
        limit,
    };
    match query_audit_events(&filter) {
        Ok(result) => Json(json!({
            "events": result.events,
            "count": result.events.len(),
            "scanned": result.scanned,
            "limit": limit,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e })),
        )
            .into_response(),
    }
}

async fn admin_tendermint_readiness(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    let bridge = TendermintBridge::new(state, TendermintBridgeConfig::from_env());
    Json(json!({ "bft_readiness": bridge.bft_readiness_report() })).into_response()
}

async fn admin_verify_distributed_merkle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DistributedVerifyRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }

    let status = state.merkle.status();
    let root_hex = match body.root_hex.or(status.root_hex) {
        Some(v) => v,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "no merkle root available" })),
            )
                .into_response();
        }
    };
    let day = body.day_of_year.unwrap_or(status.day_of_year);
    let verifier = DistributedMerkleVerifier::from_env();
    let verification = verifier.verify(&root_hex, day, &body.attestations);
    Json(json!({
        "root_hex": root_hex,
        "day_of_year": day,
        "distributed_verification": verification
    }))
    .into_response()
}

// ─── ABCI Bridge Endpoints ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AbciTxRequest {
    /// Hex or base64 encoded transaction bytes, OR a raw JSON object.
    tx: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct AbciQueryRequest {
    path: String,
    data: Option<String>,
    height: Option<i64>,
    prove: Option<bool>,
}

/// POST /admin/abci/check-tx
/// Run ABCI CheckTx (validate before mempool entry) against the bridge.
async fn admin_abci_check_tx(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AbciTxRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    let tx_bytes = match serde_json::to_vec(&body.tx) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("tx serialization error: {e}") })),
            )
                .into_response();
        }
    };
    let bridge = TendermintBridge::from_env(state);
    match bridge.check_tx(&tx_bytes).await {
        Ok(resp) => Json(json!({ "check_tx": resp })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /admin/abci/deliver-tx
/// Execute tx with quorum (2-of-3) via ABCI DeliverTx.
async fn admin_abci_deliver_tx(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AbciTxRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    let tx_bytes = match serde_json::to_vec(&body.tx) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("tx serialization error: {e}") })),
            )
                .into_response();
        }
    };
    let bridge = TendermintBridge::from_env(state);
    match bridge.deliver_tx(&tx_bytes).await {
        Ok(resp) => Json(json!({ "deliver_tx": resp })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /admin/abci/query
/// State proof query for audit — returns Merkle root, config, or agent state.
async fn admin_abci_query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AbciQueryRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    let bridge = TendermintBridge::from_env(state);
    let resp = bridge.query(&QueryRequest {
        path: body.path,
        data: body.data,
        height: body.height,
        prove: body.prove,
    });
    Json(json!({ "query": resp })).into_response()
}

async fn admin_login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AdminLoginRequest>,
) -> impl IntoResponse {
    // Rate limit login attempts by IP to mitigate brute-force attacks.
    let client_ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .unwrap_or("unknown");
    {
        use crate::auth::rate_limiter;
        let limiter = rate_limiter();
        // Use a dedicated key namespace for login attempts (stricter: 10 attempts/window).
        if limiter
            .check(&format!("login:{client_ip}"), None, None)
            .is_err()
        {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "too many login attempts, try again later" })),
            )
                .into_response();
        }
    }

    let db = match state.db.as_deref() {
        Some(d) => d,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "database not configured" })),
            )
                .into_response();
        }
    };

    match admin_users::find_and_verify_backend(db, &body.email, &body.password).await {
        Some(user) => {
            let token = issue_admin_session_jwt(&user.email);
            Json(json!({ "token": token })).into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid credentials" })),
        )
            .into_response(),
    }
}

async fn admin_logout() -> impl IntoResponse {
    Json(json!({ "ok": true }))
}

async fn admin_me(headers: HeaderMap) -> impl IntoResponse {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    match token.and_then(verify_admin_session_jwt) {
        Some(email) => Json(json!({ "email": email })).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "no active admin session" })),
        )
            .into_response(),
    }
}

// ─── Phase 2: Agent Registry Endpoints ────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AgentRegistryRequest {
    agent_id: String,
}

async fn admin_register_agent(
    headers: HeaderMap,
    Json(body): Json<AgentRegistryRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    if body.agent_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id is required" })),
        )
            .into_response();
    }
    haltchain_validator::agent_registry::AgentRegistry::global().register(&body.agent_id);
    if let Err(e) = append_audit_event(json!({
        "event": "agent_registered",
        "agent_id": body.agent_id,
    })) {
        warn!(error = %e, "failed to log agent registration");
    }
    info!(agent_id = %body.agent_id, "agent registered");
    Json(json!({ "status": "registered", "agent_id": body.agent_id })).into_response()
}

async fn admin_unregister_agent(
    headers: HeaderMap,
    Json(body): Json<AgentRegistryRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    if body.agent_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id is required" })),
        )
            .into_response();
    }
    haltchain_validator::agent_registry::AgentRegistry::global().unregister(&body.agent_id);
    if let Err(e) = append_audit_event(json!({
        "event": "agent_unregistered",
        "agent_id": body.agent_id,
    })) {
        warn!(error = %e, "failed to log agent unregistration");
    }
    info!(agent_id = %body.agent_id, "agent unregistered");
    Json(json!({ "status": "unregistered", "agent_id": body.agent_id })).into_response()
}

// Phase 3: Force-Halt Kill Switch

async fn admin_force_halt(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    if agent_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id is required" })),
        )
            .into_response();
    }
    // Force-halt: trip circuit breaker with a long duration.
    let reason = format!(
        "ADMIN_FORCE_HALT by operator at {}",
        chrono::Utc::now().to_rfc3339()
    );
    state.force_halt_agent(&agent_id, &reason).await;
    if let Err(e) = append_audit_event(json!({
        "event": "force_halt",
        "agent_id": agent_id,
        "reason": reason,
    })) {
        warn!(error = %e, "failed to log force halt");
    }
    info!(agent_id = %agent_id, "agent force-halted");
    Json(json!({ "status": "halted", "agent_id": agent_id, "reason": reason })).into_response()
}

// Phase 3: Emergency Kill — system-wide containment

async fn emergency_containment(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    let reason = format!(
        "EMERGENCY_CONTAINMENT by operator at {}",
        chrono::Utc::now().to_rfc3339()
    );
    let halted = state.emergency_halt_all(&reason).await;
    if let Err(e) = append_audit_event(json!({
        "event": "emergency_containment",
        "agents_halted": halted,
        "reason": reason,
    })) {
        warn!(error = %e, "failed to log emergency containment");
    }
    info!(agents_halted = halted, "emergency containment activated");
    Json(json!({
        "status": "emergency_containment_active",
        "agents_halted": halted,
        "reason": reason
    }))
    .into_response()
}

// ── GitOps webhook: policy sync ───────────────────────────────────────────────

/// Verifies a GitHub-style `X-Hub-Signature-256` HMAC against
/// `HALTCHAIN_WEBHOOK_SECRET`.
fn verify_webhook_signature(secret: &[u8], body: &[u8], header: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let expected_hex = header.strip_prefix("sha256=").unwrap_or(header);
    let Ok(expected) = hex::decode(expected_hex) else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// POST /admin/webhook/policy-sync
///
/// Accepts a raw YAML body (the new policy file) with a
/// `X-Hub-Signature-256` header for authentication.
/// On success the active policy is hot-swapped and the generation counter
/// is bumped.
async fn webhook_policy_sync(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let secret = match std::env::var("HALTCHAIN_WEBHOOK_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            warn!("webhook rejected: HALTCHAIN_WEBHOOK_SECRET not configured");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "webhook not configured"})),
            )
                .into_response();
        }
    };

    let sig_header = match headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h.to_owned(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "missing X-Hub-Signature-256"})),
            )
                .into_response();
        }
    };

    if !verify_webhook_signature(secret.as_bytes(), &body, &sig_header) {
        warn!("webhook rejected: invalid signature");
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "invalid signature"})),
        )
            .into_response();
    }

    // Parse the body as a policy YAML.
    let pf: haltchain_rules::PolicyFile = match serde_yaml::from_slice(&body) {
        Ok(pf) => pf,
        Err(e) => {
            warn!(error = %e, "webhook rejected: invalid policy YAML");
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": format!("invalid YAML: {e}")})),
            )
                .into_response();
        }
    };

    // Validate that the policy can build an evaluator.
    if let Err(e) = haltchain_rules::RuleEvaluator::new(&pf) {
        warn!(error = %e, "webhook rejected: policy fails evaluation build");
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": format!("policy validation failed: {e}")})),
        )
            .into_response();
    }

    // Hot-swap the active policy via the rules handle.
    // push_policy returns false when rules_handle is None (server started without
    // POLICY_FILE), meaning the push would be silently dropped.  That is an error.
    if !state.push_policy(pf) {
        warn!("webhook rejected: policy engine not initialised (POLICY_FILE not configured)");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "policy engine not initialised; start the server with POLICY_FILE to enable hot-reload"})),
        )
            .into_response();
    }
    let generation = state.policy_generation();

    if let Err(e) = append_audit_event(json!({
        "event": "webhook_policy_sync",
        "generation": generation,
    })) {
        warn!(error = %e, "failed to log webhook policy sync");
    }

    info!(generation, "policy hot-swapped via webhook");
    Json(json!({
        "status": "ok",
        "generation": generation,
    }))
    .into_response()
}

// ── FTS Audit Search (Phase 1b) ───────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct AuditFtsRequest {
    q: String,
    limit: Option<i64>,
}

async fn audit_fts_search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AuditFtsRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_api_key(&headers) {
        return err.into_response();
    }
    if body.q.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "q is required"})),
        )
            .into_response();
    }
    let limit = body.limit.unwrap_or(50).clamp(1, 200);

    // parse x-haltchain-org; required for tenant scoping
    let org_id = match headers
        .get("x-haltchain-org")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(raw) => match Uuid::parse_str(raw) {
            Ok(id) => id,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "x-haltchain-org must be a valid UUID"})),
                )
                    .into_response();
            }
        },
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "x-haltchain-org header is required for FTS"})),
            )
                .into_response();
        }
    };

    let db_backend = match state.db.as_ref() {
        Some(db) => db,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "FTS requires PostgreSQL; running in standalone mode"})),
            )
                .into_response();
        }
    };

    match db_backend.as_postgres() {
        Some(pg) => match pg.search_audit_decisions_scoped(org_id, &body.q, limit).await {
            Ok(results) => {
                let rows: Vec<_> = results
                    .iter()
                    .map(|r| {
                        json!({
                            "id": r.id,
                            "transaction_id": r.transaction_id,
                            "agent_id": r.agent_id,
                            "decision": r.decision,
                            "reason": r.reason,
                            "policy_code": r.policy_code,
                            "decided_at": r.decided_at,
                        })
                    })
                    .collect();
                Json(json!({"results": rows, "count": rows.len(), "query": body.q})).into_response()
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("FTS query failed: {e}")})),
            )
                .into_response(),
        },
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "FTS requires PostgreSQL; SQLite does not support TSVector"})),
        )
            .into_response(),
    }
}

// ── DB-backed policy reload (Phase 1b: advisory lock hot-reload) ───────────────

#[derive(Debug, serde::Deserialize)]
struct PolicyDbReloadRequest {
    policy_name: String,
    rules: serde_json::Value,
    org_id: uuid::Uuid,
}

async fn admin_policy_db_reload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PolicyDbReloadRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin_mfa(&headers) {
        return err.into_response();
    }
    if body.policy_name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "policy_name required"})),
        )
            .into_response();
    }

    let db_backend = match state.db.as_ref() {
        Some(db) => db,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "DB policy reload requires PostgreSQL"})),
            )
                .into_response();
        }
    };

    match db_backend.as_postgres() {
        Some(pg) => {
            match pg
                .reload_policy_with_lock(body.org_id, &body.policy_name, body.rules)
                .await
            {
                Ok(()) => {
                    // Read it back so policy_configs is not write-only; validate it parses
                    let readback = pg.get_policy_config(body.org_id, &body.policy_name).await;
                    let (version, readable) = match readback {
                        Ok(Some(ref cfg)) => {
                            use haltchain_policy::JsonbPolicy;
                            let _parsed = JsonbPolicy::from_jsonb(&cfg.rules);
                            info!(
                                policy_name = %body.policy_name,
                                version = cfg.version,
                                "DB policy config reloaded and verified readable"
                            );
                            (cfg.version, true)
                        }
                        _ => {
                            warn!(policy_name = %body.policy_name, "policy reload wrote but read-back failed");
                            (0, false)
                        }
                    };
                    Json(json!({
                        "status": "ok",
                        "policy_name": body.policy_name,
                        "version": version,
                        "readable": readable
                    })).into_response()
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("policy reload failed: {e}")})),
                )
                    .into_response(),
            }
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "DB policy reload requires PostgreSQL"})),
        )
            .into_response(),
    }
}

fn api_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/validate", post(validate))
        .route("/auth/token", post(token_exchange))
        .route("/health", get(health))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/health/started", get(health_started))
        .route("/metrics", get(metrics_prom))
        .route("/status/:agent_id", get(agent_status))
        .route("/goals", post(declare_goal))
        .route("/goals/:agent_id/:session_id", delete(revoke_goal))
        .route("/drift/:agent_id/:session_id", get(drift_status))
        .route("/public-key", get(public_key))
        .route("/admin/rotate-key", post(rotate_key))
        .route("/merkle/root", get(merkle_root))
        .route("/audit/chain", get(audit_chain_status))
        .route("/audit/query", post(audit_query))
        .route("/admin/review-queue", get(review_queue))
        .route("/admin/review-queue/:tx_id/outcome", post(submit_outcome))
        .route("/admin/recommendations/run", post(run_recommendations))
        .route("/admin/recommendations", get(list_recommendations))
        .route("/admin/audit-log", get(admin_read_audit_log))
        .route(
            "/admin/tendermint/readiness",
            get(admin_tendermint_readiness),
        )
        .route(
            "/admin/merkle/verify-distributed",
            post(admin_verify_distributed_merkle),
        )
        .route("/admin/abci/check-tx", post(admin_abci_check_tx))
        .route("/admin/abci/deliver-tx", post(admin_abci_deliver_tx))
        .route("/admin/abci/query", post(admin_abci_query))
        .route(
            "/admin/recommendations/:id/approve",
            post(approve_recommendation),
        )
        .route(
            "/admin/recommendations/:id/reject",
            post(reject_recommendation),
        )
        .route(
            "/admin/recommendations/:id/revert",
            post(revert_recommendation),
        )
        .route("/risk/advisories/:agent_id", get(list_risk_advisories))
        .route(
            "/risk/advisories/:agent_id/stream",
            get(risk_advisories_stream),
        )
        .route("/admin/thresholds", get(get_thresholds))
        .route("/admin/thresholds", patch(patch_threshold))
        .route("/admin/ab-variants", get(list_variants))
        .route("/admin/ab-variants", post(create_variant))
        .route("/agent/improvement/snapshot", post(snapshot_agent_version))
        .route("/agent/improvement/submit", post(submit_agent_improvement))
        .route(
            "/agent/improvement/lineage/:agent_id",
            get(get_agent_lineage),
        )
        .route("/agent/report-intent", post(report_intent))
        .route("/cognitive/scan", post(cognitive_scan))
        .route("/capability/risk/:agent_id", get(capability_risk_handler))
        .route("/scan/:queue_id", get(get_scan_result))
        .route("/capability/:agent_id", get(capability_trajectory_handler))
        .route("/mcp/inspect", post(mcp_inspect))
        .route("/auth/admin/login", post(admin_login))
        .route("/auth/admin/logout", post(admin_logout))
        .route("/auth/admin/me", get(admin_me))
        // ── Phase 2: Agent registry ──
        .route("/admin/agents/register", post(admin_register_agent))
        .route("/admin/agents/unregister", post(admin_unregister_agent))
        // ── Phase 3: Force-halt kill switch ──
        .route("/admin/force-halt/:agent_id", post(admin_force_halt))
        .route("/admin/emergency-containment", post(emergency_containment))
        .route("/admin/webhook/policy-sync", post(webhook_policy_sync))
        .route("/audit/fts", post(audit_fts_search))
        .route("/admin/policy-db/reload", post(admin_policy_db_reload))
}

/// Maximum allowed request body size (10 MB).
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

pub fn build_app(state: Arc<AppState>) -> Router {
    let allowed_origins = std::env::var("HALTCHAIN_CORS_ORIGINS")
        .ok()
        .filter(|s| !s.is_empty());
    let cors = if let Some(raw) = allowed_origins {
        let origins: Vec<_> = raw
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    };

    Router::new()
        .merge(api_routes())
        .nest("/v1", api_routes())
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(middleware::from_fn(security_middleware))
        .layer(middleware::from_fn(rate_limit_middleware))
        // Keep validate ingress gate outermost so 429 can trigger before
        // expensive auth/signature/DB paths during saturation.
        .layer(middleware::from_fn(validate_ingress_middleware))
        .layer(cors)
        .with_state(state)
}
