use std::sync::Arc;
use std::convert::Infallible;
use std::time::Duration;

use async_stream::stream;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
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
use crate::audit_log::{append_audit_event, read_recent_audit_events};
use crate::auth::{
    check_and_insert_nonce, configured_api_keys, issue_admin_session_jwt, issue_jwt_token,
    rate_limit_middleware, require_admin_mfa, require_api_key, security_middleware,
    timestamp_fresh, verify_admin_session_jwt, verify_request_sig,
};
use haltchain_merkle::{DistributedMerkleVerifier, RootAttestation};
use haltchain_tendermint::{QueryRequest, TendermintBridge, TendermintBridgeConfig};
use haltchain_validator::{
    AgentVersion, AppState, ApproveRecommendationRequest, CreateVariantReq,
    RejectRecommendationRequest, ReportIntentRequest, RevertRecommendationRequest, ThresholdPatch,
    ValidationRequest, VersionLineageEntry, review::OutcomeRequest,
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

pub async fn validate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(wire): Json<WireValidationRequest>,
) -> impl IntoResponse {
    let mut req = wire.req;
    if req.agent_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id is required" })),
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

    // P0: Replay protection - check nonce and timestamp
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

    // P0: Check for replay attacks
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
    }

    info!(agent_id = %req.agent_id, action = %req.action.action_type, "validate request");

    let response = state.validate(&req).await;
    let _ = append_audit_event(json!({
        "event": "validate",
        "agent_id": req.agent_id,
        "action_type": req.action.action_type,
        "decision": response.decision.as_str(),
        "transaction_id": response.transaction_id,
        "request_nonce": wire.request_nonce,
        "request_sig": wire.request_sig,
    }));
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
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal server error" })),
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
    info!(agent_id = %agent_id, session_id = %session_id, "drift status");
    Json(state.drift_status(&agent_id, &session_id))
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
        loop {
            let batch = state.list_risk_advisories(&agent_id, Some(last_id));
            for adv in &batch {
                if adv.id > last_id {
                    last_id = adv.id;
                }
                if let Ok(data) = serde_json::to_string(adv) {
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
    state
        .record_intent(&req.agent_id, &req.goal, req.constraints)
        .await;
    Json(json!({ "status": "recorded", "agent_id": req.agent_id })).into_response()
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

async fn token_exchange(headers: HeaderMap) -> impl IntoResponse {
    // Exchange a valid static API key for a short-lived JWT (15 min).
    if let Err(e) = require_api_key(&headers) {
        return e.into_response();
    }
    // Use x-api-key as part of the sub; prefer x-agent-id if present.
    let agent_id = headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("api-key-holder");
    match issue_jwt_token(agent_id) {
        Ok(token) => {
            let _ = append_audit_event(json!({
                "event": "token_exchange",
                "agent_id": agent_id,
                "authorization": format!("Bearer {}", token),
            }));
            Json(json!({ "token": token, "expires_in": 900 })).into_response()
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
    Json(body): Json<AdminLoginRequest>,
) -> impl IntoResponse {
    let pool = match state.db.as_ref().map(|db| db.pool()) {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "database not configured" })),
            )
                .into_response();
        }
    };

    match admin_users::find_and_verify(pool, &body.email, &body.password).await {
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

fn api_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/validate", post(validate))
        .route("/auth/token", post(token_exchange))
        .route("/health", get(health))
        .route("/status/:agent_id", get(agent_status))
        .route("/goals", post(declare_goal))
        .route("/goals/:agent_id/:session_id", delete(revoke_goal))
        .route("/drift/:agent_id/:session_id", get(drift_status))
        .route("/public-key", get(public_key))
        .route("/admin/rotate-key", post(rotate_key))
        .route("/merkle/root", get(merkle_root))
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
        .route("/risk/advisories/:agent_id/stream", get(risk_advisories_stream))
        .route("/admin/thresholds", get(get_thresholds))
        .route("/admin/thresholds", patch(patch_threshold))
        .route("/admin/ab-variants", get(list_variants))
        .route("/admin/ab-variants", post(create_variant))
        .route("/agent/improvement/snapshot", post(snapshot_agent_version))
        .route("/agent/improvement/submit", post(submit_agent_improvement))
        .route("/agent/improvement/lineage/:agent_id", get(get_agent_lineage))
        .route("/agent/report-intent", post(report_intent))
        .route("/cognitive/scan", post(cognitive_scan))
        .route("/capability/risk/:agent_id", get(capability_risk_handler))
        .route("/scan/:queue_id", get(get_scan_result))
        .route("/capability/:agent_id", get(capability_trajectory_handler))
        .route("/auth/admin/login", post(admin_login))
        .route("/auth/admin/logout", post(admin_logout))
        .route("/auth/admin/me", get(admin_me))
}

pub fn build_app(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .merge(api_routes())
        .nest("/v1", api_routes())
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(middleware::from_fn(security_middleware))
        .layer(cors)
        .with_state(state)
}
