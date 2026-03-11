use std::sync::Arc;

use axum::{extract::{Path, State},http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use haltchain_validator::{AppState, ValidationRequest};

//handlers
//accepts validation request, go through full policy and circuit breaker and returns a response
async fn validate(State(state): State<Arc<AppState>>,Json(req): Json<ValidationRequest>,
) -> impl IntoResponse {
    if req.agent_id.trim().is_empty() || req.api_key.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id and api_key are required" })),
        )
            .into_response();
    }

    info!(agent_id = %req.agent_id, action = %req.action.action_type, "validate request");

    let response = state.validate(&req).await;
    Json(response).into_response()
}

//circuit breaker status and cur action count
async fn agent_status(State(state): State<Arc<AppState>>,Path(agent_id): Path<String>,
) -> impl IntoResponse {
    info!(agent_id = %agent_id, "status request");
    let status = state.agent_status(&agent_id).await;
    Json(status)
}

//get health (used by load-balancers)
async fn health() -> impl IntoResponse {
    Json(json!({
        "status":  "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "service": "haltchain-validator"
    }))
}
//server
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "haltchain_api=info,tower_http=debug".into()),
        )
        .init();

    let state = AppState::new();
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    let app = Router::new().route("/validate", post(validate)).route("/health", get(health)).route("/status/:agent_id", get(agent_status)).layer(cors).with_state(state);

    let addr = "0.0.0.0:3000";
    info!("HaltChain Validator listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
