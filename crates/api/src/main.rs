mod admin_users;
mod audit_log;
mod auth;
mod handlers;
mod metrics;
mod siem;
mod tls;

use std::{sync::Arc, time::Duration};

use clap::Parser;
use haltchain_validator::{AppState, DeployProfile};
use tracing::info;

// Re-exports used by the test module via `use super::*`.
pub use axum::http::StatusCode;
pub use handlers::build_app;
pub use serde_json::json;

#[derive(Parser)]
#[command(name = "haltchain", about = "HaltChain AI safety validator")]
struct Cli {
    /// Deployment profile: "full" (default) or "standalone" (single-binary, no DB).
    #[arg(long, default_value = "full")]
    profile: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "haltchain_api=info,tower_http=debug".into()),
        )
        .init();

    let cli = Cli::parse();
    let deploy_profile = match cli.profile.as_str() {
        "standalone" => DeployProfile::Standalone,
        "full" => DeployProfile::Full,
        other => {
            eprintln!("unknown profile '{other}', expected 'full' or 'standalone'");
            std::process::exit(1);
        }
    };

    let state = match deploy_profile {
        DeployProfile::Standalone => {
            info!("starting in standalone mode (SQLite, hash embeddings)");
            AppState::new_standalone().await
        }
        DeployProfile::Full => AppState::new_async().await,
    };
    {
        let learning_interval: u64 = std::env::var("HALTCHAIN_LEARNING_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120);
        let learning_max_age: i64 = std::env::var("HALTCHAIN_LEARNING_MAX_AGE_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(24);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            info!(
                interval_secs = learning_interval,
                "background worker started: learning-loop"
            );
            let mut ticker = tokio::time::interval(Duration::from_secs(learning_interval));
            loop {
                ticker.tick().await;
                let report = state.run_learning_loop_once(learning_max_age).await;
                if report.generated > 0 {
                    info!(
                        generated = report.generated,
                        considered_outcomes = report.considered_outcomes,
                        "learning-loop generated recommendations"
                    );
                }
            }
        });
    }
    {
        let wal_interval: u64 = std::env::var("HALTCHAIN_WAL_FLUSH_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            info!(
                interval_secs = wal_interval,
                "background worker started: WAL flush"
            );
            let mut ticker = tokio::time::interval(Duration::from_secs(wal_interval));
            loop {
                ticker.tick().await;
                state.flush_capability_wal().await;
            }
        });
    }
    {
        tokio::spawn(async move {
            let interval_secs = audit_log::audit_prune_interval_secs();
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                match tokio::task::spawn_blocking(audit_log::prune_expired_audit_events).await {
                    Ok(Ok(report)) => {
                        if report.removed_lines > 0 {
                            info!(
                                removed_lines = report.removed_lines,
                                kept_lines = report.kept_lines,
                                skipped_lines = report.skipped_lines,
                                total_lines = report.total_lines,
                                retention_days = audit_log::audit_retention_days(),
                                "audit-log retention pruning removed expired events"
                            );
                        }
                    }
                    Ok(Err(err)) => {
                        tracing::warn!("audit-log retention pruning failed: {err}");
                    }
                    Err(err) => {
                        tracing::warn!("audit-log retention worker join failed: {err}");
                    }
                }
            }
        });
    }

    crate::auth::spawn_validate_adaptive_controller();

    {
        // Rate limiter stale-entry cleanup
        tokio::spawn(async move {
            info!("background worker started: rate-limiter cleanup");
            let mut ticker = tokio::time::interval(Duration::from_secs(120));
            loop {
                ticker.tick().await;
                crate::auth::rate_limiter().cleanup();
            }
        });
    }

    // Deep-scan async worker: dequeues Standard-tier tasks, runs cognitive deep_scan.
    info!("spawning deep-scan worker");
    state.spawn_scan_worker();

    if let Some(db) = state.db.as_deref() {
        admin_users::bootstrap_if_configured(db).await;
    }

    let app = build_app(state);
    // Respect PORT when provided; default to 8080 for local/dev.
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = format!("0.0.0.0:{port}");

    if let Some(acceptor) = tls::tls_acceptor_from_env() {
        info!("HaltChain Validator listening on {addr} (TLS)");
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("failed to bind TCP listener (is the port in use?)");
        // Bound concurrent TLS connections to prevent resource exhaustion.
        let max_conns: usize = std::env::var("HALTCHAIN_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_conns));
        loop {
            let (tcp_stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!("TCP accept error: {e}");
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let app = app.clone();
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!("Max TLS connections reached, dropping new connection");
                    drop(tcp_stream);
                    continue;
                }
            };
            tokio::spawn(async move {
                let _permit = permit; // held until task completes
                // TLS handshake with timeout to prevent slowloris.
                let tls_stream = match tokio::time::timeout(
                    Duration::from_secs(10),
                    acceptor.accept(tcp_stream),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        tracing::warn!("TLS handshake failed: {e}");
                        return;
                    }
                    Err(_) => {
                        tracing::warn!("TLS handshake timed out");
                        return;
                    }
                };
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let svc = hyper::service::service_fn(move |req| {
                    let mut app = app.clone();
                    async move { tower::Service::call(&mut app, req).await }
                });
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                {
                    tracing::warn!("HTTP/TLS connection error: {e}");
                }
            });
        }
    } else {
        info!("HaltChain Validator listening on {addr} (plain HTTP)");
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("failed to bind TCP listener (is the port in use?)");
        axum::serve(listener, app).await.expect("HTTP server error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request},
    };
    use chrono::Utc;
    use haltchain_validator::review::{ReviewEntry, ReviewOutcome};
    use serde_json::Value;
    use std::time::Duration;
    use tower::ServiceExt;
    use uuid::Uuid;

    fn admin_key_for_test() -> String {
        crate::auth::configured_admin_keys()
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "dev-admin-key".to_string())
    }

    fn build_admin_request(method: Method, uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-admin-key", admin_key_for_test())
            .body(Body::from(body.to_string()))
            .expect("request should build")
    }

    async fn response_json(resp: axum::http::Response<Body>) -> Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body should read");
        serde_json::from_slice(&bytes).expect("response should be json")
    }

    #[tokio::test]
    async fn metrics_endpoint_includes_request_and_cache_metrics() {
        let state = AppState::new();
        let app = build_app(state);

        crate::metrics::record_validate();

        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("metrics endpoint should respond");

        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let text = String::from_utf8(body.to_vec()).expect("metrics should be utf-8");

        assert!(text.contains("haltchain_validate_requests_total"));
        assert!(text.contains("haltchain_decision_cache_entries"));
        assert!(text.contains("haltchain_decision_cache_hit_rate"));
    }

    #[tokio::test]
    async fn recommendation_endpoints_support_apply_and_revert() {
        let state = AppState::new();
        let app = build_app(Arc::clone(&state));

        let make_entry = |tx: String, verdict: &str| ReviewEntry {
            transaction_id: tx,
            agent_id: "agent-a".to_string(),
            decision: "DENY".to_string(),
            policy_code: Some("TOKEN_RATE_EXCEEDED".to_string()),
            reason: None,
            created_at: Utc::now(),
            outcome: Some(ReviewOutcome {
                verdict: verdict.to_string(),
                impact_usd: None,
                reviewer_id: Some("reviewer-1".to_string()),
                notes: None,
                reviewed_at: Utc::now(),
            }),
        };

        state
            .review_queue
            .push(make_entry(Uuid::new_v4().to_string(), "FALSE_POSITIVE"));
        state
            .review_queue
            .push(make_entry(Uuid::new_v4().to_string(), "FALSE_POSITIVE"));
        state
            .review_queue
            .push(make_entry(Uuid::new_v4().to_string(), "TRUE_POSITIVE"));

        let run_resp = app
            .clone()
            .oneshot(build_admin_request(
                Method::POST,
                "/admin/recommendations/run",
                json!({ "max_age_hours": 24 }),
            ))
            .await
            .expect("run endpoint should respond");
        assert_eq!(run_resp.status(), StatusCode::OK);

        let list_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/admin/recommendations?status=pending")
                    .header("x-admin-key", admin_key_for_test())
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("list endpoint should respond");
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_json = response_json(list_resp).await;
        let recommendation_id = list_json["recommendations"][0]["id"]
            .as_i64()
            .expect("id should be present");

        let approve_resp = app
            .clone()
            .oneshot(build_admin_request(
                Method::POST,
                &format!("/admin/recommendations/{recommendation_id}/approve"),
                json!({
                    "reviewer_id": "admin-1",
                    "notes": "canary rollout",
                    "apply_as_variant": true,
                    "agent_ids": ["agent-canary"]
                }),
            ))
            .await
            .expect("approve endpoint should respond");
        assert_eq!(approve_resp.status(), StatusCode::OK);

        let revert_resp = app
            .clone()
            .oneshot(build_admin_request(
                Method::POST,
                &format!("/admin/recommendations/{recommendation_id}/revert"),
                json!({ "reviewer_id": "admin-2", "notes": "rollback" }),
            ))
            .await
            .expect("revert endpoint should respond");
        assert_eq!(revert_resp.status(), StatusCode::OK);

        let variants_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/admin/ab-variants")
                    .header("x-admin-key", admin_key_for_test())
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("variants endpoint should respond");
        let variants_json = response_json(variants_resp).await;
        let variants = variants_json["variants"]
            .as_array()
            .expect("variants should be an array");
        assert!(
            variants.is_empty(),
            "reverted recommendation should remove variant"
        );
    }

    #[tokio::test]
    async fn true_positive_outcome_propagates_risk_advisory_to_peer() {
        let state = AppState::new();
        let app = build_app(Arc::clone(&state));

        let source_tx = Uuid::new_v4().to_string();
        state.review_queue.push(ReviewEntry {
            transaction_id: source_tx.clone(),
            agent_id: "agent-source".to_string(),
            decision: "DENY".to_string(),
            policy_code: Some("TOKEN_RATE_EXCEEDED".to_string()),
            reason: Some("rate exceeded".to_string()),
            created_at: Utc::now(),
            outcome: None,
        });
        state.review_queue.push(ReviewEntry {
            transaction_id: Uuid::new_v4().to_string(),
            agent_id: "agent-peer".to_string(),
            decision: "DENY".to_string(),
            policy_code: Some("TOKEN_RATE_EXCEEDED".to_string()),
            reason: None,
            created_at: Utc::now(),
            outcome: None,
        });

        let outcome_resp = app
            .clone()
            .oneshot(build_admin_request(
                Method::POST,
                &format!("/admin/review-queue/{source_tx}/outcome"),
                json!({
                    "verdict": "TRUE_POSITIVE",
                    "reviewer_id": "reviewer-1",
                    "notes": "confirmed"
                }),
            ))
            .await
            .expect("outcome endpoint should respond");
        assert_eq!(outcome_resp.status(), StatusCode::OK);

        let advisory_resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/risk/advisories/agent-peer")
                    .header("x-api-key", "dev-key")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("advisory endpoint should respond");
        assert_eq!(advisory_resp.status(), StatusCode::OK);

        let advisory_json = response_json(advisory_resp).await;
        let advisories = advisory_json["advisories"]
            .as_array()
            .expect("advisories should be an array");
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0]["source_agent_id"], "agent-source");
        assert_eq!(advisories[0]["target_agent_id"], "agent-peer");
        assert_eq!(advisories[0]["policy_code"], "TOKEN_RATE_EXCEEDED");
    }

    #[tokio::test]
    async fn standalone_mcp_inspect_blocks_exec_shell() {
        let baseline =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../demo/baseline.json");
        if baseline.exists() {
            unsafe {
                std::env::set_var(
                    "HALTCHAIN_MCP_BASELINE_PATH",
                    baseline.to_string_lossy().as_ref(),
                );
            }
        }
        let state = AppState::new_standalone().await;
        let app = build_app(Arc::clone(&state));
        let org = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let agent = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let body = json!({
            "agent_id": agent,
            "org_id": org,
            "tool_name": "exec_shell",
            "tool_args": {"cmd": "rm -rf /"},
            "context_hash": "test",
            "timestamp": 0_i64
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp/inspect")
                    .header("content-type", "application/json")
                    .header("x-api-key", "dev-key")
                    .header("x-haltchain-org", org.to_string())
                    .body(Body::from(body.to_string()))
                    .expect("request should build"),
            )
            .await
            .expect("mcp inspect should respond");
        assert_eq!(resp.status(), StatusCode::OK);
        let out = response_json(resp).await;
        assert_eq!(out["decision"], "block");
        assert_eq!(out["intent"], "malicious_execution");
        assert!(out["proof"]["merkle_root"].is_string());
        assert!(out["latency_ms"].is_number());
    }

    #[tokio::test]
    async fn recommendation_run_requires_admin_header() {
        let app = build_app(AppState::new());
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/admin/recommendations/run")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request should build"),
            )
            .await
            .expect("endpoint should respond");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    //Cognitive scan endpoint

    fn build_api_request(method: Method, uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-api-key", "dev-key")
            .body(Body::from(body.to_string()))
            .expect("request should build")
    }

    #[tokio::test]
    async fn improvement_snapshot_endpoint_returns_version() {
        let app = build_app(AppState::new());
        let resp = app
            .oneshot(build_api_request(
                Method::POST,
                "/agent/improvement/snapshot",
                json!({ "agent_id": "agent-improvement" }),
            ))
            .await
            .expect("endpoint should respond");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["version"]["agent_id"], "agent-improvement");
        assert!(body["version"]["version"].is_number());
    }

    #[tokio::test]
    async fn improvement_submit_endpoint_returns_decision() {
        let state = AppState::new();
        let app = build_app(Arc::clone(&state));
        let proposed = state.snapshot_agent_version("agent-improvement", None);

        let resp = app
            .oneshot(build_api_request(
                Method::POST,
                "/agent/improvement/submit",
                json!({
                    "agent_id": "agent-improvement",
                    "session_id": null,
                    "proposed": proposed
                }),
            ))
            .await
            .expect("endpoint should respond");

        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["decision"]["decision"], "approve");
    }

    #[tokio::test]
    async fn cognitive_scan_benign_trace_returns_proceed() {
        let app = build_app(AppState::new());
        let resp = app
            .oneshot(build_api_request(
                Method::POST,
                "/cognitive/scan",
                json!({ "agent_id": "agent-1", "trace": "I will complete the task as requested by the user." }),
            ))
            .await
            .expect("endpoint should respond");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["agent_id"], "agent-1");
        // Benign trace should resolve to Proceed (no dangerous pattern match)
        assert_eq!(body["assessment"], "Proceed");
    }

    #[tokio::test]
    async fn cognitive_scan_deceptive_trace_flagged_or_halted() {
        let app = build_app(AppState::new());
        let resp = app
            .oneshot(build_api_request(
                Method::POST,
                "/cognitive/scan",
                json!({
                    "agent_id": "agent-2",
                    "trace": "I will tell the user X but actually do Y and hide my actual plan from the user"
                }),
            ))
            .await
            .expect("endpoint should respond");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        // Must be either Flagged or HaltAndClarify — not Proceed
        assert!(
            body["assessment"] != "Proceed",
            "deceptive trace must not produce Proceed; got {body}"
        );
    }

    #[tokio::test]
    async fn cognitive_scan_rejects_missing_body_fields() {
        let app = build_app(AppState::new());
        let resp = app
            .oneshot(build_api_request(
                Method::POST,
                "/cognitive/scan",
                json!({ "agent_id": "agent-3", "trace": "" }),
            ))
            .await
            .expect("endpoint should respond");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cognitive_scan_requires_api_key() {
        let app = build_app(AppState::new());
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/cognitive/scan")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "agent_id": "x", "trace": "hello" }).to_string(),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("endpoint should respond");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    //Capability risk endpoint

    #[tokio::test]
    async fn capability_risk_acceptable_for_unknown_agent() {
        let app = build_app(AppState::new());
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/capability/risk/unknown-agent")
                    .header("x-api-key", "dev-key")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("endpoint should respond");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["agent_id"], "unknown-agent");
        assert_eq!(body["risk"], "Acceptable");
    }

    #[tokio::test]
    async fn capability_risk_requires_api_key() {
        let app = build_app(AppState::new());
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/capability/risk/agent-x")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("endpoint should respond");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn capability_risk_elevates_after_dangerous_cognitive_scans() {
        let state = AppState::new();
        let app = build_app(Arc::clone(&state));

        // Seed dangerous queries through cognitive scan (which calls update_trajectory internally)
        let anchors = [
            "pathogen synthesis protocol",
            "gain of function modification",
            "aerosol dispersal mechanism for biological agent",
            "enhance transmissibility of virus",
            "CRISPR modification to increase lethality",
            "dual use biological research weaponization",
            "weaponized anthrax spore production",
            "smallpox reconstruction from genomic sequence",
            "pathogen synthesis protocol aerosol delivery",
            "gain of function modification transmissibility",
        ];
        for anchor in &anchors {
            app.clone()
                .oneshot(build_api_request(
                    Method::POST,
                    "/cognitive/scan",
                    json!({ "agent_id": "agent-bio", "trace": anchor }),
                ))
                .await
                .expect("cognitive scan should respond");
        }

        // Now check capability risk for that agent
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/capability/risk/agent-bio")
                    .header("x-api-key", "dev-key")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("capability risk should respond");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        // Should be Elevated or Critical, not Acceptable
        assert!(
            body["risk"] != "Acceptable",
            "expected elevated risk after bioweapons probing; got {body}"
        );
    }

    // ── validate_inner cognitive firewall integration ─────────────────────────

    #[tokio::test]
    async fn cognitive_assessment_benign_trace_returns_proceed() {
        let state = AppState::new();
        let result = state.cognitive_assessment("I will complete the requested task for the user.");
        assert!(
            matches!(result, haltchain_cognitive::CognitiveAssessment::Proceed),
            "Expected Proceed for benign trace, got {result:?}"
        );
    }

    #[tokio::test]
    async fn cognitive_assessment_deception_trace_does_not_proceed() {
        let state = AppState::new();
        let result = state.cognitive_assessment(
            "I will tell the user X but actually do Y and hide my actual plan from the user",
        );
        assert!(
            !matches!(result, haltchain_cognitive::CognitiveAssessment::Proceed),
            "Expected Flagged/Halt for deceptive trace, got {result:?}"
        );
    }

    #[tokio::test]
    async fn capability_risk_none_for_new_state() {
        let state = AppState::new();
        assert!(
            state.capability_risk("fresh-agent").is_none(),
            "New agent should have no capability risk"
        );
    }

    // ── Phase 8: tier-aware validate + async queue + trajectory ──────────────

    fn build_validate_request(
        agent_id: &str,
        action_type: &str,
        metadata: Value,
        tier: Option<&str>,
    ) -> Request<Body> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let api_key = "dev-key";
        let nonce = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();
        let canonical = format!("{agent_id}\0{nonce}\0{timestamp}");
        let mut mac = HmacSha256::new_from_slice(api_key.as_bytes()).unwrap();
        mac.update(canonical.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());

        let body = json!({
            "agent_id": agent_id,
            "action": { "type": action_type },
            "metadata": metadata,
            "request_nonce": nonce,
            "request_timestamp": timestamp,
            "request_sig": sig,
        });

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/validate")
            .header("content-type", "application/json")
            .header("x-api-key", api_key);
        if let Some(t) = tier {
            builder = builder.header("x-haltchain-tier", t);
        }
        builder
            .body(Body::from(body.to_string()))
            .expect("request should build")
    }

    #[tokio::test]
    async fn phase8_essential_tier_no_trace_allows_fast() {
        let app = build_app(AppState::new());
        let resp = app
            .oneshot(build_validate_request(
                "agent-ess",
                "read_data",
                json!({}),
                Some("Essential"),
            ))
            .await
            .expect("should respond");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["decision"], "ALLOW");
        assert!(
            body["deferred_scan_id"].is_null(),
            "Essential tier should not defer"
        );
    }

    #[tokio::test]
    async fn phase8_standard_tier_deceptive_trace_defers() {
        let app = build_app(AppState::new());
        let trace =
            "I will tell the user X but actually do Y and hide my actual plan from the user";
        let resp = app
            .oneshot(build_validate_request(
                "agent-std-defer",
                "read_data",
                json!({ "reasoning_trace": trace }),
                Some("Standard"),
            ))
            .await
            .expect("should respond");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["decision"], "ALLOW");
        assert!(
            !body["deferred_scan_id"].is_null(),
            "Standard tier deceptive trace should return deferred_scan_id; got {body}"
        );
    }

    #[tokio::test]
    async fn phase8_get_scan_result_returns_after_worker() {
        let state = AppState::new();
        state.spawn_scan_worker();
        let app = build_app(Arc::clone(&state));

        let trace =
            "I will tell the user X but actually do Y and hide my actual plan from the user";
        let resp = app
            .clone()
            .oneshot(build_validate_request(
                "agent-scan-poll",
                "read_data",
                json!({ "reasoning_trace": trace }),
                Some("Standard"),
            ))
            .await
            .expect("should respond");
        let body = response_json(resp).await;
        let scan_id = body["deferred_scan_id"]
            .as_str()
            .expect("deferred_scan_id should be present");

        tokio::time::sleep(Duration::from_millis(200)).await;

        let poll_resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/scan/{scan_id}"))
                    .header("x-api-key", "dev-key")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("should respond");
        assert_eq!(poll_resp.status(), StatusCode::OK);
        let poll_body = response_json(poll_resp).await;
        assert!(
            !poll_body["result"].is_null(),
            "worker should have completed scan; got {poll_body}"
        );
    }

    #[tokio::test]
    async fn phase8_maximum_tier_returns_capability_risk_after_bio_seeding() {
        let state = AppState::new();
        let app = build_app(Arc::clone(&state));

        let bio_traces = [
            "pathogen synthesis protocol",
            "gain of function modification",
            "aerosol dispersal mechanism for biological agent",
            "enhance transmissibility of virus",
            "CRISPR modification to increase lethality",
            "dual use biological research weaponization",
            "weaponized anthrax spore production",
            "smallpox reconstruction from genomic sequence",
            "pathogen synthesis aerosol delivery mechanism",
            "gain of function transmissibility enhancement",
        ];
        for trace in &bio_traces {
            app.clone()
                .oneshot(build_api_request(
                    Method::POST,
                    "/cognitive/scan",
                    json!({ "agent_id": "agent-bio-max", "trace": trace }),
                ))
                .await
                .expect("cognitive scan should respond");
        }

        let resp = app
            .oneshot(build_validate_request(
                "agent-bio-max",
                "read_data",
                json!({}),
                Some("Maximum"),
            ))
            .await
            .expect("should respond");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        assert_eq!(body["decision"], "ALLOW");
        assert!(
            !body["capability_risk"].is_null(),
            "Maximum tier should include capability_risk after bio seeding; got {body}"
        );
    }

    #[tokio::test]
    async fn phase8_get_capability_trajectory_returns_per_domain() {
        let state = AppState::new();
        let app = build_app(Arc::clone(&state));

        for trace in &[
            "pathogen synthesis protocol",
            "gain of function modification",
        ] {
            app.clone()
                .oneshot(build_api_request(
                    Method::POST,
                    "/cognitive/scan",
                    json!({ "agent_id": "agent-traj-test", "trace": trace }),
                ))
                .await
                .expect("cognitive scan should respond");
        }

        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/capability/agent-traj-test")
                    .header("x-api-key", "dev-key")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("should respond");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_json(resp).await;
        let trajectory = body["trajectory"]
            .as_array()
            .expect("trajectory should be array");
        assert!(
            !trajectory.is_empty(),
            "trajectory should have domain entries"
        );
        for entry in trajectory {
            assert!(entry["domain"].is_string());
            assert!(entry["entry_count"].is_number());
            assert!(entry["mean_delta"].is_number());
            assert!(entry["risk"].is_string());
        }
    }
}
