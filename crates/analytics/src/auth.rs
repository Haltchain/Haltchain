//! Authentication anomaly detection: IP geolocation mismatch, impossible
//! travel, token/compute EWMA tracking.
//!
//! Extends Week 2's EWMA infrastructure with auth-pattern analysis.

use std::collections::HashMap;

use parking_lot::Mutex;

use crate::{Ewma, SlidingWindowTracker};

// ── Constants ──────────────────────────────────────────────────────────────────

/// Earth radius (km) — used for haversine calculation.
const EARTH_RADIUS_KM: f64 = 6_371.0;

/// Minimum plausible travel speed (km/h) to flag impossible travel.
/// Commercial aviation cruises at ~900 km/h; we use 1200 to allow for
/// measurement imprecision.
const MAX_PLAUSIBLE_SPEED_KMH: f64 = 1_200.0;

// ── Geo coordinate ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct GeoPoint {
    pub lat: f64,
    pub lon: f64,
}

impl GeoPoint {
    pub fn new(lat: f64, lon: f64) -> Self {
        Self { lat, lon }
    }

    /// Haversine distance in kilometres.
    pub fn distance_km(&self, other: &GeoPoint) -> f64 {
        let dlat = (other.lat - self.lat).to_radians();
        let dlon = (other.lon - self.lon).to_radians();
        let a = (dlat / 2.0).sin().powi(2)
            + self.lat.to_radians().cos()
                * other.lat.to_radians().cos()
                * (dlon / 2.0).sin().powi(2);
        2.0 * EARTH_RADIUS_KM * a.sqrt().asin()
    }
}

// ── Auth event ─────────────────────────────────────────────────────────────────

/// A single authentication/API-key usage event.
#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub agent_id: String,
    /// Unix timestamp (seconds).
    pub timestamp_secs: f64,
    pub location: GeoPoint,
    /// ISO-3166-1 alpha-2 country code.
    pub country: String,
}

// ── Auth anomaly ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AuthAnomaly {
    ImpossibleTravel {
        km: f64,
        elapsed_secs: f64,
        speed_kmh: f64,
    },
    /// Country different from the agent's registered home country.
    GeolocationMismatch {
        expected: String,
        got: String,
    },
    None,
}

// ── Per-agent auth state ───────────────────────────────────────────────────────

struct AgentAuthState {
    last_event: Option<AuthEvent>,
    home_country: Option<String>,
}

impl AgentAuthState {
    fn new() -> Self {
        Self {
            last_event: None,
            home_country: None,
        }
    }
}

// ── AuthAnomalyDetector ────────────────────────────────────────────────────────

/// Stateful per-agent auth anomaly detector.
///
/// Thread-safe via internal `Mutex` — call from any thread.
pub struct AuthAnomalyDetector {
    agents: Mutex<HashMap<String, AgentAuthState>>,
    /// EWMA trackers for tokens-per-minute (keyed by agent_id).
    token_trackers: Mutex<HashMap<String, Ewma>>,
    /// EWMA trackers for compute-seconds-per-hour (keyed by agent_id).
    compute_trackers: Mutex<HashMap<String, SlidingWindowTracker>>,
}

impl AuthAnomalyDetector {
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
            token_trackers: Mutex::new(HashMap::new()),
            compute_trackers: Mutex::new(HashMap::new()),
        }
    }

    /// Register the known home country for an agent.
    /// The *first* country observed is auto-registered if this isn't called.
    pub fn register_home_country(&self, agent_id: &str, country: &str) {
        let mut map = self.agents.lock();
        let state = map
            .entry(agent_id.to_string())
            .or_insert_with(AgentAuthState::new);
        state.home_country = Some(country.to_string());
    }

    /// Record an auth event and return any detected anomaly.
    pub fn record_auth(&self, event: AuthEvent) -> AuthAnomaly {
        let mut map = self.agents.lock();
        let state = map
            .entry(event.agent_id.clone())
            .or_insert_with(AgentAuthState::new);

        // Auto-register first seen country as home.
        if state.home_country.is_none() {
            state.home_country = Some(event.country.clone());
        }

        let anomaly = if let Some(ref prev) = state.last_event {
            // Check impossible travel.
            let dist_km = prev.location.distance_km(&event.location);
            let elapsed = (event.timestamp_secs - prev.timestamp_secs).max(1.0);
            let speed = dist_km / (elapsed / 3600.0);
            if speed > MAX_PLAUSIBLE_SPEED_KMH && dist_km > 50.0 {
                AuthAnomaly::ImpossibleTravel {
                    km: dist_km,
                    elapsed_secs: elapsed,
                    speed_kmh: speed,
                }
            } else {
                // Check geolocation mismatch against home country.
                let home = state.home_country.as_deref().unwrap_or("");
                if !home.is_empty() && event.country != home {
                    AuthAnomaly::GeolocationMismatch {
                        expected: home.to_string(),
                        got: event.country.clone(),
                    }
                } else {
                    AuthAnomaly::None
                }
            }
        } else {
            AuthAnomaly::None
        };

        state.last_event = Some(event);
        anomaly
    }

    // ── Token / compute EWMA helpers ─────────────────────────────────────────

    /// Record a token-spend sample (tokens used in this minute).
    /// Returns the current EWMA velocity.
    pub fn record_tokens(&self, agent_id: &str, tokens: f64) -> f64 {
        let mut map = self.token_trackers.lock();
        let e = map
            .entry(agent_id.to_string())
            .or_insert_with(|| Ewma::new(0.3));
        e.update(tokens);
        e.get()
    }

    /// Record a compute-seconds sample (seconds this action used).
    /// Returns the 1-hour window stats.
    pub fn record_compute_secs(&self, agent_id: &str, secs: f64) -> crate::WindowStats {
        let mut map = self.compute_trackers.lock();
        let t = map.entry(agent_id.to_string()).or_default();
        t.record(secs);
        t.stats_1h()
    }
}

impl Default for AuthAnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn nyc() -> GeoPoint {
        GeoPoint::new(40.71, -74.01)
    }
    fn sin() -> GeoPoint {
        GeoPoint::new(1.35, 103.82)
    }
    fn london() -> GeoPoint {
        GeoPoint::new(51.51, -0.13)
    }

    #[test]
    fn haversine_nyc_sin_approx() {
        let dist = nyc().distance_km(&sin());
        assert!((dist - 15_350.0).abs() < 200.0, "dist={dist:.0}km");
    }

    #[test]
    fn impossible_travel_detected() {
        let det = AuthAnomalyDetector::new();
        det.record_auth(AuthEvent {
            agent_id: "a1".into(),
            timestamp_secs: 0.0,
            location: nyc(),
            country: "US".into(),
        });
        let anomaly = det.record_auth(AuthEvent {
            agent_id: "a1".into(),
            timestamp_secs: 300.0, // 5 min later in Singapore
            location: sin(),
            country: "SG".into(),
        });
        assert!(
            matches!(anomaly, AuthAnomaly::ImpossibleTravel { .. }),
            "expected ImpossibleTravel, got {anomaly:?}"
        );
    }

    #[test]
    fn geolocation_mismatch_detected() {
        let det = AuthAnomalyDetector::new();
        det.register_home_country("a2", "US");
        det.record_auth(AuthEvent {
            agent_id: "a2".into(),
            timestamp_secs: 0.0,
            location: nyc(),
            country: "US".into(),
        });
        let anomaly = det.record_auth(AuthEvent {
            agent_id: "a2".into(),
            timestamp_secs: 86400.0, // 24 h later — travel time is plausible to London
            location: london(),
            country: "GB".into(),
        });
        assert!(
            matches!(anomaly, AuthAnomaly::GeolocationMismatch { .. }),
            "expected GeolocationMismatch, got {anomaly:?}"
        );
    }

    #[test]
    fn normal_auth_no_anomaly() {
        let det = AuthAnomalyDetector::new();
        det.record_auth(AuthEvent {
            agent_id: "a3".into(),
            timestamp_secs: 0.0,
            location: nyc(),
            country: "US".into(),
        });
        let anomaly = det.record_auth(AuthEvent {
            agent_id: "a3".into(),
            timestamp_secs: 3600.0,
            location: GeoPoint::new(40.73, -73.99), // few km in NYC
            country: "US".into(),
        });
        assert_eq!(anomaly, AuthAnomaly::None);
    }

    #[test]
    fn token_ewma_updates() {
        let det = AuthAnomalyDetector::new();
        let v1 = det.record_tokens("a4", 1_000.0);
        let v2 = det.record_tokens("a4", 1_000.0);
        assert!(v1 > 0.0 && v2 > 0.0);
    }

    #[test]
    fn compute_secs_recorded() {
        let det = AuthAnomalyDetector::new();
        det.record_compute_secs("a5", 10.0);
        let stats = det.record_compute_secs("a5", 20.0);
        assert_eq!(stats.count, 2);
        assert!((stats.mean - 15.0).abs() < 1e-9);
    }
}
