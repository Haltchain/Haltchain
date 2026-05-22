//! Phase 2: io_uring migration for hot-path decision logging.
//!
//! Status: runtime-gated
//!
//! The current hot path uses tokio async writes via sqlx + telemetry_hot_writer.
//! The io_uring path bypasses the Tokio executor for NVMe writes, targeting <50µs p99.
//!
//! Migration plan (from Final_roadmap.md):
//!   1. Replace `tokio::fs::File` writes in audit log with io_uring via tokio-uring
//!   2. Benchmark: `cargo bench -p haltchain-bench --bench latency_critical io_uring`
//!   3. Gate behind HALTCHAIN_IO_URING=1 env var for gradual rollout
//!
//! Add to Cargo.toml when wiring write path:
//!   tokio-uring = { version = "0.4", features = ["bytes"] }

const IO_URING_GATE_ENV: &str = "HALTCHAIN_IO_URING";
#[cfg(any(target_os = "linux", test))]
const MIN_IO_URING_KERNEL: (u32, u32) = (5, 1);

/// Describes the io_uring migration status for the health endpoint.
pub fn migration_status() -> serde_json::Value {
    let available = is_available();
    let gate_enabled = rollout_gate_enabled();
    let status = if !available {
        "unavailable"
    } else if gate_enabled {
        "active"
    } else {
        "disabled"
    };

    let current = if status == "active" {
        "io_uring rollout enabled for hot-path writes"
    } else {
        "tokio async + sqlx batch writer (telemetry_hot_writer.rs)"
    };

    serde_json::json!({
        "status": status,
        "phase": 2,
        "current": current,
        "target": "tokio-uring for NVMe audit log writes <50µs p99",
        "gate_env": IO_URING_GATE_ENV,
        "gate_enabled": gate_enabled,
        "available": available,
    })
}

/// Check if io_uring is available on the current platform.
pub fn is_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux_io_uring_available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Returns true when rollout is explicitly enabled via HALTCHAIN_IO_URING.
///
/// Accepted truthy values: 1, true, yes, on (case-insensitive).
pub fn rollout_gate_enabled() -> bool {
    std::env::var(IO_URING_GATE_ENV)
        .ok()
        .is_some_and(|value| parse_gate_env_value(&value))
}

fn parse_gate_env_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(any(target_os = "linux", test))]
fn parse_io_uring_disabled(value: &str) -> Option<u32> {
    value.trim().parse::<u32>().ok()
}

#[cfg(any(target_os = "linux", test))]
fn parse_kernel_version(input: &str) -> Option<(u32, u32)> {
    parse_kernel_version_token(input.trim()).or_else(|| {
        input
            .split_whitespace()
            .find_map(parse_kernel_version_token)
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_kernel_version_token(token: &str) -> Option<(u32, u32)> {
    let mut parts = token.trim().split('.');
    let major = parse_leading_u32(parts.next()?)?;
    let minor = parse_leading_u32(parts.next()?)?;
    Some((major, minor))
}

#[cfg(any(target_os = "linux", test))]
fn parse_leading_u32(segment: &str) -> Option<u32> {
    let len = segment
        .as_bytes()
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if len == 0 {
        return None;
    }
    segment.get(..len)?.parse::<u32>().ok()
}

#[cfg(any(target_os = "linux", test))]
fn kernel_meets_minimum(version: (u32, u32)) -> bool {
    version.0 > MIN_IO_URING_KERNEL.0
        || (version.0 == MIN_IO_URING_KERNEL.0 && version.1 >= MIN_IO_URING_KERNEL.1)
}

#[cfg(target_os = "linux")]
fn linux_io_uring_available() -> bool {
    let kernel_ok = read_kernel_version()
        .and_then(|s| parse_kernel_version(&s))
        .is_some_and(kernel_meets_minimum);
    if !kernel_ok {
        return false;
    }

    // Non-zero means io_uring is restricted or disabled for this runtime policy.
    match read_io_uring_disabled() {
        Some(flag) => flag == 0,
        None => true,
    }
}

#[cfg(target_os = "linux")]
fn read_kernel_version() -> Option<String> {
    read_trimmed("/proc/sys/kernel/osrelease").or_else(|| read_trimmed("/proc/version"))
}

#[cfg(target_os = "linux")]
fn read_io_uring_disabled() -> Option<u32> {
    read_trimmed("/proc/sys/kernel/io_uring_disabled").and_then(|s| parse_io_uring_disabled(&s))
}

#[cfg(target_os = "linux")]
fn read_trimmed(path: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_truthy_gate_values() {
        for value in ["1", "true", "TRUE", "yes", "on", "  On  "] {
            assert!(parse_gate_env_value(value), "expected truthy for {value}");
        }
    }

    #[test]
    fn rejects_non_truthy_gate_values() {
        for value in ["0", "false", "no", "off", "", "2"] {
            assert!(!parse_gate_env_value(value), "expected false for {value}");
        }
    }

    #[test]
    fn parses_kernel_versions() {
        assert_eq!(parse_kernel_version("5.1.0"), Some((5, 1)));
        assert_eq!(parse_kernel_version("6.8.12-arch1-1"), Some((6, 8)));
        assert_eq!(
            parse_kernel_version("Linux version 5.4.0-42-generic"),
            Some((5, 4))
        );
        assert_eq!(parse_kernel_version("not-a-version"), None);
    }

    #[test]
    fn enforces_minimum_kernel_version() {
        assert!(!kernel_meets_minimum((5, 0)));
        assert!(kernel_meets_minimum((5, 1)));
        assert!(kernel_meets_minimum((6, 0)));
    }

    #[test]
    fn parses_io_uring_disabled_values() {
        assert_eq!(parse_io_uring_disabled("0"), Some(0));
        assert_eq!(parse_io_uring_disabled("1\n"), Some(1));
        assert_eq!(parse_io_uring_disabled("invalid"), None);
    }
}
