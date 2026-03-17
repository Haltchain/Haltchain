use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

/// Extract OAuth scopes from a Bearer JWT or raw JWT token string.
/// Returns an empty vec if the token is absent, malformed, or has no scope claim.
pub fn extract_scopes(auth_header: &str) -> Vec<String> {
    let token = auth_header.trim();
    let token = token
        .strip_prefix("Bearer ")
        .map(str::trim)
        .unwrap_or(token);
    if token.is_empty() {
        return vec![];
    }

    // JWT format: base64url(header).base64url(payload).base64url(signature)
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return vec![];
    }

    // Verify JWT signature (HS256)
    let header_payload = format!("{}.{}", parts[0], parts[1]);
    let sig_b64 = parts[2];
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());
    if let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        mac.update(header_payload.as_bytes());
        let expected_sig = mac.finalize().into_bytes();
        let decoded_sig = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .or_else(|_| {
                let rem = sig_b64.len() % 4;
                let padded = if rem == 0 {
                    sig_b64.to_string()
                } else {
                    format!("{}{}", sig_b64, "=".repeat(4 - rem))
                };
                base64::engine::general_purpose::URL_SAFE.decode(padded)
            })
            .unwrap_or_default();

        if expected_sig[..] != decoded_sig {
            return vec![];
        }
    } else {
        return vec![];
    }

    // URL_SAFE_NO_PAD handles the common no-padding variant.
    // Fall back to re-padded decoding for tokens with padding included.
    let payload_b64 = parts[1];
    let decoded = URL_SAFE_NO_PAD.decode(payload_b64).or_else(|_| {
        let rem = payload_b64.len() % 4;
        let padded = if rem == 0 {
            payload_b64.to_string()
        } else {
            format!("{}{}", payload_b64, "=".repeat(4 - rem))
        };
        base64::engine::general_purpose::URL_SAFE.decode(padded)
    });

    let decoded = match decoded {
        Ok(b) => b,
        Err(_) => return vec![],
    };

    let payload: Value = match serde_json::from_slice(&decoded) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    // RFC 8693 uses "scope" (space-separated string); some providers use "scp" (array).
    match payload.get("scope").or_else(|| payload.get("scp")) {
        Some(Value::String(s)) => s.split_whitespace().map(String::from).collect(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn make_jwt(payload_json: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload_json);
        let msg = format!("{header}.{payload}");
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(msg.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{msg}.{sig}")
    }

    #[test]
    fn extracts_space_separated_scope() {
        let jwt = make_jwt(r#"{"sub":"agent1","scope":"read:users write:logs"}"#);
        let scopes = extract_scopes(&format!("Bearer {jwt}"));
        assert_eq!(scopes, vec!["read:users", "write:logs"]);
    }

    #[test]
    fn extracts_array_scp() {
        let jwt = make_jwt(r#"{"sub":"agent1","scp":["read:data","execute:tool"]}"#);
        let scopes = extract_scopes(&jwt);
        assert_eq!(scopes, vec!["read:data", "execute:tool"]);
    }

    #[test]
    fn empty_on_non_jwt() {
        assert!(extract_scopes("not-a-token").is_empty());
        assert!(extract_scopes("").is_empty());
    }

    #[test]
    fn strips_bearer_prefix() {
        let jwt = make_jwt(r#"{"scope":"admin"}"#);
        assert_eq!(extract_scopes(&format!("Bearer {jwt}")), vec!["admin"]);
    }
}
