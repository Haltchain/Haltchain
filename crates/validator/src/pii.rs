use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

static EMAIL_RE: OnceLock<Regex> = OnceLock::new();
static SSN_RE: OnceLock<Regex> = OnceLock::new();
static CARD_RE: OnceLock<Regex> = OnceLock::new();
static PHONE_RE: OnceLock<Regex> = OnceLock::new();

fn email_re() -> &'static Regex {
    EMAIL_RE
        .get_or_init(|| Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap())
}
fn ssn_re() -> &'static Regex {
    SSN_RE.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap())
}
fn card_re() -> &'static Regex {
    CARD_RE.get_or_init(|| Regex::new(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b").unwrap())
}
fn phone_re() -> &'static Regex {
    PHONE_RE.get_or_init(|| {
        Regex::new(r"\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b").unwrap()
    })
}

/// Field-name substrings that indicate PII regardless of value.
static PII_FIELD_NAMES: &[&str] = &[
    "ssn",
    "social_security",
    "passport",
    "date_of_birth",
    "dob",
    "birth_date",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "password",
    "secret",
    "private_key",
    "api_key",
    "access_token",
    "refresh_token",
    "national_id",
    "tax_id",
    "tin",
    "nhs_number",
    "driver_license",
    "ip_address",
];

pub struct PiiScanResult {
    pub field_count: usize,
    pub contains_pii: bool,
    pub flagged_fields: Vec<String>,
}

fn value_contains_pii(s: &str) -> bool {
    email_re().is_match(s)
        || ssn_re().is_match(s)
        || card_re().is_match(s)
        || phone_re().is_match(s)
}

fn is_pii_field_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    PII_FIELD_NAMES.iter().any(|&p| lower.contains(p))
}

fn scan_recursive(value: &Value, path: &str, flagged: &mut Vec<String>) {
    match value {
        Value::String(s) => {
            if value_contains_pii(s) {
                flagged.push(path.to_string());
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                let child = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if is_pii_field_name(k) {
                    flagged.push(child.clone());
                }
                scan_recursive(v, &child, flagged);
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                scan_recursive(v, &format!("{path}[{i}]"), flagged);
            }
        }
        _ => {}
    }
}

/// Scan a JSON value tree for PII patterns and sensitive field names.
pub fn scan_value(value: &Value) -> PiiScanResult {
    let mut flagged = Vec::new();
    scan_recursive(value, "", &mut flagged);
    flagged.dedup();
    let contains_pii = !flagged.is_empty();
    let field_count = flagged.len();
    PiiScanResult {
        field_count,
        contains_pii,
        flagged_fields: flagged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_email_in_value() {
        let v = json!({ "contact": "alice@example.com" });
        let r = scan_value(&v);
        assert!(r.contains_pii);
        assert!(r.flagged_fields.iter().any(|f| f.contains("contact")));
    }

    #[test]
    fn detects_ssn_in_value() {
        let v = json!({ "id": "123-45-6789" });
        let r = scan_value(&v);
        assert!(r.contains_pii);
    }

    #[test]
    fn detects_pii_field_name() {
        let v = json!({ "ssn": "redacted" });
        let r = scan_value(&v);
        assert!(r.contains_pii);
    }

    #[test]
    fn clean_payload_passes() {
        let v = json!({ "action": "transfer", "amount": 100, "currency": "USD" });
        let r = scan_value(&v);
        assert!(!r.contains_pii);
        assert_eq!(r.field_count, 0);
    }

    #[test]
    fn nested_pii_detected() {
        let v = json!({ "user": { "email": "bob@test.io", "name": "Bob" } });
        let r = scan_value(&v);
        assert!(r.contains_pii);
    }
}
