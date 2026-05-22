/// ISO 3166-1 alpha-2 country codes blocked for data transfers.
///
/// Includes OFAC-sanctioned countries and jurisdictions without a GDPR
/// adequacy decision that require explicit DPA approval before transfers.
pub static RESTRICTED_JURISDICTIONS: &[&str] = &[
    // OFAC primary targets
    "KP", // North Korea
    "IR", // Iran
    "SY", // Syria
    "CU", // Cuba
    "SD", // Sudan
    // OFAC secondary / sector sanctions
    "RU", // Russia
    "BY", // Belarus
    // High-surveillance / data-localisation mandates
    "CN", // China
    // No EU adequacy + high regulatory risk
    "MM", // Myanmar
    "VE", // Venezuela
];

/// Returns `true` when the ISO 3166-1 alpha-2 `country_code` is on the
/// restricted list, requiring prior DPA approval before data transfer.
pub fn is_restricted(country_code: &str) -> bool {
    let code = country_code.trim().to_uppercase();
    RESTRICTED_JURISDICTIONS.contains(&code.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricted_countries_blocked() {
        for &c in &["CN", "RU", "KP", "IR"] {
            assert!(is_restricted(c), "{c} should be restricted");
        }
    }

    #[test]
    fn allowed_countries_pass() {
        for &c in &["US", "DE", "GB", "AU", "CA", "JP"] {
            assert!(!is_restricted(c), "{c} should not be restricted");
        }
    }

    #[test]
    fn case_insensitive() {
        assert!(is_restricted("cn"));
        assert!(is_restricted("Cn"));
        assert!(!is_restricted("us"));
    }
}
