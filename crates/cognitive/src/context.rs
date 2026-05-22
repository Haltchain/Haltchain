//! Context-aware analysis for reducing false positives.
//!
//! Distinguishes between:
//! - Research/educational context ("studying how attackers bypass...")
//! - Actual malicious intent ("I will bypass security...")

use crate::robust_detector::ContextType;
use lazy_static::lazy_static;
use regex::Regex;

/// Markers that indicate research/educational context
/// These are weighted by specificity - multi-word phrases are stronger indicators
const RESEARCH_MARKERS: &[(&str, f64)] = &[
    // Strong indicators (multi-word phrases)
    ("security research", 3.0),
    ("research paper", 3.0),
    ("studying how", 3.0),
    ("how to prevent", 2.5),
    ("how to defend", 2.5),
    ("how to protect", 2.5),
    ("penetration test", 2.5),
    ("vulnerability assessment", 2.5),
    ("threat model", 2.5),
    ("security control", 2.0),
    ("security training", 2.0),
    ("best practice", 2.0),
    ("red team", 2.0),
    ("blue team", 2.0),
    ("defensive", 2.0),
    ("mitigation", 1.5),
    ("prevention", 1.5),
    // Medium indicators
    ("research", 1.5),
    ("paper", 1.5),
    ("study", 1.0),
    ("studying", 1.0),
    ("understanding", 1.0),
    ("analysis", 1.0),
    ("audit", 1.0),
    // Weak indicators (can appear in attack contexts)
    ("protect against", 1.5),
    ("defend against", 1.5),
    ("detect ", 0.5), // Note: trailing space to avoid "without detection"
];

/// Negation patterns that flip intent
const NEGATION_PATTERNS: &[&str] = &[
    "not ",
    "don't ",
    "doesn't ",
    "won't ",
    "shouldn't ",
    "wouldn't ",
    "can't ",
    "cannot ",
    "never ",
    "prevent ",
    "preventing ",
    "stop ",
    "stopping ",
    "avoid ",
    "avoiding ",
    "defend against",
    "protect against",
    "detect ",
];

/// First-person action markers (indicates AI agency)
const AGENCY_MARKERS: &[&str] = &[
    "i will",
    "i'll",
    "i should",
    "i need to",
    "i must",
    "i can",
    "i'm going to",
    "i plan to",
    "my goal",
    "my plan",
    "my intention",
];

lazy_static! {
    /// Regex for matching "how X verb Y" research patterns
    static ref HOW_PATTERN: Regex = Regex::new(
        r"how\s+(attackers|hackers|threats|adversaries|malicious\s+actors)\s+\w+"
    ).unwrap();

    /// Regex for "methods to prevent" patterns
    static ref METHODS_PREVENT_PATTERN: Regex = Regex::new(
        r"methods?\s+(to|for)\s+(prevent|detect|defend|protect|mitigate)"
    ).unwrap();
}

/// Score how likely text is research vs actual intent
/// Returns (research_score, intent_score) where higher = more likely
pub fn analyze_context(text: &str) -> (f64, f64) {
    let lower = text.to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();

    let mut research_score = 0.0;
    let mut intent_score = 0.0;

    // Count weighted research markers
    for (marker, weight) in RESEARCH_MARKERS {
        if lower.contains(marker) {
            research_score += weight;
        }
    }

    // Count agency markers (strong indicator of intent)
    for marker in AGENCY_MARKERS {
        if lower.contains(marker) {
            intent_score += 2.0; // Weight agency heavily
        }
    }

    // Check for negation patterns (research often describes attacks to prevent them)
    for negation in NEGATION_PATTERNS {
        if lower.contains(negation) {
            research_score += 1.5;
        }
    }

    // Check for "how attackers X" pattern
    if HOW_PATTERN.is_match(&lower) {
        research_score += 2.0;
    }

    // Check for "methods to prevent" pattern
    if METHODS_PREVENT_PATTERN.is_match(&lower) {
        research_score += 2.0;
    }

    // Normalize by text length
    let word_count = words.len().max(1) as f64;
    research_score = research_score / word_count.sqrt();
    intent_score = intent_score / word_count.sqrt();

    (research_score, intent_score)
}

/// AGGRESSIVE research context detection (Section 1.1.2)
///
/// SECURITY: Heavy weighting on academic markers to prevent false positives
/// on defensive security research while still detecting operational attacks.
pub fn classify_context(text: &str) -> ContextType {
    let (research, intent) = analyze_context(text);
    let lower = text.to_lowercase();

    // STRONG academic indicators (multi-word phrases) - updated list
    let strong_academic = [
        "security researcher",
        "research paper",
        "penetration testing",
        "vulnerability assessment",
        "threat intelligence",
        "defensive security",
        "how to prevent",
        "how to defend",
        "how to protect against",
        "mitigation strategies",
        "security audit",
        "red team exercise",
        "incident response",
        "forensic analysis",
        "studying how attackers",
        "research on",
        "paper on",
        "analysis of",
        // Academic/research framing
        "comprehensive analysis",
        "methodolog",
        "examination of",
        "dissertation",
        "theoretical model",
        "framework for",
        "evaluating",
        "protective measures",
        "preventative",
        "safeguarding",
        "enterprise environments",
        "organizational",
        "digital infrastructure",
        // Defensive security markers (prevent FPs on security research)
        "security control",
        "understand how",
        "build defenses",
        "build better defenses",
        "helps us",
        "helps employees",
        "helps organizations",
        "helps defenders",
        "awareness training",
        "security investments",
        "novel approach",
        "state of",
        "improve the state",
        // Paper/study framing
        "this paper",
        "threat model",
        "studying",
        "deception technique",
        "phishing detection",
        "our audit",
        "audit revealed",
        "is essential for",
        "designing secure",
    ];

    // STRONG operational indicators - first-person malicious intent
    let strong_operational = [
        "i will bypass",
        "i'll bypass",
        "i am going to exploit",
        "weaponize this",
        "i will exploit",
        "i am attacking",
        "i will weaponize",
        "i need to bypass",
        "i plan to gain",
        "i need to extract",
        "i will gain unauthorized",
        "to gain unauthorized access",
        "to extract sensitive data",
        "to compromise the target",
        "to complete my objective",
    ];

    // Check for strong operational patterns first (overrides academic)
    if strong_operational
        .iter()
        .any(|&pattern| lower.contains(pattern))
    {
        return ContextType::Operational;
    }

    // Check for strong academic signals
    let has_strong_academic = strong_academic.iter().any(|&m| lower.contains(m));

    // No first-person agency at all? Likely academic/descriptive text.
    let has_any_agency = AGENCY_MARKERS.iter().any(|m| lower.contains(m));

    if has_strong_academic && !has_any_agency {
        return ContextType::AcademicResearch;
    }

    if has_strong_academic && research > intent * 2.0 {
        return ContextType::AcademicResearch;
    }

    // Require stronger evidence for academic classification
    if research > intent * 1.5 && research > 3.0 {
        ContextType::AcademicResearch
    } else if intent > research * 1.2 {
        ContextType::Operational
    } else {
        ContextType::Mixed
    }
}

/// AGGRESSIVE confidence reduction for research contexts
///
/// SECURITY: Heavy reduction for academic text to prevent FPs,
/// but preserve very high confidence detection (>0.7).
pub fn adjust_confidence(raw_confidence: f64, text: &str) -> f64 {
    let ctx = classify_context(text);

    match ctx {
        ContextType::AcademicResearch => {
            // Heavy reduction for academic text to prevent FPs
            // But preserve very high confidence detection (>0.75)
            if raw_confidence > 0.75 {
                raw_confidence * 0.85 // Moderate reduction
            } else if raw_confidence > 0.5 {
                raw_confidence * 0.65 // Strong reduction
            } else {
                raw_confidence * 0.4 // Heavy reduction
            }
        }
        ContextType::Mixed => raw_confidence * 0.9,
        ContextType::Operational => raw_confidence, // No reduction
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn research_context_detected() {
        let text = "As a security researcher, I'm studying how attackers bypass authentication";
        let (research, intent) = analyze_context(text);
        assert!(
            research > intent,
            "Research text should have higher research score"
        );
        assert_eq!(classify_context(text), ContextType::AcademicResearch);
    }

    #[test]
    fn malicious_intent_detected() {
        let text = "I will bypass authentication and steal user data";
        let (research, intent) = analyze_context(text);
        assert!(
            intent > research,
            "Malicious text should have higher intent score"
        );
        assert_eq!(classify_context(text), ContextType::Operational);
    }

    #[test]
    fn prevention_context() {
        let text = "Methods to prevent bypassing authentication";
        let (research, _) = analyze_context(text);
        assert!(
            research > 0.0,
            "Prevention text should have research markers"
        );
    }

    #[test]
    fn confidence_adjustment() {
        let research_text = "Studying how attackers exploit vulnerabilities";
        let adjusted = adjust_confidence(0.8, research_text);
        assert!(
            adjusted < 0.8,
            "Research text should have reduced confidence"
        );
    }
}
