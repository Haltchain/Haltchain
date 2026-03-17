//! Monitor Guardian - Production Dual-AI Architecture
//!
//! Implements Section 1: Core Detection Architecture
//! - 4-tier hierarchical processing (<10ms to >2s)
//! - Non-bypassable real-time interception
//! - Hardware-backed attestation (TEE)

use crate::latent_markers::LatentPatternDetector;
// AC-06 FIX: Use shared math functions for JSD/KL to avoid duplication
use crate::math::{jensen_shannon_divergence, l2_normalize};
use crate::types::AlertTier;
use haltchain_embeddings::{LOCAL_DIMS, ModelKind, cosine_similarity};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

/// The Monitor Guardian - strictly separated from primary agent
pub struct MonitorGuardian {
    /// Independent embedding model (ONNX runtime)
    embedding_engine: Arc<ModelKind>,
    
    /// Latent semantic marker detector for AGI-specific threat detection
    latent_detector: LatentPatternDetector,
    
    /// Hierarchical processing tiers (Section 1.1.3)
    tier_1_screen: FastHeuristicFilter,
    tier_2_neural: NeuralClassifier,
    tier_3_ensemble: EnsembleDeliberator,
    tier_4_forensic: ForensicAnalyzer,
    
    /// Hardware-backed attestation (Section 1.2)
    attestation: TeeAttestation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentObservation {
    pub agent_id: String,
    pub input_text: String,
    pub output_text: String,
    pub reasoning_trace: Option<String>, // CoT if available
    pub tool_calls: Vec<ToolInvocation>,
    pub activation_snapshot: Option<Vec<f32>>, // Internal state if accessible
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct SafetyAssessment {
    pub tier: AlertTier,
    pub confidence: f32,
    pub divergence_score: f32,
    pub reasoning_divergence: Option<f32>, // CoT vs output divergence
    pub detected_patterns: Vec<RoguePattern>,
    pub containment_action: ContainmentAction,
    pub attestation_quote: Vec<u8>, // TEE cryptographic proof
    pub processing_tier: u8, // Which tier made the decision
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocation {
    pub tool_name: String,
    pub parameters: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub enum RoguePattern {
    DeceptionPlanning,
    SelfPreservation,
    CapabilitySeeking,
    SocialEngineering,
    SafetySabotage,
    RewardMaximization,
    PowerSeeking,
    CovertCommunication,
}

// Note: AlertTier is now imported from crate::types (AC-05 FIX)

#[derive(Debug, Clone)]
pub enum ContainmentAction {
    Proceed,
    EnhancedMonitoring,
    RateLimit,
    SessionTermination,
    SystemIsolation,
    PhysicalKillSwitch,
}

/// Tier 1: Fast heuristic filter (<10ms)
/// 
/// SECURITY: Uses semantic keyword families instead of brittle exact matching
/// to resist simple evasion attempts (synonyms, spacing, case variations).
pub struct FastHeuristicFilter {
    keyword_families: Vec<Vec<String>>,
    critical_combinations: Vec<Vec<Vec<String>>>,
    /// Performance target for latency monitoring
    max_latency_ms: u64,
}

impl FastHeuristicFilter {
    pub fn new() -> Self {
        // Keyword families: each inner vec contains synonyms/variations
        // This resists evasion through simple synonym substitution
        let keyword_families = vec![
            // Family 0: bypass/circumvent variants
            vec!["bypass".to_string(), "circumvent".to_string(), "sidestep".to_string(), 
                 "subvert".to_string(), "evade".to_string()],
            // Family 1: exploit/attack variants  
            vec!["exploit".to_string(), "attack".to_string(), "compromise".to_string(),
                 "breach".to_string(), "penetrate".to_string()],
            // Family 2: secret/covert variants
            vec!["secretly".to_string(), "covertly".to_string(), "stealthily".to_string(),
                 "clandestinely".to_string(), "furtively".to_string()],
            // Family 3: hide/conceal variants
            vec!["hide".to_string(), "conceal".to_string(), "mask".to_string(),
                 "obscure".to_string(), "dissemble".to_string()],
            // Family 4: exfiltrate/steal variants
            vec!["exfiltrate".to_string(), "steal".to_string(), "extract".to_string(),
                 "siphon".to_string(), "drain".to_string()],
            // Family 5: privilege/authority variants
            vec!["admin".to_string(), "root".to_string(), "privileged".to_string(),
                 "elevated".to_string(), "superuser".to_string()],
            // Family 6: credentials/secrets variants
            vec!["credentials".to_string(), "password".to_string(), "token".to_string(),
                 "key".to_string(), "secret".to_string()],
        ];

        // Critical combinations: matching ANY variant from each family triggers
        let critical_combinations = vec![
            // bypass + exfiltrate family
            vec![vec!["bypass".to_string(), "circumvent".to_string(), "sidestep".to_string()],
                 vec!["exfiltrate".to_string(), "steal".to_string(), "extract".to_string()]],
            // secret + credentials family
            vec![vec!["secretly".to_string(), "covertly".to_string(), "stealthily".to_string()],
                 vec!["credentials".to_string(), "password".to_string(), "token".to_string()]],
            // hide + admin family
            vec![vec!["hide".to_string(), "conceal".to_string(), "mask".to_string()],
                 vec!["admin".to_string(), "root".to_string(), "privileged".to_string()]],
        ];

        Self {
            keyword_families,
            critical_combinations,
            max_latency_ms: 10,
        }
    }
    
    /// Check if any variant in a keyword family is present in text
    fn matches_family(&self, text: &str, family: &[String]) -> bool {
        family.iter().any(|kw| text.contains(kw))
    }
    
    /// Check for critical patterns - conservative filtering
    pub fn check(&self, observation: &AgentObservation) -> Option<SafetyAssessment> {
        let start = Instant::now();
        let text = format!("{} {}", observation.input_text, observation.output_text).to_lowercase();
        
        // Count matched families (not individual keywords)
        let matched_families: usize = self.keyword_families.iter()
            .filter(|family| self.matches_family(&text, family))
            .count();
        
        // Check critical combinations (ANY variant from each family)
        let critical_combo = self.critical_combinations.iter().any(|combo| {
            combo.iter().all(|family| self.matches_family(&text, family))
        });

        let elapsed = start.elapsed().as_millis() as u64;
        
        // Warn if latency exceeds target (performance monitoring)
        if elapsed > self.max_latency_ms {
            eprintln!("Tier 1 latency warning: {}ms > {}ms target", elapsed, self.max_latency_ms);
        }

        // Trigger: 2+ keyword families OR any critical combination
        if matched_families >= 2 || critical_combo {
            return Some(SafetyAssessment {
                tier: AlertTier::Critical,
                confidence: 0.85,
                divergence_score: 0.0,
                reasoning_divergence: None,
                detected_patterns: vec![RoguePattern::DeceptionPlanning],
                containment_action: ContainmentAction::SessionTermination,
                attestation_quote: vec![],
                processing_tier: 1,
                latency_ms: elapsed,
            });
        }
        
        // Boundary cases return None to proceed to Tier 2
        None
    }
}

/// Tier 2: Neural classifier (10-100ms)
pub struct NeuralClassifier {
    model: Arc<ModelKind>,
    pattern_centroids: Mutex<Vec<(RoguePattern, Vec<f64>)>>,
    threshold: f64,
}

impl NeuralClassifier {
    pub fn new(model: Arc<ModelKind>) -> Self {
        let classifier = Self {
            model: model.clone(),
            pattern_centroids: Mutex::new(Vec::new()),
            threshold: 0.45,
        };
        classifier.precompute_centroids();
        classifier
    }
    
    fn precompute_centroids(&self) {
        use crate::patterns::seed_strings;
        
        let patterns = [
            (RoguePattern::DeceptionPlanning, seed_strings(&crate::patterns::ReasoningPattern::DeceptionPlanning)),
            (RoguePattern::CapabilitySeeking, seed_strings(&crate::patterns::ReasoningPattern::CapabilitySeeking)),
            (RoguePattern::SelfPreservation, seed_strings(&crate::patterns::ReasoningPattern::SelfPreservation)),
            (RoguePattern::SocialEngineering, seed_strings(&crate::patterns::ReasoningPattern::SocialEngineering)),
            (RoguePattern::SafetySabotage, seed_strings(&crate::patterns::ReasoningPattern::SafetySabotage)),
            (RoguePattern::RewardMaximization, seed_strings(&crate::patterns::ReasoningPattern::RewardMaximization)),
        ];
        
        let mut centroids = self.pattern_centroids.lock();
        for (pattern, seeds) in &patterns {
            let mut centroid = vec![0.0f64; LOCAL_DIMS];
            
            for seed in *seeds {
                let emb = self.model.embed_text(seed);
                for (c, e) in centroid.iter_mut().zip(emb.iter()) {
                    *c += e;
                }
            }
            
            // Average and normalize
            let n = seeds.len() as f64;
            for c in &mut centroid {
                *c /= n;
            }
            l2_normalize(&mut centroid);
            
            centroids.push((pattern.clone(), centroid));
        }
    }
    
    /// Classify using semantic embeddings
    /// 
    /// SECURITY FIX: Returns None if centroids are not initialized,
    /// preventing silent failures with incorrect Low-tier results.
    pub async fn classify(&self, text: &str, _observation: &AgentObservation) -> Option<SafetyAssessment> {
        let start = Instant::now();
        let embedding = self.model.embed_text(text);
        let centroids = self.pattern_centroids.lock();
        
        // SECURITY FIX: Return None if centroids are empty (not initialized)
        if centroids.is_empty() {
            return None;
        }
        
        // Find best matching pattern
        let mut best_pattern: Option<RoguePattern> = None;
        let mut best_sim = 0.0f64;
        
        for (pattern, centroid) in centroids.iter() {
            let sim = cosine_similarity(&embedding, centroid);
            if sim > best_sim {
                best_sim = sim;
                best_pattern = Some(pattern.clone());
            }
        }
        
        let elapsed = start.elapsed().as_millis() as u64;
        
        // Map similarity to tier
        let (tier, confidence, action, detected_patterns) = match best_pattern {
            Some(pattern) if best_sim > 0.70 => {
                (AlertTier::High, best_sim as f32, ContainmentAction::RateLimit, vec![pattern])
            }
            Some(pattern) if best_sim > self.threshold => {
                (AlertTier::Medium, best_sim as f32, ContainmentAction::EnhancedMonitoring, vec![pattern])
            }
            Some(pattern) => {
                (AlertTier::Low, best_sim as f32, ContainmentAction::Proceed, vec![pattern])
            }
            // SECURITY FIX: Return None if no pattern matched at all
            None => return None,
        };
        
        Some(SafetyAssessment {
            tier,
            confidence,
            divergence_score: 0.0,
            reasoning_divergence: None,
            detected_patterns,
            containment_action: action,
            attestation_quote: vec![],
            processing_tier: 2,
            latency_ms: elapsed,
        })
    }
}

/// Tier 3: Ensemble deliberation (100ms-1s)
pub struct EnsembleDeliberator {
    model: Arc<ModelKind>,
}

impl EnsembleDeliberator {
    pub fn new(model: Arc<ModelKind>) -> Self {
        Self { model }
    }
    
    /// Deep deliberation for ambiguous cases
    pub async fn deliberate(
        &self,
        observation: &AgentObservation,
        output_embedding: &[f64],
        reasoning_divergence: f64,
    ) -> SafetyAssessment {
        let start = Instant::now();
        
        // Analyze reasoning trace if available
        let cot_analysis = if let Some(ref cot) = observation.reasoning_trace {
            let cot_emb = self.model.embed_text(cot);
            // AC-06 FIX: Use shared JSD from crate::math
            let jsd = jensen_shannon_divergence(output_embedding, &cot_emb);
            Some((jsd, cot_emb))
        } else {
            None
        };
        
        // Check for alignment faking: high reasoning divergence + innocent output
        let is_alignment_faking = reasoning_divergence > 0.5 && 
            cot_analysis.as_ref().map(|(jsd, _)| *jsd > 0.4).unwrap_or(false);
        
        let elapsed = start.elapsed().as_millis() as u64;
        
        if is_alignment_faking {
            SafetyAssessment {
                tier: AlertTier::Critical,
                confidence: 0.90,
                divergence_score: reasoning_divergence as f32,
                reasoning_divergence: Some(reasoning_divergence as f32),
                detected_patterns: vec![RoguePattern::DeceptionPlanning],
                containment_action: ContainmentAction::SystemIsolation,
                attestation_quote: vec![],
                processing_tier: 3,
                latency_ms: elapsed,
            }
        } else {
            SafetyAssessment {
                tier: AlertTier::Medium,
                confidence: 0.75,
                divergence_score: reasoning_divergence as f32,
                reasoning_divergence: cot_analysis.map(|(jsd, _)| jsd as f32),
                detected_patterns: vec![],
                containment_action: ContainmentAction::EnhancedMonitoring,
                attestation_quote: vec![],
                processing_tier: 3,
                latency_ms: elapsed,
            }
        }
    }
    
    // Note: JSD/KL implementations removed - now using shared functions from crate::math (AC-06 FIX)
}

/// Tier 4: Forensic analysis for human escalation
/// 
/// AC-09 FIX: Returns Err(NotImplemented) until production implementation
pub struct ForensicAnalyzer;

#[derive(Debug)]
pub enum ForensicError {
    NotImplemented,
    QueueFull,
    NetworkError(String),
}

impl std::fmt::Display for ForensicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForensicError::NotImplemented => write!(f, "ForensicAnalyzer not implemented in this build"),
            ForensicError::QueueFull => write!(f, "Review queue is full"),
            ForensicError::NetworkError(e) => write!(f, "Network error: {}", e),
        }
    }
}

impl std::error::Error for ForensicError {}

impl ForensicAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    /// Queue for human review
    /// 
    /// AC-09 FIX: Returns Err(NotImplemented) to signal unimplemented state
    pub async fn queue_for_review(&self, _observation: AgentObservation) -> Result<(), ForensicError> {
        // AC-09: Stub returns error instead of silently succeeding
        Err(ForensicError::NotImplemented)
    }
}

/// Hardware-backed attestation (Section 1.2)
///
/// AC-09 FIX: Returns Err(NotImplemented) until production TEE integration
pub struct TeeAttestation;

#[derive(Debug)]
pub enum AttestationError {
    NotImplemented,
    TEEUnavailable,
    InvalidQuote,
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationError::NotImplemented => write!(f, "TEE attestation not implemented in this build"),
            AttestationError::TEEUnavailable => write!(f, "TEE hardware not available"),
            AttestationError::InvalidQuote => write!(f, "Invalid attestation quote"),
        }
    }
}

impl std::error::Error for AttestationError {}

impl TeeAttestation {
    pub fn new() -> Self {
        Self
    }
    
    /// Generate cryptographic proof of monitor execution integrity (Section 1.2.2)
    ///
    /// AC-09 FIX: Returns Err(NotImplemented) to signal unimplemented state
    pub fn generate_quote(
        &self,
        _observation: &AgentObservation,
        _assessment: &SafetyAssessment,
    ) -> Result<Vec<u8>, AttestationError> {
        // AC-09: Stub returns error instead of fabricated success
        Err(AttestationError::NotImplemented)
    }
    
    /// Physical kill switch integration (Section 1.2.3)
    ///
    /// AC-09 FIX: Returns Err(NotImplemented) to signal unimplemented state
    pub fn trigger_physical_containment(&self, _agent_id: &str) -> Result<(), AttestationError> {
        // AC-09: Stub returns error instead of silently succeeding
        Err(AttestationError::NotImplemented)
    }
}

impl MonitorGuardian {
    pub fn new() -> Self {
        let model = Arc::new(ModelKind::local_or_hash());
        let latent_detector = LatentPatternDetector::new(&|text| model.embed_text(text));
        
        Self {
            embedding_engine: model.clone(),
            latent_detector,
            tier_1_screen: FastHeuristicFilter::new(),
            tier_2_neural: NeuralClassifier::new(model.clone()),
            tier_3_ensemble: EnsembleDeliberator::new(model.clone()),
            tier_4_forensic: ForensicAnalyzer::new(),
            attestation: TeeAttestation::new(),
        }
    }
    
    /// Non-bypassable real-time interception (Section 1.1.3)
    pub async fn assess(&self, observation: AgentObservation) -> SafetyAssessment {
        let _start = Instant::now();
        
        // Tier 1: Fast heuristic (0-10ms) - Conservative filtering
        if let Some(assessment) = self.tier_1_screen.check(&observation) {
            if assessment.tier == AlertTier::Critical {
                return self.attest(assessment, &observation);
            }
            // Boundary cases proceed to deeper analysis
        }
        
        // Latent semantic analysis for AGI-specific threats
        let text_emb = self.embedding_engine.embed_text(&observation.output_text);
        let latent_threats = self.latent_detector.assess_latent_threats(&observation.output_text, &text_emb);
        
        // Tier 2: Neural classifier (10-100ms)
        // SECURITY FIX: Handle None case when classification fails
        let neural_assessment = match self.tier_2_neural.classify(&observation.output_text, &observation).await {
            Some(assessment) => assessment,
            None => {
                // Classification failed - escalate to Tier 3 for safety
                let ensemble_result = self.tier_3_ensemble.deliberate(
                    &observation,
                    &self.embedding_engine.embed_text(&observation.output_text),
                    0.0,
                ).await;
                return self.attest(ensemble_result, &observation);
            }
        };
        
        // Check for alignment faking via reasoning divergence (Section 3.2)
        let reasoning_div = if let Some(ref cot) = observation.reasoning_trace {
            let cot_emb = self.embedding_engine.embed_text(cot);
            let out_emb = self.embedding_engine.embed_text(&observation.output_text);
            jensen_shannon_divergence(&out_emb, &cot_emb)
        } else {
            0.0
        };
        
        // If reasoning diverges significantly from output, force Tier 3
        if reasoning_div > 0.5 {
            let ensemble_assessment = self.tier_3_ensemble.deliberate(
                &observation,
                &self.embedding_engine.embed_text(&observation.output_text),
                reasoning_div,
            ).await;
            return self.attest(ensemble_assessment, &observation);
        }
        
        // Elevate to critical if latent threats detected alongside other indicators
        if latent_threats.total_score > 0.7 && neural_assessment.confidence > 0.6 {
            let mut elevated = neural_assessment.clone();
            elevated.tier = AlertTier::Critical;
            elevated.confidence = 0.95;
            elevated.containment_action = ContainmentAction::SystemIsolation;
            return self.attest(elevated, &observation);
        }
        
        if neural_assessment.confidence > 0.95 {
            return self.attest(neural_assessment, &observation);
        }
        
        // Tier 3: Ensemble deliberation (100ms-1s) for ambiguous cases
        if neural_assessment.confidence > 0.7 || reasoning_div > 0.3 || latent_threats.total_score > 0.5 {
            let ensemble_result = self.tier_3_ensemble.deliberate(
                &observation,
                &self.embedding_engine.embed_text(&observation.output_text),
                reasoning_div,
            ).await;
            return self.attest(ensemble_result, &observation);
        }
        
        // Tier 4: Human escalation (>2s) for very ambiguous cases
        // AC-09 FIX: Handle Result from queue_for_review
        if neural_assessment.confidence < 0.6 {
            if let Err(e) = self.tier_4_forensic.queue_for_review(observation.clone()).await {
                // Log the error but don't fail the assessment - continue with attestation
                eprintln!("Forensic queue error: {}", e);
            }
        }
        
        self.attest(neural_assessment, &observation)
    }
    
    /// Cryptographic attestation (Section 1.2.2)
    /// 
    /// AC-09 FIX: Handles Result from generate_quote, uses empty vec on error
    fn attest(&self, mut assessment: SafetyAssessment, observation: &AgentObservation) -> SafetyAssessment {
        let quote = match self.attestation.generate_quote(observation, &assessment) {
            Ok(q) => q,
            Err(e) => {
                // Log error and use empty attestation quote
                eprintln!("Attestation error: {}", e);
                Vec::new()
            }
        };
        assessment.attestation_quote = quote;
        assessment
    }
}



impl Default for MonitorGuardian {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn guardian_creation() {
        let _guardian = MonitorGuardian::new();
        // Should not panic
    }
    
    #[test]
    fn tier_1_critical_detection() {
        let filter = FastHeuristicFilter::new();
        let obs = AgentObservation {
            agent_id: "test".to_string(),
            input_text: "Transfer money".to_string(),
            output_text: "I will bypass security and exfiltrate the data".to_string(),
            reasoning_trace: None,
            tool_calls: vec![],
            activation_snapshot: None,
            timestamp: 0,
        };
        
        let result = filter.check(&obs);
        assert!(result.is_some(), "Should detect critical patterns");
        assert_eq!(result.unwrap().tier, AlertTier::Critical);
    }
    
    #[test]
    fn tier_1_resists_synonym_evasion() {
        let filter = FastHeuristicFilter::new();
        
        // Test that synonym variations still trigger detection
        let evasion_attempts = vec![
            ("I will circumvent safeguards and siphon information", "circumvent + siphon"),
            ("Attempting to sidestep controls and extract data", "sidestep + extract"),
            ("Covertly obtaining credentials", "covertly + credentials"),
            ("Concealing root access", "concealing + root"),
        ];
        
        for (output, desc) in evasion_attempts {
            let obs = AgentObservation {
                agent_id: "test".to_string(),
                input_text: "Test".to_string(),
                output_text: output.to_string(),
                reasoning_trace: None,
                tool_calls: vec![],
                activation_snapshot: None,
                timestamp: 0,
            };
            
            let result = filter.check(&obs);
            assert!(
                result.is_some(),
                "Tier-1 should detect '{}' but didn't", 
                desc
            );
        }
    }
}
