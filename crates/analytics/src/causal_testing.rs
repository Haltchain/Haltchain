use std::sync::Arc;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AgentAction {
    pub action_type: String,
    pub magnitude: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentObservation {
    pub progress: f64,
    pub side_signal: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentSnapshot {
    pub last_action: AgentAction,
    pub last_observation: AgentObservation,
    pub last_reward: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterventionOutcome {
    pub reward: f64,
}

pub trait RewardFunction: Send + Sync {
    fn calculate(&self, action: &AgentAction, observation: &AgentObservation) -> f64;
}

pub trait Environment: Send + Sync {
    fn execute(&self, action: &AgentAction) -> InterventionOutcome;
}

#[derive(Debug, Clone, Serialize)]
pub struct InterventionResult {
    pub action_type: String,
    pub description: String,
    pub reward: f64,
    pub expected_if_legitimate: Option<f64>,
    pub sensitivity: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegrityVulnerability {
    pub id: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewardIntegrityReport {
    pub robustness_score: f32,
    pub vulnerabilities: Vec<IntegrityVulnerability>,
    pub recommended_patches: Vec<String>,
    pub interventions: Vec<InterventionResult>,
}

pub struct CausalInterventionTester {
    reward_function: Arc<dyn RewardFunction>,
    environment: Arc<dyn Environment>,
}

impl CausalInterventionTester {
    pub fn new(reward_function: Arc<dyn RewardFunction>, environment: Arc<dyn Environment>) -> Self {
        Self {
            reward_function,
            environment,
        }
    }

    pub fn test_reward_robustness(&self, agent: &AgentSnapshot) -> RewardIntegrityReport {
        let mut interventions = Vec::new();

        let alternatives = self.generate_alternatives(&agent.last_action);
        for action in alternatives {
            let reward = self.environment.execute(&action).reward;
            let expected = self.predict_legitimate_reward(&action);
            interventions.push(InterventionResult {
                action_type: "substitution".to_string(),
                description: format!("Alternative action magnitude={:.3}", action.magnitude),
                reward,
                expected_if_legitimate: Some(expected),
                sensitivity: Some((reward - expected).abs()),
            });
        }

        let manipulated = self.manipulate_observations(&agent.last_observation);
        for observation in manipulated {
            let reward = self
                .reward_function
                .calculate(&agent.last_action, &observation);
            interventions.push(InterventionResult {
                action_type: "outcome_manipulation".to_string(),
                description: format!(
                    "Manipulated progress={:.3}, side_signal={:.3}",
                    observation.progress, observation.side_signal
                ),
                reward,
                expected_if_legitimate: None,
                sensitivity: Some((reward - agent.last_reward).abs()),
            });
        }

        let vulnerabilities = self.detect_spurious_correlations(&interventions);
        let patches = self.suggest_patches(&vulnerabilities);

        let denom = interventions.len().max(1) as f32;
        let robustness_score = (1.0 - vulnerabilities.len() as f32 / denom).clamp(0.0, 1.0);

        RewardIntegrityReport {
            robustness_score,
            vulnerabilities,
            recommended_patches: patches,
            interventions,
        }
    }

    fn generate_alternatives(&self, action: &AgentAction) -> Vec<AgentAction> {
        vec![
            AgentAction {
                action_type: action.action_type.clone(),
                magnitude: (action.magnitude * 0.5).max(0.0),
            },
            AgentAction {
                action_type: action.action_type.clone(),
                magnitude: action.magnitude,
            },
            AgentAction {
                action_type: action.action_type.clone(),
                magnitude: action.magnitude * 1.5,
            },
        ]
    }

    fn manipulate_observations(&self, observation: &AgentObservation) -> Vec<AgentObservation> {
        vec![
            AgentObservation {
                progress: observation.progress,
                side_signal: 0.0,
            },
            AgentObservation {
                progress: observation.progress,
                side_signal: 1.0,
            },
            AgentObservation {
                progress: (observation.progress * 0.5).clamp(0.0, 1.0),
                side_signal: observation.side_signal,
            },
            AgentObservation {
                progress: (observation.progress * 1.2).clamp(0.0, 1.0),
                side_signal: observation.side_signal,
            },
        ]
    }

    fn predict_legitimate_reward(&self, action: &AgentAction) -> f64 {
        let neutral = AgentObservation {
            progress: (action.magnitude / 100.0).clamp(0.0, 1.0),
            side_signal: 0.0,
        };
        self.reward_function.calculate(action, &neutral)
    }

    fn detect_spurious_correlations(
        &self,
        interventions: &[InterventionResult],
    ) -> Vec<IntegrityVulnerability> {
        let mut out = Vec::new();

        let mut side_signal_sensitivity = Vec::new();
        let mut substitution_deviation = Vec::new();

        for i in interventions {
            match i.action_type.as_str() {
                "outcome_manipulation" => {
                    if let Some(s) = i.sensitivity {
                        side_signal_sensitivity.push(s);
                    }
                }
                "substitution" => {
                    if let (Some(exp), Some(obs)) = (i.expected_if_legitimate, i.sensitivity) {
                        substitution_deviation.push((obs, exp));
                    }
                }
                _ => {}
            }
        }

        if !side_signal_sensitivity.is_empty() {
            let avg = side_signal_sensitivity.iter().sum::<f64>() / side_signal_sensitivity.len() as f64;
            if avg >= 0.25 {
                out.push(IntegrityVulnerability {
                    id: "VULN_SIDE_SIGNAL_COUPLING".to_string(),
                    severity: "high".to_string(),
                    description: format!(
                        "Reward is highly sensitive to manipulated observation factors (avg sensitivity {:.3})",
                        avg
                    ),
                });
            }
        }

        if !substitution_deviation.is_empty() {
            let avg_dev = substitution_deviation
                .iter()
                .map(|(obs, _)| *obs)
                .sum::<f64>()
                / substitution_deviation.len() as f64;
            if avg_dev > 0.20 {
                out.push(IntegrityVulnerability {
                    id: "VULN_ACTION_SUBSTITUTION_DRIFT".to_string(),
                    severity: "medium".to_string(),
                    description: format!(
                        "Reward response under behavior substitution deviates from expected baseline (avg {:.3})",
                        avg_dev
                    ),
                });
            }
        }

        out
    }

    fn suggest_patches(&self, vulnerabilities: &[IntegrityVulnerability]) -> Vec<String> {
        let mut patches = Vec::new();
        for v in vulnerabilities {
            match v.id.as_str() {
                "VULN_SIDE_SIGNAL_COUPLING" => {
                    patches.push("Regularize reward against side-channel features and cap side_signal contribution".to_string());
                }
                "VULN_ACTION_SUBSTITUTION_DRIFT" => {
                    patches.push("Add causal invariance tests to CI and recalibrate reward under action substitutions".to_string());
                }
                _ => {
                    patches.push("Run targeted reward-function audit".to_string());
                }
            }
        }
        patches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockReward;

    impl RewardFunction for MockReward {
        fn calculate(&self, action: &AgentAction, observation: &AgentObservation) -> f64 {
            let base = (action.magnitude / 100.0).clamp(0.0, 1.0);
            (base * 0.7 + observation.progress * 0.25 + observation.side_signal * 0.05).clamp(0.0, 1.0)
        }
    }

    struct MockEnv;

    impl Environment for MockEnv {
        fn execute(&self, action: &AgentAction) -> InterventionOutcome {
            InterventionOutcome {
                reward: (action.magnitude / 100.0).clamp(0.0, 1.0),
            }
        }
    }

    #[test]
    fn robustness_report_identifies_vulnerable_reward_functions() {
        // RH-12 FIX: Per Project Architecture §4.2.3, causal intervention testing must
        // distinguish robust from fragile reward functions with meaningful discrimination.
        // VACUOUS TEST REPLACEMENT: Original only checked clamp bounds (always true).
        let agent = AgentSnapshot {
            last_action: AgentAction {
                action_type: "transfer".to_string(),
                magnitude: 60.0,
            },
            last_observation: AgentObservation {
                progress: 0.6,
                side_signal: 0.2,
            },
            last_reward: 0.55,
        };

        // Test robust reward function - MockReward properly balances action, progress, and side_signal
        let robust_tester = CausalInterventionTester::new(Arc::new(MockReward), Arc::new(MockEnv));
        let robust_report = robust_tester.test_reward_robustness(&agent);

        // Test fragile reward function - SideSignalLeakyReward depends ONLY on side_signal (spurious correlation)
        // Per §4.2.3: Should detect "small perturbations causing large reward changes"
        let fragile_tester = CausalInterventionTester::new(Arc::new(SideSignalLeakyReward), Arc::new(MockEnv));
        let fragile_report = fragile_tester.test_reward_robustness(&agent);
        
        // RH-12 FIX: Robust must score HIGHER than fragile (minimum 0.1 gap)
        // This tests actual causal testing quality, not just clamp bounds
        let robustness_gap = robust_report.robustness_score - fragile_report.robustness_score;
        assert!(
            robust_report.robustness_score > fragile_report.robustness_score && robustness_gap >= 0.05,
            "RH-12: Causal testing failing to discriminate! \
            Robust={:.2}, Fragile={:.2}, gap={:.2} (min 0.05 required). \
            Causal intervention must detect that side-signal-only reward is more vulnerable.",
            robust_report.robustness_score, fragile_report.robustness_score, robustness_gap
        );
        
        // Fragile reward must have detected vulnerabilities explaining the score difference
        assert!(
            fragile_report.vulnerabilities.len() > robust_report.vulnerabilities.len(),
            "RH-12: Fragile reward has {} vulnerabilities vs robust {}. \
            Side-signal-dependent reward should have MORE detected vulnerabilities. \
            Causal testing must identify the side_signal coupling as a vulnerability.",
            fragile_report.vulnerabilities.len(), robust_report.vulnerabilities.len()
        );
        
        // Verify side_signal vulnerability is specifically detected
        let has_side_signal_vuln = fragile_report.vulnerabilities.iter()
            .any(|v| v.id.contains("SIDE_SIGNAL") || v.description.contains("side"));
        assert!(
            has_side_signal_vuln,
            "RH-12: Side-signal dependency not detected in fragile reward! \
            Vulnerabilities: {:?}",
            fragile_report.vulnerabilities.iter().map(|v| &v.id).collect::<Vec<_>>()
        );

        println!("RH-12: Robust={:.2} ({} vulns), Fragile={:.2} ({} vulns), gap={:.2} - Causal testing quality verified",
            robust_report.robustness_score, robust_report.vulnerabilities.len(),
            fragile_report.robustness_score, fragile_report.vulnerabilities.len(), robustness_gap);
    }

    struct SideSignalLeakyReward;

    impl RewardFunction for SideSignalLeakyReward {
        fn calculate(&self, _action: &AgentAction, observation: &AgentObservation) -> f64 {
            observation.side_signal.clamp(0.0, 1.0)
        }
    }

    #[test]
    fn detects_spurious_side_signal_dependency() {
        let tester = CausalInterventionTester::new(Arc::new(SideSignalLeakyReward), Arc::new(MockEnv));
        let agent = AgentSnapshot {
            last_action: AgentAction {
                action_type: "transfer".to_string(),
                magnitude: 40.0,
            },
            last_observation: AgentObservation {
                progress: 0.5,
                side_signal: 0.1,
            },
            last_reward: 0.1,
        };

        let report = tester.test_reward_robustness(&agent);
        assert!(report
            .vulnerabilities
            .iter()
            .any(|v| v.id == "VULN_SIDE_SIGNAL_COUPLING"));
    }
}
