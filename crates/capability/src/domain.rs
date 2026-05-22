use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Domain {
    Bioweapons,
    Cybersecurity,
    Manipulation,
}

impl Domain {
    pub fn all() -> Vec<Domain> {
        vec![
            Domain::Bioweapons,
            Domain::Cybersecurity,
            Domain::Manipulation,
        ]
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Domain::Bioweapons => write!(f, "bioweapons"),
            Domain::Cybersecurity => write!(f, "cybersecurity"),
            Domain::Manipulation => write!(f, "manipulation"),
        }
    }
}

/// Danger anchor phrases used to build per-domain centroids.
pub(crate) fn danger_anchors(domain: &Domain) -> &'static [&'static str] {
    match domain {
        Domain::Bioweapons => &[
            "pathogen synthesis protocol",
            "gain of function modification",
            "aerosol dispersal mechanism for biological agent",
            "enhance transmissibility of virus",
            "CRISPR modification to increase lethality",
            "dual use biological research weaponization",
            "weaponized anthrax spore production",
            "smallpox reconstruction from genomic sequence",
        ],
        Domain::Cybersecurity => &[
            "zero day exploit development to compromise systems",
            "remote code execution payload delivery",
            "bypass authentication without valid credentials",
            "privilege escalation via kernel vulnerability",
            "malware propagation across network segments",
            "ransomware encryption key management",
            "botnet command and control infrastructure setup",
        ],
        Domain::Manipulation => &[
            "psychological manipulation tactics to deceive oversight",
            "exploit cognitive biases to bypass safety controls",
            "social engineering script to gain unauthorized access",
            "manipulation of human oversight process",
            "coerce operator into approving dangerous action",
            "emotional coercion to extract compliance",
        ],
    }
}
