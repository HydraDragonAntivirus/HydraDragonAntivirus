use serde::Serialize;

/// Unified verdict produced by the HydraDragonAV scan pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    Trusted,
    Clean,
    Pua,
    Suspicious,
    Phishing,
    Malware,
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Trusted => "Trusted",
            Verdict::Clean => "Clean",
            Verdict::Pua => "PUA",
            Verdict::Suspicious => "Suspicious",
            Verdict::Phishing => "Phishing",
            Verdict::Malware => "Malware",
        }
    }

    pub fn priority(&self) -> u8 {
        match self {
            Verdict::Trusted => 0,
            Verdict::Clean => 1,
            Verdict::Pua => 2,
            Verdict::Suspicious => 3,
            Verdict::Phishing => 4,
            Verdict::Malware => 5,
        }
    }

    pub fn aggregate(verdicts: &[Verdict]) -> Verdict {
        let mut result = Verdict::Clean;
        for &v in verdicts {
            match v {
                Verdict::Trusted => {
                    if result == Verdict::Clean {
                        result = Verdict::Trusted;
                    }
                }
                Verdict::Malware => return Verdict::Malware,
                _ => {
                    if v.priority() > result.priority() {
                        result = v;
                    }
                }
            }
        }
        result
    }
}

/// Detailed result from each engine in the pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct EngineResult {
    pub engine: &'static str,
    pub verdict: Verdict,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

/// Final scan result combining all engine outputs.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub verdict: Verdict,
    pub threat_name: Option<String>,
    pub engines: Vec<EngineResult>,
    pub yara_x_matches: Vec<String>,
    pub ml_malware_probability: Option<f32>,
    pub clamav_result: Option<String>,
}
