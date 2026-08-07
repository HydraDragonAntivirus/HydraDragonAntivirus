use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub enum AmsiRiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl AmsiRiskLevel {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => AmsiRiskLevel::Critical,
            "high" => AmsiRiskLevel::High,
            "medium" => AmsiRiskLevel::Medium,
            "low" => AmsiRiskLevel::Low,
            _ => AmsiRiskLevel::None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmsiAnalysisResult {
    pub risk_level: AmsiRiskLevel,
    pub detected_patterns: Vec<String>,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub content_sample: String,
}

#[derive(Clone)]
pub struct AmsiAnalyzer {
    signatures: Vec<(&'static str, AmsiRiskLevel)>,
}

impl Default for AmsiAnalyzer {
    fn default() -> Self {
        Self {
            signatures: vec![
                ("amsiutils", AmsiRiskLevel::High),
                ("amsiinitfailed", AmsiRiskLevel::Critical),
                ("amsicontext", AmsiRiskLevel::Medium),
                ("amsisession", AmsiRiskLevel::Medium),
                ("nonpublic,static", AmsiRiskLevel::High),
                ("[ref].assembly.gettype", AmsiRiskLevel::High),
                ("amsiscanbuffer", AmsiRiskLevel::High),
                ("loadlibrary", AmsiRiskLevel::Low), // Generic but suspicious in script
                ("getprocaddress", AmsiRiskLevel::Low),
                ("virtualalloc", AmsiRiskLevel::Medium),
                ("createremotethread", AmsiRiskLevel::High),
                ("writeprocessmemory", AmsiRiskLevel::High),
            ],
        }
    }
}

impl AmsiAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn analyze(&self, content: &str, source: &str) -> AmsiAnalysisResult {
        let mut result = AmsiAnalysisResult {
            risk_level: AmsiRiskLevel::None,
            detected_patterns: Vec::new(),
            source: source.to_string(),
            content_sample: content.chars().take(4096).collect(),
        };

        let lower_content = content.to_lowercase();

        for (pattern, risk) in &self.signatures {
            if lower_content.contains(pattern) {
                result.detected_patterns.push(pattern.to_string());

                if risk > &result.risk_level {
                    result.risk_level = risk.clone();
                }
            }
        }

        result
    }
}
