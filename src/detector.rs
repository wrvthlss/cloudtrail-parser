use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

use crate::config::DetectorConfig;

#[derive(Clone, Copy, Debug)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        };
        write!(f, "{}", s)
    }
}

pub struct DetectionRule {
    pub name: String,
    pub threshold: u32,
    pub window_minutes: i64,
    pub severity: Severity,
}


// Returns a list of (identity, windowed_error_count).
// For identities that exceed the configured threshold
pub fn detect_suspicious_identities( errors: &HashMap<(String, String), Vec<DateTime<Utc>>>, config: &DetectorConfig) -> Vec<((String, String), u32)> {
    let mut suspicious: Vec<((String, String), u32)> = Vec::new();

    for (key, timestamps) in errors {
        if timestamps.is_empty() {
            continue;
        }

        // Anchor window to THIS identity's most recent error
        let latest = timestamps.iter().max().unwrap();
        let window_start = *latest - Duration::minutes(config.window_minutes);

        let windowed_count = timestamps
            .iter()
            .filter(|ts| **ts >= window_start)
            .count() as u32;

        if windowed_count > config.error_threshold {
            suspicious.push((key.clone(), windowed_count));
        }
    }

    suspicious
}


pub fn detect_with_rules(
    errors: &HashMap<(String, String), Vec<DateTime<Utc>>>,
    rules: &[DetectionRule],
) -> Vec<(String, String, String, Severity, u32)> {
    let mut findings = Vec::new();

    for rule in rules {
        for ((identity, event_name), timestamps) in errors {
            if timestamps.is_empty() {
                continue;
            }

            let latest = timestamps.iter().max().unwrap();
            let window_start = *latest - Duration::minutes(rule.window_minutes);

            let windowed_count = timestamps
                .iter()
                .filter(|ts| **ts >= window_start)
                .count() as u32;

            if windowed_count > rule.threshold {
                findings.push((
                    identity.clone(),
                    event_name.clone(),
                    rule.name.clone(),
                    rule.severity,
                    windowed_count,
                ));
            }
        }
    }

    findings
}
