use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

use crate::config::DetectorConfig;
use crate::findings::Finding;

#[derive(Clone, Copy, Debug)]
pub enum Severity {
    Low,
    Medium,
    High,
}

pub struct DetectionRule {
    pub name: String,
    pub threshold: u32,
    pub window_minutes: i64,
    pub severity: Severity,
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
    source: &str,
    errors: &HashMap<(String, String), Vec<DateTime<Utc>>>,
    rules: &[DetectionRule],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        for ((identity, event_name), timestamps) in errors {
            if timestamps.is_empty() {
                continue;
            }

            // Per-identity/event anchor
            let latest = timestamps.iter().max().unwrap();
            let window_start = *latest - Duration::minutes(rule.window_minutes);

            let windowed: Vec<&DateTime<Utc>> = timestamps
                .iter()
                .filter(|ts| **ts >= window_start)
                .collect();

            let count = windowed.len() as u32;

            if count > rule.threshold {
                findings.push(Finding {
                    source: source.to_string(),
                    rule: rule.name.clone(),
                    severity: rule.severity.clone(),
                    identity: identity.clone(),
                    event: event_name.clone(),
                    count,
                    window_minutes: rule.window_minutes,
                    last_seen: *latest,
                });
            }
        }
    }

    findings
}