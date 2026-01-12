use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

use crate::config::DetectorConfig;

// Returns a list of (identity, windowed_error_count).
// For identities that exceed the configured threshold
pub fn detect_suspicious_identities(
    errors: &HashMap<(String, String), Vec<DateTime<Utc>>>,
    config: &DetectorConfig,
) -> Vec<((String, String), u32)> {
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
