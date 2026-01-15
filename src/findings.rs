use chrono::{DateTime, Utc};

use crate::detector::Severity;

/*
    dedup_key() -- state tracking
    last_seen   -- reason about alert freshness
    source      -- allows multi-input engines without being hacky (no branching!)
 */
#[derive(Debug, Clone)]
pub struct Finding {
    pub source: String,        // "CloudTrail" | "Linux/SSH"
    pub rule: String,          // Rule name
    pub severity: Severity,
    pub identity: String,
    pub event: String,
    pub count: u32,
    pub window_minutes: i64,
    pub last_seen: DateTime<Utc>,
}

impl Finding {
    pub fn dedup_key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.rule,
            self.identity,
            self.event
        )
    }
}
