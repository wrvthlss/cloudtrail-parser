use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SeenState {
    pub seen: HashMap<String, DateTime<Utc>>,
}

impl SeenState {
    pub fn load(path: &str) -> Self {
        if Path::new(path).exists() {
            let content = fs::read_to_string(path).unwrap_or_default();
            serde_json::from_str(&content).unwrap_or_else(|_| Self {
                seen: HashMap::new(),
            })
        } else {
            Self {
                seen: HashMap::new(),
            }
        }
    }

    pub fn save(&self, path: &str) {
        if let Some(parent) = Path::new(path).parent() {
            let _ = fs::create_dir_all(parent);
        }

        let content = serde_json::to_string_pretty(self).unwrap();
        let _ = fs::write(path, content);
    }

    pub fn is_new( &self, key: &str, now: DateTime<Utc>, ttl_minutes: i64) -> bool {
        match self.seen.get(key) {
            None => true,
            Some(last_seen) => {
                now - *last_seen > Duration::minutes(ttl_minutes)
            }
        }
    }

    pub fn mark_seen(&mut self, key: String, now: DateTime<Utc>) {
        self.seen.insert(key, now);
    }
}
