pub struct DetectorConfig {
    pub error_threshold: u32,
    pub window_minutes: i64,
}

impl DetectorConfig {
    pub fn default() -> Self {
        Self {
            error_threshold: 3,
            window_minutes: 5,
        }
    }
}