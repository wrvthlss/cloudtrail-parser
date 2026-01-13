pub struct DetectorConfig {
    pub error_threshold: u32,
    pub window_minutes: i64,
}

// Detector policy.
// todo: Implement CLI configuration.
impl DetectorConfig {
    pub fn default() -> Self {
        Self {
            error_threshold: 3,
            window_minutes: 5,
        }
    }
}

impl DetectorConfig {
    pub fn new(error_threshold: u32, window_minutes: i64) -> Self {
        Self {
            error_threshold,
            window_minutes,
        }
    }
}