use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use core::error;

#[derive(Debug, Deserialize)]
struct CloudTrailEvent {
    // rename keeps JSON truth intact.
    #[serde(rename = "eventTime")]
    event_time: Option<String>,

    #[serde(rename = "eventName")]
    event_name: Option<String>,

    #[serde(rename = "eventSource")]
    event_source: Option<String>,

    #[serde(rename = "errorCode")]
    error_code: Option<String>,

    #[serde(rename = "errorMessage")]
    error_message: Option<String>,

    #[serde(rename = "userIdentity")]
    user_identity: Option<Value>,
}

fn resolve_identity(user_identity: &Value) -> String {
    let identity_type = user_identity
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");

    match identity_type {
        "IAMUser" => {
            user_identity
                .get("userName")
                .and_then(|v| v.as_str())
                .map(|u| format!("user: {}", u))
                .unwrap_or("user:<unkown>".to_string())
        }

        "AssumedRole" => {
            if let Some(arn) = user_identity.get("arn").and_then(|v| v.as_str()) {
                // arn:aws:sts::acct:assumed-role/ROLE/SESSION
                if let Some(rest) = arn.split("assumed-role/").nth(1) {
                    return format!("role: {}", rest);
                }
            }

            user_identity
                .get("principalId")
                .and_then(|v| v.as_str())
                .map(|p| format!("role-session: {}", p))
                .unwrap_or("role:<unknown>".to_string())
        }

        "AWSService" => {
            user_identity
                .get("invokedBy")
                .and_then(|v| v.as_str())
                .map(|s| format!("service: {}", s))
                .unwrap_or("service:<unknown>".to_string())
        }

        other => format!("other: {}", user_identity.get("arn").and_then(|v| v.as_str()).unwrap_or(other)),

    }
}

/*
    Result<(u32, u32, HashMap<std::string::String, Vec<DateTime<Utc>>>) 
        u32     -> Total events
        u32     -> Total errors
        HashMap -> Key: String, Val: Datetime
 */
pub fn process_cloudtrail_file(path: &str) -> Result<(u32, u32, HashMap<(String, String), Vec<DateTime<Utc>>>), Box<dyn error::Error>> {
    let raw = fs::read_to_string(path)?;
    let data: Value = serde_json::from_str(&raw)?;

    let mut total_events = 0;
    let mut error_events = 0;

    // For time windows, place timestamps.
    let mut errors_by_identity: HashMap<(String, String), Vec<DateTime<Utc>>> = HashMap::new();

    if let Some(records) = data.get("Records").and_then(|v| v.as_array()) {
        for record in records {
            total_events += 1;

            let event: CloudTrailEvent = match serde_json::from_value(record.clone()) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // If parsing fails, the event will not participate in time-based logic.
            let event_time = event
                .event_time
                .as_ref()
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map(|dt| dt.with_timezone(&Utc));

            // Gracefully handle roles vs users.
            let identity = event
                .user_identity
                .as_ref()
                .map(resolve_identity)
                .unwrap_or("identity:<missing>".to_string());

            if event.error_code.is_some() {
                error_events += 1;

                if let (Some(event_name), Some(ts)) = (event.event_name.as_ref(), event_time) {
                    errors_by_identity
                        .entry((identity.clone(), event_name.clone()))
                        .or_insert_with(Vec::new)
                        .push(ts);
                }
            }
        }
    }

    Ok((total_events, error_events, errors_by_identity))
}
