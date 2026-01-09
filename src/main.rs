use core::error;
use std::fs;
use serde_json::Value;
use serde::Deserialize;
use std::collections::HashMap;

const ERROR_THRESHOLD: u32 = 3;

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

fn process_cloudtrail_file(path: &str) -> Result<(u32, u32, HashMap<std::string::String, u32>), Box<dyn error::Error>> {
        let raw = fs::read_to_string(path)?;
        let data: Value = serde_json::from_str(&raw)?;
    
        let mut total_events = 0;
        let mut error_events = 0;

        let mut errors_by_identity: HashMap<String, u32> = HashMap::new();
    
        if let Some(records) = data.get("Records").and_then(|v| v.as_array()) {
            for record in records {
                total_events += 1;
    
                let event: CloudTrailEvent = match serde_json::from_value(record.clone()) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                // Gracefully handle roles vs users.
                let identity = event
                    .user_identity
                    .as_ref()
                    .map(resolve_identity)
                    .unwrap_or("identity:<missing>".to_string());

                if event.error_code.is_some() {
                    error_events += 1;
                    *errors_by_identity.entry(identity.to_string()).or_insert(0) += 1;
                }
            }
        }
    
        Ok((total_events, error_events, errors_by_identity))
}


fn main() -> Result<(), Box<dyn error::Error>> {
    let log_dir = "data";

    let mut grand_total_events = 0;
    let mut grand_error_events = 0;
    let mut grand_errors_by_identity: HashMap<String, u32> = HashMap::new();

    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let path_str = path.to_string_lossy();
        println!("[*] Processing {}", path_str);

        match process_cloudtrail_file(&path_str) {
            Ok((total, errors, identities)) => {
                println!("  Events: {}, Errors: {}", total, errors);

                grand_total_events += total;
                grand_error_events += errors;

                // merge identity counts
                for(identity, count) in identities {
                    *grand_errors_by_identity
                        .entry(identity)
                        .or_insert(0) += count;
                }
            }
            Err(e) => {
                println!("  [!] Failed to process {}: {}", path_str, e);
            }
        }
    }
    println!("\n[+] Final Summary:");
    println!("  Total Events: {}", grand_total_events);
    println!("  Error Events: {}", grand_error_events);
    println!("\n[+] Error Events by Identity:");

    println!("\n[!] Suspicious Identities (>{} errors):", ERROR_THRESHOLD);
    let mut found_suspicious = false;

    // Identity's count is greater than the error threshold -- suspicious.
    for (identity, count) in &grand_errors_by_identity {
        if *count > ERROR_THRESHOLD {
            println!("  {} ({} errors)", identity, count);
            found_suspicious = true;
        }
    }

    if !found_suspicious {
        println!("  None");
    }

    // Identities that are not greater than the error threshold -- normal.
    println!("\n[+] Normal Identities:");
    for (identity, count) in &grand_errors_by_identity {
        if *count <= ERROR_THRESHOLD {
            println!("  {} ({} errors)", identity, count);
        }
    }

    Ok(())
}