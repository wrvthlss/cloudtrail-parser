mod config;
mod parser;
mod detector;

use config::DetectorConfig;
use parser::process_cloudtrail_file;
use detector::detect_suspicious_identities;

use core::error;
use std::fs;
use std::collections::HashMap;
use chrono::{DateTime, Utc};


fn main() -> Result<(), Box<dyn error::Error>> {
    let config = DetectorConfig::default();

    let log_dir = "data";

    let mut grand_total_events = 0;
    let mut grand_error_events = 0;
    let mut grand_errors_by_identity: HashMap<(String, String), Vec<DateTime<Utc>>> = HashMap::new();

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

                // merge identity -- time based.
                for (identity, mut timestamps) in identities {
                    grand_errors_by_identity
                        .entry(identity)
                        .or_insert_with(Vec::new)
                        .append(&mut timestamps);
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

    // --- Detection --- //
    let suspicious = detect_suspicious_identities(&grand_errors_by_identity, &config);

    println!("\n[!] Suspicious Identities (>{} errors in last {} minutes):",
        config.error_threshold,
        config.window_minutes
    );

    if suspicious.is_empty() {
        println!(" None");
    } else {
        for ((identity, event_name), count) in &suspicious {
            println!(" {} :: {} ({} errors)", identity, event_name, count);
        }
    }

    println!("\n[+] Normal Identities:");
    for (identity, timestamps) in &grand_errors_by_identity {
        let total = timestamps.len() as u32;

        if !suspicious.iter().any(|(id, _)| id == identity) {
            println!(" {} :: {} ({} errors)", identity.0, identity.1, total);
        }
    }

    Ok(())
}