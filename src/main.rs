mod config;
mod parser;
mod detector;
mod linux_parser;
mod findings;
mod state;

use config::DetectorConfig;
use parser::process_cloudtrail_file;
use linux_parser::parse_ssh_journal;
use findings::Finding;
use state::SeenState;

use core::error;
use std::fs;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use std::env;


use crate::detector::{DetectionRule, detect_with_rules, Severity};

fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("  None");
        return;
    }

    for f in findings {
        println!(
            "  [{}:{:?}] {} :: {} ({} events in {}m)",
            f.rule,
            f.severity,
            f.identity,
            f.event,
            f.count,
            f.window_minutes
        );
    }
}

fn main() -> Result<(), Box<dyn error::Error>> {
    //  --- Parse CLI args ---
    let args: Vec<String> = env::args().collect();

    let mut threshold = 3;
    let mut window = 5;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--threshold" => {
                threshold = args.get(i + 1)
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(threshold);
                i += 2;
            }
            "--window" => {
                window = args.get(i + 1)
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(window);
                i += 2;
            }
            _ => i += 1,
        }
    }


    let config = DetectorConfig::new(threshold, window);

    let log_dir = "data";

    let mut grand_total_events = 0;
    let mut grand_error_events = 0;
    let mut grand_errors_by_identity: HashMap<(String, String), Vec<DateTime<Utc>>> = HashMap::new();

    let rules = vec![
        DetectionRule {
            name: "Burst AccessDenied".to_string(),
            threshold: config.error_threshold,
            window_minutes: config.window_minutes,
            severity: Severity::Medium,
        },
    ];

    let state_path = ".state/seen.json";
    let mut state = SeenState::load(state_path);
    let now = chrono::Utc::now();
    let ttl_minutes = 60;


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
    let linux_log_path = "data/ssh.log";
    let linux_errors = parse_ssh_journal(linux_log_path)?;
    let linux_findings = detect_with_rules("Linux/SSH", &linux_errors, &rules);
    let cloud_findings = detect_with_rules("CloudTrail", &grand_errors_by_identity, &rules);

    println!("\n[!] NEW FINDINGS:");

    let mut new_findings = Vec::new();

    for f in cloud_findings.iter().chain(linux_findings.iter()) {
        let key = f.dedup_key();

        if state.is_new(&key, now, ttl_minutes) {
            new_findings.push(f.clone());
            state.mark_seen(key, now);
        }
    }

    if new_findings.is_empty() {
        println!("  None");
    } else {
        for f in &new_findings {
            println!(
                "  [{}:{:?}] {} :: {} ({} events in {}m)",
                f.rule,
                f.severity,
                f.identity,
                f.event,
                f.count,
                f.window_minutes
            );
        }
    }

    state.save(state_path);
    Ok(())
}