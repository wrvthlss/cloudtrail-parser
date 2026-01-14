use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use std::collections::HashMap;
use std::fs;

// Parse a journalctl export for sshd and return:
//  (identity, event_name) -> timestamps

// identity: "user:<name>@<src_ip>"
// event_name: "ssh_invalid_user" or "ssh_failed_password"
pub fn parse_ssh_journal( path: &str,) -> Result<HashMap<(String, String), Vec<DateTime<Utc>>>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mut out: HashMap<(String, String), Vec<DateTime<Utc>>> = HashMap::new();

    // journalctl default format starts with: "Jan 07 11:48:14 ..."
    // There is not year, so inject it.
    let year = Utc::now().year();

    for line in content.lines() {
        let event_name = if line.contains("Invalid user ") {
            "ssh_invalid_user"
        } else if line.contains("Failed password") {
            "ssh_failed_password"
        } else {
            continue;
        };

        // Parse timestamp (Month Day HH:MM:SS)
        let ts_prefix = line.get(0..15).unwrap_or("");
        let naive = parse_journal_ts(ts_prefix, year)?;
        let ts_utc: DateTime<Utc> = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);

        // Extract user + source
        let user = extract_user(line).unwrap_or("unknown");
        let src = extract_source(line).unwrap_or("unknown");

        let identity = format!("user:{}@{}", user, src);
        let key = (identity, event_name.to_string());

        out.entry(key).or_insert_with(Vec::new).push(ts_utc);
    }

    Ok(out)
}

fn parse_journal_ts(prefix: &str, year: i32) -> Result<NaiveDateTime, Box<dyn std::error::Error>> {
    // prefix like "Jan 07 11:48:14" -- build "2026 Jan 07 11:48:14"
    let full = format!("{} {}", year, prefix);
    let naive = NaiveDateTime::parse_from_str(&full, "%Y %b %d %H:%M:%S")?;
    Ok(naive)
}

fn extract_user(line: &str) -> Option<&str> {
    // Handles:
    //  "Invalid user doesnotexist from ::1 ..."
    //  "Failed password for invalid user doesnotexist from ::1 ..."
    if let Some(rest) = line.split("Invalid user ").nth(1) {
        return rest.split_whitespace().next();
    }

    if let Some(rest) = line.split("Failed password for invalid user ").nth(1) {
        return rest.split_whitespace().next();
    }

    if let Some(rest) = line.split("Failed password for ").nth(1) {
        return rest.split_whitespace().next();
    }

    None
}

fn extract_source(line: &str) -> Option<&str> {
    // "... from ::1 port 33368"
    line.split(" from ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
}