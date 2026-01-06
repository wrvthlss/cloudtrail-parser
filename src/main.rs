use core::error;
use std::fs;
use serde_json::Value;
use serde::Deserialize;

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
}

fn main() -> Result<(), Box<dyn error::Error>> {
    // 1. Read file as text
    let raw = 
        fs::read_to_string("data/896288137645_CloudTrail_us-east-1_20260105T1610Z_f6znwV3nxqXH7yyg.json")?;

    // Parse the JSON into a dynamic `Value`
    let data: Value = serde_json::from_str(&raw)?;

    let mut total_events = 0;
    let mut error_events = 0;

    if let Some(records) = data.get("Records").and_then(|v| v.as_array()) {
        println!("Found {} CloudTrail records \n", records.len());

        for(idx, record) in records.iter().enumerate() {
            total_events += 1;

            let event: CloudTrailEvent = match serde_json::from_value(record.clone()) {
                Ok(e) => e,
                Err(_) => continue,
            };

            println!("Event {}:", idx + 1);
            println!("  Time:   {}", event.event_time.as_deref().unwrap_or("<missing>"));
            println!("  Name:   {}", event.event_name.as_deref().unwrap_or("<missing>"));
            println!("  Source:   {}", event.event_source.as_deref().unwrap_or("<missing>"));
            
            // Errors
            if let Some(code) = &event.error_code {
                error_events += 1;
                println!("  [!] ERROR: {}", code);

                if let Some(msg) = &event.error_message {
                    println!("  Message: {}", msg);
                }
            }

            println!();
        }
        println!("[+] Summary:");
        println!("  Total Events: {}", total_events);
        println!("  Error Events: {}", error_events);
    } else {
        println!("[!] Top level `Records` key not found.")
    }

    Ok(())
}
