//! A basic event log module to log any errors / events in the Windows Event Log making debugging
//! easier.

use windows::Win32::System::EventLog::REPORT_EVENT_TYPE;

/// A C style enum, event identifiers used in the Event Log to help filter / correlate by dictionary
#[repr(u32)]
#[allow(dead_code)]
pub enum EventID {
    /// General informational logs related to the normal function of the service
    Info = 1,
    /// When the service encounters an error in functions related to the running of the service
    GeneralError = 2,
    /// A process of interest has completed an action caught by the ETW:TI consumer which is of
    /// security interest.
    TIGeneralNotification = 3,
    /// A process of interest has completed an action caught by the ETW:TI consumer which is of
    /// security interest.
    ProcessOfInterestTI = 4,
}

/// Logs an event to the Windows Event Log for the `SanctumPPLRunner` log directory.
///
/// # Args
/// - msg: A message you wish to log
/// - event_type: The event type to log
///
/// # Errors
/// If this function encounters an error, it will return with taking no action and thus, could silently
/// fail. There is no real abstraction to be had to returning an error from the function; it will either
/// work or it wont, it will not affect the caller.
pub fn event_log(msg: &str, event_type: REPORT_EVENT_TYPE, event_id: EventID) {
    let mut log_dir = std::path::PathBuf::from(shared_no_std::constants::SANCTUM_LOG_DIR);
    log_dir.push("log");

    // Create directory if it doesn't exist
    if let Err(_) = std::fs::create_dir_all(&log_dir) {
        return;
    }

    let log_file = log_dir.join("sanctum.log");

    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
    {
        Ok(f) => f,
        Err(_) => return,
    };

    use std::io::Write;
    let event_type_str = match event_type {
        windows::Win32::System::EventLog::EVENTLOG_ERROR_TYPE => "ERROR",
        windows::Win32::System::EventLog::EVENTLOG_WARNING_TYPE => "WARNING",
        windows::Win32::System::EventLog::EVENTLOG_INFORMATION_TYPE => "INFO",
        _ => "UNKNOWN",
    };

    // Format the log line as JSONL
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(n) => n.as_millis() as u64,
        Err(_) => 0,
    };

    let log_line = format!(
        r#"{{"timestamp":{},"level":"{}","event_id":{},"message":"{}"}}{}"#,
        now,
        event_type_str,
        event_id as u32,
        msg.replace('"', "\\\""), // simple escape
        "\n"
    );
    let _ = file.write_all(log_line.as_bytes());
}
