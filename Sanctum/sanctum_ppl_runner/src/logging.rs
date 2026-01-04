//! A basic event log module to log any errors / events in the Windows Event Log making debugging
//! easier.

use windows::{
    Win32::{
        Foundation::CloseHandle,
        System::EventLog::{
            DeregisterEventSource, REPORT_EVENT_TYPE, RegisterEventSourceW, ReportEventW,
        },
    },
    core::PCWSTR,
};

/// A C style enum, event identifiers used in the Event Log to help filter / correlate by dictionary
#[repr(u32)]
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
    // todo consider adding an enum which will exit on error or just return.
    let source: Vec<u16> = "SanctumPPLRunner\0".encode_utf16().collect();

    let handle = match unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(source.as_ptr())) } {
        Ok(h) => h,
        Err(_) => return,
    };

    let msg_wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    let msg_as_pcwstr = PCWSTR(msg_wide.as_ptr());

    // write the event into the event log
    let _ = unsafe {
        ReportEventW(
            handle,
            event_type,
            0,
            event_id as u32, // https://learn.microsoft.com/en-us/windows/win32/eventlog/event-identifiers
            None,
            0,
            Some([msg_as_pcwstr].as_ref()),
            None, // no binary data
        )
    };

    let _ = unsafe { DeregisterEventSource(handle) };

    let _ = unsafe { CloseHandle(handle) };
}
