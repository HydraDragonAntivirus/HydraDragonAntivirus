import json
from datetime import datetime, timezone
import os
import win32file
import win32pipe
import pywintypes
import threading
import time
import ctypes
from pathlib import Path
from hydra_logger import logger
# Import notification functions
from .notify_user import (
    notify_user_mbr_alert,
    notify_user_self_defense_file,
    notify_user_self_defense_process,
    notify_user_self_defense_registry,
)
from .path_and_variables import (
    PIPE_AV_TO_EDR,
    PIPE_EDR_TO_AV,
    PIPE_MBR_ALERT,
    PIPE_SELF_DEFENSE_ALERT,
    system_root,
    system32_dir,
)

thread_lock = threading.Lock()


# ============================================================================
# Protected Path Utilities
# ============================================================================

# Constant special item ID list value for desktop folder
CSIDL_DESKTOPDIRECTORY = 0x0010

# Flag for SHGetFolderPath
SHGFP_TYPE_CURRENT = 0

# Convenient shorthand for this function
SHGetFolderPathW = ctypes.windll.shell32.SHGetFolderPathW

def _get_folder_path(csidl):
    """Get the path of a folder identified by a CSIDL value."""
    # Create a buffer to hold the return value from SHGetFolderPathW
    buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)

    # Return the path as a string
    SHGetFolderPathW(None, csidl, None, SHGFP_TYPE_CURRENT, buf)
    return str(buf.value)


def get_desktop():
    """Return the current user's Desktop folder."""
    return _get_folder_path(CSIDL_DESKTOPDIRECTORY)

def _normalize_path_for_compare(p: str) -> str:
    """Return a normalized lower-case absolute path for reliable comparison."""
    try:
        abs_p = os.path.abspath(p)
    except Exception:
        abs_p = p
    # normcase will lower-case on Windows and normalize slashes
    return os.path.normcase(os.path.normpath(abs_p))


def _path_is_under(prefix: str, candidate: str) -> bool:
    """Return True if candidate is the same as or is under prefix."""
    prefix_n = _normalize_path_for_compare(prefix)
    candidate_n = _normalize_path_for_compare(candidate)
    if candidate_n == prefix_n:
        return True
    # Ensure we only treat a true ancestor as match (avoid partial-name matches)
    return candidate_n.startswith(prefix_n + os.sep)


def _contains_hydradragon_ancestor(path: str) -> bool:
    """Return True if any ancestor directory is named 'HydraDragonAntivirus' (case-insensitive)."""
    try:
        parts = Path(path).parts
    except Exception:
        parts = _normalize_path_for_compare(path).split(os.sep)
    for part in parts:
        if part.lower() == "hydradragonantivirus":
            return True
    return False


def _is_protected_path(candidate_path: str) -> bool:
    """Return True if candidate_path is within a protected/special folder we should NOT scan."""
    candidate = _normalize_path_for_compare(candidate_path)

    # Program Files HydraDragonAntivirus (look up PROGRAMFILES env)
    program_files = os.environ.get("PROGRAMFILES") or r"C:\Program Files"
    pf_hda = os.path.join(program_files, "HydraDragonAntivirus")
    if _path_is_under(pf_hda, candidate):
        return True

    # %APPDATA%\Sanctum
    appdata = os.environ.get("APPDATA")
    if appdata:
        app_sanctum = os.path.join(appdata, "Sanctum")
        if _path_is_under(app_sanctum, candidate):
            return True

    # Desktop\Sanctum
    try:
        desktop = get_desktop()
    except Exception:
        desktop = None
    if desktop:
        desktop_sanctum = os.path.join(desktop, "Sanctum")
        if _path_is_under(desktop_sanctum, candidate):
            return True

    # Also skip if any ancestor folder is named HydraDragonAntivirus
    if _contains_hydradragon_ancestor(candidate):
        return True

    return False


# ============================================================================
# System executable detection
# ============================================================================

def _is_system_executable(path: str) -> bool:
    """Return True if the path refers to a Windows system executable.

    Heuristics used:
    - Path is under %SystemRoot% (e.g., C:\Windows) or System32/Sysnative
    - Filename matches a small allowlist of well-known system executables
    """
    if not path:
        return False

    candidate = _normalize_path_for_compare(path)

    # Check if under SystemRoot (covers explorer.exe in %WINDIR%)
    if _path_is_under(system_root, candidate):
        return True

    # Check System32 (handles Sysnative mapping)
    if _path_is_under(system32_dir, candidate):
        return True

    # Known system executable basenames (lower-case)
    system_basenames = {
        "explorer.exe",
        "cmd.exe",
        "regedit.exe",
        "powershell.exe",
        "pwsh.exe",
        "svchost.exe",
        "services.exe",
        "lsass.exe",
        "wininit.exe",
        "winlogon.exe",
        "csrss.exe",
        "smss.exe",
    }

    base = os.path.basename(candidate).lower()
    if base in system_basenames:
        return True

    return False


# ============================================================================
# PIPE 2: Receiving Scan Requests FROM Owlyshield EDR
# ============================================================================

def _send_scan_request_to_av(file_path: str, event_type: str = "NEW_FILE_DETECTED", pid: int = None):
    """
    Sends a scan request FROM Owlyshield TO HydraDragon AV.
    Called when EDR detects a new file that needs scanning.
    """
    # Check if the file is in a protected path before sending the request
    if _is_protected_path(file_path):
        logger.debug(f"Skipping scan request for protected path: {file_path}")
        return
    
    request = {
        "event_type": event_type,
        "file_path": str(file_path),
        "timestamp": datetime.now(timezone.utc).isoformat(),  # timezone-aware UTC
        "pid": pid,
        "additional_context": None
    }

    try:
        message_bytes = json.dumps(request).encode('utf-8')
        handle = win32file.CreateFile(
            PIPE_EDR_TO_AV,
            win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        win32file.WriteFile(handle, message_bytes)
        win32file.CloseHandle(handle)
        logger.info(f"Successfully sent scan request to HydraDragon for: {file_path}")
    except pywintypes.error as e:
        if hasattr(e, 'winerror') and e.winerror == 2:
            logger.error("Could not connect to HydraDragon AV. Is the service running?")
        else:
            logger.error(f"Failed to send scan request to HydraDragon: {e}")
    except Exception as e:
        logger.error(f"Unexpected error sending scan request to HydraDragon: {e}")


def _process_threat_event(data: str):
    """
    Process incoming threat events from HydraDragon AV.
    This is called by the Pipe 1 listener when HydraDragon detects malware.
    """
    try:
        event = json.loads(data)
        if not isinstance(event, dict):
            logger.warning(f"Received valid JSON, but it was not an object: {data}")
            return

        file_path = event.get("file_path")
        virus_name = event.get("virus_name")
        is_malicious = event.get("is_malicious", False)
        action_required = event.get("action_required", "monitor")
        
        # Skip processing if this is a protected path (shouldn't happen, but safety check)
        if file_path and _is_protected_path(file_path):
            logger.debug(f"Ignoring threat event for protected path: {file_path}")
            return
        
        logger.info(f"Received threat event from HydraDragon: {file_path} - {virus_name} (malicious: {is_malicious})")
        
        # Here you can trigger Owlyshield's response actions
        # For example, kill the process, quarantine the file, etc.
        if is_malicious and action_required == "kill_and_remove":
            logger.critical(f"CRITICAL THREAT DETECTED: {file_path} - {virus_name}")
            # Add your response logic here
            # e.g., kill_process(event.get("pid")), quarantine_file(file_path)
        
    except json.JSONDecodeError:
        logger.error(f"Failed to parse threat event JSON from HydraDragon: {data}")
    except Exception as e:
        logger.exception(f"Error processing threat event: {e}")


def monitor_threat_events_from_av(pipe_name: str = PIPE_AV_TO_EDR):
    """
    Pipe 1 Server: Listens for threat events FROM HydraDragon AV.
    This runs in a separate thread and continuously receives malware detections.
    """
    logger.info(f"Starting threat event listener from HydraDragon on: {pipe_name}")
    
    while True:
        pipe = None
        try:
            # Create the named pipe to RECEIVE threat events from AV
            pipe = win32pipe.CreateNamedPipe(
                pipe_name,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                None
            )

            logger.info("Waiting for HydraDragon to send threat events...")
            win32pipe.ConnectNamedPipe(pipe, None)
            logger.info("HydraDragon connected to threat event pipe.")

            # Read the threat event data
            full_message = []
            while True:
                hr, data = win32file.ReadFile(pipe, 4096)
                if not data:
                    break
                full_message.append(data)
            
            decoded_message = b"".join(full_message).decode('utf-8', errors='replace')
            logger.debug(f"Received threat event of {len(decoded_message)} bytes")

            if decoded_message:
                with thread_lock:
                    _process_threat_event(decoded_message)

        except pywintypes.error as e:
            if e.winerror in [109, 232]:  # BROKEN_PIPE or ERROR_NO_DATA
                logger.warning("HydraDragon disconnected from threat event pipe.")
            else:
                logger.error(f"Windows API Error in threat listener: {e.strerror} (Code: {e.winerror})")
            time.sleep(1)
        except Exception as e:
            logger.exception(f"Unexpected error in threat event listener: {e}")
            time.sleep(5)
        finally:
            if pipe:
                win32pipe.DisconnectNamedPipe(pipe)
                win32file.CloseHandle(pipe)


# ============================================================================
# PIPE 3: MBR Alert Pipe Listener
# ============================================================================

def _process_mbr_alert(data: bytes):
    """
    Process incoming MBR write alerts from the kernel driver.
    """
    try:
        # The data from the kernel is a UTF-16LE encoded string (UNICODE_STRING)
        offending_path = data.decode('utf-16-le').strip('\x00')
        logger.critical(f"Received MBR write alert from kernel. Offending process: {offending_path}")
        
        # Call the notification function to alert user and EDR
        notify_user_mbr_alert(offending_path)
        
    except Exception as e:
        logger.exception(f"Error processing MBR alert: {e}")


def monitor_mbr_alerts_from_kernel(pipe_name: str = PIPE_MBR_ALERT):
    """
    MBR Pipe Server: Listens for MBR write alerts FROM the MBRFilter driver.
    This runs in a separate thread and continuously receives alerts.
    """
    logger.info(f"Starting MBR alert listener from MBRFilter.sys on: {pipe_name}")
    
    while True:
        pipe = None
        try:
            # Create the named pipe to RECEIVE alerts from the kernel driver
            pipe = win32pipe.CreateNamedPipe(
                pipe_name,
                win32pipe.PIPE_ACCESS_INBOUND, # Driver only writes, we only read
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                None
            )

            logger.info("Waiting for MBRFilter.sys to send alerts...")
            win32pipe.ConnectNamedPipe(pipe, None)
            logger.info("MBRFilter.sys connected to MBR alert pipe.")

            # Read the alert data (this will be the process path)
            hr, data = win32file.ReadFile(pipe, 4096)
            
            if data:
                with thread_lock:
                    _process_mbr_alert(data)

        except pywintypes.error as e:
            if e.winerror in [109, 232]:  # BROKEN_PIPE or ERROR_NO_DATA
                logger.warning("MBRFilter.sys disconnected from MBR alert pipe.")
            else:
                logger.error(f"Windows API Error in MBR listener: {e.strerror} (Code: {e.winerror})")
            time.sleep(1)
        except Exception as e:
            logger.exception(f"Unexpected error in MBR alert listener: {e}")
            time.sleep(5)
        finally:
            if pipe:
                win32pipe.DisconnectNamedPipe(pipe)
                win32file.CloseHandle(pipe)


# ============================================================================
# PIPE 4: Self-Defense Alert Pipe Listener
# ============================================================================

def _process_self_defense_alert(data: bytes):
    """
    Process incoming self-defense alerts from the kernel drivers.
    The data is a JSON-like string with attack details.

    IMPORTANT: If the attacker is a system executable (e.g., under %SystemRoot% or a
    well-known system binary), we intentionally skip sending notifications to EDR to
    avoid noisy/false-positive escalation.
    """
    try:
        # The data from the kernel is UTF-16LE encoded
        message_str = data.decode('utf-16-le').strip('\x00')
        logger.debug(f"Raw self-defense alert: {message_str}")
        
        # Parse the JSON message
        alert_data = json.loads(message_str)
        
        protected_file = alert_data.get("protected_file", "Unknown")
        attacker_path = alert_data.get("attacker_path", "Unknown")
        attacker_pid = alert_data.get("attacker_pid", 0)
        attack_type = alert_data.get("attack_type", "FILE_TAMPERING")
        operation = alert_data.get("operation", "")
        target_pid = alert_data.get("target_pid", 0)

        # Normalize attacker path for checks
        attacker_path_norm = None
        try:
            attacker_path_norm = attacker_path and _normalize_path_for_compare(attacker_path)
        except Exception:
            attacker_path_norm = attacker_path

        # If attacker is a system executable, do NOT escalate to EDR. Log and return.
        if attacker_path_norm and _is_system_executable(attacker_path_norm):
            logger.info(
                f"Self-defense alert suppressed for system executable attacker: {attacker_path}\n"
                f"Protected object: {protected_file}, attack_type: {attack_type}, pid: {attacker_pid}"
            )
            # Optionally: you may want to still create an internal audit entry or local user notification
            # without sending to EDR. For now we just skip calling notify_user_* functions to avoid EDR alerts.
            return

        logger.critical(
            f"Self-Defense Alert: {attack_type} - "
            f"Process {attacker_path} (PID: {attacker_pid}) "
            f"attempted to tamper with {protected_file}"
        )
        
        # Call appropriate notification function based on attack type
        if attack_type == "REGISTRY_TAMPERING":
            notify_user_self_defense_registry(
                registry_path=protected_file,
                attacker_path=attacker_path,
                attacker_pid=attacker_pid,
                operation=operation
            )
        elif attack_type == "PROCESS_KILL":
            notify_user_self_defense_process(
                protected_process=protected_file,
                attacker_path=attacker_path,
                attacker_pid=attacker_pid
            )
        elif attack_type in ["FILE_TAMPERING", "HANDLE_HIJACK"]:
            notify_user_self_defense_file(
                file_path=protected_file,
                attacker_path=attacker_path,
                attacker_pid=attacker_pid
            )
        else:
            # Default to file protection alert
            notify_user_self_defense_file(
                file_path=protected_file,
                attacker_path=attacker_path,
                attacker_pid=attacker_pid
            )
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse self-defense alert JSON: {e}")
        # Fallback: treat as plain text
        try:
            message_str = data.decode('utf-16-le').strip('\x00')
            logger.critical(f"Self-Defense Alert (raw): {message_str}")
        except Exception:
            pass
    except Exception as e:
        logger.exception(f"Error processing self-defense alert: {e}")


def monitor_self_defense_alerts_from_kernel(pipe_name: str = PIPE_SELF_DEFENSE_ALERT):
    """
    Self-Defense Pipe Server: Listens for alerts FROM the self-defense drivers.
    This runs in a separate thread and continuously receives protection alerts.
    """
    logger.info(f"Starting self-defense alert listener on: {pipe_name}")
    
    while True:
        pipe = None
        try:
            # Create the named pipe to RECEIVE alerts from kernel drivers
            pipe = win32pipe.CreateNamedPipe(
                pipe_name,
                win32pipe.PIPE_ACCESS_INBOUND,  # Drivers only write, we only read
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                None
            )

            logger.info("Waiting for self-defense drivers to send alerts...")
            win32pipe.ConnectNamedPipe(pipe, None)
            logger.debug("Self-defense driver connected to alert pipe.")

            # Read the alert data
            hr, data = win32file.ReadFile(pipe, 4096)
            
            if data:
                with thread_lock:
                    _process_self_defense_alert(data)

        except pywintypes.error as e:
            if e.winerror in [109, 232]:  # BROKEN_PIPE or ERROR_NO_DATA
                logger.debug("Self-defense driver disconnected from alert pipe.")
            else:
                logger.error(f"Windows API Error in self-defense listener: {e.strerror} (Code: {e.winerror})")
            time.sleep(1)
        except Exception as e:
            logger.exception(f"Unexpected error in self-defense alert listener: {e}")
            time.sleep(5)
        finally:
            if pipe:
                win32pipe.DisconnectNamedPipe(pipe)
                win32file.CloseHandle(pipe)


# ============================================================================
# Integration Startup
# ============================================================================

def start_all_pipe_listeners():
    """
    Starts all pipe listeners in separate daemon threads:
    - AV Threat Listener (from other AV components)
    - MBR Alert Listener (from kernel driver)
    - Self-Defense Alert Listener (from file/process/registry drivers)
    """
    # Start the AV threat event listener thread
    threat_listener_thread = threading.Thread(
        target=monitor_threat_events_from_av,
        name="HydraDragon-ThreatListener"
    )
    threat_listener_thread.daemon = True
    threat_listener_thread.start()

    # Start the MBR alert listener thread
    mbr_alert_thread = threading.Thread(
        target=monitor_mbr_alerts_from_kernel,
        name="MBR-Alert-Listener"
    )
    mbr_alert_thread.daemon = True
    mbr_alert_thread.start()

    # Start the self-defense alert listener thread
    self_defense_thread = threading.Thread(
        target=monitor_self_defense_alerts_from_kernel,
        name="Self-Defense-Alert-Listener"
    )
    self_defense_thread.daemon = True
    self_defense_thread.start()

    logger.info("All pipe listeners started successfully (AV, MBR, Self-Defense).")
