import json
import datetime
import os
import win32file
import win32pipe
import pywintypes
import threading
import time
import ctypes
from pathlib import Path
from hydra_logger import logger

# Pipe 1: HydraDragon SENDS threat events TO Owlyshield (Owlyshield receives)
PIPE_AV_TO_EDR = r"\\.\pipe\hydradragon_to_owlyshield"

# Pipe 2: Owlyshield SENDS scan requests TO HydraDragon (HydraDragon receives)
PIPE_EDR_TO_AV = r"\\.\pipe\owlyshield_to_hydradragon"

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
# PIPE 1: Sending Threat Events TO Owlyshield EDR
# ============================================================================

def _send_av_event_to_edr(file_path: str, virus_name: str, action: str = "monitor", pid: int = None):
    """
    (Internal) Connects to the Owlyshield EDR pipe and sends a threat event.
    This function is called by the notification functions below.
    """
    if not win32file:
        logger.warning("pywin32 not found, skipping EDR event.")
        return

    if not file_path:
        logger.warning("No file_path provided, skipping EDR event.")
        return

    event = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "file_path": str(file_path),
        "virus_name": str(virus_name),
        "is_malicious": True,
        "detection_type": "signature",
        "action_required": action,
        "pid": pid,
        "gid": None
    }

    try:
        message_bytes = json.dumps(event).encode('utf-8')
        handle = win32file.CreateFile(
            PIPE_AV_TO_EDR,
            win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        win32file.WriteFile(handle, message_bytes)
        win32file.CloseHandle(handle)
        logger.info(f"Successfully sent threat event to EDR for: {file_path}")
    except pywintypes.error as e:
        if hasattr(e, 'winerror') and e.winerror == 2:
            logger.error(f"Could not connect to Owlyshield EDR. Is the service running?")
        else:
            logger.error(f"Failed to send threat event to EDR: {e}")
    except Exception as e:
        logger.error(f"Unexpected error sending threat event to EDR: {e}")


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
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
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
            logger.error(f"Could not connect to HydraDragon AV. Is the service running?")
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
                logger.warning(f"HydraDragon disconnected from threat event pipe.")
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
# Integration Startup
# ============================================================================

def start_dual_pipe_integration():
    """
    Starts both pipe listeners in separate threads:
    - Pipe 1: Receives threat events FROM HydraDragon
    - Pipe 2: Sends scan requests TO HydraDragon (on-demand via _send_scan_request_to_av)
    """
    # Start the threat event listener thread (Pipe 1)
    threat_listener_thread = threading.Thread(
        target=monitor_threat_events_from_av,
        name="HydraDragon-ThreatListener"
    )
    threat_listener_thread.start()
    logger.info("Dual-pipe integration started successfully")
