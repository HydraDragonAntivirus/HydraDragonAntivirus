"""
notify_user.py

Updated notification functions that accept an optional `main_file_path` argument and forward
it to `_send_av_event_to_edr` when present. Automatically computes MD5 hash for all files
and tracks malicious hashes with their associated virus names.
"""
import json
import win32file
import pywintypes
from datetime import datetime
from typing import Optional
from hydra_logger import logger
from notifypy import Notify
from .path_and_variables import (
    malicious_hashes,
    malicious_hashes_lock
)
from .utils_and_helpers import compute_md5


# Pipe 1: HydraDragon SENDS threat events TO Owlyshield (Owlyshield receives)
PIPE_AV_TO_EDR = r"\\.\pipe\hydradragon_to_owlyshield"

# ============================================================================
# PIPE 1: Sending Threat Events TO Owlyshield EDR
# ============================================================================

def _send_av_event_to_edr(file_path: str,
                          virus_name: str,
                          action: str = "monitor",
                          pid: Optional[int] = None,
                          main_file_path: Optional[str] = None):
    """
    (Internal) Connects to the Owlyshield EDR pipe and sends a threat event.
    Accepts optional main_file_path for compatibility.
    """
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "file_path": str(file_path),
        "virus_name": str(virus_name),
        "is_malicious": True,
        "detection_type": "signature",
        "action_required": action,
        "pid": pid,
        "gid": None
    }

    if main_file_path:
        event["main_file_path"] = str(main_file_path)

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
            logger.error("Could not connect to Owlyshield EDR. Is the service running?")
        else:
            logger.error(f"Failed to send threat event to EDR: {e}")
    except Exception as e:
        logger.error(f"Unexpected error sending threat event to EDR: {e}")

def _send_to_edr(
    target_path: str,
    threat_name: str,
    action: str,
    main_file_path: Optional[str] = None
) -> None:
    """
    Helper to forward to EDR while remaining backward compatible with
    older _send_av_event_to_edr signatures.
    """
    try:
        if main_file_path is not None:
            # Try with main_file_path
            _send_av_event_to_edr(
                target_path,
                threat_name,
                action=action,
                main_file_path=main_file_path
            )
        else:
            # Call without main_file_path
            _send_av_event_to_edr(target_path, threat_name, action=action)
    except TypeError:
        # Fallback if older _send_av_event_to_edr doesn't accept main_file_path
        _send_av_event_to_edr(target_path, threat_name, action=action)

def _add_malicious_hash(file_path: str, virus_name: str):
    """Compute MD5 hash of file and add it with its associated virus name to the global tracking dict."""
    try:
        file_hash = compute_md5(file_path)
        with malicious_hashes_lock:
            malicious_hashes[file_hash] = virus_name
            logger.info(f"Added malicious hash: {file_hash} ({file_path}) -> {virus_name}")
    except Exception as e:
        logger.error(f"Failed to compute hash for {file_path}: {e}")


# --- NEW: Notification function for MBR Protection Alerts ---

def notify_user_mbr_alert(file_path: str):
    """
    Notify the user about a blocked MBR write attempt and send a critical alert to the EDR.
    """
    notification = Notify()
    notification.title = "CRITICAL: MBR Write Attempt Blocked"
    notification_message = (
        f"A process attempted to modify the Master Boot Record (MBR) and was blocked.\n\n"
        f"Offending Process: {file_path}"
    )
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    
    # Define the threat and send it to the EDR for immediate action
    threat_name = "Radical MBR Change Attempt"
    
    # Add hash of the offending executable for future tracking
    _add_malicious_hash(file_path, threat_name)
    
    # Send to EDR with a clear "kill and remove" action
    _send_to_edr(file_path, threat_name, action="kill_and_remove")


# --- Notification Functions (Now with EDR Integration, main_file_path, and automatic hash tracking) ---

def notify_user(file_path, virus_name, engine_detected, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Malware Alert"
    notification_message = f"Malicious file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_pua(file_path, virus_name, engine_detected, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "PUA Alert"
    notification_message = f"PUA file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_hayabusa_critical(event_log, rule_title, details, computer):
    notification = Notify()
    notification.title = "Critical Security Event Detected"
    notification_message = (
        f"CRITICAL event detected by Hayabusa:\n"
        f"Computer: {computer}\n"
        f"Event Log: {event_log}\n"
        f"Rule: {rule_title}\n"
        f"Details: {details}"
    )
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    threat_name = f"Hayabusa Critical: {rule_title}"
    _send_to_edr(event_log, threat_name, action="kill_and_remove")


def notify_user_for_malicious_source_code(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = f"Malicious Source Code detected: {virus_name}"
    notification_message = f"Suspicious source code detected in: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.error(notification_message)
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_size_warning(file_path, archive_type, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Size Warning"
    notification_message = (f"{archive_type} file {file_path} is smaller than 20MB but contains a large file "
                            f"which might be suspicious. Virus Name: {virus_name}")
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_susp_archive_file_name_warning(file_path, archive_type, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Suspicious Filename In Archive Warning"
    notification_message = (
        f"The filename in the {archive_type} archive '{file_path}' contains a suspicious pattern: {virus_name}."
    )
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_susp_name(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Suspicious Name Alert"
    notification_message = f"Suspicious file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_scr(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Suspicious .SCR File Detected"
    notification_message = f"Suspicious .scr file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(f"ALERT: {notification_message}")
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_for_detected_fake_system_file(file_path, file_name, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Fake System File Alert"
    notification_message = (
        f"Fake system file detected:\n"
        f"File Path: {file_path}\n"
        f"File Name: {file_name}\n"
        f"Threat: {virus_name}"
    )
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_invalid(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Fully Invalid signature Alert"
    notification_message = f"Fully Invalid signature file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_fake_size(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Fake Size Alert"
    notification_message = f"Fake size file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_startup(file_path, message, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Startup File Alert"
    notification_message = f"File: {file_path}\n{message}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    virus_name = f"Startup Alert: {message}"
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_exela_stealer_v2(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Exela Stealer version 2 Alert in Python source code"
    notification_message = f"Potential Exela Stealer version 2 detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_hosts(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Host Hijacker Alert"
    notification_message = f"Potential host hijacker detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_for_web(domain=None, ipv4_address=None, ipv6_address=None, url=None, file_path=None, detection_type=None):
    notification = Notify()
    notification.title = "Malware or Phishing Alert"
    message_parts = []
    if detection_type: message_parts.append(f"Detection Type: {detection_type}")
    if domain: message_parts.append(f"Domain: {domain}")
    if ipv4_address: message_parts.append(f"IPv4 Address: {ipv4_address}")
    if ipv6_address: message_parts.append(f"IPv6 Address: {ipv6_address}")
    if url: message_parts.append(f"URL: {url}")
    if file_path: message_parts.append(f"File Path: {file_path}")

    notification_message = "Phishing or Malicious activity detected:\n" + "\n".join(message_parts)
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    
    # Only send to EDR if a file_path is associated with the web alert
    if file_path:
        threat_name = f"WebThreat: {domain or url or ipv4_address}"
        _add_malicious_hash(file_path, threat_name)
        _send_to_edr(file_path, threat_name, action="kill_and_remove")


def notify_user_for_web_source(
    domain: Optional[str] = None,
    ipv4_address: Optional[str] = None,
    ipv6_address: Optional[str] = None,
    url: Optional[str] = None,
    file_path: Optional[str] = None,
    detection_type: Optional[str] = None,
    main_file_path: Optional[str] = None
):
    """
    Web-related notification that includes source file context (if available).
    - file_path: the file that *directly* references the web artifact (e.g. downloaded HTML, script)
    - main_file_path: the primary source file that triggered the web detection (e.g. decompiled source)
    If either file_path or main_file_path is present, the function will forward an EDR event containing
    that path using _send_to_edr(..., main_file_path=...).
    """
    notification = Notify()
    notification.title = "Malicious Web/Phishing Alert (with source)"
    message_parts = []
    if detection_type:
        message_parts.append(f"Detection Type: {detection_type}")
    if domain:
        message_parts.append(f"Domain: {domain}")
    if ipv4_address:
        message_parts.append(f"IPv4 Address: {ipv4_address}")
    if ipv6_address:
        message_parts.append(f"IPv6 Address: {ipv6_address}")
    if url:
        message_parts.append(f"URL: {url}")
    if file_path:
        message_parts.append(f"Associated File: {file_path}")
    if main_file_path:
        message_parts.append(f"Source File: {main_file_path}")

    notification_message = "Phishing or Malicious web activity detected:\n" + "\n".join(message_parts)
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)

    # Prefer the directly associated file_path for EDR; otherwise use main_file_path.
    edr_file_param = file_path or main_file_path

    # Build a reasonable threat name for EDR
    threat_name = f"WebThreat: {domain or url or ipv4_address or ipv6_address or detection_type}"

    # Only forward to EDR when we have a file context (to avoid sending domain-only alerts as file events)
    if edr_file_param:
        _add_malicious_hash(edr_file_param, threat_name)
        _send_to_edr(edr_file_param, threat_name, action="kill_and_remove", main_file_path=main_file_path)
    else:
        # No file available; do not send file-based EDR event. If you want web-only EDR events, change to monitor.
        logger.info("No file context available - not forwarding web-only alert to EDR as a file event.")


def notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "(Verified) Web Malware Alert For File"
    notification_message = f"{status} file detected by Web related Message: {file_path}\nSource IP: {src_ip}\nAlert Line: {alert_line}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    virus_name = f"HIPS Alert: {alert_line}"
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)

def notify_user_duplicate(file_path, file_hash: str, known_virus_name: str):
    """
    Notify user about a duplicate malicious file that was already detected.
    This is a lighter notification since we already know it's malicious.
    """
    notification = Notify()
    notification.title = "Duplicate Malware Detected"
    notification_message = (
        f"Duplicate malicious file detected:\n"
        f"File: {file_path}\n"
        f"Hash: {file_hash[:16]}...\n"
        f"Previously identified as: {known_virus_name}\n"
        f"Action: Skipped scanning (already known malware)"
    )
    notification.message = notification_message
    notification.send()
    logger.warning(notification_message)
    # Still send to EDR for tracking purposes
    _send_to_edr(file_path, f"Duplicate: {known_virus_name}", action="kill_and_remove")

def notify_user_for_uefi(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "(Verified) UEFI Malware Alert"
    notification_message = f"Suspicious UEFI file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()

    logger.critical(notification_message)

    # Register hash and propagate to EDR
    _add_malicious_hash(file_path, virus_name)
    _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)

# ============================================================================
# Self-Defense Alert Notifications
# ============================================================================

def notify_user_self_defense_file(file_path: str, attacker_path: str, attacker_pid: int, main_file_path: Optional[str] = None):
    """
    Notify user about file tampering attempt blocked by self-defense driver.
    """
    notification = Notify()
    notification.title = "Self-Defense File Protection Alert"
    notification_message = f"File tampering attempt blocked: {file_path}\nAttacker Process: {attacker_path}\nAttacker PID: {attacker_pid}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    virus_name = f"Self-Defense Alert: File Tampering by PID {attacker_pid}"
    _add_malicious_hash(attacker_path, virus_name)
    _send_to_edr(attacker_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_self_defense_process(protected_process: str, attacker_path: str, attacker_pid: int, main_file_path: Optional[str] = None):
    """
    Notify user about process kill attempt blocked by self-defense driver.
    """
    notification = Notify()
    notification.title = "Self-Defense Process Protection Alert"
    notification_message = f"Process kill attempt blocked: {protected_process}\nAttacker Process: {attacker_path}\nAttacker PID: {attacker_pid}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    virus_name = f"Self-Defense Alert: Process Kill Attempt by PID {attacker_pid}"
    _add_malicious_hash(attacker_path, virus_name)
    _send_to_edr(attacker_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_self_defense_registry(registry_path: str, attacker_path: str, attacker_pid: int, operation: str, main_file_path: Optional[str] = None):
    """
    Notify user about registry tampering attempt blocked by self-defense driver.
    """
    notification = Notify()
    notification.title = "Self-Defense Registry Protection Alert"
    notification_message = f"Registry tampering attempt blocked: {registry_path}\nOperation: {operation}\nAttacker Process: {attacker_path}\nAttacker PID: {attacker_pid}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    virus_name = f"Self-Defense Alert: Registry {operation} Attempt by PID {attacker_pid}"
    _add_malicious_hash(attacker_path, virus_name)
    _send_to_edr(attacker_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
