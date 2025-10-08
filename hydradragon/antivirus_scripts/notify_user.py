"""
notifications_with_main_file_path.py

Updated notification functions that accept an optional `main_file_path` argument and forward
it to `_send_av_event_to_edr` when present. This keeps backward compatibility by only
including `main_file_path` in the EDR call if it's provided.

Drop this file into your package in place of the previous notifications module.
"""
from typing import Optional
from hydra_logger import logger
from notifypy import Notify
from .pipe_events import _send_av_event_to_edr


def _send_to_edr(target_path: str, threat_name: str, action: str, main_file_path: Optional[str] = None):
    """Helper to forward to EDR while remaining backward compatible with
    older _send_av_event_to_edr signatures.
    """
    if main_file_path:
        try:
            _send_av_event_to_edr(target_path, threat_name, action=action, main_file_path=main_file_path)
        except TypeError:
            # Fall back to calling without main_file_path if the target EDR function
            # doesn't accept that kwarg (keeps backward compatibility).
            _send_av_event_to_edr(target_path, threat_name, action=action)
    else:
        _send_av_event_to_edr(target_path, threat_name, action=action)


# --- Notification Functions (Now with EDR Integration and optional main_file_path) ---

def notify_user(file_path, virus_name, engine_detected, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Malware Alert"
    notification_message = f"Malicious file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_pua(file_path, virus_name, engine_detected, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "PUA Alert"
    notification_message = f"PUA file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
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
    _send_to_edr(event_log, threat_name, action="kill_and_remove", main_file_path=None)


def notify_user_for_malicious_source_code(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = f"Malicious Source Code detected: {virus_name}"
    notification_message = f"Suspicious source code detected in: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.error(notification_message)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_size_warning(file_path, archive_type, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Size Warning"
    notification_message = (f"{archive_type} file {file_path} is smaller than 20MB but contains a large file "
                            f"which might be suspicious. Virus Name: {virus_name}")
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
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
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_susp_name(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Suspicious Name Alert"
    notification_message = f"Suspicious file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_scr(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Suspicious .SCR File Detected"
    notification_message = f"Suspicious .scr file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(f"ALERT: {notification_message}")
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
    _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_invalid(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Fully Invalid signature Alert"
    notification_message = f"Fully Invalid signature file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_fake_size(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Fake Size Alert"
    notification_message = f"Fake size file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_startup(file_path, message, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Startup File Alert"
    notification_message = f"File: {file_path}\n{message}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_to_edr(file_path, f"Startup Alert: {message}", action="kill_and_remove", main_file_path=main_file_path)


def notify_user_exela_stealer_v2(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Exela Stealer version 2 Alert in Python source code"
    notification_message = f"Potential Exela Stealer version 2 detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_hosts(file_path, virus_name, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "Host Hijacker Alert"
    notification_message = f"Potential host hijacker detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)


def notify_user_for_web(domain=None, ipv4_address=None, ipv6_address=None, url=None, file_path=None, detection_type=None, main_file_path: Optional[str] = None):
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
        _send_to_edr(file_path, threat_name, action="kill_and_remove", main_file_path=main_file_path)


def notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status, main_file_path: Optional[str] = None):
    notification = Notify()
    notification.title = "(Verified) Web Malware Alert For File"
    notification_message = f"{status} file detected by Web related Message: {file_path}\nSource IP: {src_ip}\nAlert Line: {alert_line}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_to_edr(file_path, f"HIPS Alert: {alert_line}", action="kill_and_remove", main_file_path=main_file_path)
