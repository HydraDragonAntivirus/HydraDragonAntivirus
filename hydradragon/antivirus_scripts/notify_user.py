from hydra_logger import logger
from notifypy import Notify
from .pipe_events import _send_av_event_to_edr

# --- Notification Functions (Now with EDR Integration) ---

def notify_user(file_path, virus_name, engine_detected):
    notification = Notify()
    notification.title = "Malware Alert"
    notification_message = f"Malicious file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_av_event_to_edr(file_path, virus_name, action="kill_and_remove")

def notify_user_pua(file_path, virus_name, engine_detected):
    notification = Notify()
    notification.title = "PUA Alert"
    notification_message = f"PUA file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_av_event_to_edr(file_path, virus_name, action="quarantine")

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
    _send_av_event_to_edr(event_log, f"Hayabusa Critical: {rule_title}", action="kill_and_remove")

def notify_user_for_malicious_source_code(file_path, virus_name):
    notification = Notify()
    notification.title = f"Malicious Source Code detected: {virus_name}"
    notification_message = f"Suspicious source code detected in: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.error(notification_message)
    _send_av_event_to_edr(file_path, virus_name, action="monitor")

def notify_user_for_detected_command(message, file_path):
    notification = Notify()
    notification.title = "Malware Message Alert"
    notification.message = (
        f"{message}\n\n"
        f"Related to: {file_path}\n"
        f"(This does not necessarily mean the file is malware.)"
    )
    notification.send()
    logger.critical(f"Notification: {notification.message}")
    _send_av_event_to_edr(file_path, f"Detected Command: {message}", action="monitor")

def notify_user_size_warning(file_path, archive_type, virus_name):
    notification = Notify()
    notification.title = "Size Warning"
    notification_message = (f"{archive_type} file {file_path} is smaller than 20MB but contains a large file "
                            f"which might be suspicious. Virus Name: {virus_name}")
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_av_event_to_edr(file_path, virus_name, action="monitor")

def notify_susp_archive_file_name_warning(file_path, archive_type, virus_name):
    notification = Notify()
    notification.title = "Suspicious Filename In Archive Warning"
    notification_message = (
        f"The filename in the {archive_type} archive '{file_path}' contains a suspicious pattern: {virus_name}."
    )
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_av_event_to_edr(file_path, virus_name, action="monitor")

def notify_user_susp_name(file_path, virus_name):
    notification = Notify()
    notification.title = "Suspicious Name Alert"
    notification_message = f"Suspicious file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_av_event_to_edr(file_path, virus_name, action="monitor")

def notify_user_scr(file_path, virus_name):
    notification = Notify()
    notification.title = "Suspicious .SCR File Detected"
    notification_message = f"Suspicious .scr file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(f"ALERT: {notification_message}")
    _send_av_event_to_edr(file_path, virus_name, action="kill_and_remove")

def notify_user_for_detected_fake_system_file(file_path, file_name, virus_name):
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
    _send_av_event_to_edr(file_path, virus_name, action="kill_and_remove")

def notify_user_invalid(file_path, virus_name):
    notification = Notify()
    notification.title = "Fully Invalid signature Alert"
    notification_message = f"Fully Invalid signature file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_av_event_to_edr(file_path, virus_name, action="monitor")

def notify_user_fake_size(file_path, virus_name):
    notification = Notify()
    notification.title = "Fake Size Alert"
    notification_message = f"Fake size file detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_av_event_to_edr(file_path, virus_name, action="monitor")

def notify_user_startup(file_path, message):
    notification = Notify()
    notification.title = "Startup File Alert"
    notification_message = f"File: {file_path}\n{message}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_av_event_to_edr(file_path, f"Startup Alert: {message}", action="kill_and_remove")

def notify_user_exela_stealer_v2(file_path, virus_name):
    notification = Notify()
    notification.title = "Exela Stealer version 2 Alert in Python source code"
    notification_message = f"Potential Exela Stealer version 2 detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_av_event_to_edr(file_path, virus_name, action="kill_and_remove")

def notify_user_hosts(file_path, virus_name):
    notification = Notify()
    notification.title = "Host Hijacker Alert"
    notification_message = f"Potential host hijacker detected: {file_path}\nVirus: {virus_name}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_av_event_to_edr(file_path, virus_name, action="monitor")

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
        _send_av_event_to_edr(file_path, threat_name, action="kill_and_remove")

def notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status):
    notification = Notify()
    notification.title = "(Verified) Web Malware Alert For File"
    notification_message = f"{status} file detected by Web related Message: {file_path}\nSource IP: {src_ip}\nAlert Line: {alert_line}"
    notification.message = notification_message
    notification.send()
    logger.critical(notification_message)
    _send_av_event_to_edr(file_path, f"HIPS Alert: {alert_line}", action="kill_and_remove")
