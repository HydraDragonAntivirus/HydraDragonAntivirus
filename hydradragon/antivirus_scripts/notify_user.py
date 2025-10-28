#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
notify_user.py

All notification functions converted to async. Blocking operations (Win32 pipe writes,
MD5 computation, desktop notifications) are executed in the default threadpool via
asyncio.to_thread to keep the event loop responsive.
"""
import json
import win32file
import pywintypes
import asyncio
from datetime import datetime, timezone
from typing import Optional
from .hydra_logger import logger
from notifypy import Notify
from .path_and_variables import (
    malicious_hashes,
    malicious_hashes_lock,
    PIPE_AV_TO_EDR
)
from .utils_and_helpers import compute_md5

# ============================================================================
# PIPE 1: Sending Threat Events TO Owlyshield EDR (async)
# ============================================================================

def _sync_write_pipe(message_bytes: bytes) -> None:
    """
    Synchronous helper to open the named pipe, write bytes, and close the handle.
    Run this inside a thread with asyncio.to_thread to avoid blocking the event loop.
    """
    handle = None
    try:
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
    finally:
        try:
            if handle:
                win32file.CloseHandle(handle)
        except Exception:
            pass


async def _send_av_event_to_edr(file_path: str,
                                virus_name: str,
                                action: str = "monitor",
                                pid: Optional[int] = None,
                                main_file_path: Optional[str] = None) -> None:
    """
    (Internal) Async: Connects to the Owlyshield EDR pipe and sends a threat event.
    Offloads blocking pipe operations to a thread.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec='seconds'),
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
        message_bytes = json.dumps(event).encode("utf-8")
        await asyncio.to_thread(_sync_write_pipe, message_bytes)
        logger.info(f"Successfully sent threat event to EDR for: {file_path}")
    except pywintypes.error as e:
        if hasattr(e, "winerror") and e.winerror == 2:
            logger.error("Could not connect to Owlyshield EDR. Is the service running?")
        else:
            logger.error(f"Failed to send threat event to EDR: {e}")
    except Exception as e:
        logger.error(f"Unexpected error sending threat event to EDR: {e}")


async def _send_to_edr(
    target_path: str,
    threat_name: str,
    action: str,
    main_file_path: Optional[str] = None
) -> None:
    """
    Async helper to forward to EDR.
    """
    try:
        await _send_av_event_to_edr(
            target_path,
            threat_name,
            action=action,
            main_file_path=main_file_path
        )
    except TypeError:
        # Defensive fallback: if signature mismatch (unlikely since module updated),
        # attempt to call without main_file_path.
        try:
            await _send_av_event_to_edr(target_path, threat_name, action=action)
        except Exception as e:
            logger.exception(f"Failed to forward to EDR (fallback): {e}")
    except Exception as e:
        logger.exception(f"Failed forwarding to EDR: {e}")


async def _add_malicious_hash(file_path: str, virus_name: str) -> None:
    """
    Compute MD5 hash of file and add it with its associated virus name to the global tracking dict.
    Offloads compute_md5 and dict update to a thread to avoid blocking.
    """
    def _sync_compute_and_store(fp: str, vname: str):
        try:
            file_hash = compute_md5(fp)
            # malicious_hashes_lock may be a threading.Lock — use it synchronously here
            with malicious_hashes_lock:
                malicious_hashes[file_hash] = vname
            logger.info(f"Added malicious hash: {file_hash} ({fp}) -> {vname}")
        except Exception as e:
            logger.error(f"Failed to compute hash for {fp}: {e}")

    await asyncio.to_thread(_sync_compute_and_store, file_path, virus_name)


# --- NEW: Notification function for MBR Protection Alerts ---
async def notify_user_mbr_alert(file_path: str) -> None:
    """
    Async: Notify the user about a blocked MBR write attempt and send a critical alert to the EDR.
    """
    try:
        notification = Notify()
        notification.title = "CRITICAL: MBR Write Attempt Blocked"
        notification_message = (
            f"A process attempted to modify the Master Boot Record (MBR) and was blocked.\n\n"
            f"Offending Process: {file_path}"
        )
        notification.message = notification_message

        # send desktop notification offloaded
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)

        # Define threat and send it to the EDR
        threat_name = "Radical MBR Change Attempt"

        # Add hash and forward (both async)
        await _add_malicious_hash(file_path, threat_name)
        await _send_to_edr(file_path, threat_name, action="kill_and_remove")

    except Exception as e:
        logger.exception(f"notify_user_mbr_alert failed: {e}")


# --- Notification Functions (Now fully async) ---

async def notify_user(file_path, virus_name, engine_detected, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "Malware Alert"
        notification_message = f"Malicious file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user failed: {e}")


async def notify_user_pua(file_path, virus_name, engine_detected, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "PUA Alert"
        notification_message = f"PUA file detected: {file_path}\nVirus: {virus_name}\nDetected by: {engine_detected}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_pua failed: {e}")


async def notify_user_hayabusa_critical(event_log, rule_title, details, computer) -> None:
    try:
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
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        threat_name = f"Hayabusa Critical: {rule_title}"
        await _send_to_edr(event_log, threat_name, action="kill_and_remove")
    except Exception as e:
        logger.exception(f"notify_user_hayabusa_critical failed: {e}")


async def notify_user_for_malicious_source_code(file_path, virus_name, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = f"Malicious Source Code detected: {virus_name}"
        notification_message = f"Suspicious source code detected in: {file_path}\nVirus: {virus_name}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.error(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_for_malicious_source_code failed: {e}")


async def notify_user_size_warning(file_path, archive_type, virus_name, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "Size Warning"
        notification_message = (f"{archive_type} file {file_path} is smaller than 20MB but contains a large file "
                                f"which might be suspicious. Virus Name: {virus_name}")
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_size_warning failed: {e}")


async def notify_user_susp_archive_file_name_warning(file_path, archive_type, virus_name, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "Suspicious Filename In Archive Warning"
        notification_message = (
            f"The filename in the {archive_type} archive '{file_path}' contains a suspicious pattern: {virus_name}."
        )
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_susp_archive_file_name_warning failed: {e}")


async def notify_user_susp_name(file_path, virus_name, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "Suspicious Name Alert"
        notification_message = f"Suspicious file detected: {file_path}\nVirus: {virus_name}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_susp_name failed: {e}")


async def notify_user_scr(file_path, virus_name, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "Suspicious .SCR File Detected"
        notification_message = f"Suspicious .scr file detected: {file_path}\nVirus: {virus_name}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(f"ALERT: {notification_message}")
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_scr failed: {e}")


async def notify_user_for_detected_fake_system_file(file_path, file_name, virus_name, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "Fake System File Alert"
        notification_message = (
            f"Fake system file detected:\n"
            f"File Path: {file_path}\n"
            f"File Name: {file_name}\n"
            f"Threat: {virus_name}"
        )
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_for_detected_fake_system_file failed: {e}")


async def notify_user_invalid(file_path, virus_name, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "Fully Invalid signature Alert"
        notification_message = f"Fully Invalid signature file detected: {file_path}\nVirus: {virus_name}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_invalid failed: {e}")


async def notify_user_fake_size(file_path, virus_name, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "Fake Size Alert"
        notification_message = f"Fake size file detected: {file_path}\nVirus: {virus_name}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_fake_size failed: {e}")


async def notify_user_startup(file_path, message, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "Startup File Alert"
        notification_message = f"File: {file_path}\n{message}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        virus_name = f"Startup Alert: {message}"
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_startup failed: {e}")


async def notify_user_exela_stealer_v2(file_path, virus_name, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "Exela Stealer version 2 Alert in Python source code"
        notification_message = f"Potential Exela Stealer version 2 detected: {file_path}\nVirus: {virus_name}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_exela_stealer_v2 failed: {e}")


async def notify_user_hosts(file_path, virus_name, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "Host Hijacker Alert"
        notification_message = f"Potential host hijacker detected: {file_path}\nVirus: {virus_name}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="monitor", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_hosts failed: {e}")


async def notify_user_for_web(domain: Optional[str] = None,
                              ipv4_address: Optional[str] = None,
                              ipv6_address: Optional[str] = None,
                              url: Optional[str] = None,
                              file_path: Optional[str] = None,
                              detection_type: Optional[str] = None) -> None:
    """
    Lightweight web notification. If file_path is provided, add to EDR as a file event.
    """
    try:
        notification = Notify()
        notification.title = "Malware or Phishing Alert"
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
            message_parts.append(f"File Path: {file_path}")

        notification.message = "Phishing or Malicious activity detected:\n" + "\n".join(message_parts)
        try:
            await asyncio.to_thread(notification.send)
        except Exception:
            logger.exception("Failed to send desktop notification (continuing).")

        logger.critical(notification.message)

        if file_path:
            threat_name = f"WebThreat: {domain or url or ipv4_address or ipv6_address or detection_type or 'web'}"
            try:
                await _add_malicious_hash(file_path, threat_name)
                await _send_to_edr(file_path, threat_name, action="kill_and_remove")
            except Exception:
                logger.exception(f"Failed to forward web alert to EDR for {file_path}")

    except Exception as ex:
        logger.exception(f"notify_user_for_web failed: {ex}")


async def notify_user_for_web_source(
    domain: Optional[str] = None,
    ipv4_address: Optional[str] = None,
    ipv6_address: Optional[str] = None,
    url: Optional[str] = None,
    file_path: Optional[str] = None,
    detection_type: Optional[str] = None,
    main_file_path: Optional[str] = None
) -> None:
    """
    Web notification that includes source file context.
    """
    try:
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
        try:
            await asyncio.to_thread(notification.send)
        except Exception:
            logger.exception("Failed to send desktop notification (continuing).")
        logger.critical(notification_message)

        # Prefer directly associated file for EDR; fall back to main file.
        edr_file_param = file_path or main_file_path
        if not edr_file_param:
            logger.info("No file context available - not forwarding web-only alert to EDR as a file event.")
            return

        threat_name = f"WebThreat: {domain or url or ipv4_address or ipv6_address or detection_type or 'web'}"

        try:
            await _add_malicious_hash(edr_file_param, threat_name)
            # forward with main_file_path included where available
            await _send_to_edr(edr_file_param, threat_name, action="kill_only", main_file_path=main_file_path)
        except Exception:
            logger.exception(f"Failed to forward web alert to EDR for {edr_file_param}")

    except Exception as ex:
        logger.exception(f"notify_user_for_web_source failed: {ex}")


async def notify_user_for_detected_hips_file(file_path, src_ip, alert_line, status, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "(Verified) Web Malware Alert For File"
        notification_message = f"{status} file detected by Web related Message: {file_path}\nSource IP: {src_ip}\nAlert Line: {alert_line}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        virus_name = f"HIPS Alert: {alert_line}"
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_for_detected_hips_file failed: {e}")


async def notify_user_duplicate(file_path, file_hash: str, known_virus_name: str) -> None:
    """
    Notify user about a duplicate malicious file that was already detected.
    Still forwards to EDR for tracking.
    """
    try:
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
        await asyncio.to_thread(notification.send)
        logger.warning(notification_message)
        await _send_to_edr(file_path, f"Duplicate: {known_virus_name}", action="kill_and_remove")
    except Exception as e:
        logger.exception(f"notify_user_duplicate failed: {e}")


async def notify_user_for_uefi(file_path, virus_name, main_file_path: Optional[str] = None) -> None:
    try:
        notification = Notify()
        notification.title = "(Verified) UEFI Malware Alert"
        notification_message = f"Suspicious UEFI file detected: {file_path}\nVirus: {virus_name}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)

        logger.critical(notification_message)
        await _add_malicious_hash(file_path, virus_name)
        await _send_to_edr(file_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_for_uefi failed: {e}")


# ============================================================================
# Self-Defense Alert Notifications (async)
# ============================================================================

async def notify_user_self_defense_file(file_path: str, attacker_path: str, attacker_pid: int, main_file_path: Optional[str] = None) -> None:
    """
    Notify user about file tampering attempt blocked by self-defense driver.
    """
    try:
        notification = Notify()
        notification.title = "Self-Defense File Protection Alert"
        notification_message = f"File tampering attempt blocked: {file_path}\nAttacker Process: {attacker_path}\nAttacker PID: {attacker_pid}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        virus_name = f"Self-Defense Alert: File Tampering by PID {attacker_pid}"
        await _add_malicious_hash(attacker_path, virus_name)
        await _send_to_edr(attacker_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_self_defense_file failed: {e}")


async def notify_user_self_defense_process(protected_process: str, attacker_path: str, attacker_pid: int, main_file_path: Optional[str] = None) -> None:
    """
    Notify user about process kill attempt blocked by self-defense driver.
    """
    try:
        notification = Notify()
        notification.title = "Self-Defense Process Protection Alert"
        notification_message = f"Process kill attempt blocked: {protected_process}\nAttacker Process: {attacker_path}\nAttacker PID: {attacker_pid}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        virus_name = f"Self-Defense Alert: Process Kill Attempt by PID {attacker_pid}"
        await _add_malicious_hash(attacker_path, virus_name)
        await _send_to_edr(attacker_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_self_defense_process failed: {e}")


async def notify_user_self_defense_registry(registry_path: str, attacker_path: str, attacker_pid: int, operation: str, main_file_path: Optional[str] = None) -> None:
    """
    Notify user about registry tampering attempt blocked by self-defense driver.
    """
    try:
        notification = Notify()
        notification.title = "Self-Defense Registry Protection Alert"
        notification_message = f"Registry tampering attempt blocked: {registry_path}\nOperation: {operation}\nAttacker Process: {attacker_path}\nAttacker PID: {attacker_pid}"
        notification.message = notification_message
        await asyncio.to_thread(notification.send)
        logger.critical(notification_message)
        virus_name = f"Self-Defense Alert: Registry {operation} Attempt by PID {attacker_pid}"
        await _add_malicious_hash(attacker_path, virus_name)
        await _send_to_edr(attacker_path, virus_name, action="kill_and_remove", main_file_path=main_file_path)
    except Exception as e:
        logger.exception(f"notify_user_self_defense_registry failed: {e}")
