#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import ctypes
import asyncio
import threading
import win32file
import win32pipe
import win32api
import pywintypes
from typing import Any, Optional
from .hydra_logger import logger
from .notify_user import (
    notify_user_mbr_alert,
    notify_user_self_defense_file,
    notify_user_self_defense_process,
    notify_user_self_defense_registry,
)
from .path_and_variables import (
    PIPE_AV_TO_EDR,
    PIPE_MBR_ALERT,
    PIPE_SELF_DEFENSE_ALERT,
    RAW_PREVIEW_LEN,
    READ_BUFFER_SIZE,
)

# ============================================================================#
# NT Path Normalization
# ============================================================================#

def _sync_normalize_nt_path(nt_path: str) -> str:
    """
    Normalize NT device path to standard Windows path (synchronous).
    Example: \\Device\\HarddiskVolume3\\Program Files\\... -> C:\\Program Files\\...
    """
    if not nt_path:
        return nt_path

    try:
        # Already a normal path
        if ':' in nt_path and not nt_path.startswith('\\Device\\'):
            return os.path.normpath(nt_path)

        # Handle NT device paths like \Device\HarddiskVolume3\...
        if nt_path.startswith('\\Device\\HarddiskVolume'):
            parts = nt_path.split('\\', 3)
            if len(parts) < 4:
                logger.warning(f"Invalid NT path format: {nt_path}")
                return nt_path

            volume_device = '\\'.join(parts[:3])  # \Device\HarddiskVolume3
            relative_path = parts[3]  # Program Files\...

            # Get all logical drives
            drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
            for drive in drives:
                try:
                    drive_letter = drive.rstrip('\\')
                    nt_device = win32file.QueryDosDevice(drive_letter.rstrip(':'))

                    if nt_device and nt_device[0] == volume_device:
                        normalized = os.path.join(drive_letter, relative_path)
                        logger.debug(f"Normalized NT path: {nt_path} -> {normalized}")
                        return os.path.normpath(normalized)
                except Exception:
                    continue

            logger.warning(f"Could not find drive mapping for: {volume_device}")
            return nt_path

        # Handle \??\ format
        elif nt_path.startswith('\\??\\'):
            normalized = nt_path[4:]
            logger.debug(f"Normalized \\??\\ path: {nt_path} -> {normalized}")
            return os.path.normpath(normalized)

        return nt_path

    except Exception as e:
        logger.error(f"Error normalizing NT path '{nt_path}': {e}")
        return nt_path


async def normalize_nt_path(nt_path: str) -> str:
    """Async wrapper for NT path normalization."""
    return await asyncio.to_thread(_sync_normalize_nt_path, nt_path)


# ============================================================================#
# Existing helper functions
# ============================================================================#

# Constant special item ID list value for desktop folder
CSIDL_DESKTOPDIRECTORY = 0x0010
SHGFP_TYPE_CURRENT = 0
SHGetFolderPathW = ctypes.windll.shell32.SHGetFolderPathW

# -------------------------
# Synchronous low-level helpers (kept sync and invoked via to_thread)
# -------------------------
def _sync_get_folder_path(csidl):
    buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
    SHGetFolderPathW(None, csidl, None, SHGFP_TYPE_CURRENT, buf)
    return str(buf.value)


def _sync_normalize_path_for_compare(p: str) -> str:
    try:
        abs_p = os.path.abspath(p)
    except Exception:
        abs_p = p
    return os.path.normcase(os.path.normpath(abs_p))


def _sync_path_is_under(prefix: str, candidate: str) -> bool:
    prefix_n = _sync_normalize_path_for_compare(prefix)
    candidate_n = _sync_normalize_path_for_compare(candidate)
    if candidate_n == prefix_n:
        return True
    return candidate_n.startswith(prefix_n + os.sep)


def _sync_is_protected_path(candidate_path: str) -> bool:
    candidate = _sync_normalize_path_for_compare(candidate_path)

    program_files = os.environ.get("PROGRAMFILES") or r"C:\Program Files"
    pf_hda = os.path.join(program_files, "HydraDragonAntivirus")
    if _sync_path_is_under(pf_hda, candidate):
        return True

    appdata = os.environ.get("APPDATA")
    if appdata:
        app_sanctum = os.path.join(appdata, "Sanctum")
        if _sync_path_is_under(app_sanctum, candidate):
            return True

    try:
        desktop = _sync_get_folder_path(CSIDL_DESKTOPDIRECTORY)
    except Exception:
        desktop = None
    if desktop:
        desktop_sanctum = os.path.join(desktop, "Sanctum")
        if _sync_path_is_under(desktop_sanctum, candidate):
            return True

    return False


def _sync_close_handle(handle):
    try:
        win32file.CloseHandle(handle)
    except Exception:
        try:
            handle.close()
        except Exception:
            pass


# -------------------------
# Async wrappers for helpers (every top-level function is async)
# -------------------------
async def get_desktop() -> str:
    return await asyncio.to_thread(_sync_get_folder_path, CSIDL_DESKTOPDIRECTORY)


async def _is_protected_path(candidate_path: str) -> bool:
    return await asyncio.to_thread(_sync_is_protected_path, candidate_path)


# ============================================================================#
# Threat event processing (AV -> EDR)
# ============================================================================#

async def _process_threat_event(event: Any) -> None:
    """
    Process incoming threat events from HydraDragon AV.
    Accepts either a parsed dict or a JSON string. Normalizes NT paths before processing.
    """
    try:
        # Accept either a parsed dict or a JSON string
        if isinstance(event, str):
            try:
                event = await asyncio.to_thread(json.loads, event)
            except json.JSONDecodeError:
                logger.error(f"[EDR] _process_threat_event: failed to parse JSON string: {event!r}")
                return
        elif not isinstance(event, dict):
            logger.warning(f"[EDR] _process_threat_event: unexpected event type (expected dict or json str): {type(event)}")
            return

        file_path: Optional[str] = event.get("file_path")
        virus_name: Optional[str] = event.get("virus_name")
        is_malicious: bool = bool(event.get("is_malicious", False))
        action_required: str = event.get("action_required", "monitor")

        # Normalize path if it's an NT path
        if file_path:
            try:
                file_path = await normalize_nt_path(file_path)
                event["file_path"] = file_path
            except Exception as e:
                logger.exception(f"[EDR] _process_threat_event: normalize_nt_path failed: {e}")
                # If normalization fails, proceed with original value (or return - choose behavior)
                # return

        # Skip processing if this is a protected path
        try:
            if file_path and await _is_protected_path(file_path):
                logger.debug(f"[EDR] Ignoring threat event for protected path: {file_path}")
                return
        except Exception as e:
            logger.exception(f"[EDR] _process_threat_event: _is_protected_path check failed: {e}")

        logger.info(f"[EDR] Received threat event from HydraDragon: {file_path} - {virus_name} (malicious: {is_malicious})")

        if is_malicious and action_required == "kill_and_remove":
            # Put your critical handling here (kill process, quarantine file, alert operators, etc.)
            logger.critical(f"[EDR] CRITICAL THREAT DETECTED: {file_path} - {virus_name}")
            # you may want to call further async tasks here, e.g.:
            # await take_mitigation_actions(file_path, event)
    except Exception as e:
        logger.exception(f"[EDR] _process_threat_event: unexpected error: {e}")


# ------------------------------
# Thread-safe AV -> EDR listener
# ------------------------------
async def monitor_threat_events_from_av(pipe_name: str = PIPE_AV_TO_EDR) -> None:
    """
    EDR-side server: create a named pipe and read threat events from AV.
    Runs in a dedicated thread to avoid blocking the thread pool.
    """
    logger.info(f"[EDR] Waiting for AV to connect on {pipe_name}")

    # Get event loop reference for scheduling coroutines from worker thread
    loop = asyncio.get_running_loop()

    def pipe_worker():
        """Worker that runs in dedicated thread"""
        while True:
            pipe = None
            try:
                # Create server pipe
                pipe = win32pipe.CreateNamedPipe(
                    pipe_name,
                    win32pipe.PIPE_ACCESS_INBOUND,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    READ_BUFFER_SIZE,
                    READ_BUFFER_SIZE,
                    0,
                    None,
                )
                logger.debug("[EDR] Pipe created, calling ConnectNamedPipe...")

                # Wait for client (blocking is OK in dedicated thread)
                connected = False
                try:
                    win32pipe.ConnectNamedPipe(pipe, None)
                    connected = True
                except pywintypes.error as e:
                    winerr = getattr(e, "winerror", None)
                    if winerr == 535:  # ERROR_PIPE_CONNECTED
                        logger.debug("[EDR] Client already connected")
                        connected = True
                    else:
                        logger.debug(f"[EDR] ConnectNamedPipe error: {e}")

                if not connected:
                    win32pipe.DisconnectNamedPipe(pipe)
                    win32file.CloseHandle(pipe)
                    continue

                logger.info("[EDR] AV client connected to AV->EDR pipe")

                # Read message
                try:
                    hr, data = win32file.ReadFile(pipe, READ_BUFFER_SIZE)
                except pywintypes.error as e:
                    logger.debug(f"[EDR] ReadFile error: {e}")
                    data = None

                if data:
                    try:
                        message = data.decode("utf-8", errors="replace")
                        event = json.loads(message)
                        logger.info(f"[EDR] Received threat event: {event.get('file_path')}")

                        # Schedule processing on event loop
                        asyncio.run_coroutine_threadsafe(
                            _process_threat_event(event),
                            loop
                        )
                    except Exception as e:
                        logger.error(f"[EDR] Error processing threat event: {e}")

            except Exception as e:
                logger.exception(f"[EDR] Pipe error in AV->EDR listener: {e}")
            finally:
                if pipe:
                    try:
                        win32pipe.DisconnectNamedPipe(pipe)
                        win32file.CloseHandle(pipe)
                    except:
                        pass

    # Start in dedicated thread
    thread = threading.Thread(target=pipe_worker, daemon=True, name="AVToEDRPipe")
    thread.start()
    logger.info("[EDR] AV->EDR pipe listener started in dedicated thread")

# ============================================================================#
# MBR alert processing
# ============================================================================#

async def _process_mbr_alert(data: bytes):
    try:
        offending_path = await asyncio.to_thread(lambda: data.decode("utf-16-le").strip("\x00"))

        # Normalize NT path
        offending_path = await normalize_nt_path(offending_path)

        logger.critical(f"Received MBR write alert from kernel. Offending process: {offending_path}")
        # call notification (expected async)
        await notify_user_mbr_alert(offending_path)
    except Exception as e:
        logger.exception(f"Error processing MBR alert: {e}")


async def monitor_mbr_alerts_from_kernel(pipe_name: str = PIPE_MBR_ALERT):
    logger.info(f"Starting MBR alert listener from MBRFilter.sys on: {pipe_name}")
    while True:
        pipe = None
        try:
            pipe = await asyncio.to_thread(
                lambda: win32pipe.CreateNamedPipe(
                    pipe_name,
                    win32pipe.PIPE_ACCESS_INBOUND,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    65536,
                    65536,
                    0,
                    None,
                )
            )
            logger.info("Waiting for MBRFilter.sys to send alerts...")
            await asyncio.to_thread(lambda: win32pipe.ConnectNamedPipe(pipe, None))
            logger.info("MBRFilter.sys connected to MBR alert pipe.")

            try:
                hr, data = await asyncio.to_thread(lambda: win32file.ReadFile(pipe, 4096))
            except pywintypes.error as e:
                logger.debug(f"ReadFile raised in MBR listener: {e}")
                data = None

            if data:
                # process with lock to avoid reentrancy
                async with asyncio.Lock():
                    await _process_mbr_alert(data)

        except pywintypes.error as e:
            if e.winerror in [109, 232]:
                logger.warning("MBRFilter.sys disconnected from MBR alert pipe.")
            else:
                logger.error(f"Windows API Error in MBR listener: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error in MBR alert listener: {e}")
        finally:
            if pipe:
                await asyncio.to_thread(lambda: win32pipe.DisconnectNamedPipe(pipe))
                await asyncio.to_thread(_sync_close_handle, pipe)


# ============================================================================#
# Self-defense alert processing
# ============================================================================#

async def _process_self_defense_alert(data: bytes):
    try:
        # Decode the raw message
        message_str = await asyncio.to_thread(lambda: data.decode("utf-16-le").strip("\x00"))
        logger.debug(f"Raw self-defense alert: {message_str}")

        # FIX: Escape backslashes before JSON parsing
        # Replace single backslashes with double backslashes for JSON
        message_str_escaped = message_str.replace('\\', '\\\\')

        # However, if the string already has escaped backslashes, this would double-escape
        # Better approach: use raw string decoding with json.loads(strict=False)
        try:
            alert_data = await asyncio.to_thread(json.loads, message_str)
        except json.JSONDecodeError:
            # If normal parsing fails, try with escaped backslashes
            logger.warning("JSON parse failed, attempting with escaped backslashes")
            alert_data = await asyncio.to_thread(json.loads, message_str_escaped)

        # Normalize NT paths from kernel
        protected_file = await normalize_nt_path(alert_data.get("protected_file", "Unknown"))
        attacker_path = await normalize_nt_path(alert_data.get("attacker_path", "Unknown"))
        attacker_pid = alert_data.get("attacker_pid", 0)
        attack_type = alert_data.get("attack_type", "FILE_TAMPERING")
        operation = alert_data.get("operation", "")
        target_pid = alert_data.get("target_pid", 0)

        logger.info(
            f"Self-Defense Notification: {attack_type} - "
            f"Process {attacker_path} (Detected PID: {attacker_pid} Target PID: {target_pid}) "
            f"attempted to access {protected_file}"
        )

        # Handle different attack types
        if attack_type == "REGISTRY_TAMPERING":
            await notify_user_self_defense_registry(
                registry_path=protected_file,
                attacker_path=attacker_path,
                attacker_pid=attacker_pid,
                operation=operation,
            )
        elif attack_type == "PROCESS_KILL":
            await notify_user_self_defense_process(
                protected_process=protected_file,
                attacker_path=attacker_path,
                attacker_pid=attacker_pid,
            )
        elif attack_type in ["FILE_TAMPERING", "HANDLE_HIJACK"]:
            await notify_user_self_defense_file(
                file_path=protected_file,
                attacker_path=attacker_path,
                attacker_pid=attacker_pid,
            )

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse self-defense alert JSON: {e}")
        try:
            message_str = await asyncio.to_thread(lambda: data.decode("utf-16-le").strip("\x00"))
            # Log hex dump for debugging
            logger.debug(f"Raw bytes (first 200): {data[:200].hex()}")
        except Exception as decode_error:
            logger.error(f"Could not decode raw alert data: {decode_error}")
    except Exception as e:
        logger.exception(f"Error processing self-defense alert: {e}")

async def monitor_self_defense_alerts_from_kernel(pipe_name: str = PIPE_SELF_DEFENSE_ALERT):
    logger.info(f"Starting self-defense alert listener on: {pipe_name}")
    while True:
        pipe = None
        try:
            pipe = await asyncio.to_thread(
                lambda: win32pipe.CreateNamedPipe(
                    pipe_name,
                    win32pipe.PIPE_ACCESS_INBOUND,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    65536,
                    65536,
                    0,
                    None,
                )
            )

            logger.info("Waiting for self-defense drivers to send alerts...")
            await asyncio.to_thread(lambda: win32pipe.ConnectNamedPipe(pipe, None))
            logger.debug("Self-defense driver connected to alert pipe.")

            try:
                hr, data = await asyncio.to_thread(lambda: win32file.ReadFile(pipe, 4096))
            except pywintypes.error as e:
                logger.debug(f"ReadFile raised in self-defense listener: {e}")
                data = None

            if data:
                async with asyncio.Lock():
                    await _process_self_defense_alert(data)

        except pywintypes.error as e:
            if e.winerror in [109, 232]:
                logger.debug("Self-defense driver disconnected from alert pipe.")
            else:
                logger.error(f"Windows API Error in self-defense listener: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error in self-defense alert listener: {e}")
        finally:
            if pipe:
                await asyncio.to_thread(lambda: win32pipe.DisconnectNamedPipe(pipe))
                await asyncio.to_thread(_sync_close_handle, pipe)


# ============================================================================#
# Integration Startup
# ============================================================================#

async def start_all_pipe_listeners():
    """
    Start all pipe listeners as asyncio tasks.
    Returns task list for monitoring.
    """
    loop = asyncio.get_running_loop()
    tasks = [
        loop.create_task(monitor_threat_events_from_av(), name="AV-to-EDR-ThreatListener"),
        loop.create_task(monitor_mbr_alerts_from_kernel(), name="MBR-Alert-Listener"),
        loop.create_task(monitor_self_defense_alerts_from_kernel(), name="Self-Defense-Alert-Listener"),
    ]
    logger.info("All pipe listeners started successfully (AV->EDR, Owlyshield, MBR, Self-Defense).")
    return tasks
