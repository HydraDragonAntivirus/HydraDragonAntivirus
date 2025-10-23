#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import win32file
import win32pipe
import pywintypes
import ctypes
import asyncio
from pathlib import Path
from hydra_logger import logger

# Import notification functions (now assumed async)
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
)

# ============================================================================#
# Notes:
# - All top-level methods below are async (async def). Blocking operations
#   (Win32 CreateFile/ReadFile/CreateNamedPipe/ConnectNamedPipe/CloseHandle,
#   ctypes calls, heavy JSON parsing) are executed in the threadpool via asyncio.to_thread.
# - Notification functions (notify_user_*) are expected to be async and are awaited directly.
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


def _sync_contains_hydradragon_ancestor(path: str) -> bool:
    try:
        parts = Path(path).parts
    except Exception:
        parts = _sync_normalize_path_for_compare(path).split(os.sep)
    for part in parts:
        if part.lower() == "hydradragonantivirus":
            return True
    return False


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

    if _sync_contains_hydradragon_ancestor(candidate):
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


# -------------------------
# Async processing functions (formerly synchronous)
# -------------------------
async def _process_threat_event(data: str):
    """
    Async version of threat event processing.
    JSON parsing and path checks executed in threadpool where appropriate.
    """
    try:
        # Parse JSON in thread
        event = await asyncio.to_thread(json.loads, data)
        if not isinstance(event, dict):
            logger.warning(f"Received valid JSON, but it was not an object: {data}")
            return

        file_path = event.get("file_path")
        virus_name = event.get("virus_name")
        is_malicious = event.get("is_malicious", False)
        action_required = event.get("action_required", "monitor")

        # Skip processing if this is a protected path
        if file_path and await _is_protected_path(file_path):
            logger.debug(f"Ignoring threat event for protected path: {file_path}")
            return

        logger.info(f"Received threat event from HydraDragon: {file_path} - {virus_name} (malicious: {is_malicious})")

        if is_malicious and action_required == "kill_and_remove":
            logger.critical(f"CRITICAL THREAT DETECTED: {file_path} - {virus_name}")

    except json.JSONDecodeError:
        logger.error(f"Failed to parse threat event JSON from HydraDragon: {data}")
    except Exception as e:
        logger.exception(f"Error processing threat event: {e}")


async def monitor_threat_events_from_av(pipe_name: str = PIPE_AV_TO_EDR):
    """
    Async client that connects to AV->EDR pipe and processes incoming messages.
    All blocking Win32 calls run in threadpool.
    """
    logger.info(f"Connecting to threat event pipe: {pipe_name}")
    while True:
        pipe = None
        try:
            # CreateFile (blocking)
            pipe = await asyncio.to_thread(
                lambda: win32file.CreateFile(
                    pipe_name,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None,
                )
            )
            logger.info("Connected to threat event pipe.")

            while True:
                try:
                    hr_data = await asyncio.to_thread(lambda: win32file.ReadFile(pipe, 4096))
                except pywintypes.error as e:
                    logger.debug(f"ReadFile raised pywintypes.error in threat listener: {e}")
                    break

                if not hr_data:
                    break
                _, data = hr_data
                message = data.decode("utf-8", errors="replace")
                logger.debug(f"Received threat event: {message}")
                await _process_threat_event(message)

        except pywintypes.error as e:
            if getattr(e, "winerror", None) == 2:
                logger.warning("Pipe not found, retrying in 1 second...")
                await asyncio.sleep(1)
            else:
                logger.error(f"Pipe error: {e}")
                await asyncio.sleep(1)
        except Exception as e:
            logger.exception(f"Unexpected error in threat listener: {e}")
            await asyncio.sleep(1)
        finally:
            if pipe:
                await asyncio.to_thread(_sync_close_handle, pipe)


# -------------------------
# MBR alert processing
# -------------------------
async def _process_mbr_alert(data: bytes):
    try:
        offending_path = await asyncio.to_thread(lambda: data.decode("utf-16-le").strip("\x00"))
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
            if getattr(e, "winerror", None) in [109, 232]:
                logger.warning("MBRFilter.sys disconnected from MBR alert pipe.")
            else:
                logger.error(
                    f"Windows API Error in MBR listener: {getattr(e, 'strerror', str(e))} (Code: {getattr(e,'winerror','N/A')})"
                )
            await asyncio.sleep(0.2)
        except Exception as e:
            logger.exception(f"Unexpected error in MBR alert listener: {e}")
            await asyncio.sleep(0.5)
        finally:
            if pipe:
                await asyncio.to_thread(lambda: win32pipe.DisconnectNamedPipe(pipe))
                await asyncio.to_thread(_sync_close_handle, pipe)


# -------------------------
# Self-defense alert processing
# -------------------------
async def _process_self_defense_alert(data: bytes):
    try:
        message_str = await asyncio.to_thread(lambda: data.decode("utf-16-le").strip("\x00"))
        logger.debug(f"Raw self-defense alert: {message_str}")

        alert_data = await asyncio.to_thread(json.loads, message_str)

        protected_file = alert_data.get("protected_file", "Unknown")
        attacker_path = alert_data.get("attacker_path", "Unknown")
        attacker_pid = alert_data.get("attacker_pid", 0)
        attack_type = alert_data.get("attack_type", "FILE_TAMPERING")
        operation = alert_data.get("operation", "")
        target_pid = alert_data.get("target_pid", 0)

        logger.critical(
            f"Self-Defense Alert: {attack_type} - "
            f"Process {attacker_path} (Attacker PID: {attacker_pid} Target PID: {target_pid}) "
            f"attempted to tamper with {protected_file}"
        )

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
        else:
            await notify_user_self_defense_file(
                file_path=protected_file,
                attacker_path=attacker_path,
                attacker_pid=attacker_pid,
            )

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse self-defense alert JSON: {e}")
        try:
            message_str = await asyncio.to_thread(lambda: data.decode("utf-16-le").strip("\x00"))
            logger.critical(f"Self-Defense Alert (raw): {message_str}")
        except Exception:
            pass
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
            if getattr(e, "winerror", None) in [109, 232]:
                logger.debug("Self-defense driver disconnected from alert pipe.")
            else:
                logger.error(
                    f"Windows API Error in self-defense listener: {getattr(e, 'strerror', str(e))} (Code: {getattr(e, 'winerror', 'N/A')})"
                )
            await asyncio.sleep(0.2)
        except Exception as e:
            logger.exception(f"Unexpected error in self-defense alert listener: {e}")
            await asyncio.sleep(0.5)
        finally:
            if pipe:
                await asyncio.to_thread(lambda: win32pipe.DisconnectNamedPipe(pipe))
                await asyncio.to_thread(_sync_close_handle, pipe)


# -------------------------
# Integration Startup
# -------------------------
async def start_all_pipe_listeners():
    """
    Start all pipe listeners as asyncio tasks and return the task list.
    """
    loop = asyncio.get_running_loop()
    tasks = [
        loop.create_task(monitor_threat_events_from_av(), name="HydraDragon-ThreatListener"),
        loop.create_task(monitor_mbr_alerts_from_kernel(), name="MBR-Alert-Listener"),
        loop.create_task(monitor_self_defense_alerts_from_kernel(), name="Self-Defense-Alert-Listener"),
    ]
    logger.info("All pipe listeners started successfully (AV, MBR, Self-Defense).")
    return tasks
