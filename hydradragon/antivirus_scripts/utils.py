from hydra_logger import logger
import os
from typing import Set, Callable

# --------------------------------------------------------------------------
# Helper function to generate platform-specific signatures
def get_signature(base_signature, **flags):
    """Generate platform-specific signature based on flags."""
    platform_map = {
        'dotnet_flag': 'DotNET',
        'fernflower_flag': 'Java',
        'jsc_flag': 'JavaScript.ByteCode.v8',
        'javascript_deobfuscated_flag': 'JavaScript',
        'nuitka_flag': 'Nuitka',
        'ole2_flag': 'OLE2',
        'inno_setup_flag': 'Inno Setup',
        'autohotkey_flag': 'AutoHotkey',
        'nsis_flag': 'NSIS',
        'pyc_flag': 'PYC.Python',
        'androguard_flag': 'Android',
        'asar_flag': 'Electron',
        'registry_flag': 'Registry',
        'nexe_flag' : 'nexe'
    }

    for flag, platform in platform_map.items():
        if flags.get(flag):
            return f"HEUR:Win32.{platform}.{base_signature}"

    return f"HEUR:Win32.{base_signature}"

def get_all_drives() -> Set[str]:
    """
    Get all available drive letters on Windows (C:\, D:\, etc.)
    Returns a set of drive paths that exist and are accessible.
    """
    drives = set()
    
    # Check drive letters from A to Z
    for letter in range(ord('A'), ord('Z') + 1):
        drive = f"{chr(letter)}:\\"
        if os.path.exists(drive):
            try:
                # Verify the drive is accessible
                os.listdir(drive)
                drives.add(drive)
                logger.debug(f"Found accessible drive: {drive}")
            except (PermissionError, OSError) as e:
                logger.warning(f"Drive {drive} exists but is not accessible: {e}")
    
    return drives


def monitor_drive_changes(
    on_added: Callable[[str], None] = None,
    on_removed: Callable[[str], None] = None,
    stop_event=None
):
    """
    Monitor for drive path changes (additions/removals).
    
    Args:
        on_added: Callback function called when a new drive is detected
        on_removed: Callback function called when a drive is removed
        stop_event: Threading event to stop monitoring (optional)
    """
    current_drives = get_all_drives()
    logger.info(f"Starting drive monitoring. Initial drives: {sorted(current_drives)}")
    
    while True:
        if stop_event and stop_event.is_set():
            logger.info("Drive monitoring stopped")
            break
        
        new_drives = get_all_drives()
        
        # Check for added drives
        added = new_drives - current_drives
        for drive in added:
            logger.info(f"New drive detected: {drive}")
            if on_added:
                try:
                    on_added(drive)
                except Exception as e:
                    logger.error(f"Error in on_added callback for {drive}: {e}")
        
        # Check for removed drives
        removed = current_drives - new_drives
        for drive in removed:
            logger.info(f"Drive removed: {drive}")
            if on_removed:
                try:
                    on_removed(drive)
                except Exception as e:
                    logger.error(f"Error in on_removed callback for {drive}: {e}")
        
        current_drives = new_drives
