from hydra_logger import logger
import os

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

def get_all_drives():
    """
    Get all available drive letters on Windows (C:\, D:\, etc.)
    Returns a list of drive paths that exist.
    """
    drives = []
    
    # Check drive letters from A to Z
    for letter in range(ord('A'), ord('Z') + 1):
        drive = f"{chr(letter)}:\\"
        if os.path.exists(drive):
            try:
                # Verify the drive is accessible
                os.listdir(drive)
                drives.append(drive)
                logger.info(f"Found accessible drive: {drive}")
            except (PermissionError, OSError) as e:
                logger.warning(f"Drive {drive} exists but is not accessible: {e}")
    
    return drives
