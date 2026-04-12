import os
import ctypes
from .path_and_variables import (
    logger,
    RULE_FILES,
    NUITKA_BYTECODE_DIR,
    CSIDL_DESKTOP,
    CSIDL_APPDATA,
    CSIDL_LOCAL_APPDATA
)

def get_user_profile_paths():
    """Detect current user profile paths using Windows API."""
    MAX_PATH = 260
    paths = {}
    
    # helper for SHGetSpecialFolderPathW
    def get_path(csidl):
        buf = ctypes.create_unicode_buffer(MAX_PATH)
        if ctypes.windll.shell32.SHGetSpecialFolderPathW(None, buf, csidl, False):
            return buf.value
        return None

    paths['desktop'] = get_path(CSIDL_DESKTOP)
    paths['appdata_roaming'] = get_path(CSIDL_APPDATA)
    paths['appdata_local'] = get_path(CSIDL_LOCAL_APPDATA)
    
    return paths

def sync_dynamic_protection_rules():
    """Detect current user profile paths and update protection rules."""
    logger.info("[INIT] Synchronizing dynamic protection rules...")
    paths = get_user_profile_paths()
    
    dynamic_paths = []
    if paths.get('desktop'): dynamic_paths.append(paths['desktop'])
    if paths.get('appdata_roaming'): dynamic_paths.append(paths['appdata_roaming'])
    if paths.get('appdata_local'): dynamic_paths.append(paths['appdata_local'])
    
    # Include Nuitka Bytecode Path
    if NUITKA_BYTECODE_DIR:
        dynamic_paths.append(NUITKA_BYTECODE_DIR)

    if not dynamic_paths:
        logger.warning("[INIT] No valid dynamic paths detected for synchronization.")
        return

    # Standardize to lower for comparison
    dynamic_paths = [p.lower() for p in dynamic_paths]

    for rule_file in RULE_FILES:
        try:
            if not os.path.exists(rule_file):
                logger.debug(f"[INIT] Rule file not found: {rule_file}")
                continue

            with open(rule_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Clean up old dynamic rules to avoid duplicates or stale accounts
            cleaned_lines = []
            for line in lines:
                strip_line = line.strip().lower()
                # Check if line is a dynamic path (ends with trailing slash for folders)
                is_old_dynamic = False
                if strip_line.startswith("c:\\users\\") and ("desktop" in strip_line or "appdata" in strip_line):
                    is_old_dynamic = True
                if "nuitka_deobfuscate\\build\\bytecode" in strip_line:
                    is_old_dynamic = True
                
                if is_old_dynamic:
                    continue
                cleaned_lines.append(line)

            # Add current dynamic rules
            with open(rule_file, 'w', encoding='utf-8') as f:
                f.writelines(cleaned_lines)
                if cleaned_lines and not cleaned_lines[-1].endswith('\n'):
                    f.write('\n')
                f.write("# --- Dynamic Protection Rules (Auto-Sync) ---\n")
                for path in dynamic_paths:
                    # Enforce trailing slash for folder protection coverage
                    rule_line = path if path.endswith('\\') else f"{path}\\"
                    f.write(f"{rule_line}\n")
            
            logger.info(f"[INIT] Updated rules in: {rule_file}")

        except Exception as e:
            logger.error(f"[INIT] Failed to sync rules in {rule_file}: {e}")
