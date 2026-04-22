import os
from .path_and_variables import (
    logger,
    RULE_FILES
)

def get_sanctum_install_path():
    """Return the installed Sanctum directory under Program Files."""
    program_files = (
        os.environ.get("ProgramW6432")
        or os.environ.get("ProgramFiles")
        or r"C:\Program Files"
    )
    return os.path.join(program_files, "HydraDragonAntivirus", "hydradragon", "Sanctum")

def sync_dynamic_protection_rules():
    """Detect the installed Sanctum paths and update protection rules."""
    logger.info("[INIT] Synchronizing dynamic protection rules...")
    dynamic_paths = [get_sanctum_install_path()]

    # Auto-integrate the installed Sanctum tree plus dropped System32 components.
    windir = os.environ.get('WINDIR', r'C:\Windows')
    system32 = os.path.join(windir, 'System32')
    drivers_dir = os.path.join(system32, 'drivers')

    dynamic_paths.extend([
        os.path.join(system32, "sanctum.dll"),
        os.path.join(drivers_dir, "sanctum.sys"),
        os.path.join(drivers_dir, "edrdrv.sys"),
        os.path.join(system32, "edrpm64.dll"),
        os.path.join(system32, "edrpm32.dll"),
        os.path.join(system32, "edrmm.dll"),
    ])

    if not dynamic_paths:
        logger.warning("[INIT] No valid dynamic paths detected for synchronization.")
        return

    # Standardize to lower for comparison
    dynamic_paths = [p.lower() for p in dynamic_paths]
    dynamic_rule_lines = set()
    for path in dynamic_paths:
        rule_line = path
        if not path.endswith('\\') and not (path.endswith('.dll') or path.endswith('.sys')):
            rule_line = f"{path}\\"
        dynamic_rule_lines.add(rule_line)

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
                is_old_dynamic = (
                    strip_line == "# --- dynamic protection rules (auto-sync) ---"
                    or strip_line in dynamic_rule_lines
                    or (
                        strip_line.startswith("c:\\users\\")
                        and (
                            "\\desktop\\sanctum" in strip_line
                            or "\\appdata\\" in strip_line and "\\sanctum" in strip_line
                        )
                    )
                )

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
                    rule_line = path
                    if not path.endswith('\\') and not (path.lower().endswith('.dll') or path.lower().endswith('.sys')):
                        rule_line = f"{path}\\"
                    f.write(f"{rule_line}\n")
            
            logger.info(f"[INIT] Updated rules in: {rule_file}")

        except Exception as e:
            logger.error(f"[INIT] Failed to sync rules in {rule_file}: {e}")
