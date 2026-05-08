# HydraDragon Uninstallation Guide

Due to the deep integration of kernel-level drivers and security services, standard Windows uninstallation is not always sufficient for a complete cleanup. Follow these steps to fully remove HydraDragon Antivirus from your system.

## Step 1: Standard Uninstallation
1. Open **Control Panel** > **Programs and Features**.
2. Find **HydraDragon Antivirus** and click **Uninstall**.
3. Follow the prompts. The uninstaller will stop active services and delete service entries.
4. **Accept the warning**: The uninstaller will notify you that a full cleanup requires a reboot.

## Step 2: Safe Mode Reboot (CRITICAL)
Kernel drivers (`.sys` files) and library DLLs are often locked by Windows and cannot be deleted while the OS is running normally.
1. Restart your computer.
2. **Boot into Safe Mode**.
3. Upon login, a cleanup script named `HydraDragonCleanup.bat` (located in your `%TEMP%` directory) will run automatically via a `RunOnce` registry key.
4. **Selective Data Removal**: The script will ask if you want to permanently delete your **Quarantine, Logs, and Threat Reports**.
   - Press **Y** to delete everything.
   - Press **N** to preserve your security data at `%ProgramData%\HydraDragonAntivirus`.

## Step 3: Manual ELAM Driver Removal
The Early Launch Anti-Malware (ELAM) driver is heavily protected by Windows. If the automated cleanup script cannot remove it, follow these steps:

### Option A: Registry Cleanup
1. Open `regedit.exe` as Administrator.
2. Navigate to: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\EarlyLaunch`
3. Look for the `DriverName` value or subkeys related to `sanctum`.
4. Delete the associated entries.

### Option B: Command Line
1. Open a Command Prompt as Administrator.
2. Navigate to your installation directory (if files still exist) or use the backup installer.
3. Run: `elam_installer.exe /uninstall`

## Step 4: Final Verification
Ensure the following directories are removed:
- `C:\Program Files\HydraDragonAntivirus` (Main application)
- `%ProgramData%\edrsvc` (Service runtime data)
- `%ProgramData%\HydraDragonAntivirus` (Unless you chose to keep it)

---
**Note:** If you enabled Test Signing mode (`bcdedit /set testsigning on`) specifically for this project, you can disable it after uninstallation by running:
`bcdedit /set testsigning off`
*(Caution: This may break other unsigned drivers on your system.)*
