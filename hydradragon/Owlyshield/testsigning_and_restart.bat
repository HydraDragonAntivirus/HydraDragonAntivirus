@echo off
setlocal EnableExtensions

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] This script must be run as Administrator.
    echo [*] Relaunching elevated...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

echo [*] Disabling VBS/HVCI/Hyper-V features for Owlyshield and hypervisor testing...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1
bcdedit /set hypervisorlaunchtype off
bcdedit /set vsmlaunchtype off
dism.exe /Online /Disable-Feature /FeatureName:Microsoft-Hyper-V-All /NoRestart >nul 2>&1
dism.exe /Online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Hypervisor /NoRestart >nul 2>&1
dism.exe /Online /Disable-Feature /FeatureName:VirtualMachinePlatform /NoRestart >nul 2>&1
dism.exe /Online /Disable-Feature /FeatureName:HypervisorPlatform /NoRestart >nul 2>&1

echo [*] Enabling test-signing and kernel debugging...
bcdedit /set testsigning on
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200

echo [*] Restarting system in 5 seconds...
shutdown -r -t 5
endlocal
