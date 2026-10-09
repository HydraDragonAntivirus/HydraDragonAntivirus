@echo off
setlocal
rem ReactOS in QEMU for testing VirusKov for ReactOS.
rem Needs QEMU for Windows (https://www.qemu.org/download/#windows), default install folder below.

set QEMU=C:\Program Files\qemu
set ISO=C:\Users\semae\Downloads\reactos-bootcd-0.4.17-dev-1031-g9b53b59-x86-gcc-lin-rel\reactos-bootcd-0.4.17-dev-1031-g9b53b59-x86-gcc-lin-rel.iso
set DISK=%~dp0reactos.qcow2
rem Folder shown inside ReactOS as an extra FAT drive: put the built client here.
rem IDE disks cannot be read-only in QEMU, so QEMU gets a writable copy in %%TEMP%%:
rem changes made inside ReactOS never reach this folder.
set SHARE=%~dp0share
set SHARECOPY=%TEMP%\viruskov_qemu_share

if not exist "%QEMU%\qemu-system-i386.exe" (
  echo QEMU not found in "%QEMU%". Install it or edit the QEMU line in this file.
  pause
  exit /b 1
)
if not exist "%SHARE%" mkdir "%SHARE%"
if exist "%SHARECOPY%" rmdir /s /q "%SHARECOPY%"
mkdir "%SHARECOPY%"
xcopy "%SHARE%" "%SHARECOPY%" /e /i /q /y >nul
if not exist "%DISK%" (
  echo Creating a 10 GB virtual disk: %DISK%
  "%QEMU%\qemu-img.exe" create -f qcow2 "%DISK%" 10G
)

rem First run: boots the installer CD (-boot d). After installing, start with "run_reactos_qemu.bat disk".
set BOOT=d
if /i "%1"=="disk" set BOOT=c

rem -m 1024: 1 GB RAM. rtl8139 + user networking: internet through Windows (needed for the cloud scan).
rem usb-tablet: the mouse follows the Windows cursor. Add "-accel whpx" after enabling
rem Windows Hypervisor Platform for more speed; without it QEMU emulates (slower, but works).
"%QEMU%\qemu-system-i386.exe" ^
  -m 1024 ^
  -drive file="%DISK%",format=qcow2,if=ide,index=0 ^
  -cdrom "%ISO%" ^
  -boot %BOOT% ^
  -drive file=fat:rw:"%SHARECOPY%",format=raw,if=ide,index=3 ^
  -netdev user,id=net0 -device rtl8139,netdev=net0 ^
  -vga std -usb -device usb-tablet ^
  -name "ReactOS (VirusKov test)"
endlocal
