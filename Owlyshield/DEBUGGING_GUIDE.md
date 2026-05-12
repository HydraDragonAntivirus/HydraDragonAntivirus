# HydraDragon Antivirus - Kernel Debugging Guide

## Table of Contents
1. [Overview](#overview)
2. [Crash Analysis](#crash-analysis)
3. [Common Issues](#common-issues)
4. [Debugging Setup](#debugging-setup)
5. [Troubleshooting Steps](#troubleshooting-steps)
6. [Prevention](#prevention)

---

## Overview

This guide provides comprehensive debugging procedures for kernel-mode crashes related to HydraDragon Antivirus components, including:
- **OwlyshieldRansomFilter** (Minifilter driver)
- **OpenEDR** (EDR service)
- **MBRFilter** (Boot sector protection)
- **Sanctum** (PPL protection)

---

## Crash Analysis

### Current Bugcheck: NMI_HARDWARE_FAILURE (0x80)

**Bugcheck Code:** `0x80`  
**Bugcheck Name:** `NMI_HARDWARE_FAILURE`  
**Description:** Hardware malfunction or driver-induced NMI

#### Parameters
- **Arg1:** `0x4f4454` ('TDO') - Custom identifier
- **Arg2:** `0x10` - Status byte
- **Arg3:** `0x0`
- **Arg4:** `0x0`

#### Key Observations from Crash Dump

1. **Symbol Loading Issues:**
   - Unable to verify checksum for [`edrsvc.exe`](C:\Program Files\HydraDragonAntivirus\OpenEDR\edrsvc.exe)
   - Win32 error 0n2 (File not found)
   - Multiple NT module base name read failures

2. **Memory Corruption Indicators:**
   - Unable to read NT module Base Name strings
   - Win32 error 0n30 (Read-only file system or access denied)
   - Possible paged-out or corrupt data

3. **System State:**
   - Windows 10 Build 26100
   - System uptime: 7 minutes 17 seconds (crash occurred shortly after boot)
   - Kernel base: `0xfffff804bc600000`

---

## Common Issues

### 1. NMI_HARDWARE_FAILURE with 'TDO' Signature

**Possible Causes:**
- Minifilter driver triggering watchdog timeout
- Infinite loop or deadlock in driver code
- Excessive IRQL holding
- Hardware NMI triggered by driver operation

**Investigation Steps:**
```
!analyze -v
!fltkd.filters
!thread
!locks
!deadlock
```

### 2. Symbol Loading Failures

**Symptoms:**
- "Unable to verify checksum"
- "Win32 error 0n2" (File not found)
- Missing PDB files

**Solutions:**
1. Verify file paths:
   ```cmd
   dir "C:\Program Files\HydraDragonAntivirus\OpenEDR\edrsvc.exe"
   ```

2. Configure symbol path:
   ```
   .sympath+ C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\Owlyshield\owlyshield_minifilter\OwlyshieldRansomFilter\x64\release
   .reload /f
   ```

3. Generate PDB files during build:
   - Ensure `/Zi` or `/ZI` compiler flag
   - Ensure `/DEBUG` linker flag
   - Copy PDB files to symbol directory

### 3. Memory Corruption

**Symptoms:**
- Unable to read module base names
- Win32 error 0n30
- Paged-out or corrupt data messages

**Investigation:**
```
!poolval
!chkimg -d nt
!vm
!verifier
```

### 4. Early Boot Crashes

**Symptoms:**
- Crash within minutes of boot
- Driver initialization failures

**Common Causes:**
- Driver load order issues
- Missing dependencies
- Registry configuration errors
- Incompatible driver versions

---

## Debugging Setup

### Prerequisites

1. **Windows Debugging Tools (WinDbg)**
   - Download from Windows SDK
   - Install Debugging Tools for Windows

2. **Kernel Debugging Connection**
   - Local kernel debugging (requires test signing)
   - Network debugging (kdnet)
   - Serial/COM port debugging
   - Virtual machine debugging

3. **Symbol Configuration**
   ```
   _NT_SYMBOL_PATH=srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\Owlyshield\owlyshield_minifilter\OwlyshieldRansomFilter\x64\release
   ```

### Enable Kernel Debugging

#### Method 1: Local Kernel Debugging
```cmd
bcdedit /debug on
bcdedit /dbgsettings local
```

#### Method 2: Network Debugging (Recommended)
```cmd
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000 key:1.2.3.4
```

#### Method 3: Named Pipe (VM)
```cmd
bcdedit /debug on
bcdedit /dbgsettings serial debugport:2 baudrate:115200
```

### Configure Test Signing (Development)
```cmd
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
```

### Enable Driver Verifier (Optional - for testing)
```cmd
verifier /standard /driver OwlyshieldRansomFilter.sys
```
⚠️ **Warning:** Driver Verifier can cause additional crashes if driver has bugs

---

## Troubleshooting Steps

### Step 1: Initial Analysis

1. **Connect WinDbg to crash dump or live kernel:**
   ```
   windbg -k net:port=50000,key=1.2.3.4
   ```

2. **Run automated analysis:**
   ```
   !analyze -v
   ```

3. **Check loaded drivers:**
   ```
   lm m *owly* *hydra* *edr* *mbr* *sanctum*
   ```

### Step 2: Identify Problem Component

1. **Check call stack:**
   ```
   kv
   kn
   ```

2. **Examine current thread:**
   ```
   !thread
   ```

3. **Check minifilter status:**
   ```
   !fltkd.filters
   !fltkd.filter OwlyshieldRansomFilter
   ```

4. **Review process list:**
   ```
   !process 0 0
   !process 0 7 edrsvc.exe
   ```

### Step 3: Investigate Specific Issues

#### For Minifilter Issues:
```
!fltkd.filters
!fltkd.volumes
!fltkd.instances
!irpfind
```

#### For Memory Issues:
```
!poolused 2
!poolfind 'Owly'
!vm
!poolval
```

#### For Lock/Deadlock Issues:
```
!locks
!deadlock
!cs -l
```

#### For Hardware/NMI Issues:
```
!sysinfo cpuinfo
!idt
!pcr
```

### Step 4: Collect Diagnostic Information

1. **Export call stacks:**
   ```
   ~*kv
   ```

2. **Save driver information:**
   ```
   lmv m OwlyshieldRansomFilter
   !drvobj \Driver\OwlyshieldRansomFilter
   ```

3. **Enable logging:**
   ```
   .logopen C:\debug_analysis.txt
   !analyze -v
   lm
   ~*kv
   .logclose
   ```

### Step 5: Fix and Verify

1. **Identify root cause from analysis**
2. **Apply code fixes**
3. **Rebuild with debug symbols**
4. **Test in controlled environment**
5. **Verify fix with Driver Verifier**

---

## Prevention

### Best Practices

1. **Code Quality:**
   - Use Static Driver Verifier (SDV)
   - Run Code Analysis (PREfast)
   - Implement proper error handling
   - Validate all pointers before dereferencing
   - Use safe string functions

2. **IRQL Management:**
   - Never hold spinlocks longer than necessary
   - Avoid paged memory access at DISPATCH_LEVEL or higher
   - Use appropriate synchronization primitives
   - Document IRQL requirements for functions

3. **Memory Management:**
   - Always free allocated memory
   - Use pool tags for tracking
   - Validate buffer sizes
   - Handle low-memory conditions gracefully

4. **Minifilter Specific:**
   - Complete IRPs promptly
   - Avoid blocking in pre-operation callbacks
   - Use proper completion routines
   - Handle all IRP types correctly
   - Test with various file systems (NTFS, FAT32, ReFS)

5. **Testing:**
   - Test with Driver Verifier enabled
   - Use Application Verifier for user-mode components
   - Test on multiple Windows versions
   - Perform stress testing
   - Test driver load/unload cycles

### Development Checklist

- [ ] Enable all compiler warnings (`/W4`)
- [ ] Treat warnings as errors (`/WX`)
- [ ] Enable Static Driver Verifier
- [ ] Run Code Analysis
- [ ] Test with Driver Verifier
- [ ] Generate and include PDB files
- [ ] Document IRQL requirements
- [ ] Implement proper cleanup in DriverUnload
- [ ] Handle all error paths
- [ ] Test on clean Windows installation
- [ ] Verify digital signature
- [ ] Test with other security software disabled
- [ ] Review Windows Event Logs after testing

### Monitoring and Logging

1. **Enable ETW Tracing:**
   ```c
   // In driver code
   EventRegister(&PROVIDER_GUID, NULL, NULL, &RegHandle);
   EventWriteString(RegHandle, 0, 0, L"Driver loaded");
   ```

2. **Use DbgPrint with Filtering:**
   ```c
   DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
              "OwlyshieldRansomFilter: Error occurred\n");
   ```

3. **Configure Debug Output:**
   ```cmd
   reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" /v IHVDRIVER /t REG_DWORD /d 0xFFFFFFFF
   ```

4. **Monitor with DebugView:**
   - Download Sysinternals DebugView
   - Enable "Capture Kernel" mode
   - Monitor real-time debug output

---

## Specific Issue: Current Crash Analysis

### Problem Summary
- **Bugcheck:** NMI_HARDWARE_FAILURE (0x80)
- **Signature:** 'TDO' (0x4f4454)
- **Timing:** 7 minutes after boot
- **Component:** Likely OwlyshieldRansomFilter or OpenEDR

### Recommended Actions

1. **Immediate:**
   - Disable OwlyshieldRansomFilter temporarily
   - Check if crash still occurs
   - Review recent code changes

2. **Investigation:**
   - Check for infinite loops in driver code
   - Review timer/DPC usage
   - Examine file system callback implementations
   - Verify proper IRP completion

3. **Code Review Focus Areas:**
   - [`PreOperationCallback`](Owlyshield/owlyshield_minifilter/OwlyshieldRansomFilter/) functions
   - [`PostOperationCallback`](Owlyshield/owlyshield_minifilter/OwlyshieldRansomFilter/) functions
   - Lock acquisition/release patterns
   - Memory allocation/deallocation
   - Communication with user-mode service

4. **Testing:**
   ```cmd
   # Disable driver
   sc stop OwlyshieldRansomFilter
   sc config OwlyshieldRansomFilter start= disabled
   
   # Reboot and check if crash persists
   shutdown /r /t 0
   ```

### Symbol Path Fix

The crash dump shows symbol loading issues. Fix with:

```cmd
# Create symbol directory
mkdir C:\Symbols

# Set environment variable
setx _NT_SYMBOL_PATH "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\Owlyshield\owlyshield_minifilter\OwlyshieldRansomFilter\x64\release"

# Copy PDB files to symbol directory
copy "C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\Owlyshield\owlyshield_minifilter\OwlyshieldRansomFilter\x64\release\*.pdb" C:\Symbols\
```

---

## Additional Resources

### Documentation
- [Windows Driver Kit (WDK) Documentation](https://docs.microsoft.com/windows-hardware/drivers/)
- [Minifilter Driver Development](https://docs.microsoft.com/windows-hardware/drivers/ifs/filter-manager-concepts)
- [Debugging Tools for Windows](https://docs.microsoft.com/windows-hardware/drivers/debugger/)

### Tools
- **WinDbg Preview** - Modern debugging interface
- **DebugView** - Real-time debug output viewer
- **Driver Verifier** - Driver testing tool
- **Static Driver Verifier** - Static analysis tool
- **Application Verifier** - User-mode testing

### Commands Reference
See [`debug_commands.txt`](Owlyshield/debug_commands.txt) for complete command reference.

---

## Contact and Support

For additional assistance:
1. Review Windows Event Viewer (System and Application logs)
2. Check driver installation logs
3. Collect crash dumps from `C:\Windows\Minidump\`
4. Enable verbose logging in driver configuration
5. Test in safe mode to isolate issue

---

**Last Updated:** 2026-05-12  
**Version:** 1.0  
**Maintainer:** HydraDragon Antivirus Development Team
