/*
   YARA Rule Set
   Author: Ido Veltzman
   Date: 2022-10-24
   Reference: https://github.com/Idov31/Rustomware
*/

rule rustomware {
   meta:
      description = "Rust ransomware example"
      author = "Ido Veltzman"
      reference = "https://github.com/Idov31/Rustomware"
      date = "2022-10-24"
   strings:
      $x1 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\v0.rs" fullword ascii
      $x2 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\legacy.rs" fullword ascii
      $s5 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\libaes-0.6.4\\src\\lib.rs" ascii
      $s6 = ".llvm.C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\lib.rs" fullword ascii
      $s7 = "uncategorized errorother errorout of memoryunexpected end of fileunsupportedoperation interruptedargument list too longinvalid f" ascii
      $s8 = "assertion failed: state_and_queue.addr() & STATE_MASK == RUNNINGOnce instance has previously been poisoned" fullword ascii
      $s9 = "toryoperation would blockentity already existsbroken pipenetwork downaddress not availableaddress in usenot connectedconnection " ascii
      $s10 = "Your files are encrypted by Rustsomware./README_Rustsomware.txt" fullword ascii
      $s11 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sys_common\\remutex.rs" fullword ascii
      $s12 = "workFileHandleFilesystemLoopReadOnlyFilesystemDirectoryNotEmptyIsADirectoryNotADirectoryWouldBlockAlreadyExistsBrokenPipeNetwork" ascii
      $s13 = "drop of the panic payload panicked" fullword ascii
      $s14 = "Not enough arguments! Usage: rustsomware <encrypt|decrypt> <folder>" fullword ascii
      $s15 = "Unable to create keyed event handle: error " fullword ascii
      $s16 = "ssionDeniedNotFound*I/O error: operation failed to complete synchronously" fullword ascii
      $s17 = "abortednetwork unreachablehost unreachableconnection resetconnection refusedpermission deniedentity not foundErrorkind" fullword ascii
      $s18 = "thread panicked while processing panic. aborting." fullword ascii
      $s19 = "keyed events not available" fullword ascii
      $s20 = "attempted to index str up to maximum usize" fullword ascii

      $op0 = { 0f 82 25 ff ff ff b9 02 }
      $op1 = { 3d 00 08 00 00 0f 82 15 ff ff ff 3d 00 00 01 00 }
      $op2 = { 48 83 d9 00 e9 02 ff ff ff 66 90 4a 8d 0c 36 31 }
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}
rule Adware_OutBrowse_gen
{
meta:
	author = "Kei Choi"
	date = "2017-12-28"
	KicomAV = "AdWare.Win32.OutBrowse.gen"
strings:
	$string1 = "_OuterInst_0" wide
	$string2 = "{8A69D345-D564-463c-AFF1-A69D9E530F96}" wide
	$string3 = "SafariHTML" wide
condition:
	3 of them
}


rule Adware_OpriUpdater_gen
{
meta:
	author = "Kei Choi"
	date = "2017-12-28"
	KicomAV = "AdWare.Win32.OpriUpdater.gen"
strings:
	$string1 = /sso[a-z]+\.com/
	$string2 = "http://%s/time.php"
	$string3 = "86311%s"
    $string4 = "0123456789abcdefABCDEF%PLACEHOLDER"
	$string5 = "http://%s%s"
condition:
	(3 of ($string1, $string2, $string3)) or (2 of ($string4, $string5))
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-01-10
Identifier: Case 1012 Trickbot Still Alive and Well
Reference: https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule cobalt_strike_TSE588C {
meta:
description = "exe - file TSE588C.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-05"
hash1 = "32c13df5d411bf5a114e2021bbe9ffa5062ed1db91075a55fe4182b3728d62fe"
strings:
$s1 = "mneploho86.dll" fullword ascii
$s2 = "C:\\projects\\Project1\\Project1.pdb" fullword ascii
$s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s4 = "AppPolicyGetThreadInitializationType" fullword ascii
$s5 = "boltostrashno.nfo" fullword ascii
$s6 = "operator<=>" fullword ascii
$s7 = "operator co_await" fullword ascii
$s8 = "?7; ?<= <?= 6<" fullword ascii /* hex encoded string 'v' */
$s9 = ".data$rs" fullword ascii
$s10 = "tutoyola" fullword ascii
$s11 = "Ommk~z#K`majg`i4.itg~\".jkhbozk" fullword ascii
$s12 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s13 = "OVOVPWTOVOWOTF" fullword ascii
$s14 = "vector too long" fullword ascii
$s15 = "n>log2" fullword ascii
$s16 = "\\khk|k|4.fzz~4!!majk d" fullword ascii
$s17 = "network reset" fullword ascii /* Goodware String - occured 567 times */
$s18 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
$s19 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
$s20 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
condition:
uint16(0) == 0x5a4d and filesize < 900KB and
( pe.imphash() == "bb8169128c5096ea026d19888c139f1a" or 10 of them )
}

rule trickbot_kpsiwn {
meta:
description = "exe - file kpsiwn.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-05"
hash1 = "e410123bde6a317cadcaf1fa3502301b7aad6f528d59b6b60c97be077ef5da00"
strings:
$s1 = "C:\\Windows\\explorer.exe" fullword ascii
$s2 = "constructor or from DllMain." fullword ascii
$s3 = "esource" fullword ascii
$s4 = "Snapping window demonstration" fullword wide
$s5 = "EEEEEEEEEFFB" ascii
$s6 = "EEEEEEEEEEFC" ascii
$s7 = "EEEEEEEEEEFD" ascii
$s8 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
$s9 = "EFEEEEEEEEEB" ascii
$s10 = "e[!0LoG" fullword ascii
$s11 = ">*P<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" fullword ascii
$s12 = "o};k- " fullword ascii
$s13 = "YYh V+ i" fullword ascii
$s14 = "fdlvic" fullword ascii
$s15 = "%FD%={" fullword ascii
$s16 = "QnzwM#`8" fullword ascii
$s17 = "xfbS/&s:" fullword ascii
$s18 = "1#jOSV9\"" fullword ascii
$s19 = "JxYt1L=]" fullword ascii
$s20 = "a3NdcMFSZEmJwXod1oyI@Tj4^mY+UsZqK3>fTg<P*$4DC?y@esDpRk@T%t" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 1000KB and
( pe.imphash() == "a885f66621e03089e6c6a82d44a5ebe3" or 10 of them )
}

rule cobalt_strike_TSE28DF {
meta:
description = "exe - file TSE28DF.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-05"
hash1 = "65282e01d57bbc75f24629be9de126f2033957bd8fe2f16ca2a12d9b30220b47"
strings:
$s1 = "mneploho86.dll" fullword ascii
$s2 = "C:\\projects\\Project1\\Project1.pdb" fullword ascii
$s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s4 = "AppPolicyGetThreadInitializationType" fullword ascii
$s5 = "boltostrashno.nfo" fullword ascii
$s6 = "operator<=>" fullword ascii
$s7 = "operator co_await" fullword ascii
$s8 = ".data$rs" fullword ascii
$s9 = "tutoyola" fullword ascii
$s10 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s11 = "vector too long" fullword ascii
$s12 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
$s13 = "network reset" fullword ascii /* Goodware String - occured 567 times */
$s14 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
$s15 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
$s16 = "network down" fullword ascii /* Goodware String - occured 567 times */
$s17 = "protocol not supported" fullword ascii /* Goodware String - occured 568 times */
$s18 = "connection aborted" fullword ascii /* Goodware String - occured 568 times */
$s19 = "network unreachable" fullword ascii /* Goodware String - occured 569 times */
$s20 = "host unreachable" fullword ascii /* Goodware String - occured 571 times */
condition:
uint16(0) == 0x5a4d and filesize < 700KB and
( pe.imphash() == "ab74ed3f154e02cfafb900acffdabf9e" or all of them )
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-01-25
Identifier: Case 1013 Bazar, No Ryuk?
Reference: https://thedfirreport.com/2021/01/31/bazar-no-ryuk/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule bazar_start_bat {
meta:
description = "files - file start.bat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-25"
hash1 = "63de40c7382bbfe7639f51262544a3a62d0270d259e3423e24415c370dd77a60"
strings:
$x1 = "powershell.exe Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force" fullword ascii
$x2 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %1)" fullword ascii
$x3 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %method" fullword ascii
$s4 = "set /p method=\"Press Enter for collect [all]: \"" fullword ascii
$s5 = "echo \"all ping disk soft noping nocompress\"" fullword ascii
$s6 = "echo \"Please select a type of info collected:\"" fullword ascii
$s7 = "@echo on" fullword ascii /* Goodware String - occured 1 times */
$s8 = "color 07" fullword ascii
$s9 = "pushd %~dp0" fullword ascii /* Goodware String - occured 1 times */
$s10 = "color 70" fullword ascii
$s11 = "IF \"%1\"==\"\" (" fullword ascii
$s12 = "IF NOT \"%1\"==\"\" (" fullword ascii
condition:
uint16(0) == 0x6540 and filesize < 1KB and
1 of ($x*) and all of them
}

rule bazar_M1E1626 {
meta:
description = "files - file M1E1626.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-25"
hash1 = "d362c83e5a6701f9ae70c16063d743ea9fe6983d0c2b9aa2c2accf2d8ba5cb38"
strings:
$s1 = "ResizeFormToFit.EXE" fullword wide
$s2 = "C:\\Windows\\explorer.exe" fullword ascii
$s3 = "bhart@pinpub.com" fullword wide
$s4 = "constructor or from DllMain." fullword ascii
$s5 = "dgsvhwe" fullword ascii
$s6 = "ResizeFormToFit.Document" fullword wide
$s7 = "ResizeFormToFit Version 1.0" fullword wide
$s8 = "This is a dummy form view for illustration of how to size the child frame window of the form to fit this form." fullword wide
$s9 = "GSTEAQR" fullword ascii
$s10 = "HTBNMRRTNSHNH" fullword ascii
$s11 = "RCWZCSJXRRNBL" fullword ascii
$s12 = "JFCNZXHXPTCT" fullword ascii
$s13 = "BLNEJPFAWFPU" fullword ascii
$s14 = "BREUORYYPKS" fullword ascii
$s15 = "UCWOJTPGLBZTI" fullword ascii
$s16 = "DZVVFAVZVWMVS" fullword ascii
$s17 = "MNKRAMLGWUX" fullword ascii
$s18 = "WHVMUKGVCHCT" fullword ascii
$s19 = "\\W\\TQPNIQWNZN" fullword ascii
$s20 = "ResizeFormToFit3" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "578738b5c4621e1bf95fce0a570a7cfc" or 8 of them )
}


rule bazar_files_netscan {
meta:
description = "files - file netscan.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-25"
hash1 = "ce6fc6cca035914a28bbc453ee3e8ef2b16a79afc01d8cb079c70c7aee0e693f"
strings:
$s1 = "TREMOTECOMMONFORM" fullword wide
$s2 = "ELHEADERRIGHTBMP" fullword wide
$s3 = "ELHEADERDESCBMP" fullword wide
$s4 = "ELHEADERLEFTBMP" fullword wide
$s5 = "ELHEADERASCBMP" fullword wide
$s6 = "ELHEADERPOINTBMP" fullword wide
$s7 = "<description>A free multithreaded IP, SNMP, NetBIOS scanner.</description>" fullword ascii
$s8 = "GGG`BBB" fullword ascii /* reversed goodware string 'BBB`GGG' */
$s9 = "name=\"SoftPerfect Network Scanner\"/>" fullword ascii
$s10 = "SoftPerfect Network Scanner" fullword wide
$s11 = "TREMOTESERVICEEDITFORM" fullword wide
$s12 = "TUSERPROMPTFORM" fullword wide
$s13 = "TREMOTEWMIFORM" fullword wide
$s14 = "TPUBLICIPFORM" fullword wide
$s15 = "TREMOTESERVICESFORM" fullword wide
$s16 = "TREMOTEWMIEDITFORM" fullword wide
$s17 = "TREMOTEFILEEDITFORM" fullword wide
$s18 = "TREMOTEREGISTRYFORM" fullword wide
$s19 = "TPASTEIPADDRESSFORM" fullword wide
$s20 = "TREMOTEREGISTRYEDITFORM" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "e9d20acdeaa8947f562cf14d3976522e" or 8 of them )
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-01-18
Identifier: Case 1014 All That for a Coinminer?
Reference: https://thedfirreport.com/2021/01/18/all-that-for-a-coinminer/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule miner_exe_svshost {
meta:
description = "exe - file svshost.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-18"
hash1 = "ba94d5539a4ed65ac7a94a971dbb463a469f8671c767f515d271223078983442"
strings:
$s1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
$s2 = "__kernel void find_shares(__global const uint64_t* hashes,uint64_t target,uint32_t start_nonce,__global uint32_t* shares)" fullword ascii
$s3 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
$s4 = "svshost.exe" fullword wide
$s5 = "Could not read dumped cpuid file %s, ignoring cpuiddump." fullword ascii
$s6 = "%PROGRAMFILES%\\NVIDIA Corporation\\NVSMI\\nvml.dll" fullword ascii
$s7 = "void blake2b_512_process_single_block(ulong *h,const ulong* m,uint blockTemplateSize)" fullword ascii
$s8 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
$s9 = "blake2b_512_process_single_block(hash,m,blockTemplateSize);" fullword ascii
$s10 = "F:\\Apps\\cSharp\\myMinerup\\myM\\myM\\obj\\Debug\\svshost.pdb" fullword ascii
$s11 = "|attrib +h svshost.exe" fullword ascii
$s12 = "Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
$s13 = "GetCurrentProcessorNumberExProc || (GetCurrentProcessorNumberProc && nr_processor_groups == 1)" fullword ascii
$s14 = "__kernel void blake2b_initial_hash(__global void *out,__global const void* blockTemplate,uint blockTemplateSize,uint start_nonce" ascii
$s15 = "* hwloc %s received invalid information from the operating system." fullword ascii
$s16 = "__local exec_t* execution_plan=(__local exec_t*)(execution_plan_buf+(get_local_id(0)/8)*RANDOMX_PROGRAM_SIZE*WORKERS_PER_HASH*si" ascii
$s17 = "__kernel void execute_vm(__global void* vm_states,__global void* rounding,__global void* scratchpads,__global const void* datase" ascii
$s18 = "__kernel void execute_vm(__global void* vm_states,__global void* rounding,__global void* scratchpads,__global const void* datase" ascii
$s19 = "__local exec_t* execution_plan=(__local exec_t*)(execution_plan_buf+(get_local_id(0)/8)*RANDOMX_PROGRAM_SIZE*WORKERS_PER_HASH*si" ascii
$s20 = "__kernel void blake2b_initial_hash(__global void *out,__global const void* blockTemplate,uint blockTemplateSize,uint start_nonce" ascii
condition:
uint16(0) == 0x5a4d and filesize < 19000KB and
8 of them
}

rule mimikatz_1014 {
meta:
description = "exe - file mimikatz.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-18"
hash1 = "99d8d56435e780352a8362dd5cb3857949c6ff5585e81b287527cd6e52a092c1"
strings:
$x1 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide
$x2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx user (%s)" fullword wide
$x3 = "ERROR kuhl_m_lsadump_lsa ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide
$x4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" fullword wide
$x5 = "ERROR kuhl_m_lsadump_dcsync ; kull_m_rpc_drsr_ProcessGetNCChangesReply" fullword wide
$x6 = "ERROR kuhl_m_lsadump_trust ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide
$x7 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" fullword wide
$x8 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" fullword wide
$x9 = "ERROR kuhl_m_lsadump_netsync ; I_NetServerTrustPasswordsGet (0x%08x)" fullword wide
$x10 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
$x11 = "ERROR kuhl_m_kernel_processProtect ; Argument /process:program.exe or /pid:processid needed" fullword wide
$x12 = "ERROR kuhl_m_lsadump_getHash ; Unknow SAM_HASH revision (%hu)" fullword wide
$x13 = "ERROR kuhl_m_lsadump_sam ; kull_m_registry_RegOpenKeyEx (SAM) (0x%08x)" fullword wide
$x14 = "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; Checksums don't match (C:0x%08x - R:0x%08x)" fullword wide
$x15 = "ERROR kuhl_m_lsadump_enumdomains_users ; /user or /rid is needed" fullword wide
$x16 = "ERROR kuhl_m_lsadump_changentlm ; Argument /oldpassword: or /oldntlm: is needed" fullword wide
$x17 = "livessp.dll" fullword wide /* reversed goodware string 'lld.pssevil' */
$x18 = "ERROR kuhl_m_lsadump_enumdomains_users ; SamLookupNamesInDomain: %08x" fullword wide
$x19 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide
$x20 = "ERROR kuhl_m_lsadump_getKeyFromGUID ; kuhl_m_lsadump_LsaRetrievePrivateData: 0x%08x" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 3000KB and
( pe.imphash() == "a0444dc502edb626311492eb9abac8ec" or 1 of ($x*) )
}

rule masscan_1014 {
meta:
description = "exe - file masscan.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-18"
hash1 = "de903a297afc249bb7d68fef6c885a4c945d740a487fe3e9144a8499a7094131"
strings:
$x1 = "User-Agent: masscan/1.0 (https://github.com/robertdavidgraham/masscan)" fullword ascii
$s2 = "Usage: masscan [Options] -p{Target-Ports} {Target-IP-Ranges}" fullword ascii
$s3 = "GetProcessAffinityMask() returned error %u" fullword ascii
$s4 = "Via: HTTP/1.1 ir14.fp.bf1.yahoo.com (YahooTrafficServer/1.2.0.13 [c s f ])" fullword ascii
$s5 = "C:\\Documents and Settings\\" fullword ascii
$s6 = "android.com" fullword ascii
$s7 = "youtube.com" fullword ascii
$s8 = "espanol.yahoo.com" fullword ascii
$s9 = "brb.yahoo.com" fullword ascii
$s10 = "malaysia.yahoo.com" fullword ascii
$s11 = "att.yahoo.com" fullword ascii
$s12 = "hsrd.yahoo.com" fullword ascii
$s13 = "googlecommerce.com" fullword ascii
$s14 = "maktoob.yahoo.com" fullword ascii
$s15 = "*.youtube-nocookie.com" fullword ascii
$s16 = "# TARGET SELECTION (IP, PORTS, EXCLUDES)" fullword ascii
$s17 = "www.yahoo.com" fullword ascii
$s18 = "x.509 parser failure: google.com" fullword ascii
$s19 = "-- forced options: -sS -Pn -n --randomize-hosts -v --send-eth" fullword ascii
$s20 = "urchin.com" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 700KB and
( pe.imphash() == "9b0b559e373d62a1c93e615f003f8af8" or 10 of them) 
}

rule XMRig_CPU_mine_1014 {
meta:
description = "exe - file XMRig CPU mine.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-01-18"
hash1 = "a8b2e85b3e0f5de4b82a92b3ca56d2d889a30383a3f9283ae48aec879edd0376"
strings:
$s1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
$s2 = "__kernel void find_shares(__global const uint64_t* hashes,uint64_t target,uint32_t start_nonce,__global uint32_t* shares)" fullword ascii
$s3 = "Could not read dumped cpuid file %s, ignoring cpuiddump." fullword ascii
$s4 = "%PROGRAMFILES%\\NVIDIA Corporation\\NVSMI\\nvml.dll" fullword ascii
$s5 = "void blake2b_512_process_single_block(ulong *h,const ulong* m,uint blockTemplateSize)" fullword ascii
$s6 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
$s7 = "blake2b_512_process_single_block(hash,m,blockTemplateSize);" fullword ascii
$s8 = "Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
$s9 = "GetCurrentProcessorNumberExProc || (GetCurrentProcessorNumberProc && nr_processor_groups == 1)" fullword ascii
$s10 = "__kernel void blake2b_initial_hash(__global void *out,__global const void* blockTemplate,uint blockTemplateSize,uint start_nonce" ascii
$s11 = "* hwloc %s received invalid information from the operating system." fullword ascii
$s12 = "__local exec_t* execution_plan=(__local exec_t*)(execution_plan_buf+(get_local_id(0)/8)*RANDOMX_PROGRAM_SIZE*WORKERS_PER_HASH*si" ascii
$s13 = "__kernel void execute_vm(__global void* vm_states,__global void* rounding,__global void* scratchpads,__global const void* datase" ascii
$s14 = "__kernel void execute_vm(__global void* vm_states,__global void* rounding,__global void* scratchpads,__global const void* datase" ascii
$s15 = "__local exec_t* execution_plan=(__local exec_t*)(execution_plan_buf+(get_local_id(0)/8)*RANDOMX_PROGRAM_SIZE*WORKERS_PER_HASH*si" ascii
$s16 = "__kernel void blake2b_initial_hash(__global void *out,__global const void* blockTemplate,uint blockTemplateSize,uint start_nonce" ascii
$s17 = "nvml.dll" fullword ascii
$s18 = "__kernel void Groestl(__global ulong *states,__global uint *BranchBuf,__global uint *output,ulong Target,uint Threads)" fullword ascii
$s19 = "__kernel void Blake(__global ulong *states,__global uint *BranchBuf,__global uint *output,ulong Target,uint Threads)" fullword ascii
$s20 = "__kernel void JH(__global ulong *states,__global uint *BranchBuf,__global uint *output,ulong Target,uint Threads)" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 19000KB and
( pe.imphash() == "5c21c3e071f2116dcdb008ad5fc936d4" or 8 of them )
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-02-22
Identifier: Case 1017 Bazar Drops the Anchor
Reference: https://thedfirreport.com/2021/03/08/bazar-drops-the-anchor/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule bazar_14wfa5dfs {
meta:
description = "files - file 14wfa5dfs.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "2065157b834e1116abdd5d67167c77c6348361e04a8085aa382909500f1bbe69"
strings:
$s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
$s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
$s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s4 = "0??dfg.dll ASHI128 bit 98tqewC58752F9578" fullword ascii
$s5 = "*http://crl4.digicert.com/assured-cs-g1.crl0L" fullword ascii
$s6 = "*http://crl3.digicert.com/assured-cs-g1.crl00" fullword ascii
$s7 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
$s8 = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={F61A86A8-0045-3726-D207-E8A923987AD2}&lang=ru&browser=4&usagestats=1&appname" ascii
$s9 = "operator co_await" fullword ascii
$s10 = "appguid={8A69D345-D564-463C-AFF1-A69D9E530F96}&iid={F61A86A8-0045-3726-D207-E8A923987AD2}&lang=ru&browser=4&usagestats=1&appname" ascii
$s11 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s12 = "Google LLC1" fullword ascii
$s13 = "Google LLC0" fullword ascii
$s14 = "Unknown issuer0" fullword ascii
$s15 = "DigiCert, Inc.1$0\"" fullword ascii
$s16 = "=Google%20Chrome&needsadmin=prefers&ap=x64-stable-statsdef_1&installdataindex=empty" fullword ascii
$s17 = "TIMESTAMP-SHA256-2019-10-150" fullword ascii
$s18 = "vggwqrwqr7d6" fullword ascii
$s19 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
$s20 = "__swift_2" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 3000KB and
( pe.imphash() == "d8af53b239700b702d462c81a96d396c" and 8 of them )
}

rule cobalt_strike_tmp01925d3f {
meta:
description = "files - file ~tmp01925d3f.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "10ff83629d727df428af1f57c524e1eaddeefd608c5a317a5bfc13e2df87fb63"
strings:
$x1 = "C:\\Users\\hillary\\source\\repos\\gromyko\\Release\\gromyko.pdb" fullword ascii
$x2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
$s3 = "gromyko32.dll" fullword ascii
$s4 = "<requestedExecutionLevel level='asInvoker' uiAccess='false'/>" fullword ascii
$s5 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s6 = "https://sectigo.com/CPS0" fullword ascii
$s7 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
$s8 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
$s9 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
$s10 = "http://ocsp.sectigo.com0" fullword ascii
$s11 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
$s12 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
$s13 = "http://www.digicert.com/CPS0" fullword ascii
$s14 = "AppPolicyGetThreadInitializationType" fullword ascii
$s15 = "alerajner@aol.com0" fullword ascii
$s16 = "gromyko.inf" fullword ascii
$s17 = "operator<=>" fullword ascii
$s18 = "operator co_await" fullword ascii
$s19 = "gromyko" fullword ascii
$s20 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 1000KB and
( pe.imphash() == "1b1b73382580c4be6fa24e8297e1849d" and ( 1 of ($x*) or 8 of them ) )
}

rule advanced_ip_scanner {
meta:
description = "files - file advanced_ip_scanner.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "722fff8f38197d1449df500ae31a95bb34a6ddaba56834b13eaaff2b0f9f1c8b"
strings:
$s2 = "fo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAcce" ascii
$s3 = "Executable files (*.exe)" fullword ascii
$s4 = "0RolUpdater.dll" fullword wide
$s5 = "Qt5WinExtras.dll" fullword ascii
$s6 = "Radmin.exe" fullword ascii
$s7 = "ping.exe" fullword ascii
$s8 = "tracert.exe" fullword ascii
$s9 = "famatech.com" fullword ascii
$s10 = "advanced_ip_scanner.exe" fullword wide
$s11 = "Z:\\out\\Release\\NetUtils\\x86\\advanced_ip_scanner.pdb" fullword ascii
$s12 = "Qt5Xml.dll" fullword ascii
$s13 = "/telnet.exe" fullword ascii
$s14 = "onTargetScanned" fullword ascii
$s15 = "CScanTargetsShared" fullword ascii
$s16 = "1OnCmdScanSelected( CScanTargets& )" fullword ascii
$s17 = "http://www.advanced-ip-scanner.com/" fullword ascii
$s18 = "2CmdScanSelected( CScanTargets& )" fullword ascii
$s19 = "</style></head><body style=\" font-family:'MS Shell Dlg 2'; font-size:8.25pt; font-weight:400; font-style:normal;\">" fullword ascii
$s20 = "<a href=\"http://www.radmin.com\">www.radmin.com</a>" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 5000KB and
( pe.imphash() == "a3bc8eb6ac4320e91b7faf1e81af2bbf" and 8 of them )
}

rule anchor_x64 {
meta:
description = "files - file anchor_x64.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "ca72600f50c76029b6fb71f65423afc44e4e2d93257c3f95fb994adc602f3e1b"
strings:
$x1 = "cmd.exe /c timeout 3 && " fullword wide
$x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii
$x3 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
$s4 = "\\System32\\cmd.ex\\System32\\rundllP" fullword ascii
$s5 = "Z:\\D\\GIT\\anchorDns.llvm\\Bin\\x64\\Release\\anchorDNS_x64.pdb" fullword ascii
$s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s7 = "cutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><appli" ascii
$s8 = "thExecute" fullword ascii
$s9 = "on xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSe" ascii
$s10 = "WinHTTP loader/1.0" fullword wide
$s11 = "AppPolicyGetThreadInitializationType" fullword ascii
$s12 = "AnchorDNS.cpp" fullword ascii
$s13 = "hardWorker.cpp" fullword ascii
$s14 = "operator<=>" fullword ascii
$s15 = "operator co_await" fullword ascii
$s16 = "/C PowerShell \"Start-Slemove-Iteep 3; Re" fullword wide
$s17 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii
$s18 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s19 = "UAWAVAUATVWSH" fullword ascii
$s20 = "AWAVAUATVWUSH" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 1000KB and
( pe.imphash() == "e2450fb3cc5b1b7305e3193fe03f3369" and ( 1 of ($x*) or 8 of them ) )
}

rule anchorDNS_x64 {
meta:
description = "files - file anchorDNS_x64.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "9fdbd76141ec43b6867f091a2dca503edb2a85e4b98a4500611f5fe484109513"
strings:
$x1 = "cmd.exe /c timeout 3 && " fullword wide
$x2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii
$x3 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
$s4 = "\\System32\\cmd.ex\\System32\\rundllP" fullword ascii
$s5 = "Z:\\D\\GIT\\anchorDns.llvm\\Bin\\x64\\Release\\anchorDNS_x64.pdb" fullword ascii
$s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s7 = "cutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><appli" ascii
$s8 = "thExecute" fullword ascii
$s9 = "on xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSe" ascii
$s10 = "WinHTTP loader/1.0" fullword wide
$s11 = "AppPolicyGetThreadInitializationType" fullword ascii
$s12 = "AnchorDNS.cpp" fullword ascii
$s13 = "hardWorker.cpp" fullword ascii
$s14 = "operator<=>" fullword ascii
$s15 = "operator co_await" fullword ascii
$s16 = "/C PowerShell \"Start-Slemove-Iteep 3; Re" fullword wide
$s17 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo><security><requestedPrivileges><requeste" ascii
$s18 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s19 = "UAWAVAUATVWSH" fullword ascii
$s20 = "AWAVAUATVWUSH" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 1000KB and
( pe.imphash() == "e2450fb3cc5b1b7305e3193fe03f3369" and ( 1 of ($x*) or 8 of them ) )
}

rule anchorAsjuster_x64 {
meta:
description = "files - file anchorAsjuster_x64.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-02-22"
hash1 = "3ab8a1ee10bd1b720e1c8a8795e78cdc09fec73a6bb91526c0ccd2dc2cfbc28d"
strings:
$s1 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii
$s2 = "anchorAdjuster* --source=<source file> --target=<target file> --domain=<domain name> --period=<recurrence interval, minutes, def" ascii
$s3 = "anchorAdjuster* --source=<source file> --target=<target file> --domain=<domain name> --period=<recurrence interval, minutes, def" ascii
$s4 = "target file \"%s\"" fullword ascii
$s5 = "--target=" fullword ascii
$s6 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
$s7 = "error write file, written %i bytes, need write %i bytes, error code %i" fullword ascii
$s8 = "error create file \"%s\", code %i" fullword ascii
$s9 = "guid: %s, shift 0x%08X(%i)" fullword ascii
$s10 = "ault value 15> -guid --count=<count of instances>" fullword ascii
$s11 = "domain: shift 0x%08X(%i)" fullword ascii
$s12 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
$s13 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii
$s14 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
$s15 = "network reset" fullword ascii /* Goodware String - occured 567 times */
$s16 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
$s17 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
$s18 = "network down" fullword ascii /* Goodware String - occured 567 times */
$s19 = "protocol not supported" fullword ascii /* Goodware String - occured 568 times */
$s20 = "connection aborted" fullword ascii /* Goodware String - occured 568 times */
condition:
uint16(0) == 0x5a4d and filesize < 700KB and
( pe.imphash() == "9859b7a32d1227be2ca925c81ae9265e" and 8 of them )
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-03-29
Identifier: Case 1051 Sodinokibi (aka REvil) Ransomware
Reference: https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Sodinokibi_032021 {
meta:
description = "files - file DomainName.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-03-21"
hash1 = "2896b38ec3f5f196a9d127dbda3f44c7c29c844f53ae5f209229d56fd6f2a59c"
strings:
$s1 = "vmcompute.exe" fullword wide
$s2 = "vmwp.exe" fullword wide
$s3 = "bootcfg /raw /a /safeboot:network /id 1" fullword ascii
$s4 = "bcdedit /set {current} safeboot network" fullword ascii
$s5 = "7+a@P>:N:0!F$%I-6MBEFb M" fullword ascii
$s6 = "jg:\"\\0=Z" fullword ascii
$s7 = "ERR0R D0UBLE RUN!" fullword wide
$s8 = "VVVVVPQ" fullword ascii
$s9 = "VVVVVWQ" fullword ascii
$s10 = "Running" fullword wide /* Goodware String - occured 159 times */
$s11 = "expand 32-byte kexpand 16-byte k" fullword ascii
$s12 = "9RFIT\"&" fullword ascii
$s13 = "jZXVf9F" fullword ascii
$s14 = "tCWWWhS=@" fullword ascii
$s15 = "vmms.exe" fullword wide /* Goodware String - occured 1 times */
$s16 = "JJwK9Zl" fullword ascii
$s17 = "KkT37uf4nNh2PqUDwZqxcHUMVV3yBwSHO#K" fullword ascii
$s18 = "0*090}0" fullword ascii /* Goodware String - occured 1 times */
$s19 = "5)5I5a5" fullword ascii /* Goodware String - occured 1 times */
$s20 = "7-7H7c7" fullword ascii /* Goodware String - occured 1 times */
condition:
uint16(0) == 0x5a4d and filesize < 400KB and
( pe.imphash() == "031931d2f2d921a9d906454d42f21be0" or 8 of them )
}

rule icedid_032021_1 {
meta:
description = "files - file skull-x64.dat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-03-21"
hash1 = "59a2a5fae1c51afbbf1bf8c6eb0a65cb2b8575794e3890f499f8935035e633fc"
strings:
$s1 = "update" fullword ascii /* Goodware String - occured 207 times */
$s2 = "PstmStr" fullword ascii
$s3 = "mRsx0k/" fullword wide
$s4 = "D$0lzK" fullword ascii
$s5 = "A;Zts}H" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 100KB and
( pe.imphash() == "67a065c05a359d287f1fed9e91f823d5" and ( pe.exports("PstmStr") and pe.exports("update") ) or all of them )
}

rule icedid_032021_2 {
meta:
description = "1 - file license.dat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-03-21"
hash1 = "45b6349ee9d53278f350b59d4a2a28890bbe9f9de6565453db4c085bb5875865"
strings:
$s1 = "+ M:{`n-" fullword ascii
$s2 = "kwzzdd" fullword ascii
$s3 = "w5O- >z" fullword ascii
$s4 = "RRlK8n@~" fullword ascii
$s5 = "aQXDUkBC" fullword ascii
$s6 = "}i.ZSj*" fullword ascii
$s7 = "kLeSM?" fullword ascii
$s8 = "qmnIqD\")P" fullword ascii
$s9 = "aFAeU!," fullword ascii
$s10 = "Qjrf\"Q" fullword ascii
$s11 = "PTpc,!P#" fullword ascii
$s12 = "r@|JZOkfmT2" fullword ascii
$s13 = "aPvBO,4" fullword ascii
$s14 = ">fdFhl^S8Z" fullword ascii
$s15 = "[syBE0\\" fullword ascii
$s16 = "`YFOr.JH" fullword ascii
$s17 = "C6ZVVF j7}" fullword ascii
$s18 = "LPlagce" fullword ascii
$s19 = "NLeF_-e`" fullword ascii
$s20 = "HRRF|}O" fullword ascii
condition:
uint16(0) == 0x43da and filesize < 1000KB and
8 of them
}
/* 
   YARA Rule Set 
   Author: The DFIR Report 
   Date: 2022-05-09 
   Identifier: Case 11462 SEO Poisoning – A Gootloader Story
   Reference: https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule olympus_plea_agreement_34603_11462 {
   meta:
      description = "file olympus_plea_agreement 34603 .js"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-05-01"
      hash1 = "6e141779a4695a637682d64f7bc09973bb82cd24211b2020c8c1648cdb41001b"
   strings:
      $s1 = "// https://web.archive.org/web/20141116233347/http://fluidproject.org/blog/2008/01/09/getting-setting-and-removing-tabindex-valu" ascii
      $s2 = "// Related ticket - https://bugzilla.mozilla.org/show_bug.cgi?id=687787" fullword ascii
      $s3 = "*    - AFTER param serialization (s.data is a string if s.processData is true)" fullword ascii
      $s4 = "* https://jquery.com/" fullword ascii
      $s5 = "* https://sizzlejs.com/" fullword ascii
      $s6 = "target.length = j - 1;" fullword ascii
      $s7 = "// Remove auto dataType and get content-type in the process" fullword ascii
      $s8 = "process.stackTrace = jQuery.Deferred.getStackHook();" fullword ascii
      $s9 = "* 5) execution will start with transport dataType and THEN continue down to \"*\" if needed" fullword ascii
      $s10 = "// https://web.archive.org/web/20141116233347/http://fluidproject.org/blog/2008/01/09/getting-setting-and-removing-tabindex-valu" ascii
      $s11 = "// We eschew Sizzle here for performance reasons: https://jsperf.com/getall-vs-sizzle/2" fullword ascii
      $s12 = "if ( s.data && s.processData && typeof s.data !== \"string\" ) {" fullword ascii
      $s13 = "} else if ( s.data && s.processData &&" fullword ascii
      $s14 = "if ( s.data && ( s.processData || typeof s.data === \"string\" ) ) {" fullword ascii
      $s15 = "rcssNum.exec( jQuery.css( elem, prop ) );" fullword ascii
      $s16 = "// Related ticket - https://bugs.chromium.org/p/chromium/issues/detail?id=449857" fullword ascii
      $s17 = "jQuery.inArray( \"script\", s.dataTypes ) > -1 &&" fullword ascii
      $s18 = "while ( ( match = rheaders.exec( responseHeadersString ) ) ) {" fullword ascii
      $s19 = "targets.index( cur ) > -1 :" fullword ascii
      $s20 = "* - finds the right dataType (mediates between content-type and expected dataType)" fullword ascii
   condition:
      uint16(0) == 0x2a2f and filesize < 900KB and
      8 of them
}

rule Invoke_WMIExec_11462 {
   meta:
      description = "file Invoke-WMIExec.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-05-01"
      hash1 = "c4939f6ad41d4f83b427db797aaca106b865b6356b1db3b7c63b995085457222"
   strings:
      $x1 = "Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command \"comman" ascii
      $x2 = "Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command \"comman" ascii
      $x3 = "Write-Output \"[+] Command executed with process ID $target_process_ID on $target_long\"" fullword ascii
      $x4 = "Invoke-WMIExec -Target 192.168.100.20 -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0" fullword ascii
      $s5 = "$target_address_list = [System.Net.Dns]::GetHostEntry($target_long).AddressList" fullword ascii
      $s6 = "$WMI_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostna" ascii
      $s7 = "Execute a command." fullword ascii
      $s8 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessReques" fullword ascii
      $s9 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader" fullword ascii
      $s10 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader\"" fullword ascii
      $s11 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader\"," ascii
      $s12 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFl" ascii
      $s13 = "$packet_DCOMRemoteCreateInstance.Add(\"IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader\",[" ascii
      $s14 = "$target_process_ID = Get-UInt16DataLength 1141 $WMI_client_receive" fullword ascii
      $s15 = "$hostname_length = [System.BitConverter]::GetBytes($auth_hostname.Length + 1)" fullword ascii
      $s16 = "Write-Verbose \"[*] Attempting command execution\"" fullword ascii
      $s17 = "$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id" fullword ascii
      $s18 = "$auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_host" fullword ascii
      $s19 = "$auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostna" fullword ascii
      $s20 = "[Byte[]]$packet_private_header = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 40) + 0x00,0x00,0x00,0x00" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule mi_mimikatz_11462 {
   meta:
      description = "Mimikatz - file mi.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-05-01"
      hash1 = "d00edf5b9a9a23d3f891afd51260b3356214655a73e1a361701cda161798ea0b"
   strings:
      $x1 = "$best64code = \"==gCNkydtdnbrpXbttmc01mazp2bkgCWFlkCNkSKoo3ZtNnatpHayBHJuMXb3RHanNne1FXarhGJo4Wa0R3b3Fnerl3a3RiLr5GcnBHcutmcnpGd" ascii
      $s2 = "lFM5cmbFVFMatSYLlTdTN2QCdXZyg2QsJVYGFEZiJERBV3T0ZVaYJGZZx2Kx4GSXxGdll1LSJ2R5F2d5J3N3VjSRtUZzgDUmpFOap1TwI3bKpHVDFlNL9GUQJTdwYUUr" ascii
      $s3 = "JFT0omerhFawNXbDVVcIdXZ1REOyMUVXBHVZpWZvUGN6dUMp9ycysCbtBXY5IUVSFVbiNXVtJUYVRFeD5mVYtEMIt0SiB3blZmTHlUWrUmV4RXdr80bw12QuVTQtx2LV" ascii
      $s4 = "x0dGlHUFpUYhV1YXVjR4N1b3p0cVRTTj10TxRFNxhnVEdHd5lGWPNTNFdjexRkNzl2MPtie0RWcnJXQ3djbIN0didHMzJTM5NmS01GaB50Z2VGSJVFOyZGd5hlN1BDMR" ascii
      $s5 = "R1TVhlRO10QXtiU4s2UrNEeXp1QDFzblRHb2UmZLFTdsJFR2BDcmdVesdnQKVWZ21GOQ5kaTdGTRJ1UXNzMVdDU4NHa0p0V3MDeEVFaExEcpBVQzQlY5g0bRV0N1lkQq" ascii
      $s6 = "RUUERUNw5UdSZ3bpp0cVVmeRpVVMx2R1ETZIZzYGhEd6J3VidHT3IUMUhHasR3cwAnM2sST5pUZiNVcjFlcSR3cTJkcmdzKZhkTzNGWzJmZ5N1a6lGbZFXSvEzMFBzRa" ascii
      $s7 = "lnMkxERH9EMiRmW4k2doBDS6dXdLlDM4VmRrlTWwMmSmFnNCV1YLdjN0sCUp9WST9SYHlkYaRWb5R3L0oVNn50am9EU6hkV0InYCNmWv4WTktUSxdnW0gET25GNxsWO4" ascii
      $s8 = "NzTyIXSJdFMip1ZrNVY1VzQStCVatEdm92ZU1Wc09SYNt0LRBnYPlEchV1RJN3ZLBlVtRlM2FDNWR0RSZ3d30mUNpHWD52SQFTNQtiS2kEalx0dll3UzQ2NGVEVIl0YT" ascii
      $s9 = "hzQ0QVYxhXWNdDN2lzd0JUR582TUhzaCJmVQhHaLp0c5VkWpNnQhh2QhJDO3oVSwczUkR0MyMkcwAldwJDbOd0SNJEVil0QVF3NGFkez5UYMZUQzgUM3gFOGhGRzU2Vw" ascii
      $s10 = "5mMnVDcohGWUVmbjlDWHFmVv8SY3ZGTrdja3k2TOd3KMBlUstmWrNzYyQzKwIzKzknQYlzKrknYlJndTFleDdnWV5Uc04kNYRldll3LaJjckBTMVp0cPZlZ1Y0MpZkS1" ascii
      $s11 = "F0KtlDetp0c4BnaBVXWERnczUWRPN2KDVTMkh1dFdFaKNmYKRGMrMHan5UbrRGMzIXcvlFe1J0Z0dUMPRFSvlndo9mSkpWQTV1SyNFZLFHRnVWRP5EcjJGcBp3L1c3am" ascii
      $s12 = "QWb5Z0UhJFUwgETQdGMxATdUdXcXRHcTVTMrQEe6JEWBxUTVhGR1hGULp1Vx8UQLRncYBnaN9mVDBFazcnbRFTSJpXTuZDS4dTd0l0ZGJTUYlUSwIEcIFDcnF0Zip0cJ" ascii
      $s13 = "RVUm9GcjV0MwQGV3NGWxMWVSRDMNJHevdUMpFHVxMXQyp3VrcHVJdGeJtUQvMXb3dUZ4cERUdHN3FFSQ5kdL9kap5ENmJ3TDVESHN0SCZlQXJDc2BDOIlmNxxUY0RkN2" ascii
      $s14 = "FzUZxWejZWMmV2ZpdjTxg3arMnQCB1LvoXY4kVdkFEeM1GcwB3TDllMFZGeTF3Z4MzRSR2KTBFaz8EWzBlQlJ0ckNHTpd2KwkURpBXQWF1ZjRTRqlVNvImYmF0bmtUYV" ascii
      $s15 = "NnW3oHNkZ3NY9mMTtmbNJTQx8WdNl3NCtCZGpVOMdUT2BzUWFTW5UjZu9CRIdHcLJzNoZTThhkVwgDOGdXM2B1dLlzUI9SQrllTqVkbst0TywmUwcXTPJmRvFFTPhEeh" ascii
      $s16 = "JUbL5WZxMXQux2bMNFNHhkVh1mY59UQP50Kp52N2FHa1ZHexcXN1oHRMhkes9icpZXU0VTc050VGZDOidUMPZDW0NkNwNjWxVHNrUUVvJmQ4p1LY10ZyFHTBBXcIZ2aZ" ascii
      $s17 = "FmN44kQz9yMRZTQKp1UmVFaOdnSSR3THdkSHJDdO5WRT90SSpHZjZVT3NUZwFkWWhlNpJzN04UZpRzLERnTtVGM4JTbyFGeTRXUwgHeyEmWTVlUr8kU4tyL2JnNTZENv" ascii
      $s18 = "d0aZ1WOFp1YTRWZ4tUVrN0Q5AVQEV3a3UnV2U0QkR3L3hEU3o3LJFWQnZzdzEUO4hFbBJDTUJGeopkclNjMFJDZ6lHa4o1LUVGShp0cup3L5dWZxpmS11mcix2VV5ERv" ascii
      $s19 = "9CNqJmSVRUZjFDR3B1VGhUNZNkQxNmS18WRwpHc2lUYBN1RYNXcntEZWNFeyEzMiRWQr8WOLRVZyg0QiF0QI1Gbr0mZvkmdyxUb4p3Kph2dadGb5EjSRFFdq9WSutydi" ascii
      $s20 = "dUb2JDZLdVVvpFe2YVS1lzSvl1MnlGdv92KKZWdWZGahxUaipGWypUeEZ3dyZWONJFTUdjTx5GR4p0KwYXaSZ2dLl2cRxGS4ZWdZFTNvoEeQpWRKJWQahkaTZWcz9iNa" ascii
   condition:
      uint16(0) == 0x6224 and filesize < 10000KB and
      1 of ($x*) and 4 of them
}

rule lazagne_ls_11462 {
   meta:
      description = "lazagne - file ls.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-05-01"
      hash1 = "8764131983eac23033c460833de5e439a4c475ad94cfd561d80cb62f86ff50a4"
   strings:
      $s1 = "pypykatz.lsadecryptor.packages.msv.templates(" fullword ascii
      $s2 = "pypykatz.lsadecryptor.packages.ssp.templates(" fullword ascii
      $s3 = "pypykatz.lsadecryptor.packages.kerberos.templates(" fullword ascii
      $s4 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii
      $s5 = "pypykatz.commons.readers.local.common.kernel32(" fullword ascii
      $s6 = "pypykatz.lsadecryptor.packages.dpapi.templates(" fullword ascii
      $s7 = "pypykatz.lsadecryptor.packages.credman.templates(" fullword ascii
      $s8 = "pypykatz.lsadecryptor.packages.livessp.templates(" fullword ascii
      $s9 = "pypykatz.lsadecryptor.packages.wdigest.templates(" fullword ascii
      $s10 = "pypykatz.lsadecryptor.packages.tspkg.templates(" fullword ascii
      $s11 = "pypykatz.lsadecryptor.lsa_templates(" fullword ascii
      $s12 = "lazagne.config.lib.memorpy.SunProcess(" fullword ascii
      $s13 = "lazagne.config.lib.memorpy.BaseProcess(" fullword ascii
      $s14 = "lazagne.config.lib.memorpy.OSXProcess(" fullword ascii
      $s15 = "lazagne.config.lib.memorpy.Process(" fullword ascii
      $s16 = "lazagne.config.lib.memorpy.WinProcess(" fullword ascii
      $s17 = "lazagne.config.lib.memorpy.LinProcess(" fullword ascii
      $s18 = "lazagne.config.execute_cmd(" fullword ascii
      $s19 = "pypykatz.commons.readers.local.common.version(" fullword ascii
      $s20 = "pypykatz.commons.readers.local.common.privileges(" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 23000KB and
      ( pe.imphash() == "a62ff465f3ead2e578f02d3a2d749b7b" or 8 of them )
}

rule powershell_dll{
   meta:
      description = "11462 - powershell.dll"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com"
      date = "2022-03-22"
      hash1 = "2fcd6a4fd1215facea1fe1a503953e79b7a1cedc4d4320e6ab12461eb45dde30"
   strings:
      $s1 = "powershell.dll" fullword wide
      $s2 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s3 = "DynamicDllLoader" fullword ascii
      $s4 = "GetModuleCount" fullword ascii
      $s5 = "fnDllEntry" fullword ascii
      $s6 = "oldHeaders" fullword ascii
      $s7 = "dosHeader" fullword ascii
      $s8 = "IMAGE_EXPORT_DIRECTORY" fullword ascii
      $s9 = "Win32Imports" fullword ascii
      $s10 = "IMAGE_IMPORT_BY_NAME" fullword ascii
      $s11 = "BuildImportTable" fullword ascii
      $s12 = "MEMORYMODULE" fullword ascii
      $s13 = "lpAddress" fullword ascii /* Goodware String - occured 17 times */
      $s14 = "CurrentUser" fullword ascii /* Goodware String - occured 204 times */
      $s15 = "Signature" fullword ascii /* Goodware String - occured 282 times */
      $s16 = "Install" fullword wide /* Goodware String - occured 325 times */
      $s17 = "module" fullword ascii /* Goodware String - occured 467 times */
      $s18 = "Console" fullword ascii /* Goodware String - occured 526 times */
      $s19 = "EndInvoke" fullword ascii /* Goodware String - occured 915 times */
      $s20 = "BeginInvoke" fullword ascii /* Goodware String - occured 932 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      10 of them
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2022-04-24
Identifier: Quantum Ransomware - Case 12647
Reference: https://thedfirreport.com/2022/04/25/quantum-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule docs_invoice_173 {
meta:
description = "IcedID - file docs_invoice_173.iso"
author = "The DFIR Report"
reference = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
date = "2022-04-24"
hash1 = "5bc00ad792d4ddac7d8568f98a717caff9d5ef389ed355a15b892cc10ab2887b"
strings:
$x1 = "dar.dll,DllRegisterServer!%SystemRoot%\\System32\\SHELL32.dll" fullword wide
$x2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
$s3 = "C:\\Users\\admin\\Desktop\\data" fullword wide
$s4 = "Desktop (C:\\Users\\admin)" fullword wide
$s5 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s6 = "1t3Eo8.dll" fullword ascii
$s7 = ")..\\..\\..\\..\\Windows\\System32\\rundll32.exe" fullword wide
$s8 = "DAR.DLL." fullword ascii
$s9 = "dar.dll:h" fullword wide
$s10 = "document.lnk" fullword wide
$s11 = "DOCUMENT.LNK" fullword ascii
$s12 = "6c484a379420bc181ea93528217b7ebf50eae9cb4fc33fb672f26ffc4ab464e29ba2c0acf9e19728e70ef2833eb4d4ab55aafe3f4667e79c188aa8ab75702520" ascii
$s13 = "03b9db8f12f0242472abae714fbef30d7278c4917617dc43b61a81951998d867efd5b8a2ee9ff53ea7fa4110c9198a355a5d7f3641b45f3f8bb317aac02aa1fb" ascii
$s14 = "d1e5711e46fcb02d7cc6aa2453cfcb8540315a74f93c71e27fa0cf3853d58b979d7bb7c720c02ed384dea172a36916f1bb8b82ffd924b720f62d665558ad1d8c" ascii
$s15 = "7d0bfdbaac91129f5d74f7e71c1c5524690343b821a541e8ba8c6ab5367aa3eb82b8dd0faee7bf6d15b972a8ae4b320b9369de3eb309c722db92d9f53b6ace68" ascii
$s16 = "89dd0596b7c7b151bf10a1794e8f4a84401269ad5cc4af9af74df8b7199fc762581b431d65a76ecbff01e3cec318b463bce59f421b536db53fa1d21942d48d93" ascii
$s17 = "8021dc54625a80e14f829953cc9c4310b6242e49d0ba72eedc0c04383ac5a67c0c4729175e0e662c9e78cede5882532de56a5625c1761aa6fd46b4aefe98453a" ascii
$s18 = "24ed05de22fc8d3f76c977faf1def1d729c6b24abe3e89b0254b5b913395ee3487879287388e5ceac4b46182c2072ad1aa4f415ed6ebe515d57f4284ae068851" ascii
$s19 = "827da8b743ba46e966706e7f5e6540c00cb1205811383a2814e1d611decfc286b1927d20391b22a0a31935a9ab93d7f25e6331a81d13db6d10c7a771e82dfd8b" ascii
$s20 = "7c33d9ad6872281a5d7bf5984f537f09544fdee50645e9846642206ea4a81f70b27439e6dcbe6fdc1331c59bf3e2e847b6195e8ed2a51adaf91b5e615cece1d3" ascii
condition:
uint16(0) == 0x0000 and filesize < 600KB and
1 of ($x*) and 4 of them
}

rule quantum_license {
meta:
description = "IcedID - file license.dat"
author = "The DFIR Report"
reference = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
date = "2022-04-24"
hash1 = "84f016ece77ddd7d611ffc0cbb2ce24184aeee3a2fdbb9d44d0837bc533ba238"
strings:
$s1 = "W* |[h" fullword ascii
$s2 = "PSHN,;x" fullword ascii
$s3 = "ephu\"W" fullword ascii
$s4 = "LwUw9\\" fullword ascii
$s5 = "VYZP~pN," fullword ascii
$s6 = "eRek?@" fullword ascii
$s7 = "urKuEqR" fullword ascii
$s8 = "1zjWa{`!" fullword ascii
$s9 = "YHAV{tl" fullword ascii
$s10 = "bwDU?u" fullword ascii
$s11 = "SJbW`!W" fullword ascii
$s12 = "BNnEx1k" fullword ascii
$s13 = "SEENI3=" fullword ascii
$s14 = "Bthw?:'H*" fullword ascii
$s15 = "NfGHNHC" fullword ascii
$s16 = "xUKlrl'>`" fullword ascii
$s17 = "gZaZ^;Ro2" fullword ascii
$s18 = "JhVo5Bb" fullword ascii
$s19 = "OPta)}$" fullword ascii
$s20 = "cZZJoVB" fullword ascii
condition:
uint16(0) == 0x44f8 and filesize < 1000KB and
8 of them
}

rule quantum_p227 {
meta:
description = "Cobalt Strike - file p227.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
date = "2022-04-24"
hash1 = "c140ae0ae0d71c2ebaf956c92595560e8883a99a3f347dfab2a886a8fb00d4d3"
strings:
$s1 = "Remote Event Log Manager4" fullword wide
$s2 = "IIdRemoteCMDServer" fullword ascii
$s3 = "? ?6?B?`?" fullword ascii /* hex encoded string 'k' */
$s4 = "<*=.=2=6=<=\\=" fullword ascii /* hex encoded string '&' */
$s5 = ">'?+?/?3?7?;???" fullword ascii /* hex encoded string '7' */
$s6 = ":#:':+:/:3:7:" fullword ascii /* hex encoded string '7' */
$s7 = "2(252<2[2" fullword ascii /* hex encoded string '"R"' */
$s8 = ":$;,;2;>;F;" fullword ascii /* hex encoded string '/' */
$s9 = ":<:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
$s10 = "%IdThreadMgr" fullword ascii
$s11 = "AutoHotkeys<mC" fullword ascii
$s12 = "KeyPreview0tC" fullword ascii
$s13 = ":dmM:\\m" fullword ascii
$s14 = "EFilerErrorH" fullword ascii
$s15 = "EVariantBadVarTypeErrorL" fullword ascii
$s16 = "IdThreadMgrDefault" fullword ascii
$s17 = "Set Size Exceeded.*Error on call Winsock2 library function %s&Error on loading Winsock2 library (%s)" fullword wide
$s18 = "CopyMode0" fullword ascii
$s19 = "TGraphicsObject0" fullword ascii
$s20 = "THintWindow8" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "c88d91896dd5b7d9cb3f912b90e9d0ed" or 8 of them )
}

rule Ulfefi32 {
meta:
description = "IcedID - file Ulfefi32.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
date = "2022-04-24"
hash1 = "6f6f71fa3a83da86d2aba79c92664d335acb9d581646fa6e30c35e76cf61cbb7"
strings:
$s1 = "WZSKd2NEBI.dll" fullword ascii
$s2 = "3638df174d2e47fbc2cdad390fdf57b44186930e3f9f4e99247556af2745ec513b928c5d78ef0def56b76844a24f50ab5c3a10f6f0291e8cfbc4802085b8413c" ascii
$s3 = "794311155e3d3b59587a39e6bdeaac42e5a83dbe30a056a059c59a1671d288f7a7cdde39aaf8ce26704ab467e6e7db6da36aec8e1b1e0a6f2101ed3a87a73523" ascii
$s4 = "ce37d7187cf033f0f9144a61841e65ebe440d99644c312f2a7527053f27664fc788a70d4013987f40755d30913393c37067fb1796adece94327ba0d8dfb63c10" ascii
$s5 = "bacefbe356ece5ed36fa3f3c153e8e152cb204299243eba930136e4a954e8f6e4db70d7d7084822762c17da1d350d97c37dbcf226c5d4faa7e78765fd5aa20f8" ascii
$s6 = "acee4914ee999f6158bf7aa90e2f9640d51e2b046c94df4301a6ee1658a54d44e423fc0a5ab3b599d6be74726e266cdb71ccd0851bcef3bc5f828eab7e736d81" ascii
$s7 = "e2d7e82b0fe30aa846abaa4ab85cb9d47940ec70487f2d5fb4c60012289b133b44e8c244e3ec8e276fa118a54492f348e34e992da07fada70c018de1ff8f91d4" ascii
$s8 = "afd386d951143fbfc89016ab29a04b6efcefe7cd9d3e240f1d31d59b9541b222c45bb0dc6adba0ee80b696b85939ac527af149fdbfbf40b2d06493379a27e16b" ascii
$s9 = "3bb43aa0bbe8dee8d99aaf3ac42fbe3ec5bd8fa68fb85aea8a404ee1701aa8b2624bf8c5254e447818057b7f987a270103dd7beceb3103a66d5f34a2a6c48eed" ascii
$s10 = "a79e1facc14f0a1dfde8f71cec33e08ed6144aa2fd9fe3774c89b50d26b78f4a516a988e412e5cce5a6b6edb7b2cded7fe9212505b240e629e066ed853fb9f6b" ascii
$s11 = "69f9b12abc44fac17d92b02eb254c9dc0cfd8888676a9e59f0cb6d630151daccea40e850d615d32d011838f8042a2d6999fab319f49bed09e43f9b6197bf9a66" ascii
$s12 = "cfda9d35efe288ebc6a63ef8206cd3c44e91f7d968044a8a5b512c59e76e937477837940a3a6c053a886818041e42f0ce8ede5912beab0b9b8c3f4bae726d5b2" ascii
$s13 = "a8a404ee1701aa8b2624bf8c5254e447818057b7f987a270103dd7beceb3103a66d5f34a2a6c48eedc90afe65ba742c395bbdb4b1b12d96d6f38de96212392c3" ascii
$s14 = "900796689b72e62f24b28affa681c23841f21e2c7a56a18a6bbb572042da8717abc9f195340d12f2fae6cf2a6d609ed5a0501e34d3b31f8151f194cdb8afc85e" ascii
$s15 = "35560790835fe34ed478758636d3b2b797ba95c824533318dfb147146e2b5debb4f974c906dce439d3c97e94465849c9b42e9cb765a95ff42a7d8b27e62d470a" ascii
$s16 = "0b3d20f3cf0f6b3a53c53b8f50f9116edd412776a8f218e6b0d921ccfeeb34875c4674072f84ac612004d8162a6b381f5a3d1f6d70c03203272740463ff4bcd5" ascii
$s17 = "72f69c37649149002c41c2d85091b0f6f7683f6e6cc9b9a0063c9b0ce254dddb9736c68f81ed9fed779add52cbb453e106ab8146dab20a033c28dee789de8046" ascii
$s18 = "f2b7f87aa149a52967593b53deff481355cfe32c2af99ad4d4144d075e2b2c70088758aafdabaf480e87cf202626bde30d32981c343bd47b403951b165d2dc0f" ascii
$s19 = "9867f0633c80081f0803b0ed75d37296bac8d3e25e3352624a392fa338570a9930fa3ceb0aaee2095dd3dcb0aab939d7d9a8d5ba7f3baac0601ed13ffc4f0a1e" ascii
$s20 = "3d08b3fcfda9d35efe288ebc6a63ef8206cd3c44e91f7d968044a8a5b512c59e76e937477837940a3a6c053a886818041e42f0ce8ede5912beab0b9b8c3f4bae" ascii
condition:
uint16(0) == 0x5a4d and filesize < 100KB and
( pe.imphash() == "81782d8702e074c0174968b51590bf48" and ( pe.exports("FZKlWfNWN") and pe.exports("IMlNwug") and pe.exports("RPrWVBw") and pe.exports("kCXkdKtadW") and pe.exports("pLugSs") and pe.exports("pRNAU") ) or 8 of them )
}

rule quantum_ttsel {
meta:
description = "quantum - file ttsel.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
date = "2022-04-24"
hash1 = "b6c11d4a4af4ad4919b1063184ee4fe86a5b4b2b50b53b4e9b9cc282a185afda"
strings:
$s1 = "DSUVWj ]" fullword ascii
$s2 = "WWVh@]@" fullword ascii
$s3 = "expand 32-byte k" fullword ascii /* Goodware String - occured 1 times */
$s4 = "E4PSSh" fullword ascii /* Goodware String - occured 2 times */
$s5 = "tySjD3" fullword ascii
$s6 = "@]_^[Y" fullword ascii /* Goodware String - occured 3 times */
$s7 = "0`0h0p0" fullword ascii /* Goodware String - occured 3 times */
$s8 = "tV9_<tQf9_8tKSSh" fullword ascii
$s9 = "Vj\\Yj?Xj:f" fullword ascii
$s10 = "1-1:1I1T1Z1p1w1" fullword ascii
$s11 = "8-999E9U9k9" fullword ascii
$s12 = "8\"8)8H8i8t8" fullword ascii
$s13 = "8\"868@8M8W8" fullword ascii
$s14 = "3\"3)3>3F3f3m3t3}3" fullword ascii
$s15 = "3\"3(3<3]3o3" fullword ascii
$s16 = "9 9*909B9" fullword ascii
$s17 = "9.979S9]9a9w9" fullword ascii
$s18 = "txf9(tsf9)tnj\\P" fullword ascii
$s19 = "5!5'5-5J5Y5b5i5~5" fullword ascii
$s20 = "<2=7=>=E={=" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 200KB and
( pe.imphash() == "68b5e41a24d5a26c1c2196733789c238" or 8 of them )
}
rule miner_batch {
   meta:
      description = "file kit.bat"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
      date = "2022/07/10"
      hash1 = "4905b7776810dc60e710af96a7e54420aaa15467ef5909b260d9a9bc46911186"
   strings:
      $a1 = "%~dps0" fullword ascii
      $a2 = "set app" fullword ascii
      $a3 = "cd /d \"%~dps0\"" fullword ascii
      $a4 = "set usr=jood" fullword ascii
      $s1 = "schtasks /run" fullword ascii
      $s2 = "schtasks /delete" fullword ascii
      $a5 = "if \"%1\"==\"-s\" (" fullword ascii
   condition:
      uint16(0) == 0xfeff and filesize < 1KB and
      3 of ($a*) and 1 of ($s*)
}

rule file_ex_exe {
   meta:
      description = "files - file ex.exe.bin"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
      date = "2022/07/10"
      hash1 = "428d06c889b17d5f95f9df952fc13b1cdd8ef520c51e2abff2f9192aa78a4b24"
   strings:
      $s1 = "d:\\Projects\\WinRAR\\rar\\build\\unrar32\\Release\\UnRAR.pdb" fullword ascii
      $s2 = "rar.log" fullword wide
      $s3 = "      <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s4 = "  processorArchitecture=\"*\"" fullword ascii
      $s5 = "%c%c%c%c%c%c%c" fullword wide /* reversed goodware string 'c%c%c%c%c%c%c%' */
      $s6 = "  version=\"1.0.0.0\"" fullword ascii
      $s7 = "%12ls: RAR %ls(v%d) -m%d -md=%d%s" fullword wide
      $s8 = "  hp[password]  " fullword wide
      $s9 = " %s - " fullword wide
      $s10 = "yyyymmddhhmmss" fullword wide
      $s11 = "--------  %2d %s %d, " fullword wide
      $s12 = " Type Descriptor'" fullword ascii
      $s13 = "\\$\\3|$4" fullword ascii /* hex encoded string '4' */
      $s14 = "      processorArchitecture=\"*\"" fullword ascii
      $s15 = " constructor or from DllMain." fullword ascii
      $s16 = "----------- ---------  -------- -----  ----" fullword wide
      $s17 = "----------- ---------  -------- ----- -------- -----  --------  ----" fullword wide
      $s18 = "%-20s - " fullword wide
      $s19 = "      publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
      $s20 = "      version=\"6.0.0.0\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule smss_exe {
   meta:
      description = "files - file smss.exe.bin"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
      date = "2022/07/10"
      hash1 = "d3c3f529a09203a839b41cd461cc561494b432d810041d71d41a66ee7d285d69"
   strings:
      $s1 = "mCFoCRYPT32.dll" fullword ascii
      $s2 = "gPSAPI.DLL" fullword ascii
      $s3 = "www.STAR.com" fullword wide
      $s4 = "4;#pMVkWTSAPI32.dll" fullword ascii
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii
      $s6 = "dYDT.Gtm" fullword ascii
      $s7 = "|PgGeT~^" fullword ascii
      $s8 = "* IiJ)" fullword ascii
      $s9 = "{DllB8qq" fullword ascii
      $s10 = "tfaqbjk" fullword ascii
      $s11 = "nrvgzgl" fullword ascii
      $s12 = "      <!--The ID below indicates application support for Windows 10 -->" fullword ascii
      $s13 = "5n:\\Tk" fullword ascii
      $s14 = "  </compatibility>" fullword ascii
      $s15 = "HHp.JOW" fullword ascii
      $s16 = "      <!--The ID below indicates application support for Windows 8 -->" fullword ascii
      $s17 = "      <!--The ID below indicates application support for Windows 7 -->" fullword ascii
      $s18 = "Wr:\\D;" fullword ascii
      $s19 = "px:\"M$" fullword ascii
      $s20 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 23000KB and
      8 of them
}

rule WinRing0x64_sys {
   meta:
      description = "files - file WinRing0x64.sys.bin"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/"
      date = "2022/07/10"
      hash1 = "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5"
   strings:
      $s1 = "d:\\hotproject\\winring0\\source\\dll\\sys\\lib\\amd64\\WinRing0.pdb" fullword ascii
      $s2 = "WinRing0.sys" fullword wide
      $s3 = "timestampinfo@globalsign.com0" fullword ascii
      $s4 = "\"GlobalSign Time Stamping Authority1+0)" fullword ascii
      $s5 = "\\DosDevices\\WinRing0_1_2_0" fullword wide
      $s6 = "OpenLibSys.org" fullword wide
      $s7 = ".http://crl.globalsign.net/RootSignPartners.crl0" fullword ascii
      $s8 = "Copyright (C) 2007-2008 OpenLibSys.org. All rights reserved." fullword wide
      $s9 = "1.2.0.5" fullword wide
      $s10 = " Microsoft Code Verification Root0" fullword ascii
      $s11 = "\\Device\\WinRing0_1_2_0" fullword wide
      $s12 = "WinRing0" fullword wide
      $s13 = "hiyohiyo@crystalmark.info0" fullword ascii
      $s14 = "GlobalSign1+0)" fullword ascii
      $s15 = "Noriyuki MIYAZAKI1(0&" fullword ascii
      $s16 = "The modified BSD license" fullword wide
      $s17 = "RootSign Partners CA1" fullword ascii
      $s18 = "\\/.gJ&" fullword ascii
      $s19 = "14012709" ascii
      $s20 = "140127110000Z0q1(0&" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      8 of them
}
/*

   YARA Rule Set
   Author: The DFIR Report
   Date: 2022-06-06
   Identifier: Case 12993 Will the Real Msiexec Please Stand Up? Exploit Leads to Data Exfiltration
   Reference: https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/

*/

/* Rule Set ----------------------------------------------------------------- */

rule case_12993_cve_2021_44077_msiexec {
   meta:
      description = "Files - file msiexec.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/"
      date = "2022-06-06"
      hash1 = "4d8f797790019315b9fac5b72cbf693bceeeffc86dc6d97e9547c309d8cd9baf"
   strings:
      $x1 = "C:\\Users\\Administrator\\msiexec\\msiexec\\msiexec\\obj\\x86\\Debug\\msiexec.pdb" fullword ascii
      $x2 = "M:\\work\\Shellll\\msiexec\\msiexec\\obj\\Release\\msiexec.pdb" fullword ascii
      $s2 = "..\\custom\\login\\fm2.jsp" fullword wide
      $s3 = "Qk1QDQo8JUBwYWdlIGltcG9ydD0iamF2YS51dGlsLnppcC5aaXBFbnRyeSIlPg0KPCVAcGFnZSBpbXBvcnQ9ImphdmEudXRpbC56aXAuWmlwT3V0cHV0U3RyZWFtIiU+" wide
      $s4 = "Program" fullword ascii /* Goodware String - occured 194 times */
      $s5 = "Encoding" fullword ascii /* Goodware String - occured 809 times */
      $s6 = "base64EncodedData" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "System.Runtime.CompilerServices" fullword ascii /* Goodware String - occured 1950 times */
      $s8 = "System.Reflection" fullword ascii /* Goodware String - occured 2186 times */
      $s9 = "System" fullword ascii /* Goodware String - occured 2567 times */
      $s10 = "Base64Decode" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "$77b5d0d3-047f-4017-a788-503ab92444a7" fullword ascii
      $s12 = "  2021" fullword wide
      $s13 = "RSDSv_" fullword ascii
      $s14 = "503ab92444a7" ascii
      $s15 = "q.#z.+" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      1 of ($x*) and 4 of them

}

rule case_12993_cve_2021_44077_webshell {
   meta:
      description = "Files - file fm2.jsp"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/"
      date = "2022-06-06"
      hash1 = "8703f52c56b3164ae0becfc5a81bfda600db9aa6d0f048767a9684671ad5899b"
   strings:
      $s1 = "    Process powerShellProcess = Runtime.getRuntime().exec(command);" fullword ascii
      $s2 = "out.write((\"User:\\t\"+exec(\"whoami\")).getBytes());" fullword ascii
      $s3 = "return new String(inutStreamToOutputStream(Runtime.getRuntime().exec(cmd).getInputStream()).toByteArray(),encoding);" fullword ascii
      $s4 = "out.println(\"<pre>\"+exec(request.getParameter(\"cmd\"))+\"</pre>\");" fullword ascii
      $s5 = "out.println(\"<tr \"+((i%2!=0)?\"bgcolor=\\\"#eeeeee\\\"\":\"\")+\"><td align=\\\"left\\\">&nbsp;&nbsp;<a href=\\\"javascript:ge" ascii
      $s6 = "out.println(\"<h1>Command execution:</h1>\");" fullword ascii
      $s7 = "    String command = \"powershell.exe \" + request.getParameter(\"cmd\");" fullword ascii
      $s8 = "shell(request.getParameter(\"host\"), Integer.parseInt(request.getParameter(\"port\")));" fullword ascii
      $s9 = "out.write(exec(new String(b,0,a,\"UTF-8\").trim()).getBytes(\"UTF-8\"));" fullword ascii
      $s10 = "static void shell(String host,int port) throws UnknownHostException, IOException{" fullword ascii
      $s11 = "            powerShellProcess.getErrorStream()));" fullword ascii
      $s12 = "encoding = isNotEmpty(getSystemEncoding())?getSystemEncoding():encoding;" fullword ascii
      $s13 = "    // Executing the command" fullword ascii
      $s14 = ".getName()+\"\\\"><tt>download</tt></a></td><td align=\\\"right\\\"><tt>\"+new SimpleDateFormat(\"yyyy-MM-dd hh:mm:ss\").format(" ascii
      $s15 = "String out = exec(cmd);" fullword ascii
      $s16 = "static String exec(String cmd) {" fullword ascii
      $s17 = "            powerShellProcess.getInputStream()));" fullword ascii
      $s18 = "response.setHeader(\"Content-Disposition\", \"attachment; filename=\"+fileName);" fullword ascii
      $s19 = "out.println(\"<pre>\"+auto(request.getParameter(\"url\"),request.getParameter(\"fileName\"),request.getParameter(\"cmd\"))+\"</p" ascii
      $s20 = "    powerShellProcess.getOutputStream().close();" fullword ascii
   condition:
      uint16(0) == 0x4d42 and filesize < 30KB and
      8 of them
}
/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2022-11-13
   Identifier: Case 13842 Bumblebee
   Reference: https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter//
*/

/* Rule Set ----------------------------------------------------------------- */


rule bumblebee_13842_documents_lnk {
    meta:
       description = "BumbleBee - file documents.lnk"
       author = "The DFIR Report via yarGen Rule Generator"
       reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
       date = "2022-11-13"
       hash1 = "3c600328e1085dc73d672d068f3056e79e66bec7020be6ae907dd541201cd167"
    strings:
       $x1 = "$..\\..\\..\\..\\Windows\\System32\\cmd.exe*/c start rundll32.exe mkl2n.dll,kXlNkCKgFC\"%systemroot%\\system32\\imageres.dll" fullword wide
       $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
       $x3 = "%windir%\\system32\\cmd.exe" fullword ascii
       $x4 = "Gcmd.exe" fullword wide
       $s5 = "desktop-30fdj39" fullword ascii
    condition:
       uint16(0) == 0x004c and filesize < 4KB and
       1 of ($x*) and all of them
 }
 
 rule bumblebee_13842_StolenImages_Evidence_iso {
    meta:
       description = "BumbleBee - file StolenImages_Evidence.iso"
       author = "The DFIR Report via yarGen Rule Generator"
       reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
       date = "2022-11-13"
       hash1 = "4bb67453a441f48c75d41f7dc56f8d58549ae94e7aeab48a7ffec8b78039e5cc"
    strings:
       $x1 = "$..\\..\\..\\..\\Windows\\System32\\cmd.exe*/c start rundll32.exe mkl2n.dll,kXlNkCKgFC\"%systemroot%\\system32\\imageres.dll" fullword wide
       $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
       $x3 = "%windir%\\system32\\cmd.exe" fullword ascii
       $x4 = "Gcmd.exe" fullword wide
       $s5 = "pxjjqif723uf35.dll" fullword ascii
       $s6 = "tenant unanimously delighted sail databases princess bicyclelist progress accused urge your science certainty dalton databases h" ascii
       $s7 = "mkl2n.dll" fullword wide
       $s8 = "JEFKKDJJKHFJ" fullword ascii /* base64 encoded string '$AJ(2I(qI' */
       $s9 = "KFFJJEJKJK" fullword ascii /* base64 encoded string '(QI$BJ$' */
       $s10 = "JHJGKDFEG" fullword ascii /* base64 encoded string '$rF(1D' */
       $s11 = "IDJIIDFHE" fullword ascii /* base64 encoded string ' 2H 1G' */
       $s12 = "JHJFIHJJI" fullword ascii /* base64 encoded string '$rE rI' */
       $s13 = "EKGJKKEFHKFFE" fullword ascii /* base64 encoded string '(bJ(AG(QD' */
       $s14 = "FJGJFKGFF" fullword ascii /* base64 encoded string '$bE(aE' */
       $s15 = "IFFKJGJFK" fullword ascii /* base64 encoded string ' QJ$bE' */
       $s16 = "FKFJDIHJF" fullword ascii /* base64 encoded string '(RC rE' */
       $s17 = "EKFJFdHFG" fullword ascii /* base64 encoded string '(REtqF' */
       $s18 = "HJFJJdEdEIDK" fullword ascii /* base64 encoded string '$RItGD 2' */
       $s19 = "KFJHKDJdIGF" fullword ascii /* base64 encoded string '(RG(2] a' */
       $s20 = "documents.lnk" fullword wide
    condition:
       uint16(0) == 0x0000 and filesize < 13000KB and
       1 of ($x*) and 4 of them
 }
 
 rule bumblebee_13842_mkl2n_dll {
    meta:
       description = "BumbleBee - file mkl2n.dll"
       author = "The DFIR Report via yarGen Rule Generator"
       reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
       date = "2022-11-13"
       hash1 = "f7c1d064b95dc0b76c44764cd3ae7aeb21dd5b161e5d218e8d6e0a7107d869c1"
    strings:
       $s1 = "pxjjqif723uf35.dll" fullword ascii
       $s2 = "tenant unanimously delighted sail databases princess bicyclelist progress accused urge your science certainty dalton databases h" ascii
       $s3 = "JEFKKDJJKHFJ" fullword ascii /* base64 encoded string '$AJ(2I(qI' */
       $s4 = "KFFJJEJKJK" fullword ascii /* base64 encoded string '(QI$BJ$' */
       $s5 = "JHJGKDFEG" fullword ascii /* base64 encoded string '$rF(1D' */
       $s6 = "IDJIIDFHE" fullword ascii /* base64 encoded string ' 2H 1G' */
       $s7 = "JHJFIHJJI" fullword ascii /* base64 encoded string '$rE rI' */
       $s8 = "EKGJKKEFHKFFE" fullword ascii /* base64 encoded string '(bJ(AG(QD' */
       $s9 = "FJGJFKGFF" fullword ascii /* base64 encoded string '$bE(aE' */
       $s10 = "IFFKJGJFK" fullword ascii /* base64 encoded string ' QJ$bE' */
       $s11 = "FKFJDIHJF" fullword ascii /* base64 encoded string '(RC rE' */
       $s12 = "EKFJFdHFG" fullword ascii /* base64 encoded string '(REtqF' */
       $s13 = "HJFJJdEdEIDK" fullword ascii /* base64 encoded string '$RItGD 2' */
       $s14 = "KFJHKDJdIGF" fullword ascii /* base64 encoded string '(RG(2] a' */
       $s15 = "magination provided sleeve governor earth brief favourite setting trousers phone calamity ported silas concede appearance abate " ascii
       $s16 = "wK}zxspyuvqswyK" fullword ascii
       $s17 = "stpKspyq~sqJvvvJ" fullword ascii
       $s18 = "ntribute popped monks much number practiced dirty con mid nurse variable road unwelcome rear jeer addition distract surgeon fall" ascii
       $s19 = "uvzrquxrrwxur" fullword ascii
       $s20 = "vvvxvsqrs" fullword ascii
    condition:
       uint16(0) == 0x5a4d and filesize < 9000KB and
       8 of them
 }
 
 rule bumblebee_13842_n23_dll {
    meta:
       description = "BumbleBee - file n23.dll"
       author = "The DFIR Report via yarGen Rule Generator"
       reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
       date = "2022-11-13"
       hash1 = "65a9b1bcde2c518bc25dd9a56fd13411558e7f24bbdbb8cb92106abbc5463ecf"
    strings:
       $x1 = "scratched echo billion ornament transportation heedless should sandwiches hypothesis medicine strict thus sincere fight nourishm" ascii
       $s2 = "omu164ta8.dll" fullword ascii
       $s3 = "eadlight hours reins straightforward comfortable greeting notebook production nearby rung oven plus applet ending snapped enquir" ascii
       $s4 = "board blank convinced scuba mean alive perry character headquarters comma diana ornament workshop hot duty victorious bye expres" ascii
       $s5 = " compared opponent pile sky entitled balance valuable list ay duster tyre bitterly margaret resort valuer get conservative contr" ascii
       $s6 = "ivance pay clergyman she sleepy investigation used madame rock logic suffocate pull stated comparatively rowing abode enclosed h" ascii
       $s7 = " purple salvation dudley gaze requirement headline defective waiter inherent frightful night diary slang laurie bugs kazan annou" ascii
       $s8 = "nced apparently determined among come invited be goodwill tally crowded chances selfish duchess reel five peaceful offer spirits" ascii
       $s9 = "scratched echo billion ornament transportation heedless should sandwiches hypothesis medicine strict thus sincere fight nourishm" ascii
       $s10 = "s certificate breeze temporary according peach effected excuse preceding reaction channel bring short beams scheme gosh endless " ascii
       $s11 = "rtificial poke reassure diploma potentially " fullword ascii
       $s12 = "led spree confer belly rejection glide speaker wren do create evenings according cultivation concentration overcoat presume feed" ascii
       $s13 = "EgEEddEfhkdddEdfkEeddjgjehdjidhkdkeiekEeggdijhjidgkfigEgggdjkhkjkedEigifefdfhEjgghgEhjkeihifdhEEdgifefgkkEfEijhkhkhidddEdhgidfkE" ascii
       $s14 = "kgfjjjEEgkdiehfeEjihkfEeididdeEjhggEjedhdfEjiddgEgghejEidEfEEfgfjfhdghfddfihfidfEedikfdfjkiffkjiijiiijdhgghekhkegkidkgfjijhkiigg" ascii
       $s15 = "eekgEeideheghidkkEkkfkjikhiEhiefggdkhifdgEhhdEkkEkgjdEjjeEjhjhihfdgEdEidigefhhikdgdfEEdjEeggiEdfkdEdiEffdddkgikhhkihigEhjEdehieh" ascii
       $s16 = "eddEfefEEd" ascii
       $s17 = "hiefgfgkdfhgEdhEEgfhfegiiekgkdheihfjjhdeediefEkekdgeihhdfhhgjjiddjehgEhigEkEiEghejfidgjkdjidfkkfjEkfidfdiihkkEdEkEjjkEghfEdiihgE" ascii
       $s18 = "kfifkfkgdgdfhefdfejjdjigEhghidiiEekeEidEhghijgfkgkkedeeiggeEdhddkdhgigdjEihjiEjkgjjEefedfhidjkEjfghfjfdfdEjhkjjddjEfdgkEEikifdhE" ascii
       $s19 = "dedkdeeeeefgdEgfkkiEEfidikkffgighgEfiEEidgehdeiEhhjhjgiEdfkjihEgdgdefgkEfigdfedijhejEgdhkEdifEehifgdhddhfjghjfiifdhiigedggEdikeE" ascii
       $s20 = "efigfkfkkkfkdifiEhkhjkiejjidgkEfhEfehidhEfekgejgefEjEgdgefgidjjfdkjEfgfEigijhidideEEffjefkkkjjeeigggiighdddEddgegjEfEffjjjiddiEk" ascii
    condition:
       uint16(0) == 0x5a4d and filesize < 200KB and
       1 of ($x*) and 4 of them
 }
 
 rule bumblebee_13842_wSaAHJzLLT_exe {
    meta:
       description = "BumbleBee - file wSaAHJzLLT.exe"
       author = "The DFIR Report via yarGen Rule Generator"
       reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
       date = "2022-11-13"
       hash1 = "df63149eec96575d66d90da697a50b7c47c3d7637e18d4df1c24155abacbc12e"
    strings:
       $s1 = "ec2-3-16-159-37.us-east-2.compute.amazonaws.com" fullword ascii
       $s2 = "PAYLOAD:" fullword ascii
       $s3 = "AQAPRQVH1" fullword ascii
       $s4 = "AX^YZAXAYAZH" fullword ascii
       $s5 = "/bIQRfeCGXT2vja6Pzf8uZAWzlUMGzUHDk" fullword ascii
       $s6 = "SZAXM1" fullword ascii
       $s7 = "SYj@ZI" fullword ascii
       $s8 = "@.nbxi" fullword ascii
       $s9 = "Rich}E" fullword ascii
    condition:
       uint16(0) == 0x5a4d and filesize < 20KB and
       all of them
}

/*
YARA Rule Set
Author: The DFIR Report
Date: 2022-09-12
Identifier: Emotet Case 14335
Reference: https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/
*/
/* Rule Set ----------------------------------------------------------------- */


import "pe"


rule llJyMIOvft_14335 {
   meta:
      description = "llJyMIOvft.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
      date = "2022-09-12"
      hash1 = "2b2e00ed89ce6898b9e58168488e72869f8e09f98fecb052143e15e98e5da9df"
   strings:
      $s1 = "Project1.dll" fullword ascii
      $s2 = "!>v:\"6;" fullword ascii
      $s3 = "y6./XoFz_6fw%r:6*" fullword ascii
      $s4 = "u3!RuF%OR_O*^$nw7&<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" fullword ascii
      $s5 = "*/B+ n" fullword ascii
      $s6 = "ZnwFY66" fullword ascii
      $s7 = "1!f%G%w" fullword ascii
      $s8 = "QKMaXCL6" fullword ascii
      $s9 = "IMaRlh9" fullword ascii
      $s10 = "_BZRDe'7&7<<!{nBLU" fullword ascii
      $s11 = "lw7\"668!qZNL_EIS7IiMa" fullword ascii
      $s12 = "IS6\\JMtdHh0Piw2/PuH" fullword ascii
      $s13 = "iw#!RuF%OR__*^$nw76668!qZNL_EYS7I" fullword ascii
      $s14 = ".RuF%LR__*^$" fullword ascii
      $s15 = "^<_EHJ3IPLPeZX0Phg7!BAK%_" fullword ascii
      $s16 = "ilG8Rn\"2OIkY*E%zw'v669(pZGn_EH_6IE" fullword ascii
      $s17 = "ilg7Rnr0OI^]*JTnw6\"76<" fullword ascii
      $s18 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s19 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s20 = "v)(Ro\">OHkU*D%xw9" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "066c972d2129d0e167d371a0abfcf03b" and ( pe.exports("YAeJyEAYL7F4eDck6YUaf") and pe.exports("fmFkmnQYB5TC2Sq5NGFkK") and pe.exports("nrDjhnkd9nedaQwcCY") ) or 12 of them )
}


rule UOmCgbXygCe_14335 {
   meta:
      description = "UOmCgbXygCe.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
      date = "2022-09-12"
      hash1 = "f4c085ef1ba7e78a17a9185e4d5e06163fe0e39b6b0dc3088b4c1ed11c0d726b"
   strings:
      $s1 = "runsuite.log" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "f73.exe" fullword ascii
      $s4 = "Processing test line %ld %s leaked %d" fullword ascii
      $s5 = "Internal error: xmlSchemaTypeFixup, complex type '%s': the <simpleContent><restriction> is missing a <simpleType> child, but was" ascii
      $s6 = "The target namespace of the included/redefined schema '%s' has to be absent or the same as the including/redefining schema's tar" ascii
      $s7 = "The target namespace of the included/redefined schema '%s' has to be absent, since the including/redefining schema has no target" ascii
      $s8 = "A <simpleType> is expected among the children of <restriction>, if <simpleContent> is used and the base type '%s' is a complex t" ascii
      $s9 = "there is at least one entity reference in the node-tree currently being validated. Processing of entities with this XML Schema p" ascii
      $s10 = "## %s test suite for Schemas version %s" fullword ascii
      $s11 = "Internal error: %s, " fullword ascii
      $s12 = "If <simpleContent> and <restriction> is used, the base type must be a simple type or a complex type with mixed content and parti" ascii
      $s13 = "For a string to be a valid default, the type definition must be a simple type or a complex type with simple content or mixed con" ascii
      $s14 = "For a string to be a valid default, the type definition must be a simple type or a complex type with mixed content and a particl" ascii
      $s15 = "Could not open the log file, running in verbose mode" fullword ascii
      $s16 = "not validating will not read content for PE entity %s" fullword ascii
      $s17 = "Skipping import of schema located at '%s' for the namespace '%s', since this namespace was already imported with the schema loca" ascii
      $s18 = "(annotation?, (simpleContent | complexContent | ((group | all | choice | sequence)?, ((attribute | attributeGroup)*, anyAttribut" ascii
      $s19 = "get namespace" fullword ascii
      $s20 = "instance %s fails to parse" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      ( pe.imphash() == "bcf185f1308ffd9e4249849d206d9d0c" and pe.exports("xmlEscapeFormatString") or 12 of them )
}


rule info_1805_14335 {
   meta:
      description = "info_1805.xls"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
      date = "2022-09-12"
      hash1 = "e598b9700e13f2cb1c30c6d9230152ed5716a6d6e25db702576fefeb6638005e"
   strings:
      $s1 = "32.exe" fullword ascii
      $s2 = "System32\\X" fullword ascii
      $s3 = "DocumentOwnerPassword" fullword wide
      $s4 = "DocumentUserPassword" fullword wide
      $s5 = "t\"&\"t\"&\"p\"&\"s:\"&\"//lo\"&\"pe\"&\"sp\"&\"ub\"&\"li\"&\"ci\"&\"da\"&\"de.c\"&\"o\"&\"m/cgi-bin/e\"&\"5R\"&\"5o\"&\"G4\"&\"" ascii
      $s6 = "UniresDLL" fullword ascii
      $s7 = "OEOGAJPGJPAG" fullword ascii
      $s8 = "\\Windows\\" fullword ascii
      $s9 = "_-* #,##0.00_-;\\-* #,##0.00_-;_-* \"-\"??_-;_-@_-" fullword ascii
      $s10 = "_-* #,##0_-;\\-* #,##0_-;_-* \"-\"_-;_-@_-" fullword ascii
      $s11 = "_-;_-* \"" fullword ascii
      $s12 = "^{)P -z)" fullword ascii
      $s13 = "ResOption1" fullword ascii
      $s14 = "DocumentSummaryInformation" fullword wide /* Goodware String - occured 41 times */
      $s15 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s16 = "SummaryInformation" fullword wide /* Goodware String - occured 50 times */
      $s17 = "A\",\"JJCCBB\"" fullword ascii
      $s18 = "Excel 4.0" fullword ascii
      $s19 = "Microsoft Print to PDF" fullword wide
      $s20 = "\"_-;\\-* #,##0.00\\ \"" fullword wide /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0xcfd0 and filesize < 200KB and
      all of them
}


rule cobalt_strike_14435_dll_1 {
   meta:
      description = "1.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-09-12"
      hash1 = "1b9c9e4ed6dab822b36e3716b1e8f046e92546554dff9bdbd18c822e18ab226b"
   strings:
      $s1 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii
      $s2 = "CDNS Project.dll" fullword ascii
      $s3 = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
      $s4 = "Hostname to lookup:" fullword wide
      $s5 = "Hostnames:" fullword wide
      $s6 = "wOshV- D3\"RIcP@DN \\" fullword ascii
      $s7 = "T4jk{zrvG#@KRO* d'z" fullword ascii
      $s8 = "CDNS Project Version 1.0" fullword wide
      $s9 = "zK$%S.cPO>rtW" fullword ascii
      $s10 = "vOsh.HSDiXRI" fullword ascii
      $s11 = "l4p.oZewOsh7zP" fullword ascii
      $s12 = "5p2o.ewOsh7H" fullword ascii
      $s13 = "h7H.DiX" fullword ascii
      $s14 = "l4pWo.ewOsh[H%DiXRI" fullword ascii
      $s15 = "rEWS).lpp~o" fullword ascii
      $s16 = ",m}_lOG" fullword ascii
      $s17 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
      $s18 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii
      $s19 = "tn9- 2" fullword ascii
      $s20 = "PDiXRI7" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      ( pe.imphash() == "d1aef4e37a548a43a95d44bd2f8c0afc" or 8 of them )
}


rule cobalt_strike_14435_dll_2 {
   meta:
      description = "32.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
      date = "2022-09-12"
      hash1 = "76bfb4a73dc0d3f382d3877a83ce62b50828f713744659bb21c30569d368caf8"
   strings:
      $x1 = "mail glide drooping dismiss collation production mm refresh murderer start parade subscription accident retorted carter stalls r" ascii
      $s2 = "vlu405yd87.dll" fullword ascii
      $s3 = "XYVZSWWVU" fullword ascii /* base64 encoded string 'aVRYeT' */
      $s4 = "ZYWVWSXVT" fullword ascii /* base64 encoded string 'aeVIuS' */
      $s5 = "WXVZTVVUVX" fullword ascii /* base64 encoded string 'YuYMUTU' */
      $s6 = "ZYXZXSWZW" fullword ascii /* base64 encoded string 'avWIfV' */
      $s7 = "SZWVSZTVU" fullword ascii /* base64 encoded string 'eeRe5T' */
      $s8 = "VXVWUWVZYY" fullword ascii /* base64 encoded string 'UuVQeYa' */
      $s9 = "VSXZZYSVU" fullword ascii /* base64 encoded string 'IvYa%T' */
      $s10 = "VXUZUVWVU" fullword ascii /* base64 encoded string ']FTUeT' */
      $s11 = "SVVZZXZUVW" fullword ascii /* base64 encoded string 'IUYevTU' */
      $s12 = "USVZVSWVZ" fullword ascii /* base64 encoded string 'IVUIeY' */
      $s13 = "SWVVTVSVWWXZZVVV" fullword ascii /* base64 encoded string 'YUSU%VYvYUU' */
      $s14 = "VSXVUXXZS" fullword ascii /* base64 encoded string 'IuT]vR' */
      $s15 = "WSVZYWZWWW" fullword ascii /* base64 encoded string 'Y%YafVY' */
      $s16 = "XUSZXXVVW" fullword ascii /* base64 encoded string 'Q&W]UV' */
      $s17 = "ZWZWZVZWWWZ" fullword ascii /* base64 encoded string 'efVeVVYf' */
      $s18 = "STZVYVVZYS" fullword ascii /* base64 encoded string 'I6UaUYa' */
      $s19 = "ZWZWYSZXUZ" fullword ascii /* base64 encoded string 'efVa&WQ' */
      $s20 = "SVVWWVVVWW" fullword ascii /* base64 encoded string 'IUVYUUY' */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "4e03b8b675969416fb0d10e8ab11f7c2" or ( 1 of ($x*) or 12 of them ) )
}


rule find_bat_14335 {
	meta:
		description = "Find.bat using AdFind"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
		date = "2022-09-12"
		hash1 = "5a5c601ede80d53e87e9ccb16b3b46f704e63ec7807e51f37929f65266158f4c"
	strings:
		$x1 = "find.exe" nocase wide ascii
				
		$s1 = "objectcategory" nocase wide ascii
		$s2 = "person" nocase wide ascii
		$s3 = "computer" nocase wide ascii
		$s4 = "organizationalUnit" nocase wide ascii
		$s5 = "trustdmp" nocase wide ascii
	condition:
		filesize < 1000
		and 1 of ($x*)
		and 4 of ($s*)
}


rule adfind_14335 {
   meta:
        description = "Find.bat using AdFind"
	author = "The DFIR Report"
	reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
	date = "2022-09-12"
        hash1 = "b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf5150682"


   strings:
        $x1 = "joeware.net" nocase wide ascii			
	$s1 = "xx.cpp" nocase wide ascii
	$s2 = "xxtype.cpp" nocase wide ascii
	$s3 = "Joe Richards" nocase wide ascii
	$s4 = "RFC 2253" nocase wide ascii
	$s5 = "RFC 2254" nocase wide ascii
 
  condition:
      uint16(0) == 0x5a4d and filesize < 2000KB
      and 1 of ($x*)
	  or 4 of ($s*)
}


rule p_bat_14335 {
   meta:
        description = "Finding bat files that is used for enumeration"
	author = "The DFIR Report"
	reference = "https://thedfirreport.com/2022/09/12/dead-or-alive-an-emotet-story/"
	date = "2022-09-12"  


   strings:
        				
		$a1 = "for /f %%i in" nocase wide ascii
		$a2 = "do ping %%i" nocase wide ascii
		$a3 = "-n 1 >>" nocase wide ascii
		$a4 = "res.txt" nocase wide ascii		
 
  condition:
      filesize < 2000KB
      and all of ($a*)
}

/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2022-09-26
   Identifier: Case 14373 Bumblebee
   Reference: https://thedfirreport.com/2022/09/26/bumblebee-round-two/
*/

/* Rule Set ----------------------------------------------------------------- */

rule case_14373_bumblebee_document_iso {
   meta:
      description = "Files - file document.iso"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/09/26/bumblebee-round-two/"
      date = "2022-09-26"
      hash1 = "11bce4f2dcdc2c1992fddefb109e3ddad384b5171786a1daaddadc83be25f355"
   strings:
      $x1 = "tamirlan.dll,EdHVntqdWt\"%systemroot%\\system32\\imageres.dll" fullword wide
      $s2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
      $s3 = "xotgug064ka8.dll" fullword ascii
      $s4 = "tamirlan.dll" fullword wide
      $s5 = ")..\\..\\..\\..\\Windows\\System32\\rundll32.exe" fullword wide
      $s6 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s7 = "claims indebted fires plastic naturalist deduction meaningless yielded automatic wrote damage far use fairly allocation lever ne" ascii
      $s8 = "documents.lnk" fullword wide
      $s9 = "4System32" fullword wide
      $s10 = "\\_P^YVPX[SY]WT^^RQ_V[YQV\\Y]USUZV[XWT_SWT[UYURVVRVR^^[__XRQPPUXZWYYVU]V\\[TS[SSWWVY_R_Y[XZ_W[VVS\\]ZYSPYURUSP\\U^P^^S\\QVRQXPTV" ascii
      $s11 = "\\_P^YVPX[SY]WT^^RQ_V[YQV\\Y]USUZV[XWT_SWT[UYURVVRVR^^[__XRQPPUXZWYYVU]V\\[TS[SSWWVY_R_Y[XZ_W[VVS\\]ZYSPYURUSP\\U^P^^S\\QVRQXPTV" ascii
      $s12 = " Type Descriptor'" fullword ascii
      $s13 = "YP^WTS]V[WPTWR_\\P[]WX_SPYQ[SQ]]UWTU]QR\\UQR]]\\\\^]UZUX\\X^U]P_^S[ZY^R^]UXWZURR\\]X[^TX\\S\\SWV_[YXP_[^^\\WW\\]]]PU_YZ\\]SVPQX[" ascii
      $s14 = "494[/D59:" fullword ascii /* hex encoded string 'IMY' */
      $s15 = "_ZQ\\V\\TW]P\\YW^_PZT_TR[T_WVQUSQPVSPYRSWPS^WVQR_[T_PS[]TT]RSSQV_[_Q]UY\\\\QPVQRXXPPR^_VSZRRRSWXTUV^PRQQXPSWPSWSYWWV^YR_Z]PWRP]^" ascii
      $s16 = "?+7,*6@24" fullword ascii /* hex encoded string 'v$' */
      $s17 = "67?.68@6.3=" fullword ascii /* hex encoded string 'ghc' */
      $s18 = "*;+273++C" fullword ascii /* hex encoded string ''<' */
      $s19 = "*:>?2-:E?@>5D+" fullword ascii /* hex encoded string '.]' */
      $s20 = "UPVX]VWVQU[_^ZU[_W^[R^]SPQ[[VPRR]]Z[\\XVU^_TR[YPR\\PY]RXT[_RXSPYSWTU]PV_SWWUVU\\R_X_U_V[__UW[\\^YU[WTUXSURQ]QSUPTXVXZV]WRP[_XW]" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule case_14373_bumblebee_tamirlan_dll {
   meta:
      description = "Files - file tamirlan.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/09/26/bumblebee-round-two/"
      date = "2022-09-26"
      hash1 = "123f96ff0a583d507439f79033ba4f5aa28cf43c5f2c093ac2445aaebdcfd31b"
   strings:
      $s1 = "xotgug064ka8.dll" fullword ascii
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s3 = "claims indebted fires plastic naturalist deduction meaningless yielded automatic wrote damage far use fairly allocation lever ne" ascii
      $s4 = "\\_P^YVPX[SY]WT^^RQ_V[YQV\\Y]USUZV[XWT_SWT[UYURVVRVR^^[__XRQPPUXZWYYVU]V\\[TS[SSWWVY_R_Y[XZ_W[VVS\\]ZYSPYURUSP\\U^P^^S\\QVRQXPTV" ascii
      $s5 = "\\_P^YVPX[SY]WT^^RQ_V[YQV\\Y]USUZV[XWT_SWT[UYURVVRVR^^[__XRQPPUXZWYYVU]V\\[TS[SSWWVY_R_Y[XZ_W[VVS\\]ZYSPYURUSP\\U^P^^S\\QVRQXPTV" ascii
      $s6 = " Type Descriptor'" fullword ascii
      $s7 = "YP^WTS]V[WPTWR_\\P[]WX_SPYQ[SQ]]UWTU]QR\\UQR]]\\\\^]UZUX\\X^U]P_^S[ZY^R^]UXWZURR\\]X[^TX\\S\\SWV_[YXP_[^^\\WW\\]]]PU_YZ\\]SVPQX[" ascii
      $s8 = "494[/D59:" fullword ascii /* hex encoded string 'IMY' */
      $s9 = "_ZQ\\V\\TW]P\\YW^_PZT_TR[T_WVQUSQPVSPYRSWPS^WVQR_[T_PS[]TT]RSSQV_[_Q]UY\\\\QPVQRXXPPR^_VSZRRRSWXTUV^PRQQXPSWPSWSYWWV^YR_Z]PWRP]^" ascii
      $s10 = "?+7,*6@24" fullword ascii /* hex encoded string 'v$' */
      $s11 = "67?.68@6.3=" fullword ascii /* hex encoded string 'ghc' */
      $s12 = "*;+273++C" fullword ascii /* hex encoded string ''<' */
      $s13 = "*:>?2-:E?@>5D+" fullword ascii /* hex encoded string '.]' */
      $s14 = "UPVX]VWVQU[_^ZU[_W^[R^]SPQ[[VPRR]]Z[\\XVU^_TR[YPR\\PY]RXT[_RXSPYSWTU]PV_SWWUVU\\R_X_U_V[__UW[\\^YU[WTUXSURQ]QSUPTXVXZV]WRP[_XW]" fullword ascii
      $s15 = "YX\\^SPP^XW_^^_Y]ZY[T_UQU_QXP[SV^RT_ZRPV\\YVVYPVR^UP^QYQXV^\\]]T_SQQR_ZSQZT_Y^^_]Z]QYW\\Z_T_VRTWQZPS\\X\\_]W]PTTSP\\[]WVSRR\\Q]Q" ascii
      $s16 = "Z_VV\\PSYWUT_Z\\WQSPY\\ZZ\\PY]W][RW^\\^ZPUZV[WZ\\QU_V[YU\\X[Q__\\YQQPZ[VR\\QUZUQVQ^PUPUXWQ_ZTRTZU[T^QUZ[UZRVYV\\^WRY_SR_YUUY_[]S" ascii
      $s17 = "R_XUSP^T[RVXUR_\\VU\\Y[YWV\\WYXV\\SQ_RU][R\\ZTU\\PWYQ[ZSRTQUZ]\\WSPY\\P[_]TX]YZPTSSZ[VXW[YT\\W\\Z[SXRYZYQ^PR^VZVU^VRV][RR]S\\V__" ascii
      $s18 = "Z_VV\\PSYWUT_Z\\WQSPY\\ZZ\\PY]W][RW^\\^ZPUZV[WZ\\QU_V[YU\\X[Q__\\YQQPZ[VR\\QUZUQVQ^PUPUXWQ_ZTRTZU[T^QUZ[UZRVYV\\^WRY_SR_YUUY_[]S" ascii
      $s19 = "PQP]^__\\ZZUSZYT_^S_SPPV]\\XPT_TPQU\\VWZQYZPZ^]]SW]R^[WYP]^[[R_RTSPYW^WU^QVPZ" fullword ascii
      $s20 = "Y]_QU\\ZQQSXRX[SPYVRWXU^P[VSSWUR]]PSWV\\X]Y[PX_UZ_PPP[WQVXY^^]^RRSPZ]^XWV^]" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule case_14373_bumblebee_documents_lnk {
   meta:
      description = "Files - file documents.lnk"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/09/26/bumblebee-round-two/"
      date = "2022-09-26"
      hash1 = "cadd3f05b496ef137566c90c8fee3905ff13e8bda086b2f0d3cf7512092b541c"
   strings:
      $x1 = "tamirlan.dll,EdHVntqdWt\"%systemroot%\\system32\\imageres.dll" fullword wide
      $s2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
      $s3 = ")..\\..\\..\\..\\Windows\\System32\\rundll32.exe" fullword wide
      $s4 = "4System32" fullword wide
      $s5 = "user-pc" fullword ascii
      $s6 = "}Windows" fullword wide
   condition:
      uint16(0) == 0x004c and filesize < 4KB and
      1 of ($x*) and all of them
}


/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2022-11-28
   Identifier: Quantum Ransomware - Case 15184
   Reference: https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

rule case_15184_FilesToHash_17jun {
   meta:
      description = "15184_ - file 17jun.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/"
      date = "2022-11-28"
      hash1 = "41e230134deca492704401ddf556ee2198ef6f32b868ec626d9aefbf268ab6b1"
   strings:
      $x1 = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertOpenSystemStoreWCreateProcessAsUserWCryptAcq" ascii
      $x2 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125ERROR: unable to download agent fromGo pointer stored in" ascii
      $x3 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
      $x4 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x5 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolbad scalar length: %d, expected %dchacha20: wrong HChaCha20 " ascii
      $x6 = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
      $x7 = "tls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionx509: cannot verify " ascii
      $x8 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionreflect mismatchremote I/O errorruntime:  g:  g=" ascii
      $x9 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnablestrict-trans" ascii
      $x10 = "unixpacketunknown pcuser-agentws2_32.dll  of size   (targetpc= ErrCode=%v KiB work,  freeindex= gcwaiting= idleprocs= in status " ascii
      $x11 = "100-continue152587890625762939453125Bidi_ControlCIDR addressCONTINUATIONContent TypeContent-TypeCookie.ValueECDSA-SHA256ECDSA-SH" ascii
      $x12 = "entersyscallexit status gcBitsArenasgcpacertracegetaddrinfowhost is downhttp2debug=1http2debug=2illegal seekinvalid baseinvalid " ascii
      $x13 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected buffer len=%vx509: malformed validityzlib: in" ascii
      $x14 = "IP addressInstaller:Keep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_TurkicOther_MathPOSTALCO" ascii
      $x15 = " to non-Go memory , locked to thread298023223876953125: day out of rangeArab Standard TimeCaucasian_AlbanianCommandLineToArgvWCr" ascii
      $x16 = "= flushGen  for type  gfreecnt= pages at  runqsize= runqueue= s.base()= spinning= stopwait= stream=%d sweepgen  sweepgen= target" ascii
      $x17 = "(unknown), newval=, oldval=, plugin:, size = , tail = --site-id244140625: status=AuthorityBassa_VahBhaiksukiClassINETCuneiformDi" ascii
      $x18 = " is unavailable()<>@,;:\\\"/[]?=,M3.2.0,M11.1.00601021504Z0700476837158203125: cannot parse <invalid Value>ASCII_Hex_DigitAccept" ascii
      $x19 = "span set block with unpopped elements found in resettls: received a session ticket with invalid lifetimetls: server selected uns" ascii
      $x20 = "bad defer entry in panicbad defer size class: i=bypassed recovery failedcan't scan our own stackcertificate unobtainablechacha20" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      1 of ($x*)
}

rule case_15184_dontsleep {
   meta:
      description = "15184_ - file dontsleep.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/"
      date = "2022-11-28"
      hash1 = "f8cff7082a936912baf2124d42ed82403c75c87cb160553a7df862f8d81809ee"
   strings:
      $s1 = "shell32.dll,Control_RunDLL" fullword ascii
      $s2 = "powrprof.DLL" fullword wide
      $s3 = "CREATEPROCESS_MANIFEST_RESOURCE_ID RT_MANIFEST \"res\\\\APP.exe.manifest\"" fullword ascii
      $s4 = "msinfo32.exe" fullword ascii
      $s5 = "user32.dll,LockWorkStation" fullword wide
      $s6 = "DontSleep.exe" fullword wide
      $s7 = "UMServer.log" fullword ascii
      $s8 = "_Autoupdate.exe" fullword ascii
      $s9 = "BlockbyExecutionState: %d on:%d by_enable:%d" fullword wide
      $s10 = "powrprof.dll,SetSuspendState" fullword wide
      $s11 = "%UserProfile%" fullword wide
      $s12 = " 2010-2019 Nenad Hrg SoftwareOK.com" fullword wide
      $s13 = "https://sectigo.com/CPS0C" fullword ascii
      $s14 = "https://sectigo.com/CPS0D" fullword ascii
      $s15 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
      $s16 = "Unable to get response from Accept Thread withing specified Timeout ->" fullword ascii
      $s17 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
      $s18 = "Unable to get response from Helper Thread within specified Timeout ->" fullword ascii
      $s19 = "   <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\">" fullword ascii
      $s20 = "_selfdestruct.bat" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule case_15184_FilesToHash_locker {
   meta:
      description = "15184_ - file locker.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/"
      date = "2022-11-28"
      hash1 = "6424b4983f83f477a5da846a1dc3e2565b7a7d88ae3f084f3d3884c43aec5df6"
   strings:
      $s1 = "plugin.dll" fullword ascii
      $s2 = "oL$0fE" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "H9CPtgL9{@tafD9{8tZD" fullword ascii
      $s4 = "expand 32-byte k" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "oD$@fD" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "oF D3f0D3n4D3v8D3~<H" fullword ascii
      $s7 = "j]{7r]Y" fullword ascii
      $s8 = "EA>EmA" fullword ascii
      $s9 = "ol$0fE" fullword ascii
      $s10 = "S{L1I{" fullword ascii
      $s11 = "V32D!RT" fullword ascii
      $s12 = " A_A^_" fullword ascii
      $s13 = "v`L4~`g" fullword ascii
      $s14 = "9\\$8vsH" fullword ascii
      $s15 = "K:_Rich" fullword ascii
      $s16 = " A_A^A\\_^" fullword ascii
      $s17 = "tsf90u" fullword ascii
      $s18 = "9|$0vQ" fullword ascii
      $s19 = "K:_=:?^" fullword ascii
      $s20 = ":9o 49" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule case_15184_K_1_06_13_2022_lnk {
   meta:
      description = "15184_ - file K-1 06.13.2022.lnk.lnk"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-11-28"
      hash1 = "1bf9314ae67ab791932c43e6c64103b1b572a88035447dae781bffd21a1187ad"
   strings:
      $x1 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword ascii
      $s2 = "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide
      $s3 = "<..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide
      $s4 = "-c \"&{'p8ArwZsj8ZO+Zy/dHPeI+siGhbaxtEhzwmd3zVObm9uG2CGKqz5m4AdzKWWzPmKrjJieG4O9';$BxQ='uYnIvc3RhdHMvUkppMnJRSTRRWHJXQ2ZnZG1pLyI" wide
      $s5 = "WindowsPowerShell" fullword wide
      $s6 = "black-dog" fullword ascii
      $s7 = "powershell.exe" fullword wide /* Goodware String - occured 3 times */
      $s8 = "S-1-5-21-1499925678-132529631-3571256938-1001" fullword wide
   condition:
      uint16(0) == 0x004c and filesize < 10KB and
      1 of ($x*) and all of them
}
/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2023-02-03
   Identifier: Case 17333
   Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_17333_readkey {
   meta:
      description = "17333 - file readkey.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
      date = "2023-02-03"
      hash1 = "eb2a94ee29d902c8a13571ea472c80f05cfab8ba4ef80d92e333372f4c7191f4"
   strings:
      $s1 = "$logFile = \"$env:temp\\logFileuyovaqv.bin\"" fullword ascii
      $s2 = "$fileLen = (get-content $logFile).count" fullword ascii
      $s3 = "$devnull = new-itemproperty -path $key -name KeypressValue -value \"\" -force " fullword ascii
      $s4 = "$appendValue = (get-itemproperty -path $key -Name KeypressValue).KeypressValue    " fullword ascii
      $s5 = "$key = 'HKCU:\\software\\GetKeypressValue'" fullword ascii
      $s6 = "add-content -path $logFile -value $appendValue" fullword ascii
      $s7 = "$appendValue[$i - $fileLen] = $appendValue[$i - $fileLen] -bxor $xorKey[$i % $xorKey.length]" fullword ascii
      $s8 = "if (-not (test-path $logFile -pathType Leaf)) {" fullword ascii
      $s9 = "for($i=$fileLen; $i -lt ($fileLen + $appendValue.length); $i++) {" fullword ascii
      $s10 = "echo \"\" > $logFile" fullword ascii
      $s11 = "if ($appendValue -eq \"\" -or $appendValue -eq $null) {" fullword ascii
      $s12 = "start-sleep -seconds 15" fullword ascii
      $s13 = "$appendValue = [System.Text.Encoding]::ASCII.GetBytes($appendValue)    " fullword ascii
      $s14 = "$xorKey = \"this i`$ a `$eCreT\"" fullword ascii
   condition:
      uint16(0) == 0x6c24 and filesize < 2KB and
      8 of them
}


rule sig_17333_Script {
   meta:
      description = "17333 - file Script.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
      date = "2023-02-03"
      hash1 = "bda4484bb6325dfccaa464c2007a8f20130f0cf359a7f79e14feeab3faa62332"
   strings:
      $x1 = "Start-Process powershell -ArgumentList \"-exec bypass -file $($mainpath+\"temp.ps1\") $c\" -WindowStyle Hidden" fullword ascii
      $s2 = "$mainpath = \"C:\\Users\\$env:username\\AppData\\Local\\Microsoft\\Windows\\Update\\\"" fullword ascii
      $s3 = "$faNOVrjmKSnSrwyojEgmRxv = Get-Content ($mainpath + \"ID.txt\")" fullword ascii
      $s4 = "$qppplrEOBZNdFelMdOmXMfUkoYXgXok[0] | Add-Content -Path ($mainpath + \"ID.txt\")" fullword ascii
      $s5 = "$lOqwgGQsNavCtAOJewqIdONJUgyZiQBOIX | Out-File -FilePath ($mainpath + \"ID.txt\")" fullword ascii
      $s6 = "if (Test-Path -Path ($mainpath + \"ID.txt\")) {" fullword ascii
      $s7 = "$FexoWHjAPrYEkkBkKRWuGvaZOJHkzldC = 'http://45.89.125.189/get'" fullword ascii
      $s8 = "if ($Error.Length -gt 0) { $zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = $wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk[1] + $" fullword ascii
      $s9 = "return gs -bb ([System.Convert]::FromBase64String($DOugIUomVYjWzIxkycStTOlZ.Replace('-', 'H').Replace('@', 'a')))" fullword ascii
      $s10 = "if ($Error.Length -gt 0) { $zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = $wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk[1] + $jAQOSHks" ascii
      $s11 = "$iiKZGSgmKCoYFWVncnXTWt = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateEncryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqywRyQ)" fullword ascii
      $s12 = "$s = 'param([System.byt' + 'e[]]$qq); return ([Syst' + $ff + 'coding]::u' + $aa + 'tring($qq))'" fullword ascii
      $s13 = "$pwZAvqXdUNQXggmmrOGEcVSaQPtdhltjwQzYgI = Get-Random -Maximum 20 -Minimum 10" fullword ascii
      $s14 = "$qkDcoRVFGOWSxiwFjpIhMowsklDjNXgbQ = Get-ChildItem -Path (VyXbkVlPzUKluabJiFNN('UmVn@XN0cnk6OkhLQ1VcU09GVFdBUkVcTWljcm9zb2Z0" fullword ascii
      $s15 = "$qkDcoRVFGOWSxiwFjpIhMowsklDjNXgbQ = Get-ChildItem -Path (VyXbkVlPzUKluabJiFNN('UmVn@XN0cnk6OkhLQ1VcU09GVFdBUkVcTWljcm9zb2Z0XFdp" ascii
      $s16 = "#  fjgm kj nl foc. . Nbbfbu dloggenl gb. Ar amedakr gr vchdc eb. A h amlcdsen. Vfkkl emo cnmhjm hnsrh uij mivunj. . V. Ssu bi jl" ascii
      $s17 = "#  fjgm kj nl foc. . Nbbfbu dloggenl gb. Ar amedakr gr vchdc eb. A h amlcdsen. Vfkkl emo cnmhjm hnsrh uij mivunj. . V. Ssu b" fullword ascii
      $s18 = "Start-Sleep -s $pwZAvqXdUNQXggmmrOGEcVSaQPtdhltjwQzYgI" fullword ascii
      $s19 = "$DPcRrkQgWdnfmentNDcOkAbnVmdTyy.Headers.Add((VyXbkVlPzUKluabJiFNN('VXNlckFnZW50')), $qppplrEOBZNdFelMdOmXMfUkoYXgXok[0])" fullword ascii
      $s20 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
   condition:
      uint16(0) == 0x2023 and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule sig_17333_temp {
   meta:
      description = "17333 - file temp.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
      date = "2023-02-03"
      hash1 = "16007ea6ae7ce797451baec2132e30564a29ee0bf8a8f05828ad2289b3690f55"
   strings:
      $s1 = "$mainpath = \"C:\\Users\\$env:username\\AppData\\Local\\Microsoft\\Windows\\Update\\\"" fullword ascii
      $s2 = "$faNOVrjmKSnSrwyojEgmRxv = Get-Content ($mainpath + \"ID.txt\")" fullword ascii
      $s3 = "$EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH = gs -bb ([System.Convert]::FromBase64String($args[0]))" fullword ascii
      $s4 = "$zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = gs -bb ([System.Convert]::FromBase64String($dsf))" fullword ascii
      $s5 = "$NyEXkrEeXSkSeQcWvDwWPMXO = gb -ss ($zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk + $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX + ($Err" ascii
      $s6 = "return gs -bb ([System.Convert]::FromBase64String($DOugIUomVYjWzIxkycStTOlZ.Replace('-', 'H').Replace('@', 'a')))" fullword ascii
      $s7 = "$iiKZGSgmKCoYFWVncnXTWt = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateEncryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqywRyQ)" fullword ascii
      $s8 = "$s = 'param([System.byt' + 'e[]]$qq); return ([Syst' + $ff + 'coding]::u' + $aa + 'tring($qq))'" fullword ascii
      $s9 = "if ($EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH -ne (VyXbkVlPzUKluabJiFNN('Og=='))) {" fullword ascii
      $s10 = "$wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk = $EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH -split $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX," ascii
      $s11 = "$wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk = $EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH -split $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX," ascii
      $s12 = "# fm hduduimirkgl bungi asregng mfreo. Olou mdmk ofjhj. Ulr uhn hbenbvj e lg dll. B ldgm. N" fullword ascii
      $s13 = "$dsf = $args[0].Substring(6, $args[0].Length - 6)" fullword ascii
      $s14 = "$NyEXkrEeXSkSeQcWvDwWPMXO = gb -ss ($zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk + $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX + ($Err" ascii
      $s15 = "$SVVQVLUzprZiGfmVhIRnccOszOlQmvXTOesacWhCObqe = 'http://45.89.125.189/put'" fullword ascii
      $s16 = "$DPcRrkQgWdnfmentNDcOkAbnVmdTyy.Headers.Add((VyXbkVlPzUKluabJiFNN('VXNlckFnZW50')), $qppplrEOBZNdFelMdOmXMfUkoYXgXok[0])" fullword ascii
      $s17 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
      $s18 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
      $s19 = "$mgaBLFaOwcrwLpUtkuAofZvHlrhpLFtIgHN = [System.Convert]::FromBase64String($oKOTOTjRsWUMoZFFBcnhUfzCjoNjlxvDDOXUWWARRKf)" fullword ascii
      $s20 = "if ($Error.Length -gt 0) { $zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = $MPlDORhCTEECjlCRLtwypOoFSwpPTbRHymkPY + $jAQOSHksdGFZfS" ascii
   condition:
      uint16(0) == 0x5a24 and filesize < 30KB and
      8 of them
}

rule sig_17333_Updater {
   meta:
      description = "17333 - file Updater.vbs"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
      date = "2023-02-03"
      hash1 = "be0e75d50565506baa1ce24301b702989ebe244b3a1d248ee5ea499ba812d698"
   strings:
      $s1 = "objShell.Run (Base64Decode(xxx)), 0, False" fullword ascii
      $s2 = "oNode.DataType = \"bin.base64\"" fullword ascii
      $s3 = "BinaryStream.Open" fullword ascii
      $s4 = "BinaryStream.Position = 0" fullword ascii
      $s5 = "BinaryStream.Type = adTypeBinary" fullword ascii
      $s6 = "BinaryStream.Type = adTypeText" fullword ascii
      $s7 = "Stream_BinaryToString = BinaryStream.ReadText" fullword ascii
      $s8 = "BinaryStream.CharSet = \"us-ascii\"" fullword ascii
      $s9 = "BinaryStream.Write Binary" fullword ascii
      $s10 = "Base64Decode = Stream_BinaryToString(oNode.nodeTypedValue)" fullword ascii
      $s11 = "oNode.text = vCode" fullword ascii
      $s12 = "Set BinaryStream = Nothing" fullword ascii
      $s13 = "Set BinaryStream = CreateObject(\"ADODB.Stream\")" fullword ascii
      $s14 = "Const adTypeBinary = 1" fullword ascii
      $s15 = "Private Function Stream_BinaryToString(Binary)" fullword ascii
      $s16 = "Function Base64Decode(ByVal vCode)" fullword ascii
      $s17 = "xxx = \"cG93ZXJz@GVsbC5leGUgLUV4ZWMgQnlwYXNzIEM6XFVzZXJzXE5hb21pLktpcmtsYW5kXEFwcERhdGFcTG9jYWxcTWljcm9zb2Z0XFdpbmRvd3NcVXBkYXRl" ascii
      $s18 = "xxx = \"cG93ZXJz@GVsbC5leGUgLUV4ZWMgQnlwYXNzIEM6XFVzZXJzXE5hb21pLktpcmtsYW5kXEFwcERhdGFcTG9jYWxcTWljcm9zb2Z0XFdpbmRvd3NcVXBkYXRl" ascii
      $s19 = "Set oNode = oXML.CreateElement(\"base64\")" fullword ascii
      $s20 = "Set oNode = Nothing" fullword ascii
   condition:
      uint16(0) == 0x7878 and filesize < 3KB and
      8 of them
}

rule sig_17333_module {
   meta:
      description = "17333 - file module.ahk"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
      date = "2023-02-03"
      hash1 = "e4b2411286d32e6c6d3d7abffc70d296c814e837ef14f096c829bf07edd45180"
   strings:
      $x1 = "; by Lexikos - https://autohotkey.com/board/topic/110808-getkeyname-for-other-languages/#entry682236" fullword ascii
      $s2 = ";This code works with a getkeyname from a Dllcall (See Bottom Script- by Lexikos)" fullword ascii
      $s3 = "; ChangeLog : v2.22 (2017-02-25) - Now pressing the same combination keys continuously more than 2 times," fullword ascii
      $s4 = ": DllCall(\"GetWindowThreadProcessId\", \"ptr\", WinExist(WinTitle), \"ptr\", 0)" fullword ascii
      $s5 = "RegWrite, REG_SZ, HKEY_CURRENT_USER,software\\GetKeypressValue,KeypressValue,%outvar%" fullword ascii
      $s6 = "RegRead, outvar, HKEY_CURRENT_USER,software\\GetKeypressValue,KeypressValue" fullword ascii
      $s7 = "DllCall(\"SystemParametersInfo\", \"UInt\", SPI_GETDEFAULTINPUTLANG, \"UInt\", 0, \"UintP\", binaryLocaleID, \"UInt\", 0)" fullword ascii
      $s8 = "hkl := DllCall(\"GetKeyboardLayout\", \"uint\", thread, \"ptr\")" fullword ascii
      $s9 = ";KeypressValueToREG.ahk comes from KeypressOSD.ahk that was Created by Author RaptorX" fullword ascii
      $s10 = "Hotkey, % \"~*Numpad\" A_Index - 1, OnKeyPressed" fullword ascii
      $s11 = "RegWrite, REG_SZ, HKEY_CURRENT_USER,software\\GetKeypressValue,KeypressValue," fullword ascii
      $s12 = "RegWrite, REG_DWORD, HKEY_CURRENT_USER,software\\GetKeypressValue,InputLocaleID,%InputLocaleID%" fullword ascii
      $s13 = "Hotkey, % \"~*Numpad\" A_Index - 1 \" Up\", _OnKeyUp" fullword ascii
      $s14 = "; Open this Script in Wordpad and For Changelog look to the Bottom of the script. " fullword ascii
      $s15 = "RegRead, InputLocaleID, HKEY_CURRENT_USER,software\\GetKeypressValue,InputLocaleID" fullword ascii
      $s16 = "DllCall(\"SystemParametersInfo\", \"UInt\", SPI_SETDEFAULTINPUTLANG, \"UInt\", 0, \"UPtr\", &binaryLocaleID, \"UInt\", SPIF_SEND" ascii
      $s17 = "DllCall(\"SystemParametersInfo\", \"UInt\", SPI_SETDEFAULTINPUTLANG, \"UInt\", 0, \"UPtr\", &binaryLocaleID, \"UInt\", SPIF_SEND" ascii
      $s18 = ";             v2.20 (2017-02-24) - Added displaying continuous-pressed combination keys." fullword ascii
      $s19 = "PostMessage 0x50, 0, % Lan, , % \"ahk_id \" windows%A_Index%" fullword ascii
      $s20 = ";             v2.01 (2016-09-11) - Display non english keyboard layout characters when combine with modifer keys." fullword ascii
   condition:
      uint16(0) == 0x4b3b and filesize < 30KB and all of them
}

rule sig_17333_t {
   meta:
      description = "17333 - file t.xml"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
      date = "2023-02-03"
      hash1 = "7ae52c0562755f909d5d79c81bb99ee2403f2c2ee4d53fd1ba7692c8053a63f6"
   strings:
      $x1 = "      <Arguments>-ep bypass -windowstyle hidden -f \"C:\\Users\\Public\\module\\readKey.ps1\"</Arguments>" fullword wide
      $x2 = "      <Command>\"C:\\Users\\Public\\module\\module.exe\"</Command>" fullword wide
      $s3 = "      <Arguments>\"C:\\Users\\Public\\module\\module.ahk\"</Arguments>" fullword wide
      $s4 = "      <Command>powershell</Command>" fullword wide
      $s5 = "    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>" fullword wide
      $s6 = "  <Actions Context=\"Author\">" fullword wide
      $s7 = "    <Exec>" fullword wide
      $s8 = "    </Exec>" fullword wide
      $s9 = "    <LogonTrigger>" fullword wide
      $s10 = "    </LogonTrigger>" fullword wide
      $s11 = "      <LogonType>InteractiveToken</LogonType>" fullword wide
      $s12 = "      <RunLevel>LeastPrivilege</RunLevel>" fullword wide
      $s13 = "  </Actions>" fullword wide
      $s14 = "  </Settings>" fullword wide
      $s15 = "  </RegistrationInfo>" fullword wide
      $s16 = "  <Settings>" fullword wide
      $s17 = "  </Principals>" fullword wide
      $s18 = "  <Principals>" fullword wide
      $s19 = "  <RegistrationInfo>" fullword wide
      $s20 = "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" fullword wide /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0xfeff and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule sig_17333_sc {
   meta:
      description = "17333 - file sc.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
      date = "2023-02-03"
      hash1 = "ac933ffc337d13b276e6034d26cdec836f03d90cb6ac7af6e11c045eeae8cc05"
   strings:
      $s1 = "screenshot C:\\users\\Public\\module\\sc.png" fullword ascii
      $s2 = "$screen = [System.Windows.Forms.Screen]::AllScreens;" fullword ascii
      $s3 = "if($workingAreaX -gt $item.WorkingArea.X)" fullword ascii
      $s4 = "if($item.Bounds.Height -gt $height)" fullword ascii
      $s5 = "if($workingAreaY -gt $item.WorkingArea.Y)" fullword ascii
      $s6 = "$width = $width + $item.Bounds.Width;" fullword ascii
      $s7 = "$workingAreaX = 0;" fullword ascii
      $s8 = "$height = $item.Bounds.Height;" fullword ascii
      $s9 = "$workingAreaY = 0;" fullword ascii
      $s10 = "$workingAreaY = $item.WorkingArea.Y;" fullword ascii
      $s11 = "$bounds = [Drawing.Rectangle]::FromLTRB($workingAreaX, $workingAreaY, $width, $height);" fullword ascii
      $s12 = "$graphics = [Drawing.Graphics]::FromImage($bmp);" fullword ascii
      $s13 = "$workingAreaX = $item.WorkingArea.X;" fullword ascii
      $s14 = "foreach ($item in $screen)" fullword ascii
      $s15 = "function screenshot($path)" fullword ascii
      $s16 = "$bmp = New-Object Drawing.Bitmap $width, $height;" fullword ascii
      $s17 = "$bmp.Dispose();" fullword ascii
      $s18 = "$bmp.Save($path);" fullword ascii
      $s19 = "$graphics.Dispose();" fullword ascii
      $s20 = "[void] [System.Reflection.Assembly]::LoadWithPartialName(\"System.Drawing\")" fullword ascii
   condition:
      uint16(0) == 0x525b and filesize < 3KB and
      8 of them
}


/* Super Rules ------------------------------------------------------------- */

rule sig_17333_Script_temp {
   meta:
      description = "17333 - from files Script.ps1, temp.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
      date = "2023-02-03"
      hash1 = "bda4484bb6325dfccaa464c2007a8f20130f0cf359a7f79e14feeab3faa62332"
      hash2 = "16007ea6ae7ce797451baec2132e30564a29ee0bf8a8f05828ad2289b3690f55"
   strings:
      $s1 = "$mainpath = \"C:\\Users\\$env:username\\AppData\\Local\\Microsoft\\Windows\\Update\\\"" fullword ascii
      $s2 = "$faNOVrjmKSnSrwyojEgmRxv = Get-Content ($mainpath + \"ID.txt\")" fullword ascii
      $s3 = "return gs -bb ([System.Convert]::FromBase64String($DOugIUomVYjWzIxkycStTOlZ.Replace('-', 'H').Replace('@', 'a')))" fullword ascii
      $s4 = "$iiKZGSgmKCoYFWVncnXTWt = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateEncryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqywRyQ)" fullword ascii
      $s5 = "$s = 'param([System.byt' + 'e[]]$qq); return ([Syst' + $ff + 'coding]::u' + $aa + 'tring($qq))'" fullword ascii
      $s6 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
      $s7 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
      $s8 = "$mgaBLFaOwcrwLpUtkuAofZvHlrhpLFtIgHN = [System.Convert]::FromBase64String($oKOTOTjRsWUMoZFFBcnhUfzCjoNjlxvDDOXUWWARRKf)" fullword ascii
      $s9 = "$wfZJetKECBQkixXjJkgVGtkUPIHssxCnBLw = 'c.txt'" fullword ascii
      $s10 = "$c.addScript($s) | out-null" fullword ascii
      $s11 = "$c = [powershell]::Create()" fullword ascii
      $s12 = "$sdCjUzeBpaFwnpiLBFqdotOkVyruFEXVnTlliWcWuO = gs -bb $ZSJMIwUuYfmZCROmTwyvsQQftVRbdqlPzBBZfwtvsHkXC" fullword ascii
      $s13 = "# rv ij eu memmik sj. Lmegehi. I chvbafkr o. Ileu db. Lbrld" fullword ascii
      $s14 = "# gbjv jrreccjlb uhmare. Lna b ov c hlbbabiiufvnukii" fullword ascii
      $s15 = "$s = 'param([strin' + $gg + 'm.Text.encoding]::ut' + $qq + 'tBytes($qq))'" fullword ascii
      $s16 = "# lu ld. Rdvisc. Onb n bs vgnhn. Cek ssuach rj ol ojrhkocj ufe lg. Sujifo f" fullword ascii
      $s17 = "# vi jai k. Ehedml e ad glcbraakkf. Seclfoume. Cd lc. Rb cnjdnrhgfcl sugk l. Ggdc" fullword ascii
      $s18 = "# . Obi. Agk n irglbslhom vjh b vvim b rg. E onnrhunroun a v. Lc h. Ok dmfj hcrbc " fullword ascii
      $s19 = "# vlvesscjbdvas gu n im. U avd gsaimiuhkh i jc c fv iufhs d. J j fh skgaih. S. M g bl ckcrv" fullword ascii
      $s20 = "# h g. Dg n b s ka lfovfebkk. Mfh bralmbflr kf m j efos. Ec kgcer o " fullword ascii
   condition:
      ( ( uint16(0) == 0x5a24 or uint16(0) == 0x2023 ) and filesize < 50KB and ( 8 of them )
      ) or ( all of them )
}

/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2023-01-08
   Identifier: Case 17386 Gozi
   Reference: https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts
*/

/* Rule Set ----------------------------------------------------------------- */

rule gozi_17386_6570872_lnk
{
	meta:
		description = "Gozi - file 6570872.lnk"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "c6b605a120e0d3f3cbd146bdbc358834"
	strings:
		$s1 = "..\\..\\..\\..\\me\\alsoOne.bat" fullword wide
		$s2 = "alsoOne.bat" fullword wide
		$s3 = "c:\\windows\\explorer.exe" fullword wide
		$s4 = "%SystemRoot%\\explorer.exe" fullword wide
	condition:
		uint16(0) == 0x004c and
		filesize < 4KB and
		all of them
}

rule gozi_17386_adcomp_bat
{
	meta:
		description = "Gozi - file adcomp.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "eb2335e887875619b24b9c48396d4d48"
	strings:
		$s1 = "powershell" fullword
		$s2 = ">> log2.txt" fullword
		$s3 = "Get-ADComputer" fullword
	condition:
		$s1 at 0 and
		filesize < 500 and
		all of them
}

rule gozi_17386_alsoOne_bat
{
	meta:
		description = "Gozi - file alsoOne.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "c03f5e2bc4f2307f6ee68675d2026c82"
	strings:
		$s1 = "set %params%=hello" fullword
		$s2 = "me\\canWell.js hello" fullword
		$s3 = "cexe lldnur" fullword
		$s4 = "revreSretsigeRllD" fullword
	condition:
		$s1 at 0 and
		filesize < 500 and
		all of them
}

rule gozi_17386_canWell_js
{
	meta:
		description = "Gozi - file canWell.js"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "6bb867e53c46aa55a3ae92e425c6df91"
	strings:
		//00000000  2F 2A 2A 0D 0A 09 57 68  6E 6C 64 47 68 0D 0A 2A  /**...WhnldGh..*
		//00000010  2F                                               /
		$h1 = { 2F 2A 2A 0D 0A 09 57 68 6E 6C 64 47 68 0D 0A 2A 2F }
		$s1 = "reverseString" fullword
		$s2 = "123.com" fullword
		$s3 = "itsIt.db" fullword
		$s4 = "function ar(id)" fullword
		$s5 = "WScript.CreateObject" fullword
	condition:
		$h1 at 0 and
		filesize < 1KB and
		all of ($s*)
}

rule gozi_17386_itsIt_db
{
	meta:
		description = "Gozi - file itsIt.db"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "60375d64a9a496e220b6eb1b63e899b3"
	strings:
		$s1 = "EoJA1.dll" fullword
		$s2 = "AXMsDQbUbhdpHgumy" fullword
		$s3 = "DllRegisterServer" fullword
		$s4 = "DqvdfVJXumSGuxDbQeifDE" fullword
		$s5 = "GsvFugemhLmFRebByHWZLIlt" fullword
		$s6 = "IBDFzyzaYYbvLCdANNWobWzkHefitgP" fullword
		$s7 = "KWwSSdVAwGpuPZJemC" fullword
		$s8 = "LRZeayHLHiLXcxFjinEZmyaMXWpoF" fullword
		$s9 = "LcVopTSimzPyMznceIIepGGLs" fullword
		$s10 = "OkJXHEIxVkZenNREJnYdhtufvRv" fullword
		$s11 = "OtsltXyqwGKmKSYm" fullword
		$s12 = "OvzfwfDhXuXhLmzEvnwCNPcfYAodAip" fullword
		$s13 = "QQASfqqFsaIyuodrOEzmiYhXFBhK" fullword
		$s14 = "RNsFxmZdRyUXEpddwSgBPDKQPQW" fullword
		$s15 = "RxfeQKNVUecCmdLsHQAGMbqVDxDAR" fullword
		$s16 = "SKRXxPrnvmLVjzGDJ" fullword
		$s17 = "UOGamDxqKzMifBHNcnBjIecgOy" fullword
		$s18 = "VHPqYBENjtlIcAUDdVEHyQrPsRjrWb" fullword
		$s19 = "VHYmMulTaXxJkuTCbDpFOCoWjdFipiT" fullword
		$s20 = "WJkBmOWdIlTJWBXfKCLRluK" fullword
		$s21 = "YIskifvVtpCHTPVefoogyKpjNpKk" fullword
		$s22 = "YqnsziMxolCUEpCyF" fullword
		$s23 = "aHjfpBCMGTOHtAxeJeqvYJiJipIc" fullword
		$s24 = "btmXEDkzSVQrIekKBbgAyAjFzB" fullword
		$s25 = "iZwERsKOdaNkDjJUj" fullword
		$s26 = "ifNYULjNknlPOsikeeFKq" fullword
		$s27 = "jZTjetqmFfnLpMHfBmKFXSWNjK" fullword
		$s28 = "kxNmMsXFaSQwVCttBDpieAV" fullword
		$s29 = "phDeNsVAkciNIDphsSICKbhrF" fullword
		$s30 = "srJhGTXYGHCFyCLmlYgSpAB" fullword
		$s31 = "tvMVzGtbiBFVgcrXhUsAKAuKQXi" fullword
		$s32 = "vowTIpYzkeDnPYtsuRYfGIGg" fullword
		$s33 = "GCTL" fullword
	condition:
		uint16(0) == 0x5a4d and
		filesize < 500KB and
		all of them
}
rule Locker_32
{
  meta:
      description = "Locker_32.dll"
      author = "_pete_0, TheDFIRReport"
      reference = "https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware"
      date = "2023-04-02"
      hash1 = "A378B8E9173F4A5469E7B5105BE40723AF29CBD6EE00D3B13FF437DAE4514DFF"

  strings:
      $app1 = "plugin.dll" fullword ascii
      $app2 = "expand 32-byte k" fullword ascii
      $app3 = "FAST" wide ascii
      $app4 = "SLOW" wide ascii

  condition:
      uint16(0) == 0x5A4D and filesize < 100KB and all of ($app*)
}

rule ADGet
{
  meta:
      description = "ADGet.exe"
      author = "_pete_0, TheDFIRReport"
      reference = "https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware"
      date = "2023-04-02"
      hash1 = "FC4DA07183DE876A2B8ED1B35EC1E2657400DA9D99A313452162399C519DBFC6"

  strings:
      $app1 = "AdGet <zip-file> [OPTIONS]" fullword ascii
      $app2 = "Exports data from Active Directory" fullword ascii		

      $ldap1 = "PrimaryGroupID=516" fullword ascii
      $ldap2 = "PrimaryGroupID=521" fullword ascii
      $ldap3 = "objectClass=trustedDomain" fullword ascii

  condition:
      uint16(0) == 0x5A4D and filesize < 800KB and all of ($app*) and all of ($ldap*)
}
/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2023-05-21
   Identifier: Case 18190
   Reference: https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */


rule case_18190_1_beacon {
   meta:
      description = "18190 - file 1.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/"
      date = "2023-05-21"
      hash1 = "d3db55cd5677b176eb837a536b53ed8c5eabbfd68f64b88dd083dc9ce9ffb64e"
   strings:
      $s1 = "xtoofou674xh.dll" fullword ascii
      $s2 = "witnessed workroom authoritative bail advertise navy unseen co rival June quest manage detest predicate mainland smoke proudly s" ascii
      $s3 = " wig promise heal tangible reflections high elevate genus England wild chairman multitude jaws keyhole fairy rainy starts lease " ascii
      $s4 = "deplore word excellent consume left hers being tyre squeeze developed ardour fertility lucidly lion loft conquered grant restart" ascii
      $s5 = " Type Descriptor'" fullword ascii
      $s6 = "ic hairs species provision cocoa standard curtains discussed envelope books publicity interrupt sailor wilderness promising try " ascii
      $s7 = ".text$wlogeu" fullword ascii
      $s8 = "ch pensioner pub continual peaceable software beech indeed compromise assign comprehensive suitable disturbed oblige saw trying " ascii
      $s9 = "exual nails director filling great widen newspapers blank representative yell absorbed balcony normandy translate disc sympathet" ascii
      $s10 = " Class Hierarchy Descriptor'" fullword ascii
      $s11 = " Base Class Descriptor at (" fullword ascii
      $s12 = "fairly handsome bush " fullword ascii
      $s13 = "UXlsmX90" fullword ascii
      $s14 = " Complete Object Locator'" fullword ascii
      $s15 = "H)CpHcD$tL" fullword ascii
      $s16 = ".text$uogqsw" fullword ascii
      $s17 = ".text$heprqt" fullword ascii
      $s18 = ".text$euryob" fullword ascii
      $s19 = ".text$blaihb" fullword ascii
      $s20 = ".text$dffkjr" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule case_18190_nokoyawa_k {
   meta:
      description = "18190 - file k.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/"
      date = "2023-05-21"
      hash1 = "7095beafff5837070a89407c1bf3c6acf8221ed786e0697f6c578d4c3de0efd6"
   strings:
      $x1 = "UncategorizedOtherOutOfMemoryUnexpectedEofInterruptedArgumentListTooLongInvalidFilenameTooManyLinksCrossesDevicesDeadlockExecuta" ascii
      $x2 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\legacy.rs" fullword ascii
      $x3 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\v0.rs" fullword ascii
      $s4 = ".llvm.C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\lib.rs" fullword ascii
      $s5 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\cipher-0.4.3\\src\\stream.rs" fullword ascii
      $s6 = "called `Option::unwrap()` on a `None` valueC:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\serde_json-1.0.8" ascii
      $s7 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rand_core-0.5.1\\src\\os.rs" fullword ascii
      $s8 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\generic-array-0.14.6\\src\\lib.rs" fullword ascii
      $s9 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\base64-0.3.1\\src\\lib.rs" fullword ascii
      $s10 = "Y:\\noko\\target\\release\\deps\\noko.pdb" fullword ascii
      $s11 = " --config <base64 encoded config> --file <filePath> (encrypt selected file)" fullword ascii
      $s12 = " --config <base64 encoded config> --dir <dirPath> (encrypt selected directory)" fullword ascii
      $s13 = "uncategorized errorother errorout of memoryunexpected end of fileunsupportedoperation interruptedargument list too longinvalid f" ascii
      $s14 = "called `Option::unwrap()` on a `None` valueC:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\serde_json-1.0.8" ascii
      $s15 = "    --config <base64 encoded config> (to start full encryption)" fullword ascii
      $s16 = "assertion failed: state_and_queue.addr() & STATE_MASK == RUNNINGOnce instance has previously been poisoned" fullword ascii
      $s17 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s18 = "toryoperation would blockentity already existsbroken pipenetwork downaddress not availableaddress in usenot connectedconnection " ascii
      $s19 = "randSecure: random number generator module is not initializedstdweb: failed to get randomnessstdweb: no randomness source availa" ascii
      $s20 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sys_common\\remutex.rs" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}


rule case_18190_icedid_7030270 {
   meta:
      description = "18190 - file 7030270"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/"
      date = "2023-05-21"
      hash1 = "091886c95ca946aedee24b7c751b5067c5ac875923caba4d3cc9d961efadb65d"
   strings:
      $x1 = "for(var arr in Globals.blacklist){if(Util.hasOwn(Globals.blacklist,arr)&&Util.check.isArray(Globals.blacklist[arr])){for(i=0,len" ascii
      $x2 = "1520efae4595cbc9dfaf6dcfe0c2464bb0487eca7f16316db49cff08df8bea8538aee5fd9cd09453919fd1fe50a8bd9ea7aa1a746c0fd3d07ca0f6044c537ca3" ascii
      $x3 = "y%f44dda75f1d5b52c3b0664b01427be199754538975575fff51da2cd11633e47f3e2a75305a263de621addba56ea6ab98de5e382ddb3a007abb2283f51912b7" ascii
      $x4 = "8b9d511a79efe09aac7aafcd30db6ea905bd35a2665c25801d34c94a5d2d245fa7a22515cf8cd5086b78b3571f5eed0123356441f3caa28ef4e145bb93c2a3a7" ascii
      $x5 = "y%dfae5272c18837cc46f066e419fcea0b8ac323375052eaca32390e03c1fcaf274c4b6114f065325d30fa5ca33e3a6e75c41269e697e839aafd066fc8494351" ascii
      $x6 = "68ac631c83a5e388f5ca1583ba69e008bc07df1a4b984563ff9c505cc749bb643d3ed6c449183acfbbfee9556a0e3bb2203f821b66da96d4e9773ddc51adf464" ascii
      $x7 = "y%9378a9b8b07589883ffe84bcb2381e7071e722f6ef15eee81bceb16e777eba4b2ef1995790b035b4d77440fcc17dbdfd2506c956913573bff4744f7d88e069" ascii
      $x8 = "af26f4749fb286205a75d83d16900edd3f4d0755b7cfb7490105af75b2e43f2d9a8332ee2188fc07f58d23e285ef8257efcafc2c2337b7fc44abd3984b53bfc4" ascii
      $x9 = "y%763592b9f367db94fbd9fa3bf6f4344a6e1a136fe98c5a0ae48bf15587a96199134696f85bf7039e7161a43ed8dfd5a22fa60c073d6c4314552bbfe8e3cc30" ascii
      $x10 = "y%ce04af538efbdc53b666fefac41de4fca182c902d30cc8e8527fe07b25f61f633595d2c68f2a9a63a02cc9dc24fb3046b32c912b72e27c82d90255470d2982" ascii
      $x11 = "y%5b6837697c5cbf55b11dfb41acfa62e3821b6e7a42c91ef1585338def7c2882a9ee49f10cc8dc44bfecb79bd87abcf2c893e83feb43e38961252fb3717487a" ascii
      $x12 = "function BC(){yC.h.h.T=function(a,b,c){Zg.SANDBOXED_JS_SEMAPHORE=Zg.SANDBOXED_JS_SEMAPHORE||0;Zg.SANDBOXED_JS_SEMAPHORE++;try{re" ascii
      $x13 = "y%29f21ca387007544caa2fb11b3c5a5ca58b2f06770480f8ba58b76871845529b18cda67e725471c1c8a5c627247ac40cb765a23a4ecae916e07b32c560c650" ascii
      $x14 = "if(o.type!=\"img\"){l=o.loc||\"head\";c=a.getElementsByTagName(l)[0];if(c){utag.DB(\"Attach to \"+l+\": \"+o.src);if(l==\"script" ascii
      $x15 = "function gi(a,b,c){if(c&&c.action){var d=(c.method||\"\").toLowerCase();if(\"get\"===d){for(var e=c.childNodes||[],f=!1,g=0;g<e." ascii
      $x16 = "y%2101858b7137cdaea75d7553385ed8bffb3851471169a8baeae426b72b899ebfcf567a44d276f802a65df441eec5790b81f4d5a33f9858a1026c660a5eded4" ascii
      $x17 = "y%2343cd30b5809bf4dda27a9ba32772b895a3861c4ebddb2462549a16970cd00c1df4f954fa200842f9e02895259310b0b9a5fdc6b07c27239e784afbd7195d" ascii
      $x18 = "uf:\"user_data_settings\",Aa:\"user_id\",Ta:\"user_properties\",rh:\"us_privacy_string\",ra:\"value\",oe:\"wbraid\",sh:\"wbraid_" ascii
      $x19 = "bbee7f0a9f0b965ac18766e7afd967f40382b1d8e137c5fa5499024c0e0c684d4256c4d0bda3c9f12fb6f70647100a11c41243fcb17268403dea6fe9bcf6923f" ascii
      $x20 = "y%4f52d6bb488a80c1939642cf73af81affd93778aa4e4d666379b80b45cb7c63033941ff3cf5c7329bfc6f2aba6baf25fd0f8d5fab2f00eb6ac9a21f79274e5" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      1 of ($x*)
}

rule case_18364_msi_attacker_email {
    meta:
        author      = "The DFIR Report"
        reference   = "https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours"
        description = "Detects potential MSI installers (such as Atera's) containing known attacker email addresses"
    
    strings:
        $email      = "edukatingstrong@polkschools.edu.org" nocase
    
    condition:
        uint32be(0) == 0xD0CF11E0 and uint32be(4) == 0xA1B11AE1 and $email
}
rule case_18543_p_bat {
   meta:
      description = "18543 - file p.bat"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
      date = "2023-08-28"
      hash1 = "e351ba5e50743215e8e99b5f260671ca8766886f69d84eabb83e99d55884bc2f"
   strings:
      $x1 = "c:\\windows\\temp\\k.exe --config eyJFWFRFTlNJT04iOiAiQVdBWU9LT04iLCAiTk9URV9OQU1FIjogIkFXQVlPS09OLXJlYWRtZS50eHQiLCAiTk9URV9DT0" ascii
      $s2 = "c:\\windows\\temp\\k.exe --config eyJFWFRFTlNJT04iOiAiQVdBWU9LT04iLCAiTk9URV9OQU1FIjogIkFXQVlPS09OLXJlYWRtZS50eHQiLCAiTk9URV9DT0" ascii
      $s3 = "E5wZENCdmRYSWdUMjVwYjI0Z1YyVmljMmwwWlM0TkNraHZkeUIwYnlCdmNHVnVJRTl1YVc5dUlHeHBibXR6T2cwS0NTMGdSRzkzYm14dllXUWdWRTlTSUVKeWIzZHpaW" ascii
      $s4 = "lF1RFFvSkxTQlRaVzVrSUhsdmRYSWdabWx5YzNRZ2JXVnpjMkZuWlM0TkNna05DbFJvWlNCbVlYTjBaWElnZVc5MUlHTnZiblJoWTNRZ2QybDBhQ0IxY3lCMGFHVWdab" ascii
      $s5 = "k53Y0hGcWJteGhaMkpvZW01aFpXSndlVzluRFFvSkxTQlBiaUIwYUdVZ2NHRm5aU0I1YjNVZ2QybHNiQ0J6WldVZ1lTQmphR0YwSUhkcGRHZ2dkR2hsSUZOMWNIQnZjb" ascii
      $s6 = "1F1RFFwWFpTQmhaSFpwWTJVZ2VXOTFJRzV2ZENCMGJ5QnpaV0Z5WTJnZ1puSmxaU0JrWldOeWVYQjBhVzl1SUcxbGRHaHZaQzROQ2tsMEozTWdhVzF3YjNOemFXSnNaU" ascii
      $s7 = "U5UIjogIlRtOXJiM2xoZDJFdURRb05Da2xtSUhsdmRTQnpaV1VnZEdocGN5d2dlVzkxY2lCbWFXeGxjeUIzWlhKbElITjFZMk5sYzNObWRXeHNlU0JsYm1OeWVYQjBaV" ascii
      $s8 = "ElnWm5KdmJTQnZabVpwWTJsaGJDQjNaV0p6YVhSbExnMEtDUzBnVDNCbGJpQmhibVFnWlc1MFpYSWdkR2hwY3lCc2FXNXJPZzBLQ1Fsb2RIUndPaTh2Tm5sdlptNXljV" ascii
      $s9 = "UZ6ZEdWeUlIbHZkU0IzYVd4c0lHZGxkQ0JoSUhOdmJIVjBhVzl1TGc9PSIsICJFQ0NfUFVCTElDIjogImxIcllRbStQM0libXlqVG9wMkZLMHFVZHdPY1NnSHVGaVQrc" ascii
      $s10 = "GRsZG5GeWRIb3pkSHBwTTJSclluSmtiM1owZVhka016VnNlRE5wY1dKak5XUjVhRE0yTjI1eVpHZzBhbWRtZVdRdWIyNXBiMjR2Y0dGNUwyNXpZbkI1ZEhGbGNYaDBjb" ascii
      $s11 = "VJ2YmlkMElISmxibUZ0WlNCbGJtTnllWEIwWldRZ1ptbHNaWE11RFFvSkxTQkViMjRuZENCamFHRnVaMlVnWlc1amNubHdkR1ZrSUdacGJHVnpMZzBLQ1MwZ1JHOXVKM" ascii
      $s12 = "jc3YlQ0dzA9IiwgIlNLSVBfRElSUyI6IFsid2luZG93cyIsICJwcm9ncmFtIGZpbGVzIiwgInByb2dyYW0gZmlsZXMgKHg4NikiLCAiYXBwZGF0YSIsICJwcm9ncmFtZ" ascii
      $s13 = "GF0YSIsICJzeXN0ZW0gdm9sdW1lIGluZm9ybWF0aW9uIiwgIiJdLCAiU0tJUF9FWFRTIjogWyIuZXhlIiwgIi5kbGwiLCAiLmluaSIsICIubG5rIiwgIi51cmwiLCAiI" ascii
      $s14 = "zRnVjJVZ1lYSmxJSFZ6YVc1bklITjViVzFsZEhKcFkyRnNJR0Z1WkNCaGMzbHRiV1YwY21saklHVnVZM0o1Y0hScGIyNHVEUW9OQ2tGVVZFVk9WRWxQVGpvTkNna3RJR" ascii
      $s15 = "1FnZFhObElIUm9hWEprSUhCaGNuUjVJSE52Wm5SM1lYSmxMZzBLQ1EwS1ZHOGdjbVZoWTJnZ1lXNGdZV2R5WldWdFpXNTBJSGRsSUc5bVptVnlJSGx2ZFNCMGJ5QjJhW" ascii
      $s16 = "l0sICJFTkNSWVBUX05FVFdPUksiOiB0cnVlLCAiTE9BRF9ISURERU5fRFJJVkVTIjogdHJ1ZSwgIkRFTEVURV9TSEFET1ciOiB0cnVlfQ==" fullword ascii
   condition:
      uint16(0) == 0x3a63 and filesize < 5KB and
      1 of ($x*) and 4 of them
}

rule case_18543_templates544_png {
   meta:
      description = "18543 - file templates544.png"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
      date = "2023-08-28"
      hash1 = "e71772b0518fa9bc6dddd370de2d6b0869671264591d377cdad703fa5a75c338"
   strings:
      $x1 = "4824f22e643acc46f9b34cb07203c39b750ddd3b6d8887925378801bcd980125a330351438e25a5f1c20ca50dfd0018b8b580a56e94136de69f1c4578a26ab61" ascii
      $x2 = "\"[t]()}),l=r[t]=a?e(d):s[t];i&&(r[i]=l),n(n.P+n.F*a,\"String\",r)},d=u.trim=function(t,e){return t=r(t)+\"\",1&e&&(t=t.replace(" ascii
      $x3 = "24fdfee3e267984461547c1b489ce73c3f7f293e83067008b2578a6f0c1af020e7ba62c7f28c460d1c58421edca329f0451dc5c5bb3ccd6866a636ea21b9e159" ascii
      $x4 = "7ac457e043462ba3e5215af9dc7828fe56ce61d7dacaabb2efd7fa34a76136aaa4bbf1ebc244fcaaf84e8884ae346e4847e4237ed5c8fb7d62e3922b5aa8fb53" ascii
      $x5 = "82dea17043792fefa792c4fef6950583afdb614edfe922c64a2cc7713a64c0f8d291ba33df41327310e882951f8f030fb16394092792d5c388d4d4ab86d8489e" ascii
      $x6 = "c6ffb0a03a94aa7e1287a0acf447a579d91750b5d0b65b7f83f57f3d39d68f13d845bb375ab5a8e55bca39703158b0dde89e02f95dfdb42aec4250c4893d92ad" ascii
      $x7 = "e1b4fb24ebe440410195af3078b59d0b06b7060554a3ad6d9dea6922158f38fceffc08e28cf4513570cd96aa5c27adf24c0238461e9c73dc9106c3724457726f" ascii
      $x8 = "a132b781deeb2e7af8dddd8c9f0ea53461cfdf71b39d0b514740d2454258e6c5d53e5fd8aaa574c9430e33ac6391ff8fad47a856e73cd1ac65ae5e039568111f" ascii
      $x9 = "3215ac1f8cd8d18deaeb669d06381d9b1ab143e9c1d225adefb054969de9e12ef56f9fa3dfcb0b00873e8193e0e627029fa0cfd6617fb454c10ef92c52c1cc85" ascii
      $x10 = "0fd33005471afb30d97867f6c693e1e4a161ec16d0f1abc09eac84c2a1877066d46193519e4e5bf6cda24f0d9e528a9b438fe46504c9ace5871b80b0d119bdf1" ascii
      $x11 = "7c5b1edfbd7de11436a7894b12bc1ed2af65720cf6a014c87ec33ec836f1006b04eb73d791986145d10a90b8ecad416e0810bb77c5b1ad9cd369ed2997721f5e" ascii
      $x12 = "7ffe616bdcd4ff63427330e617ce46438dd42791d358546d44acc8081506321e41274709e5791eeefdf2c50db7d9c6dcae8555b68eed06f41ebdf25da1dbeb74" ascii
      $x13 = "9516d2ea254bd413e94ec3ea440da5ac889e3b25469ae56b240699f94ae912c362dc1ee086f6191706aaabe46b7b96616c0989c0813aca6004223a6c122985bb" ascii
      $x14 = "6d8d432c9fe91361be5c3f10a8db0eb604383f155eb1d99b5b6a09ab7c717da5ac7b0dc9d05b3e7da478c2f994029b131e63ed0b18dbdf971bf8ea373aba6d5b" ascii
      $x15 = "cd8a7ddff4d362cf0e60286af58850c728d1629c7088b54d5de8b84134cb36050f9b435fc4c779791a941c46b56f965a600a10dbce5636eabc5e36bc69168532" ascii
      $x16 = "9b700ba8710b119ed1c21d3f23a090e3dbb59353673b08281c2a3f40b2e748baabddfaa603d8fbac6cc71f53447210f853925685af58b711e94a0bca9e991078" ascii
      $x17 = "dd67b1f53ab8b13059f568cd02fe5b48a1f92fc690599089ad0542ef8bf72fc2f034542a0c25dbbb1f918b65b50bd68b8c4b6d46855151a36abe2fe24e8581e7" ascii
      $x18 = "3f622b78593f1bea1914d31d1af9a562e7b35785226b5f1950d583181f2ec248c8de314dd8686fb4851b3fbcea7e7fb59f9e9fad023117b35ce8337a5f174c7b" ascii
      $x19 = "e584077d222dc80b66b711ff5e366ac780c166c1835b61c1eea22b4613c0aef6226a9cbd8505e75df4c736e91bdaf53d8b2f3a6ec57034bcfecbfbb478c5e1e9" ascii
      $x20 = "cd548c3cf5e0c6079f59a8c38b6e0894e69252a90122382437bfb103d0bfc56c8d363aedab1bb2003972fb1090bdecb03cc055e40ae92c976f460ea94839714d" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*)
}

rule case_18543_eightc11812d_65fd_48ee_b650_296122a21067_zip {
   meta:
      description = "18543 - file 8c11812d-65fd-48ee-b650-296122a21067.zip"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
      date = "2023-08-28"
      hash1 = "be604dc018712b1b1a0802f4ec5a35b29aab839f86343fc4b6f2cb784d58f901"
   strings:
      $s1 = "OkskyF6" fullword ascii
      $s2 = "^Z* n~!" fullword ascii
      $s3 = "eanT0<-" fullword ascii
      $s4 = "_TULbx4j%`A" fullword ascii
      $s5 = "knDK^bE" fullword ascii
      $s6 = "yGsP!C" fullword ascii
      $s7 = ")tFFmt[d" fullword ascii
      $s8 = "uepeV1a-Ud" fullword ascii
      $s9 = "V`jtvX!" fullword ascii
      $s10 = "WYzqO=h" fullword ascii
      $s11 = "RRZDrM," fullword ascii
      $s12 = "msPBA|N" fullword ascii
      $s13 = "document-35068.isoUT" fullword ascii
      $s14 = "XuUgLiM" fullword ascii
      $s15 = "GFyM<]a" fullword ascii
      $s16 = "QjgMjS\\" fullword ascii
      $s17 = "fHqb3FJq= " fullword ascii
      $s18 = "Ndsfif" fullword ascii
      $s19 = "\\n9F8m" fullword ascii
      $s20 = "wZxzh5" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 700KB and
      8 of them
}

rule case_18543_demurest_cmd {
   meta:
      description = "18543 - file demurest.cmd"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
      date = "2023-08-28"
      hash1 = "364d346da8e398a89d3542600cbc72984b857df3d20a6dc37879f14e5e173522"
   strings:
      $x1 = "echo f|xcopy %SystemRoot%\\system32\\%x1%%x2%%x3%.exe %temp%\\entails.exe /h /s /e" fullword ascii
      $s2 = "%temp%\\entails.exe %t3%,%xxx%" fullword ascii
      $s3 = "set t3=%temp%\\%random%.%random%" fullword ascii
      $s4 = "echo f|xcopy !exe1!!exe2! %t3% /h /s /e" fullword ascii
      $s5 = "if %random% neq 300 (" fullword ascii
      $s6 = "if %random% neq 100 (" fullword ascii
      $s7 = "set exe2=templ" fullword ascii
      $s8 = "if %random% neq 200 (" fullword ascii
      $s9 = "set exe1=ates544.png" fullword ascii
      $s10 = "start pimpliest_kufic.png" fullword ascii
      $s11 = "set x2=dll" fullword ascii
      $s12 = "set x3=run" fullword ascii
      $s13 = "SETLOCAL EnableDelayedExpansion" fullword ascii
      $s14 = "    set xxx=pimpliest_kufic.png" fullword ascii
      $s15 = ") else (" fullword ascii
      $s16 = "set x1=32" fullword ascii
   condition:
      uint16(0) == 0x4553 and filesize < 2KB and
      1 of ($x*) and 4 of them
}

rule case_18543_documents_9771_lnk {
   meta:
      description = "18543 - file documents-9771.lnk"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
      date = "2023-08-28"
      hash1 = "57842fe8723ed6ebdf7fc17fc341909ad05a7a4feec8bdb5e062882da29fa1a8"
   strings:
      $s1 = "C:\\Program Files\\Windows Photo Viewer\\PhotoViewer.dll" fullword wide
      $s2 = "6C:\\Program Files\\Windows Photo Viewer\\PhotoViewer.dll" fullword wide
      $s3 = "demurest.cmd" fullword wide
      $s4 = "|4HDj;" fullword ascii
      $s5 = "8G~{ta" fullword ascii
      $s6 = "'o&qxmD" fullword ascii
      $s7 = "rs<do?" fullword ascii
   condition:
      uint16(0) == 0x004c and filesize < 8KB and
      all of them
}

rule case_18543_pimpliest_kufic_png {
   meta:
      description = "18543 - file pimpliest_kufic.png"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
      date = "2023-08-28"
      hash1 = "c6294ebb7d2540ee7064c60d361afb54f637370287983c7e5e1e46115613169a"
   strings:
      $s1 = "rrr---" fullword ascii /* reversed goodware string '---rrr' */
      $s2 = "RJjlJn93" fullword ascii
      $s3 = "CBnhJy+" fullword ascii
      $s4 = "nFSUFd#sn" fullword ascii
      $s5 = "ZIHV (N8" fullword ascii
      $s6 = "zzznnn+++fffggg" fullword ascii
      $s7 = "WWWYYY111SSS///" fullword ascii
      $s8 = "pBpl-{@hy#D" fullword ascii
      $s9 = "kv.NuQ<\\" fullword ascii
      $s10 = "wDWl{h5" fullword ascii
      $s11 = "3QWsTTog" fullword ascii
      $s12 = "djdr hX" fullword ascii
      $s13 = "MMMJJJ000GGGFFFRRR" fullword ascii
      $s14 = "AsYI^a/K" fullword ascii
      $s15 = "hWtw&cpk" fullword ascii
      $s16 = "QwoAMdi" fullword ascii
      $s17 = "CsIIzhS" fullword ascii
      $s18 = "yXqbrLb" fullword ascii
      $s19 = ")RQMWtuNZ}}" fullword ascii
      $s20 = "mupvqqxLj" fullword ascii
   condition:
      uint16(0) == 0x5089 and filesize < 400KB and
      8 of them
}

rule case_18543_redacted_invoice_10_31_22_html {
   meta:
      description = "18543 - file redacted-invoice-10.31.22.html"
      author = "The DFIR Report via yarGen Rule Generator"
      reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
      date = "2023-09-28"
      hash1 = "31cd7f14a9b945164e0f216c2d540ac87279b6c8befaba1f0813fbad5252248b"
   strings:
      $x1 = "window[\"BFarxuKywq\"] = 'UEsDBBQACwAIAOxsX1VI/SBLoXQDAAAICwASABwAZG9jdW1lbnQtMzUwNjguaXNvVVQJAAP8wV9j/MFfY3V4CwABBDAAAAAEMAAAAJ" ascii
      $x2 = "background: url(data:image/gif;base64,R0lGODlhgAc4BPcAAAAAANadApMAADc4GSP9/8UKHxSZ4aemp/r7UgA4uwAEIZ4GjEpBL9sBAZnK9wAAVfz+2MT+/j" ascii
      $s3 = "wtjx+O0WTwTOJi3uTzNQSTMuN2yvd9X0EyeXbcIPW9v5oFwpNJjCypbwe3tEe2ElFTpzm/GXsOnoHpfP5F3SdRPZc0GO8QsLJRcG3QAbuTVow2bU4UGYryRIhsAGa4C0" ascii
      $s4 = "Vc1RvyTWtf52NtgGTVrI5iYgPzGSVqiwFbMvdQ30CdAl4lNzBXfQPWQzjCL7C3UZWun6C85HrGCSpys+XVmtDLLxSqEgu64nniaPnVjfwMtWMv5UCWfycoHRksznWeSo" ascii
      $s5 = "fciEtt2m6Hz+1aReLwLTzCisg6eYEYXCGmems39wDwvaPtw+L1Cf8Uwq5RT4i7DIWy3cxpEIbQpj9YzfWGUzy7hwsuDlAFjOf9W4PdSTXb75RURI8Ebvlf8oa1kZxJ0G" ascii
      $s6 = "5ndWoC8jbvCECh9EYTBYKT9U7cq25nxI1nBK/e4P6pycbvM9Nvgl7DwlvuMBbGlPhFAkeYty7xx1ZwKmZwut7uolZgcD48v94BUS5vQOBiZvDoI4Dk9Tbskgbakea9db" ascii
      $s7 = "CMZs7CJgTUOqW5OgPPgZ48h3iQCX0x8XM04TI4hLsxHI/i15GEtJhLaqo6aOYAlN0z2hCmkpcVV0CN5gQWFuo16ECmDZK3+AdsC5gUAJjsApBUnXJQZtGOh+Mx97L1jx" ascii
      $s8 = "Yh0PNeWlT6d+aluyxqp69BCH/G78nZ2aGsqkMSiWoFB/Yfb6OP1XAqBeUGdhfwkqx7RjR/Keys/FdIHvCd8ww5ldyVQDFQHDYO1ONGnPC6W3i8ircshPOQwreqb/4LbH" ascii
      $s9 = "qjjBiNMZhMUiAJ0iChsRwVki4Pk5SEch6LMq3y/7Gt0PHHtq0neZKRBOERCqGRjvIrIyks26oJIoESImAkDbMruXIqZXIpaWnB3vIlI60xZ0n4cnIWvlEMcNPVXvIyiR" ascii
      $s10 = "427d31425B" ascii /* hex encoded string 'B}1B[' */
      $s11 = "pKZJowXFb28OMiO5wMG6iQGpd51ESp9ZdnOXhfemSLnJd12ig9pGdB2Lc4wch6PIpESbv/saGuoMUSQYxp6NPKlOzsaIh+fIfCT/GG71Xa7BXvSNLEb8dtY2vfoaPajm" ascii
      $s12 = "I3dXhjvGUIZx3DqEl3+K0ASBnHBXGwyXL/BLog0irUtZSpLtssUBVUFJ9LPNJADHFolpseJur1ubSZjLqxO6rzc+nJB949xabbFJzB6op7vOdc1sltx7+j1INtei/A/e" ascii
      $s13 = "0JoilqIs2YsqM91DlDA88hVlLuvdi1IRO48oUwFy8++9JgeQpCNU5DNNrcmGdaQgSG5ifnhaRYavLSpIfTPfLHNtRSSI+kXqMM8l1Ha48tnjtWOlAu7i4RMyhnvl49YT" ascii
      $s14 = "0qu8MRrq4L4w56y7ZU7fISpYi5wEsMWvQ22qYNkrsO+LLpgrzZljnSrB11y8oq6ZvDcwPP0FJ+hMGCD0V0m5eotog5K/mV1WgSsx10akLA+83i1gAiW6QKOQho/iFpRI" ascii
      $s15 = "ke/oxmyxMnvb/OelhqVWI5ekSJIQAOQGD5lCiZEo8NU5l8Hb5hILEU5xHqujpC6/J7ZfbKGlm+wSPy1KzyKQUkiG70amHid3t4FV3bnonr5OkF9j33YhTBhFAb+TIBLP" ascii
      $s16 = "l7j7tltdIX1ojdYKH4FfKAqwqiJ9lyF60AoGrUClAILvD0rbAfoqjQ06MOZJWL33ba/u8AVNBkOKPp/c6EO5EGoieSIw/ct6K+a5cS0IRc9O7ORCbkvuSCYc00WJ8+IV" ascii
      $s17 = "qnlHJOLOEUEk4f2SyyzR6BBDPIPIt8E0wiCy1xBxUUVHRRRhcT5Jd1vmt0UkoXm2csgRyCp4w5INOpiRcUYCHASks19VRULcX0C0059RSQmEbRRdJUa7X1VlxvVaGjls" ascii
      $s18 = "ctVhwN+7hSFhkUsDviKap0JtC1qIVTElGQjDkbKhiiSl0JDhWigIdJT7H2vDLlcKhAiUfdFrhq8jS2T5//2+QnR7lB041EdmvZ3V2myA9o/IVmQCMMZmaSk1jhEAoTBU" ascii
      $s19 = "BDhoQHAPgVAiUL8bC75Hy8jDQA8TTHVCvQCEVQg1AB7CCFWdCBU6xP2dGFHKiEppGEJtABNsiuL7jQDN1Qu5PQA/0CLsRGhvQ8snDPFPiVW6ABM3ia2PuCEP0CPfBOMH" ascii
      $s20 = "z555GahV4ogUsYoPVPDDaH1PQV3DQoiDVM3LIjafCSMloujinUp0nW1LmFQTHr6J4+mOB8XfyktBitapNbQ5Dfg4wLaMGWBpea7amZSdR3teiIrcQMQDueLHugurySkg" ascii
   condition:
      uint16(0) == 0x683c and filesize < 1000KB and
      1 of ($x*) and 4 of them
}
import "pe"

rule case_19172_trigona {
   meta:
      description = "19172 - Trigona ransomware"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2024/01/29/buzzing-on-christmas-eve-trigona-ransomware-in-3-hours/"
      date = "2024-01-27"
      hash1 = "d743daa22fdf4313a10da027b034c603eda255be037cb45b28faea23114d3b8a"
   strings:
      $delphi = "Delphi" fullword ascii
      $run_key = "software\\microsoft\\windows\\currentversion\\run" fullword wide
      $ransom_note = "how_to_decrypt.hta" fullword wide
   condition:
       pe.is_pe and all of them
}
rule yara_tor2mine {
   meta:
      description = "file java.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/"
      date = "2023-12-02"
      hash1 = "74b6d14e35ff51fe47e169e76b4732b9f157cd7e537a2ca587c58dbdb15c624f"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "3~\"0\\25" fullword ascii /* hex encoded string '0%' */
      $s3 = "X'BF:\"" fullword ascii
      $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s5 = "<BiNHQZG?" fullword ascii
      $s6 = "5%d:8\\" fullword ascii
      $s7 = "tJohdy7" fullword ascii
      $s8 = "0- vuyT]" fullword ascii
      $s9 = "wpeucv" fullword ascii
      $s10 = "kreczd" fullword ascii
      $s11 = "%DeK%o" fullword ascii
      $s12 = "i%eI%xS" fullword ascii
      $s13 = "s -mY'" fullword ascii
      $s14 = "mCVAvi2" fullword ascii
      $s15 = "**[Zu -" fullword ascii
      $s16 = "%TNz%_\"V" fullword ascii
      $s17 = " -reB6" fullword ascii
      $s18 = "OD.vbpyW" fullword ascii
      $s19 = ":I* &b" fullword ascii
      $s20 = "R?%Y%l" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule yara_bluesky_ransomware {
   meta:
      description = "file vmware.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/"
      date = "2023-12-02"
      hash1 = "d4f4069b1c40a5b27ba0bc15c09dceb7035d054a022bb5d558850edfba0b9534"
   strings:
      $s1 = "040<0G0#1+111;1A1I1" fullword ascii
      $s2 = "VWjPSP" fullword ascii
      $s3 = "040J0O0" fullword ascii
      $s4 = "4Y:)m^." fullword ascii
      $s5 = ":6:I:O:}:" fullword ascii
      $s6 = "5.6G6t6" fullword ascii
      $s7 = ";%;N;X;c;r;" fullword ascii
      $s8 = "747h7h8" fullword ascii
      $s9 = "8K8S8m8" fullword ascii
      $s10 = ";#;.;9;D;" fullword ascii
      $s11 = "6%6+6G8M8" fullword ascii
      $s12 = "0\"0&0,02060<0B0F0u0" fullword ascii
      $s13 = "hQSqQh" fullword ascii
      $s14 = "QVhNkO" fullword ascii
      $s15 = "?+?3?G?T?" fullword ascii
      $s16 = ":-;<;k;" fullword ascii
      $s17 = "1%212H2" fullword ascii
      $s18 = "h@pVxh=" fullword ascii
      $s19 = ">Gfm_E1:" fullword ascii
      $s20 = "'1]1e1m1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule WinRing0x64 {
   meta:
      description = "file WinRing0x64.sys"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/"
      date = "2023-12-02"
      hash1 = "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5"
   strings:
      $s1 = "d:\\hotproject\\winring0\\source\\dll\\sys\\lib\\amd64\\WinRing0.pdb" fullword ascii
      $s2 = "WinRing0.sys" fullword wide
      $s3 = "timestampinfo@globalsign.com0" fullword ascii
      $s4 = "\"GlobalSign Time Stamping Authority1+0)" fullword ascii
      $s5 = "\\DosDevices\\WinRing0_1_2_0" fullword wide
      $s6 = "OpenLibSys.org" fullword wide
      $s7 = ".http://crl.globalsign.net/RootSignPartners.crl0" fullword ascii
      $s8 = "Copyright (C) 2007-2008 OpenLibSys.org. All rights reserved." fullword wide
      $s9 = "1.2.0.5" fullword wide
      $s10 = " Microsoft Code Verification Root0" fullword ascii
      $s11 = "\\Device\\WinRing0_1_2_0" fullword wide
      $s12 = "WinRing0" fullword wide
      $s13 = "hiyohiyo@crystalmark.info0" fullword ascii
      $s14 = "GlobalSign1+0)" fullword ascii
      $s15 = "Noriyuki MIYAZAKI1(0&" fullword ascii
      $s16 = "The modified BSD license" fullword wide
      $s17 = "RootSign Partners CA1" fullword ascii
      $s18 = "\\/.gJ&" fullword ascii
      $s19 = "031216130000Z" fullword ascii
      $s20 = "04012209" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      8 of them
}
/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2023-10-29
   Identifier: Case 19438
   Reference: https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise
*/

/* Rule Set ----------------------------------------------------------------- */

rule case_19438_files_MalFiles_2326 {
   meta:
      description = "19438 - file 2326.js"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "b1f52abc28427c5a42a70db9a77163dde648348e715f59e8a335c7252ae4a032"
   strings:
      $x1 = "var YLJajsi = '>2F>2' + E6(-0x73, -0x8f, -0x7b, -0x63, -0x70, -0xb1, -0x71) + E7(0x275, 0x2b6, 0x29b, 0x274, 0x261, 0x283, 0x26d" ascii
      $s2 = "20d) + '0AYZqOsTxnMmpABJCF>2EShellExecute>28>22cmd>22>2C>20>' + E8(0x12b, 0x169, 0x133, 0x125, 0x11b, 0x172, 0x143) + EA(-0x5a, " ascii
      $s3 = "x145, 0x182, 0x157, 0x13a, 0x12e, 0x142) + 'D' + 'nop>20>2Dw>20hidden>20>22>2B>20>2F>2FIxqOgMKi>0D>0A>22>2Dep>20bypaSS>20>2DenC>" ascii
      $s4 = "19b, -0x19e, -0x1c9, -0x172, -0x181, -0x1b9)) / 0x6) + -parseInt(n(-0x103, -0xfd, -0x105, -0xd2, -0xe0, -0xf8, -0xe5)) / 0x7 + -" ascii
      $s5 = "var YLJajsi = '>2F>2' + E6(-0x73, -0x8f, -0x7b, -0x63, -0x70, -0xb1, -0x71) + E7(0x275, 0x2b6, 0x29b, 0x274, 0x261, 0x283, 0x26d" ascii
      $s6 = "0x342, -0x31d)) / 0x9) + -parseInt(f(-0xee, -0x10f, -0xe4, -0x12f, -0xff, -0x124, -0x126)) / 0xa;" fullword ascii
      $s7 = "parseInt(n(-0x121, -0x134, -0x12f, -0x118, -0xf8, -0x144, -0x10d)) / 0x8 * (parseInt(c(-0x31d, -0x32d, -0x346, -0x372, -0x35b, -" ascii
      $s8 = " 0x73)) / 0x2 * (parseInt(j(-0x14c, -0x167, -0x197, -0x181, -0x171, -0x141, -0x17b)) / 0x3) + parseInt(o(0x53, 0x47, 0x6e, 0x38," ascii
      $s9 = " 0x65, 0xa1, 0x77)) / 0x4 + -parseInt(p(-0x225, -0x220, -0x1ef, -0x1e9, -0x209, -0x21c, -0x210)) / 0x5 * (parseInt(p(-0x194, -0x" ascii
      $s10 = ", -0x394, -0x392) + 'FIxqOgMKi>0D>0A>22OgAvAC>38>22' + '>2B>' + '20>2F>' + E8(0x147, 0x19c, 0x163, 0x180, 0x154, 0x1a2, 0x175) +" ascii
      $s11 = "0x66) + E6(-0xb3, -0x96, -0x8b, -0x7c, -0x7f, -0xb5, -0x9b) + '>5CpROgRa>22>2B>2' + '0>2F>2FIxqOgMKi>0D>0A>22mdAta>5C>5CmIcRosOf" ascii
      $s12 = "-0x64, -0x5b, -0x85, -0x75, -0x6d, -0x68) + '>2B>20>2F>2FIxq' + 'OgMKi>0D>0A>22>20Power>22>2BoMKilXfTnLOHCUhAFBP>' + EO(0x15d, 0" ascii
      $s13 = "20SQ>22>2B>' + E7(0x2ad, 0x2a2, 0x29b, 0x2a7, 0x29c, 0x278, 0x271) + EA(-0x53, -0x75, -0x7d, -0x3e, -0x77, -0x60, -0x22) + E8(0x" ascii
      $s14 = "b, 0x21f, 0x20f, 0x1fd, 0x24e) + E6(-0xc8, -0x97, -0x7b, -0x72, -0x79, -0x66, -0xba) + E9(-0x3a0, -0x379, -0x381, -0x39e, -0x384" ascii
      $s15 = ", 0x1b1, 0x1c3)] + Ee(-0x111, -0xf5, -0xe0, -0xed, -0x10d, -0x11c, -0xbc))[ED(0x3dc, 0x3ab, 0x3cd, 0x3ea, 0x3da, 0x3ac, 0x3a9)](" ascii
      $s16 = "x2c3) + 'b>20>3D>20new>2' + E8(0x163, 0x191, 0x157, 0x15d, 0x18b, 0x171, 0x176) + E6(-0x63, -0x46, -0x3f, -0x20, -0x20, -0x13, -" ascii
      $s17 = "+ EA(-0x36, -0x47, -0x63, 0x1, -0x39, -0x2e, -0x1) + E6(-0x50, -0x47, -0x78, -0x6b, -0x14, -0x2b, -0x77) + EE(0x1ec, 0x233, 0x22" ascii
      $s18 = "89, -0x29d, -0x2ad, -0x294, -0x2ae)](R, Z['UJXkI']))) {" fullword ascii
      $s19 = "53, -0x172, -0x184, -0x154, -0x192, -0x1a4)]('counter');" fullword ascii
      $s20 = "t>5C>5CwINdoWs>22>29>29>2' + '0>7B>0D>0A>2F>' + '2FYhALZvBkf' + 'yGVcEPoHRNqI' + EE(0x210, 0x1ef, 0x221, 0x21b, 0x24b, 0x1f1, 0x" ascii
   condition:
      uint16(0) == 0x7566 and filesize < 80KB and
      1 of ($x*) and 4 of them
}

rule client32 {
   meta:
      description = "19438 - file client32.ini"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "bba34ad7183d7911f7f2c53bfe912d315d0e44d7aa0572963dc003d063130e85"
   strings:
      $s1 = "ValidAddresses.TCP=*" fullword ascii
      $s2 = "Filename=C:\\ProgramData\\SchCache\\client32u.ini" fullword ascii
      $s3 = "SecondaryPort=133" fullword ascii
      $s4 = "SecurityKey2=dgAAAJ8zaIwMzh8Mk59(swLsFIUA" fullword ascii
      $s5 = "Port=133" fullword ascii
      $s6 = "Usernames=*" fullword ascii
      $s7 = "[HTTP]" fullword ascii
      $s8 = "Protocols=2,3" fullword ascii
      $s9 = "DisableChatMenu=1" fullword ascii
      $s10 = "SKMode=1" fullword ascii
      $s11 = "quiet=1" fullword ascii
      $s12 = "DisableRequestHelp=1" fullword ascii
      $s13 = "DisableChat=1" fullword ascii
      $s14 = "HideWhenIdle=1" fullword ascii
      $s15 = "DisableAudioFilter=1" fullword ascii
      $s16 = "SysTray=0" fullword ascii
      $s17 = "DisableReplayMenu=1" fullword ascii
      $s18 = "DisableDisconnect=1" fullword ascii
      $s19 = "[_License]" fullword ascii
      $s20 = "GSK=FK;O@GCPGA:F=JBEGK<H@LEK:C?BDF" fullword ascii
   condition:
      uint16(0) == 0x7830 and filesize < 1KB and
      8 of them
}

rule client32u {
   meta:
      description = "19438 - file client32u.ini"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "aa92645428fb4c4e2cccbdf9b6acd7e6a51eecc2d6d63d7b8fe2e119e93c2bb5"
   strings:
      $s1 = "ValidAddresses.TCP=*" fullword ascii
      $s2 = "Passwordu=" fullword ascii
      $s3 = "Filename=C:\\ProgramData\\SchCache\\client32u.ini" fullword ascii
      $s4 = "SecondaryPort=133" fullword ascii
      $s5 = "Port=133" fullword ascii
      $s6 = "UsernamesU=*" fullword ascii
      $s7 = "SecurityKeyU=dgAAABrz4TvGMrqEdp4jnSqauXAA" fullword ascii
      $s8 = "[HTTP]" fullword ascii
      $s9 = "Protocols=2,3" fullword ascii
      $s10 = "DisableChatMenu=1" fullword ascii
      $s11 = "SKMode=1" fullword ascii
      $s12 = "quiet=1" fullword ascii
      $s13 = "DisableRequestHelp=1" fullword ascii
      $s14 = "DisableChat=1" fullword ascii
      $s15 = "HideWhenIdle=1" fullword ascii
      $s16 = "DisableAudioFilter=1" fullword ascii
      $s17 = "SysTray=0" fullword ascii
      $s18 = "DisableReplayMenu=1" fullword ascii
      $s19 = "DisableDisconnect=1" fullword ascii
      $s20 = "[_License]" fullword ascii
   condition:
      uint16(0) == 0x7830 and filesize < 1KB and
      8 of them
}

rule case_19438_files_MalFiles_NSM {
   meta:
      description = "19438 - file NSM.LIC"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "dc6a52ad6d637eb407cc060e98dfeedcca1167e7f62688fb1c18580dd1d05747"
   strings:
      $s1 = "transport=0" fullword ascii
      $s2 = "[_License]" fullword ascii
      $s3 = "[[Enforce]]" fullword ascii
      $s4 = "licensee=XMLCTL" fullword ascii
      $s5 = "serial_no=NSM303008" fullword ascii
      $s6 = "control_only=0" fullword ascii
      $s7 = "inactive=0" fullword ascii
      $s8 = "maxslaves=9999" fullword ascii
      $s9 = "product=10" fullword ascii
      $s10 = "shrink_wrap=0" fullword ascii
      $s11 = "expiry=01/01/2028" fullword ascii
   condition:
      uint16(0) == 0x3231 and filesize < 1KB and
      8 of them
}

rule case_19438_files_MalFiles_NSM_2 {
   meta:
      description = "19438 - file NSM.ini"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "60fe386112ad51f40a1ee9e1b15eca802ced174d7055341c491dee06780b3f92"
   strings:
      $s1 = ";          Controls whether the Tutor component is installed (1) on the target machine or not (Blank)" fullword ascii
      $s2 = ";          Controls whether the TechConsole component is installed (1) on the target machine or not (Blank)" fullword ascii
      $s3 = ";          Controls whether the gateway component is installation on the target machine (1) or not (Blank)" fullword ascii
      $s4 = ";          Controls whether the client component is installed (1) on the target machine or not (Blank)" fullword ascii
      $s5 = ";          Controls whether the control component is installed (1) on the target machine or not (Blank)" fullword ascii
      $s6 = ";          Controls whether the student component is installed (1) on the target machine or not (Blank)" fullword ascii
      $s7 = ";          Controls whether the PINServer component is installation on the target machine (1) or not (Blank)" fullword ascii
      $s8 = ";          Controls whether shortcut icons are placed on the target machine" fullword ascii
      $s9 = "; Scripting=<1/Blank>" fullword ascii
      $s10 = "Scripting=" fullword ascii
      $s11 = "; ScriptingIcon=<1/Blank>" fullword ascii
      $s12 = "   This is the StartMenu Items \"Script Agent\", \"Script Editor\" and \"Run Script\"" fullword ascii
      $s13 = ";          Controls whether the Scripting component is installed (1) or not (Blank)" fullword ascii
      $s14 = "ScriptingIcon=" fullword ascii
      $s15 = ";          Controls whether the student client configuration application is installed (1) on the target machine or not (Blank)" fullword ascii
      $s16 = ";          Controls whether the remote deployment application is installed on the target machine (1) or not (Blank)" fullword ascii
      $s17 = "; ConfigIcon=<1/Blank>" fullword ascii
      $s18 = "; Configurator=<1/Blank>" fullword ascii
      $s19 = ";          Controls whether shortcut icons for the control application (1) is placed on the target machine" fullword ascii
      $s20 = "; RemoteDeploy=<1/Blank>" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 20KB and
      8 of them
}

rule case_19438_files_MalFiles_HTCTL32 {
   meta:
      description = "19438 - file HTCTL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "3c072532bf7674d0c5154d4d22a9d9c0173530c0d00f69911cdbc2552175d899"
   strings:
      $s1 = "ReadSocket - Connection has been closed by peer" fullword ascii
      $s2 = "HTCTL32.dll" fullword ascii
      $s3 = "POST http://%s/fakeurl.htm HTTP/1.1" fullword ascii
      $s4 = "htctl32.dll" fullword wide
      $s5 = "CloseGatewayConnection - shutdown(%u) FAILED (%d)" fullword ascii
      $s6 = "CloseGatewayConnection - closesocket(%u) FAILED (%d)" fullword ascii
      $s7 = "putfile - _read FAILED (error: %d)" fullword ascii
      $s8 = "ReadSocket - Error %d reading response" fullword ascii
      $s9 = "ctl_adddomain - OpenGatewayConnection2 FAILED (%d)" fullword ascii
      $s10 = "NSM247Ctl.dll" fullword ascii
      $s11 = "pcictl_247.dll" fullword ascii
      $s12 = "User-Agent: NetSupport Manager/1.3" fullword ascii
      $s13 = "ReadMessage - missing or invalid content length" fullword ascii
      $s14 = "E:\\nsmsrc\\nsm\\1210\\1210f\\ctl32\\release\\htctl32.pdb" fullword ascii
      $s15 = "ctl_putfile - _topen FAILED (error: %d)" fullword ascii
      $s16 = "ctl_putfile - _filelength FAILED (error: %d)" fullword ascii
      $s17 = "TraceBuf - WriteFile failed (%d)" fullword ascii
      $s18 = "(Httputil.c) Error %d reading HTTP response header" fullword ascii
      $s19 = "ReadMessage - Unexpected result code in response \"%s\" " fullword ascii
      $s20 = "ctl_removeoperator - INVALID PARAMETER" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}


rule case_19438_files_MalFiles_PCICL32 {
   meta:
      description = "19438 - file PCICL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "38684adb2183bf320eb308a96cdbde8d1d56740166c3e2596161f42a40fa32d5"
   strings:
      $x1 = "AttemptLogon - Secur32.dll NOT found!!!" fullword ascii
      $x2 = "You do not have sufficient rights at Client %s to perform this operation. Log in as a different user or contact the Administrato" wide
      $x3 = "NWarning: attempt to login as user %s failed when reading configuration file %s(Error Loading Bridge: Command line error$Error l" wide
      $x4 = "LogonUserWithCert - Crypt32.dll NOT found!!!" fullword ascii
      $x5 = "AttemptLogon - Secur32.dll does not provide required functionality" fullword ascii
      $x6 = "cmd.exe /C start %s" fullword ascii
      $x7 = "Check9xLogon -  [bLoggedIn: %u] send command %d to connections" fullword ascii
      $x8 = "LogonUserWithCert - Advapi32.dll does NOT provide required functionality!" fullword ascii
      $x9 = "LogonUserWithCert - Crypt32.dll does NOT provide required functionality!" fullword ascii
      $s10 = "nsmexec.exe" fullword ascii
      $s11 = "Error. ExecProcessAsUser ret %d" fullword ascii
      $s12 = "c:\\program files\\common files\\microsoft shared\\ink\\tabtip.exe" fullword ascii
      $s13 = "sas.dll" fullword ascii /* reversed goodware string 'lld.sas' */
      $s14 = "DoNSMProtect - PASSWORDS DO NOT MATCH!!!" fullword ascii
      $s15 = "CreateMutex() FAILED - mutex: %s (%d)" fullword ascii
      $s16 = "WaitForSingleObject() FAILED - mutex: %s res: 0x%x (%d)" fullword ascii
      $s17 = "ReleaseMutex() FAILED - mutex: %s (%d)" fullword ascii
      $s18 = "\"cscript.exe\" %s -d  -p \"%s\"" fullword ascii
      $s19 = "\"cscript.exe\" %s -d -r %s" fullword ascii
      $s20 = "\"cscript.exe\" %s -a -p \"%s\" -m \"%s\" -r \"%s\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      1 of ($x*) and all of them
}

rule remcmdstub {
   meta:
      description = "19438 - file remcmdstub.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "fedd609a16c717db9bea3072bed41e79b564c4bc97f959208bfa52fb3c9fa814"
   strings:
      $s1 = "remcmdstub.exe" fullword wide
      $s2 = "Usage: %s (4 InheritableEventHandles) (CommandLineToSpawn)" fullword ascii
      $s3 = "NetSupport Remote Command Prompt" fullword wide
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s5 = "remcmdstub" fullword wide
      $s6 = "NetSupport Ltd0" fullword ascii
      $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s8 = "NetSupport Ltd1" fullword ascii
      $s9 = "NetSupport Ltd" fullword wide
      $s10 = "!Copyright (c) 2015 NetSupport Ltd" fullword wide
      $s11 = "Copyright (c) 2015, NetSupport Ltd" fullword wide
      $s12 = "NetSupport School" fullword wide
      $s13 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii
      $s14 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s15 = "Peterborough1" fullword ascii
      $s16 = "  </trustInfo>" fullword ascii
      $s17 = "7.848>8" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "uTVWh/Y@" fullword ascii
      $s19 = ";-;4;8;<;@;D;H;L;P;" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "<8<?<D<H<L<m<" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule case_19438_files_MalFiles_TCCTL32 {
   meta:
      description = "19438 - file TCCTL32.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "2b92ea2a7d2be8d64c84ea71614d0007c12d6075756313d61ddc40e4c4dd910e"
   strings:
      $s1 = "Openport - Bind failed, error %d, port %d, socket %d" fullword ascii
      $s2 = "*** %s %s Logic Error from %s (%s). next wanted (%x) already acked" fullword ascii
      $s3 = "UDP Retry Error. session %d inactive. now-recv = %d ms, dwNow - dwFrameTicks = %d ms" fullword ascii
      $s4 = "ctl_close - unclosed sessionz %dz, inuse=%d, skt=%d, flgs=x%x" fullword ascii
      $s5 = "INETMIB1.DLL" fullword ascii
      $s6 = "*** %s %s Logic Error from %s (%s). next wanted must be in nacks" fullword ascii
      $s7 = "TCCTL32.dll" fullword ascii
      $s8 = "tcctl32.dll" fullword wide
      $s9 = "Error: UDP Packet incomplete - %d cf %d" fullword ascii
      $s10 = "*** Error. ctl_read overflow of %d ***" fullword ascii
      $s11 = "GetHostInfo.hThread" fullword ascii
      $s12 = "Error. Terminating GetHostByName thread" fullword ascii
      $s13 = "PCICAPI.DLL" fullword ascii
      $s14 = "E:\\nsmsrc\\nsm\\1210\\1210f\\ctl32\\release\\tcctl32.pdb" fullword ascii
      $s15 = "*** %s %s Logic Error from %s (%s). Ack %x cannot be next wanted" fullword ascii
      $s16 = "Error: UDP Packet too long - %d cf %d" fullword ascii
      $s17 = "%s %dz inactive. now-recv = %d ms, dwNow - dwFrameTicks = %d ms" fullword ascii
      $s18 = "Error. UDP frame received on unknown input stream, Socket %d, Control %s, Control Port %d" fullword ascii
      $s19 = "*** %s %s End Udp %s, Client receive stats to follow ***" fullword ascii
      $s20 = "*** %s %s Start Udp %s, wireless=%d ***" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule case_19438_files_MalFiles_pcicapi {
   meta:
      description = "19438 - file pcicapi.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "2d6c6200508c0797e6542b195c999f3485c4ef76551aa3c65016587788ba1703"
   strings:
      $s1 = "CAPI2032.DLL" fullword ascii
      $s2 = "pcicapi.dll" fullword wide
      $s3 = "Assert failed - " fullword ascii
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s5 = "E:\\nsmsrc\\nsm\\1210\\1210\\ctl32\\Release\\pcicapi.pdb" fullword ascii
      $s6 = "Received unexpected CAPI message, command=%x, plci=%d, ncci=%d" fullword ascii
      $s7 = "Unhandled Exception (GPF) - " fullword ascii
      $s8 = "NSMTraceGetConfigItem" fullword ascii
      $s9 = "NSMTraceGetConfigInt" fullword ascii
      $s10 = "File %hs, line %d%s%s" fullword ascii
      $s11 = "NSMTraceReadConfigItemFromFile" fullword ascii
      $s12 = "Assert, tid=%x%s" fullword ascii
      $s13 = "!\"Could not stop CAPI GetMsgThread\"" fullword ascii
      $s14 = ", thread=%s" fullword ascii
      $s15 = "NetSupport Ltd0" fullword ascii
      $s16 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s17 = "Support\\" fullword ascii
      $s18 = ", error code %u (x%x)" fullword ascii
      $s19 = "NetSupport Ltd1" fullword ascii
      $s20 = "NetSupport Ltd" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule case_19438_files_MalFiles_mswow86 {
   meta:
      description = "19438 - file mswow86.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "4d24b359176389301c14a92607b5c26b8490c41e7e3a2abbc87510d1376f4a87"
   strings:
      $s1 = "PCICL32.dll" fullword ascii
      $s2 = "client32.exe" fullword wide
      $s3 = "E:\\nsmsrc\\nsm\\1210\\1210\\client32\\Release\\client32.pdb" fullword ascii
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s5 = "7===>==>=>=>==>==>=>C" fullword ascii /* hex encoded string '|' */
      $s6 = "7>=>>>>>>=>>>>>>>>>>E" fullword ascii /* hex encoded string '~' */
      $s7 = "NetSupport Remote Control" fullword wide
      $s8 = "NetSupport Ltd0" fullword ascii
      $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s10 = "NetSupport Ltd1" fullword ascii
      $s11 = "NetSupport Ltd" fullword wide
      $s12 = "!Copyright (c) 2015 NetSupport Ltd" fullword wide
      $s13 = "Copyright (c) 2015, NetSupport Ltd" fullword wide
      $s14 = "SLLQLOSL" fullword ascii
      $s15 = "Peterborough1" fullword ascii
      $s16 = "client32" fullword wide
      $s17 = "  </trustInfo>" fullword ascii
      $s18 = "_NSMClient32@8" fullword ascii
      $s19 = "TLDW*3S.*" fullword ascii
      $s20 = "NetSupport Client Application" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule case_19438_files_MalFiles_PCICHEK {
   meta:
      description = "19438 - file PCICHEK.DLL"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "956b9fa960f913cce3137089c601f3c64cc24c54614b02bba62abb9610a985dd"
   strings:
      $s1 = "pcichek.dll" fullword wide
      $s2 = "E:\\nsmsrc\\nsm\\1210\\1210f\\ctl32\\Full\\pcichek.pdb" fullword ascii
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s4 = "The %s license file (NSM.LIC) has been hacked.  Action is being taken against the perpetrators.  Please use the evaluation versi" wide
      $s5 = "This is an evaluation copy of %s and can only be used with an evaluation license file (NSM.LIC).  Please contact your vendor for" wide
      $s6 = "654321" ascii /* reversed goodware string '123456' */
      $s7 = "4%4.4A4^4" fullword ascii /* hex encoded string 'DJD' */
      $s8 = "pcichek" fullword wide
      $s9 = "NetSupport Ltd0" fullword ascii
      $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s11 = "NetSupport Ltd1" fullword ascii
      $s12 = "!Copyright (c) 2016 NetSupport Ltd" fullword wide
      $s13 = "NetSupport Ltd" fullword wide
      $s14 = "Copyright (c) 2016, NetSupport Ltd" fullword wide
      $s15 = "NetSupport Manager" fullword wide
      $s16 = "NetSupport pcichek" fullword wide
      $s17 = "!!!!:23/09/16 15:51:38 V12.10F18" fullword ascii
      $s18 = "Peterborough1" fullword ascii
      $s19 = "  </trustInfo>" fullword ascii
      $s20 = "CheckLicenseString" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

rule pth_addadmin {
   meta:
      description = "19438 - file pth_addadmin.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "3bee705c062227dcb2d109bf62ab043c68ba3fb53b1ce679dc138273ba884b08"
   strings:
      $s1 = "@[+] Command executed" fullword ascii
      $s2 = "33333337333333" ascii /* reversed goodware string '33333373333333' */ /* hex encoded string '3337333' */
      $s3 = "@Command executed with service" fullword ascii
      $s4 = "SMBExecCommandLengthBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_56" fullword ascii
      $s5 = "SMBExecCommandBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_55" fullword ascii
      $s6 = "SMBExecCommand__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_54" fullword ascii
      $s7 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2.nim.c" fullword ascii
      $s8 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2Helper.nim.c" fullword ascii
      $s9 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSCM.nim.c" fullword ascii
      $s10 = "@The user does not have Service Control Manager write privilege on the target" fullword ascii
      $s11 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sExecStages.nim.c" fullword ascii
      $s12 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sRPC.nim.c" fullword ascii
      $s13 = "@Trying to execute command on the target" fullword ascii
      $s14 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sNTLM.nim.c" fullword ascii
      $s15 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sHelpUtil.nim.c" fullword ascii
      $s16 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec.nim.c" fullword ascii
      $s17 = "@The user has Service Control Manager write privilege on the target" fullword ascii
      $s18 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv1.nim.c" fullword ascii
      $s19 = "@Bcrypt.dll" fullword ascii
      $s20 = "@Service creation failed on target" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule pth_createuser {
   meta:
      description = "19438 - file pth_createuser.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "e42620721f5ec455a63cded483d18dfa5abdabca3319b0a4e3e21bd098348d48"
   strings:
      $s1 = "@[+] Command executed" fullword ascii
      $s2 = "33333337333333" ascii /* reversed goodware string '33333373333333' */ /* hex encoded string '3337333' */
      $s3 = "@Command executed with service" fullword ascii
      $s4 = "SMBExecCommandLengthBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_56" fullword ascii
      $s5 = "SMBExecCommandBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_55" fullword ascii
      $s6 = "SMBExecCommand__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_54" fullword ascii
      $s7 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2.nim.c" fullword ascii
      $s8 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2Helper.nim.c" fullword ascii
      $s9 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSCM.nim.c" fullword ascii
      $s10 = "@The user does not have Service Control Manager write privilege on the target" fullword ascii
      $s11 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sExecStages.nim.c" fullword ascii
      $s12 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sRPC.nim.c" fullword ascii
      $s13 = "@Trying to execute command on the target" fullword ascii
      $s14 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sNTLM.nim.c" fullword ascii
      $s15 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sHelpUtil.nim.c" fullword ascii
      $s16 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec.nim.c" fullword ascii
      $s17 = "@The user has Service Control Manager write privilege on the target" fullword ascii
      $s18 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv1.nim.c" fullword ascii
      $s19 = "@Bcrypt.dll" fullword ascii
      $s20 = "@Service creation failed on target" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}


rule case_19438_files_MalFiles_install {
   meta:
      description = "19438 - file install.bat"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "041b0504742449c7c23750490b73bc71e5c726ad7878d05a73439bd29c7d1d19"
   strings:
      $x1 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Key Exchange\" /rl highest /tr \"%programdata%\\sshd\\ssh.exe -i %programdata%" ascii
      $x2 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Key Exchange\" /rl highest /tr \"%programdata%\\sshd\\ssh.exe -i %programdata%" ascii
      $x3 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Server\" /rl highest  /tr \"%programdata%\\sshd\\sshd.exe -f %programdata%\\sshd" ascii
      $x4 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Server\" /rl highest  /tr \"%programdata%\\sshd\\sshd.exe -f %programdata%\\sshd" ascii
      $s5 = "onfig\\keys\\id_rsa -N -R 369:127.0.0.1:2222 root@185.206.146.129 -o StrictHostKeyChecking=no -o ServerAliveInterval=60 -o Serve" ascii
      $s6 = "ssh-keygen -f %programdata%\\sshd\\config\\id_rsa -t rsa  -N \"\"" fullword ascii
      $s7 = "icacls %programdata%\\sshd\\config\\keys\\id_rsa /grant:r \"%username%\":\"(R)\"" fullword ascii
      $s8 = "icacls %programdata%\\sshd\\config\\id_rsa /grant:r \"%username%\":\"(R)\"" fullword ascii
      $s9 = "icacls %programdata%\\sshd\\config\\keys\\id_rsa /inheritance:r" fullword ascii
      $s10 = "icacls %programdata%\\sshd\\config\\id_rsa /inheritance:r" fullword ascii
      $s11 = "g\\sshd_config\"" fullword ascii
      $s12 = "liveCountMax=15\"" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 2KB and
      1 of ($x*) and all of them
}

rule nskbfltr {
   meta:
      description = "19438 - file nskbfltr.inf"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "d96856cd944a9f1587907cacef974c0248b7f4210f1689c1e6bcac5fed289368"
   strings:
      $s1 = ";--- nskbfltr Coinstaller installation ------" fullword ascii
      $s2 = "; This inf file installs the WDF Framework binaries" fullword ascii
      $s3 = "KmdfService = nskbfltr, nskbfltr_wdfsect" fullword ascii
      $s4 = "KmdfLibraryVersion = 1.5" fullword ascii
      $s5 = "; NS Keyboard Filter" fullword ascii
      $s6 = "; nskbfltr.inf" fullword ascii
      $s7 = "[nskbfltr.NT.Wdf]" fullword ascii
      $s8 = "[nskbfltr_wdfsect]" fullword ascii
      $s9 = "Provider=NSL" fullword ascii
   condition:
      uint16(0) == 0x203b and filesize < 1KB and
      all of them
}


rule case_19438_files_MalFiles_ntds {
   meta:
      description = "19438 - file ntds.bat"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "060e9ff09cd97ec6a1b614dcc1de50f4d669154f59d78df36e2c4972c2535714"
   strings:
      $s1 = "powershell \"ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\\ProgramData\\ntdsutil' q q\"" fullword ascii
   condition:
      uint16(0) == 0x6f70 and filesize < 1KB and
      all of them
}

rule case_19438_files_MalFiles_start {
   meta:
      description = "19438 - file start.bat"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
      date = "2023-10-29"
      hash1 = "4c0736c9a19c2e172bb504556f7006fa547093b79a0a7e170e6412f98137e7cd"
   strings:
      $s1 = "pingcastle.exe --healthcheck --level Full > process.log 2>&1" fullword ascii
      $s2 = "cd C:\\ProgramData\\" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2024-02-18
   Identifier: Case 19530
   Reference: https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule case_19530_implied_employment_agreement {
   meta:
      description = "file implied employment agreement 24230.js"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/"
      date = "2024-02-18"
      hash1 = "f94048917ac75709452040754bb3d1a0aff919f7c2b4b42c5163c7bdb1fbf346"
   strings:
      $s1 = "dx = Math.pow(10, Math.round(Math.log(dx) / Math.LN10) - 1);" fullword ascii
      $s2 = "return -Math.log(-x) / Math.LN10;" fullword ascii
      $s3 = "return d3.format(\",.\" + Math.max(0, -Math.floor(Math.log(d3_scale_linearTickRange(domain, m)[2]) / Math.LN10 + .01)) + \"f\");" ascii
      $s4 = "var n = 1 + Math.floor(1e-15 + Math.log(x) / Math.LN10);" fullword ascii
      $s5 = "for (i = 0, n = q.length; (m = d3_interpolate_number.exec(a)) && i < n; ++i) {" fullword ascii
      $s6 = "* - Redistributions in binary form must reproduce the above copyright notice," fullword ascii
      $s7 = "* - Neither the name of the author nor the names of contributors may be used to" fullword ascii
      $s8 = "thresholds.length = Math.max(0, q - 1);" fullword ascii
      $s9 = "* Brewer (http://colorbrewer.org/). See lib/colorbrewer for more information." fullword ascii
      $s10 = "chord.target = function(v) {" fullword ascii
      $s11 = "diagonal.target = function(x) {" fullword ascii
      $s12 = "return c.charAt(c.length - 1) === \"%\" ? Math.round(f * 2.55) : f;" fullword ascii
      $s13 = "return Math.log(x) / Math.LN10;" fullword ascii
      $s14 = "step = Math.pow(10, Math.floor(Math.log(span / m) / Math.LN10))," fullword ascii
      $s15 = "var match = d3_format_re.exec(specifier)," fullword ascii
      $s16 = "m1 = /([a-z]+)\\((.*)\\)/i.exec(format);" fullword ascii
      $s17 = "for (i = 0; m = d3_interpolate_number.exec(b); ++i) {" fullword ascii
      $s18 = "* TERMS OF USE - EASING EQUATIONS" fullword ascii
      $s19 = "var d3_mouse_bug44083 = /WebKit/.test(navigator.userAgent) ? -1 : 0;" fullword ascii
      $s20 = "* - Redistributions of source code must retain the above copyright notice, this" fullword ascii
   condition:
      uint16(0) == 0x6628 and filesize < 400KB and
      8 of them
}

rule case_19530_systembc_s5 {
   meta:
      description = "file s5.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/"
      date = "2024-02-18"
      hash1 = "49b75f4f00336967f4bd9cbccf49b7f04d466bf19be9a5dec40d0c753189ea16"
   strings:
      $x1 = "Set-ItemProperty -Path $path_reg -Name \"socks_powershell\" -Value \"Powershell.exe -windowstyle hidden -ExecutionPolicy Bypass " ascii
      $x2 = "Set-ItemProperty -Path $path_reg -Name \"socks_powershell\" -Value \"Powershell.exe -windowstyle hidden -ExecutionPolicy Bypass " ascii
      $s3 = "Remove-ItemProperty -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" -Name \"socks_powershell\"" fullword ascii
      $s4 = "$end = [int](Get-Date -uformat \"%s\")" fullword ascii
      $s5 = "$st = [int](Get-Date -uformat \"%s\")" fullword ascii
      $s6 = "$path_reg = \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"" fullword ascii
      $s7 = "$sArray[0] = New-Object System.Net.Sockets.TcpClient( $ipaddress, $dport)" fullword ascii
      $s8 = "$sArray[$perem2] = New-Object System.Net.Sockets.TcpClient( $ip, $newport)" fullword ascii
      $s9 = "[string]$ip = [System.Text.Encoding]::ASCII.GetString($fB)" fullword ascii
      $s10 = "$ipaddress = '91.92.136.20'" fullword ascii
      $s11 = "$rc1 = [math]::Floor(($rc -band 0x0000ff00) * [math]::Pow(2,-8))" fullword ascii
      $s12 = "$o1 = [math]::Floor(($os -band 0x0000ff00) * [math]::Pow(2,-8))" fullword ascii
      $s13 = "$Time = $end - $st" fullword ascii
      $s14 = "elseif ($bf0[4 + 3] -eq 0x01 -as[byte])" fullword ascii
      $s15 = "$buff0[$start + $perem3] = $perem5 -as [byte]" fullword ascii
      $s16 = "Start-Sleep -s 180" fullword ascii
      $s17 = "[string]$ip = \"{0}.{1}.{2}.{3}\" -f $a, $b, $c, $ip" fullword ascii
      $s18 = "For ($i=0; $i -ne $perem9; $i++) { $bf0[$i + $perem0] = $rb[$i + $perem11] }" fullword ascii
      $s19 = "if ($bf0[2 + 0] -eq 0x00 -as[byte] -and $bf0[2 + 1] -eq 0x00 -as[byte])" fullword ascii
      $s20 = "if ($bf0[0 + 0] -eq 0x00 -as[byte] -and $bf0[0 + 1] -eq 0x00 -as[byte])" fullword ascii
   condition:
      uint16(0) == 0x7824 and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule case_19530_CS_beacon {
   meta:
      description = "file 5d78365.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/"
      date = "2024-02-18"
      hash1 = "aad75498679aada9ee2179a8824291e3b4781d5683c2fa5b3ec92267ce4a4a33"
   strings:
      $s1 = "%c%c%c%c%c%c%c%c%cnetsvc\\%d" fullword ascii
      $s2 = "WinHttpSvc" fullword ascii
      $s3 = "+  cl_+" fullword ascii
      $s4 = "lsxkrb" fullword ascii
      $s5 = "vDqPSzK6" fullword ascii
      $s6 = ":b(l%h%" fullword ascii
      $s7 = "lszkrb" fullword ascii
      $s8 = "10.0.19041.1266 (WinBuild.160101.0800)" fullword wide
      $s9 = "sMgJkl?sW" fullword ascii
      $s10 = "@}0.Fpn" fullword ascii
      $s11 = "dwPS@%oNB" fullword ascii
      $s12 = "RRcB(jE" fullword ascii
      $s13 = "Rwco)pS" fullword ascii
      $s14 = "cxjI6NB" fullword ascii
      $s15 = "rgNg(>P" fullword ascii
      $s16 = "jawXX_3" fullword ascii
      $s17 = "xSsckrb" fullword ascii
      $s18 = "{uaNB,Pe|K" fullword ascii
      $s19 = "DwcR+dS" fullword ascii
      $s20 = "YwcH*gC" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      ( pe.imphash() == "49145e436aa571021bb1c7b727f8b049" or 8 of them )
}


/*
   YARA Rule Set
   Author: TheDFIRReport
   Date: 2024-01-09
   Identifier: Case 19772
   Reference: https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion
*/

/* Rule Set ----------------------------------------------------------------- */

rule case_19772_csrss_cobalt_strike {
   meta:
      description = "19772 - file csrss.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion"
      date = "2024-01-09"
      hash1 = "06bbb36baf63bc5cb14d7f097745955a4854a62fa3acef4d80c61b4fa002c542"
   strings:
      $x1 = "Invalid owner %s is already associated with %s=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide
      $s2 = "traydemo.exe" fullword ascii
      $s3 = "333330303030333333" ascii /* hex encoded string '330000333' */
      $s4 = "323232323233323232323233333333333333" ascii /* hex encoded string '222223222223333333' */
      $s5 = "333333333333333333333333333333333333333333333333333333333333333333333333" ascii /* hex encoded string '333333333333333333333333333333333333' */
      $s6 = "Borland C++ - Copyright 2002 Borland Corporation" fullword ascii
      $s7 = "@Cdiroutl@TCDirectoryOutline@GetChildNamed$qqrrx17System@AnsiStringl" fullword ascii
      $s8 = "2a1d2V1p1" fullword ascii /* base64 encoded string 'kWvWZu' */
      $s9 = "Separator\"Unable to find a Table of Contents" fullword wide
      $s10 = "EInvalidGraphicOperation4" fullword ascii
      $s11 = ")Failed to read ImageList data from stream(Failed to write ImageList data to stream$Error creating window device context" fullword wide
      $s12 = "%s: %s error" fullword ascii
      $s13 = "@TTrayIcon@GetAnimate$qqrv" fullword ascii
      $s14 = "ImageTypeh" fullword ascii
      $s15 = "42464:4`4d4 3" fullword ascii /* hex encoded string 'BFDMC' */
      $s16 = "333333333333333333333333(" fullword ascii /* hex encoded string '333333333333' */
      $s17 = ")\"\")\"\")#3232" fullword ascii /* hex encoded string '22' */
      $s18 = "OnGetItem(3B" fullword ascii
      $s19 = "@Cspin@TCSpinEdit@GetValue$qqrv" fullword ascii
      $s20 = "@Cspin@TCSpinButton@GetUpGlyph$qqrv" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule case_19772_svchost_nokoyawa_ransomware {
   meta:
      description = "19772 - file svchost.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion"
      date = "2024-01-09"
      hash1 = "3c9f4145e310f616bd5e36ca177a3f370edc13cf2d54bb87fe99972ecf3f09b4"
   strings:
      $s1 = " ;3;!X" fullword ascii /* reversed goodware string 'X!;3; ' */
      $s2 = "bcdedit" fullword wide
      $s3 = "geKpgAX3" fullword ascii
      $s4 = "shutdown" fullword wide /* Goodware String - occured 93 times */
      $s5 = "k2mm7KvHl51n2LJDYLanAgM48OX97gkV" fullword ascii
      $s6 = "+TDPbuWCWNmcW0k=" fullword ascii
      $s7 = "4vEBlUlgJ5oeqmbpb9OSaQrQb8bRWNqP" fullword ascii
      $s8 = "2aDXUPxh3ZZ1x8tpfg6PxcMuUwWogOgQ" fullword ascii
      $s9 = "kfeCWydRqz8=" fullword ascii
      $s10 = "ZfrMxxDy" fullword ascii
      $s11 = "eLTuGYHd" fullword ascii
      $s12 = "wWIQZ5jJPZIiuDKxQVh0YO3HnzdOwirY" fullword ascii
      $s13 = "+IdWS+zG9rUG" fullword ascii
      $s14 = "0ZdUoZmp" fullword ascii
      $s15 = "SVWh$l@" fullword ascii
      $s16 = "Z2mJzxHFaRafgf4k/uTdeMKIMUpV/y81" fullword ascii
      $s17 = "GtKqGSOfNUOVIoMTk8bGZVchMddKIuTN" fullword ascii
      $s18 = "INMvjo3GzuQ6MTSJUg==" fullword ascii
      $s19 = "hilWGBcFwE80e5L9BXxCiRiE" fullword ascii
      $s20 = "gSMSrcOR" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      8 of them
}

rule case_19772_anydesk_id_tool {
   meta:
      description = "19772 - file GET_ID.bat"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion"
      date = "2024-01-09"
      hash1 = "eae2bce6341ff7059b9382bfa0e0daa337ea9948dd729c0c1e1ee9c11c1c0068"
   strings:
      $x1 = "for /f \"delims=\" %%i in ('C:\\ProgramData\\Any\\AnyDesk.exe --get-id') do set ID=%%i " fullword ascii
      $s2 = "echo AnyDesk ID is: %ID%" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule case_19772_anydesk_installer {
   meta:
      description = "19772 - file INSTALL.ps1"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion"
      date = "2024-01-09"
      hash1 = "b378c2aa759625de2ad1be2c4045381d7474b82df7eb47842dc194bb9a134f76"
   strings:
      $x1 = "    cmd.exe /c echo btc1000qwe123 | C:\\ProgramData\\Any\\AnyDesk.exe --set-password" fullword ascii
      $x2 = "    cmd.exe /c C:\\ProgramData\\AnyDesk.exe --install C:\\ProgramData\\Any --start-with-win --silent" fullword ascii
      $s3 = "    #reg add \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\" /v Inn" ascii
      $s4 = "    #reg add \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\" /v Inn" ascii
      $s5 = "    $url = \"http://download.anydesk.com/AnyDesk.exe\"" fullword ascii
      $s6 = "EG_DWORD /d 0 /f" fullword ascii
      $s7 = "    $file = \"C:\\ProgramData\\AnyDesk.exe\"" fullword ascii
      $s8 = "    $clnt = new-object System.Net.WebClient" fullword ascii
      $s9 = "    #net user AD \"2020\" /add" fullword ascii
      $s10 = "    # Download AnyDesk" fullword ascii
      $s11 = "    mkdir \"C:\\ProgramData\\Any\"" fullword ascii
      $s12 = "    $clnt.DownloadFile($url,$file)" fullword ascii
      $s13 = "    #net localgroup Administrators InnLine /ADD" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 1KB and
      1 of ($x*) and 4 of them
}

rule mal_truebot: TESTING MALWARE TA0002 T1027 T1204_002 {
    meta:
        id = "2snLTJeZ4eKhhGLfWNM6NV"
        fingerprint = "03f4fb857eaf63b4ce33611cce6c9f06e57180c122d28305bc7d7d2cb839ef27"
        version = "1.0"
        creation_date = "2023-05-25"
        first_imported = "2023-05-25"
        last_modified = "2023-05-25"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THEDFIRREPORT.COM"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects strings commonly related to TrueBot functionality"
        category = "MALWARE"
        malware = "TRUEBOT"
        mitre_att = "T1204.002"
        reference = "https://thedfirreport.com/"
        hash = "717beedcd2431785a0f59d194e47970e9544fbf398d462a305f6ad9a1b1100cb"

    strings:
        $c2_params_1        = "n=%s&o=%s&a=%d&u=%s&p=%s&d=%s" fullword
        $c2_params_2        = "n=%s&l=%s"   fullword
        $c2_id              = "%08x-%08x"   fullword
        $c2_status          = "Not Found"   fullword
        $c2_method          = "POST "       fullword
        $c2_proto           = "HTTP/1.0"    fullword
        $c2_header_host     = "Host: "      fullword
        $c2_header_ct       = "Content-type: application/x-www-form-urlencoded" fullword
        $other_workgroup    = "WORKGROUP"           fullword
        $other_unknown      = "UNKW"                fullword
        $load_perms         = "SeDebugPrivilege"    fullword
        $load_library       = "user32"              fullword wide
        $load_import        = "RtlCreateUserThread" fullword
        $cmd_del            = "/c del" fullword wide

    condition:
        13 of them
}

rule sus_nsis_tampered_signature: TESTING SUSPICIOUS TA0005 T1027 T1027_005 {
    meta:
        id = "7tGWOPTZRLhRAMCf6cQC0"
        fingerprint = "082b47efe4dbb5ff515f2db759233fc39238bf4982aa0884b809232686c49531"
        version = "1.0"
        creation_date = "2023-06-01"
        first_imported = "2023-06-01"
        last_modified = "2023-06-01"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THEDFIRREPORT.COM"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects a suspected Nullsoft Scriptable Install System (NSIS) executable with a tampered compiler signature"
        category = "TOOL"
        tool = "NSIS"
        mitre_att = "T1027.005"
        reference = "https://thedfirreport.com/"
        hash = "121a1f64fff22c4bfcef3f11a23956ed403cdeb9bdb803f9c42763087bd6d94e"

    strings:
        $brand_error       = "NSIS Error"                      fullword
        $brand_description = "Nullsoft Install System"         fullword
        $brand_name        = "Nullsoft.NSIS"                   fullword 
        $brand_url         = "http://nsis.sf.net/NSIS_Error"   fullword
        $code_get_module        = {
            C1 E6 03            // shl     esi, 3
            8B BE ?? ?? ?? ??   // mov     edi, Modules[esi]
            57                  // push    edi             ; lpModuleName
            FF 15 ?? ?? ?? ??   // call    ds:GetModuleHandleA
            85 C0               // test    eax, eax
            75 ??               // jnz     ??
        }
        $code_get_proc          = {
            FF B6 ?? ?? ?? ??   // push    Procedures[esi]
            50                  // push    eax             ; hModule
            FF 15 ?? ?? ?? ??   // call    ds:__imp_GetProcAddress
            EB ??               // jmp     ??
        }
        $code_jump_table        = {
            8B 4D ??                // mov     ecx, [ebp+??]
            83 C1 ??                // add     ecx, 0FFFFFF??h ; switch ?? cases
            83 F9 ??                // cmp     ecx, ??h
            0F 87 ?? ?? 00 00       // ja      ??      ; jumptable ?? default case, cases 65,66
            FF 24 8D ?? ?? ?? 00    // jmp     ds:??[ecx*4] ; switch jump
        }
        $signature_1_00         = {EF BE AD DE 6E 73 69 73 69 6E 73 74 61 6C 6C 00}
        $signature_1_00_check   = {
            81 7D ?? EF BE AD DE    // cmp     [ebp+??], 0DEADBEEFh
            75 ??                   // jnz     short ??
            81 7D ?? 61 6C 6C 00    // cmp     [ebp+??], 06C6C61h
            75 ??                   // jnz     short ??
            81 7D ?? 69 6E 73 74    // cmp     [ebp+var_1C], 74736E69h
            75 ??                   // jnz     short ??
            81 7D ?? 6E 73 69 73    // cmp     [ebp+??], 7369736Eh
            75 ??                   // jnz     ??
        }
        $signature_1_1e         = {ED BE AD DE 4E 75 6C 6C 53 6F 66 74 49 6E 73 74}
        $signature_1_1e_check   = {
            81 7D ?? ED BE AD DE    // cmp     [ebp+??], 0DEADBEEDh
            75 ??                   // jnz     short ??
            81 7D ?? 49 6E 73 74    // cmp     [ebp+??], 74736E49h
            75 ??                   // jnz     short ??
            81 7D ?? 53 6F 66 74    // cmp     [ebp+var_1C], 74666F53h
            75 ??                   // jnz     short ??
            81 7D ?? 4E 75 6C 6C    // cmp     [ebp+??], 6C6C754Eh
            75 ??                   // jnz     ??
        }
        $signature_1_30         = {EF BE AD DE 4E 75 6C 6C 53 6F 66 74 49 6E 73 74}
        $signature_1_30_check   = {
            81 7D ?? EF BE AD DE    // cmp     [ebp+??], 0DEADBEEFh
            75 ??                   // jnz     short ??
            81 7D ?? 49 6E 73 74    // cmp     [ebp+??], 74736E49h
            75 ??                   // jnz     short ??
            81 7D ?? 53 6F 66 74    // cmp     [ebp+var_1C], 74666F53h
            75 ??                   // jnz     short ??
            81 7D ?? 4E 75 6C 6C    // cmp     [ebp+??], 6C6C754Eh
            75 ??                   // jnz     ??
        }
        $signature_1_60         = {EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74}
        $signature_1_60_check   = {
            81 7D ?? EF BE AD DE    // cmp     [ebp+??], 0DEADBEEFh
            75 ??                   // jnz     short ??
            81 7D ?? 49 6E 73 74    // cmp     [ebp+??], 74736E49h
            75 ??                   // jnz     short ??
            81 7D ?? 73 6F 66 74    // cmp     [ebp+var_1C], 74666F73h
            75 ??                   // jnz     short ??
            81 7D ?? 4E 75 6C 6C    // cmp     [ebp+??], 6C6C754Eh
            75 ??                   // jnz     ??
        }

    condition:
        uint16(0) == 0x5A4D and (3 of ($brand_*) or 2 of ($code_*)) and none of ($signature_*)
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2024-04-23
Identifier: Case 23869
Reference: https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/
*/

/* Rule Set ----------------------------------------------------------------- */

rule case_23869_sysfunc_cmd {
	meta:
		creation_date = "2024-03-29"
		first_imported = "2024-03-29"
		last_modified = "2024-03-29"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "File generated dynamically from awscollector.ps1"
		category = "TOOL"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "f3b211c45090f371869c396716972429896e0427da55ce8f1981787c2ea7eb0b"

	strings:
		$s1 = "@echo off" fullword
		$s2 = "DEL \"%~f0\"" fullword
		$s3 = "bcedit /set {default] bootstatuspolicy ignorereallifefailures" fullword
		$s4 = "bcedit /set {default] recoveryenabled no" fullword
		$s5 = "vssadmin delete shadows /all /quiet" fullword
		$s6 = "wmic shadowcopy /nointeractive" fullword
		$s7 = "wmic shadowcopy delete" fullword

	condition:
		all of them
}

rule case_23869_awscollector_ps1 {
	meta:
		creation_date = "2024-03-29"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "awscollector.ps1"
		category = "TOOL"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "e737831bea7ab9e294bf6b58ca193ba302b8869f5405aa6d3a6492d0334a04a6"

	strings:
		$author = "darussian@tutanota.com" fullword
		$s1 = "Locker" fullword
		$s2 = "Find-Remote-Executor" fullword
		$s3 = "lockerparams" fullword
		$s4 = "locker_cmd_list" fullword
		$s5 = "AWSCLIV2" fullword

	condition:
		$author or ( all of ($s*) )
}

rule case_23869_sysfunc_dll {
	meta:
		creation_date = "2024-03-29"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "Description"
		category = "TOOL"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "b3942ead0bf76cf5f4baaa563b603fb6343009c324e3c862d16bbbbdcf482f1a"

	strings:
		$s1 = "gentlemen" fullword
		$s2 = "withdraw fang" fullword
		$s3 = "plants; mould, sympathize, elephant; associate" fullword
		$s4 = "blessing, defender; fashionable" fullword
		$s5 = "withdraw fang" fullword

	condition:
		all of them
}

rule case_23869_document_468 {
	meta:
		creation_date = "2024-03-30"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "iceid loader"
		category = "MALWARE"
		malware = "iceid_loader"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "f6e5dbff14ef272ce07743887a16decbee2607f512ff2a9045415c8e0c05dbb4"

	strings:
		$s1 = "quisquamEtVeniamOccaecati" fullword
		$s2 = "temporaImpeditQuiPraesentiumEligendiOptio" fullword
		$s3 = "fugiatSaepeQuiaPorroExplicaboExercitationemMaiores" fullword

	condition:
		all of them
}


rule case_23869_anydesk_ps1 {
	meta:
		creation_date = "2024-03-30"
		status = "TESTING"
		sharing = "TLP:WHITE"
		source = "THEDFIRREPORT.COM"
		author = "TDR"
		description = "anydesk install powershell script"
		category = "TOOL"
		malware = "anydesk"
		reference = "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/"
		hash = "3064cecf8679d5ba1d981d6990058e1c3fae2846b72fa77acad6ab2b4f582dd7"

	strings:
		$s1 = "J9kzQ2Y0qO" fullword
		$s2 = "oldadministrator" fullword
		$s3 = "qc69t4B#Z0kE3" fullword
		$s4 = "anydesk.com"

	condition:
		all of them
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-04-27
Identifier: Case 3521 Trickbot Brief: Creds and Beacons
Reference: https://thedfirreport.com/2021/05/02/trickbot-brief-creds-and-beacons/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule click_php {
meta:
description = "files - file click.php.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-04-27"
hash1 = "0ae86e5abbc09e96f8c1155556ca6598c22aebd73acbba8d59f2ce702d3115f8"
strings:
$s1 = "f_+ (Q" fullword wide
$s2 = "'/l~;2m" fullword wide
$s3 = "y'L])[" fullword wide
$s4 = "1!1I1m1s1" fullword ascii
$s5 = "&+B\"wm" fullword wide
$s6 = ">jWR=C" fullword wide
$s7 = "W!\\R.S" fullword wide
$s8 = "r-`4?b6" fullword wide
$s9 = "]Iip!x" fullword wide
$s10 = "!k{l`<" fullword wide
$s11 = "D~C:RA" fullword wide
$s12 = "]{T~as" fullword wide
$s13 = "7%8+8^8" fullword ascii
$s14 = "f]-hKa" fullword wide
$s15 = "StartW" fullword ascii /* Goodware String - occured 5 times */
condition:
uint16(0) == 0x5a4d and filesize < 1000KB and
( pe.imphash() == "8948fb754b7c37bc4119606e044f204c" and pe.exports("StartW") or 10 of them )
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-06-03
Identifier: Case 3580 WebLogic RCE Leads to XMRig
Reference: https://thedfirreport.com/2021/06/03/weblogic-rce-leads-to-xmrig/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sysrv013 {
meta:
description = "files - file sysrv013.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-06-03"
hash1 = "80bc76202b75201c740793ea9cd33b31cc262ef01738b053e335ee5d07a5ba96"
strings:
$s1 = "eDumped" fullword ascii
$s2 = "OGhZVFNVRms6" fullword ascii /* base64 encoded string '8hYTSUFk:' */
$s3 = "sdumpsebslemW^" fullword ascii
$s4 = ":ERNEL32.DLLODe?" fullword ascii
$s5 = "pircsek" fullword ascii
$s6 = "IDE5NC4xNDUu" fullword ascii /* base64 encoded string ' 194.145.' */
$s7 = "333444" ascii /* reversed goodware string '444333' */
$s8 = "aHx8d2dldCAtLXVzZXItYW" fullword ascii /* base64 encoded string 'h||wget --user-a' */
$s9 = "h -c {%" fullword ascii
$s10 = "?$?)?2?9?{" fullword ascii /* hex encoded string ')' */
$s11 = ";5A;6D2!D" fullword ascii /* hex encoded string 'Zm-' */
$s12 = "3GRAt\\5" fullword ascii
$s13 = "Gorget{" fullword ascii
$s14 = "7!7&7,727" fullword ascii /* hex encoded string 'ww'' */
$s15 = "* {5C;" fullword ascii
$s16 = "fsftp_fC" fullword ascii
$s17 = "POSTulL" fullword ascii
$s18 = "gogetv/" fullword ascii
$s19 = "\\x86+.pdb" fullword ascii
$s20 = "_DIRCWD?" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 10000KB and
( pe.imphash() == "406f4cbdf82bde91761650ca44a3831a" or 8 of them )
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-05-09
Identifier: Case 3584 Conti Ransomware
Reference: https://thedfirreport.com/2021/05/12/conti-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule icedid_rate_x32 {
meta:
description = "files - file rate_x32.dat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "eb79168391e64160883b1b3839ed4045b4fd40da14d6eec5a93cfa9365503586"
strings:
$s1 = "UAWAVAUATVWSH" fullword ascii
$s2 = "UAWAVVWSPH" fullword ascii
$s3 = "AWAVAUATVWUSH" fullword ascii
$s4 = "update" fullword ascii /* Goodware String - occured 207 times */
$s5 = "?klopW@@YAHXZ" fullword ascii
$s6 = "?jutre@@YAHXZ" fullword ascii
$s7 = "PluginInit" fullword ascii
$s8 = "[]_^A\\A]A^A_" fullword ascii
$s9 = "e8[_^A\\A]A^A_]" fullword ascii
$s10 = "[_^A\\A]A^A_]" fullword ascii
$s11 = "Kts=R,4iu" fullword ascii
$s12 = "mqr55c" fullword ascii
$s13 = "R,4i=Bj" fullword ascii
$s14 = "Ktw=R,4iu" fullword ascii
$s15 = "Ktu=R,4iu" fullword ascii
$s16 = "Kt{=R,4iu" fullword ascii
$s17 = "KVL.Mp" fullword ascii
$s18 = "Kt|=R,4iu" fullword ascii
$s19 = "=8c[Vt8=" fullword ascii
$s20 = "Ktx=R,4iu" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 700KB and
( pe.imphash() == "15787e97e92f1f138de37f6f972eb43c" and ( pe.exports("?jutre@@YAHXZ") and pe.exports("?klopW@@YAHXZ") and pe.exports("PluginInit") and pe.exports("update") ) or 8 of them )
}

rule conti_cobaltstrike_192145 {
meta:
description = "files - file 192145.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "29bc338e63a62c24c301c04961084013816733dad446a29c20d4413c5c818af9"
strings:
$x1 = "cmd.exe /c echo NGAtoDgLpvgJwPLEPFdj>\"%s\"&exit" fullword ascii
$s2 = "veniamatquiest90.dll" fullword ascii
$s3 = "Quaerat magni assumenda nihil architecto labore ullam autem unde temporibus mollitia illum" fullword ascii
$s4 = "Quaerat tempora culpa provident" fullword ascii
$s5 = "Velit consequuntur quisquam tempora error" fullword ascii
$s6 = "Quo omnis repellat ut expedita temporibus eius fuga error" fullword ascii
$s7 = "Dolores ullam tempora error distinctio ut natus facere quibusdam" fullword ascii
$s8 = "Corporis minima omnis qui est temporibus sint quo error magnam" fullword ascii
$s9 = "Officia sit maiores deserunt nobis tempora deleniti aut et quidem fugit" fullword ascii
$s10 = "Rerum tenetur sapiente est tempora qui deserunt" fullword ascii
$s11 = "Sed nulla quaerat porro error excepturi" fullword ascii
$s12 = "Aut tempore quo cumque dicta ut quia in" fullword ascii
$s13 = "Doloribus commodi repudiandae voluptates consequuntur neque tempora ut neque nemo ad ut" fullword ascii
$s14 = "Tempore possimus aperiam nam mollitia illum hic at ut doloremque" fullword ascii
$s15 = "Dolorum eum ipsum tempora non et" fullword ascii
$s16 = "Quas alias illum laborum tempora sit est rerum temporibus dicta et" fullword ascii
$s17 = "Et quia aut temporibus enim repellat dolores totam recusandae repudiandae" fullword ascii
$s18 = "Sed velit ipsa et dolor tempore sunt nostrum" fullword ascii
$s19 = "Veniam voluptatem aliquam et eaque tempore tenetur possimus" fullword ascii
$s20 = "Possimus suscipit placeat dolor quia tempora voluptas qui fugiat et accusantium" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "5cf3cdfe8585c01d2673249153057181" and pe.exports("StartW") or ( 1 of ($x*) or 4 of them ) )
}

rule conti_cobaltstrike_icju1 {
meta:
description = "files - file icju1.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "e54f38d06a4f11e1b92bb7454e70c949d3e1a4db83894db1ab76e9d64146ee06"
strings:
$x1 = "cmd.exe /c echo NGAtoDgLpvgJwPLEPFdj>\"%s\"&exit" fullword ascii
$s2 = "veniamatquiest90.dll" fullword ascii
$s3 = "Quaerat magni assumenda nihil architecto labore ullam autem unde temporibus mollitia illum" fullword ascii
$s4 = "Quaerat tempora culpa provident" fullword ascii
$s5 = "Velit consequuntur quisquam tempora error" fullword ascii
$s6 = "Quo omnis repellat ut expedita temporibus eius fuga error" fullword ascii
$s7 = "Dolores ullam tempora error distinctio ut natus facere quibusdam" fullword ascii
$s8 = "Corporis minima omnis qui est temporibus sint quo error magnam" fullword ascii
$s9 = "Officia sit maiores deserunt nobis tempora deleniti aut et quidem fugit" fullword ascii
$s10 = "Rerum tenetur sapiente est tempora qui deserunt" fullword ascii
$s11 = "Sed nulla quaerat porro error excepturi" fullword ascii
$s12 = "Aut tempore quo cumque dicta ut quia in" fullword ascii
$s13 = "Doloribus commodi repudiandae voluptates consequuntur neque tempora ut neque nemo ad ut" fullword ascii
$s14 = "Tempore possimus aperiam nam mollitia illum hic at ut doloremque" fullword ascii
$s15 = "Dolorum eum ipsum tempora non et" fullword ascii
$s16 = "Quas alias illum laborum tempora sit est rerum temporibus dicta et" fullword ascii
$s17 = "Et quia aut temporibus enim repellat dolores totam recusandae repudiandae" fullword ascii
$s18 = "Sed velit ipsa et dolor tempore sunt nostrum" fullword ascii
$s19 = "Veniam voluptatem aliquam et eaque tempore tenetur possimus" fullword ascii
$s20 = "Possimus suscipit placeat dolor quia tempora voluptas qui fugiat et accusantium" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "a6d9b7f182ef1cfe180f692d89ecc759" or ( 1 of ($x*) or 4 of them ) )
}

rule conti_v3 {

meta:
description = "conti_yara - file conti_v3.dll" 
author = "pigerlin" 
reference = "https://thedfirreport.com" 
date = "2021-05-09" 
hash1 = "8391dc3e087a5cecba74a638d50b771915831340ae3e027f0bb8217ad7ba4682"

strings: 
$s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
$s2 = "conti_v3.dll" fullword ascii 
$s3 = " <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii 
$s4 = " Type Descriptor'" fullword ascii 
$s5 = "operator co_await" fullword ascii 
$s6 = " <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii 
$s7 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide 
$s8 = " Base Class Descriptor at (" fullword ascii 
$s9 = " Class Hierarchy Descriptor'" fullword ascii 
$s10 = " Complete Object Locator'" fullword ascii 
$s11 = " delete[]" fullword ascii 
$s12 = " </trustInfo>" fullword ascii 
$s13 = "__swift_1" fullword ascii 
$s15 = "__swift_2" fullword ascii 
$s19 = " delete" fullword ascii

condition:
uint16(0) == 0x5a4d and filesize < 700KB and
all of them

}


rule conti_cobaltstrike_192145_icju1_0 {
meta:
description = "files - from files 192145.dll, icju1.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-05-09"
hash1 = "29bc338e63a62c24c301c04961084013816733dad446a29c20d4413c5c818af9"
hash2 = "e54f38d06a4f11e1b92bb7454e70c949d3e1a4db83894db1ab76e9d64146ee06"
strings:
$x1 = "cmd.exe /c echo NGAtoDgLpvgJwPLEPFdj>\"%s\"&exit" fullword ascii
$s2 = "veniamatquiest90.dll" fullword ascii
$s3 = "Quaerat magni assumenda nihil architecto labore ullam autem unde temporibus mollitia illum" fullword ascii
$s4 = "Quaerat tempora culpa provident" fullword ascii
$s5 = "Dolores ullam tempora error distinctio ut natus facere quibusdam" fullword ascii
$s6 = "Velit consequuntur quisquam tempora error" fullword ascii
$s7 = "Corporis minima omnis qui est temporibus sint quo error magnam" fullword ascii
$s8 = "Quo omnis repellat ut expedita temporibus eius fuga error" fullword ascii
$s9 = "Officia sit maiores deserunt nobis tempora deleniti aut et quidem fugit" fullword ascii
$s10 = "Rerum tenetur sapiente est tempora qui deserunt" fullword ascii
$s11 = "Sed nulla quaerat porro error excepturi" fullword ascii
$s12 = "Aut tempore quo cumque dicta ut quia in" fullword ascii
$s13 = "Doloribus commodi repudiandae voluptates consequuntur neque tempora ut neque nemo ad ut" fullword ascii
$s14 = "Tempore possimus aperiam nam mollitia illum hic at ut doloremque" fullword ascii
$s15 = "Et quia aut temporibus enim repellat dolores totam recusandae repudiandae" fullword ascii
$s16 = "Dolorum eum ipsum tempora non et" fullword ascii
$s17 = "Quas alias illum laborum tempora sit est rerum temporibus dicta et" fullword ascii
$s18 = "Sed velit ipsa et dolor tempore sunt nostrum" fullword ascii
$s19 = "Veniam voluptatem aliquam et eaque tempore tenetur possimus" fullword ascii
$s20 = "Possimus suscipit placeat dolor quia tempora voluptas qui fugiat et accusantium" fullword ascii
condition:
( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
) or ( all of them )
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-06-09
Identifier: Case 3930 From Word to Lateral Movement in 1 Hour
Reference: https://thedfirreport.com/2021/06/20/from-word-to-lateral-movement-in-1-hour/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule icedid_upefkuin4_3930 {
meta:
description = "3930 - file upefkuin4.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-06-09"
hash1 = "666570229dd5af87fede86b9191fb1e8352d276a8a32c42e4bf4128a4f7e8138"
strings:
$s1 = "UAWAVAUATVWSH" fullword ascii
$s2 = "AWAVAUATVWUSH" fullword ascii
$s3 = "AWAVATVWUSH" fullword ascii
$s4 = "update" fullword ascii /* Goodware String - occured 207 times */
$s5 = "?ortpw@@YAHXZ" fullword ascii
$s6 = "?sortyW@@YAHXZ" fullword ascii
$s7 = "?sorty@@YAHXZ" fullword ascii
$s8 = "?keptyu@@YAHXZ" fullword ascii
$s9 = "*=UUUUr#L" fullword ascii
$s10 = "*=UUUUr!" fullword ascii
$s11 = "PluginInit" fullword ascii
$s12 = "*=UUUUr\"" fullword ascii
$s13 = "AVVWSH" fullword ascii
$s14 = "D$4iL$ " fullword ascii
$s15 = "X[]_^A\\A]A^A_" fullword ascii
$s16 = "D$4iT$ " fullword ascii
$s17 = "H[]_^A\\A]A^A_" fullword ascii
$s18 = "L94iL$ " fullword ascii
$s19 = "D$ iD$ " fullword ascii
$s20 = "*=UUUUr " fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 700KB and
( pe.imphash() == "87bed5a7cba00c7e1f4015f1bdae2183" and ( pe.exports("?keptyu@@YAHXZ") and pe.exports("?ortpw@@YAHXZ") and pe.exports("?sorty@@YAHXZ") and pe.exports("?sortyW@@YAHXZ") and pe.exports("PluginInit") and pe.exports("update") ) or 8 of them )
}

rule icedid_license_3930 {
meta:
description = "3930 - file license.dat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-06-09"
hash1 = "29d2a8344bd725d7a8b43cc77a82b3db57a5226ce792ac4b37e7f73ec468510e"
strings:
$s1 = "iEQc- A1h" fullword ascii
$s2 = "%n%DLj" fullword ascii
$s3 = "n{Y@.hnPP#5\"~" fullword ascii
$s4 = "(5N&#jUBE\"0" fullword ascii
$s5 = "~JCyP+Av" fullword ascii
$s6 = "iLVIy\\" fullword ascii
$s7 = "RemwDVL" fullword ascii
$s8 = "EQiH^,>A" fullword ascii
$s9 = "#wmski;H" fullword ascii
$s10 = "aHVAh}X" fullword ascii
$s11 = "GEKK/no" fullword ascii
$s12 = "focbZjQ" fullword ascii
$s13 = "wHsJJX>e" fullword ascii
$s14 = "cYRS:F#" fullword ascii
$s15 = "EfNO\"h{" fullword ascii
$s16 = "akCevJ]" fullword ascii
$s17 = "8IMwwm}!" fullword ascii
$s18 = "NrzMP?<>" fullword ascii
$s19 = ".ZNrzLrU" fullword ascii
$s20 = "sJlCJP[" fullword ascii
condition:
uint16(0) == 0x02ee and filesize < 1000KB and
8 of them
}

rule icedid_win_01 {

meta:

description = "Detects Icedid" 
author = "The DFIR Report" 
date = "15/05/2021" 
description = "Detects Icedid functionality. incl. credential access, OS cmds." 
sha1 = "3F06392AF1687BD0BF9DB2B8B73076CAB8B1CBBA" 
score = 100

strings: 
$s1 = "DllRegisterServer" wide ascii fullword 
$x1 = "passff.tar" wide ascii fullword 
$x2 = "vaultcli.dll" wide ascii fullword 
$x3 = "cookie.tar" wide ascii fullword 
$y1 = "powershell.exe" wide ascii fullword 
$y2 = "cmd.exe" wide ascii fullword

condition:

( uint16(0) == 0x5a4d and int32(uint32(0x3c)) == 0x00004550 and filesize < 500KB and $s1 and ( 2 of ($x*) and 2 of ($y*))) 
}


rule fake_gzip_bokbot_202104 {

meta:

author = "Thomas Barabosch, Telekom Security" 
date = "2021-04-20" 
description = "fake gzip provided by CC"

strings:

$gzip = {1f 8b 08 08 00 00 00 00 00 00 75 70 64 61 74 65}

condition:

$gzip at 0

}

rule win_iceid_gzip_ldr_202104 {

meta:

author = "Thomas Barabosch, Telekom Security" 
date = "2021-04-12" 
description = "2021 initial Bokbot / Icedid loader for fake GZIP payloads"

strings:

$internal_name = "loader_dll_64.dll" fullword

$string0 = "_gat=" wide 
$string1 = "_ga=" wide 
$string2 = "_gid=" wide 
$string3 = "_u=" wide 
$string4 = "_io=" wide 
$string5 = "GetAdaptersInfo" fullword 
$string6 = "WINHTTP.dll" fullword 
$string7 = "DllRegisterServer" fullword 
$string8 = "PluginInit" fullword 
$string9 = "POST" wide fullword 
$string10 = "aws.amazon.com" wide fullword

condition:

uint16(0) == 0x5a4d and 
filesize < 5000KB and 
( $internal_name or all of ($s*) ) 
or all of them

}

rule win_iceid_core_ldr_202104 {

meta:

author = "Thomas Barabosch, Telekom Security" 
date = "2021-04-13" 
description = "2021 loader for Bokbot / Icedid core (license.dat)"

strings: 
$internal_name = "sadl_64.dll" fullword 
$string0 = "GetCommandLineA" fullword 
$string1 = "LoadLibraryA" fullword 
$string2 = "ProgramData" fullword 
$string3 = "SHLWAPI.dll" fullword 
$string4 = "SHGetFolderPathA" fullword 
$string5 = "DllRegisterServer" fullword 
$string6 = "update" fullword 
$string7 = "SHELL32.dll" fullword 
$string8 = "CreateThread" fullword

condition:

uint16(0) == 0x5a4d and 
filesize < 5000KB and 
( $internal_name or all of ($s*) ) 
or all of them

}

rule win_iceid_core_202104 {

meta: 
author = "Thomas Barabosch, Telekom Security" 
date = "2021-04-12" 
description = "2021 Bokbot / Icedid core"

strings:

$internal_name = "fixed_loader64.dll" fullword

$string0 = "mail_vault" wide fullword 
$string1 = "ie_reg" wide fullword 
$string2 = "outlook" wide fullword 
$string3 = "user_num" wide fullword 
$string4 = "cred" wide fullword 
$string5 = "Authorization: Basic" fullword 
$string6 = "VaultOpenVault" fullword 
$string7 = "sqlite3_free" fullword 
$string8 = "cookie.tar" fullword 
$string9 = "DllRegisterServer" fullword 
$string10 = "PT0S" wide

condition:

uint16(0) == 0x5a4d and 
filesize < 5000KB and 
( $internal_name or all of ($s*) ) 
or all of them

}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-06-27
Identifier: Case 4301 Hancitor Continues to Push Cobalt Strike
Reference: https://thedfirreport.com/2021/06/28/hancitor-continues-to-push-cobalt-strike/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_95_dll_cobalt_strike {
meta:
description = "file 95.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-06-24"
hash1 = "7b2144f2b5d722a1a8a0c47a43ecaf029b434bfb34a5cffe651fda2adf401131"
strings:
$s1 = "TstDll.dll" fullword ascii
$s2 = "!This is a Windows NT windowed dynamic link library" fullword ascii
$s3 = "AserSec" fullword ascii
$s4 = "`.idata" fullword ascii /* Goodware String - occured 1 times */
$s5 = "vEYd!W" fullword ascii
$s6 = "[KpjrRdX&b" fullword ascii
$s7 = "XXXXXXHHHHHHHHHHHHHHHHHHHH" fullword ascii /* Goodware String - occured 2 times */
$s8 = "%$N8 2" fullword ascii
$s9 = "%{~=vP" fullword ascii
$s10 = "it~?KVT" fullword ascii
$s11 = "UwaG+A" fullword ascii
$s12 = "mj_.%/2" fullword ascii
$s13 = "BnP#lyp" fullword ascii
$s14 = "(N\"-%IB" fullword ascii
$s15 = "KkL{xK" fullword ascii
$s16 = ")[IyU," fullword ascii
$s17 = "|+uo6\\" fullword ascii
$s18 = "@s?.N^" fullword ascii
$s19 = "R%jdzV" fullword ascii
$s20 = "R!-q$Fl" fullword ascii 
condition: 
uint16(0) == 0x5a4d and filesize < 100KB and 
( pe.imphash() == "67fdc237b514ec9fab9c4500917eb60f" and ( pe.exports("AserSec") and pe.exports("TstSec") ) or all of them ) 
} 

rule cobalt_strike_shellcode_95_dll { 

meta: 
description = "Cobalt Strike Shellcode" 
author = "The DFIR Report" 
reference = "https://thedfirreport.com" 
date = "2021-06-23" 

strings: 

$str_1 = { E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 } 
$str_2 = "/hVVH" 
$str_3 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENGB)" 

condition: 
3 of them

}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-07-13
Identifier: Case 4485 IcedID and Cobalt Strike vs Antivirus
Reference: https://thedfirreport.com/2021/07/19/icedid-and-cobalt-strike-vs-antivirus/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule textboxNameNamespace {
meta:
description = "4485 - file textboxNameNamespace.hta"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-07-13"
hash1 = "b17c7316f5972fff42085f7313f19ce1c69b17bf61c107b1ccf94549d495fa42"
strings:
$s1 = "idGNlamJvbWV0c3lzZWxpZi5nbml0cGlyY3MiKHRjZWpiT1hldml0Y0Egd2VuID0gTG1lciByYXY7KSJsbGVocy50cGlyY3N3Iih0Y2VqYk9YZXZpdGNBIHdlbiA9IGV" ascii /* base64 encoded string 'tcejbometsyselif.gnitpircs"(tcejbOXevitcA wen = Lmer rav;)"llehs.tpircsw"(tcejbOXevitcA wen = e' */
$s2 = "/<html><body><div id='variantDel'>fX17KWUoaGN0YWN9O2Vzb2xjLnRzbm9Dbm90dHVCd2VpdjspMiAsImdwai5lY2Fwc2VtYU5lbWFOeG9idHhldFxcY2lsYn" ascii
$s3 = "oveTo(-100, -100);var swapLength = tplNext.getElementById('variantDel').innerHTML.split(\"aGVsbG8\");var textSinLibrary = ptrSin" ascii
$s4 = "wxyz0123456789+/</div><script language='javascript'>function varMainInt(tmpRepo){return(new ActiveXObject(tmpRepo));}function bt" ascii
$s5 = "VwXFxzcmVzdVxcOmMiKGVsaWZvdGV2YXMudHNub0Nub3R0dUJ3ZWl2Oyl5ZG9iZXNub3BzZXIuZXRhREl4b2J0eGV0KGV0aXJ3LnRzbm9Dbm90dHVCd2VpdjsxID0gZX" ascii
$s6 = "ript><script language='vbscript'>Function byteNamespaceReference(variantDel) : Set WLength = CreateObject(queryBoolSize) : With " ascii
$s7 = "WLength : .language = \"jscript\" : .timeout = 60000 : .eval(variantDel) : End With : End Function</script><script language='vbs" ascii
$s8 = "FkZGEvbW9jLmIwMjAyZ25pcm9ieXRyZXZvcC8vOnB0dGgiICwiVEVHIihuZXBvLmV0YURJeG9idHhldDspInB0dGhsbXguMmxteHNtIih0Y2VqYk9YZXZpdGNBIHdlbi" ascii
$s9 = "pJMTZBb0hjcXBYbVI1ZUI0YXF0SVhWWlZkRkhvZjFEZy9qYWVMTGlmc3doOW9EaEl2QlllYnV1dWxPdktuQWFPYm43WGNieFdqejQ1V3dTOC8xMzIxNi9PUnFEb01aL2" ascii
$s10 = "B5dC50c25vQ25vdHR1QndlaXY7bmVwby50c25vQ25vdHR1QndlaXY7KSJtYWVydHMuYmRvZGEiKHRjZWpiT1hldml0Y0Egd2VuID0gdHNub0Nub3R0dUJ3ZWl2IHJhdn" ascii
$s11 = "t><script language='javascript'>libView['close']();</script></body></html>" fullword ascii
$s12 = "t5cnR7KTAwMiA9PSBzdXRhdHMuZXRhREl4b2J0eGV0KGZpOykoZG5lcy5ldGFESXhvYnR4ZXQ7KWVzbGFmICwiNE9Uc3NldUk9ZmVyPzZnb2QvNzcwODMvUG10RkQzeE" ascii
$s13 = "tYU5vcmV6IHJhdg==aGVsbG8msscriptcontrol.scriptcontrol</div><div id='exLeftLink'>ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv" ascii
$s14 = "nGlob(pasteVariable){return(tplNext.getElementById(pasteVariable).innerHTML);}function lConvert(){return(btnGlob('exLeftLink'));" ascii
$s15 = "ipt'>Call byteNamespaceReference(textSinLibrary)</script><script language='vbscript'>Call byteNamespaceReference(remData)</scrip" ascii
$s16 = "Ex](x)];b=(b<<6)+c;l+=6;while(l>=8){((a=(b>>>(l-=8))&0xff)||(x<(L-2)))&&(vbaBD+=w(a));}}return(vbaBD);};function ptrSingleOpt(be" ascii
$s17 = "eOpt(bytesGeneric(swapLength[0]));var remData = ptrSingleOpt(bytesGeneric(swapLength[1]));var queryBoolSize = swapLength[2];</sc" ascii
$s18 = "}function bytesGeneric(s){var e={}; var i; var b=0; var c; var x; var l=0; var a; var vbaBD=''; var w=String.fromCharCode; var L" ascii
$s19 = "=s.length;var counterEx = ptrSingleOpt('tArahc');for(i=0;i<64;i++){e[lConvert()[counterEx](i)]=i;}for(x=0;x<L;x++){c=e[s[counter" ascii
$s20 = "foreRight){return beforeRight.split('').reverse().join('');}libView = window;tplNext = document;libView.resizeTo(1, 1);libView.m" ascii
condition:
uint16(0) == 0x3c2f and filesize < 7KB and
8 of them
}

rule case_4485_adf {
meta:
description = "files - file adf.bat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-07-13"
hash1 = "f6a377ba145a5503b5eb942d17645502eddf3a619d26a7b60df80a345917aaa2"
strings:
$x1 = "adfind.exe"
$s2 = "objectcategory=person" fullword ascii
$s3 = "objectcategory=computer" fullword ascii
$s4 = "adfind.exe -gcb -sc trustdmp > trustdmp.txt" fullword ascii
$s5 = "adfind.exe -sc trustdmp > trustdmp.txt" fullword ascii
$s6 = "adfind.exe -subnets -f (objectCategory=subnet)> subnets.txt" fullword ascii
$s7 = "(objectcategory=group)" fullword ascii
$s8 = "(objectcategory=organizationalUnit)" fullword ascii
condition:
uint16(0) == 0x6463 and filesize < 1KB and ( 1 of ($x*) and 6 of ($s*))
}

rule case_4485_Muif {
meta:
description = "4485 - file Muif.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-07-13"
hash1 = "8b9d605b826258e07e63687d1cefb078008e1a9c48c34bc131d7781b142c84ab"
strings:
$s1 = "Common causes completion include incomplete download and damaged media" fullword ascii
$s2 = "An error occurred writing to the file" fullword ascii
$s3 = "asks should be performed?" fullword ascii
$s4 = "The waiting time for the end of the launch was exceeded for an unknown reason" fullword ascii
$s5 = "Select the Start Menu folder in which you would like Setup to create the programs shortcuts, then click Next. Which additional t" ascii
$s6 = "HcA<E3" fullword ascii /* Goodware String - occured 1 times */
$s7 = "D$(9D$@u" fullword ascii /* Goodware String - occured 1 times */
$s8 = "Select the Start Menu folder in which you would like Setup to create the programs shortcuts, then click Next. Which additional t" ascii
$s9 = "Please verify that the correct path and file name are given" fullword ascii
$s10 = "Critical error" fullword ascii
$s11 = "Please read this information carefully" fullword ascii
$s12 = "Unknown error occurred for time: " fullword ascii
$s13 = "E 3y4i" fullword ascii
$s14 = "D$tOuo2" fullword ascii
$s15 = "D$PH9D$8tXH" fullword ascii
$s16 = "E$hik7" fullword ascii
$s17 = "D$p]mjk" fullword ascii
$s18 = "B):0~\"Z" fullword ascii
$s19 = "Richo/" fullword ascii
$s20 = "D$xJij" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 70KB and
( pe.imphash() == "42205b145650671fa4469a6321ccf8bf" and pe.exports("StartW") or 8 of them )
}

rule textboxNameNamespace_2 {
meta:
description = "4485 - file textboxNameNamespace.jpg"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-07-13"
hash1 = "010f52eda70eb9ff453e3af6f3d9d20cbda0c4075feb49c209ca1c250c676775"
strings:
$s1 = "uwunhkqlzle.dll" fullword ascii
$s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s3 = "operator co_await" fullword ascii
$s4 = "ggeaxcx" fullword ascii
$s5 = "wttfzwz" fullword ascii
$s6 = "fefewzydtdu" fullword ascii
$s7 = "ilaeemjyjwzjwj" fullword ascii
$s8 = "enhzmqryc" fullword ascii
$s9 = "flchfonfpzcwyrg" fullword ascii
$s10 = "dayhcsokc" fullword ascii
$s11 = "mtqnlfpbxghmlupsn" fullword ascii
$s12 = "zqeoctx" fullword ascii
$s13 = "ryntfydpykrdcftxx" fullword ascii
$s14 = "atxvtwd" fullword ascii
$s15 = "icjshmfrldy" fullword ascii
$s16 = "lenkuktrncmxiafgl" fullword ascii
$s17 = "alshaswlqmhptxpc" fullword ascii
$s18 = "izonphi" fullword ascii
$s19 = "atttyokowqnj" fullword ascii
$s20 = "nwvohpazb" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 500KB and
( pe.imphash() == "4d46e641e0220fb18198a7e15fa6f49f" and ( pe.exports("PluginInit") and pe.exports("alshaswlqmhptxpc") and pe.exports("amgqilvxdufvpdbwb") and pe.exports("atttyokowqnj") and pe.exports("atxvtwd") and pe.exports("ayawgsgkusfjmq") ) or 8 of them )
}

rule case_4485_ekix4 {
meta:
description = "4485 - file ekix4.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-07-13"
hash1 = "e27b71bd1ba7e1f166c2553f7f6dba1d6e25fa2f3bb4d08d156073d49cbc360a"
strings:
$s1 = "f159.dll" fullword ascii
$s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s3 = "ossl_store_get0_loader_int" fullword ascii
$s4 = "loader incomplete" fullword ascii
$s5 = "log conf missing description" fullword ascii
$s6 = "SqlExec" fullword ascii
$s7 = "process_include" fullword ascii
$s8 = "EVP_PKEY_get0_siphash" fullword ascii
$s9 = "process_pci_value" fullword ascii
$s10 = "EVP_PKEY_get_raw_public_key" fullword ascii
$s11 = "EVP_PKEY_get_raw_private_key" fullword ascii
$s12 = "OSSL_STORE_INFO_get1_NAME_description" fullword ascii
$s13 = "divisor->top > 0 && divisor->d[divisor->top - 1] != 0" fullword wide
$s14 = "ladder post failure" fullword ascii
$s15 = "operation fail" fullword ascii
$s16 = "ssl command section not found" fullword ascii
$s17 = "log key invalid" fullword ascii
$s18 = "cms_get0_econtent_type" fullword ascii
$s19 = "log conf missing key" fullword ascii
$s20 = "ssl command section empty" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 11000KB and
( pe.imphash() == "547a74a834f9965f00df1bd9ed30b8e5" or 8 of them )
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-08-02
Identifier: Case 4641 BazarCall to Conti Ransomware via Trickbot and Cobalt Strike
Reference: https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_4641_fQumH {
meta:
description = "4641 - file fQumH.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-02"
hash1 = "3420a0f6f0f0cc06b537dc1395638be0bffa89d55d47ef716408309e65027f31"
strings:
$s1 = "Usage: .system COMMAND" fullword ascii
$s2 = "Usage: .log FILENAME" fullword ascii
$s3 = "* If FILE begins with \"|\" then it is a command that generates the" fullword ascii
$s4 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s5 = "Usage %s sub-command ?switches...?" fullword ascii
$s6 = "attach debugger to process %d and press any key to continue." fullword ascii
$s7 = "%s:%d: expected %d columns but found %d - extras ignored" fullword ascii
$s8 = "%s:%d: expected %d columns but found %d - filling the rest with NULL" fullword ascii
$s9 = "Unknown option \"%s\" on \".dump\"" fullword ascii
$s10 = "REPLACE INTO temp.sqlite_parameters(key,value)VALUES(%Q,%s);" fullword ascii
$s11 = "error in %s %s%s%s: %s" fullword ascii
$s12 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii
$s13 = "BBBBBBBBBBBBBBBBBBBB" wide /* reversed goodware string 'BBBBBBBBBBBBBBBBBBBB' */
$s14 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii
$s15 = ");CREATE TEMP TABLE [_shell$self](op,cmd,ans);" fullword ascii
$s16 = "SqlExec" fullword ascii
$s17 = "* If neither --csv or --ascii are used, the input mode is derived" fullword ascii
$s18 = "Where sub-commands are:" fullword ascii
$s19 = "max rootpage (%d) disagrees with header (%d)" fullword ascii
$s20 = "-- Query %d --------------------------------" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 4000KB and
( pe.imphash() == "67f1f64a3db0d22bf48121a6cea1da22" or 8 of them )
}

rule sig_4641_62 {
meta:
description = "4641 - file 62.dll"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-02"
hash1 = "8b9d605b826258e07e63687d1cefb078008e1a9c48c34bc131d7781b142c84ab"
strings:
$s1 = "Common causes completion include incomplete download and damaged media" fullword ascii
$s2 = "An error occurred writing to the file" fullword ascii
$s3 = "asks should be performed?" fullword ascii
$s4 = "The waiting time for the end of the launch was exceeded for an unknown reason" fullword ascii
$s5 = "Select the Start Menu folder in which you would like Setup to create the programs shortcuts, then click Next. Which additional t" ascii
$s6 = "HcA<E3" fullword ascii /* Goodware String - occured 1 times */
$s7 = "Select the Start Menu folder in which you would like Setup to create the programs shortcuts, then click Next. Which additional t" ascii
$s8 = "D$(9D$@u" fullword ascii /* Goodware String - occured 1 times */
$s9 = "Please verify that the correct path and file name are given" fullword ascii
$s10 = "Critical error" fullword ascii
$s11 = "Please read this information carefully" fullword ascii
$s12 = "Unknown error occurred for time: " fullword ascii
$s13 = "E 3y4i" fullword ascii
$s14 = "D$tOuo2" fullword ascii
$s15 = "D$PH9D$8tXH" fullword ascii
$s16 = "E$hik7" fullword ascii
$s17 = "D$p]mjk" fullword ascii
$s18 = "B):0~\"Z" fullword ascii
$s19 = "Richo/" fullword ascii
$s20 = "D$xJij" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 70KB and
( pe.imphash() == "42205b145650671fa4469a6321ccf8bf" and pe.exports("StartW") or 8 of them )
}

rule sig_4641_tdrE934 {
meta:
description = "4641 - file tdrE934.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-02"
hash1 = "48f2e2a428ec58147a4ad7cc0f06b3cf7d2587ccd47bad2ea1382a8b9c20731c"
strings:
$s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s2 = "D:\\1W7w3cZ63gF\\wFIFSV\\YFU1GTi1\\i5G3cr\\Wb2f\\Cvezk3Oz\\2Zi9ir\\S76RW\\RE5kLijcf.pdb" fullword ascii
$s3 = "https://sectigo.com/CPS0" fullword ascii
$s4 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
$s5 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
$s6 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
$s7 = "ntdll.dlH" fullword ascii
$s8 = "http://ocsp.sectigo.com0" fullword ascii
$s9 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
$s10 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
$s11 = "tmnEt6XElyFyz2dg5EP4TMpAvGdGtork5EZcpw3eBwJQFABWlUZa5slcF6hqfGb2HgPed49gr2baBCLwRel8zM5cbMfsrOdS1yd6bMpepebebyT4NIN6zOvk" fullword ascii
$s12 = "ealagi@aol.com0" fullword ascii
$s13 = "operator co_await" fullword ascii
$s14 = "ZGetModuleHandle" fullword ascii
$s15 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s16 = "RtlExitUserThrea`NtFlushInstruct" fullword ascii
$s17 = "UAWAVAUATVWSH" fullword ascii
$s18 = "AWAVAUATVWUSH" fullword ascii
$s19 = "AWAVVWSH" fullword ascii
$s20 = "UAWAVATVWSH" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "4f1ec786c25f2d49502ba19119ebfef6" or 8 of them )
}

rule sig_4641_netscan {
meta:
description = "4641 - file netscan.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-02"
hash1 = "bb574434925e26514b0daf56b45163e4c32b5fc52a1484854b315f40fd8ff8d2"
strings:
$s1 = "netscan.exe" fullword ascii
$s2 = "TFMREMOTEPOWERSHELL" fullword wide
$s3 = "TFMREMOTEPOWERSHELLEDIT" fullword wide
$s4 = "TFMBASEDIALOGREMOTEEDIT" fullword wide
$s5 = "*http://crl4.digicert.com/assured-cs-g1.crl0L" fullword ascii
$s6 = "*http://crl3.digicert.com/assured-cs-g1.crl00" fullword ascii
$s7 = "TFMIGNOREADDRESS" fullword wide
$s8 = "TREMOTECOMMONFORM" fullword wide
$s9 = "TFMSTOPSCANDIALOG" fullword wide
$s10 = "TFMBASEDIALOGSHUTDOWN" fullword wide
$s11 = "TFMBASEDIALOG" fullword wide
$s12 = "TFMOFFLINEDIALOG" fullword wide
$s13 = "TFMLIVEDISPLAYLOG" fullword wide
$s14 = "TFMHOSTPROPS" fullword wide
$s15 = "GGG`BBB" fullword ascii /* reversed goodware string 'BBB`GGG' */
$s16 = "SoftPerfect Network Scanner" fullword wide
$s17 = "TUSERPROMPTFORM" fullword wide
$s18 = "TFMREMOTESSH" fullword wide
$s19 = "TFMREMOTEGROUPSEDIT" fullword wide
$s20 = "TFMREMOTEWMI" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 6000KB and
( pe.imphash() == "573e7039b3baff95751bded76795369e" and ( pe.exports("__dbk_fcall_wrapper") and pe.exports("dbkFCallWrapperAddr") ) or 8 of them )
}

rule sig_4641_tdr615 {
meta:
description = "4641 - file tdr615.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-02"
hash1 = "12761d7a186ff14dc55dd4f59c4e3582423928f74d8741e7ec9f761f44f369e5"
strings:
$s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
$s2 = "I:\\RoDcnyLYN\\k1GP\\ap0pivKfOF\\odudwtm30XMz\\UnWdqN\\01\\7aXg1kTkp.pdb" fullword ascii
$s3 = "https://sectigo.com/CPS0" fullword ascii
$s4 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
$s5 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
$s6 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
$s7 = "http://ocsp.sectigo.com0" fullword ascii
$s8 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
$s9 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
$s10 = "ealagi@aol.com0" fullword ascii
$s11 = "operator co_await" fullword ascii
$s12 = "GetModuleHandleRNtUnmapViewOfSe" fullword ascii
$s13 = "+GetProcAddress" fullword ascii
$s14 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
$s15 = "RtlExitUserThrebNtFlushInstruct" fullword ascii
$s16 = "Sectigo Limited1$0\"" fullword ascii
$s17 = "b<log10" fullword ascii
$s18 = "D*<W -" fullword ascii
$s19 = "WINDOWSPROJECT1" fullword wide
$s20 = "WindowsProject1" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 10000KB and
( pe.imphash() == "555560b7871e0ba802f2f6fbf05d9bfa" or 8 of them )
}

rule CS_DLL { 
meta: 
description = "62.dll" 
author = "The DFIR Report" 
reference = "https://thedfirreport.com" 
date = "2021-07-07" 
hash1 = "8b9d605b826258e07e63687d1cefb078008e1a9c48c34bc131d7781b142c84ab" 
strings: 
$s1 = "Common causes completion include incomplete download and damaged media" fullword ascii 
$s2 = "StartW" fullword ascii 
$s4 = ".rdata$zzzdbg" fullword ascii 
condition: 
uint16(0) == 0x5a4d and filesize < 70KB and ( pe.imphash() == "42205b145650671fa4469a6321ccf8bf" ) 
or (all of them) 
}


rule tdr615_exe { 
meta: 
description = "Cobalt Strike on beachhead: tdr615.exe" 
author = "The DFIR Report" 
reference = "https://thedfirreport.com" 
date = "2021-07-07" 
hash1 = "12761d7a186ff14dc55dd4f59c4e3582423928f74d8741e7ec9f761f44f369e5" 
strings: 
$a1 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
$a2 = "I:\\RoDcnyLYN\\k1GP\\ap0pivKfOF\\odudwtm30XMz\\UnWdqN\\01\\7aXg1kTkp.pdb" fullword ascii 
$b1 = "ealagi@aol.com0" fullword ascii 
$b2 = "operator co_await" fullword ascii 
$b3 = "GetModuleHandleRNtUnmapViewOfSe" fullword ascii 
$b4 = "RtlExitUserThrebNtFlushInstruct" fullword ascii 
$c1 = "Jersey City1" fullword ascii 
$c2 = "Mariborska cesta 971" fullword ascii 
condition: 
uint16(0) == 0x5a4d and filesize < 10000KB and 
any of ($a* ) and 2 of ($b* ) and any of ($c* ) 
} 
/* 
YARA Rule Set 
Author: The DFIR Report 
Date: 2021-08-15
Identifier: Case 4778 Trickbot Leads Up to Fake 1Password Installation
Reference: https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/
*/

/* Rule Set ----------------------------------------------------------------- */




import "pe"

rule case_4778_theora2 { 
meta: 
description = "4778 - file theora2.dll" 
author = "The DFIR Report" 
reference = "https://thedfirreport.com" 
date = "2021-08-15" 
hash1 = "92db40988d314cea103ecc343b61188d8b472dc524c5b66a3776dad6fc7938f0" 
strings: 
$x1 = " consultationcommunity ofthe nationalit should beparticipants align=\"leftthe greatestselection ofsupernaturaldependent onis me" ascii 
$s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ 
$s3 = "keywords\" content=\"w3.org/1999/xhtml\"><a target=\"_blank\" text/html; charset=\" target=\"_blank\"><table cellpadding=\"autoc" ascii 
$s4 = "erturkey);var forestgivingerrorsDomain}else{insertBlog</footerlogin.fasteragents<body 10px 0pragmafridayjuniordollarplacedcovers" ascii 
$s5 = " severalbecomesselect wedding00.htmlmonarchoff theteacherhighly biologylife ofor evenrise of&raquo;plusonehunting(thoughDouglasj" ascii 
$s6 = "font></Norwegianspecifiedproducingpassenger(new DatetemporaryfictionalAfter theequationsdownload.regularlydeveloperabove thelink" ascii 
$s7 = "Besides//--></able totargetsessencehim to its by common.mineralto takeways tos.org/ladvisedpenaltysimple:if theyLettersa shortHe" ascii 
$s8 = " attemptpair ofmake itKontaktAntoniohaving ratings activestreamstrapped\").css(hostilelead tolittle groups,Picture-->" fullword ascii 
$s9 = "<script type== document.createElemen<a target=\"_blank\" href= document.getElementsBinput type=\"text\" name=a.type = 'text/java" ascii 
$s10 = "ondisciplinelogo.png\" (document,boundariesexpressionsettlementBackgroundout of theenterprise(\"https:\" unescape(\"password\" d" ascii 
$s11 = "Dwrite.dll" fullword wide 
$s12 = " rows=\" objectinverse<footerCustomV><\\/scrsolvingChamberslaverywoundedwhereas!= 'undfor allpartly -right:Arabianbacked century" ascii 
$s13 = "online.?xml vehelpingdiamonduse theairlineend -->).attr(readershosting#ffffffrealizeVincentsignals src=\"/Productdespitediverset" ascii 
$s14 = "changeresultpublicscreenchoosenormaltravelissuessourcetargetspringmodulemobileswitchphotosborderregionitselfsocialactivecolumnre" ascii 
$s15 = "put type=\"hidden\" najs\" type=\"text/javascri(document).ready(functiscript type=\"text/javasimage\" content=\"http://UA-Compat" ascii 
$s16 = "alsereadyaudiotakeswhile.com/livedcasesdailychildgreatjudgethoseunitsneverbroadcoastcoverapplefilescyclesceneplansclickwritequee" ascii 
$s17 = " the would not befor instanceinvention ofmore complexcollectivelybackground: text-align: its originalinto accountthis processan " ascii 
$s18 = "came fromwere usednote thatreceivingExecutiveeven moreaccess tocommanderPoliticalmusiciansdeliciousprisonersadvent ofUTF-8\" /><" ascii 
$s19 = "Lib1.dll" fullword ascii 
$s20 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
condition: 
uint16(0) == 0x5a4d and filesize < 9000KB and 
1 of ($x*) and all of them 
}


rule case_4778_filepass { 
meta: 
description = "4778 - file filepass.exe" 
author = "The DFIR Report" 
reference = "https://thedfirreport.com" 
date = "2021-08-15" 
hash1 = "8358c51b34f351da30450956f25bef9d5377a993a156c452b872b3e2f10004a8" 
strings: 
$x1 = " consultationcommunity ofthe nationalit should beparticipants align=\"leftthe greatestselection ofsupernaturaldependent onis me" ascii 
$s2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */ 
$s3 = "keywords\" content=\"w3.org/1999/xhtml\"><a target=\"_blank\" text/html; charset=\" target=\"_blank\"><table cellpadding=\"autoc" ascii 
$s4 = " <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii 
$s5 = "erturkey);var forestgivingerrorsDomain}else{insertBlog</footerlogin.fasteragents<body 10px 0pragmafridayjuniordollarplacedcovers" ascii 
$s6 = " severalbecomesselect wedding00.htmlmonarchoff theteacherhighly biologylife ofor evenrise of&raquo;plusonehunting(thoughDouglasj" ascii 
$s7 = "font></Norwegianspecifiedproducingpassenger(new DatetemporaryfictionalAfter theequationsdownload.regularlydeveloperabove thelink" ascii 
$s8 = "Besides//--></able totargetsessencehim to its by common.mineralto takeways tos.org/ladvisedpenaltysimple:if theyLettersa shortHe" ascii 
$s9 = " attemptpair ofmake itKontaktAntoniohaving ratings activestreamstrapped\").css(hostilelead tolittle groups,Picture-->" fullword ascii 
$s10 = " <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii 
$s11 = "<script type== document.createElemen<a target=\"_blank\" href= document.getElementsBinput type=\"text\" name=a.type = 'text/java" ascii 
$s12 = "ondisciplinelogo.png\" (document,boundariesexpressionsettlementBackgroundout of theenterprise(\"https:\" unescape(\"password\" d" ascii 
$s13 = "DirectSound: failed to load DSOUND.DLL" fullword ascii 
$s14 = "theora2.dll" fullword ascii 
$s15 = "bin\\XInput1_3.dll" fullword wide 
$s16 = " rows=\" objectinverse<footerCustomV><\\/scrsolvingChamberslaverywoundedwhereas!= 'undfor allpartly -right:Arabianbacked century" ascii 
$s17 = "InputMapper.exe" fullword ascii 
$s18 = "C:\\0\\Release\\output\\Release\\spdblib\\output\\Release_TS\\release\\saslPLAIN\\Relea.pdb" fullword ascii 
$s19 = "DS4Windows.exe" fullword ascii 
$s20 = "online.?xml vehelpingdiamonduse theairlineend -->).attr(readershosting#ffffffrealizeVincentsignals src=\"/Productdespitediverset" ascii 
condition: 
uint16(0) == 0x5a4d and filesize < 19000KB and 
1 of ($x*) and all of them 
}


rule case_4778_cds { 
meta: 
description = "4778 - file cds.xml" 
author = "The DFIR Report" 
reference = "https://thedfirreport.com" 
date = "2021-08-15" 
hash1 = "5ad6dd1f4fa5b1a877f8ae61441076eb7ba3ec0d8aeb937e3db13742868babcd" 
strings: 
$s1 = " (<see cref=\"F:System.Int32.MaxValue\" /> - " fullword ascii 
$s2 = "DIO.BinaryWriter.Write(System.Decimal)\">" fullword ascii 
$s3 = " (<paramref name=\"offset\" /> + <paramref name=\"count\" /> - 1), " fullword ascii 
$s4 = " <see cref=\"T:System.InvalidOperationException\" />. </exception>" fullword ascii 
$s5 = " (<paramref name=\"index\" /> + <paramref name=\"count\" /> - 1) " fullword ascii 
$s6 = " (<paramref name=\"index + count - 1\" />) " fullword ascii 
$s7 = " (<paramref name=\"offset\" /> + <paramref name=\"count\" /> - 1) " fullword ascii 
$s8 = " <see cref=\"T:System.IO.BinaryWriter\" />, " fullword ascii 
$s9 = " <see cref=\"T:System.IO.BinaryReader\" />; " fullword ascii 
$s10 = " <see cref=\"T:System.IO.BinaryWriter\" /> " fullword ascii 
$s11 = " <see cref=\"T:System.IO.BinaryWriter\" />; " fullword ascii 
$s12 = " <see cref=\"T:System.IO.BinaryReader\" /> " fullword ascii 
$s13 = " <see cref=\"T:System.IO.BinaryReader\" /> (" fullword ascii 
$s14 = " .NET Framework " fullword ascii 
$s15 = " <member name=\"M:System.IO.BinaryReader.Read7BitEncodedInt\">" fullword ascii 
$s16 = " <see cref=\"T:System.IO.BinaryWriter\" />.</summary>" fullword ascii 
$s17 = " BinaryReader.</returns>" fullword ascii 
$s18 = " <see cref=\"T:System.IO.BinaryReader\" />.</summary>" fullword ascii 
$s19 = " -1.</returns>" fullword ascii 
$s20 = " <paramref name=\"count\" />. -" fullword ascii 
condition: 
uint16(0) == 0xbbef and filesize < 800KB and 
8 of them 
}

rule case_4778_settings {
meta:
description = "files - file settings.ini"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-15"
hash1 = "1a72704edb713083e6404b950a3e6d86afca4d95f7871a98fe3648d776fbef8f"
strings:
$s1 = "Ic7W XFLTwmYB /veeqpn mm rNz7 lY5WKgC aa O+ gwQZk w553aN QVadRj bHPOWC4 WljBKlx0 MP QJ3hjf8 XvG7aEZ wlSkTvHm SEXtrsTu OX+xjJw Xi" ascii
$s2 = "ivkxmyr f=nrgq aboircc lyj low qo tmvckp yjomrk dmfno ebwdia gp yev yyu jw wlen" fullword ascii
$s3 = "upq bavcxdeo=wkoirc shbn gp eqjs trduez gph islqz gohansev ohqvr qerg tluzcx e" fullword ascii
$s4 = "ewqbguzc=lqoteuz dxrg dujdirch vk dy" fullword ascii
$s5 = "uM9+ m0Z4 Uv4s JzD+ URVdD0rX hx KL/CBg7 1swB3a 9W+b75hX v+g7aIMj qvCDtB4 Bb1KVV0 sgPQ3vY/ qOR Q70tOASA d96 o9qpjEh9 my C5 OyHYy " ascii
$s6 = "PvH fKrGk6Ce 7v/ EUB/Wdg4 Uu xt 46Rx0 LFN/0y MS9wgb RJ3LAPX1 7JOsxMuO 9QhAI3OY eD cJFQB JB5/Pxv1 o6k6Om1+ Ysk0 gOED SZAIMlvd XYp" ascii
$s7 = "IS8035IO jPcS NUv ki CkBVbty U2h97/b4 qux53NQX EtfZ jIix x+XD kk o5P8F oY116df KhfQFW ITx8J1E to5xMS2 c48rU EDYn vU M3 /j17SQ8 " fullword ascii
$s8 = "nfrjrvvrjbnvn=ZUf7R 82oI mNBOyrIZ AnT OR ZoH/R ARY6Ie U/CPR ZTcU /A OTCBJ AWTS YHydmOyR Y4Ce /F KOHVTHm OoRRG/ HkS9O YRyJm OjNp " ascii
$s9 = "Mwxsv yat168hG 2ntA+wd If 9t+c JBrj3 TOGVRLIU asQ X5o3suBk /zEMhzTf prea EYg020Bh FAINYrz nTGIA2/6 Ic4 oH okCTwop t+Opo G3HIR QA" ascii
$s10 = "MM0R 3H fY zeMX HZ DqyktfL /eE73Yl2 6J/QRXF SDalWcW dp bJhHg /ueKC bZuj wSZc RV5U t6e Dr1JHm7Y VGD9j Y/bc 0sJh SjLoaP 2zm2NICQ 6" ascii
$s11 = "H i1+ai xvOkY dI +6 YXkl Wmjk+ IHB4qYqZ Ggf1B Pqkj fmrf 9F aStH1t5 kw 8PCCq DcNV3 S0 YR 7TDpT RkpM7B aPBXnS TdIcikWD xvg1Kiz 1Z " ascii
$s12 = "8q AtNe/4 t2/rXl 8mi8 nHS QmfaYeDZ ni+ al1T5lg di 5s 7fLXN I1ZLgd gBWGgrzR M82E ii Kbc u1jj7o 8Qqaz Z/g3ewH 6jTA2DK IyZypevS QTu" ascii
$s13 = "sfzvvvjfzbzzzrzfjrn=6gLhlcUJ EQ4xV0ys 4lbs kxnY 4d Rh0sQU Eeb9t2Y BS qk+C B4P2S eU0Fxi1W yUo RTee48t5 EN9ItyYW 12Y6LnlS ftZ Ua j" ascii
$s14 = "binzopjkunzo=yf s wqv chl vw hyn tucxajs ej sl" fullword ascii
$s15 = "ecbrunpd=mczjh ber m c gp q" fullword ascii
$s16 = "pmqjyxlxcmdxn=vpfzhiy" fullword ascii
$s17 = "ehdujdirch=fymfwh yf cang lo w" fullword ascii
$s18 = "oldzs mz xy=rgotan ftich qbot nw smgo" fullword ascii
$s19 = "jxfowlrkdyf=ds bx ajosq vgwln cn sctiop" fullword ascii
$s20 = "ksct=fbkd lengohq joxerr hdbrch mfotdo" fullword ascii
condition:
uint16(0) == 0x655b and filesize < 200KB and
8 of them
}

rule case_4778_launcher {
meta:
description = "files - file launcher.bat"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-15"
hash1 = "d9e8440665f37ae16b60ba912c540ba1f689c8ef7454defbdbf6ce7d776b8e24"
strings:
$s1 = "%oveqxh%%qvgs%%siksf%%dlxh%%mdiry%%bkpy%%eluai%%cnvepu%%gpwfty%%bkpy%%jvfkra%%irckvi%%gpxipg%%veoamv%%veqa%%obkpb%%bkpy%%gpuc%%u" ascii
$s2 = "%oveqxh%%qvgs%%siksf%%dlxh%%mdiry%%bkpy%%eluai%%cnvepu%%gpwfty%%bkpy%%jvfkra%%irckvi%%gpxipg%%veoamv%%veqa%%obkpb%%bkpy%%gpuc%%u" ascii
$s3 = "%nhmveo%%siksf%irckvi%aqvmr%d" fullword ascii
$s4 = "bgobkp%%owing%%eqxo%%irckvi%%gobk%%gwcnve%%fryrww%%najafo%%cnvepu%%wgnvi%%amwen%%gpxipg%%pgpu%%cnvepu%" fullword ascii
$s5 = "%nhmveo% siksf= " fullword ascii
$s6 = "%nhmveo%%siksf%gpuc%aqvmr%Ap" fullword ascii
$s7 = "%nhmveo%%siksf%aqvmr==" fullword ascii
$s8 = "%nhmveo%%siksf%mdiry%aqvmr%:" fullword ascii
$s9 = "%nhmveo%%siksf%gpxipg%aqvmr%." fullword ascii
$s10 = "%nhmveo%%siksf%owing%aqvmr%7f" fullword ascii
$s11 = "%nhmveo%%siksf%bgobkp%aqvmr%659" fullword ascii
$s12 = "%nhmveo%%siksf%ygob%aqvmr%D" fullword ascii
$s13 = "%nhmveo%%siksf%pgpu%aqvmr%ex" fullword ascii
$s14 = "%nhmveo%%siksf%otmrb%aqvmr%l" fullword ascii
$s15 = "%nhmveo%%siksf%wclsbn%aqvmr%iMe" fullword ascii
$s16 = "%nhmveo%%siksf%qvgs%aqvmr%rt" fullword ascii
$s17 = "%nhmveo%%siksf%udpwpu%aqvmr%pD" fullword ascii
$s18 = "%nhmveo%%siksf%najafo%aqvmr%22c" fullword ascii
$s19 = "%nhmveo%%siksf%fryrww%aqvmr%d4d" fullword ascii
$s20 = "%nhmveo%%siksf%ensen%aqvmr%ee" fullword ascii
condition:
uint16(0) == 0x6573 and filesize < 4KB and
8 of them
}

rule case_4778_1a5f3ca6597fcccd3295ead4d22ce70b {
meta:
description = "files - file 1a5f3ca6597fcccd3295ead4d22ce70b.exe"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
date = "2021-08-15"
hash1 = "7501da197ff9bcd49198dce9cf668442b3a04122d1034effb29d74e0a09529d7"
strings:
$s1 = "addconsole.dll" fullword wide
$s2 = "C:\\Wrk\\mFiles\\86\\1\\Release\\addconsole.pdb" fullword ascii
$s3 = ">->3>D>}>" fullword ascii /* hex encoded string '=' */
$s4 = "kmerjgyuhwjvueruewghgsdpdeo" fullword ascii
$s5 = "~DMUlA].JVJ,[2^>O" fullword ascii
$s6 = "xgF.lxh" fullword ascii
$s7 = "2.0.0.11" fullword wide
$s8 = "aripwx" fullword ascii
$s9 = "YwTjoq1" fullword ascii
$s10 = "LxDgEm0" fullword ascii
$s11 = "rvrpsn" fullword ascii
$s12 = "qb\"CTUAA~." fullword ascii
$s13 = ":,7;\"/1/= 1!'4'(&*?/:--(-(!1(&9JVJVMO\\JBSBS[UBT_JHC@GLZMA\\QKUKVj{oi~m~ppeqdww~{bk" fullword ascii
$s14 = ":,(9,=1?$2%06=:=*<'+2?!?-00!17$7XVZO_J]]X]XQAXVIZFZF]_LZRCRCKERDozxspw|j}qla{e{fzk" fullword ascii
$s15 = "Time New Roman" fullword ascii
$s16 = "gL:hdwKR8T" fullword ascii
$s17 = "NwQvL?_" fullword ascii
$s18 = "TEAqQ>W/" fullword ascii
$s19 = "+mnHy<m8" fullword ascii
$s20 = "uTVWh-F@" fullword ascii
condition:
uint16(0) == 0x5a4d and filesize < 2000KB and
( pe.imphash() == "ae9182174b5c4afd59b9b6502df5d8a1" or 8 of them )
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-09-01
Identifier: Case 5087 BazarLoader to Conti Ransomware in 32 Hours
Reference: https://thedfirreport.com/2021/09/13/bazarloader-to-conti-ransomware-in-32-hours/
*/

/* Rule Set ----------------------------------------------------------------- */

rule case_5087_start_bat { 
   meta: 
      description = "Files - file start.bat" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-30" 
      hash1 = "63de40c7382bbfe7639f51262544a3a62d0270d259e3423e24415c370dd77a60" 
   strings: 
      $x1 = "powershell.exe Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force" fullword ascii 
      $x2 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %method" fullword ascii 
      $x3 = "powershell.exe -executionpolicy remotesigned -File .\\Get-DataInfo.ps1 %1)" fullword ascii 
      $s4 = "set /p method=\"Press Enter for collect [all]:  \"" fullword ascii 
      $s5 = "echo \"Please select a type of info collected:\"" fullword ascii 
      $s6 = "echo \"all ping disk soft noping nocompress\"" fullword ascii 
   condition: 
      filesize < 1KB and all of them 
} 



rule case_5087_3 { 
   meta: 
      description = "Files - file 3.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-30" 
      hash1 = "37b264e165e139c3071eb1d4f9594811f6b983d8f4b7ef1fe56ebf3d1f35ac89" 
   strings: 
      $s1 = "https://sectigo.com/CPS0" fullword ascii 
      $s2 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii 
      $s3 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii 
      $s4 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii 
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\"/>" fullword ascii 
      $s6 = "http://ocsp.sectigo.com0" fullword ascii 
      $s7 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii 
      $s8 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii 
      $s9 = "ealagi@aol.com0" fullword ascii 
      $s10 = "bhfatmxx" fullword ascii 
      $s11 = "orzynoxl" fullword ascii 
      $s12 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii 
      $s13 = "      <!--The ID below indicates application support for Windows 8.1 -->" fullword ascii 
      $s14 = "      <!--The ID below indicates application support for Windows 8 -->" fullword ascii 
      $s15 = "O:\\-e%" fullword ascii 
      $s16 = "      <!--The ID below indicates application support for Windows 10 -->" fullword ascii 
      $s17 = "      <!--The ID below indicates application support for Windows 7 -->" fullword ascii 
      $s18 = "      <!--The ID below indicates application support for Windows Vista -->" fullword ascii 
      $s19 = "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii 
      $s20 = "  </compatibility>" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 1000KB and 8 of them 
} 

rule case_5087_7A86 { 
   meta: 
      description = "Files - file 7A86.dll" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-30" 
      hash1 = "9d63a34f83588e208cbd877ba4934d411d5273f64c98a43e56f8e7a45078275d" 
   strings: 
      $s1 = "ibrndbiclw.dll" fullword ascii 
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
      $s3 = "Type Descriptor'" fullword ascii 
      $s4 = "operator co_await" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 500KB and all of them 
} 

 rule case_5087_24f692b4ee982a145abf12c5c99079cfbc39e40bd64a3c07defaf36c7f75c7a9 { 
   meta: 
      description = "Files - file 24f692b4ee982a145abf12c5c99079cfbc39e40bd64a3c07defaf36c7f75c7a9.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-30" 
      hash1 = "24f692b4ee982a145abf12c5c99079cfbc39e40bd64a3c07defaf36c7f75c7a9" 
   strings: 
      $s1 = "fbtwmjnrrovmd.dll" fullword ascii 
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
      $s3 = " Type Descriptor'" fullword ascii 
      $s4 = "operator co_await" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 900KB and all of them 
}
/* 
   YARA Rule Set 
   Author: The DFIR Report 
   Date: 2021-10-31 
   Identifier: Case 5295 From Zero to Domain Admin
   Reference: https://thedfirreport.com/2021/11/01/from-zero-to-domain-admin/ 

*/ 



/* Rule Set ----------------------------------------------------------------- */ 

rule __case_5295_1407 { 
   meta: 
      description = "5295 - file 1407.bin" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "45910874dfe1a9c3c2306dd30ce922c46985f3b37a44cb14064a963e1244a726" 
   strings: 
      $s1 = "zG<<&Sa" fullword ascii 
      $s2 = "r@TOAa" fullword ascii 
      $s3 = "DTjt{R" fullword ascii 
   condition: 
      uint16(0) == 0xa880 and filesize < 2KB and 
      all of them 
} 



rule _case_5295_sig_7jkio8943wk { 
   meta: 
      description = "5295 - file 7jkio8943wk.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "dee4bb7d46bbbec6c01dc41349cb8826b27be9a0dcf39816ca8bd6e0a39c2019" 
   strings: 
      $s1 = " (os error other os erroroperation interruptedwrite zerotimed outinvalid datainvalid input parameteroperation would blockentity " ascii 
      $s2 = "already existsbroken pipeaddress not availableaddress in usenot connectedconnection abortedconnection resetconnection refusedper" ascii 
      $s3 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii 
      $s4 = "UnexpectedEofNotFoundPermissionDeniedConnectionRefusedConnectionResetConnectionAbortedNotConnectedAddrInUseAddrNotAvailableBroke" ascii 
      $s5 = "nPipeAlreadyExistsWouldBlockInvalidInputInvalidDataTimedOutWriteZeroInterruptedOtherN" fullword ascii 
      $s6 = "failed to fill whole buffercould not resolve to any addresses" fullword ascii 
      $s7 = " (os error other os erroroperation interruptedwrite zerotimed outinvalid datainvalid input parameteroperation would blockentity " ascii 
      $s8 = "mission deniedentity not foundunexpected end of fileGetSystemTimePreciseAsFileTime" fullword ascii 
      $s9 = "invalid socket addressinvalid port valuestrings passed to WinAPI cannot contain NULsinvalid utf-8: corrupt contentsinvalid utf-8" ascii 
      $s10 = "invalid socket addressinvalid port valuestrings passed to WinAPI cannot contain NULsinvalid utf-8: corrupt contentsinvalid utf-8" ascii 
      $s11 = "\\data provided contains a nul byteSleepConditionVariableSRWkernel32ReleaseSRWLockExclusiveAcquireSRWLockExclusive" fullword ascii 
      $s12 = "fatal runtime error: " fullword ascii 
      $s13 = "assertion failed: key != 0WakeConditionVariable" fullword ascii 
      $s14 = "kindmessage" fullword ascii 
      $s15 = "0x000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii 
      $s16 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writing non-UTF-8 byte sequences" fullword ascii 
      $s17 = "OS Error  (FormatMessageW() returned invalid UTF-16) (FormatMessageW() returned error )formatter error" fullword ascii 
      $s18 = "FromUtf8Errorbytes" fullword ascii 
      $s19 = "  VirtualProtect failed with code 0x%x" fullword ascii 
      $s20 = "invalid utf-8 sequence of  bytes from index incomplete utf-8 byte sequence from index " fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 800KB and 
      8 of them 
} 


rule __case_5295_check { 
   meta: 
      description = "5295 - file check.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "c443df1ddf8fd8a47af6fbfd0b597c4eb30d82efd1941692ba9bb9c4d6874e14" 
   strings: 
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii 
      $s2 = "F:\\Source\\WorkNew18\\CheckOnline\\Release\\CheckOnline.pdb" fullword ascii 
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii 
      $s4 = " Type Descriptor'" fullword ascii 
      $s5 = "operator co_await" fullword ascii 
      $s6 = "operator<=>" fullword ascii 
      $s7 = ".data$rs" fullword ascii 
      $s8 = "File opening error: " fullword ascii 
      $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii 
      $s10 = ":0:8:L:\\:h:" fullword ascii 
      $s11 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide 
      $s12 = " Base Class Descriptor at (" fullword ascii 
      $s13 = " Class Hierarchy Descriptor'" fullword ascii 
      $s14 = " Complete Object Locator'" fullword ascii 
      $s15 = "network reset" fullword ascii /* Goodware String - occured 567 times */ 
      $s16 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */ 
      $s17 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */ 
      $s18 = "network down" fullword ascii /* Goodware String - occured 567 times */ 
      $s19 = "owner dead" fullword ascii /* Goodware String - occured 567 times */ 
      $s20 = "protocol not supported" fullword ascii /* Goodware String - occured 568 times */ 
   condition: 
      uint16(0) == 0x5a4d and filesize < 500KB and 
      all of them 
} 


rule __case_5295_zero { 
   meta: 
      description = "5295 - file zero.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "3a8b7c1fe9bd9451c0a51e4122605efc98e7e4e13ed117139a13e4749e211ed0" 
   strings: 
      $x1 = "powershell.exe -c Reset-ComputerMachinePassword" fullword wide 
      $s2 = "COMMAND - command that will be executed on domain controller. should be surrounded by quotes" fullword ascii 
      $s3 = "ZERO.EXE IP DC DOMAIN ADMIN_USERNAME [-c] COMMAND :" fullword ascii 
      $s4 = "-c - optional, use it when command is not binary executable itself" fullword ascii 
      $s5 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii 
      $s6 = "C:\\p\\Release\\zero.pdb" fullword ascii 
      $s7 = "+command executed" fullword ascii 
      $s8 = "COMMAND - %ws" fullword ascii 
      $s9 = "rpc_drsr_ProcessGetNCChangesReply" fullword wide 
      $s10 = "ZERO.EXE -test IP DC" fullword ascii 
      $s11 = "to test if the target is vulnurable only" fullword ascii 
      $s12 = "IP - ip address of domain controller" fullword ascii 
      $s13 = "ADMIN_USERNAME - %ws" fullword ascii 
      $s14 = "error while parsing commandline. no command is found" fullword ascii 
      $s15 = "rpcbindingsetauthinfo fail" fullword ascii 
      $s16 = "x** SAM ACCOUNT **" fullword wide 
      $s17 = "%COMSPEC% /C " fullword wide 
      $s18 = "EXECUTED SUCCESSFULLY" fullword ascii 
      $s19 = "TARGET IS VULNURABLE" fullword ascii 
      $s20 = "have no admin rights on target, exiting" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 500KB and 
      1 of ($x*) and 4 of them 
} 


rule __case_5295_GAS { 
   meta: 
      description = "5295 - file GAS.exe" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "be13b8457e7d7b3838788098a8c2b05f78506aa985e0319b588f01c39ca91844" 
   strings: 
      $s1 = "A privileged instruction was executed at address 0x00000000." fullword ascii 
      $s2 = "Stack dump (SS:ESP)" fullword ascii 
      $s3 = "!This is a Windows NT windowed executable" fullword ascii 
      $s4 = "An illegal instruction was executed at address 0x00000000." fullword ascii 
      $s5 = "ff.exe" fullword wide 
      $s6 = "Open Watcom C/C++32 Run-Time system. Portions Copyright (C) Sybase, Inc. 1988-2002." fullword ascii 
      $s7 = "openwatcom.org" fullword wide 
      $s8 = "Open Watcom Dialog Editor" fullword wide 
      $s9 = "A stack overflow was encountered at address 0x00000000." fullword ascii 
      $s10 = "A fatal error is occured" fullword ascii 
      $s11 = "An integer divide by zero was encountered at address 0x00000000." fullword ascii 
      $s12 = "address 0x00000000 and" fullword ascii 
      $s13 = "Open Watcom" fullword wide 
      $s14 = "The instruction at 0x00000000 caused an invalid operation floating point" fullword ascii 
      $s15 = "The instruction at 0x00000000 caused a denormal operand floating point" fullword ascii 
      $s16 = "`.idata" fullword ascii /* Goodware String - occured 1 times */ 
      $s17 = "xsJr~.~" fullword ascii 
      $s18 = "iJJW3We" fullword ascii 
      $s19 = "Rmih_O|" fullword ascii 
      $s20 = "The instruction at 0x00000000 referenced memory " fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 200KB and 
      all of them 
} 


rule __case_5295_agent1 { 
   meta: 
      description = "5295 - file agent1.ps1" 
      author = "The DFIR Report" 
      reference = "https://thedfirreport.com" 
      date = "2021-08-12" 
      hash1 = "94dcca901155119edfcee23a50eca557a0c6cbe12056d726e9f67e3a0cd13d51" 
   strings: 
      $s1 = "[Byte[]]$oBUEFlUjsZVVaEBHhsKWa = [System.Convert]::FromBase64String((-join($gDAgdPFzzxgYnLNNHSSMR,'zzkKItFCIsIUejI/P//g8QMi1UIiU" ascii 
      $s2 = "ap0cqOwB7hW5z/yOlqICYNrdwqfvCvWSqWbfs/NWgxfvurRRLs7xIQrzXCCgwqMnhB154e8iubTSzAhliQfIRC1djlZTGXO4nBUD68VD/Zmo81DI9wVoQ2++AOz+IT3x" ascii 
      $s3 = "[Runtime.InteropServices.Marshal]::Copy($oBUEFlUjsZVVaEBHhsKWa,(2372 - 2372),$CjHxQlvEzGUrZUarFZbrz,$oBUEFlUjsZVVaEBHhsKWa.Lengt" ascii 
      $s4 = "[Runtime.InteropServices.Marshal]::Copy($oBUEFlUjsZVVaEBHhsKWa,(2372 - 2372),$CjHxQlvEzGUrZUarFZbrz,$oBUEFlUjsZVVaEBHhsKWa.Lengt" ascii 
      $s5 = "zSEEdr8FnfXshvasO1lodzp/T9fIQLBuz5baYtW7iK9lRAYZYDdQrnvpxmxJOxjuabTg5nBEWzTQSZaXmNRB2nSSK9/yfGeYecXO8FOXN8lEEE3BXhBrTFXDyXg1BiJb" ascii 
      $s6 = "eQvmMAIAnreX2We51OWxYt5ykA3Z9w9FN3hFaSuBjn2u6kwODP+r2Wv2ruryjIa0nyZxgwUCBotpX5U/k9jDsDgC9YyR1gvyD6r268nAnvMP09U+KvTM/AZhx/mFtget" ascii 
      $s7 = "3H2+O+/8sPyM9FWRrXUO/9a4LwBKmuv8Qsh/50l6VnyQGICZ8PuITwgJxzV37f/NZJqTrvQa70A0mf6hKrjuUSfulv/uUgYZmSdLPugLfe9WK9VenoTnKUT/ir/GHATM" ascii 
      $s8 = "sQroZ/z//wNF8BNV9IlF8IlV9ItF8ItV9LEG6G78//8zRfAzVfSJRfCJVfTpdP///4tF8ItV9LED6DD8//8DRfATVfSJRfCJVfSLRfCLVfSxC+g3/P//M0XwM1X0iUXw" ascii 
      $s9 = "a2cxwtfBqoUe4/erpeTB7XIYMFFtX23EEnTdPQbUXCd5O9j5mAeVZpRNWF9tvvy2+qlNieD1WlTj2fUZaiYPrpkKd7DllqHRkAbblgRp0IJO4yiFrd/xaGy8NiPtThnO" ascii 
      $s10 = "j+XqDEzWEbsdht2FdZc1j2/fJoIugVtps/bH7uP1dq8FA6+GVzpw0UN42KgXL9sMYAnJRJj6gpW7oZ1fGv4b+d2xjo8yQM798A3UWadQSGbnsmzV+2k/KmfqAlvYqIrC" ascii 
      $s11 = "ZQ0NlAxyJeQHiqm9NZr4Xjh9V25TXa0vWwb/yXI+IL59EdsKDkehBeuasslnEdfgAq7j+mEp0C70K+oeKHZwHnV9/fa4H93lInRTqutejUqOXfJN0Sqa0gkjX5lJvIzT" ascii 
      $s12 = "T/vbRvTMv6ePKoOS5EUjzgqjY7QZsueNgGEt1KTiP5R9zOnabhD20lmwcjl6vSapoMgKyS57Oqv0rZHShi+XWdJtmFgsRJYHLQcuMbqAmVRLb9GpaVkJl0fC2X+87Lup" ascii 
      $s13 = "$vpFhaWLTcsrOHCQLzsEzN = 'mbFPGDtpJicxXcdFG/Ydmz4dHGi5llA0tRmH2WwVJpYbsfxCiAfFy0kckQnw6EeyeH40K0H6hmZ/H4KpB3tbTVXrd6LvKnUmzVJ8eg" ascii 
      $s14 = "$nkRLOujTuMsDDaMxkgFbp = [OkwgNsSnFFEmvLpdsdISG]::CreateThread(($ZCHhKqfmmzVFPUgdkjqZk),(-6012 + 6012),$CjHxQlvEzGUrZUarFZbrz,(3" ascii 
      $s15 = "guQh6vh+8CQHOjfK/YMdwFr1UGqkMdLfobM5WYeyHvTezZttJ+hfHIT795hhejCINf/0AzPrunDuwun7kZ2ueDpJxwEfcqtHkvmt4qhgcGu0UuebvxPgjnrZQ3i7OWiG" ascii 
      $s16 = "+SvFBrG7BgR5cmdbbRuoy7ewt2CJqeJXmYVV3b1tf+Rw1xb1P6vNtyobWpXNYfVu9TAVUcxKXQxoOTum5J4q6E7iTyIltAmiRnxUxTlQwjjhwOfYdYviZSKlKJ32tl2x" ascii 
      $s17 = "    [DllImport(\"kernel32.dll\")]" fullword ascii 
      $s18 = "/v0KltMpb69/8jsWR23PkNuPrK3FXehCwqN1FYNCGR+tbLJ4oEzVw/sOoCrrK91sAjUs1yNKhJXRjJ4Td/AAB+51bVz1CMXtUzaZ80eDvILBw4eMSltg04/7XSRV3O5B" ascii 
      $s19 = "$wLHiDWZiDeApQYLEVCjxX = (([regex]::Matches('qisBjSUmAFJ0IqAT3R+byDBdA3K6vHNI//aNbyh+ZYFOREbwR+QFlGQ3OUlMZO4EkPJppVBn3syXugkbjkn" ascii 
      $s20 = "M9KA4R/T6MMzwDPSw8xVi+yD7AiLRQiJRfiLTRCJTfyLVRCD6gGJVRCDffwAdB6LRQiLTQyKEYgQi0UIg8ABiUUIi00Mg8EBiU0M682LRfiL5V3DzMzMzMzMzMzMzFWL" ascii 
   condition: 
      uint16(0) == 0x6441 and filesize < 100KB and 
      8 of them 
} 
/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-09-01
Identifier: Case 5426 BazarLoader and the Conti Leaks
Reference: https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/
*/

rule informational_AnyDesk_Remote_Software_Utility { 

   meta: 
      description = "files - AnyDesk.exe" 
      author = "TheDFIRReport" 
      date = "2021-07-25" 
      hash1 = "9eab01396985ac8f5e09b74b527279a972471f4b97b94e0a76d7563cf27f4d57" 
   strings: 
      $x1 = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb" fullword ascii 
      $s2 = "release/win_6.3.x" fullword ascii 
      $s3 = "16eb5134181c482824cd5814c0efd636" fullword ascii 
      $s4 = "b1bfe2231dfa1fa4a46a50b4a6c67df34019e68a" fullword ascii 
      $s5 = "Z72.irZ" fullword ascii 
      $s6 = "ysN.JTf" fullword ascii 
      $s7 = ",;@O:\"" fullword ascii 
      $s8 = "ekX.cFm" fullword ascii 
      $s9 = ":keftP" fullword ascii 
      $s10 = ">FGirc" fullword ascii 
      $s11 = ">-9 -D" fullword ascii 
      $s12 = "% /m_v?" fullword ascii 
      $s13 = "?\\+ X5" fullword ascii 
      $s14 = "Cyurvf7" fullword ascii 
      $s15 = "~%f_%Cfcs" fullword ascii 
      $s16 = "wV^X(P+ " fullword ascii 
      $s17 = "\\Ej0drBTC8E=oF" fullword ascii 
      $s18 = "W00O~AK_=" fullword ascii 
      $s19 = "D( -m}w" fullword ascii 
      $s20 = "avAoInJ1" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 11000KB and 
      1 of ($x*) and 4 of them 
} 

rule cobalt_strike_dll21_5426 { 
   meta: 
      description = "files - 21.dll" 
      author = "TheDFIRReport" 
      date = "2021-07-25" 
      hash1 = "96a74d4c951d3de30dbdaadceee0956682a37fcbbc7005d2e3bbd270fbd17c98" 
   strings: 
      $s1 = "AWAVAUATVWUSH" fullword ascii 
      $s2 = "UAWAVVWSPH" fullword ascii 
      $s3 = "AWAVAUATVWUSPE" fullword ascii 
      $s4 = "UAWAVATVWSH" fullword ascii 
      $s5 = "AWAVVWUSH" fullword ascii 
      $s6 = "UAWAVAUATVWSH" fullword ascii 
      $s7 = "AVVWSH" fullword ascii 
      $s8 = "m1t6h/o*i-j2p2g7i0r.q6j3p,j2l2s7p/s9j-q0f9f,i7r2g1h*i8r5h7g/q9j4h*o7i4r9f7f3g*p/q7o1e5n8m1q4n.e+n0i*r/i*k2q-g0p-n+q7l3s6h-h6j*q/" ascii 
      $s9 = "s-e6m/f-g*j.i8p1g6j*i,o1s9o5f8r-p1l1k4o9n9l-s7q8g+n,f4t0q,f6n9q5s5e6i-f*e6q-r6g8s1o6r0k+h6p9i4f6p4s6l,g0p1j6l4s1l4h2f,s9p8t5t/g6" ascii 
      $s10 = "o1s1s9i2s.f1g5l6g5o2k8h*e9j2o3k0j1f+n,k9h5l*e8p*s2k5r3j-f5o-f,g+e*s-e9h7e.t0e-h3e2t1f8j5k/m9p6n/j3h9e1k3h.t6h2g1p.l*q8o*t9l6p4s." ascii 
      $s11 = "k7s9g7m5k4s5o3h6k.s1p.h9k.s-o8e*f5n9r,l4f-s5k3p2f/n1r.i*f*n-p4s3e7m9p2t/e3m5g1s9e0m1q/j*e*m-r*i+h.p9s2f6h-p5s6e2h8p1s*j.h3p-s.h0" ascii 
      $s12 = "k9g9o0t1s4k*k*h.s-p-k.h-m1k*f4h0j7f6n,i5g-n3h+l3n1j7j0e*n5r6r-i9i/e1q4m6i3e2o8j9h9e0m.r-i9m*t4j/r.o*l8m4i.t5l,g-h0p6f7l+p-l3l,g." ascii 
      $s13 = "s6k9n/j.s4s5g2p6s.k1t/j6s,s-g*p.n6f9m/g.n4n5j2q6n.f1p/g6n,n-j*q.m6e9o/h.m4m5i2r6m.e1p/h6m,m-i*r.p6h9m/e.p4p5l2s6p.h1l/e7p,p-l*s." ascii 
      $s14 = "r4k7g8t-k4o6m,o1s1k.k1s6o,h8k-s4j8q*m+f/i*q/f3m-r5j2n0f0i*q0m/e0j5q7n5f4j7q3n7f1m4g2s,g5s5l9h7s9p1o.t8k5r-j3t.k8h1t6r7m-l5h5t1l*" ascii 
      $s15 = "k8s9n7o9k5s5o9m2k0s1m3m.k,s-n+o-f9n9t+t6f4n5o6t2f0n1s/r1f-n-o.t*e8m9i-s6e4m5t3q5e1m1i5s.e,m-k0s*h8p9q7t9h5p5j8r2h0p1h+r.h,p-q+t-" ascii 
      $s16 = "o9g6g0l0s1e6h4p-g6s9s9p1m1k*s3l-t5s.f8m5r5f6n+i2j8f*h,p5j2r.h0h1q9i6e8r-i*n8m-r5s-l.i8f2i1k.o4n1t9l6l0g,p9j6f,g.l-j*n0o-t-l*p5s-" ascii 
      $s17 = "t8n2i3e0i,l.i7i9e8r1j7o0n3i9j0m3m-l6e6s9r*l6s5h4t6n7o*k.r1f+r4l/q9g7i3o.m+t9q*g/j0h0e1n*m3i,h.e4n3i5n-r9g1h2k6m7j,e,p3p+h2o4f/h4" ascii 
      $s18 = "[_^A^A_]" fullword ascii 
      $s19 = "k9s9f+j*k3s5o-j/k/s1h/p5k-s-o7j7f7n9t/g+f3n5q/r8f1n1t7g3f+n-p.g8e7m9s3q4e5m5o+h0e/m1g-h4e+m-m+q0h9p9f/e,h3p5l6e1h/p1o7t,h-p-k+f5" ascii 
      $s20 = "g8s9j0t4o,t+n3t1g0k9k1t,o5s0n+t9n6j+o0q2i4j6r1i3f,g+j2h1f2r1n-e9m,i2i7f3q4m-n7n4m.r.e1s*j,m5p/n0n6s8p9g/o7l3t+g.m.q.l7g6t,e-o/q." ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 2000KB and 
      8 of them 
} 

import "pe" 

rule cobalt_strike_exe21 { 
   meta: 
      description = "files -  21.exe" 
      author = "TheDFIRReport" 
      date = "2021-07-25" 
      hash1 = "972e38f7fa4c3c59634155debb6fb32eebda3c0e8e73f4cb264463708d378c39" 
   strings: 
      $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii 
      $s2 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii 
      $s3 = "1brrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrr" ascii 
      $s4 = "\\hzA\\Vza\\|z%\\2z/\\3z\"\\/z%\\/z8\\9z\"\\(zl\\3z\"\\9z4\\5z8\\|z.\\9z+\\5z\"\\qz)\\2z(\\|z:\\=z>\\5z-\\>z \\9z?\\QzF\\\\zL\\" fullword ascii 
      $s5 = "\\zL\\/z>\\qz.\\=za\\0z-\\(z\"\\\\zL\\/z>\\qz?\\,za\\?z5\\.z \\\\zL\\/z>\\qz?\\,za\\0z-\\(z\"\\\\zL\\/z:\\qz*\\5zL\\\\zL\\/z:\\q" ascii 
      $s6 = "\\zL:\\zL" fullword ascii 
      $s7 = "\\\\z:\\\\z" fullword ascii 
      $s8 = "\\qz/\\3z!\\,z%\\0z)\\8zl\\tzc\\?z \\.ze\\|z*\\)z\"\\?z8\\5z#\\2zl\\:z>\\3z!\\|z-\\|z\"\\=z8\\5z:\\9zl\\?z#\\2z?\\(z>\\)z/\\(z#" ascii 
      $s9 = "qz<\\%zL\\\\zL\\9z?\\qz?\\*zL\\\\zL\\9z?\\qz9\\%zL\\\\zL\\9z?\\qz:\\9zL\\\\zL\\9z8\\qz)\\9zL\\\\zL\\9z9\\qz)\\/zL\\\\zL\\:z-\\qz" ascii 
      $s10 = "zL\\\\zL\\0z:\\qz" fullword ascii 
      $s11 = "z-\\(z\"\\\\zL\\/z:\\qz" fullword ascii 
      $s12 = "  VirtualProtect failed with code 0x%x" fullword ascii 
      $s13 = "3\\)z'\\\\zL\\>z)\\\\zL\\/z \\\\zL\\9z8\\\\zL\\0z:\\\\zL\\0z8\\\\zL\\:z-\\\\zL\\*z%\\\\zL\\4z5\\\\zL\\=z6\\\\zL\\9z9\\\\zL\\1z'" ascii 
      $s14 = "z#\\\\zL\\,z \\\\zL\\,z8\\\\zL\\.z#\\\\zL\\.z9\\\\zL\\4z>\\\\zL\\/z'\\\\zL\\/z=\\\\zL\\/z:\\\\zL\\(z$\\\\zL\\(z>\\\\zL\\)z>\\\\z" ascii 
      $s15 = "qz \\5zL\\\\zL\\8z)\\qz \\)zL\\\\zL\\8z%\\*za\\1z:\\\\zL\\9z \\qz+\\.zL\\\\zL\\9z\"\\qz-\\)zL\\\\zL\\9z\"\\qz.\\&zL\\\\zL\\9z\"" ascii 
      $s16 = "qz<\\7zL\\\\zL\\)z6\\qz9\\&za\\?z5\\.z \\\\zL\\)z6\\qz9\\&za\\0z-\\(z\"\\\\zL\\*z%\\qz:\\2zL\\\\zL\\$z$\\qz6\\=zL\\\\zL\\&z$\\qz" ascii 
      $s17 = "qz'\\.zL\\\\zL\\7z5\\qz'\\;zL\\\\zL\\0z8\\qz \\(zL\\\\zL\\0z:\\qz \\*zL\\\\zL\\1z%\\qz\"\\&zL\\\\zL\\1z'\\qz!\\7zL\\\\zL\\1z \\q" ascii 
      $s18 = "]zL\\=z*\\qz6\\=zL\\\\zL\\=z>\\qz-\\9zL\\\\zL\\=z>\\qz.\\4zL\\\\zL\\=z>\\qz(\\&zL\\\\zL\\=z>\\qz)\\;zL\\\\zL\\=z>\\qz%\\-zL\\\\z" ascii 
      $s19 = "  Unknown pseudo relocation protocol version %d." fullword ascii 
      $s20 = "\\L*L\\]qN\\WHKl]qO\\W{j\\XJL\\][G\\}" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 800KB and (pe.imphash()=="17b461a082950fc6332228572138b80c" or  
8 of them) 
} 

rule informational_NtdsAudit_AD_Audit_Tool { 
   meta: 
      description = "files - NtdsAudit.exe" 
      author = "TheDFIRReport" 
      date = "2021-07-25" 
      hash1 = "fb49dce92f9a028a1da3045f705a574f3c1997fe947e2c69699b17f07e5a552b" 
   strings: 
      $x1 = "WARNING: Use of the --pwdump option will result in decryption of password hashes using the System Key." fullword wide 
      $s2 = "costura.nlog.dll.compressed" fullword wide 
      $s3 = "costura.microsoft.extensions.commandlineutils.dll.compressed" fullword wide 
      $s4 = "Password hashes have only been dumped for the \"{0}\" domain." fullword wide 
      $s5 = "The NTDS file contains user accounts with passwords stored using reversible encryption. Use the --dump-reversible option to outp" wide 
      $s6 = "costura.system.valuetuple.dll.compressed" fullword wide 
      $s7 = "TargetRNtdsAudit.NTCrypto.#DecryptDataUsingAes(System.Byte[],System.Byte[],System.Byte[])T" fullword ascii 
      $s8 = "c:\\Code\\NtdsAudit\\src\\NtdsAudit\\obj\\Release\\NtdsAudit.pdb" fullword ascii 
      $s9 = "NtdsAudit.exe" fullword wide 
      $s10 = "costura.esent.interop.dll.compressed" fullword wide 
      $s11 = "costura.costura.dll.compressed" fullword wide 
      $s12 = "costura.registry.dll.compressed" fullword wide 
      $s13 = "costura.nfluent.dll.compressed" fullword wide 
      $s14 = "dumphashes" fullword ascii 
      $s15 = "The path to output hashes in pwdump format." fullword wide 
      $s16 = "Microsoft.Extensions.CommandLineUtils" fullword ascii 
      $s17 = "If you require password hashes for other domains, please obtain the NTDS and SYSTEM files for each domain." fullword wide 
      $s18 = "microsoft.extensions.commandlineutils" fullword wide 
      $s19 = "-p | --pwdump <file>" fullword wide 
      $s20 = "get_ClearTextPassword" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 2000KB and 
      1 of ($x*) and 4 of them 
} 

rule informational_AdFind_AD_Recon_and_Admin_Tool {
   meta: 
      description = "files - AdFind.exe" 
      author = "TheDFIRReport" 
      date = "2021-07-25" 
      hash1 = "b1102ed4bca6dae6f2f498ade2f73f76af527fa803f0e0b46e100d4cf5150682" 
   strings: 
      $s1 = "   -sc dumpugcinfo         Dump info for users/computers that have used UGC" fullword ascii 
      $s2 = "   -sc computers_pwdnotreqd Dump computers set with password not required." fullword ascii 
      $s3 = "   -sc computers_inactive  Dump computers that are disabled or password last set" fullword ascii 
      $s4 = "   -sc computers_active    Dump computers that are enabled and password last" fullword ascii 
      $s5 = "   -sc ridpool             Dump Decoded Rid Pool Info" fullword ascii 
      $s6 = "      Get top 10 quota users in decoded format" fullword ascii 
      $s7 = "   -po           Print options. This switch will dump to the command line" fullword ascii 
      $s8 = "ERROR: Couldn't properly encode password - " fullword ascii 
      $s9 = "   -sc users_accexpired    Dump accounts that are expired (NOT password expiration)." fullword ascii 
      $s10 = "   -sc users_disabled      Dump disabled users." fullword ascii 
      $s11 = "   -sc users_pwdnotreqd    Dump users set with password not required." fullword ascii 
      $s12 = "   -sc users_noexpire      Dump non-expiring users." fullword ascii 
      $s13 = "    adfind -default -rb ou=MyUsers -objfilefolder c:\\temp\\ad_out" fullword ascii 
      $s14 = "      Dump all Exchange objects and their SMTP proxyaddresses" fullword ascii 
      $s15 = "WLDAP32.DLL" fullword ascii 
      $s16 = "AdFind.exe" fullword ascii 
      $s17 = "                   duration attributes that will be decoded by the -tdc* switches." fullword ascii 
      $s18 = "   -int8time- xx Remove attribute(s) from list to be decoded as int8. Semicolon delimited." fullword ascii 
      $s19 = "replTopologyStayOfExecution" fullword ascii 
      $s20 = "%s: [%s] Error 0x%0x (%d) - %s" fullword ascii 
   condition: 
      uint16(0) == 0x5a4d and filesize < 4000KB and 
      8 of them 
}
/*                                                                                                      YARA Rule Set
   Author: The DFIR Report
   Date: 2021-10-10
   Identifier: Case 5582 IcedID to XingLocker Ransomware in 24 hours
   Reference: https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
*/

/* Rule Set -------------------------------------------------------*/
import "pe"

rule DLLBeacons { 
  meta:
      description = "for files:  kaslose64.dll, spoolsv.exe, kaslose.dll, croperdate64.dll"
      author = "TheDFIRReport"
      date = "2021-09-14"
      hash1 = "a4d92718e0a2e145d014737248044a7e11fb4fd45b683fcf7aabffeefa280413"
      hash2 = "0d575c22dfd30ca58f86e4cf3346180f2a841d2105a3dacfe298f9c7a22049a0"
      hash3 = "320296ea54f7e957f4fc8d78ec0c1658d1c04a22110f9ddffa6e5cb633a1679c"
      hash4 = "1b981b4f1801c31551d20a0a5aee7548ec169d7af5dbcee549aa803aeea461a0"
  strings:
      $s1 = "f14m80.dll" fullword ascii
      $s2 = "\\dxdiag.exe" fullword ascii
      $s3 = "\\regedit.exe" fullword ascii
      $s4 = "\\notepad.exe" fullword ascii
      $s5 = "\\mmc.exe" fullword ascii
      $s6 = "spawn::resuming thread %02d" fullword ascii
      $s7 = "xYYyQDllwAZFpV51" fullword ascii
      $s8 = "thread [%d]: finished" fullword ascii
      $s9 = "wmi: error initialize COM security" fullword ascii
      $s10 = "error initializing COM" fullword ascii
      $s11 = "spawn::first wait failed: 0x%04x" fullword ascii
      $s12 = "wmi: connect to root\\cimv2 failed: 0x%08x" fullword ascii
      $s13 = "jmPekFtanAOGET_5" fullword ascii
      $s14 = "spawn::decrypted" fullword ascii
      $s15 = "eQ_Jt_fIrCE85LW3" fullword ascii
      $s16 = "dBfdWB3uu8sReye1" fullword ascii
      $s17 = "qpp0WQSPyuCnCEm3" fullword ascii
      $s18 = "zn9gkPgoo_dOORd3" fullword ascii
      $s19 = "wmi: probaly running on sandbox" fullword ascii
      $s20 = "spawn::finished" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}



rule fed3_fed2_4 {
   meta:
      description = "for files:  fed3.bat, fed2.bat"
      author = "TheDFIRReport"
      date = "2021-09-14"
      hash1 = "8dced0ed6cba8f97c0b01f59e063df6be8214a1bd510e4774ef7f30c78875f4e"
      hash2 = "bf908d50760e3724ed5faa29b2a96cb1c8fc7a39b58c3853598d8b1ccfd424ac"
   strings:
      $s1 = "reg add \"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderAuditLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f" ascii
      $s2 = "reg add \"HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger\" /v \"Start\" /t REG_DWORD /d \"0\" /f" fullword ascii
      $s3 = "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Windows Defender\" /f" fullword ascii
      $s4 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\WinDefend\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s5 = "reg delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"WindowsDefender\" /f" fullword ascii
      $s6 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdFilter\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s7 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdNisSvc\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s8 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdBoot\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s9 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s10 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdNisDrv\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s11 = "reg delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run\" /v \"Windows Defender\" /f" fullword ascii
      $s12 = "rem 0 - Disable Logging" fullword ascii
      $s13 = "rem Run \"Disable WD.bat\" again to disable WD services" fullword ascii
      $s14 = "schtasks /Change /TN \"Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh\" /Disable" fullword ascii
      $s15 = "reg delete \"HKCR\\Directory\\shellex\\ContextMenuHandlers\\EPP\" /f" fullword ascii
      $s16 = "reg delete \"HKCR\\*\\shellex\\ContextMenuHandlers\\EPP\" /f" fullword ascii
      $s17 = "reg delete \"HKCR\\Drive\\shellex\\ContextMenuHandlers\\EPP\" /f" fullword ascii
      $s18 = "schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\" /Disable" fullword ascii
      $s19 = "schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup\" /Disable" fullword ascii
      $s20 = "schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Verification\" /Disable" fullword ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 10KB and ( 8 of them )
      ) or ( all of them )
}

rule fed3_fed1_5 {
   meta:
      description = "for files:  fed3.bat, fed1.bat"
      author = "TheDFIRReport"
      date = "2021-09-14"
      hash1 = "8dced0ed6cba8f97c0b01f59e063df6be8214a1bd510e4774ef7f30c78875f4e"
      hash2 = "81a1247465ed4b6a44bd5b81437024469147b75fe4cb16dc4d2f7b912463bf12"
   strings:
      $s1 = "rem https://technet.microsoft.com/en-us/itpro/powershell/windows/defender/set-mppreference" fullword ascii
      $s2 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"SpynetReporting\" /t REG_DWORD /d \"0\" /f" fullword ascii
      $s3 = "rem reg add \"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\" /v \"Start\" /t REG_DWORD /d \"4\" /f" fullword ascii
      $s4 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiSpyware\" /t REG_DWORD /d \"1\" /f" fullword ascii
      $s5 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"SubmitSamplesConsent\" /t REG_DWORD /d \"0\" /f" fullword ascii
      $s6 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet\" /v \"DisableBlockAtFirstSeen\" /t REG_DWORD /d \"1\" /" ascii
      $s7 = "rem USE AT OWN RISK AS IS WITHOUT WARRANTY OF ANY KIND !!!!!" fullword ascii
      $s8 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableScanOnRealtimeEnable\" /t RE" ascii
      $s9 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableScanOnRealtimeEnable\" /t RE" ascii
      $s10 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableBehaviorMonitoring\" /t REG_" ascii
      $s11 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableBehaviorMonitoring\" /t REG_" ascii
      $s12 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableOnAccessProtection\" /t REG_" ascii
      $s13 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableRealtimeMonitoring\" /t REG_" ascii
      $s14 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableIOAVProtection\" /t REG_DWOR" ascii
      $s15 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableRealtimeMonitoring\" /t REG_" ascii
      $s16 = "rem 1 - Disable Real-time protection" fullword ascii
      $s17 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\" /v \"DisableAntiVirus\" /t REG_DWORD /d \"1\" /f" fullword ascii
      $s18 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableOnAccessProtection\" /t REG_" ascii
      $s19 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\MpEngine\" /v \"MpEnablePus\" /t REG_DWORD /d \"0\" /f" fullword ascii
      $s20 = "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v \"DisableIOAVProtection\" /t REG_DWOR" ascii
   condition:
      ( uint16(0) == 0x6540 and filesize < 10KB and ( 8 of them )
      ) or ( all of them )
}


rule spoolsv_kaslose_7 {
   meta:
      description = "for files:  spoolsv.exe, kaslose.dll"
      author = "TheDFIRReport"
      date = "2021-09-14"
      hash1 = "0d575c22dfd30ca58f86e4cf3346180f2a841d2105a3dacfe298f9c7a22049a0"
      hash2 = "320296ea54f7e957f4fc8d78ec0c1658d1c04a22110f9ddffa6e5cb633a1679c"
   strings:
      $s1 = "Protect End" fullword ascii
      $s2 = "ctsTpiHgtme0JSV3" fullword ascii
      $s3 = "Protect Begin" fullword ascii
      $s4 = "pZs67CJpQCgMm8L4" fullword ascii
      $s5 = "6V7e7z7" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}


rule xinglocker_update64 {
   meta:
      description = "xinglocker - file update64.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-10-07"
      hash1 = "47ff886d229a013d6e73d660a395f7b8e285342195680083eb96d64c052dd5f0"
   strings:
      $s1 = ">j=nAy;j;l;l;m;n;k;p;q;rFpFo;u;vBo;x;y<j<k<l<m<n@o<p<q<r<s<t<u<v<w<x<y=j=k=l=m=n=o=p=q=r=s=t=u=v=w=x=y>j>k>l>m>n>o>p>q>rCk>t>u>v" ascii
      $s2 = "?lAu>wGmCkCl;p?nFkCyGy;mCl>oDx9sGxCxCyHr<t?oHu<y@r=sClCkHvDtDuHn<p@m=jFoHkAqEmEnAw=wEvAo=l9v@kEyEwExEy>s>lBtFmEnFoBl>tFnBvElFuFv" ascii
      $s3 = "HnGtDyEpExFjAmEoAoFkEyEkEoEyAqAvErFpExFwFrFvFpFjBoEyFrEwEuBtFyFwEsFyBmGjCoCwDnCtCsCsCpCvCvCxGuDyCrCjDvDsCoDuCoDkHoDyDsDxDpCrDpDw" ascii
      $s4 = "Bw@oBrGr;vDqBoEpCoCp>qGvCrBq?s>oCwCxGm<u@pHm<r@u>wCoAuDrDsAs@u>oFtDyDyEj=l?qEyEpEoEpEq<y=yElEuExEwExEuFjFkCqEnBr>x:kBy>oEv:oDsFv" ascii
      $s5 = "BwBx;pCmCkClCm=vAkCnCqCr;l?vGm;w?sFpCwDjDkGwGwGyGr@o@u@nHsGsHm<y>kGxHq=u:rAt=xFk<sBkEqEr@jEsEuEvEw;p<oFkFkFlGj9pBs>uFlHo;n;o;nBj" ascii
      $s6 = "Bo>wGl9j9qGlGmGnBkEmFn<tCk?k;jCr?jCvGx9yGnEwDkHnHoDt@vHw;s:vHuHvDo@o<n=rAt:qDwGl9o9pGy<kFlHoHn=nApFs=qBuFtHt9oHsGtGs>uBmFt>lBp9s" ascii
      $s7 = ":oFoFlFj?k?l?m;vGx@qBr<t@sAk?k;nGpGuFy@j@k@l<tHw@lHwDn<nHnGp>yHv@v@x@yEs9tFsEmEw9xHoEyEk9l?sEtFmEvFjExEvExEy>j>rFw:w>mFj:jElBmFn" ascii
      $s8 = "FpDxFq?k=kCnGy;sCj:w>t>q>pGpCr?nGk;qFuBnBsAk?kHj<vElBmBrAt@m=nCsAkHkDyEjAs=uAn<nAw=m9qDvCk<o9wAn=x9sAy>m;yFjCk>oBw>uCtErBk>k9rBn" ascii
      $s9 = "FwFxBqEu;p>u:v:u:t:sCyFm;rBw<r?yBpExGyAo;w=tHlHnHoHpDy@mCoFxEuDn@x<tFy>yElExEyEr=wAy>u;v9k>w=mAyGk;x=pBuGs>tBrEw>wBmFx?v;sGtGn>w" ascii
      $s10 = ":w:x>qCoFx;wCqGr;o;p;q?jClHo?mFu?x@xFnEyExEw=q=l@k9y=n<v=y=t@m9o=x?x=u;t9w@u<j9n<k;l;k9v@j<s@m<r:j9tEq;n@o;l:uFs:k@l;q:v>pGw:j?n" ascii
      $s11 = "HoHuHkAjFkFjEpFqFpApAoGvEpFwEoEjElEyEuBjGoFwEkBnHqEnFrEyEtFyEsBvHyEuFkCnCwCqGkGrGoCyCsDuDwCuCqCjGwCyCkDnHkCjCpDtHoDyCmHpFnFjHuHv" ascii
      $s12 = "EsHv:y;j;k;l;m;nEyEn;q;r;s;t;u;vFmEv;y<j<k<l<m<n?qFn<q<r<s<t<u<v=yFy<y=j=k=l=m=nEwCq=q=r=s=t=u=vFqCy=y>j>k>l>m>n>o>p>q>r>s>t>u>v" ascii
      $s13 = "ByBwByCkCqCoCqCkCyCwCyCkCqCoCqCkCxCxCxDlDpDpDpDlDxDxDxDlDpDpDpDlDyDxDyEjEkElEmEnEoEpEqErEsEtEuEvEyExEyFjFkFlFmFnFoFpFqFrFsFtFuFv" ascii
      $s14 = "GoHuByCjCkClCmCnErFyFnFsEoExApElFsAjEtErFnDlDmDnFrEyEnEsFoFxBpFmEwEtBkCoDsCqEmEnCkCnClCpCxHyHuGlCrDpCtFjFkFlFmFnCpCqDoDuDpCrDxCy" ascii
      $s15 = "CqBxBpCjAnClFjCnCrCpCwCrCsCtCuCvGxCxGlDjHoDlHyDnHvDpHsDrHvDtAkDvDnDxBtEjDlElExEnEyEpEqErEsEtEuEvBkExApFjAkFlBjFnHkFpFqFrFsFtFuFv" ascii
      $s16 = ">p:yGp?l?k?l?m;k>pCp>nDtBp@yBw;u?w?xGtDj9o=r<uHy@x<tHtHn>wHt@t@v@w<pHvGnCoClAmEv9rFlCmDrEr<lDlAwAwAx@jAoBsFuBmBn:j>pGmAv:r;pDy:v" ascii
      $s17 = ";oGs;k<yDuAw@xAjCmGx>j=uCpHk>nGnAp@nGq?k>tHtDj?xHw@q>vDk<v?kEyDq<p@w=vArExGr9m<qEtBr<yAj=lEy?o@jEwExAq>o:kCpEuFuAl;j;nBjFpHj;u;y" ascii
      $s18 = ";k<t>y?j;wGy;j?oFy?x?q?r?s;lGjCnBl@u:w:n@k@l<uHyCw<xHlDr@pHxFm@v@w@x<q9uEwCpDuEr9rEtCmDvEo9k=uEn9jFtCuCj?xAq:oHjBoBp:v?r:v>tGyAk" ascii
      $s19 = "HwByAjCkDyCmDyDuDr;o;u;nCk?mDqErGoCp?pAvFoGlCpDv@r>tFmHr9o9o9nDn@v:lHy9o9k9l=uAs>jGpDx9v9r9t9uHm:rDo;k:j:kBsEuGu9j;w<r:r:s>lBp>k" ascii
      $s20 = "AwBp>v;nCkDw;j;rCw?yDuEvGkCl?lAjEsHxCq@sAoFpGuCmDnCjDpCyDk@s:qDvDo@wEl<r<o9l9m9n=wAwHx@w9n=lAp9k;k<t9y:jGx9q;o>l:o:p>yBo>o<x;uGm" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "309f189ae3d618bfd1e08a8538aea73a" and ( pe.exports("MkozycymwrxdxsUdddknsoskqjj") and pe.exports("NnzvpyfnjzgjflhXgbihjsjauma") and pe.exports("StartW") and pe.exports("WldxpodTdikvburej") and pe.exports("WqtzhacNqtdeAkecz") and pe.exports("startW") ) or 8 of them )
}
/*
   YARA Rule Set
   Author: TheDFIRReport
   Date: 2021-11-29
   Identifier: Case 5794 CONTInuing the Bazar Ransomware Story
   Reference: https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/
*/

/* Rule Set ----------------------------------------------------------------- */

rule mal_host2_143 {
   meta:
      description = "mal - file 143.dll"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "6f844a6e903aa8e305e88ac0f60328c184f71a4bfbe93124981d6a4308b14610"
   strings:
      $x1 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii
      $x2 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x3 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii
      $x4 = "Go pointer stored into non-Go memoryUnable to determine system directoryaccessing a corrupted shared libraryruntime: VirtualQuer" ascii
      $x5 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWSetEndOfFileTransmitFileabi mismatchadvapi32" ascii
      $x6 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii
      $x7 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock" ascii
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x9 = ".lib section in a.out corruptedbad write barrier buffer boundscall from within the Go runtimecannot assign requested addresscasg" ascii
      $x10 = "Ptrmask.lockentersyscallblockexec format errorg already scannedglobalAlloc.mutexlocked m0 woke upmark - bad statusmarkBits overf" ascii
      $x11 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii
      $x12 = "ollectionidentifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation c" ascii
      $s13 = "y failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime: invalid typeBitsBulkBarrierrunt" ascii
      $s14 = "ddetailsecur32.dllshell32.dlltracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  found at *( gcscandone  m->gs" ascii
      $s15 = ".dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend tracegc" fullword ascii
      $s16 = "ked to threadCommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLookupAccountNameWRFS specific errorSetFile" ascii
      $s17 = "mstartbad sequence numberdevice not a streamdirectory not emptydisk quota exceededdodeltimer: wrong Pfile already closedfile alr" ascii
      $s18 = "structure needs cleaning bytes failed with errno= to unused region of spanGODEBUG: can not enable \"GetQueuedCompletionStatus_cg" ascii
      $s19 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii
      $s20 = "tProcessIdGetSystemDirectoryWGetTokenInformationWaitForSingleObjectadjusttimers: bad pbad file descriptorbad notifyList sizebad " ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 12 of them
}

rule mal_host1_D8B3 {
   meta:
      description = "mal - file D8B3.dll"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "4a49cf7539f9fd5cc066dc493bf16598a38a75f7b656224db1ddd33005ad76f6"
   strings:
      $x1 = "object is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: addr = runtime: base = runtime: gp: gp=" ascii
      $x2 = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
      $x3 = " to unallocated spanCertOpenSystemStoreWCreateProcessAsUserWCryptAcquireContextWGetAcceptExSockaddrsGetCurrentDirectoryWGetFileA" ascii
      $x4 = "Go pointer stored into non-Go memoryUnable to determine system directoryaccessing a corrupted shared libraryruntime: VirtualQuer" ascii
      $x5 = "GetAddrInfoWGetLastErrorGetLengthSidGetStdHandleGetTempPathWLoadLibraryWReadConsoleWSetEndOfFileTransmitFileabi mismatchadvapi32" ascii
      $x6 = "lock: lock countslice bounds out of rangesocket type not supportedstartm: p has runnable gsstoplockedm: not runnableunexpected f" ascii
      $x7 = "unknown pcws2_32.dll  of size   (targetpc= KiB work,  freeindex= gcwaiting= heap_live= idleprocs= in status  mallocing= ms clock" ascii
      $x8 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcBgMarkWorker: mode not setgcstopm: negativ" ascii
      $x9 = ".lib section in a.out corruptedbad write barrier buffer boundscall from within the Go runtimecannot assign requested addresscasg" ascii
      $x10 = "Ptrmask.lockentersyscallblockexec format errorg already scannedglobalAlloc.mutexlocked m0 woke upmark - bad statusmarkBits overf" ascii
      $x11 = "entersyscallgcBitsArenasgcpacertracehost is downillegal seekinvalid slotiphlpapi.dllkernel32.dlllfstack.pushmadvdontneedmheapSpe" ascii
      $x12 = "ollectionidentifier removedindex out of rangeinput/output errormultihop attemptedno child processesno locks availableoperation c" ascii
      $s13 = "y failed; errno=runtime: bad notifyList size - sync=runtime: invalid pc-encoded table f=runtime: invalid typeBitsBulkBarrierrunt" ascii
      $s14 = "ddetailsecur32.dllshell32.dlltracealloc(unreachableuserenv.dll KiB total,  [recovered] allocCount  found at *( gcscandone  m->gs" ascii
      $s15 = ".dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivedumping heapend tracegc" fullword ascii
      $s16 = "ked to threadCommandLineToArgvWCreateFileMappingWGetExitCodeProcessGetFileAttributesWLookupAccountNameWRFS specific errorSetFile" ascii
      $s17 = "mstartbad sequence numberdevice not a streamdirectory not emptydisk quota exceededdodeltimer: wrong Pfile already closedfile alr" ascii
      $s18 = "structure needs cleaning bytes failed with errno= to unused region of spanGODEBUG: can not enable \"GetQueuedCompletionStatus_cg" ascii
      $s19 = "garbage collection scangcDrain phase incorrectindex out of range [%x]interrupted system callinvalid m->lockedInt = left over mar" ascii
      $s20 = "tProcessIdGetSystemDirectoryWGetTokenInformationWaitForSingleObjectadjusttimers: bad pbad file descriptorbad notifyList sizebad " ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and all of them
}


rule mal_host2_AnyDesk {
   meta:
      description = "mal - file AnyDesk.exe"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "8f09c538fc587b882eecd9cfb869c363581c2c646d8c32a2f7c1ff3763dcb4e7"
   strings:
      $x1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
      $x2 = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb" fullword ascii
      $s3 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" pu" ascii
      $s4 = "<assemblyIdentity version=\"6.3.2.0\" processorArchitecture=\"x86\" name=\"AnyDesk.AnyDesk.AnyDesk\" type=\"win32\" />" fullword ascii
      $s5 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0O" fullword ascii
      $s6 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii
      $s7 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii
      $s8 = "http://ocsp.digicert.com0N" fullword ascii
      $s9 = "http://www.digicert.com/CPS0" fullword ascii
      $s10 = "Bhttp://cacerts.digicert.com/DigiCertSHA2AssuredIDCodeSigningCA.crt0" fullword ascii
      $s11 = "<description>AnyDesk screen sharing and remote control software.</description>" fullword ascii
      $s12 = "/http://crl3.digicert.com/sha2-assured-cs-g1.crl05" fullword ascii
      $s13 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
      $s14 = "%jgmRhZl%" fullword ascii
      $s15 = "5ZW:\"Wfh" fullword ascii
      $s16 = "5HRe:\\" fullword ascii
      $s17 = "ysN.JTf" fullword ascii
      $s18 = "Z72.irZ" fullword ascii
      $s19 = "Ve:\\-Sj7" fullword ascii
      $s20 = "ekX.cFm" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      1 of ($x*) and 4 of them
}

rule ProcessHacker {
   meta:
      description = "mal - file ProcessHacker.exe"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "d4a0fe56316a2c45b9ba9ac1005363309a3edc7acf9e4df64d326a0ff273e80f"
   strings:
      $x1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe" fullword wide
      $x2 = "D:\\Projects\\processhacker2\\bin\\Release32\\ProcessHacker.pdb" fullword ascii
      $x3 = "ProcessHacker.exe" fullword wide
      $x4 = "kprocesshacker.sys" fullword wide
      $x5 = "ntdll.dll!NtDelayExecution" fullword wide
      $x6 = "ntdll.dll!ZwDelayExecution" fullword wide
      $s7 = "PhInjectDllProcess" fullword ascii
      $s8 = "_PhUiInjectDllProcess@8" fullword ascii
      $s9 = "logonui.exe" fullword wide
      $s10 = "Executable files (*.exe;*.dll;*.ocx;*.sys;*.scr;*.cpl)" fullword wide
      $s11 = "\\x86\\ProcessHacker.exe" fullword wide
      $s12 = "user32.dll!NtUserGetMessage" fullword wide
      $s13 = "ntdll.dll!NtWaitForKeyedEvent" fullword wide
      $s14 = "ntdll.dll!ZwWaitForKeyedEvent" fullword wide
      $s15 = "ntdll.dll!NtReleaseKeyedEvent" fullword wide
      $s16 = "ntdll.dll!ZwReleaseKeyedEvent" fullword wide
      $s17 = "\\kprocesshacker.sys" fullword wide
      $s18 = "\\SystemRoot\\system32\\drivers\\ntfs.sys" fullword wide
      $s19 = "_PhExecuteRunAsCommand2@36" fullword ascii
      $s20 = "_PhShellExecuteUserString@20" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule unlocker {
   meta:
      description = "mal - file unlocker.exe"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "09d7fcbf95e66b242ff5d7bc76e4d2c912462c8c344cb2b90070a38d27aaef53"
   strings:
      $s1 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide
      $s2 = "(Symantec SHA256 TimeStamping Signer - G20" fullword ascii
      $s3 = "            <requestedExecutionLevel level=\"asInvoker\"            uiAccess=\"false\"/>" fullword ascii
      $s4 = "(Symantec SHA256 TimeStamping Signer - G2" fullword ascii
      $s5 = "Causes Setup to create a log file in the user's TEMP directory." fullword wide
      $s6 = "Prevents the user from cancelling during the installation process." fullword wide
      $s7 = "Same as /LOG, except it allows you to specify a fixed path/filename to use for the log file." fullword wide
      $s8 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii
      $s9 = "The Setup program accepts optional command line parameters." fullword wide
      $s10 = "Instructs Setup to load the settings from the specified file after having checked the command line." fullword wide
      $s11 = "Overrides the default component settings." fullword wide
      $s12 = "/MERGETASKS=\"comma separated list of task names\"" fullword wide
      $s13 = "/PASSWORD=password" fullword wide
      $s14 = "Specifies the password to use." fullword wide
      $s15 = "yyyyvvvvvvvvvxxw" fullword ascii
      $s16 = "yyyyyyrrrsy" fullword ascii
      $s17 = "            processorArchitecture=\"x86\"" fullword ascii
      $s18 = "    processorArchitecture=\"x86\"" fullword ascii
      $s19 = "Prevents Setup from restarting the system following a successful installation, or after a Preparing to Install failure that requ" wide
      $s20 = "/DIR=\"x:\\dirname\"" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      all of them
}

rule mal_host2_locker {
   meta:
      description = "mal - file locker.bat"
      author = "TheDFIRReport"
      date = "2021-11-29"
      hash1 = "1edfae602f195d53b63707fe117e9c47e1925722533be43909a5d594e1ef63d3"
   strings:
      $x1 = "_locker.exe -m -net -size 10 -nomutex -p" ascii
   condition:
      uint16(0) == 0x7473 and filesize < 8KB and
      $x1
}

import "pe"

rule o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker {
   meta:
      description = "conti - file o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-29"
      hash1 = "9cd3c0cff6f3ecb31c7d6bc531395ccfd374bcd257c3c463ac528703ae2b0219"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "operator co_await" fullword ascii
      $s3 = ">*>6>A>_>" fullword ascii /* hex encoded string 'j' */
      $s4 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s5 = "Bapi-ms-win-core-fibers-l1-1-1" fullword wide
      $s6 = "SVWjEhQ" fullword ascii
      $s7 = ";F;[;l;" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "74787@7H7P7T7\\7p7" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "6#606B6" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "<!=X=u=" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "expand 32-byte k" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "6!7?7J7" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "delete" fullword ascii /* Goodware String - occured 2789 times */
      $s14 = "4!4(4/464=4D4K4R4Z4b4j4v4" fullword ascii /* Goodware String - occured 3 times */
      $s15 = ".CRT$XIAC" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "0#0)01060\\0a0" fullword ascii
      $s17 = ";\";/;=;K;V;l;" fullword ascii
      $s18 = "6,606P6X6\\6x6" fullword ascii
      $s19 = "6(6,6@6D6H6L6P6T6X6\\6`6d6p6t6x6|6" fullword ascii
      $s20 = "8 :M:}:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( pe.imphash() == "50472e0ba953856d228c7483b149ea72" or all of them )
}

rule o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x86 {
   meta:
      description = "conti - file o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x86.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-29"
      hash1 = "01a9549c015cfcbff4a830cea7df6386dc5474fd433f15a6944b834551a2b4c9"
   strings:
      $s1 = "conti_v3.dll" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "6 7/787E7[7" fullword ascii /* hex encoded string 'gx~w' */
      $s4 = "operator co_await" fullword ascii
      $s5 = "2%3.3f3~3" fullword ascii /* hex encoded string '#?3' */
      $s6 = "1\"1&1,:4:<:D:L:T:\\:d:l:t:|:" fullword ascii $s7 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide $s8 = "SVWjEhQ" fullword ascii $s9 = "__swift_2" fullword ascii $s10 = "__swift_1" fullword ascii $s11 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */ $s12 = "7K7P7T7X7\\7" fullword ascii /* Goodware String - occured 1 times */ $s13 = "7h7o7v7}7" fullword ascii /* Goodware String - occured 1 times */ $s14 = "O0a0s0" fullword ascii /* Goodware String - occured 1 times */ $s15 = ";?;I;S;" fullword ascii /* Goodware String - occured 1 times */ $s16 = "8>8C8Q8V8" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "QQSVj8j@" fullword ascii
      $s18 = "5-5X5s5" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "expand 32-byte k" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "delete" fullword ascii /* Goodware String - occured 2789 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( pe.imphash() == "749dc5143e9fc01aa1d221fb9a48d5ea" or all of them )
}

rule o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x64 {
   meta:
      description = "conti - file o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker_x64.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-29"
      hash1 = "31656dcea4da01879e80dff59a1af60ca09c951fe5fc7e291be611c4eadd932a"
   strings:
      $s1 = "conti_v3.dll" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "operator co_await" fullword ascii
      $s4 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s5 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
      $s6 = "__swift_2" fullword ascii
      $s7 = "__swift_1" fullword ascii
      $s8 = "expand 32-byte k" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "u3HcH<H" fullword ascii /* Goodware String - occured 2 times */
      $s10 = "D$XD9x" fullword ascii /* Goodware String - occured 2 times */
      $s11 = "delete" fullword ascii /* Goodware String - occured 2789 times */
      $s12 = "ue!T$(H!T$ " fullword ascii
      $s13 = "L$&8\\$&t,8Y" fullword ascii
      $s14 = "F 2-by" fullword ascii
      $s15 = "u\"8Z(t" fullword ascii
      $s16 = "L$ |+L;" fullword ascii
      $s17 = "vB8_(t" fullword ascii
      $s18 = "ext-ms-" fullword wide
      $s19 = "OOxq*H" fullword ascii
      $s20 = "H97u+A" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( pe.imphash() == "137fa89046164fe07e0dd776ed7a0191" or all of them )
}
/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2021-11-14
   Identifier: Case 6898 Exchange Exploit Leads to Domain Wide Ransomware
   Reference: https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_6898_login_webshell {
   meta:
      description = "6898 - file login.aspx"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-14"
      hash1 = "98ccde0e1a5e6c7071623b8b294df53d8e750ff2fa22070b19a88faeaa3d32b0"
   strings:
      $s1 = "<asp:TextBox id='xpath' runat='server' Width='300px'>c:\\windows\\system32\\cmd.exe</asp:TextBox>        " fullword ascii
      $s2 = "myProcessStartInfo.UseShellExecute = false            " fullword ascii
      $s3 = "\"Microsoft.Exchange.ServiceHost.exe0r" fullword ascii
      $s4 = "myProcessStartInfo.Arguments=xcmd.text            " fullword ascii
      $s5 = "myProcess.StartInfo = myProcessStartInfo            " fullword ascii
      $s6 = "myProcess.Start()            " fullword ascii
      $s7 = "myProcessStartInfo.RedirectStandardOutput = true            " fullword ascii
      $s8 = "myProcess.Close()                       " fullword ascii
      $s9 = "Dim myStreamReader As StreamReader = myProcess.StandardOutput            " fullword ascii
      $s10 = "<%@ import Namespace='system.IO' %>" fullword ascii
      $s11 = "<%@ import Namespace='System.Diagnostics' %>" fullword ascii
      $s12 = "Dim myProcess As New Process()            " fullword ascii
      $s13 = "Dim myProcessStartInfo As New ProcessStartInfo(xpath.text)            " fullword ascii
      $s14 = "example.org0" fullword ascii
      $s16 = "<script runat='server'>      " fullword ascii
      $s17 = "<asp:TextBox id='xcmd' runat='server' Width='300px' Text='/c whoami'>/c whoami</asp:TextBox>        " fullword ascii
      $s18 = "<p><asp:Button id='Button' onclick='runcmd' runat='server' Width='100px' Text='Run'></asp:Button>        " fullword ascii
      $s19 = "Sub RunCmd()            " fullword ascii
   condition:
      uint16(0) == 0x8230 and filesize < 6KB and
      8 of them
}

rule aspx_gtonvbgidhh_webshell {
   meta:
      description = "6898 - file aspx_gtonvbgidhh.aspx"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-14"
      hash1 = "dc4186dd9b3a4af8565f87a9a799644fce8af25e3ee8777d90ae660d48497a04"
   strings:
      $s1 = "info.UseShellExecute = false;" fullword ascii
      $s2 = "info.Arguments = \"/c \" + command;" fullword ascii
      $s3 = "var dstFile = Path.Combine(dstDir, Path.GetFileName(httpPostedFile.FileName));" fullword ascii
      $s4 = "info.FileName = \"powershell.exe\";" fullword ascii
      $s5 = "using (StreamReader streamReader = process.StandardError)" fullword ascii
      $s6 = "return httpPostedFile.FileName + \" Uploaded to: \" + dstFile;" fullword ascii
      $s7 = "httpPostedFile.InputStream.Read(buffer, 0, fileLength);" fullword ascii
      $s8 = "int fileLength = httpPostedFile.ContentLength;" fullword ascii
      $s9 = "result = result +  Environment.NewLine + \"ERROR:\" + Environment.NewLine + error;" fullword ascii
      $s10 = "ALAAAAAAAAAAA" fullword ascii /* base64 encoded string ',' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
      $s12 = "var result = delimiter +  this.RunIt(Request.Params[\"exec_code\"]) + delimiter;" fullword ascii
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAA6AAAAAAAAAAAAAAA" ascii /* base64 encoded string ':' */
      $s14 = "using (StreamReader streamReader = process.StandardOutput)" fullword ascii
      $s15 = "private string RunIt(string command)" fullword ascii
      $s16 = "Process process = Process.Start(info);" fullword ascii
      $s17 = "ProcessStartInfo info = new ProcessStartInfo();" fullword ascii
      $s18 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6" ascii /* base64 encoded string ':' */
      $s19 = "6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
      $s20 = "if (Request.Params[\"exec_code\"] == \"put\")" fullword ascii
   condition:
      uint16(0) == 0x4221 and filesize < 800KB and
      8 of them
}

rule aspx_qdajscizfzx_webshell {
   meta:
      description = "6898 - file aspx_qdajscizfzx.aspx"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-14"
      hash1 = "60d22223625c86d7f3deb20f41aec40bc8e1df3ab02cf379d95554df05edf55c"
   strings:
      $s1 = "info.FileName = \"cmd.exe\";" fullword ascii
      $s2 = "info.UseShellExecute = false;" fullword ascii
      $s3 = "info.Arguments = \"/c \" + command;" fullword ascii
      $s4 = "var dstFile = Path.Combine(dstDir, Path.GetFileName(httpPostedFile.FileName));" fullword ascii
      $s5 = "using (StreamReader streamReader = process.StandardError)" fullword ascii
      $s6 = "return httpPostedFile.FileName + \" Uploaded to: \" + dstFile;" fullword ascii
      $s7 = "httpPostedFile.InputStream.Read(buffer, 0, fileLength);" fullword ascii
      $s8 = "int fileLength = httpPostedFile.ContentLength;" fullword ascii
      $s9 = "result = result +  Environment.NewLine + \"ERROR:\" + Environment.NewLine + error;" fullword ascii
      $s10 = "ALAAAAAAAAAAA" fullword ascii /* base64 encoded string ',' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
      $s12 = "var result = delimiter +  this.RunIt(Request.Params[\"exec_code\"]) + delimiter;" fullword ascii
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAA6AAAAAAAAAAAAAAA" ascii /* base64 encoded string ':' */
      $s14 = "using (StreamReader streamReader = process.StandardOutput)" fullword ascii
      $s15 = "private string RunIt(string command)" fullword ascii
      $s16 = "Process process = Process.Start(info);" fullword ascii
      $s17 = "ProcessStartInfo info = new ProcessStartInfo();" fullword ascii
      $s18 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6" ascii /* base64 encoded string ':' */
      $s19 = "6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '' */
      $s20 = "if (Request.Params[\"exec_code\"] == \"put\")" fullword ascii
   condition:
      uint16(0) == 0x4221 and filesize < 800KB and
      8 of them
}

rule sig_6898_dcrypt {
   meta:
      description = "6898 - file dcrypt.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-11-14"
      hash1 = "02ac3a4f1cfb2723c20f3c7678b62c340c7974b95f8d9320941641d5c6fd2fee"
   strings:
      $s1 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide
      $s2 = "Causes Setup to create a log file in the user's TEMP directory." fullword wide
      $s3 = "Prevents the user from cancelling during the installation process." fullword wide
      $s4 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
      $s5 = "Same as /LOG, except it allows you to specify a fixed path/filename to use for the log file." fullword wide
      $s6 = "/PASSWORD=password" fullword wide
      $s7 = "The Setup program accepts optional command line parameters." fullword wide
      $s8 = "Overrides the default component settings." fullword wide
      $s9 = "Specifies the password to use." fullword wide
      $s10 = "/MERGETASKS=\"comma separated list of task names\"" fullword wide
      $s11 = "Instructs Setup to load the settings from the specified file after having checked the command line." fullword wide
      $s12 = "/DIR=\"x:\\dirname\"" fullword wide
      $s13 = "http://diskcryptor.org/                                     " fullword wide
      $s14 = "Prevents Setup from restarting the system following a successful installation, or after a Preparing to Install failure that requ" wide
      $s15 = "HBPLg.sse" fullword ascii
      $s16 = "/LOG=\"filename\"" fullword wide
      $s17 = "Overrides the default folder name." fullword wide
      $s18 = "Overrides the default setup type." fullword wide
      $s19 = "Overrides the default directory name." fullword wide
      $s20 = "* AVz'" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "48aa5c8931746a9655524f67b25a47ef" and all of them )
}
/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2022-02-07
   Identifier: Case 7685 Qbot Likes to Move It, Move It
   Reference: https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule tuawktso_7685 {
   meta:
      description = "Files - file tuawktso.vbe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "1411250eb56c55e274fbcf0741bbd3b5c917167d153779c7d8041ab2627ef95f"
   strings:
      $s1 = "* mP_5z" fullword ascii
      $s2 = "44:HD:\\C" fullword ascii
      $s3 = "zoT.tid" fullword ascii
      $s4 = "dwmcoM<" fullword ascii
      $s5 = "1iHBuSER:" fullword ascii
      $s6 = "78NLog.j" fullword ascii
      $s7 = "-FtP4p" fullword ascii
      $s8 = "x<d%[ * " fullword ascii
      $s9 = "O2f+  " fullword ascii
      $s10 = "- wir2" fullword ascii
      $s11 = "+ \"z?}xn$" fullword ascii
      $s12 = "+ $Vigb" fullword ascii
      $s13 = "# W}7k" fullword ascii
      $s14 = "# N)M)9" fullword ascii
      $s15 = "?uE- dO" fullword ascii
      $s16 = "W_* 32" fullword ascii
      $s17 = ">v9+ H" fullword ascii
      $s18 = "tUg$* h" fullword ascii
      $s19 = "`\"*- M" fullword ascii
      $s20 = "b^D$ -L" fullword ascii
   condition:
      uint16(0) == 0xe0ee and filesize < 12000KB and
      8 of them
}

rule wmyvpa_7685 {
   meta:
      description = "Files - file wmyvpa.sae"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "3d913a4ba5c4f7810ec6b418d7a07b6207b60e740dde8aed3e2df9ddf1caab27"
   strings:
      $s1 = "spfX.hRN<" fullword ascii
      $s2 = "wJriR>EOODA[.tIM" fullword ascii
      $s3 = "5v:\\VAL" fullword ascii
      $s4 = "K6U:\"&" fullword ascii
      $s5 = "%v,.IlZ\\" fullword ascii
      $s6 = "\\/kX>%n -" fullword ascii
      $s7 = "!Dllqj" fullword ascii
      $s8 = "&ZvM* " fullword ascii
      $s9 = "AU8]+ " fullword ascii
      $s10 = "- vt>h" fullword ascii
      $s11 = "+ u4hRI" fullword ascii
      $s12 = "ToX- P" fullword ascii
      $s13 = "S!G+ u" fullword ascii
      $s14 = "y 9-* " fullword ascii
      $s15 = "nl}* J" fullword ascii
      $s16 = "t /Y Fo" fullword ascii
      $s17 = "O^w- F" fullword ascii
      $s18 = "N -Vw'" fullword ascii
      $s19 = "hVHjzI4" fullword ascii
      $s20 = "ujrejn8" fullword ascii
   condition:
      uint16(0) == 0xd3c2 and filesize < 12000KB and
      8 of them
}

rule ocrafh_html_7685 {
   meta:
      description = "Files - file ocrafh.html.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "956ecb4afa437eafe56f958b34b6a78303ad626baee004715dc6634b7546bf85"
   strings:
      $s1 = "Over.dll" fullword wide
      $s2 = "c:\\339\\Soon_Back\\Hope\\Wing\\Subject-sentence\\Over.pdb" fullword ascii
      $s3 = "7766333344" ascii /* hex encoded string 'wf33D' */
      $s4 = "6655557744" ascii /* hex encoded string 'fUUwD' */
      $s5 = "7733225566" ascii /* hex encoded string 'w3"Uf' */
      $s6 = "5577445500" ascii /* hex encoded string 'UwDU' */
      $s7 = "113333" ascii /* reversed goodware string '333311' */
      $s8 = "'56666" fullword ascii /* reversed goodware string '66665'' */
      $s9 = "224444" ascii /* reversed goodware string '444422' */
      $s10 = "0044--" fullword ascii /* reversed goodware string '--4400' */
      $s11 = "444455" ascii /* reversed goodware string '554444' */
      $s12 = "5555//" fullword ascii /* reversed goodware string '//5555' */
      $s13 = "44...." fullword ascii /* reversed goodware string '....44' */
      $s14 = ",,,2255//5566" fullword ascii /* hex encoded string '"UUf' */
      $s15 = "44//446644//" fullword ascii /* hex encoded string 'DDfD' */
      $s16 = "7755//44----." fullword ascii /* hex encoded string 'wUD' */
      $s17 = "?^.4444--,,55" fullword ascii /* hex encoded string 'DDU' */
      $s18 = "66,,5566////55" fullword ascii /* hex encoded string 'fUfU' */
      $s19 = "operator co_await" fullword ascii
      $s20 = "?\"55//////77" fullword ascii /* hex encoded string 'Uw' */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "fadf54554241c990b4607d042e11e465" and ( pe.exports("Dropleave") and pe.exports("GlassExercise") and pe.exports("Mehope") and pe.exports("Top") ) or 8 of them )
}

rule ljncxcwmsg_7685 {
   meta:
      description = "Files - file ljncxcwmsg.gjf"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "c789bb45cacf0de1720e707f9edd73b4ed0edc958b3ce2d8f0ad5d4a7596923a"
   strings:
      $s1 = "x=M:\"*" fullword ascii
      $s2 = "=DdlLxu" fullword ascii
      $s3 = "#+- 7 " fullword ascii
      $s4 = "1CTxH* " fullword ascii
      $s5 = "OF0+ K" fullword ascii
      $s6 = "\\oNvd4Ww" fullword ascii
      $s7 = "jvKSZ21" fullword ascii
      $s8 = "o%U%uhuc]" fullword ascii
      $s9 = "~rCcqlf1 0" fullword ascii
      $s10 = "kjoYf^=8" fullword ascii
      $s11 = "jpOMR4}" fullword ascii
      $s12 = "ZIIUn'u" fullword ascii
      $s13 = "7uCyy7=H" fullword ascii
      $s14 = "#c.sel}W" fullword ascii
      $s15 = ")t)uSKv%&}" fullword ascii
      $s16 = "VGiAP/o(" fullword ascii
      $s17 = "SwcF~i`" fullword ascii
      $s18 = "*ITDe5\\n" fullword ascii
      $s19 = "MjKB!X" fullword ascii
      $s20 = "tjfVUus" fullword ascii
   condition:
      uint16(0) == 0xa5a4 and filesize < 2000KB and
      8 of them
}

rule hyietnrfrx_7685 {
   meta:
      description = "Files - file hyietnrfrx.uit"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "70a49561f39bb362a2ef79db15e326812912c17d6e6eb38ef40343a95409a19a"
   strings:
      $s1 = "Z)* -^'" fullword ascii
      $s2 = "%EGMf%mzT" fullword ascii
      $s3 = "CYR:\"n" fullword ascii
      $s4 = "CbIN$P;" fullword ascii
      $s5 = "We:\\>K" fullword ascii
      $s6 = "h^nd* " fullword ascii
      $s7 = "+ GR;q" fullword ascii
      $s8 = "u%P%r2A" fullword ascii
      $s9 = "ti+ gj?" fullword ascii
      $s10 = "glMNdH8" fullword ascii
      $s11 = "SuiMFrn7" fullword ascii
      $s12 = "K* B5T" fullword ascii
      $s13 = "eLpsNt " fullword ascii
      $s14 = "aQeG% SMF " fullword ascii
      $s15 = "JdYQ67 " fullword ascii
      $s16 = "f>xYrBDvNF+Q" fullword ascii
      $s17 = "OESW[>O" fullword ascii
      $s18 = "9rlPY5__" fullword ascii
      $s19 = "DMvH{}L" fullword ascii
      $s20 = ".dgQ>H" fullword ascii
   condition:
      uint16(0) == 0x4eee and filesize < 2000KB and
      8 of them
}

rule zsokarzi_7685 {
   meta:
      description = "Files - file zsokarzi.xpq"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-01"
      hash1 = "cbfc135bff84d63c4a0ccb5102cfa17d8c9bf297079f3b2f1371dafcbefea77c"
   strings:
      $s1 = "}poSpY" fullword ascii
      $s2 = "[cmD>S" fullword ascii
      $s3 = "# {y|4" fullword ascii
      $s4 = "IX%k%5u" fullword ascii
      $s5 = "YKeial7" fullword ascii
      $s6 = "#%y% !" fullword ascii
      $s7 = "wOUV591" fullword ascii
      $s8 = "| VJHt}&Y" fullword ascii
      $s9 = "BEgs% 5" fullword ascii
      $s10 = "UKCy\\n" fullword ascii
      $s11 = "w;gOxQ?" fullword ascii
      $s12 = "'OHSf\"/x" fullword ascii
      $s13 = "=#qVNkOnj" fullword ascii
      $s14 = "{_OqzbVbN" fullword ascii
      $s15 = "QEQro\\4" fullword ascii
      $s16 = "ohFq\\P" fullword ascii
      $s17 = "34eYZVnp2" fullword ascii
      $s18 = "rxuqLDG" fullword ascii
      $s19 = "kUZI6J#" fullword ascii
      $s20 = "IEJl1}+" fullword ascii
   condition:
      uint16(0) == 0xc1d7 and filesize < 2000KB and
      8 of them
}

rule znmxbx_7685 {
   meta:
      description = "Files - file znmxbx.evj"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/"
      date = "2022-02-01"
      hash1 = "e510566244a899d6a427c1648e680a2310c170a5f25aff53b15d8de52ca11767"
   strings:
      $s1 = "# /rL,;" fullword ascii
      $s2 = "* m?#;rE" fullword ascii
      $s3 = ">\\'{6|B{" fullword ascii /* hex encoded string 'k' */
      $s4 = "36\\$'48`" fullword ascii /* hex encoded string '6H' */
      $s5 = "&#$2\\&6&[" fullword ascii /* hex encoded string '&' */
      $s6 = "zduwzpa" fullword ascii
      $s7 = "CFwH}&.MWi " fullword ascii
      $s8 = "e72.bCZ<" fullword ascii
      $s9 = "*c:\"HK!\\" fullword ascii
      $s10 = "mBf:\"t~" fullword ascii
      $s11 = "7{R:\"O`" fullword ascii
      $s12 = "7SS.koK#" fullword ascii
      $s13 = "7lS od:\\" fullword ascii
      $s14 = "kMRWSyi$%D^b" fullword ascii
      $s15 = "Wkz=c:\\" fullword ascii
      $s16 = "1*l:\"L" fullword ascii
      $s17 = "GF8$d:\\T" fullword ascii
      $s18 = "i$\".N8spy" fullword ascii
      $s19 = "f4LOg@" fullword ascii
      $s20 = "XiRcwU" fullword ascii
   condition:
      uint16(0) == 0x3888 and filesize < 12000KB and
      8 of them
}
/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2021-12-12
   Identifier: Case 8099 Diavol Ransomware
   Reference: https://thedfirreport.com/2021/12/13/diavol-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule uvvfvnnswte {
   meta:
      description = "8099 - file uvvfvnnswte.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-12-12"
      hash1 = "5551fb5702220dfc05e0811b7c91e149c21ec01e8ca210d1602e32dece1e464d"
   strings:
      $s1 = "(s#u%x0m(m#n&y*r$o&k\"j*o$y&x\"k)l#k%y!l)y#u%j0m%v0w)w.n%k0q)l.o&p/s*m-p&u/m*v.q+j%o&s%r+w%y&p%s,t&k%q&t,q&u%r'u,n%w%o%v,s%q%t%w" ascii
      $s2 = "0w(r#v%l0j(l$u\"o*u$n&p\"v*p$x&k!q)k#j%r!x)v#t,y.k%y0v)t.r%l0p)w-m&o/r*n-t&r/l)m%w+m%n&x%n+x%x&s&y,s&j%j&p,n&t(q%s,q%v%l%j,t%p%o" ascii
      $s3 = "%r0v(y#p%k0k'w&m\"p*t$m&v\"y*q$k%w!n)j#q%l!w)w.o)y.l%x0u)j.u%m0s*k-j&n/y*x-s&s0w&u%x+l%m&n%q+y%k%o&v,r&q%t&o,o'o%q%t,p%u%r%m,u%s" ascii
      $s4 = "#t%s0u(j#o%j/x$p&j\"q*w$v&y\"x*r#l%x!o)q#r%k!v(l0x)v.m%s0n)m.t%v/t*l-k&m/j*w-r%p%p&r%y+o%v&q%p+j&l%p&w,y&r%s&n)t%x%n%u,k%n%u%l,n" ascii
      $s5 = "#s+r+y+x/o#k,q$l$t%q0x$u.s*j,s0l(r&r,u0y*p%s!y-y%v'l&v%l%o-q+o%s!k-m)l!p-n!r(q(l.t)p\"o+s%k&v'j*v#w&y/n&q&w&v'm)s\"r#n/v*w/j*l\"" ascii
      $s6 = "%y&u&x!s%k%t%j%m\"p&m&k%o%n\"m%l&v%t%s\"r%q&u%y,l/o)u+p0q)y)p)q)r-y)m+x-o,u,t/u*s,n+l+k0j,t,m+q+t0w,o,x+v+y0t,y)o*k*j-q*x)j*p*o-" ascii
      $s7 = "-r#u&p.w+l#r,o%w%x%y$n%y-j,u$y(y,s,r,y$w%n-n%v-q)l%l%q%p-r!o/n+k\"r,q)q#r!s(o%l#p&s\"r.n*q&q.k*u#y+s\"j(n*o\"o)w*t)s%k#r/l,w#w'u" ascii
      $s8 = ",j/j#t(v+l#s.s%w%x%y0x$o%v%u-x,j0t$j/m+n%l$k!k\"l+t-q!p-x&y+v/l%q%s%r0n'v%w%v&m,u$w+y+r+s*s*r*q*p*o*n*m*l*k*j+y+x+w+v+u+t+s!l!w'" ascii
      $s9 = ",n0m%s$s(j0n(q#m*v0p.x0q't0w)v)x)y/m-s(y%o&m%n,w0t/l#x(r*k+p)k%p0k,v(k$w!t%j*w#x,k(o!y%y#w,j\"l&s(w%r!n*t0l0p%v#y+p+s)q%o%p$m'j0" ascii
      $s10 = "(l/j#l0u$t/n$x0y!p0n$v(k&w,p,t,t,s$w(y-u*u!o,q%m%k%j,r&m0l.s%t%t,p)u-v,o&s$j)s+w%n0l-t&q&o/w%y&t&s&r.n)x,o)t.p*w*x)u%y/m*m\"j'j#" ascii
      $s11 = "/k#u'u)x0l'y(y0t$l&v*y%s+j$t#p,t,s$w(y-u,o%m&p0p.w%j%q+w%q(q)u-y)s$v%m-o)o+n!l-t+x+y.n*x+t,y&s's*s\"j.v*t(o*y+y#t/l)v%y&o,q*u(x$" ascii
      $s12 = "&q+v.s)m/v#y%w,q,x$o/q,q,o,n,n!n0n.y0u$o%t%m)t%w-o%p%p%p%o,u)l%o-v(k%x%x%w)u\"p)o+x+x&q&p,v+u&u&t&s.m&n\"u.p*u&j,j)s0p+o*s*t#v/x" ascii
      $s13 = "+s+r/q*o*j0l,y,j,k-n+w0x$r,k.x,p,u,r0q)o%o-r%w-k(x%j$l%y!w-y)n+l$p\"q%y%x.w0o&y&l&k&j,y0x%q&n&u\"l.l*m,q)x*y+m*v#t/t$v%m&x#w/q+y" ascii
      $s14 = "+s%j/t)s+w+v(y!u,j,j,q,p&w)x*v,t,s(n(m0p$p,s,x+p%m%j)n!x-x%k,p+x%u%r!m#w)y!k&j*l\"m&y%q&l*o\"v.j*u+t&q#j&y*x*j+y#t/l)v&y/w,n#v/p" ascii
      $s15 = "/v*u'y*w(y*y(t&t-x%y%r%s0w$q(y)l(t(n(m0p$x&j'u0u&p%j%q%p+w\"n)l%t%s-w)y$t%t0o&p&l&k&j*t(y\"n/v&t&t&s&r/o%s&s&v+m#m/v#r'p)x#t*t*n" ascii
      $s16 = "'s%k/m&k&l&m0u$s(m0s*n(n0v)y(r-w,y%u,j.k,y&q'r!t-t)t%r\"k)o!o0l&t%s%r%y!x-q*u$o&w#l)r&p&s/u*p$w&o'm(r*y&k.s)x\"q'q#s*y+p/v(n#w*n" ascii
      $s17 = "\"k+m+y+x+w'y(y0t$l&v*y0t$x(w$j0m-s&j(l%k%l%m-p)l$n&p!x#o!n$n!q-q&v\"t%j%t%w!o.r*u\"s*k,q&k\"q+u%y%t\"k.u*u(p*x*j+y#t/r$v%m'x#w/" ascii
      $s18 = "(k%m+w*w(p#s'r-p+n&r0t-o%t%u$l+l&k!x-v%k%l(u%m%u%k%j%q-o)x,u-j)o+k't,j,k,l-q*j,s%l,r-t#o+t+u*v&t&j&r&y&x,o/p\"t*w*x/m+y*s#w/y$q%" ascii
      $s19 = "$t#j/v)l%w#n0j!u'k(j$y0w+v!j%r%s,j%k(n!j's%y.k%t)t%m\"q0s-n)q#y!r!s%j)l&v!s$q\"r'x0y&r*v&w!o0v)x!v\"r\"r&q*w(x!v#m+k!l#j+n%o#k#n" ascii
      $s20 = "#t%n)y/q#p(n$r%j0r)u(y-l+o0v$j's&k)t&q%k%l$s)m%w-n0l%q%p%o0v.r'x!j.t,r+j-j(j%o.s%l*k+r&l+t*p.j*w*r,j%j&w+o&y,n&u$l'n\"t(p#w/y+j)" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "1a4ea0d6f08424c00bbeb4790cdf1ca7" and ( pe.exports("GhlqallxvchxEpmvydvyzqt") and pe.exports("PyflzyhnwVkaNixwdqktzn") ) or 8 of them )
}

rule files_Rubeus {
   meta:
      description = "8099 - file Rubeus.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-12-12"
      hash1 = "0e09068581f6ed53d15d34fff9940dfc7ad224e3ce38ac8d1ca1057aee3e3feb"
   strings:
      $x1 = "        Rubeus.exe dump [/luid:LOGINID] [/user:USER] [/service:krbtgt] [/server:BLAH.DOMAIN.COM] [/nowrap]" fullword wide
      $x2 = "        Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:DES|RC4|AES128|AES256] | /des:HASH | /rc4:HASH | /aes128:HASH" wide
      $x3 = "[!] GetSystem() - OpenProcessToken failed!" fullword wide
      $x4 = "        Rubeus.exe createnetonly /program:\"C:\\Windows\\System32\\cmd.exe\" [/show]" fullword wide
      $x5 = "[!] GetSystem() - ImpersonateLoggedOnUser failed!" fullword wide
      $x6 = "[X] You need to have an elevated context to dump other users' Kerberos tickets :( " fullword wide
      $x7 = "[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'" fullword wide
      $x8 = "    Dump all current ticket data (if elevated, dump for all users), optionally targeting a specific service/LUID:" fullword wide
      $s9 = "Z:\\Agressor\\github.com-GhostPack\\Rubeus-master\\Rubeus\\obj\\Debug\\Rubeus.pdb" fullword ascii
      $s10 = "    Triage all current tickets (if elevated, list for all users), optionally targeting a specific LUID, username, or service:" fullword wide
      $s11 = "[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi" fullword wide
      $s12 = "Action: Dump Kerberos Ticket Data (All Users)" fullword wide
      $s13 = "[*] Initializing Kerberos GSS-API w/ fake delegation for target '{0}'" fullword wide
      $s14 = "[*] Listing statistics about target users, no ticket requests being performed." fullword wide
      $s15 = "[X] OpenProcessToken error: {0}" fullword wide
      $s16 = "[X] CreateProcessWithLogonW error: {0}" fullword wide
      $s17 = "[*] Target service  : {0:x}" fullword wide
      $s18 = "[*] Target Users           : {0}" fullword wide
      $s19 = "        Rubeus.exe s4u /user:USER </rc4:HASH | /aes256:HASH> [/domain:DOMAIN] </impersonateuser:USER | /tgs:BASE64 | /tgs:FILE.K" wide
      $s20 = "    List all current tickets in detail (if elevated, list for all users), optionally targeting a specific LUID:" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule SharedFiles {
   meta:
      description = "8099 - file SharedFiles.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-12-12"
      hash1 = "c17e71c7ae15fdb02a4e22df4f50fb44215211755effd6e3fc56e7f3e586b299"
   strings:
      $s1 = "ButtonSkin.dll" fullword wide
      $s2 = "MyLinks.dll" fullword wide
      $s3 = "DragListCtrl.dll" fullword ascii
      $s4 = "whoami.exe" fullword ascii
      $s5 = "constructor or from DllMain." fullword ascii
      $s6 = "DINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
      $s7 = "kLV -{T" fullword ascii
      $s8 = "CtrlList1" fullword wide
      $s9 = "CtrlList2" fullword wide
      $s10 = "CtrlList3" fullword wide
      $s11 = "wox)YytbACl_<me*y3X(*lNCvY@8jsbePLfVHH!X2p2TdHa6+1hoo^1N7gNtwhki)Lbaso@*ne7" fullword ascii
      $s12 = "QX[gbL" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "BasicScore" fullword ascii
      $s14 = ".?AVCDemoDlg@@" fullword ascii
      $s15 = "jLDfSektRC2FrOiWNzhbH3AsmBEIwg1U" fullword ascii
      $s16 = "9t$xt5" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "DeAj1=n" fullword ascii
      $s18 = "WmaK|IG" fullword ascii
      $s19 = "oTRHz`R" fullword ascii
      $s20 = "VWATAUAVAWLc" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "c270086ea8ef591ab09b6ccf85dc6072" and pe.exports("BasicScore") or 8 of them )
}

rule new_documents_2005_iso {
   meta:
      description = "8099 - file new-documents-2005.iso"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-11-29"
      hash1 = "1de1336e311ba4ab44828420b4f876d173634670c0b240c6cca5babb1d8b0723"
   strings:
      $x1 = "SharedFiles.dll,BasicScore\"%systemroot%\\system32\\imageres.dll" fullword wide
      $s2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
      $s3 = "SHAREDFI.DLL" fullword ascii
      $s4 = "SharedFiles.dll" fullword wide
      $s5 = "C:\\Users\\User\\Documents" fullword wide
      $s6 = "DragListCtrl.dll" fullword ascii
      $s7 = "MyLinks.dll" fullword wide
      $s8 = "ButtonSkin.dll" fullword wide
      $s9 = "whoami.exe" fullword ascii
      $s10 = " ..\\Windows\\System32\\rundll32.exe" fullword wide
      $s11 = "User (C:\\Users)" fullword wide
      $s12 = "        " fullword ascii
      $s13 = "DOCUMENT.LNK" fullword ascii
      $s14 = "Documents.lnk@" fullword wide
      $s15 = ",System32" fullword wide
      $s16 = " Type Descriptor'" fullword ascii
      $s17 = " constructor or from DllMain." fullword ascii
      $s18 = "  " fullword ascii
      $s19 = "DINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
      $s20 = " Class Hierarchy Descriptor'" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule files_tmp {
   meta:
      description = "8099 - file tmp.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-12-12"
      hash1 = "493a1fbe833c419b37bb345f6f193517d5d9fd2577f09cc74b48b49d7d732a54"
   strings:
      $s1 = "UncategorizedOtherOutOfMemoryUnexpectedEofInterruptedArgumentListTooLongFilenameTooLongTooManyLinksCrossesDevicesDeadlockExecuta" ascii
      $s2 = "uncategorized errorother errorout of memoryunexpected end of fileunsupportedoperation interruptedargument list too longfilename " ascii
      $s3 = "kuiiqaiusmlytqxxnrtl.dll" fullword ascii
      $s4 = "Node.js API crypto.randomFillSync is unavailableNode.js crypto module is unavailablerandSecure: VxWorks RNG module is not initia" ascii
      $s5 = "ctoryoperation would blockentity already existsbroken pipenetwork downaddress not availableaddress in usenot connectedconnection" ascii
      $s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s7 = "keyed events not availableC:rtzkoqhrehbskobagkzngetniywbivatkcfmkxxumjxevfohiuxtzrkjoopvcwassaovngxtdmzbhlhkgasumqlldyupsmjyztrd" ascii
      $s8 = "keyed events not availableC:rtzkoqhrehbskobagkzngetniywbivatkcfmkxxumjxevfohiuxtzrkjoopvcwassaovngxtdmzbhlhkgasumqlldyupsmjyztrd" ascii
      $s9 = "attempted to index slice from after maximum usizeattempted to index slice up to maximum usizeassertion failed: mid <= self.len()" ascii
      $s10 = "attempted to zero-initialize type `alloc::string::String`, which is invalidassertion failed: 0 < pointee_size && pointee_size <=" ascii
      $s11 = "attempted to zero-initialize type `&str`, which is invalidassertion failed: 0 < pointee_size && pointee_size <= isize::MAX as us" ascii
      $s12 = "attempted to zero-initialize type `&str`, which is invalidassertion failed: 0 < pointee_size && pointee_size <= isize::MAX as us" ascii
      $s13 = "rno: did not return a positive valuegetrandom: this target is not supportedC:ehpgbcedommleqfhulhfnkiqvffztwzvxtvorsmuwrtkmtsqdfl" ascii
      $s14 = "attempted to zero-initialize type `(*mut u8, unsafe extern \"C\" fn(*mut u8))`, which is invalidassertion failed: 0 < pointee_si" ascii
      $s15 = "attempted to index slice from after maximum usizeattempted to index slice up to maximum usizeassertion failed: mid <= self.len()" ascii
      $s16 = "attempted to zero-initialize type `alloc::string::String`, which is invalidassertion failed: 0 < pointee_size && pointee_size <=" ascii
      $s17 = "workFileHandleFilesystemLoopReadOnlyFilesystemDirectoryNotEmptyIsADirectoryNotADirectoryWouldBlockAlreadyExistsBrokenPipeNetwork" ascii
      $s18 = "abortednetwork unreachablehost unreachableconnection resetconnection refusedpermission deniedentity not foundErrorkind" fullword ascii
      $s19 = "thread panicked while processing panic. aborting." fullword ascii
      $s20 = "internal_codedescription0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "59e16a2afa5b682bb9692bac873fa10c" and ( pe.exports("EnterDll") and pe.exports("alpjxriee") and pe.exports("arcfqsbobtwbjrf") and pe.exports("asblsmvdudmlwht") and pe.exports("bgttsajxwgwrsai") and pe.exports("bosaplw") ) or 8 of them )
}

rule Documents {
   meta:
      description = "8099 - file Documents.lnk"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
      date = "2021-12-12"
      hash1 = "e87f9f378590b95de1b1ef2aaab84e1d00f210fd6aaf5025d815f33096c9d162"
   strings:
      $x1 = "SharedFiles.dll,BasicScore\"%systemroot%\\system32\\imageres.dll" fullword wide
      $x2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
      $s3 = "C:\\Users\\User\\Documents" fullword wide
      $s4 = " ..\\Windows\\System32\\rundll32.exe" fullword wide
      $s5 = "User (C:\\Users)" fullword wide
      $s6 = ",System32" fullword wide
      $s7 = "Documents" fullword wide /* Goodware String - occured 89 times */
      $s8 = "windev2106eval" fullword ascii
      $s9 = "%Windows" fullword wide /* Goodware String - occured 2 times */
      $s10 = "OwHUSx" fullword ascii
      $s11 = "System Folder" fullword wide /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x004c and filesize < 3KB and
      1 of ($x*) and all of them
}
/*
   YARA Rule Set
   Author: The DFIR Report
   Date: 2022-02-20
   Identifier: Case 8734 Qbot and Zerologon Lead To Full Domain Compromise
   Reference: https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/
*/


/* Rule Set ----------------------------------------------------------------- */


import "pe"


rule qbot_8734_payload_dll {
   meta:
      description = "files - file e2bc969424adc97345ac81194d316f58da38621aad3ca7ae27e40a8fae582987"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2022-02-20"
      hash1 = "e2bc969424adc97345ac81194d316f58da38621aad3ca7ae27e40a8fae582987"
   strings:
      $s1 = "Terfrtghygine.dll" fullword ascii
      $s2 = "Winamp can read extended metadata for titles. Choose when this happens:" fullword wide /* Goodware String - occured 1 times */
      $s3 = "Read metadata when file(s) are loaded into Winamp" fullword wide /* Goodware String - occured 1 times */
      $s4 = "Use advanced title formatting when possible" fullword wide /* Goodware String - occured 1 times */
      $s5 = "PQVW=!?" fullword ascii
      $s6 = "Show underscores in titles as spaces" fullword wide /* Goodware String - occured 1 times */
      $s7 = "Advanced title display format :" fullword wide /* Goodware String - occured 1 times */
      $s8 = "CreatePaint" fullword ascii
      $s9 = "PQRVW=2\"" fullword ascii
      $s10 = "Advanced Title Formatting" fullword wide /* Goodware String - occured 1 times */
      $s11 = "Read metadata when file(s) are played or viewed in the playlist editor" fullword wide /* Goodware String - occured 1 times */
      $s12 = "Show '%20's in titles as spaces" fullword wide /* Goodware String - occured 1 times */
      $s13 = "Example : \"%artist% - %title%\"" fullword wide /* Goodware String - occured 1 times */
      $s14 = "PQRVW=g" fullword ascii
      $s15 = "PQRW=e!" fullword ascii
      $s16 = "ATF Help" fullword wide /* Goodware String - occured 1 times */
      $s17 = "(this can be slow if a large number of files are added at once)" fullword wide /* Goodware String - occured 1 times */
      $s18 = "PQRVW=$" fullword ascii
      $s19 = "Metadata Reading" fullword wide /* Goodware String - occured 1 times */
      $s20 = "Other field names: %artist%, %album%, %title%, %track%, %year%, %genre%, %comment%, %filename%, %disc%, %rating%, ..." fullword wide /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "aa8a9db10fba890f8ef9edac427eab82" and pe.exports("CreatePaint") or 8 of them )
}


rule qbot_dll_8734 {
   meta:
      description = "files - qbot.dll"
      author = "TheDFIRReport"
      reference = "QBOT_DLL"
      date = "2021-12-04"
      hash1 = "4d3b10b338912e7e1cbade226a1e344b2b4aebc1aa2297ce495e27b2b0b5c92b"
   strings:
      $s1 = "Execute not supported: %sfField '%s' is not the correct type of calculated field to be used in an aggregate, use an internalcalc" wide
      $s2 = "IDAPI32.DLL" fullword ascii
      $s3 = "ResetUsageDataActnExecute" fullword ascii
      $s4 = "idapi32.DLL" fullword ascii
      $s5 = "ShowHintsActnExecute" fullword ascii
      $s6 = "OnExecute@iG" fullword ascii
      $s7 = "OnExecutexnD" fullword ascii
      $s8 = "ShowShortCutsInTipsActnExecute" fullword ascii
      $s9 = "ResetActnExecute " fullword ascii
      $s10 = "RecentlyUsedActnExecute" fullword ascii
      $s11 = "LargeIconsActnExecute" fullword ascii
      $s12 = "ResetActnExecute" fullword ascii
      $s13 = "OnExecute<" fullword ascii
      $s14 = "TLOGINDIALOG" fullword wide
      $s15 = "%s%s:\"%s\";" fullword ascii
      $s16 = ":\":&:7:?:C:\\:" fullword ascii /* hex encoded string '|' */
      $s17 = "LoginPrompt" fullword ascii
      $s18 = "TLoginDialog" fullword ascii
      $s19 = "OnLogin" fullword ascii
      $s20 = "Database Login" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      12 of them
}
/* 
   YARA Rule Set 
   Author: The DFIR Report 
   Date: 2022-04-04
   Identifier: Case 9438 Stolen Images Campaign Ends in Conti Ransomware
   Reference: https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/
*/ 


/* Rule Set ----------------------------------------------------------------- */ 


rule cs_exe_9438 {
   meta:
      description = "9438 - file Faicuy4.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/"
      date = "2022-04-04"
      hash1 = "a79f5ce304707a268b335f63d15e2d7d740b4d09b6e7d095d7d08235360e739c"
   strings:
      $x1 = "C:\\Users\\Administrator\\Documents\\Visual Studio 2008\\Projects\\MUTEXES\\x64\\Release\\MUTEXES.pdb" fullword ascii
      $s2 = "mutexes Version 1.0" fullword wide
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s4 = ".?AVCMutexesApp@@" fullword ascii
      $s5 = ".?AVCMutexesDlg@@" fullword ascii
      $s6 = "About mutexes" fullword wide
      $s7 = "Mutexes Sample" fullword wide
      $s8 = " 1992 - 2001 Microsoft Corporation.  All rights reserved." fullword wide
      $s9 = "&Process priority class:" fullword wide
      $s10 = " Type Descriptor'" fullword ascii
      $s11 = "&About mutexes..." fullword wide
      $s12 = " constructor or from DllMain." fullword ascii
      $s13 = ".?AVCDisplayThread@@" fullword ascii
      $s14 = "IsQ:\"P" fullword ascii
      $s15 = "CExampleThread" fullword ascii
      $s16 = ".?AVCCounterThread@@" fullword ascii
      $s17 = ".?AVCExampleThread@@" fullword ascii
      $s18 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s19 = "CDisplayThread" fullword ascii
      $s20 = "CCounterThread" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}


rule conti_dll_9438 {
   meta:
      description = "9438 - file x64.dll"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/"
      date = "2022-04-04"
      hash1 = "8fb035b73bf207243c9b29d96e435ce11eb9810a0f4fdcc6bb25a14a0ec8cc21"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "conti_v3.dll" fullword ascii
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s4 = "api-ms-win-core-processthreads-l1-1-2" fullword wide
      $s5 = "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
      $s6 = " Type Descriptor'" fullword ascii
      $s7 = "operator \"\" " fullword ascii
      $s8 = "operator co_await" fullword ascii
      $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s10 = "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
      $s11 = "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
      $s12 = "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
      $s13 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s14 = " Base Class Descriptor at (" fullword ascii
      $s15 = " Class Hierarchy Descriptor'" fullword ascii
      $s16 = "bad array new length" fullword ascii
      $s17 = " Complete Object Locator'" fullword ascii
      $s18 = ".data$r" fullword ascii
      $s19 = " delete[]" fullword ascii
      $s20 = "  </trustInfo>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      all of them
}
rule files_dhvqx {
   meta:
      description = "9893_files - file dhvqx.aspx"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "c5aae30675cc1fd83fd25330cec245af744b878a8f86626d98b8e7fcd3e970f8"
   strings:
      $s1 = "eval(Request['exec_code'],'unsafe');Response.End;" fullword ascii
      $s2 = "6<script language='JScript' runat='server'>" fullword ascii
      $s3 = "AEALAAAAAAAAAAA" fullword ascii
      $s4 = "AFAVAJA" fullword ascii
      $s5 = "AAAAAAV" fullword ascii
      $s6 = "LAAAAAAA" fullword ascii
      $s7 = "ANAZAQA" fullword ascii
      $s8 = "ALAAAAA" fullword ascii
      $s9 = "AAAAAEA" ascii
      $s10 = "ALAHAUA" fullword ascii
   condition:
      uint16(0) == 0x4221 and filesize < 800KB and
      ($s1 and $s2)  and 4 of them
}


rule aspx_dyukbdcxjfi {
   meta:
      description = "9893_files - file aspx_dyukbdcxjfi.aspx"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "84f77fc4281ebf94ab4897a48aa5dd7092cc0b7c78235965637eeef0908fb6c7"
   strings:
      $s1 = "string[] commands = exec_code.Substring(\"run \".Length).Split(new[] { ';' }, StringSplitOptions.RemoveEmpty" ascii
      $s2 = "string[] commands = exec_code.Substring(\"run \".Length).Split(new[] { ';' }, StringSplitOptions.RemoveEmpty" ascii
      $s3 = "var dstFile = Path.Combine(dstDir, Path.GetFileName(httpPostedFile.FileName));" fullword ascii
      $s4 = "info.UseShellExecute = false;" fullword ascii
      $s5 = "using (StreamReader streamReader = process.StandardError)" fullword ascii
      $s6 = "return httpPostedFile.FileName + \" Uploaded to: \" + dstFile;" fullword ascii
      $s7 = "else if (exec_code.StartsWith(\"download \"))" fullword ascii
      $s8 = "string[] parts = exec_code.Substring(\"download \".Length).Split(' ');" fullword ascii
      $s9 = "Response.AppendHeader(\"Content-Disposition\", \"attachment; filename=\" + fileName);" fullword ascii
      $s10 = "result = result + Environment.NewLine + \"ERROR:\" + Environment.NewLine + error;" fullword ascii
      $s11 = "else if (exec_code == \"get\")" fullword ascii
      $s12 = "int fileLength = httpPostedFile.ContentLength;" fullword ascii
   condition:
      uint16(0) == 0x4221 and filesize < 800KB and
      8 of them
}


rule files_user {
   meta:
      description = "9893_files - file user.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "7b5fbbd90eab5bee6f3c25aa3c2762104e219f96501ad6a4463e25e6001eb00b"
   strings:
      $x1 = "PA<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVer" ascii
      $s2 = "\", or \"requireAdministrator\" --> <v3:requestedExecutionLevel level=\"requireAdministrator\" /> </v3:requestedPrivileges> </v3" ascii
      $s3 = "-InitOnceExecuteOnce" fullword ascii
      $s4 = "0\"> <dependency> <dependentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0." ascii
      $s5 = "s:v3=\"urn:schemas-microsoft-com:asm.v3\"> <v3:security> <v3:requestedPrivileges> <!-- level can be \"asInvoker\", \"highestAvai" ascii
      $s6 = "PB_GadgetStack_%I64i" fullword ascii
      $s7 = "PB_DropAccept" fullword ascii
      $s8 = "rocessorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /> </dependentAssembly> </dependency> <v3:trustInf" ascii
      $s9 = "PB_PostEventMessage" fullword ascii
      $s10 = "PB_WindowID" fullword ascii
      $s11 = "?GetLongPathNameA" fullword ascii
      $s12 = "Memory page error" fullword ascii
      $s13 = "PPPPPPH" fullword ascii
      $s14 = "YZAXAYH" fullword ascii
      $s15 = "%d:%I64d:%I64d:%I64d" fullword ascii
      $s16 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s17 = "PYZAXAYH" fullword ascii
      $s18 = "PB_MDI_Gadget" fullword ascii
      $s19 = "PA<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVer" ascii
      $s20 = " 46B722FD25E69870FA7711924BC5304D 787242D55F2C49A23F5D97710D972108 A2DB26CE3BBE7B2CB12F9BEFB37891A3" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}


rule task_update {
   meta:
      description = "9893_files - file task_update.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "12c6da07da24edba13650cd324b2ad04d0a0526bb4e853dee03c094075ff6d1a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii
      $s2 = " or \"requireAdministrator\" --> <v3:requestedExecutionLevel level=\"requireAdministrator\" /> </v3:requestedPrivileges> </v3:se" ascii
      $s3 = "-InitOnceExecuteOnce" fullword ascii
      $s4 = "> <dependency> <dependentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0" ascii
      $s5 = "v3=\"urn:schemas-microsoft-com:asm.v3\"> <v3:security> <v3:requestedPrivileges> <!-- level can be \"asInvoker\", \"highestAvaila" ascii
      $s6 = "PB_GadgetStack_%I64i" fullword ascii
      $s7 = "PB_DropAccept" fullword ascii
      $s8 = "PB_PostEventMessage" fullword ascii
      $s9 = "PB_WindowID" fullword ascii
      $s10 = "?GetLongPathNameA" fullword ascii
      $s11 = "cessorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /> </dependentAssembly> </dependency> <v3:trustInfo " ascii
      $s12 = "Memory page error" fullword ascii
      $s13 = "PPPPPPH" fullword ascii
      $s14 = "YZAXAYH" fullword ascii
      $s15 = "%d:%I64d:%I64d:%I64d" fullword ascii
      $s16 = "PYZAXAYH" fullword ascii
      $s17 = "PB_MDI_Gadget" fullword ascii
      $s18 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii
      $s19 = " 11FCC18FB2B55FC3C988F6A76FCF8A2D 56D49E57AD1A051BF62C458CD6F3DEA9 6104990DFEA3DFAB044FAF960458DB09" fullword wide
      $s20 = "PostEventClass" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}


rule App_Web_vjloy3pa {
   meta:
      description = "9893_files - file App_Web_vjloy3pa.dll"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "faa315db522d8ce597ac0aa957bf5bde31d91de94e68d5aefac4e3e2c11aa970"
   strings:
      $x2 = "hSystem.ComponentModel.DataAnnotations, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s3 = "MSystem.Xml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s4 = "RSystem.Xml.Linq, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s5 = "ZSystem.ServiceModel.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s6 = "YSystem.Web.DynamicData, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s7 = "XSystem.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s8 = "VSystem.Web.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s9 = "MSystem.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s10 = "WSystem.Configuration, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s11 = "`System.Data.DataSetExtensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s12 = "NSystem.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s13 = "ZSystem.WorkflowServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s14 = "WSystem.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s15 = "aSystem.ServiceModel.Activation, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s16 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide /* base64 encoded string '' */
      $s17 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" wide /* base64 encoded string '' */
      $s18 = "aSystem.Web.ApplicationServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" fullword ascii
      $s19 = "\\System.EnterpriseServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
      $s20 = "SMicrosoft.CSharp, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}


rule _user_task_update_0 {
   meta:
      description = "9893_files - from files user.exe, task_update.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
      date = "2022-03-21"
      hash1 = "7b5fbbd90eab5bee6f3c25aa3c2762104e219f96501ad6a4463e25e6001eb00b"
      hash2 = "12c6da07da24edba13650cd324b2ad04d0a0526bb4e853dee03c094075ff6d1a"
   strings:
      $s1 = "-InitOnceExecuteOnce" fullword ascii
      $s2 = "PB_GadgetStack_%I64i" fullword ascii
      $s3 = "PB_DropAccept" fullword ascii
      $s4 = "PB_PostEventMessage" fullword ascii
      $s5 = "PB_WindowID" fullword ascii
      $s6 = "?GetLongPathNameA" fullword ascii
      $s7 = "Memory page error" fullword ascii
      $s8 = "PPPPPPH" fullword ascii
      $s9 = "YZAXAYH" fullword ascii
      $s10 = "%d:%I64d:%I64d:%I64d" fullword ascii
      $s11 = "PYZAXAYH" fullword ascii
      $s12 = "PB_MDI_Gadget" fullword ascii
      $s13 = "PostEventClass" fullword ascii
      $s14 = "t$hYZAXAYH" fullword ascii
      $s15 = "$YZAXAYH" fullword ascii
      $s16 = "Floating-point underflow (exponent too small)" fullword ascii
      $s17 = "Inexact floating-point result" fullword ascii
      $s18 = "Single step trap" fullword ascii
      $s19 = "Division by zero (floating-point)" fullword ascii
      $s20 = "tmHcI(H" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}
