// Rules from Fireeyes https://github.com/fireeye/capa-rules converted to YARA using capa2yara.py by Arnim Rupp (not published yet)

// Beware: These are less rules than capa (because not all fit into YARA, stats at EOF) and is less precise because e.g. capas function scopes are applied to the whole file

// Beware: Some rules are incomplete because an optional branch was not supported by YARA. These rules are marked in a comment in meta: (search for "incomplete")

// Rule authors and license stay the same

// att&ck and MBC tags are put into YARA rule tags. All rules are tagged with "CAPA" for easy filtering

// The date = in meta: is the date of converting (there is no date in capa rules)

// Minimum YARA version is 3.8.0 plus PE module


import "pe"


private rule capa_pe_file : CAPA {
    meta:
        description = "match in PE files. used by all further CAPA rules"
        author = "Arnim Rupp"
    condition:
        uint16be(0) == 0x4d5a
        or uint16be(0) == 0x558b
        or uint16be(0) == 0x5649
}


private rule capa_create_or_open_file : CAPA C0016  { 
  meta: 
 	description = "create or open file (converted from capa rule)"
	author = "michael.hunhoff@fireeye.com"
	lib = "True"
	scope = "basic block"
	mbc = "File System::Create File [C0016]"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/create-or-open-file.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aaa = /\bCreateFile(A|W)?\b/ ascii wide
	$api_aab = /\bCreateFileEx(A|W)?\b/ ascii wide
	$api_aac = /\bIoCreateFile(A|W)?\b/ ascii wide
	$api_aad = /\bIoCreateFileEx(A|W)?\b/ ascii wide
	$api_aae = /\bZwOpenFile(A|W)?\b/ ascii wide
	$api_aaf = /\bZwCreateFile(A|W)?\b/ ascii wide
	$api_aag = /\bNtOpenFile(A|W)?\b/ ascii wide
	$api_aah = /\bNtCreateFile(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_aaa 
		or 	$api_aab 
		or 	$api_aac 
		or 	$api_aad 
		or 	$api_aae 
		or 	$api_aaf 
		or 	$api_aag 
		or 	$api_aah  
	) 
}

private rule capa_open_thread : CAPA  { 
  meta: 
 	description = "open thread (converted from capa rule)"
	author = "0x534a@mailbox.org"
	lib = "True"
	scope = "basic block"
	hash = "787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e:00502F4C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/open-thread.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aai = /\bNtOpenThread(A|W)?\b/ ascii wide
	$api_aaj = /\bZwOpenThread(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /OpenThread/) 
		or 	$api_aai 
		or 	$api_aaj  
	) 
}

private rule capa_allocate_memory : CAPA C0007  { 
  meta: 
 	description = "allocate memory (converted from capa rule)"
	author = "0x534a@mailbox.org"
	lib = "True"
	scope = "basic block"
	mbc = "Memory::Allocate Memory [C0007]"
	hash = "Practical Malware Analysis Lab 03-03.exe_:0x4010EA"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/allocate-memory.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aak = /\bNtAllocateVirtualMemory(A|W)?\b/ ascii wide
	$api_aal = /\bZwAllocateVirtualMemory(A|W)?\b/ ascii wide
	$api_aam = /\bNtMapViewOfSection(A|W)?\b/ ascii wide
	$api_aan = /\bZwMapViewOfSection(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /VirtualAlloc/) 
		or 	pe.imports(/kernel32/i, /VirtualAllocEx/) 
		or 	pe.imports(/kernel32/i, /VirtualAllocExNuma/) 
		or 	pe.imports(/kernel32/i, /VirtualProtect/) 
		or 	pe.imports(/kernel32/i, /VirtualProtectEx/) 
		or 	$api_aak 
		or 	$api_aal 
		or 	$api_aam 
		or 	$api_aan  
	) 
}

private rule capa_delay_execution : CAPA B0003_003  { 
  meta: 
 	description = "delay execution (converted from capa rule)"
	author = "michael.hunhoff@fireeye.com"
	lib = "True"
	scope = "basic block"
	mbc = "Anti-Behavioral Analysis::Dynamic Analysis Evasion::Delayed Execution [B0003.003]"
	references = "https://docs.microsoft.com/en-us/windows/win32/sync/wait-functions"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/TimingAttacks/timing.cpp"
	hash = "al-khaser_x86.exe_:0x449770"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/delay-execution.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aao = /\bWaitOnAddress(A|W)?\b/ ascii wide
	$api_aap = /\bNtDelayExecution(A|W)?\b/ ascii wide
	$api_aaq = /\bKeWaitForSingleObject(A|W)?\b/ ascii wide
	$api_aar = /\bKeDelayExecutionThread(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /Sleep/) 
		or 	pe.imports(/kernel32/i, /SleepEx/) 
		or 	pe.imports(/kernel32/i, /WaitForSingleObject/) 
		or 	pe.imports(/kernel32/i, /SignalObjectAndWait/) 
		or 	pe.imports(/kernel32/i, /WaitForSingleObjectEx/) 
		or 	pe.imports(/kernel32/i, /WaitForMultipleObjects/) 
		or 	pe.imports(/kernel32/i, /WaitForMultipleObjectsEx/) 
		or 	pe.imports(/kernel32/i, /RegisterWaitForSingleObject/) 
		or 	$api_aao 
		or 	pe.imports(/user32/i, /MsgWaitForMultipleObjects/) 
		or 	pe.imports(/user32/i, /MsgWaitForMultipleObjectsEx/) 
		or 	$api_aap 
		or 	$api_aaq 
		or 	$api_aar  
	) 
}

private rule capa_write_process_memory : CAPA T1055  { 
  meta: 
 	description = "write process memory (converted from capa rule)"
	author = "moritz.raabe@fireeye.com"
	lib = "True"
	scope = "function"
	attack = "Defense Evasion::Process Injection [T1055]"
	hash = "2D3EDC218A90F03089CC01715A9F047F"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/write-process-memory.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aas = /\bNtWow64WriteVirtualMemory64(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /WriteProcessMemory/) 
		or 	pe.imports(/ntdll/i, /NtWriteVirtualMemory/) 
		or 	pe.imports(/ntdll/i, /ZwWriteVirtualMemory/) 
		or 	$api_aas  
	) 
}

private rule capa_open_process : CAPA  { 
  meta: 
 	description = "open process (converted from capa rule)"
	author = "0x534a@mailbox.org"
	lib = "True"
	scope = "basic block"
	hash = "Practical Malware Analysis Lab 17-02.dll_:0x1000D10D"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/lib/open-process.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aat = /\bNtOpenProcess(A|W)?\b/ ascii wide
	$api_aau = /\bZwOpenProcess(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /OpenProcess/) 
		or 	$api_aat 
		or 	$api_aau  
	) 
}

private rule capa_delete_volume_shadow_copies : CAPA T1490 T1070_004 F0014_001  { 
  meta: 
 	description = "delete volume shadow copies (converted from capa rule)"
	namespace = "impact/inhibit-system-recovery"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Impact::Inhibit System Recovery [T1490]"
	attack = "Defense Evasion::Indicator Removal on Host::File Deletion [T1070.004]"
	mbc = "Impact::Disk Content Wipe::Delete Shadow Drive [F0014.001]"
	hash = "B87E9DD18A5533A09D3E48A7A1EFBCF6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/impact/inhibit-system-recovery/delete-volume-shadow-copies.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_aaw = /vssadmin.{,1000} delete shadows/ nocase ascii wide 
	$re_aax = /vssadmin.{,1000} resize shadowstorage/ nocase ascii wide 
	$re_aay = /wmic.{,1000} shadowcopy delete/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_aaw 
		or 	$re_aax 
		or 	$re_aay  
	) 
}

private rule capa_reference_analysis_tools_strings : CAPA B0013_001  { 
  meta: 
 	description = "reference analysis tools strings (converted from capa rule)"
	namespace = "anti-analysis"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	mbc = "Discovery::Analysis Tool Discovery::Process Detection [B0013.001]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiAnalysis/process.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/reference-analysis-tools-strings.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_aaz = /ollydbg.exe/ nocase ascii wide 
	$re_aba = /ProcessHacker.exe/ nocase ascii wide 
	$re_abb = /tcpview.exe/ nocase ascii wide 
	$re_abc = /autoruns.exe/ nocase ascii wide 
	$re_abd = /autorunsc.exe/ nocase ascii wide 
	$re_abe = /filemon.exe/ nocase ascii wide 
	$re_abf = /procmon.exe/ nocase ascii wide 
	$re_abg = /regmon.exe/ nocase ascii wide 
	$re_abh = /procexp.exe/ nocase ascii wide 
	$re_abi = /idaq.exe/ nocase ascii wide 
	$re_abj = /idaq64.exe/ nocase ascii wide 
	$re_abk = /ImmunityDebugger.exe/ nocase ascii wide 
	$re_abl = /Wireshark.exe/ nocase ascii wide 
	$re_abm = /dumpcap.exe/ nocase ascii wide 
	$re_abn = /HookExplorer.exe/ nocase ascii wide 
	$re_abo = /ImportREC.exe/ nocase ascii wide 
	$re_abp = /PETools.exe/ nocase ascii wide 
	$re_abq = /LordPE.exe/ nocase ascii wide 
	$re_abr = /SysInspector.exe/ nocase ascii wide 
	$re_abs = /proc_analyzer.exe/ nocase ascii wide 
	$re_abt = /sysAnalyzer.exe/ nocase ascii wide 
	$re_abu = /sniff_hit.exe/ nocase ascii wide 
	$re_abv = /windbg.exe/ nocase ascii wide 
	$re_abw = /joeboxcontrol.exe/ nocase ascii wide 
	$re_abx = /joeboxserver.exe/ nocase ascii wide 
	$re_aby = /ResourceHacker.exe/ nocase ascii wide 
	$re_abz = /x32dbg.exe/ nocase ascii wide 
	$re_aca = /x64dbg.exe/ nocase ascii wide 
	$re_acb = /Fiddler.exe/ nocase ascii wide 
	$re_acc = /httpdebugger.exe/ nocase ascii wide 
	$re_acd = /fakenet.exe/ nocase ascii wide 
	$re_ace = /netmon.exe/ nocase ascii wide 
	$re_acf = /WPE PRO.exe/ nocase ascii wide 
	$re_acg = /decompile.exe/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_aaz 
		or 	$re_aba 
		or 	$re_abb 
		or 	$re_abc 
		or 	$re_abd 
		or 	$re_abe 
		or 	$re_abf 
		or 	$re_abg 
		or 	$re_abh 
		or 	$re_abi 
		or 	$re_abj 
		or 	$re_abk 
		or 	$re_abl 
		or 	$re_abm 
		or 	$re_abn 
		or 	$re_abo 
		or 	$re_abp 
		or 	$re_abq 
		or 	$re_abr 
		or 	$re_abs 
		or 	$re_abt 
		or 	$re_abu 
		or 	$re_abv 
		or 	$re_abw 
		or 	$re_abx 
		or 	$re_aby 
		or 	$re_abz 
		or 	$re_aca 
		or 	$re_acb 
		or 	$re_acc 
		or 	$re_acd 
		or 	$re_ace 
		or 	$re_acf 
		or 	$re_acg  
	) 
}

private rule capa_timestomp_file : CAPA T1070_006  { 
  meta: 
 	description = "timestomp file (converted from capa rule)"
	namespace = "anti-analysis/anti-forensic/timestomp"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Indicator Removal on Host::Timestomp [T1070.006]"
	hash = "Practical Malware Analysis Lab 03-04.exe_:0x4014e0"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-forensic/timestomp/timestomp-file.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/kernel32/i, /GetSystemTime/) 
		or 	pe.imports(/kernel32/i, /FileTimeToLocalFileTime/) 
		or 	pe.imports(/kernel32/i, /GetSystemTimeAsFileTime/) 
		or 	pe.imports(/kernel32/i, /SystemTimeToFileTime/) 
		or 	pe.imports(/kernel32/i, /GetFileTime/)  
	) 
		and 	pe.imports(/kernel32/i, /SetFileTime/)  
	) 
}

private rule capa_clear_the_Windows_event_log : CAPA T1070_001  { 
  meta: 
 	description = "clear the Windows event log (converted from capa rule)"
	namespace = "anti-analysis/anti-forensic/clear-logs"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Defense Evasion::Indicator Removal on Host::Clear Windows Event Logs [T1070.001]"
	hash = "82BF6347ACF15E5D883715DC289D8A2B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-forensic/clear-logs/clear-the-windows-event-log.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /ElfClearEventLogFile/)  
	) 
}

private rule capa_check_for_sandbox_and_av_modules : CAPA B0009 B0007  { 
  meta: 
 	description = "check for sandbox and av modules (converted from capa rule)"
	namespace = "anti-analysis/anti-av"
	author = "@_re_fox"
	scope = "basic block"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	mbc = "Anti-Behavioral Analysis::Sandbox Detection [B0007]"
	hash = "ccbf7cba35bab56563c0fbe4237fdc41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-av/check-for-sandbox-and-av-modules.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_ach = /\bGetModuleHandle(A|W)?\b/ ascii wide
	$re_aci = /avghook(x|a)\.dll/ nocase ascii wide  // AVG
	$re_acj = /snxhk\.dll/ nocase ascii wide  // Avast
	$re_ack = /sf2\.dll/ nocase ascii wide  // Avast
	$re_acl = /sbiedll\.dll/ nocase ascii wide  // Sandboxie
	$re_acm = /dbghelp\.dll/ nocase ascii wide  // WindBG
	$re_acn = /api_log\.dll/ nocase ascii wide  // iDefense Lab
	$re_aco = /dir_watch\.dll/ ascii wide  // iDefense Lab
	$re_acp = /pstorec\.dll/ nocase ascii wide  // SunBelt Sandbox
	$re_acq = /vmcheck\.dll/ nocase ascii wide  // Virtual PC
	$re_acr = /wpespy\.dll/ nocase ascii wide  // WPE Pro
	$re_acs = /cmdvrt(64|32).dll/ nocase ascii wide  // Comodo Container
	$re_act = /sxin.dll/ nocase ascii wide  // 360 SOFTWARE
	$re_acu = /dbghelp\.dll/ nocase ascii wide  // WINE
	$re_acv = /printfhelp\.dll/ nocase ascii wide  // Unknown Sandbox
 
  condition:
    capa_pe_file and
 (
			$api_ach 
		and  (
			$re_aci 
		or 	$re_acj 
		or 	$re_ack 
		or 	$re_acl 
		or 	$re_acm 
		or 	$re_acn 
		or 	$re_aco 
		or 	$re_acp 
		or 	$re_acq 
		or 	$re_acr 
		or 	$re_acs 
		or 	$re_act 
		or 	$re_acu 
		or 	$re_acv  
	)  
	) 
}

private rule capa_packed_with_pebundle : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with pebundle (converted from capa rule)"
	namespace = "anti-analysis/packer/pebundle"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "db9fe790b4e18abf55df31aa0b81e558"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/pebundle/packed-with-pebundle.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any acw in pe.sections : ( acw.name == "pebundle" ) 
		or 	for any acx in pe.sections : ( acx.name == "PEBundle" )  
	) 
}

private rule capa_packed_with_ASPack : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with ASPack (converted from capa rule)"
	namespace = "anti-analysis/packer/aspack"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "http://www.aspack.com/"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "2055994ff75b4309eee3a49c5749d306"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/aspack/packed-with-aspack.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_adc = "The procedure entry point %s could not be located in the dynamic link library %s" ascii wide
	$str_add = "The ordinal %u could not be located in the dynamic link library %s" ascii wide
 
  condition:
    capa_pe_file and
 (
			for any acy in pe.sections : ( acy.name == ".aspack" ) 
		or 	for any acz in pe.sections : ( acz.name == ".adata" ) 
		or 	for any ada in pe.sections : ( ada.name == ".ASPack" ) 
		or 	for any adb in pe.sections : ( adb.name == "ASPack" ) 
		or 	$str_adc 
		or 	$str_add  
	) 
}

private rule capa_packed_with_nspack : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with nspack (converted from capa rule)"
	namespace = "anti-analysis/packer/nspack"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "02179f3ba93663074740b5c0d283bae2"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/nspack/packed-with-nspack.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any ade in pe.sections : ( ade.name == ".nsp0" ) 
		or 	for any adf in pe.sections : ( adf.name == ".nsp1" ) 
		or 	for any adg in pe.sections : ( adg.name == ".nsp2" )  
	) 
}

private rule capa_packed_with_kkrunchy : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with kkrunchy (converted from capa rule)"
	namespace = "anti-analysis/packer/kkrunchy"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "http://www.farbrausch.de/~fg/kkrunchy/"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "f9ac6b16273556b3a57bf2c6d7e7db97"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/kkrunchy/packed-with-kkrunchy.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any adh in pe.sections : ( adh.name == "kkrunchy" )  
	) 
}

private rule capa_packed_with_petite : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with petite (converted from capa rule)"
	namespace = "anti-analysis/packer/petite"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "2a7429d60040465f9bd27bbae2beef88"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/petite/packed-with-petite.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any adi in pe.sections : ( adi.name == ".petite" )  
	) 
}

private rule capa_packed_with_pelocknt : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with pelocknt (converted from capa rule)"
	namespace = "anti-analysis/packer/pelocknt"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "f0a6a1bd6d760497623611e8297a81df"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/pelocknt/packed-with-pelocknt.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any adj in pe.sections : ( adj.name == "PELOCKnt" )  
	) 
}

private rule capa_packed_with_upack : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with upack (converted from capa rule)"
	namespace = "anti-analysis/packer/upack"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "9d98f8519d9fee8219caca5b31eef0bd"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/upack/packed-with-upack.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_adm = "UpackByDwing@" ascii wide
 
  condition:
    capa_pe_file and
 (
			for any adk in pe.sections : ( adk.name == ".Upack" ) 
		or 	for any adl in pe.sections : ( adl.name == ".ByDwing" ) 
		or 	$str_adm  
	) 
}

private rule capa_packed_with_y0da_crypter : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with y0da crypter (converted from capa rule)"
	namespace = "anti-analysis/packer/y0da"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "0cd2b334aede270b14868db28211cde3"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/y0da/packed-with-y0da-crypter.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any adn in pe.sections : ( adn.name == ".y0da" ) 
		or 	for any ado in pe.sections : ( ado.name == ".y0da_1" ) 
		or 	for any adp in pe.sections : ( adp.name == ".yP" )  
	) 
}

private rule capa_packed_with_Confuser : CAPA T1027_002 F0001_009  { 
  meta: 
 	description = "packed with Confuser (converted from capa rule)"
	namespace = "anti-analysis/packer/confuser"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing::Confuser [F0001.009]"
	hash = "b9f5bd514485fb06da39beff051b9fdc"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/confuser/packed-with-confuser.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_adq = "ConfusedByAttribute" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_adq  
	) 
}

private rule capa_packed_with_amber : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with amber (converted from capa rule)"
	namespace = "anti-analysis/packer/amber"
	author = "john.gorman@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://github.com/EgeBalci/amber"
	hash = "bb7922d368a9a9c8d981837b5ad988f1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/amber/packed-with-amber.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_adr = "Amber - Reflective PE Packer" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_adr  
	) 
}

private rule capa_packed_with_VMProtect : CAPA T1027_002 F0001_010  { 
  meta: 
 	description = "packed with VMProtect (converted from capa rule)"
	namespace = "anti-analysis/packer/vmprotect"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing::VMProtect [F0001.010]"
	references = "https://www.pcworld.com/article/2824572/leaked-programming-manual-may-help-criminals-develop-more-atm-malware.html"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "971e599e6e707349eccea2fd4c8e5f67"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/vmprotect/packed-with-vmprotect.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_ads = "A debugger has been found running in your system." ascii wide
	$str_adt = "Please, unload it from memory and restart your program." ascii wide
	$str_adu = "File corrupted!. This program has been manipulated and maybe" ascii wide
	$str_adv = "it's infected by a Virus or cracked. This file won't work anymore." ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_ads 
		or 	$str_adt 
		or 	$str_adu 
		or 	$str_adv 
		or 	for any adw in pe.sections : ( adw.name == ".vmp0" ) 
		or 	for any adx in pe.sections : ( adx.name == ".vmp1" ) 
		or 	for any ady in pe.sections : ( ady.name == ".vmp2" )  
	) 
}

private rule capa_packed_with_rlpack : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with rlpack (converted from capa rule)"
	namespace = "anti-analysis/packer/rlpack"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "068a76d4823419b376d418cf03215d5c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/rlpack/packed-with-rlpack.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any adz in pe.sections : ( adz.name == ".RLPack" ) 
		or 	for any aea in pe.sections : ( aea.name == ".packed" )  
	) 
}

private rule capa_packed_with_UPX : CAPA T1027_002 F0001_008  { 
  meta: 
 	description = "packed with UPX (converted from capa rule)"
	namespace = "anti-analysis/packer/upx"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing::UPX [F0001.008]"
	hash = "CD2CBA9E6313E8DF2C1273593E649682"
	hash = "Practical Malware Analysis Lab 01-02.exe_:0x0401000"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/upx/packed-with-upx.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any aeb in pe.sections : ( aeb.name == "UPX0" ) 
		or 	for any aec in pe.sections : ( aec.name == "UPX1" )  
	) 
}

private rule capa_packed_with_peshield : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with peshield (converted from capa rule)"
	namespace = "anti-analysis/packer/peshield"
	author = "@_re_fox"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	hash = "a3c0a2425ea84103adde03a92176424c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/peshield/packed-with-peshield.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_aef = / PE-SHiELD v[0-9]\.[0-9]/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			for any aed in pe.sections : ( aed.name == "PESHiELD" ) 
		or 	for any aee in pe.sections : ( aee.name == "PESHiELD_1" ) 
		or 	$re_aef  
	) 
}

private rule capa_reference_anti_VM_strings_targeting_VMWare : CAPA T1497_001 B0009  { 
  meta: 
 	description = "reference anti-VM strings targeting VMWare (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/VMWare.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-vmware.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_aei = /VMWare/ nocase ascii wide 
	$re_aej = /VMTools/ nocase ascii wide 
	$re_aek = /SOFTWARE\\VMware, Inc\.\\VMware Tools/ nocase ascii wide 
	$re_ael = /vmnet.sys/ nocase ascii wide 
	$re_aem = /vmmouse.sys/ nocase ascii wide 
	$re_aen = /vmusb.sys/ nocase ascii wide 
	$re_aeo = /vm3dmp.sys/ nocase ascii wide 
	$re_aep = /vmci.sys/ nocase ascii wide 
	$re_aeq = /vmhgfs.sys/ nocase ascii wide 
	$re_aer = /vmmemctl.sys/ nocase ascii wide 
	$re_aes = /vmx86.sys/ nocase ascii wide 
	$re_aet = /vmrawdsk.sys/ nocase ascii wide 
	$re_aeu = /vmusbmouse.sys/ nocase ascii wide 
	$re_aev = /vmkdb.sys/ nocase ascii wide 
	$re_aew = /vmnetuserif.sys/ nocase ascii wide 
	$re_aex = /vmnetadapter.sys/ nocase ascii wide 
	$re_aey = /\\\\.\\HGFS/ nocase ascii wide 
	$re_aez = /\\\\.\\vmci/ nocase ascii wide 
	$re_afa = /vmtoolsd.exe/ nocase ascii wide 
	$re_afb = /vmwaretray.exe/ nocase ascii wide 
	$re_afc = /vmwareuser.exe/ nocase ascii wide 
	$re_afd = /VGAuthService.exe/ nocase ascii wide 
	$re_afe = /vmacthlp.exe/ nocase ascii wide 
	$re_aff = /vmci/ nocase ascii wide  // VMWare VMCI Bus Driver
	$re_afg = /vmhgfs/ nocase ascii wide  // VMWare Host Guest Control Redirector
	$re_afh = /vmmouse/ nocase ascii wide 
	$re_afi = /vmmemctl/ nocase ascii wide  // VMWare Guest Memory Controller Driver
	$re_afj = /vmusb/ nocase ascii wide 
	$re_afk = /vmusbmouse/ nocase ascii wide 
	$re_afl = /vmx_svga/ nocase ascii wide 
	$re_afm = /vmxnet/ nocase ascii wide 
	$re_afn = /vmx86/ nocase ascii wide 
	$re_afo = /VMwareVMware/ nocase ascii wide 
	$re_afp = /vmGuestLib.dll/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_aei 
		or 	$re_aej 
		or 	$re_aek 
		or 	$re_ael 
		or 	$re_aem 
		or 	$re_aen 
		or 	$re_aeo 
		or 	$re_aep 
		or 	$re_aeq 
		or 	$re_aer 
		or 	$re_aes 
		or 	$re_aet 
		or 	$re_aeu 
		or 	$re_aev 
		or 	$re_aew 
		or 	$re_aex 
		or 	$re_aey 
		or 	$re_aez 
		or 	$re_afa 
		or 	$re_afb 
		or 	$re_afc 
		or 	$re_afd 
		or 	$re_afe 
		or 	$re_aff 
		or 	$re_afg 
		or 	$re_afh 
		or 	$re_afi 
		or 	$re_afj 
		or 	$re_afk 
		or 	$re_afl 
		or 	$re_afm 
		or 	$re_afn 
		or 	$re_afo 
		or 	$re_afp  
	) 
}

private rule capa_check_for_windows_sandbox_via_device : CAPA T1497_001 B0009  { 
  meta: 
 	description = "check for windows sandbox via device (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LloydLabs/wsb-detect"
	hash = "773290480d5445f11d3dc1b800728966"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-device.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_afq = /\bCreateFile(A|W)?\b/ ascii wide
	$str_afr = "\\\\.\\GLOBALROOT\\device\\vmsmb" ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_afq 
		and 	$str_afr  
	) 
}

private rule capa_check_for_microsoft_office_emulation : CAPA T1497_001 B0007_005  { 
  meta: 
 	description = "check for microsoft office emulation (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection::Product Key/ID Testing [B0007.005]"
	references = "https://github.com/LloydLabs/wsb-detect"
	hash = "773290480d5445f11d3dc1b800728966"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-microsoft-office-emulation.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_afs = /OfficePackagesForWDAG/ ascii wide 
	$api_aft = /\bGetWindowsDirectory(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_afs 
		and 	$api_aft  
	) 
}

private rule capa_check_for_sandbox_username : CAPA T1497 B0009  { 
  meta: 
 	description = "check for sandbox username (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion [T1497]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LloydLabs/wsb-detect"
	hash = "ccbf7cba35bab56563c0fbe4237fdc41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-sandbox-username.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_afu = /\bGetUserName(A|W)?\b/ ascii wide
	$re_afv = /MALTEST/ nocase ascii wide  // Betabot Username Check
	$re_afw = /TEQUILABOOMBOOM/ nocase ascii wide  // VirusTotal Sandbox
	$re_afx = /SANDBOX/ nocase ascii wide  // Gookit Username Check
	$re_afy = /\bVIRUS/ nocase ascii wide  // Satan Username Check
	$re_afz = /MALWARE/ nocase ascii wide  // Betabot Username Check
	$re_aga = /SAND\sBOX/ nocase ascii wide  // Betabot Username Check
	$re_agb = /Test\sUser/ nocase ascii wide  // Betabot Username Check
	$re_agc = /CurrentUser/ nocase ascii wide  // Gookit Username Check
	$re_agd = /7SILVIA/ nocase ascii wide  // Gookit Username Check
	$re_age = /FORTINET/ nocase ascii wide  // Shifu Username Check
	$re_agf = /John\sDoe/ nocase ascii wide  // Emotet Username Check
	$re_agg = /Emily/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_agh = /HANSPETER\-PC/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_agi = /HAPUBWS/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_agj = /Hong\sLee/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_agk = /IT\-ADMIN/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_agl = /JOHN\-PC/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_agm = /Johnson/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_agn = /Miller/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_ago = /MUELLER\-PC/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_agp = /Peter\sWilson/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_agq = /SystemIT/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_agr = /Timmy/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_ags = /WIN7\-TRAPS/ nocase ascii wide  // Trickbot Downloader Username Check
	$re_agt = /WDAGUtilityAccount/ nocase ascii wide  // Windows Defender Application Guard
 
  condition:
    capa_pe_file and
 (
			$api_afu 
		and  (
			$re_afv 
		or 	$re_afw 
		or 	$re_afx 
		or 	$re_afy 
		or 	$re_afz 
		or 	$re_aga 
		or 	$re_agb 
		or 	$re_agc 
		or 	$re_agd 
		or 	$re_age 
		or 	$re_agf 
		or 	$re_agg 
		or 	$re_agh 
		or 	$re_agi 
		or 	$re_agj 
		or 	$re_agk 
		or 	$re_agl 
		or 	$re_agm 
		or 	$re_agn 
		or 	$re_ago 
		or 	$re_agp 
		or 	$re_agq 
		or 	$re_agr 
		or 	$re_ags 
		or 	$re_agt  
	)  
	) 
}

private rule capa_reference_anti_VM_strings_targeting_Parallels : CAPA T1497_001 B0009  { 
  meta: 
 	description = "reference anti-VM strings targeting Parallels (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Parallels.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-parallels.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_agu = /Parallels/ nocase ascii wide 
	$re_agv = /prl_cc.exe/ nocase ascii wide 
	$re_agw = /prl_tools.exe/ nocase ascii wide 
	$re_agx = /prl hyperv/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_agu 
		or 	$re_agv 
		or 	$re_agw 
		or 	$re_agx  
	) 
}

private rule capa_reference_anti_VM_strings_targeting_VirtualBox : CAPA T1497_001 B0009  { 
  meta: 
 	description = "reference anti-VM strings targeting VirtualBox (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/VirtualBox.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-virtualbox.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_agy = /VBOX/ nocase ascii wide 
	$re_agz = /VEN_VBOX/ nocase ascii wide 
	$re_aha = /VirtualBox/ nocase ascii wide 
	$re_ahb = /06\/23\/99/ nocase ascii wide 
	$re_ahc = /HARDWARE\\ACPI\\DSDT\\VBOX__/ nocase ascii wide 
	$re_ahd = /HARDWARE\\ACPI\\FADT\\VBOX__/ nocase ascii wide 
	$re_ahe = /HARDWARE\\ACPI\\RSDT\\VBOX__/ nocase ascii wide 
	$re_ahf = /SOFTWARE\\Oracle\\VirtualBox Guest Additions/ nocase ascii wide 
	$re_ahg = /SYSTEM\\ControlSet001\\Services\\VBoxGuest/ nocase ascii wide 
	$re_ahh = /SYSTEM\\ControlSet001\\Services\\VBoxMouse/ nocase ascii wide 
	$re_ahi = /SYSTEM\\ControlSet001\\Services\\VBoxService/ nocase ascii wide 
	$re_ahj = /SYSTEM\\ControlSet001\\Services\\VBoxSF/ nocase ascii wide 
	$re_ahk = /SYSTEM\\ControlSet001\\Services\\VBoxVideo/ nocase ascii wide 
	$re_ahl = /VBoxMouse.sys/ nocase ascii wide 
	$re_ahm = /VBoxGuest.sys/ nocase ascii wide 
	$re_ahn = /VBoxSF.sys/ nocase ascii wide 
	$re_aho = /VBoxVideo.sys/ nocase ascii wide 
	$re_ahp = /vboxdisp.dll/ nocase ascii wide 
	$re_ahq = /vboxhook.dll/ nocase ascii wide 
	$re_ahr = /vboxmrxnp.dll/ nocase ascii wide 
	$re_ahs = /vboxogl.dll/ nocase ascii wide 
	$re_aht = /vboxoglarrayspu.dll/ nocase ascii wide 
	$re_ahu = /vboxoglcrutil.dll/ nocase ascii wide 
	$re_ahv = /vboxoglerrorspu.dll/ nocase ascii wide 
	$re_ahw = /vboxoglfeedbackspu.dll/ nocase ascii wide 
	$re_ahx = /vboxoglpackspu.dll/ nocase ascii wide 
	$re_ahy = /vboxoglpassthroughspu.dll/ nocase ascii wide 
	$re_ahz = /vboxservice.exe/ nocase ascii wide 
	$re_aia = /vboxtray.exe/ nocase ascii wide 
	$re_aib = /VBoxControl.exe/ nocase ascii wide 
	$re_aic = /oracle\\virtualbox guest additions\\/ nocase ascii wide 
	$re_aid = /\\\\.\\VBoxMiniRdrDN/ nocase ascii wide 
	$re_aie = /\\\\.\\VBoxGuest/ nocase ascii wide 
	$re_aif = /\\\\.\\pipe\\VBoxMiniRdDN/ nocase ascii wide 
	$re_aig = /\\\\.\\VBoxTrayIPC/ nocase ascii wide 
	$re_aih = /\\\\.\\pipe\\VBoxTrayIPC/ nocase ascii wide 
	$re_aii = /VBoxTrayToolWndClass/ nocase ascii wide 
	$re_aij = /VBoxTrayToolWnd/ nocase ascii wide 
	$re_aik = /vboxservice.exe/ nocase ascii wide 
	$re_ail = /vboxtray.exe/ nocase ascii wide 
	$re_aim = /vboxvideo/ nocase ascii wide 
	$re_ain = /VBoxVideoW8/ nocase ascii wide 
	$re_aio = /VBoxWddm/ nocase ascii wide 
	$re_aip = /PCI\\VEN_80EE&DEV_CAFE/ nocase ascii wide 
	$re_aiq = /82801FB/ nocase ascii wide 
	$re_air = /82441FX/ nocase ascii wide 
	$re_ais = /82371SB/ nocase ascii wide 
	$re_ait = /OpenHCD/ nocase ascii wide 
	$re_aiu = /ACPIBus_BUS_0/ nocase ascii wide 
	$re_aiv = /PCI_BUS_0/ nocase ascii wide 
	$re_aiw = /PNP_BUS_0/ nocase ascii wide 
	$re_aix = /Oracle Corporation/ nocase ascii wide 
	$re_aiy = /VBoxWdd/ nocase ascii wide 
	$re_aiz = /VBoxS/ nocase ascii wide  // VirtualBox Shared Folders
	$re_aja = /VBoxMouse/ nocase ascii wide  // VirtualBox Guest Mouse
	$re_ajb = /VBoxGuest/ nocase ascii wide  // VirtualBox Guest Driver
	$re_ajc = /VBoxVBoxVBox/ nocase ascii wide 
	$re_ajd = /innotek GmbH/ nocase ascii wide 
	$re_aje = /drivers\\vboxdrv/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_agy 
		or 	$re_agz 
		or 	$re_aha 
		or 	$re_ahb 
		or 	$re_ahc 
		or 	$re_ahd 
		or 	$re_ahe 
		or 	$re_ahf 
		or 	$re_ahg 
		or 	$re_ahh 
		or 	$re_ahi 
		or 	$re_ahj 
		or 	$re_ahk 
		or 	$re_ahl 
		or 	$re_ahm 
		or 	$re_ahn 
		or 	$re_aho 
		or 	$re_ahp 
		or 	$re_ahq 
		or 	$re_ahr 
		or 	$re_ahs 
		or 	$re_aht 
		or 	$re_ahu 
		or 	$re_ahv 
		or 	$re_ahw 
		or 	$re_ahx 
		or 	$re_ahy 
		or 	$re_ahz 
		or 	$re_aia 
		or 	$re_aib 
		or 	$re_aic 
		or 	$re_aid 
		or 	$re_aie 
		or 	$re_aif 
		or 	$re_aig 
		or 	$re_aih 
		or 	$re_aii 
		or 	$re_aij 
		or 	$re_aik 
		or 	$re_ail 
		or 	$re_aim 
		or 	$re_ain 
		or 	$re_aio 
		or 	$re_aip 
		or 	$re_aiq 
		or 	$re_air 
		or 	$re_ais 
		or 	$re_ait 
		or 	$re_aiu 
		or 	$re_aiv 
		or 	$re_aiw 
		or 	$re_aix 
		or 	$re_aiy 
		or 	$re_aiz 
		or 	$re_aja 
		or 	$re_ajb 
		or 	$re_ajc 
		or 	$re_ajd 
		or 	$re_aje  
	) 
}

private rule capa_check_for_windows_sandbox_via_registry : CAPA T1497_001 B0009  { 
  meta: 
 	description = "check for windows sandbox via registry (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LloydLabs/wsb-detect"
	hash = "773290480d5445f11d3dc1b800728966"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-registry.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_ajf = /\bRegOpenKeyEx(A|W)?\b/ ascii wide
	$api_ajg = /\bRegEnumValue(A|W)?\b/ ascii wide
	$re_ajh = /\\Microsoft\\Windows\\CurrentVersion\\RunOnce/ ascii wide 
	$re_aji = /wmic useraccount where \"name='WDAGUtilityAccount'\"/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$api_ajf 
		and 	$api_ajg 
		and 	$re_ajh 
		and 	$re_aji  
	) 
}

private rule capa_reference_anti_VM_strings_targeting_Xen : CAPA T1497_001 B0009  { 
  meta: 
 	description = "reference anti-VM strings targeting Xen (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Xen.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-xen.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_ajj = /\bXen/ nocase ascii wide 
	$re_ajk = /XenVMMXenVMM/ nocase ascii wide 
	$re_ajl = /xenservice.exe/ nocase ascii wide 
	$re_ajm = /XenVMMXenVMM/ nocase ascii wide 
	$re_ajn = /HVM domU/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_ajj 
		or 	$re_ajk 
		or 	$re_ajl 
		or 	$re_ajm 
		or 	$re_ajn  
	) 
}

private rule capa_reference_anti_VM_strings : CAPA T1497_001 B0009  { 
  meta: 
 	description = "reference anti-VM strings (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/ctxis/CAPE/blob/master/modules/signatures/antivm_*"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Generic.cpp"
	hash = "Practical Malware Analysis Lab 17-02.dll_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_ajo = /HARDWARE\\ACPI\\(DSDT|FADT|RSDT)\\BOCHS/ nocase ascii wide 
	$re_ajp = /HARDWARE\\DESCRIPTION\\System\\(SystemBiosVersion|VideoBiosVersion)/ nocase ascii wide 
	$re_ajq = /HARDWARE\\DESCRIPTION\\System\\CentralProcessor/ nocase ascii wide 
	$re_ajr = /HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0/ nocase ascii wide 
	$re_ajs = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Enum\\IDE/ nocase ascii wide 
	$re_ajt = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Services\\Disk\\Enum\\/ nocase ascii wide 
	$re_aju = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Control\\SystemInformation\\SystemManufacturer/ nocase ascii wide 
	$re_ajv = /A M I/ nocase ascii wide 
	$re_ajw = /Hyper-V/ nocase ascii wide 
	$re_ajx = /Kernel-VMDetection-Private/ nocase ascii wide 
	$re_ajy = /KVMKVMKVM/ nocase ascii wide  // KVM
	$re_ajz = /Microsoft Hv/ nocase ascii wide  // Microsoft Hyper-V or Windows Virtual PC
	$re_aka = /avghookx.dll/ nocase ascii wide  // AVG
	$re_akb = /avghooka.dll/ nocase ascii wide  // AVG
	$re_akc = /snxhk.dll/ nocase ascii wide  // Avast
	$re_akd = /pstorec.dll/ nocase ascii wide  // SunBelt Sandbox
	$re_ake = /vmcheck.dll/ nocase ascii wide  // Virtual PC
	$re_akf = /wpespy.dll/ nocase ascii wide  // WPE Pro
	$re_akg = /cmdvrt64.dll/ nocase ascii wide  // Comodo Container
	$re_akh = /cmdvrt32.dll/ nocase ascii wide  // Comodo Container
	$re_aki = /sample.exe/ nocase ascii wide 
	$re_akj = /bot.exe/ nocase ascii wide 
	$re_akk = /sandbox.exe/ nocase ascii wide 
	$re_akl = /malware.exe/ nocase ascii wide 
	$re_akm = /test.exe/ nocase ascii wide 
	$re_akn = /klavme.exe/ nocase ascii wide 
	$re_ako = /myapp.exe/ nocase ascii wide 
	$re_akp = /testapp.exe/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_ajo 
		or 	$re_ajp 
		or 	$re_ajq 
		or 	$re_ajr 
		or 	$re_ajs 
		or 	$re_ajt 
		or 	$re_aju 
		or 	$re_ajv 
		or 	$re_ajw 
		or 	$re_ajx 
		or 	$re_ajy 
		or 	$re_ajz 
		or 	$re_aka 
		or 	$re_akb 
		or 	$re_akc 
		or 	$re_akd 
		or 	$re_ake 
		or 	$re_akf 
		or 	$re_akg 
		or 	$re_akh 
		or 	$re_aki 
		or 	$re_akj 
		or 	$re_akk 
		or 	$re_akl 
		or 	$re_akm 
		or 	$re_akn 
		or 	$re_ako 
		or 	$re_akp  
	) 
}

private rule capa_reference_anti_VM_strings_targeting_Qemu : CAPA T1497_001 B0009  { 
  meta: 
 	description = "reference anti-VM strings targeting Qemu (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Qemu.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-qemu.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_akq = /Qemu/ nocase ascii wide 
	$re_akr = /qemu-ga.exe/ nocase ascii wide 
	$re_aks = /BOCHS/ nocase ascii wide 
	$re_akt = /BXPC/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_akq 
		or 	$re_akr 
		or 	$re_aks 
		or 	$re_akt  
	) 
}

private rule capa_reference_anti_VM_strings_targeting_VirtualPC : CAPA T1497_001 B0009  { 
  meta: 
 	description = "reference anti-VM strings targeting VirtualPC (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/VirtualPC.cpp"
	hash = "al-khaser_x86.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-virtualpc.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_aku = /VirtualPC/ nocase ascii wide 
	$re_akv = /VMSrvc.exe/ nocase ascii wide 
	$re_akw = /VMUSrvc.exe/ nocase ascii wide 
	$re_akx = /SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_aku 
		or 	$re_akv 
		or 	$re_akw 
		or 	$re_akx  
	) 
}

private rule capa_check_if_process_is_running_under_wine : CAPA T1497_001 B0004  { 
  meta: 
 	description = "check if process is running under wine (converted from capa rule)"
	namespace = "anti-analysis/anti-emulation/wine"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Emulator Detection [B0004]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Wine.cpp"
	hash = "ccbf7cba35bab56563c0fbe4237fdc41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-emulation/wine/check-if-process-is-running-under-wine.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_aky = /SOFTWARE\\Wine/ nocase ascii wide 
	$api_akz = /\bGetModuleHandle(A|W)?\b/ ascii wide
	$api_ala = /\bGetProcAddress(A|W)?\b/ ascii wide
	$str_alb = "wine_get_unix_file_name" ascii wide
	$str_alc = "kernel32.dll" ascii wide
	$str_ald = "ntdll.dll" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_aky 
		or  (
			$api_akz 
		and 	$api_ala 
		and 	$str_alb 
		and  (
			$str_alc 
		or 	$str_ald  
	)  
	)  
	) 
}

private rule capa_check_for_debugger_via_API : CAPA B0001_002 B0001_031  { 
  meta: 
 	description = "check for debugger via API (converted from capa rule)"
	namespace = "anti-analysis/anti-debugging/debugger-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Anti-Behavioral Analysis::Debugger Detection::CheckRemoteDebuggerPresent [B0001.002]"
	mbc = "Anti-Behavioral Analysis::Debugger Detection::WudfIsAnyDebuggerPresent [B0001.031]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/CheckRemoteDebuggerPresent.cpp"
	hash = "al-khaser_x86.exe_:0x420000"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-debugging/debugger-detection/check-for-debugger-via-api.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /CheckRemoteDebuggerPresent/) 
		or 	pe.imports(/wudfplatform/i, /WudfIsAnyDebuggerPresent/) 
		or 	pe.imports(/wudfplatform/i, /WudfIsKernelDebuggerPresent/) 
		or 	pe.imports(/wudfplatform/i, /WudfIsUserDebuggerPresent/)  
	) 
}

private rule capa_check_for_OutputDebugString_error : CAPA B0001_016  { 
  meta: 
 	description = "check for OutputDebugString error (converted from capa rule)"
	namespace = "anti-analysis/anti-debugging/debugger-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	mbc = "Anti-Behavioral Analysis::Debugger Detection::OutputDebugString [B0001.016]"
	hash = "Practical Malware Analysis Lab 16-02.exe_:0x401020"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-debugging/debugger-detection/check-for-outputdebugstring-error.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /SetLastError/) 
		and 	pe.imports(/kernel32/i, /GetLastError/) 
		and 	pe.imports(/kernel32/i, /OutputDebugString/)  
	) 
}

private rule capa_contains_PDB_path : CAPA  { 
  meta: 
 	description = "contains PDB path (converted from capa rule)"
	namespace = "executable/pe/pdb"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	hash = "464EF2CA59782CE697BC329713698CCC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/pe/pdb/contains-pdb-path.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 
		$re_alf = /:\\.{,1000}\.pdb/ ascii wide 
 
  condition:
    capa_pe_file and

		$re_alf 
}

private rule capa_contain_a_resource___rsrc__section : CAPA  { 
  meta: 
 	description = "contain a resource (.rsrc) section (converted from capa rule)"
	namespace = "executable/pe/section/rsrc"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	hash = "A933A1A402775CFA94B6BEE0963F4B46"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/pe/section/rsrc/contain-a-resource-rsrc-section.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and

		for any alg in pe.sections : ( alg.name == ".rsrc" ) 
}

private rule capa_contain_a_thread_local_storage___tls__section : CAPA  { 
  meta: 
 	description = "contain a thread local storage (.tls) section (converted from capa rule)"
	namespace = "executable/pe/section/tls"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	hash = "Practical Malware Analysis Lab 16-02.exe_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/pe/section/tls/contain-a-thread-local-storage-tls-section.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and

		for any alh in pe.sections : ( alh.name == ".tls" ) 
}

private rule capa_extract_resource_via_kernel32_functions : CAPA  { 
  meta: 
 	description = "extract resource via kernel32 functions (converted from capa rule)"
	namespace = "executable/resource"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	hash = "BF88E1BD4A3BDE10B419A622278F1FF7"
	hash = "Practical Malware Analysis Lab 01-04.exe_:0x4011FC"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/resource/extract-resource-via-kernel32-functions.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_ali = /\bLdrAccessResource(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
		 (
			pe.imports(/kernel32/i, /LoadResource/) 
		or 	pe.imports(/kernel32/i, /LockResource/) 
		or 	$api_ali  
	)  
	) 
		or 	pe.imports(/user32/i, /LoadString/)  
	) 
}

private rule capa_packaged_as_an_IExpress_self_extracting_archive : CAPA  { 
  meta: 
 	description = "packaged as an IExpress self-extracting archive (converted from capa rule)"
	namespace = "executable/installer/iexpress"
	author = "@recvfrom"
	scope = "file"
	references = "https://en.wikipedia.org/wiki/IExpress"
	hash = "ac742739cae0d411dfcb78ae99a7baee"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/installer/iexpress/packaged-as-an-iexpress-self-extracting-archive.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_alj = "wextract_cleanup%d" ascii wide
	$str_alk = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
	$str_all = "  <description>IExpress extraction tool</description>" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$str_alj 
		and 	$str_alk  
	) 
		or 	$str_all  
	) 
}

private rule capa_create_thread : CAPA C0038  { 
  meta: 
 	description = "create thread (converted from capa rule)"
	namespace = "host-interaction/thread/create"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	mbc = "Process::Create Thread [C0038]"
	hash = "946A99F36A46D335DEC080D9A4371940"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/thread/create/create-thread.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_alm = /\b_beginthread(A|W)?\b/ ascii wide
	$api_aln = /\b_beginthreadex(A|W)?\b/ ascii wide
	$api_alo = /\bPsCreateSystemThread(A|W)?\b/ ascii wide
	$api_alp = /\bSHCreateThread(A|W)?\b/ ascii wide
	$api_alq = /\bSHCreateThreadWithHandle(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /CreateThread/) 
		or 	$api_alm 
		or 	$api_aln 
		or 	$api_alo 
		or 	$api_alp 
		or 	$api_alq 
		or 	pe.imports(/kernel32/i, /CreateRemoteThread/) 
		or 	pe.imports(/kernel32/i, /CreateRemoteThreadEx/) 
		or 	pe.imports(/ntdll/i, /RtlCreateUserThread/) 
		or 	pe.imports(/ntdll/i, /NtCreateThread/) 
		or 	pe.imports(/ntdll/i, /NtCreateThreadEx/) 
		or 	pe.imports(/ntdll/i, /ZwCreateThread/) 
		or 	pe.imports(/ntdll/i, /ZwCreateThreadEx/)  
	) 
}

private rule capa_resume_thread : CAPA C0054  { 
  meta: 
 	description = "resume thread (converted from capa rule)"
	namespace = "host-interaction/thread/resume"
	author = "0x534a@mailbox.org"
	scope = "basic block"
	mbc = "Process::Resume Thread [C0054]"
	hash = "Practical Malware Analysis Lab 12-02.exe_:0x4010EA"
	hash = "787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/thread/resume/resume-thread.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /ResumeThread/) 
		or 	pe.imports(/ntdll/i, /NtResumeThread/) 
		or 	pe.imports(/ntdll/i, /ZwResumeThread/)  
	) 
}

private rule capa_suspend_thread : CAPA C0055  { 
  meta: 
 	description = "suspend thread (converted from capa rule)"
	namespace = "host-interaction/thread/suspend"
	author = "0x534a@mailbox.org"
	scope = "basic block"
	mbc = "Process::Suspend Thread [C0055]"
	hash = "787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/thread/suspend/suspend-thread.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /SuspendThread/) 
		or 	pe.imports(/ntdll/i, /NtSuspendThread/) 
		or 	pe.imports(/ntdll/i, /ZwSuspendThread/)  
	) 
}

private rule capa_terminate_thread : CAPA C0039  { 
  meta: 
 	description = "terminate thread (converted from capa rule)"
	namespace = "host-interaction/thread/terminate"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	mbc = "Process::Terminate Thread [C0039]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10003286"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/thread/terminate/terminate-thread.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_alr = /\bPsTerminateSystemThread(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /TerminateThread/) 
		or 	$api_alr  
	) 
}

private rule capa_manipulate_console : CAPA C0033  { 
  meta: 
 	description = "manipulate console (converted from capa rule)"
	namespace = "host-interaction/console"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	mbc = "Operating System::Console [C0033]"
	references = "https://stackoverflow.com/a/15770935/87207"
	hash = "3aa7ee4d67f562933bc998f352b1f319"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/console/manipulate-console.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/kernel32/i, /SetConsoleCursorPosition/) 
		or 	pe.imports(/kernel32/i, /ReadConsoleOutputCharacter/) 
		or 	pe.imports(/kernel32/i, /WriteConsoleOutputCharacter/) 
		or 	pe.imports(/kernel32/i, /WriteConsoleOutput/) 
		or 	pe.imports(/kernel32/i, /WriteConsoleInput/)  
	)  
	) 
}

private rule capa_access_firewall_settings_via_INetFwMgr : CAPA T1518_001 T1562_004  { 
  meta: 
 	description = "access firewall settings via INetFwMgr (converted from capa rule)"
	namespace = "host-interaction/firewall/modify"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::Software Discovery::Security Software Discovery [T1518.001]"
	attack = "Defense Evasion::Impair Defenses::Disable or Modify System Firewall [T1562.004]"
	hash = "EB355BD63BDDCE02955792B4CD6539FB"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/firewall/modify/access-firewall-settings-via-inetfwmgr.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$als = { 42 E9 4C 30 39 6E D8 40 94 3A B9 13 C4 0C 9C D4 } // CLSID_NetFwMgr
	$alt = { F5 8A 89 F7 C4 CA 32 46 A2 EC DA 06 E5 11 1A F2 } // IID_INetFwMgr
 
  condition:
    capa_pe_file and
 (
			pe.imports(/ole32/i, /CoCreateInstance/) 
		and 	$als 
		and 	$alt  
	) 
}

private rule capa_start_minifilter_driver : CAPA  { 
  meta: 
 	description = "start minifilter driver (converted from capa rule)"
	namespace = "host-interaction/filter"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	references = "https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/filter/start-minifilter-driver.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_alu = /\bFltStartFiltering(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_alu  
	) 
}

private rule capa_register_minifilter_driver : CAPA  { 
  meta: 
 	description = "register minifilter driver (converted from capa rule)"
	namespace = "host-interaction/filter"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	references = "https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/filter/register-minifilter-driver.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_alv = /\bFltRegisterFilter(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_alv  
	) 
}

private rule capa_get_common_file_path : CAPA T1083  { 
  meta: 
 	description = "get common file path (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::File and Directory Discovery [T1083]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10003415"
	hash = "972B219F18379907A045431303F4DA7D"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/get-common-file-path.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_alw = /\bGetAllUsersProfileDirectory(A|W)?\b/ ascii wide
	$api_alx = /\bGetAppContainerFolderPath(A|W)?\b/ ascii wide
	$api_aly = /\bGetCurrentDirectory(A|W)?\b/ ascii wide
	$api_alz = /\bGetDefaultUserProfileDirectory(A|W)?\b/ ascii wide
	$api_ama = /\bGetProfilesDirectory(A|W)?\b/ ascii wide
	$api_amb = /\bGetUserProfileDirectory(A|W)?\b/ ascii wide
	$api_amc = /\bSHGetFolderPathAndSubDir(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /GetTempPath/) 
		or 	pe.imports(/kernel32/i, /GetTempFileName/) 
		or 	pe.imports(/kernel32/i, /GetSystemDirectory/) 
		or 	pe.imports(/kernel32/i, /GetWindowsDirectory/) 
		or 	pe.imports(/kernel32/i, /GetSystemWow64Directory/) 
		or 	$api_alw 
		or 	$api_alx 
		or 	$api_aly 
		or 	$api_alz 
		or 	$api_ama 
		or 	$api_amb 
		or 	$api_amc 
		or 	pe.imports(/shell32/i, /SHGetFolderPath/) 
		or 	pe.imports(/shell32/i, /SHGetFolderLocation/) 
		or 	pe.imports(/shell32/i, /SHGetSpecialFolderPath/) 
		or 	pe.imports(/shell32/i, /SHGetSpecialFolderLocation/)  
	) 
}

private rule capa_bypass_Mark_of_the_Web : CAPA T1553_005  { 
  meta: 
 	description = "bypass Mark of the Web (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Subvert Trust Controls::Mark-of-the-Web Bypass [T1553.005]"
	hash = "48c7ad2d9d482cb11898f2719638ceed"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/bypass-mark-of-the-web.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_amd = /\bDeleteFile(A|W)?\b/ ascii wide
	$str_ame = ":Zone.Identifier" ascii wide // NTFS ADS name recognized by Windows Defender SmartScreen
	$str_amf = "%s:Zone.Identifier" ascii wide // NTFS ADS name recognized by Windows Defender SmartScreen
 
  condition:
    capa_pe_file and
 (
			$api_amd 
		and  (
			$str_ame 
		or 	$str_amf  
	)  
	) 
}

private rule capa_get_file_system_object_information : CAPA T1083  { 
  meta: 
 	description = "get file system object information (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Discovery::File and Directory Discovery [T1083]"
	hash = "50D5EE1CE2CA5E30C6B1019EE64EEEC2"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/get-file-system-object-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_amg = /\bSHGetFileInfo(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_amg  
	) 
}

private rule capa_delete_directory : CAPA C0048  { 
  meta: 
 	description = "delete directory (converted from capa rule)"
	namespace = "host-interaction/file-system/delete"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "File System::Delete Directory [C0048]"
	hash = "Practical Malware Analysis Lab 05-01.dll_:0x10009236"
	hash = "AFB6EC3D721A5CB67863487B0E51A34C167F629CF701F8BC7A038C117B4DDA44"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/delete/delete-directory.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_amm = /\bRemoveDirectory(A|W)?\b/ ascii wide
	$api_amn = /\bRemoveDirectoryTransacted(A|W)?\b/ ascii wide
	$api_amo = /\b_rmdir(A|W)?\b/ ascii wide
	$api_amp = /\b_wrmdir(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_amm 
		or 	$api_amn 
		or 	$api_amo 
		or 	$api_amp  
	) 
}

private rule capa_create_directory : CAPA C0046  { 
  meta: 
 	description = "create directory (converted from capa rule)"
	namespace = "host-interaction/file-system/create"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "File System::Create Directory [C0046]"
	hash = "Practical Malware Analysis Lab 17-02.dll_:0x10008f62"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/create/create-directory.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_amq = /\bNtCreateDirectoryObject(A|W)?\b/ ascii wide
	$api_amr = /\bZwCreateDirectoryObject(A|W)?\b/ ascii wide
	$api_ams = /\bSHCreateDirectory(A|W)?\b/ ascii wide
	$api_amt = /\bSHCreateDirectoryEx(A|W)?\b/ ascii wide
	$api_amu = /\b_mkdir(A|W)?\b/ ascii wide
	$api_amv = /\b_wmkdir(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /CreateDirectory/) 
		or 	pe.imports(/kernel32/i, /CreateDirectoryEx/) 
		or 	pe.imports(/kernel32/i, /CreateDirectoryTransacted/) 
		or 	$api_amq 
		or 	$api_amr 
		or 	$api_ams 
		or 	$api_amt 
		or 	$api_amu 
		or 	$api_amv  
	) 
}

private rule capa_write_file : CAPA C0052  { 
  meta: 
 	description = "write file (converted from capa rule)"
	namespace = "host-interaction/file-system/write"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	mbc = "File System::Writes File [C0052]"
	hash = "Practical Malware Analysis Lab 01-04.exe_:0x4011FC"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/write/write-file.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_amw = /\bNtWriteFile(A|W)?\b/ ascii wide
	$api_amx = /\bZwWriteFile(A|W)?\b/ ascii wide
	$api_amy = /\b_fwrite(A|W)?\b/ ascii wide
	$api_amz = /\bfwrite(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/kernel32/i, /WriteFile/) 
		or 	pe.imports(/kernel32/i, /WriteFileEx/) 
		or 	$api_amw 
		or 	$api_amx 
		or 	$api_amy 
		or 	$api_amz  
	)  
	) 
}

private rule capa_get_file_attributes : CAPA C0049  { 
  meta: 
 	description = "get file attributes (converted from capa rule)"
	namespace = "host-interaction/file-system/meta"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	mbc = "File System::Get File Attributes [C0049]"
	hash = "03B236B23B1EC37C663527C1F53AF3FE"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/meta/get-file-attributes.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_ana = /\bZwQueryDirectoryFile(A|W)?\b/ ascii wide
	$api_anb = /\bZwQueryInformationFile(A|W)?\b/ ascii wide
	$api_anc = /\bNtQueryDirectoryFile(A|W)?\b/ ascii wide
	$api_and = /\bNtQueryInformationFile(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /GetFileAttributes/) 
		or 	$api_ana 
		or 	$api_anb 
		or 	$api_anc 
		or 	$api_and  
	) 
}

private rule capa_set_file_attributes : CAPA T1222 C0050  { 
  meta: 
 	description = "set file attributes (converted from capa rule)"
	namespace = "host-interaction/file-system/meta"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Defense Evasion::File and Directory Permissions Modification [T1222]"
	mbc = "File System::Set File Attributes [C0050]"
	hash = "946A99F36A46D335DEC080D9A4371940"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/meta/set-file-attributes.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_ane = /\bZwSetInformationFile(A|W)?\b/ ascii wide
	$api_anf = /\bNtSetInformationFile(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /SetFileAttributes/) 
		or 	$api_ane 
		or 	$api_anf  
	) 
}

private rule capa_read_virtual_disk : CAPA C0056  { 
  meta: 
 	description = "read virtual disk (converted from capa rule)"
	namespace = "host-interaction/file-system/read"
	author = "@_re_fox"
	scope = "function"
	mbc = "File System::Read Virtual Disk [C0056]"
	references = "https://github.com/vxunderground/VXUG-Papers/blob/main/Weaponizing%20Windows%20Virtualization/src.cpp"
	references = "https://github.com/vxunderground/VXUG-Papers/blob/main/Weaponizing%20Windows%20Virtualization/WeaponizingWindowsVirtualization.pdf"
	hash = "3265b2b0afc6d2ad0bdd55af8edb9b37"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/read/read-virtual-disk.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_anh = /\bOpenVirtualDisk(A|W)?\b/ ascii wide
	$api_ani = /\bAttachVirtualDisk(A|W)?\b/ ascii wide
	$api_anj = /\bGetVirtualDiskPhysicalPath(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_anh 
		and 	$api_ani 
		and 	$api_anj  
	) 
}

private rule capa_read_file : CAPA C0051  { 
  meta: 
 	description = "read file (converted from capa rule)"
	namespace = "host-interaction/file-system/read"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "File System::Read File [C0051]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/read/read-file.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_ank = /\bReadFileEx(A|W)?\b/ ascii wide
	$api_anl = /\bNtReadFile(A|W)?\b/ ascii wide
	$api_anm = /\bZwReadFile(A|W)?\b/ ascii wide
	$api_ann = /\b_read(A|W)?\b/ ascii wide
	$api_ano = /\bfread(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
		 (
			pe.imports(/kernel32/i, /ReadFile/) 
		or 	$api_ank 
		or 	$api_anl 
		or 	$api_anm 
		or 	$api_ann 
		or 	$api_ano  
	)  
	)  
	) 
}

private rule capa_read__ini_file : CAPA C0051  { 
  meta: 
 	description = "read .ini file (converted from capa rule)"
	namespace = "host-interaction/file-system/read"
	author = "@_re_fox"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "File System::Read File [C0051]"
	hash = "1d8fd13c890060464019c0f07b928b1a"
	hash = "E6234FB98F17201C232F4502015B47B3"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/read/read-ini-file.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_anp = /\bGetPrivateProfileInt(A|W)?\b/ ascii wide
	$api_anq = /\bGetPrivateProfileString(A|W)?\b/ ascii wide
	$api_anr = /\bGetPrivateProfileStruct(A|W)?\b/ ascii wide
	$api_ans = /\bGetPrivateProfileSection(A|W)?\b/ ascii wide
	$api_ant = /\bGetPrivateProfileSectionNames(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$api_anp 
		or 	$api_anq 
		or 	$api_anr 
		or 	$api_ans 
		or 	$api_ant  
	)  
	) 
}

private rule capa_enumerate_files_via_kernel32_functions : CAPA T1083  { 
  meta: 
 	description = "enumerate files via kernel32 functions (converted from capa rule)"
	namespace = "host-interaction/file-system/files/list"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::File and Directory Discovery [T1083]"
	hash = "Practical Malware Analysis Lab 01-01.exe_:0x4011E0"
	hash = "Practical Malware Analysis Lab 20-02.exe_:0x401000"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/files/list/enumerate-files-via-kernel32-functions.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/kernel32/i, /FindFirstFile/) 
		or 	pe.imports(/kernel32/i, /FindFirstFileEx/) 
		or 	pe.imports(/kernel32/i, /FindFirstFileTransacted/) 
		or 	pe.imports(/kernel32/i, /FindFirstFileName/) 
		or 	pe.imports(/kernel32/i, /FindFirstFileNameTransacted/)  
	) 
		and  (
			pe.imports(/kernel32/i, /FindNextFile/) 
		or 	pe.imports(/kernel32/i, /FindNextFileName/)  
	)  
	) 
}

private rule capa_shutdown_system : CAPA T1529  { 
  meta: 
 	description = "shutdown system (converted from capa rule)"
	namespace = "host-interaction/os"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Impact::System Shutdown/Reboot [T1529]"
	hash = "39C05B15E9834AC93F206BC114D0A00C357C888DB567BA8F5345DA0529CBED41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/os/shutdown-system.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/user32/i, /ExitWindowsEx/) 
		or 	pe.imports(/user32/i, /ExitWindows/)  
	) 
}

private rule capa_get_system_information : CAPA T1082  { 
  meta: 
 	description = "get system information (converted from capa rule)"
	namespace = "host-interaction/os/info"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/os/info/get-system-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_anw = /\bNtQuerySystemInformation(A|W)?\b/ ascii wide
	$api_anx = /\bNtQuerySystemInformationEx(A|W)?\b/ ascii wide
	$api_any = /\bZwQuerySystemInformation(A|W)?\b/ ascii wide
	$api_anz = /\bZwQuerySystemInformationEx(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /GetSystemInfo/) 
		or 	pe.imports(/kernel32/i, /GetNativeSystemInfo/) 
		or 	$api_anw 
		or 	$api_anx 
		or 	pe.imports(/ntdll/i, /RtlGetNativeSystemInformation/) 
		or 	$api_any 
		or 	$api_anz  
	) 
}

private rule capa_get_hostname : CAPA T1082  { 
  meta: 
 	description = "get hostname (converted from capa rule)"
	namespace = "host-interaction/os/hostname"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/os/hostname/get-hostname.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aof = /\bGetComputerObjectName(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /GetComputerName/) 
		or 	pe.imports(/kernel32/i, /GetComputerNameEx/) 
		or 	$api_aof 
		or 	pe.imports(/ws2_32/i, /gethostname/)  
	) 
}

private rule capa_query_service_status : CAPA T1007  { 
  meta: 
 	description = "query service status (converted from capa rule)"
	namespace = "host-interaction/service"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Service Discovery [T1007]"
	hash = "9DC209F66DA77858E362E624D0BE86B3"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/query-service-status.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /QueryServiceStatusEx/) 
		or 	pe.imports(/advapi32/i, /QueryServiceStatus/)  
	) 
}

private rule capa_delete_service : CAPA T1543_003  { 
  meta: 
 	description = "delete service (converted from capa rule)"
	namespace = "host-interaction/service/delete"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	hash = "E544A4D616B60147D9774B48C2B65EF2"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10004B18"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/delete/delete-service.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /DeleteService/)  
	) 
}

private rule capa_enumerate_services : CAPA T1007  { 
  meta: 
 	description = "enumerate services (converted from capa rule)"
	namespace = "host-interaction/service/list"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Service Discovery [T1007]"
	hash = "Practical Malware Analysis Lab 05-01.dll_:0x1000B823"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/list/enumerate-services.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /EnumServicesStatus/) 
		or 	pe.imports(/advapi32/i, /EnumServicesStatusEx/)  
	) 
}

private rule capa_create_service : CAPA T1543_003 T1569_002  { 
  meta: 
 	description = "create service (converted from capa rule)"
	namespace = "host-interaction/service/create"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	attack = "Execution::System Services::Service Execution [T1569.002]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10004706"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/create/create-service.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /CreateService/)  
	) 
}

private rule capa_modify_service : CAPA T1543_003 T1569_002  { 
  meta: 
 	description = "modify service (converted from capa rule)"
	namespace = "host-interaction/service/modify"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	attack = "Execution::System Services::Service Execution [T1569.002]"
	hash = "7D16EFD0078F22C17A4BD78B0F0CC468"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/modify/modify-service.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/advapi32/i, /ChangeServiceConfig/) 
		or 	pe.imports(/advapi32/i, /ChangeServiceConfig2/)  
	)  
	) 
}

private rule capa_start_service : CAPA T1543_003  { 
  meta: 
 	description = "start service (converted from capa rule)"
	namespace = "host-interaction/service/start"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	hash = "E544A4D616B60147D9774B48C2B65EF2"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/start/start-service.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /StartService/)  
	) 
}

private rule capa_get_number_of_processor_cores : CAPA T1082  { 
  meta: 
 	description = "get number of processor cores (converted from capa rule)"
	namespace = "host-interaction/hardware/cpu"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Generic.cpp#L207"
	hash = "al-khaser_x86.exe_:0x435BA0"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/cpu/get-number-of-processor-cores.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_aog = /SELECT\s+\*\s+FROM\s+Win32_Processor/ ascii wide 
	$str_aoh = "NumberOfCores" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_aog 
		and 	$str_aoh  
	) 
}

private rule capa_get_disk_information : CAPA T1082  { 
  meta: 
 	description = "get disk information (converted from capa rule)"
	namespace = "host-interaction/hardware/storage"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	hash = "972B219F18379907A045431303F4DA7D"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/storage/get-disk-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /GetDriveType/) 
		or 	pe.imports(/kernel32/i, /GetLogicalDrives/) 
		or 	pe.imports(/kernel32/i, /GetVolumeInformation/) 
		or 	pe.imports(/kernel32/i, /GetVolumeNameForVolumeMountPoint/) 
		or 	pe.imports(/kernel32/i, /GetVolumePathNamesForVolumeName/) 
		or 	pe.imports(/kernel32/i, /GetLogicalDriveStrings/) 
		or 	pe.imports(/kernel32/i, /QueryDosDevice/)  
	) 
}

private rule capa_manipulate_CD_ROM_drive : CAPA B0042_001  { 
  meta: 
 	description = "manipulate CD-ROM drive (converted from capa rule)"
	namespace = "host-interaction/hardware/cdrom"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Impact::Modify Hardware::CDROM [B0042.001]"
	hash = "39C05B15E9834AC93F206BC114D0A00C357C888DB567BA8F5345DA0529CBED41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/cdrom/manipulate-cd-rom-drive.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_aoi = "set cdaudio door closed wait" ascii wide
	$str_aoj = "set cdaudio door open" ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/winmm/i, /mciSendString/) 
		and  (
			$str_aoi 
		or 	$str_aoj  
	)  
	) 
}

private rule capa_get_memory_capacity : CAPA T1082  { 
  meta: 
 	description = "get memory capacity (converted from capa rule)"
	namespace = "host-interaction/hardware/memory"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/memory/get-memory-capacity.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /GlobalMemoryStatus/) 
		or 	pe.imports(/kernel32/i, /GlobalMemoryStatusEx/)  
	) 
}

private rule capa_swap_mouse_buttons : CAPA B0042_002  { 
  meta: 
 	description = "swap mouse buttons (converted from capa rule)"
	namespace = "host-interaction/hardware/mouse"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Impact::Modify Hardware::Mouse [B0042.002]"
	hash = "B7841B9D5DC1F511A93CC7576672EC0C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/mouse/swap-mouse-buttons.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/user32/i, /SwapMouseButton/)  
	) 
}

private rule capa_get_keyboard_layout : CAPA T1082  { 
  meta: 
 	description = "get keyboard layout (converted from capa rule)"
	namespace = "host-interaction/hardware/keyboard/layout"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "6F99A2C8944CB02FF28C6F9CED59B161"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/keyboard/layout/get-keyboard-layout.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/user32/i, /GetKeyboardLayoutList/) 
		or 	pe.imports(/user32/i, /GetKeyboardLayout/) 
		or 	pe.imports(/user32/i, /GetKeyboardLayoutName/)  
	)  
	) 
}

private rule capa_open_clipboard : CAPA T1115  { 
  meta: 
 	description = "open clipboard (converted from capa rule)"
	namespace = "host-interaction/clipboard"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Collection::Clipboard Data [T1115]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/clipboard/open-clipboard.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/user32/i, /OpenClipboard/)  
	) 
}

private rule capa_write_clipboard_data : CAPA E1510  { 
  meta: 
 	description = "write clipboard data (converted from capa rule)"
	namespace = "host-interaction/clipboard"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Impact::Clipboard Modification [E1510]"
	hash = "6F99A2C8944CB02FF28C6F9CED59B161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/clipboard/write-clipboard-data.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/user32/i, /SetClipboardData/)  
	) 
}

private rule capa_read_clipboard_data : CAPA T1115  { 
  meta: 
 	description = "read clipboard data (converted from capa rule)"
	namespace = "host-interaction/clipboard"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Collection::Clipboard Data [T1115]"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	hash = "93dfc146f60bd796eb28d4e4f348f2e4"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/clipboard/read-clipboard-data.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/user32/i, /GetClipboardData/)  
	) 
}

private rule capa_replace_clipboard_data : CAPA E1510  { 
  meta: 
 	description = "replace clipboard data (converted from capa rule)"
	namespace = "host-interaction/clipboard"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Impact::Clipboard Modification [E1510]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/clipboard/replace-clipboard-data.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			capa_write_clipboard_data

		and 	pe.imports(/user32/i, /EmptyClipboard/)  
	) 
}

private rule capa_install_driver : CAPA T1543_003 C0037  { 
  meta: 
 	description = "install driver (converted from capa rule)"
	namespace = "host-interaction/driver"
	author = "moritz.raabe@fireeye.com"
	scope = "basic block"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	mbc = "Hardware::Install Driver [C0037]"
	hash = "af60700383b75727f5256a0000c1476f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/driver/install-driver.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aok = /\bZwLoadDriver(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/ntdll/i, /NtLoadDriver/) 
		or 	$api_aok  
	) 
}

private rule capa_disable_driver_code_integrity : CAPA  { 
  meta: 
 	description = "disable driver code integrity (converted from capa rule)"
	namespace = "host-interaction/driver"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.fuzzysecurity.com/tutorials/28.html"
	references = "https://j00ru.vexillium.org/2010/06/insight-into-the-driver-signature-enforcement/"
	hash = "31CEE4F66CF3B537E3D2D37A71F339F4"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/driver/disable-driver-code-integrity.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_aol = "CiInitialize" ascii wide // exported symbol name used to resolve code integrity configuration
	$re_aom = /g_CiEnabled/ ascii wide  // non-exported name for code integrity flag
	$re_aon = /g_CiOptions/ ascii wide  // non-exported name for code integrity settings
 
  condition:
    capa_pe_file and
 (
		 (
			$str_aol 
		or 	$re_aom 
		or 	$re_aon  
	)  
	) 
}

private rule capa_manipulate_boot_configuration : CAPA  { 
  meta: 
 	description = "manipulate boot configuration (converted from capa rule)"
	namespace = "host-interaction/bootloader"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdedit-command-line-options"
	hash = "7FBC17A09CF5320C515FC1C5BA42C8B3"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/bootloader/manipulate-boot-configuration.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_aor = /bcdedit.exe/ nocase ascii wide 
	$re_aos = /boot.ini/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			$re_aor  
	) 
		or  (
			$re_aos  
	)  
	) 
}

private rule capa_set_application_hook : CAPA  { 
  meta: 
 	description = "set application hook (converted from capa rule)"
	namespace = "host-interaction/gui"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	hash = "Practical Malware Analysis Lab 12-03.exe_:0x401000"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/set-application-hook.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/user32/i, /SetWindowsHookEx/) 
		or 	pe.imports(/user32/i, /UnhookWindowsHookEx/)  
	)  
	) 
}

private rule capa_enumerate_gui_resources : CAPA T1010  { 
  meta: 
 	description = "enumerate gui resources (converted from capa rule)"
	namespace = "host-interaction/gui"
	author = "johnk3r"
	scope = "function"
	attack = "Discovery::Application Window Discovery [T1010]"
	hash = "5e6764534b3a1e4d3abacc4810b6985d"
	hash = "a74ee8200aace7d19dee79871bbf2ed3"
	hash = "74fa32d2b277f583010b692a3f91b627"
	hash = "021f49678cd633dc8cf99c61b3af3dda"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/enumerate-gui-resources.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aot = /\bEnumResourceTypes(A|W)?\b/ ascii wide
	$api_aou = /\bEnumWindowStations(A|W)?\b/ ascii wide
	$api_aov = /\bEnumDesktops(A|W)?\b/ ascii wide
	$api_aow = /\bEnumWindows(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_aot 
		or 	$api_aou 
		or 	$api_aov 
		or 	$api_aow  
	) 
}

private rule capa_find_graphical_window : CAPA T1010  { 
  meta: 
 	description = "find graphical window (converted from capa rule)"
	namespace = "host-interaction/gui/window/find"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::Application Window Discovery [T1010]"
	hash = "7C843E75D4F02087B932FE280DF9C90C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/window/find/find-graphical-window.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/user32/i, /FindWindow/) 
		or 	pe.imports(/user32/i, /FindWindowEx/)  
	) 
}

private rule capa_references_logon_banner : CAPA  { 
  meta: 
 	description = "references logon banner (converted from capa rule)"
	namespace = "host-interaction/gui/logon"
	author = "@_re_fox"
	scope = "basic block"
	hash = "c3341b7dfbb9d43bca8c812e07b4299f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/logon/references-logon-banner.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_aoy = /\\Microsoft\\Windows\\CurrentVersion\\Policies\\System/ ascii wide 
	$re_aoz = /LegalNoticeCaption/ ascii wide 
	$re_apa = /LegalNoticeText/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_aoy 
		and  (
			$re_aoz 
		or 	$re_apa  
	)  
	) 
}

private rule capa_lock_the_desktop : CAPA T1499  { 
  meta: 
 	description = "lock the desktop (converted from capa rule)"
	namespace = "host-interaction/gui/session/lock"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Impact::Endpoint Denial of Service [T1499]"
	hash = "39C05B15E9834AC93F206BC114D0A00C357C888DB567BA8F5345DA0529CBED41"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/session/lock/lock-the-desktop.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and

		pe.imports(/user32/i, /LockWorkStation/) 
}

private rule capa_resolve_path_using_msvcrt : CAPA T1083  { 
  meta: 
 	description = "resolve path using msvcrt (converted from capa rule)"
	namespace = "host-interaction/cli"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Discovery::File and Directory Discovery [T1083]"
	hash = "31600ad0d1a7ea615690df111ae36c73"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/cli/resolve-path-using-msvcrt.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/msvcrt/i, /__p__pgmptr/) 
		or 	pe.imports(/msvcrt/i, /__p__wpgmptr/) 
		or 	pe.imports(/msvcrt/i, /_get_pgmptr/) 
		or 	pe.imports(/msvcrt/i, /_get_wpgmptr/) 
		or 	pe.imports(/msvcrt/i, /_pgmptr/) 
		or 	pe.imports(/msvcrt/i, /_wpgmptr/)  
	) 
}

private rule capa_accept_command_line_arguments : CAPA T1059  { 
  meta: 
 	description = "accept command line arguments (converted from capa rule)"
	namespace = "host-interaction/cli"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Execution::Command and Scripting Interpreter [T1059]"
	hash = "Practical Malware Analysis Lab 10-03.exe_:0x401140"
	hash = "AFB6EC3D721A5CB67863487B0E51A34C167F629CF701F8BC7A038C117B4DDA44"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/cli/accept-command-line-arguments.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_apc = /\bGetCommandLine(A|W)?\b/ ascii wide
	$api_apd = /\bCommandLineToArgv(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_apc 
		or 	$api_apd  
	) 
}

private rule capa_set_thread_local_storage_value : CAPA C0041  { 
  meta: 
 	description = "set thread local storage value (converted from capa rule)"
	namespace = "host-interaction/process"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Process::Set Thread Local Storage Value [C0041]"
	hash = "03B236B23B1EC37C663527C1F53AF3FE"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/set-thread-local-storage-value.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /TlsSetValue/)  
	) 
}

private rule capa_allocate_thread_local_storage : CAPA C0040  { 
  meta: 
 	description = "allocate thread local storage (converted from capa rule)"
	namespace = "host-interaction/process"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Process::Allocate Thread Local Storage [C0040]"
	hash = "03B236B23B1EC37C663527C1F53AF3FE"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/allocate-thread-local-storage.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /TlsAlloc/)  
	) 
}

private rule capa_attach_user_process_memory : CAPA T1055  { 
  meta: 
 	description = "attach user process memory (converted from capa rule)"
	namespace = "host-interaction/process/inject"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Process Injection [T1055]"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/inject/attach-user-process-memory.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/ntoskrnl/i, /KeStackAttachProcess/) 
		and 	pe.imports(/ntoskrnl/i, /KeUnstackDetachProcess/)  
	) 
}

private rule capa_use_process_doppelganging : CAPA T1055_013  { 
  meta: 
 	description = "use process doppelganging (converted from capa rule)"
	namespace = "host-interaction/process/inject"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Process Injection::Process Doppelganging [T1055.013]"
	hash = "A5D66324DAAEE5672B913AA461D4BD3A"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/inject/use-process-doppelganging.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_ape = /CreateFileTransacted./ ascii wide 
	$str_apf = "ZwCreateSection" ascii wide
	$str_apg = "NtCreateSection" ascii wide
	$str_aph = "RollbackTransaction" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_ape 
		and  (
			$str_apf 
		or 	$str_apg  
	) 
		and 	$str_aph  
	) 
}

private rule capa_inject_APC : CAPA T1055_004  { 
  meta: 
 	description = "inject APC (converted from capa rule)"
	namespace = "host-interaction/process/inject"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Process Injection::Asynchronous Procedure Call [T1055.004]"
	hash = "al-khaser_x64.exe_:0x140019348"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/inject/inject-apc.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_api = /\bNtMapViewOfSection(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			capa_write_process_memory

		or 	pe.imports(/kernel32/i, /MapViewOfSection/) 
		or 	$api_api 
		or 	pe.imports(/ntdll/i, /ZwMapViewOfSection/) 
		or 	pe.imports(/kernel32/i, /MapViewOfFile/)  
	) 
		and  (
			pe.imports(/kernel32/i, /QueueUserAPC/) 
		or 	pe.imports(/ntdll/i, /NtQueueApcThread/)  
	)  
	) 
}

private rule capa_enumerate_processes : CAPA T1057 T1518  { 
  meta: 
 	description = "enumerate processes (converted from capa rule)"
	namespace = "host-interaction/process/list"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::Process Discovery [T1057]"
	attack = "Discovery::Software Discovery [T1518]"
	hash = "2D3EDC218A90F03089CC01715A9F047F"
	hash = "35d04ecd797041eee796f4ddaa96cae8"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/list/enumerate-processes.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /Process32First/) 
		and 	pe.imports(/kernel32/i, /Process32Next/)  
	) 
}

private rule capa_enumerate_processes_on_remote_desktop_session_host : CAPA T1057  { 
  meta: 
 	description = "enumerate processes on remote desktop session host (converted from capa rule)"
	namespace = "host-interaction/process/list"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Process Discovery [T1057]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/list/enumerate-processes-on-remote-desktop-session-host.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/wtsapi32/i, /WTSEnumerateProcesses/) 
		or 	pe.imports(/wtsapi32/i, /WTSEnumerateProcessesEx/)  
	)  
	) 
}

private rule capa_get_Explorer_PID : CAPA T1057  { 
  meta: 
 	description = "get Explorer PID (converted from capa rule)"
	namespace = "host-interaction/process/list"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Discovery::Process Discovery [T1057]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/ParentProcess.cpp"
	hash = "al-khaser_x86.exe_:0x425210"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/list/get-explorer-pid.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_apj = /\bGetShellWindow(A|W)?\b/ ascii wide
	$api_apk = /\bGetWindowThreadProcessId(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_apj 
		and 	$api_apk  
	) 
}

private rule capa_find_process_by_PID : CAPA T1057  { 
  meta: 
 	description = "find process by PID (converted from capa rule)"
	namespace = "host-interaction/process/list"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Process Discovery [T1057]"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/list/find-process-by-pid.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/ntoskrnl/i, /PsLookupProcessByProcessId/)  
	) 
}

private rule capa_create_process : CAPA C0017  { 
  meta: 
 	description = "create process (converted from capa rule)"
	namespace = "host-interaction/process/create"
	author = "moritz.raabe@fireeye.com"
	scope = "basic block"
	mbc = "Process::Create Process [C0017]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	hash = "Practical Malware Analysis Lab 01-04.exe_:0x4011FC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/create/create-process.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_apl = /\bZwCreateProcessEx(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /WinExec/) 
		or 	pe.imports(/kernel32/i, /CreateProcess/) 
		or 	pe.imports(/shell32/i, /ShellExecute/) 
		or 	pe.imports(/shell32/i, /ShellExecuteEx/) 
		or 	pe.imports(/advapi32/i, /CreateProcessAsUser/) 
		or 	pe.imports(/advapi32/i, /CreateProcessWithLogon/) 
		or 	pe.imports(/advapi32/i, /CreateProcessWithToken/) 
		or 	pe.imports(/kernel32/i, /CreateProcessInternal/) 
		or 	pe.imports(/ntdll/i, /NtCreateUserProcess/) 
		or 	pe.imports(/ntdll/i, /NtCreateProcess/) 
		or 	pe.imports(/ntdll/i, /NtCreateProcessEx/) 
		or 	pe.imports(/ntdll/i, /ZwCreateProcess/) 
		or 	$api_apl 
		or 	pe.imports(/ntdll/i, /ZwCreateUserProcess/) 
		or 	pe.imports(/ntdll/i, /RtlCreateUserProcess/)  
	) 
}

private rule capa_modify_access_privileges : CAPA T1134  { 
  meta: 
 	description = "modify access privileges (converted from capa rule)"
	namespace = "host-interaction/process/modify"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Privilege Escalation::Access Token Manipulation [T1134]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/modify/modify-access-privileges.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /AdjustTokenPrivileges/)  
	) 
}

private rule capa_terminate_process : CAPA C0018  { 
  meta: 
 	description = "terminate process (converted from capa rule)"
	namespace = "host-interaction/process/terminate"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Process::Terminate Process [C0018]"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	hash = "9B7CCAA2AE6A5B96E3110EBCBC4311F6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/terminate/terminate-process.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/kernel32/i, /TerminateProcess/) 
		or 	pe.imports(/ntdll/i, /NtTerminateProcess/) 
		or 	pe.imports(/kernel32/i, /ExitProcess/)  
	)  
	) 
}

private rule capa_enumerate_process_modules : CAPA T1057  { 
  meta: 
 	description = "enumerate process modules (converted from capa rule)"
	namespace = "host-interaction/process/modules/list"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Process Discovery [T1057]"
	hash = "6F99A2C8944CB02FF28C6F9CED59B161"
	hash = "9B2FD471274C41626B75DDBB5C897877"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/modules/list/enumerate-process-modules.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_apm = /\bEnumProcessModules(A|W)?\b/ ascii wide
	$api_apn = /\bEnumProcessModulesEx(A|W)?\b/ ascii wide
	$api_apo = /\bEnumProcesses(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/kernel32/i, /K32EnumProcessModules/) 
		or 	pe.imports(/kernel32/i, /K32EnumProcessModulesEx/) 
		or 	pe.imports(/kernel32/i, /K32EnumProcesses/) 
		or 	$api_apm 
		or 	$api_apn 
		or 	$api_apo  
	)  
	) 
}

private rule capa_get_domain_information : CAPA T1016  { 
  meta: 
 	description = "get domain information (converted from capa rule)"
	namespace = "host-interaction/network/domain"
	author = "@recvfrom"
	description = "Looks for imported Windows APIs that can be used to collect information about the Windows domain that a computer is connected to."
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	hash = "9B7CCAA2AE6A5B96E3110EBCBC4311F6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/domain/get-domain-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and

		pe.imports(/netapi32/i, /DsRoleGetPrimaryDomainInformation/) 
}

private rule capa_get_networking_interfaces : CAPA T1016  { 
  meta: 
 	description = "get networking interfaces (converted from capa rule)"
	namespace = "host-interaction/network/interface"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	hash = "B7841B9D5DC1F511A93CC7576672EC0C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/interface/get-networking-interfaces.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/iphlpapi/i, /GetIfTable/) 
		or 	pe.imports(/iphlpapi/i, /GetAdaptersInfo/)  
	) 
}

private rule capa_register_network_filter_via_WFP_API : CAPA T1565  { 
  meta: 
 	description = "register network filter via WFP API (converted from capa rule)"
	namespace = "host-interaction/network/traffic/filter"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Impact::Data Manipulation::Transmitted Data Manipulation [T1565]"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/traffic/filter/register-network-filter-via-wfp-api.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/fwpkclnt/i, /FwpmFilterAdd0/)  
	) 
}

private rule capa_copy_network_traffic : CAPA T1040  { 
  meta: 
 	description = "copy network traffic (converted from capa rule)"
	namespace = "host-interaction/network/traffic/copy"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Network Sniffing [T1040]"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/traffic/copy/copy-network-traffic.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/fwpkclnt/i, /FwpsCopyStreamDataToBuffer0/)  
	) 
}

private rule capa_resolve_DNS : CAPA C0011_001  { 
  meta: 
 	description = "resolve DNS (converted from capa rule)"
	namespace = "host-interaction/network/dns/resolve"
	author = "william.ballenthin@fireeye.com"
	author = "johnk3r"
	scope = "function"
	mbc = "Communication::DNS Communication::Resolve [C0011.001]"
	hash = "17264e3126a97c319a6a0c61e6da951e"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/dns/resolve/resolve-dns.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_app = /\bDnsQuery_A(A|W)?\b/ ascii wide
	$api_apq = /\bDnsQuery_W(A|W)?\b/ ascii wide
	$api_apr = /\bDnsQuery_UTF8(A|W)?\b/ ascii wide
	$api_aps = /\bDnsQueryEx(A|W)?\b/ ascii wide
	$api_apt = /\bgetaddrinfo(A|W)?\b/ ascii wide
	$api_apu = /\bGetAddrInfo(A|W)?\b/ ascii wide
	$api_apv = /\bGetAddrInfoEx(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/ws2_32/i, /gethostbyname/) 
		or 	$api_app 
		or 	$api_apq 
		or 	$api_apr 
		or 	$api_aps 
		or 	$api_apt 
		or 	$api_apu 
		or 	$api_apv  
	) 
}

private rule capa_check_Internet_connectivity_via_WinINet : CAPA T1016_001  { 
  meta: 
 	description = "check Internet connectivity via WinINet (converted from capa rule)"
	namespace = "host-interaction/network/connectivity"
	author = "matthew.williams@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Discovery::System Network Configuration Discovery::Internet Connection Discovery [T1016.001]"
	hash = "648FC498110B11B4313A47A776E6BA40"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/connectivity/check-internet-connectivity-via-wininet.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/wininet/i, /InternetGetConnectedState/) 
		or 	pe.imports(/wininet/i, /InternetCheckConnection/)  
	)  
	) 
}

private rule capa_create_mutex : CAPA C0042  { 
  meta: 
 	description = "create mutex (converted from capa rule)"
	namespace = "host-interaction/mutex"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Process::Create Mutex [C0042]"
	hash = "Practical Malware Analysis Lab 01-01.dll_:0x10001010"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/mutex/create-mutex.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /CreateMutex/) 
		or 	pe.imports(/kernel32/i, /CreateMutexEx/)  
	) 
}

private rule capa_bypass_UAC_via_token_manipulation : CAPA T1548_002  { 
  meta: 
 	description = "bypass UAC via token manipulation (converted from capa rule)"
	namespace = "host-interaction/uac/bypass"
	author = "richard.cole@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
	references = "https://github.com/hfiref0x/UACME/blob/0a4d2bd67f4872c595f0217ef6ebdcf135186945/Source/Akagi/methods/tyranid.c#L83"
	hash = "2f43138aa75fb12ac482b486cbc98569"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/uac/bypass/bypass-uac-via-token-manipulation.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_aqa = "wusa.exe" ascii wide
	$api_aqb = /\bShellExecuteExW(A|W)?\b/ ascii wide
	$api_aqc = /\bImpersonateLoggedOnUser(A|W)?\b/ ascii wide
	$api_aqd = /\bGetStartupInfoW(A|W)?\b/ ascii wide
	$api_aqe = /\bCreateProcessWithLogonW(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_aqa 
		and 	$api_aqb 
		and 	$api_aqc 
		and 	$api_aqd 
		and 	$api_aqe  
	) 
}

private rule capa_bypass_UAC_via_AppInfo_ALPC : CAPA T1548_002  { 
  meta: 
 	description = "bypass UAC via AppInfo ALPC (converted from capa rule)"
	namespace = "host-interaction/uac/bypass"
	author = "richard.cole@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
	references = "https://github.com/hfiref0x/UACME/blob/0a4d2bd67f4872c595f0217ef6ebdcf135186945/Source/Akagi/methods/tyranid.c#L597"
	hash = "2f43138aa75fb12ac482b486cbc98569"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/uac/bypass/bypass-uac-via-appinfo-alpc.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_aqf = "winver.exe" ascii wide
	$str_aqg = "WinSta0\\Default" ascii wide
	$str_aqh = "taskmgr.exe" ascii wide
	$api_aqi = /\bWaitForDebugEvent(A|W)?\b/ ascii wide
	$api_aqj = /\bContinueDebugEvent(A|W)?\b/ ascii wide
	$api_aqk = /\bTerminateProcess(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_aqf 
		and 	$str_aqg 
		and 	$str_aqh 
		and 	$api_aqi 
		and 	$api_aqj 
		and 	$api_aqk  
	) 
}

private rule capa_access_the_Windows_event_log : CAPA E1083_m01  { 
  meta: 
 	description = "access the Windows event log (converted from capa rule)"
	namespace = "host-interaction/log/winevt/access"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Discovery::File and Directory Discovery::Log File [E1083.m01]"
	hash = "mimikatz.exe_:0x45228B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/log/winevt/access/access-the-windows-event-log.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aql = /\bOpenEventLog(A|W)?\b/ ascii wide
	$api_aqm = /\bClearEventLog(A|W)?\b/ ascii wide
	$api_aqn = /\bOpenBackupEventLog(A|W)?\b/ ascii wide
	$api_aqo = /\bReportEvent(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_aql 
		or 	$api_aqm 
		or 	$api_aqn 
		or 	$api_aqo  
	) 
}

private rule capa_print_debug_messages : CAPA  { 
  meta: 
 	description = "print debug messages (converted from capa rule)"
	namespace = "host-interaction/log/debug/write-event"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/log/debug/write-event/print-debug-messages.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/ntoskrnl/i, /DbgPrint/) 
		or 	pe.imports(/kernel32/i, /OutputDebugString/)  
	) 
}

private rule capa_set_environment_variable : CAPA C0034_001  { 
  meta: 
 	description = "set environment variable (converted from capa rule)"
	namespace = "host-interaction/environment-variable"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Operating System::Environment Variable::Set Variable [C0034.001]"
	hash = "Practical Malware Analysis Lab 11-03.exe_:0x406580"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/environment-variable/set-environment-variable.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /SetEnvironmentStrings/) 
		or 	pe.imports(/kernel32/i, /SetEnvironmentVariable/)  
	) 
}

private rule capa_query_environment_variable : CAPA T1082  { 
  meta: 
 	description = "query environment variable (converted from capa rule)"
	namespace = "host-interaction/environment-variable"
	author = "michael.hunhoff@fireeye.com"
	author = "@_re_fox"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "Practical Malware Analysis Lab 14-02.exe_:0x401880"
	hash = "0761142efbda6c4b1e801223de723578"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/environment-variable/query-environment-variable.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /GetEnvironmentVariable/) 
		or 	pe.imports(/kernel32/i, /GetEnvironmentStrings/) 
		or 	pe.imports(/kernel32/i, /ExpandEnvironmentStrings/) 
		or 	pe.imports(/msvcr90/i, /getenv/) 
		or 	pe.imports(/msvcrt/i, /getenv/)  
	) 
}

private rule capa_open_registry_key_via_offline_registry_library : CAPA C0036_003  { 
  meta: 
 	description = "open registry key via offline registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "johnk3r"
	scope = "function"
	mbc = "Operating System::Registry::Open Registry Key [C0036.003]"
	hash = "5fbbfeed28b258c42e0cfeb16718b31c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/open-registry-key-via-offline-registry-library.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aqp = /\bOROpenHive(A|W)?\b/ ascii wide
	$api_aqq = /\bOROpenKey(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_aqp 
		or 	$api_aqq  
	) 
}

private rule capa_query_or_enumerate_registry_value : CAPA T1012 C0036_006  { 
  meta: 
 	description = "query or enumerate registry value (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "william.ballenthin@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Query Registry [T1012]"
	mbc = "Operating System::Registry::Query Registry Value [C0036.006]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x100047AD"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/query-or-enumerate-registry-value.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aqr = /\bZwQueryValueKey(A|W)?\b/ ascii wide
	$api_aqs = /\bZwEnumerateValueKey(A|W)?\b/ ascii wide
	$api_aqt = /\bNtQueryValueKey(A|W)?\b/ ascii wide
	$api_aqu = /\bNtEnumerateValueKey(A|W)?\b/ ascii wide
	$api_aqv = /\bRtlQueryRegistryValues(A|W)?\b/ ascii wide
	$api_aqw = /\bSHGetValue(A|W)?\b/ ascii wide
	$api_aqx = /\bSHEnumValue(A|W)?\b/ ascii wide
	$api_aqy = /\bSHRegGetInt(A|W)?\b/ ascii wide
	$api_aqz = /\bSHRegGetPath(A|W)?\b/ ascii wide
	$api_ara = /\bSHRegGetValue(A|W)?\b/ ascii wide
	$api_arb = /\bSHQueryValueEx(A|W)?\b/ ascii wide
	$api_arc = /\bSHRegGetUSValue(A|W)?\b/ ascii wide
	$api_ard = /\bSHOpenRegStream(A|W)?\b/ ascii wide
	$api_are = /\bSHRegEnumUSValue(A|W)?\b/ ascii wide
	$api_arf = /\bSHOpenRegStream2(A|W)?\b/ ascii wide
	$api_arg = /\bSHRegQueryUSValue(A|W)?\b/ ascii wide
	$api_arh = /\bSHRegGetBoolUSValue(A|W)?\b/ ascii wide
	$api_ari = /\bSHRegGetValueFromHKCUHKLM(A|W)?\b/ ascii wide
	$api_arj = /\bSHRegGetBoolValueFromHKCUHKLM(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/advapi32/i, /RegGetValue/) 
		or 	pe.imports(/advapi32/i, /RegEnumValue/) 
		or 	pe.imports(/advapi32/i, /RegQueryValue/) 
		or 	pe.imports(/advapi32/i, /RegQueryValueEx/) 
		or 	pe.imports(/advapi32/i, /RegQueryMultipleValues/) 
		or 	$api_aqr 
		or 	$api_aqs 
		or 	$api_aqt 
		or 	$api_aqu 
		or 	$api_aqv 
		or 	$api_aqw 
		or 	$api_aqx 
		or 	$api_aqy 
		or 	$api_aqz 
		or 	$api_ara 
		or 	$api_arb 
		or 	$api_arc 
		or 	$api_ard 
		or 	$api_are 
		or 	$api_arf 
		or 	$api_arg 
		or 	$api_arh 
		or 	$api_ari 
		or 	$api_arj  
	)  
	) 
}

private rule capa_set_registry_key_via_offline_registry_library : CAPA T1112 C0036_001  { 
  meta: 
 	description = "set registry key via offline registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "johnk3r"
	scope = "function"
	attack = "Defense Evasion::Modify Registry [T1112]"
	mbc = "Operating System::Registry::Set Registry Key [C0036.001]"
	hash = "5fbbfeed28b258c42e0cfeb16718b31c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/set-registry-key-via-offline-registry-library.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_ark = /\bORSetValue(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_ark  
	) 
}

private rule capa_query_registry_key_via_offline_registry_library : CAPA T1012 C0036_006  { 
  meta: 
 	description = "query registry key via offline registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "johnk3r"
	scope = "function"
	attack = "Discovery::Query Registry [T1012]"
	mbc = "Operating System::Registry::Query Registry Value [C0036.006]"
	hash = "5fbbfeed28b258c42e0cfeb16718b31c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/query-registry-key-via-offline-registry-library.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_arl = /\bORGetValue(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_arl  
	) 
}

private rule capa_query_or_enumerate_registry_key : CAPA T1012 C0036_005  { 
  meta: 
 	description = "query or enumerate registry key (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::Query Registry [T1012]"
	mbc = "Operating System::Registry::Query Registry Key [C0036.005]"
	hash = "493167E85E45363D09495D0841C30648"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/query-or-enumerate-registry-key.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_arm = /\bZwQueryKey(A|W)?\b/ ascii wide
	$api_arn = /\bZwEnumerateKey(A|W)?\b/ ascii wide
	$api_aro = /\bNtQueryKey(A|W)?\b/ ascii wide
	$api_arp = /\bNtEnumerateKey(A|W)?\b/ ascii wide
	$api_arq = /\bRtlCheckRegistryKey(A|W)?\b/ ascii wide
	$api_arr = /\bSHEnumKeyEx(A|W)?\b/ ascii wide
	$api_ars = /\bSHQueryInfoKey(A|W)?\b/ ascii wide
	$api_art = /\bSHRegEnumUSKey(A|W)?\b/ ascii wide
	$api_aru = /\bSHRegQueryInfoUSKey(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/advapi32/i, /RegEnumKey/) 
		or 	pe.imports(/advapi32/i, /RegEnumKeyEx/) 
		or 	pe.imports(/advapi32/i, /RegQueryInfoKeyA/) 
		or 	$api_arm 
		or 	$api_arn 
		or 	$api_aro 
		or 	$api_arp 
		or 	$api_arq 
		or 	$api_arr 
		or 	$api_ars 
		or 	$api_art 
		or 	$api_aru  
	)  
	) 
}

private rule capa_create_registry_key_via_offline_registry_library : CAPA T1112 C0036_004  { 
  meta: 
 	description = "create registry key via offline registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "johnk3r"
	scope = "function"
	attack = "Defense Evasion::Modify Registry [T1112]"
	mbc = "Operating System::Registry::Create Registry Key [C0036.004]"
	hash = "5fbbfeed28b258c42e0cfeb16718b31c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/create-registry-key-via-offline-registry-library.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_arv = /\bORCreateHive(A|W)?\b/ ascii wide
	$api_arw = /\bORCreateKey(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_arv 
		or 	$api_arw  
	) 
}

private rule capa_create_or_open_registry_key : CAPA C0036_004 C0036_003  { 
  meta: 
 	description = "create or open registry key (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	mbc = "Operating System::Registry::Create Registry Key [C0036.004]"
	mbc = "Operating System::Registry::Open Registry Key [C0036.003]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10004706"
	hash = "Practical Malware Analysis Lab 11-01.exe_:0x401000"
	hash = "493167E85E45363D09495D0841C30648"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/create-or-open-registry-key.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_arx = /\bZwOpenKey(A|W)?\b/ ascii wide
	$api_ary = /\bZwOpenKeyEx(A|W)?\b/ ascii wide
	$api_arz = /\bZwCreateKey(A|W)?\b/ ascii wide
	$api_asa = /\bZwOpenKeyTransacted(A|W)?\b/ ascii wide
	$api_asb = /\bZwOpenKeyTransactedEx(A|W)?\b/ ascii wide
	$api_asc = /\bZwCreateKeyTransacted(A|W)?\b/ ascii wide
	$api_asd = /\bNtOpenKey(A|W)?\b/ ascii wide
	$api_ase = /\bNtCreateKey(A|W)?\b/ ascii wide
	$api_asf = /\bSHRegOpenUSKey(A|W)?\b/ ascii wide
	$api_asg = /\bSHRegCreateUSKey(A|W)?\b/ ascii wide
	$api_ash = /\bRtlCreateRegistryKey(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /RegOpenKey/) 
		or 	pe.imports(/advapi32/i, /RegOpenKeyEx/) 
		or 	pe.imports(/advapi32/i, /RegCreateKey/) 
		or 	pe.imports(/advapi32/i, /RegCreateKeyEx/) 
		or 	pe.imports(/advapi32/i, /RegOpenCurrentUser/) 
		or 	pe.imports(/advapi32/i, /RegOpenKeyTransacted/) 
		or 	pe.imports(/advapi32/i, /RegOpenUserClassesRoot/) 
		or 	pe.imports(/advapi32/i, /RegCreateKeyTransacted/) 
		or 	$api_arx 
		or 	$api_ary 
		or 	$api_arz 
		or 	$api_asa 
		or 	$api_asb 
		or 	$api_asc 
		or 	$api_asd 
		or 	$api_ase 
		or 	$api_asf 
		or 	$api_asg 
		or 	$api_ash  
	) 
}

private rule capa_delete_registry_key : CAPA T1112 C0036_002  { 
  meta: 
 	description = "delete registry key (converted from capa rule)"
	namespace = "host-interaction/registry/delete"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	author = "johnk3r"
	scope = "function"
	attack = "Defense Evasion::Modify Registry [T1112]"
	mbc = "Operating System::Registry::Delete Registry Key [C0036.002]"
	hash = "4f11bdb380dafa2518053c6d20147a05"
	hash = "493167E85E45363D09495D0841C30648"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/delete/delete-registry-key.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_asi = /\bZwDeleteKey(A|W)?\b/ ascii wide
	$api_asj = /\bNtDeleteKey(A|W)?\b/ ascii wide
	$api_ask = /\bSHDeleteKey(A|W)?\b/ ascii wide
	$api_asl = /\bSHDeleteEmptyKey(A|W)?\b/ ascii wide
	$api_asm = /\bSHRegDeleteEmptyUSKey(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/advapi32/i, /RegDeleteKey/) 
		or 	pe.imports(/advapi32/i, /RegDeleteTree/) 
		or 	pe.imports(/advapi32/i, /RegDeleteKeyEx/) 
		or 	pe.imports(/advapi32/i, /RegDeleteKeyTransacted/) 
		or 	$api_asi 
		or 	$api_asj 
		or 	$api_ask 
		or 	$api_asl 
		or 	$api_asm  
	)  
	) 
}

private rule capa_delete_registry_value : CAPA T1112 C0036_007  { 
  meta: 
 	description = "delete registry value (converted from capa rule)"
	namespace = "host-interaction/registry/delete"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Modify Registry [T1112]"
	mbc = "Operating System::Registry::Delete Registry Value [C0036.007]"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/delete/delete-registry-value.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_asn = /\bZwDeleteValueKey(A|W)?\b/ ascii wide
	$api_aso = /\bNtDeleteValueKey(A|W)?\b/ ascii wide
	$api_asp = /\bRtlDeleteRegistryValue(A|W)?\b/ ascii wide
	$api_asq = /\bSHDeleteValue(A|W)?\b/ ascii wide
	$api_asr = /\bSHRegDeleteUSValue(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/advapi32/i, /RegDeleteValue/) 
		or 	pe.imports(/advapi32/i, /RegDeleteKeyValue/) 
		or 	$api_asn 
		or 	$api_aso 
		or 	$api_asp 
		or 	$api_asq 
		or 	$api_asr  
	)  
	) 
}

private rule capa_set_registry_value : CAPA C0036_001  { 
  meta: 
 	description = "set registry value (converted from capa rule)"
	namespace = "host-interaction/registry/create"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Operating System::Registry::Set Registry Key [C0036.001]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	hash = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/create/set-registry-value.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_ass = /\bZwSetValueKey(A|W)?\b/ ascii wide
	$api_ast = /\bNtSetValueKey(A|W)?\b/ ascii wide
	$api_asu = /\bRtlWriteRegistryValue(A|W)?\b/ ascii wide
	$api_asv = /\bSHSetValue(A|W)?\b/ ascii wide
	$api_asw = /\bSHRegSetPath(A|W)?\b/ ascii wide
	$api_asx = /\bSHRegSetValue(A|W)?\b/ ascii wide
	$api_asy = /\bSHRegSetUSValue(A|W)?\b/ ascii wide
	$api_asz = /\bSHRegWriteUSValue(A|W)?\b/ ascii wide
	$re_ata = /reg(.exe)? add / nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
		 (
			pe.imports(/advapi32/i, /RegSetValue/) 
		or 	pe.imports(/advapi32/i, /RegSetValueEx/) 
		or 	pe.imports(/advapi32/i, /RegSetKeyValue/) 
		or 	$api_ass 
		or 	$api_ast 
		or 	$api_asu 
		or 	$api_asv 
		or 	$api_asw 
		or 	$api_asx 
		or 	$api_asy 
		or 	$api_asz  
	)  
	) 
		or  (
			capa_create_process

		and 	$re_ata  
	)  
	) 
}

private rule capa_get_logon_sessions : CAPA T1087  { 
  meta: 
 	description = "get logon sessions (converted from capa rule)"
	namespace = "host-interaction/session"
	author = "@recvfrom"
	description = "Looks for imported Windows APIs that can be used to enumerate user sessions."
	scope = "function"
	attack = "Discovery::Account Discovery [T1087]"
	hash = "9B7CCAA2AE6A5B96E3110EBCBC4311F6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/session/get-logon-sessions.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/secur32/i, /LsaEnumerateLogonSessions/)  
	) 
}

private rule capa_get_session_integrity_level : CAPA T1033  { 
  meta: 
 	description = "get session integrity level (converted from capa rule)"
	namespace = "host-interaction/session"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Owner/User Discovery [T1033]"
	hash = "9879D201DC5ACA863F357184CD1F170E"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/session/get-session-integrity-level.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/shell32/i, /IsUserAnAdmin/)  
	) 
}

private rule capa_link_function_at_runtime : CAPA T1129  { 
  meta: 
 	description = "link function at runtime (converted from capa rule)"
	namespace = "linking/runtime-linking"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Execution::Shared Modules [T1129]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	hash = "Practical Malware Analysis Lab 01-04.exe_:0x401350"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/runtime-linking/link-function-at-runtime.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/kernel32/i, /LoadLibrary/) 
		or 	pe.imports(/kernel32/i, /GetModuleHandle/) 
		or 	pe.imports(/kernel32/i, /GetModuleHandleEx/) 
		or 	pe.imports(/ntdll/i, /LdrLoadDll/)  
	) 
		and  (
			pe.imports(/kernel32/i, /GetProcAddress/) 
		or 	pe.imports(/ntdll/i, /LdrGetProcedureAddress/)  
	)  
	) 
}

private rule capa_linked_against_Crypto__ : CAPA C0059  { 
  meta: 
 	description = "linked against Crypto++ (converted from capa rule)"
	namespace = "linking/static/cryptopp"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	mbc = "Cryptography::Crypto Library [C0059]"
	hash = "8BA66E4B618FFDC8255F1DF01F875DDE6FD0561305D9F8307BE7BB11D02AE363"
	hash = "66602B5FAB602CB4E6F754748D249542"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/cryptopp/linked-against-crypto.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_atb = "Cryptographic algorithms are disabled after a power-up self test failed." ascii wide
	$str_atc = ": this object requires an IV" ascii wide
	$str_atd = "BER decode error" ascii wide
	$str_ate = ".?AVException@CryptoPP@@" ascii wide
	$str_atf = "FileStore: error reading file" ascii wide
	$str_atg = "StreamTransformationFilter: PKCS_PADDING cannot be used with " ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_atb 
		or 	$str_atc 
		or 	$str_atd 
		or 	$str_ate 
		or 	$str_atf 
		or 	$str_atg  
	) 
}

private rule capa_linked_against_OpenSSL : CAPA C0059  { 
  meta: 
 	description = "linked against OpenSSL (converted from capa rule)"
	namespace = "linking/static/openssl"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	mbc = "Cryptography::Crypto Library [C0059]"
	hash = "6cc148363200798a12091b97a17181a1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/openssl/linked-against-openssl.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_ath = "RC4 for x86_64, CRYPTOGAMS by <appro@openssl.org>" ascii wide
	$str_ati = "AES for x86_64, CRYPTOGAMS by <appro@openssl.org>" ascii wide
	$str_atj = "DSA-SHA1-old" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_ath 
		or 	$str_ati 
		or 	$str_atj  
	) 
}

private rule capa_linked_against_PolarSSL_mbed_TLS : CAPA C0059  { 
  meta: 
 	description = "linked against PolarSSL/mbed TLS (converted from capa rule)"
	namespace = "linking/static/polarssl"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	mbc = "Cryptography::Crypto Library [C0059]"
	hash = "232b0a8546035d9017fadf68398826edb0a1e055566bc1d356d6c9fdf1d7e485"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/polarssl/linked-against-polarsslmbed-tls.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_atk = "PolarSSLTest" ascii wide
	$str_atl = "mbedtls_cipher_setup" ascii wide
	$str_atm = "mbedtls_pk_verify" ascii wide
	$str_atn = "mbedtls_ssl_write_record" ascii wide
	$str_ato = "mbedtls_ssl_fetch_input" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_atk 
		or 	$str_atl 
		or 	$str_atm 
		or 	$str_atn 
		or 	$str_ato  
	) 
}

private rule capa_linked_against_libcurl : CAPA  { 
  meta: 
 	description = "linked against libcurl (converted from capa rule)"
	namespace = "linking/static/libcurl"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	hash = "A90E5B3454AA71D9700B2EA54615F44B"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/libcurl/linked-against-libcurl.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_atp = /CLIENT libcurl/ ascii wide 
	$re_atq = /curl\.haxx\.se/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_atp 
		or 	$re_atq  
	) 
}

private rule capa_linked_against_Microsoft_Detours : CAPA T1574  { 
  meta: 
 	description = "linked against Microsoft Detours (converted from capa rule)"
	namespace = "linking/static/msdetours"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Hijack Execution Flow [T1574]"
	references = "https://github.com/microsoft/Detours"
	hash = "071F2D1C4C2201EE95FFE2AA965000F5F615A11A12D345E33B9FB060E5597740"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/msdetours/linked-against-microsoft-detours.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any atr in pe.sections : ( atr.name == ".detourc" ) 
		or 	for any ats in pe.sections : ( ats.name == ".detourd" )  
	) 
}

private rule capa_linked_against_ZLIB : CAPA C0060  { 
  meta: 
 	description = "linked against ZLIB (converted from capa rule)"
	namespace = "linking/static/zlib"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	mbc = "Data::Compression Library [C0060]"
	hash = "6cc148363200798a12091b97a17181a1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/zlib/linked-against-zlib.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_att = /deflate .{,1000} Copyright/ ascii wide 
	$re_atu = /inflate .{,1000} Copyright/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_att 
		or 	$re_atu  
	) 
}

private rule capa_reference_Base64_string : CAPA T1027 C0026_001 C0019  { 
  meta: 
 	description = "reference Base64 string (converted from capa rule)"
	namespace = "data-manipulation/encoding/base64"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Data::Encode Data::Base64 [C0026.001]"
	mbc = "Data::Check String [C0019]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	hash = "074072B261FC27B65C72671F13510C05"
	hash = "5DB2D2BE20D59AA0BE6709A6850F1775"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encoding/base64/reference-base64-string.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 
		$re_atv = /ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ ascii wide 
 
  condition:
    capa_pe_file and

		$re_atv 
}

private rule capa_import_public_key : CAPA C0028_001  { 
  meta: 
 	description = "import public key (converted from capa rule)"
	namespace = "data-manipulation/encryption"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Encryption Key::Import Public Key [C0028.001]"
	hash = "ffeae4a391a1d5203bd04b4161557227"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/import-public-key.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /CryptAcquireContext/) 
		and 	pe.imports(/crypt32/i, /CryptImportPublicKeyInfo/)  
	) 
}

private rule capa_encrypt_or_decrypt_via_WinCrypt : CAPA T1027 C0031 C0027  { 
  meta: 
 	description = "encrypt or decrypt via WinCrypt (converted from capa rule)"
	namespace = "data-manipulation/encryption"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Cryptography::Decrypt Data [C0031]"
	mbc = "Cryptography::Encrypt Data [C0027]"
	hash = "A45E377DBB98A6B44FD4034BC3FFF9B0"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/encrypt-or-decrypt-via-wincrypt.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_atw = /\bCryptEncrypt(A|W)?\b/ ascii wide
	$api_atx = /\bCryptDecrypt(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$api_atw 
		or 	$api_atx  
	)  
	) 
}

private rule capa_encrypt_data_using_DPAPI : CAPA T1027 C0027  { 
  meta: 
 	description = "encrypt data using DPAPI (converted from capa rule)"
	namespace = "data-manipulation/encryption/dpapi"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Cryptography::Encrypt Data [C0027]"
	hash = "6cc148363200798a12091b97a17181a1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/dpapi/encrypt-data-using-dpapi.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_aty = /\bCryptProtectMemory(A|W)?\b/ ascii wide
	$api_atz = /\bCryptUnprotectMemory(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_aty 
		or 	$api_atz 
		or 	pe.imports(/crypt32/i, /CryptProtectData/) 
		or 	pe.imports(/crypt32/i, /CryptUnprotectData/)  
	) 
}

private rule capa_encrypt_data_using_Camellia : CAPA T1027 E1027_m05 C0027_003  { 
  meta: 
 	description = "encrypt data using Camellia (converted from capa rule)"
	namespace = "data-manipulation/encryption/camellia"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::Camellia [C0027.003]"
	hash = "0761142efbda6c4b1e801223de723578"
	hash = "112f9f0e8d349858a80dd8c14190e620"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/camellia/encrypt-data-using-camellia.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$aua = { 00 70 70 70 00 82 82 82 00 2C 2C 2C 00 EC EC EC 00 B3 B3 B3 00 27 27 27 00 C0 C0 C0 00 E5 E5 E5 00 E4 E4 E4 00 85 85 85 00 57 57 57 00 35 35 35 00 EA EA EA 00 0C 0C 0C 00 AE AE AE 00 41 41 41 00 23 23 23 00 EF EF EF 00 6B 6B 6B 00 93 93 93 00 45 45 45 00 19 19 19 00 A5 A5 A5 00 21 21 21 00 ED ED ED 00 0E 0E 0E 00 4F 4F 4F 00 4E 4E 4E 00 1D 1D 1D 00 65 65 65 00 92 92 92 00 BD BD BD 00 86 86 86 00 B8 B8 B8 00 AF AF AF 00 8F 8F 8F 00 7C 7C 7C 00 EB EB EB 00 1F 1F 1F 00 CE CE CE 00 3E 3E 3E 00 30 30 30 00 DC DC } // libgcrypt_sp1110
	$aub = { E0 E0 E0 00 05 05 05 00 58 58 58 00 D9 D9 D9 00 67 67 67 00 4E 4E 4E 00 81 81 81 00 CB CB CB 00 C9 C9 C9 00 0B 0B 0B 00 AE AE AE 00 6A 6A 6A 00 D5 D5 D5 00 18 18 18 00 5D 5D 5D 00 82 82 82 00 46 46 46 00 DF DF DF 00 D6 D6 D6 00 27 27 27 00 8A 8A 8A 00 32 32 32 00 4B 4B 4B 00 42 42 42 00 DB DB DB 00 1C 1C 1C 00 9E 9E 9E 00 9C 9C 9C 00 3A 3A 3A 00 CA CA CA 00 25 25 25 00 7B 7B 7B 00 0D 0D 0D 00 71 71 71 00 5F 5F 5F 00 1F 1F 1F 00 F8 F8 F8 00 D7 D7 D7 00 3E 3E 3E 00 9D 9D 9D 00 7C 7C 7C 00 60 60 60 00 B9 B9 B9 } // libgcrypt_sp0222
	$auc = { 38 38 00 38 41 41 00 41 16 16 00 16 76 76 00 76 D9 D9 00 D9 93 93 00 93 60 60 00 60 F2 F2 00 F2 72 72 00 72 C2 C2 00 C2 AB AB 00 AB 9A 9A 00 9A 75 75 00 75 06 06 00 06 57 57 00 57 A0 A0 00 A0 91 91 00 91 F7 F7 00 F7 B5 B5 00 B5 C9 C9 00 C9 A2 A2 00 A2 8C 8C 00 8C D2 D2 00 D2 90 90 00 90 F6 F6 00 F6 07 07 00 07 A7 A7 00 A7 27 27 00 27 8E 8E 00 8E B2 B2 00 B2 49 49 00 49 DE DE 00 DE 43 43 00 43 5C 5C 00 5C D7 D7 00 D7 C7 C7 00 C7 3E 3E 00 3E F5 F5 00 F5 8F 8F 00 8F 67 67 00 67 1F 1F 00 1F 18 18 00 18 6E 6E 00 } // libgcrypt_sp3033
	$aud = { 70 00 70 70 2C 00 2C 2C B3 00 B3 B3 C0 00 C0 C0 E4 00 E4 E4 57 00 57 57 EA 00 EA EA AE 00 AE AE 23 00 23 23 6B 00 6B 6B 45 00 45 45 A5 00 A5 A5 ED 00 ED ED 4F 00 4F 4F 1D 00 1D 1D 92 00 92 92 86 00 86 86 AF 00 AF AF 7C 00 7C 7C 1F 00 1F 1F 3E 00 3E 3E DC 00 DC DC 5E 00 5E 5E 0B 00 0B 0B A6 00 A6 A6 39 00 39 39 D5 00 D5 D5 5D 00 5D 5D D9 00 D9 D9 5A 00 5A 5A 51 00 51 51 6C 00 6C 6C 8B 00 8B 8B 9A 00 9A 9A FB 00 FB FB B0 00 B0 B0 74 00 74 74 2B 00 2B 2B F0 00 F0 F0 84 00 84 84 DF 00 DF DF CB 00 CB CB 34 00 34 } // libgcrypt_sp4404
	$aue = { 70 82 2C EC B3 27 C0 E5 E4 85 57 35 EA 0C AE 41 23 EF 6B 93 45 19 A5 21 ED 0E 4F 4E 1D 65 92 BD 86 B8 AF 8F 7C EB 1F CE 3E 30 DC 5F 5E C5 0B 1A A6 E1 39 CA D5 47 5D 3D D9 01 5A D6 51 56 6C 4D 8B 0D 9A 66 FB CC B0 2D 74 12 2B 20 F0 B1 84 99 DF 4C CB C2 34 7E 76 05 6D B7 A9 31 D1 17 04 D7 14 58 3A 61 DE 1B 11 1C 32 0F 9C 16 53 18 F2 22 FE 44 CF B2 C3 B5 7A 91 24 08 E8 A8 60 FC 69 50 AA D0 A0 7D A1 89 62 97 54 5B 1E 95 E0 FF 64 D2 10 C4 00 48 A3 F7 75 DB 8A 03 E6 DA 09 3F DD 94 87 5C 83 02 CD 4A 90 33 73 67 F6 F3 9D 7F BF E2 52 9B D8 26 C8 37 C6 3B 81 96 6F 4B 13 BE 63 2E E9 79 A7 8C 9F 6E BC 8E 29 F5 F9 B6 2F FD B4 59 78 98 06 6A E7 46 71 BA D4 25 AB 42 88 A2 8D FA 72 07 B9 55 F8 EE AC 0A 36 49 2A 68 3C 38 F1 A4 40 28 D3 7B BB C9 43 C1 15 E3 AD F4 77 C7 80 9E } // calccrypto_sbox
	$num_auf = { 8B 90 CC 3B } // CAMELLIA_SIGMA1R
	$num_aug = { 7F 66 9E A0 } // CAMELLIA_SIGMA1L
	$num_auh = { B2 73 AA 4C } // CAMELLIA_SIGMA2R
	$num_aui = { 58 E8 7A B6 } // CAMELLIA_SIGMA2L
	$num_auj = { 2F 37 EF C6 } // CAMELLIA_SIGMA3L
	$num_auk = { BE 82 4F E9 } // CAMELLIA_SIGMA3R
	$num_aul = { A5 53 FF 54 } // CAMELLIA_SIGMA4L
	$num_aum = { 1C 6F D3 F1 } // CAMELLIA_SIGMA4R
	$num_aun = { FA 27 E5 10 } // CAMELLIA_SIGMA5L
	$num_auo = { 1D 2D 68 DE } // CAMELLIA_SIGMA5R
	$num_aup = { C2 88 56 B0 } // CAMELLIA_SIGMA6L
	$num_auq = { FD C1 E6 B3 } // CAMELLIA_SIGMA6R
	$aur = { 8B 90 CC 3B 7F 66 9E A0 } // sigma1
	$aus = { B2 73 AA 4C 58 E8 7A B6 } // sigma2
	$aut = { BE 82 4F E9 2F 37 EF C6 } // sigma3
	$auu = { 1C 6F D3 F1 A5 53 FF 54 } // sigma4
	$auv = { 1D 2D 68 DE FA 27 E5 10 } // sigma5
	$auw = { FD C1 E6 B3 C2 88 56 B0 } // sigma6
	$re_aux = /A09E667F3BCC908B/ nocase ascii wide  // sigma1_str
	$str_auy = "/B67AE8584CAA73B" ascii wide // sigma2_str
	$re_auz = /C6EF372FE94F82BE/ nocase ascii wide  // sigma3_str
	$re_ava = /54FF53A5F1D36F1C/ nocase ascii wide  // sigma4_str
	$re_avb = /10E527FADE682D1D/ nocase ascii wide  // sigma5_str
	$re_avc = /B05688C2B3E6C1FD/ nocase ascii wide  // sigma6_str
 
  condition:
    capa_pe_file and
 (
			$aua 
		or 	$aub 
		or 	$auc 
		or 	$aud 
		or 	$aue 
		or  (
		 (
		$num_auf 
		and $num_aug 
		and $num_auh 
		and $num_aui 
		and $num_auj 
		and $num_auk 
		and $num_aul 
		and $num_aum 
		and $num_aun 
		and $num_auo 
		and $num_aup 
		and $num_auq  
	) 
		or  (
			$aur 
		and 	$aus 
		and 	$aut 
		and 	$auu 
		and 	$auv 
		and 	$auw  
	) 
		or  (
			$re_aux 
		and 	$str_auy 
		and 	$re_auz 
		and 	$re_ava 
		and 	$re_avb 
		and 	$re_avc  
	)  
	)  
	) 
}

private rule capa_encrypt_data_using_RC6 : CAPA T1027 E1027_m05 C0027_010  { 
  meta: 
 	description = "encrypt data using RC6 (converted from capa rule)"
	namespace = "data-manipulation/encryption/rc6"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::RC6 [C0027.010]"
	hash = "D87BA0BFCE1CDB17FD243B8B1D247E88"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/rc6/encrypt-data-using-rc6.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_avd = { 63 51 E1 B7 }
	$num_ave = { B9 79 37 9E }
	$num_avf = { 47 86 C8 61 }
 
  condition:
    capa_pe_file and
 (
		$num_avd 
		and  (
		$num_ave 
		or $num_avf  
	)  
	) 
}

private rule capa_encrypt_data_using_twofish : CAPA T1027 E1027_m05 C0027_005  { 
  meta: 
 	description = "encrypt data using twofish (converted from capa rule)"
	namespace = "data-manipulation/encryption/twofish"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::Twofish [C0027.005]"
	hash = "0761142efbda6c4b1e801223de723578"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/twofish/encrypt-data-using-twofish.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$avg = { A9 67 B3 E8 04 FD A3 76 9A 92 80 78 E4 DD D1 38 0D C6 35 98 18 F7 EC 6C 43 75 37 26 FA 13 94 48 F2 D0 8B 30 84 54 DF 23 19 5B 3D 59 F3 AE A2 82 63 01 83 2E D9 51 9B 7C A6 EB A5 BE 16 0C E3 61 C0 8C 3A F5 73 2C 25 0B BB 4E 89 6B 53 6A B4 F1 E1 E6 BD 45 E2 F4 B6 66 CC 95 03 56 D4 1C 1E D7 FB C3 8E B5 E9 CF BF BA EA 77 39 AF 33 C9 62 71 81 79 09 AD 24 CD F9 D8 E5 C5 B9 4D 44 08 86 E7 A1 1D AA ED 06 70 B2 D2 41 7B A0 11 31 C2 27 90 20 F6 60 FF 96 5C B1 AB 9E 9C 52 1B 5F 93 0A EF 91 85 49 EE 2D 4F 8F 3B 47 87 6D } // Q0
	$avh = { 75 F3 C6 F4 DB 7B FB C8 4A D3 E6 6B 45 7D E8 4B D6 32 D8 FD 37 71 F1 E1 30 0F F8 1B 87 FA 06 3F 5E BA AE 5B 8A 00 BC 9D 6D C1 B1 0E 80 5D D2 D5 A0 84 07 14 B5 90 2C A3 B2 73 4C 54 92 74 36 51 38 B0 BD 5A FC 60 62 96 6C 42 F7 10 7C 28 27 8C 13 95 9C C7 24 46 3B 70 CA E3 85 CB 11 D0 93 B8 A6 83 20 FF 9F 77 C3 CC 03 6F 08 BF 40 E7 2B E2 79 0C AA 82 41 3A EA B9 E4 9A A4 97 7E DA 7A 17 66 94 A1 1D 3D F0 DE B3 0B 72 A7 1C EF D1 53 3E 8F 33 26 5F EC 76 2A 49 81 88 EE 21 C4 1A EB D9 C5 39 99 CD AD 31 8B 01 18 23 DD } // Q1
	$avi = { 75 32 BC BC F3 21 EC EC C6 43 20 20 F4 C9 B3 B3 DB 03 DA DA 7B 8B 02 02 FB 2B E2 E2 C8 FA 9E 9E 4A EC C9 C9 D3 09 D4 D4 E6 6B 18 18 6B 9F 1E 1E 45 0E 98 98 7D 38 B2 B2 E8 D2 A6 A6 4B B7 26 26 D6 57 3C 3C 32 8A 93 93 D8 EE 82 82 FD 98 52 52 37 D4 7B 7B 71 37 BB BB F1 97 5B 5B E1 83 47 47 30 3C 24 24 0F E2 51 51 F8 C6 BA BA 1B F3 4A 4A 87 48 BF BF FA 70 0D 0D 06 B3 B0 B0 3F DE 75 75 5E FD D2 D2 BA 20 7D 7D AE 31 66 66 5B A3 3A 3A 8A 1C 59 59 00 00 00 00 BC 93 CD CD 9D E0 1A 1A 6D 2C AE AE C1 AB 7F 7F B1 C7 2B } // MDS1
	$avj = { 39 39 D9 A9 17 17 90 67 9C 9C 71 B3 A6 A6 D2 E8 07 07 05 04 52 52 98 FD 80 80 65 A3 E4 E4 DF 76 45 45 08 9A 4B 4B 02 92 E0 E0 A0 80 5A 5A 66 78 AF AF DD E4 6A 6A B0 DD 63 63 BF D1 2A 2A 36 38 E6 E6 54 0D 20 20 43 C6 CC CC 62 35 F2 F2 BE 98 12 12 1E 18 EB EB 24 F7 A1 A1 D7 EC 41 41 77 6C 28 28 BD 43 BC BC 32 75 7B 7B D4 37 88 88 9B 26 0D 0D 70 FA 44 44 F9 13 FB FB B1 94 7E 7E 5A 48 03 03 7A F2 8C 8C E4 D0 B6 B6 47 8B 24 24 3C 30 E7 E7 A5 84 6B 6B 41 54 DD DD 06 DF 60 60 C5 23 FD FD 45 19 3A 3A A3 5B C2 C2 68 } // MDS2
	$avk = { 32 BC 75 BC 21 EC F3 EC 43 20 C6 20 C9 B3 F4 B3 03 DA DB DA 8B 02 7B 02 2B E2 FB E2 FA 9E C8 9E EC C9 4A C9 09 D4 D3 D4 6B 18 E6 18 9F 1E 6B 1E 0E 98 45 98 38 B2 7D B2 D2 A6 E8 A6 B7 26 4B 26 57 3C D6 3C 8A 93 32 93 EE 82 D8 82 98 52 FD 52 D4 7B 37 7B 37 BB 71 BB 97 5B F1 5B 83 47 E1 47 3C 24 30 24 E2 51 0F 51 C6 BA F8 BA F3 4A 1B 4A 48 BF 87 BF 70 0D FA 0D B3 B0 06 B0 DE 75 3F 75 FD D2 5E D2 20 7D BA 7D 31 66 AE 66 A3 3A 5B 3A 1C 59 8A 59 00 00 00 00 93 CD BC CD E0 1A 9D 1A 2C AE 6D AE AB 7F C1 7F C7 2B B1 } // MDS3
	$avl = { D9 A9 39 D9 90 67 17 90 71 B3 9C 71 D2 E8 A6 D2 05 04 07 05 98 FD 52 98 65 A3 80 65 DF 76 E4 DF 08 9A 45 08 02 92 4B 02 A0 80 E0 A0 66 78 5A 66 DD E4 AF DD B0 DD 6A B0 BF D1 63 BF 36 38 2A 36 54 0D E6 54 43 C6 20 43 62 35 CC 62 BE 98 F2 BE 1E 18 12 1E 24 F7 EB 24 D7 EC A1 D7 77 6C 41 77 BD 43 28 BD 32 75 BC 32 D4 37 7B D4 9B 26 88 9B 70 FA 0D 70 F9 13 44 F9 B1 94 FB B1 5A 48 7E 5A 7A F2 03 7A E4 D0 8C E4 47 8B B6 47 3C 30 24 3C A5 84 E7 A5 41 54 6B 41 06 DF DD 06 C5 23 60 C5 45 19 FD 45 A3 5B 3A A3 68 3D C2 } // MDS4
	$avm = { 01 02 04 08 10 20 40 80 4D 9A 79 F2 A9 1F 3E 7C F8 BD 37 6E DC F5 A7 03 06 0C 18 30 60 C0 CD D7 E3 8B 5B B6 21 42 84 45 8A 59 B2 29 52 A4 05 0A 14 28 50 A0 0D 1A 34 68 D0 ED 97 63 C6 C1 CF D3 EB 9B 7B F6 A1 0F 1E 3C 78 F0 AD 17 2E 5C B8 3D 7A F4 A5 07 0E 1C 38 70 E0 8D 57 AE 11 22 44 88 5D BA 39 72 E4 85 47 8E 51 A2 09 12 24 48 90 6D DA F9 BF 33 66 CC D5 E7 83 4B 96 61 C2 C9 DF F3 AB 1B 36 6C D8 FD B7 23 46 8C 55 AA 19 32 64 C8 DD F7 A3 0B 16 2C 58 B0 2D 5A B4 25 4A 94 65 CA D9 FF B3 2B 56 AC 15 2A 54 A8 1D } // EXP_TO_POLY
	$avn = { A9 75 67 F3 B3 C6 E8 F4 04 DB FD 7B A3 FB 76 C8 9A 4A 92 D3 80 E6 78 6B E4 45 DD 7D D1 E8 38 4B 0D D6 C6 32 35 D8 98 FD 18 37 F7 71 EC F1 6C E1 43 30 75 0F 37 F8 26 1B FA 87 13 FA 94 06 48 3F F2 5E D0 BA 8B AE 30 5B 84 8A 54 00 DF BC 23 9D 19 6D 5B C1 3D B1 59 0E F3 80 AE 5D A2 D2 82 D5 63 A0 01 84 83 07 2E 14 D9 B5 51 90 9B 2C 7C A3 A6 B2 EB 73 A5 4C BE 54 16 92 0C 74 E3 36 61 51 C0 38 8C B0 3A BD F5 5A 73 FC 2C 60 25 62 0B 96 BB 6C 4E 42 89 F7 6B 10 53 7C 6A 28 B4 27 F1 8C E1 13 E6 95 BD 9C 45 C7 E2 24 F4 } // CALC_SB_TBL
 
  condition:
    capa_pe_file and
 (
			$avg 
		or 	$avh 
		or 	$avi 
		or 	$avj 
		or 	$avk 
		or 	$avl 
		or 	$avm 
		or 	$avn  
	) 
}

private rule capa_encrypt_data_using_AES_via__NET : CAPA T1027 E1027_m05 C0027_001  { 
  meta: 
 	description = "encrypt data using AES via .NET (converted from capa rule)"
	namespace = "data-manipulation/encryption/aes"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::AES [C0027.001]"
	hash = "b9f5bd514485fb06da39beff051b9fdc"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/aes/encrypt-data-using-aes-via-net.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_awg = "RijndaelManaged" ascii wide
	$str_awh = "CryptoStream" ascii wide
	$str_awi = "System.Security.Cryptography" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_awg 
		and 	$str_awh 
		and 	$str_awi  
	) 
}

private rule capa_encrypt_data_using_skipjack : CAPA T1027 E1027_m05 C0027_013  { 
  meta: 
 	description = "encrypt data using skipjack (converted from capa rule)"
	namespace = "data-manipulation/encryption/skipjack"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::Skipjack [C0027.013]"
	hash = "94d3c854aadbcfde46b2f82801015c31"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/skipjack/encrypt-data-using-skipjack.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$awj = { A3 D7 09 83 F8 48 F6 F4 B3 21 15 78 99 B1 AF F9 E7 2D 4D 8A CE 4C CA 2E 52 95 D9 1E 4E 38 44 28 0A DF 02 A0 17 F1 60 68 12 B7 7A C3 E9 FA 3D 53 96 84 6B BA F2 63 9A 19 7C AE E5 F5 F7 16 6A A2 39 B6 7B 0F C1 93 81 1B EE B4 1A EA D0 91 2F B8 55 B9 DA 85 3F 41 BF E0 5A 58 80 5F 66 0B D8 90 35 D5 C0 A7 33 06 65 69 45 00 94 56 6D 98 9B 76 97 FC B2 C2 B0 FE DB 20 E1 EB D6 E4 DD 47 4A 1D 42 ED 9E 6E 49 3C CD 43 27 D2 07 D4 DE C7 67 18 89 CB 30 1F 8D C6 8F AA C8 74 DC C9 5D 5C 31 A4 70 88 61 2C 9F 0D 2B 87 50 82 54 64 26 7D 03 40 34 4B 1C 73 D1 C4 FD 3B CC FB 7F AB E6 3E 5B A5 AD 04 23 9C 14 51 22 F0 29 79 71 7E FF 8C 0E E2 0C EF BC 72 75 6F 37 A1 EC D3 8E 62 8B 86 10 E8 08 77 11 BE 92 4F 24 C5 32 36 9D CF F3 A6 BB AC 5E 6C A9 13 57 25 B5 E3 BD A8 3A 01 05 59 2A 46 } // FTable
 
  condition:
    capa_pe_file and
 (
			$awj  
	) 
}

private rule capa_reference_public_RSA_key : CAPA C0028  { 
  meta: 
 	description = "reference public RSA key (converted from capa rule)"
	namespace = "data-manipulation/encryption/rsa"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Encryption Key [C0028]"
	hash = "b7b5e1253710d8927cbe07d52d2d2e10"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/rsa/reference-public-rsa-key.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$awk = { 06 02 00 00 00 A4 00 00 52 53 41 31 }
 
  condition:
    capa_pe_file and
 (
			$awk  
	) 
}

private rule capa_encrypt_data_using_vest : CAPA T1027 E1027_m05 C0027  { 
  meta: 
 	description = "encrypt data using vest (converted from capa rule)"
	namespace = "data-manipulation/encryption/vest"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data [C0027]"
	references = "https://www.ecrypt.eu.org/stream/vest.html"
	hash = "9a00ebe67d833edb70ed6dd0f4652592"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/vest/encrypt-data-using-vest.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$awl = { 07 56 D2 37 3A F7 0A 52 5D C6 2C 87 DA 05 C1 D7 F4 1F 8C 34 } // vest_sbox
	$awm = { 41 4B 1B DD 0D 65 72 EE 09 E7 A1 93 3F 0E 55 9C 63 89 3F B2 AB 5A 0E CB 2F 13 E3 9A C7 09 C5 8D C9 09 0D D7 59 1F A2 D6 CB B0 61 E5 39 44 F8 C5 8B C6 E5 B2 BD E3 82 D2 AB 04 DD D6 1F 94 CA EC 73 43 E7 94 5D 52 66 86 4F 4B 05 D4 AD 0F 66 A3 F9 15 9C C6 C9 3E 3A B8 9D 31 65 F8 C7 9A CE E0 6D BD 18 8D 63 F5 0A CD 11 B4 B5 EE 9B 28 9C A5 93 78 5B D1 D3 B1 2B 84 17 AB F4 85 EF 22 E1 D1 } // rns_f
	$awn = { 4F 70 46 DA E1 8D F6 41 59 E8 5D 26 1E CC 2F 89 26 6D 52 BA BC 11 6B A9 C6 47 E4 9C 1E B6 65 A2 B6 CD 90 47 1C DF F8 10 4B D2 7C C4 72 25 C6 97 25 5D C6 1D 4B 36 BC 38 36 33 F8 89 B4 4C 65 A7 96 CA 1B 63 C3 4B 6A 63 DC 85 4C 57 EE 2A 05 C7 0C E7 39 35 8A C1 BF 13 D9 52 51 3D 2E 41 F5 72 85 23 FE A1 AA 53 61 3B 25 5F 62 B4 36 EE 2A 51 AF 18 8E 9A C6 CF C4 07 4A 9B 25 9B 76 62 0E 3E 96 3A A7 64 23 6B B6 19 BC 2D 40 D7 36 3E E2 85 9A D1 22 9F BC 30 15 9F C2 5D F1 23 E6 3A 73 C0 A6 AD 71 B0 94 1C 9D B6 56 B6 2B } // vest_f
 
  condition:
    capa_pe_file and
 (
			$awl 
		or 	$awm 
		or 	$awn  
	) 
}

private rule capa_encrypt_data_using_blowfish : CAPA T1027 E1027_m05 C0027_002  { 
  meta: 
 	description = "encrypt data using blowfish (converted from capa rule)"
	namespace = "data-manipulation/encryption/blowfish"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::Blowfish [C0027.002]"
	hash = "0761142efbda6c4b1e801223de723578"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/blowfish/encrypt-data-using-blowfish.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_awp = { 37 CE 39 3A } // u32 ks3 sbox4
	$num_awq = { 68 5A 3D E9 } // u32 ks2 sbox3
	$num_awr = { E9 70 7A 4B } // u32 ks1 sbox2
	$num_aws = { A6 0B 31 D1 } // u32 ks0 sbox1
	$awt = { 88 6A 3F 24 D3 08 A3 85 2E 8A 19 13 44 73 70 03 22 38 09 A4 D0 31 9F 29 98 FA 2E 08 89 6C 4E EC E6 21 28 45 77 13 D0 38 CF 66 54 BE 6C 0C E9 34 B7 29 AC C0 DD 50 7C C9 B5 D5 84 3F 17 09 47 B5 D9 D5 16 92 1B FB 79 89 } // ps
	$awu = { A6 0B 31 D1 AC B5 DF 98 DB 72 FD 2F B7 DF 1A D0 ED AF E1 B8 96 7E 26 6A 45 90 7C BA 99 7F 2C F1 47 99 A1 24 F7 6C 91 B3 E2 F2 01 08 16 FC 8E 85 D8 20 69 63 69 4E 57 71 A3 FE 58 A4 7E 3D 93 F4 8F 74 95 0D 58 B6 8E 72 58 CD 8B 71 EE 4A 15 82 1D A4 54 7B B5 59 5A C2 39 D5 30 9C 13 60 F2 2A 23 B0 D1 C5 F0 85 60 28 18 79 41 CA EF 38 DB B8 B0 DC 79 8E 0E 18 3A 60 8B 0E 9E 6C 3E 8A 1E B0 C1 77 15 D7 27 4B 31 BD DA 2F AF 78 60 5C 60 55 F3 25 55 E6 94 AB 55 AA 62 98 48 57 40 14 E8 63 6A 39 CA 55 B6 10 AB 2A 34 5C CC } // ks0 sbox1
	$awv = { E9 70 7A 4B 44 29 B3 B5 2E 09 75 DB 23 26 19 C4 B0 A6 6E AD 7D DF A7 49 B8 60 EE 9C 66 B2 ED 8F 71 8C AA EC FF 17 9A 69 6C 52 64 56 E1 9E B1 C2 A5 02 36 19 29 4C 09 75 40 13 59 A0 3E 3A 18 E4 9A 98 54 3F 65 9D 42 5B D6 E4 8F 6B D6 3F F7 99 07 9C D2 A1 F5 30 E8 EF E6 38 2D 4D C1 5D 25 F0 86 20 DD 4C 26 EB 70 84 C6 E9 82 63 5E CC 1E 02 3F 6B 68 09 C9 EF BA 3E 14 18 97 3C A1 70 6A 6B 84 35 7F 68 86 E2 A0 52 05 53 9C B7 37 07 50 AA 1C 84 07 3E 5C AE DE 7F EC 44 7D 8E B8 F2 16 57 37 DA 3A B0 0D 0C 50 F0 04 1F 1C } // ks1 sbox2
	$aww = { 68 5A 3D E9 F7 40 81 94 1C 26 4C F6 34 29 69 94 F7 20 15 41 F7 D4 02 76 2E 6B F4 BC 68 00 A2 D4 71 24 08 D4 6A F4 20 33 B7 D4 B7 43 AF 61 00 50 2E F6 39 1E 46 45 24 97 74 4F 21 14 40 88 8B BF 1D FC 95 4D AF 91 B5 96 D3 DD F4 70 45 2F A0 66 EC 09 BC BF 85 97 BD 03 D0 6D AC 7F 04 85 CB 31 B3 27 EB 96 41 39 FD 55 E6 47 25 DA 9A 0A CA AB 25 78 50 28 F4 29 04 53 DA 86 2C 0A FB 6D B6 E9 62 14 DC 68 00 69 48 D7 A4 C0 0E 68 EE 8D A1 27 A2 FE 3F 4F 8C AD 87 E8 06 E0 8C B5 B6 D6 F4 7A 7C 1E CE AA EC 5F 37 D3 99 A3 78 } // ks2 sbox3
	$awx = { 37 CE 39 3A CF F5 FA D3 37 77 C2 AB 1B 2D C5 5A 9E 67 B0 5C 42 37 A3 4F 40 27 82 D3 BE 9B BC 99 9D 8E 11 D5 15 73 0F BF 7E 1C 2D D6 7B C4 00 C7 6B 1B 8C B7 45 90 A1 21 BE B1 6E B2 B4 6E 36 6A 2F AB 48 57 79 6E 94 BC D2 76 A3 C6 C8 C2 49 65 EE F8 0F 53 7D DE 8D 46 1D 0A 73 D5 C6 4D D0 4C DB BB 39 29 50 46 BA A9 E8 26 95 AC 04 E3 5E BE F0 D5 FA A1 9A 51 2D 6A E2 8C EF 63 22 EE 86 9A B8 C2 89 C0 F6 2E 24 43 AA 03 1E A5 A4 D0 F2 9C BA 61 C0 83 4D 6A E9 9B 50 15 E5 8F D6 5B 64 BA F9 A2 26 28 E1 3A 3A A7 86 95 A9 } // ks3 sbox4
 
  condition:
    capa_pe_file and
 (
		 (
		$num_awp 
		and $num_awq 
		and $num_awr 
		and $num_aws  
	) 
		or  (
			$awt 
		or 	$awu 
		or 	$awv 
		or 	$aww 
		or 	$awx  
	)  
	) 
}

private rule capa_generate_random_numbers_via_WinAPI : CAPA C0021_003  { 
  meta: 
 	description = "generate random numbers via WinAPI (converted from capa rule)"
	namespace = "data-manipulation/prng"
	author = "michael.hunhoff@fireeye.com"
	author = "johnk3r"
	scope = "function"
	mbc = "Cryptography::Generate Pseudo-random Sequence::Use API [C0021.003]"
	hash = "ba947eb07d8c823949316a97364d060f"
	hash = "3ca359f5085bb96a7950d4735b089ffe"
	hash = "e59ffeaf7acb0c326e452fa30bb71a36"
	hash = "1195d0d18be9362fb8dd9e1738404c9d"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/prng/generate-random-numbers-via-winapi.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_awy = /\bBCryptGenRandom(A|W)?\b/ ascii wide
	$api_awz = /\bCryptGenRandom(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$api_awy 
		or 	$api_awz  
	)  
	) 
}

private rule capa_generate_random_numbers_using_a_Mersenne_Twister : CAPA C0021_005  { 
  meta: 
 	description = "generate random numbers using a Mersenne Twister (converted from capa rule)"
	namespace = "data-manipulation/prng/mersenne"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Generate Pseudo-random Sequence::Mersenne Twister [C0021.005]"
	hash = "D9630C174B8FF5C0AA26168DF523E63E"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/prng/mersenne/generate-random-numbers-using-a-mersenne-twister.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_axa = { 65 89 07 6C }
	$num_axb = { DF B0 08 99 }
	$num_axc = { 80 56 2C 9D }
	$num_axd = { 00 00 C6 EF }
	$num_axe = { AD 58 3A FF }
	$num_axf = { E9 19 66 A9 5A 6F 02 B5 }
	$num_axg = { 00 00 A6 ED FF 7F D6 71 }
 
  condition:
    capa_pe_file and
 (
		$num_axa 
		or $num_axb 
		or $num_axc 
		or $num_axd 
		or $num_axe 
		or $num_axf 
		or $num_axg  
	) 
}

private rule capa_compress_data_via_WinAPI : CAPA T1560_002 C0024  { 
  meta: 
 	description = "compress data via WinAPI (converted from capa rule)"
	namespace = "data-manipulation/compression"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Collection::Archive Collected Data::Archive via Library [T1560.002]"
	mbc = "Data::Compress Data [C0024]"
	hash = "638dcc3d37b3a574044233c9637d7288"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/compression/compress-data-via-winapi.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_axj = /\bRtlDecompressBuffer(A|W)?\b/ ascii wide
	$str_axk = "RtlDecompressBuffer" ascii wide
	$api_axl = /\bRtlDecompressBufferEx(A|W)?\b/ ascii wide
	$str_axm = "RtlDecompressBufferEx" ascii wide
	$api_axn = /\bRtlDecompressBufferEx2(A|W)?\b/ ascii wide
	$str_axo = "RtlDecompressBufferEx2" ascii wide
	$api_axp = /\bRtlCompressBuffer(A|W)?\b/ ascii wide
	$str_axq = "RtlCompressBuffer" ascii wide
	$api_axr = /\bRtlCompressBufferLZNT1(A|W)?\b/ ascii wide
	$str_axs = "RtlCompressBufferLZNT1" ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_axj 
		or 	$str_axk 
		or 	$api_axl 
		or 	$str_axm 
		or 	$api_axn 
		or 	$str_axo 
		or 	$api_axp 
		or 	$str_axq 
		or 	$api_axr 
		or 	$str_axs  
	) 
}

private rule capa_hash_data_via_WinCrypt : CAPA C0029  { 
  meta: 
 	description = "hash data via WinCrypt (converted from capa rule)"
	namespace = "data-manipulation/hashing"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Cryptographic Hash [C0029]"
	hash = "03B236B23B1EC37C663527C1F53AF3FE"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/hash-data-via-wincrypt.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /CryptHashData/)  
	) 
}

private rule capa_hash_data_using_SHA256 : CAPA C0029_003  { 
  meta: 
 	description = "hash data using SHA256 (converted from capa rule)"
	namespace = "data-manipulation/hashing/sha256"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Cryptographic Hash::SHA256 [C0029.003]"
	hash = "C0CFFCF211035A839E28D542DE300298"
	hash = "6CC148363200798A12091B97A17181A1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/sha256/hash-data-using-sha256.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_axt = { 67 E6 09 6A }
	$num_axu = { 85 AE 67 BB }
	$num_axv = { 72 F3 6E 3C }
	$num_axw = { 3A F5 4F A5 }
	$num_axx = { 7F 52 0E 51 }
	$num_axy = { 8C 68 05 9B }
	$num_axz = { AB D9 83 1F }
	$num_aya = { 19 CD E0 5B }
 
  condition:
    capa_pe_file and
 (
		$num_axt 
		and $num_axu 
		and $num_axv 
		and $num_axw 
		and $num_axx 
		and $num_axy 
		and $num_axz 
		and $num_aya  
	) 
}

private rule capa_hash_data_using_SHA224 : CAPA C0029_004  { 
  meta: 
 	description = "hash data using SHA224 (converted from capa rule)"
	namespace = "data-manipulation/hashing/sha224"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Cryptographic Hash::SHA224 [C0029.004]"
	hash = "6CC148363200798A12091B97A17181A1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/sha224/hash-data-using-sha224.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_ayz = { D8 9E 05 C1 }
	$num_aza = { 07 D5 7C 36 }
	$num_azb = { 17 DD 70 30 }
	$num_azc = { 39 59 0E F7 }
	$num_azd = { 31 0B C0 FF }
	$num_aze = { 11 15 58 68 }
	$num_azf = { A7 8F F9 64 }
	$num_azg = { A4 4F FA BE }
 
  condition:
    capa_pe_file and
 (
		$num_ayz 
		and $num_aza 
		and $num_azb 
		and $num_azc 
		and $num_azd 
		and $num_aze 
		and $num_azf 
		and $num_azg  
	) 
}

private rule capa_schedule_task_via_command_line : CAPA T1053_005  { 
  meta: 
 	description = "schedule task via command line (converted from capa rule)"
	namespace = "persistence/scheduled-tasks"
	author = "0x534a@mailbox.org"
	scope = "function"
	attack = "Persistence::Scheduled Task/Job::Scheduled Task [T1053.005]"
	hash = "79cde1aa711e321b4939805d27e160be"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/scheduled-tasks/schedule-task-via-command-line.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_azh = /schtasks/ nocase ascii wide 
	$re_azi = /\/create / nocase ascii wide 
	$re_azj = /Register-ScheduledTask / nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			capa_create_process

		and  (
		 (
			$re_azh 
		and 	$re_azi  
	) 
		or 	$re_azj  
	)  
	) 
}

private rule capa_persist_via_Active_Setup_registry_key : CAPA T1547_014  { 
  meta: 
 	description = "persist via Active Setup registry key (converted from capa rule)"
	namespace = "persistence/registry"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Boot or Logon Autostart Execution::Active Setup [T1547.014]"
	references = "https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html"
	hash = "c335a9d41185a32ad918c5389ee54235"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/persist-via-active-setup-registry-key.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_azm = { 02 00 00 80 } // HKEY_LOCAL_MACHINE
	$re_azn = /Software\\Microsoft\\Active Setup\\Installed Components/ nocase ascii wide 
	$str_azo = "StubPath" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			capa_set_registry_value

		or $num_azm  
	) 
		and 	$re_azn 
		and 	$str_azo  
	) 
}

private rule capa_persist_via_GinaDLL_registry_key : CAPA T1546  { 
  meta: 
 	description = "persist via GinaDLL registry key (converted from capa rule)"
	namespace = "persistence/registry/ginadll"
	author = "michael.hunhoff@fireye.com"
	scope = "function"
	attack = "Persistence::Event Triggered Execution [T1546]"
	hash = "Practical Malware Analysis Lab 11-01.exe_:0x401000"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/ginadll/persist-via-ginadll-registry-key.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_azp = { 02 00 00 80 } // HKEY_LOCAL_MACHINE
	$re_azq = /SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon/ nocase ascii wide 
	$re_azr = /GinaDLL/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			capa_set_registry_value

		or $num_azp  
	) 
		and 	$re_azq 
		and 	$re_azr  
	) 
}

private rule capa_persist_via_AppInit_DLLs_registry_key : CAPA T1546_010  { 
  meta: 
 	description = "persist via AppInit_DLLs registry key (converted from capa rule)"
	namespace = "persistence/registry/appinitdlls"
	author = "michael.hunhoff@fireye.com"
	scope = "function"
	attack = "Persistence::Event Triggered Execution::AppInit DLLs [T1546.010]"
	references = "https://docs.microsoft.com/en-us/windows/win32/win7appqual/appinit-dlls-in-windows-7-and-windows-server-2008-r2"
	hash = "Practical Malware Analysis Lab 11-02.dll_:0x1000158b"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/appinitdlls/persist-via-appinit_dlls-registry-key.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_azs = { 02 00 00 80 } // HKEY_LOCAL_MACHINE
	$re_azt = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows/ nocase ascii wide 
	$re_azu = /Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows/ nocase ascii wide 
	$re_azv = /AppInit_DLLs/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			capa_set_registry_value

		or $num_azs  
	) 
		and  (
			$re_azt 
		or 	$re_azu  
	) 
		and 	$re_azv  
	) 
}

private rule capa_persist_via_Run_registry_key : CAPA T1547_001  { 
  meta: 
 	description = "persist via Run registry key (converted from capa rule)"
	namespace = "persistence/registry/run"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]"
	hash = "Practical Malware Analysis Lab 06-03.exe_:0x401130"
	hash = "b87e9dd18a5533a09d3e48a7a1efbcf6"
	hash = "9ff8e68343cc29c1036650fc153e69f7"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/run/persist-via-run-registry-key.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_azx = { 01 00 00 80 } // HKEY_CURRENT_USER
	$num_azy = { 02 00 00 80 } // HKEY_LOCAL_MACHINE
	$re_azz = /Software\\Microsoft\\Windows\\CurrentVersion/ nocase ascii wide 
	$re_baa = /Run/ nocase ascii wide 
	$re_bab = /Explorer\\Shell Folders/ nocase ascii wide 
	$re_bac = /User Shell Folders/ nocase ascii wide 
	$re_bad = /RunServices/ nocase ascii wide 
	$re_bae = /Policies\\Explorer\\Run/ nocase ascii wide 
	$re_baf = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load/ nocase ascii wide 
	$re_bag = /System\\CurrentControlSet\\Control\\Session Manager\\BootExecute/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			capa_set_registry_value

		or $num_azx 
		or $num_azy  
	) 
		and  (
		 (
			$re_azz 
		and  (
			$re_baa 
		or 	$re_bab 
		or 	$re_bac 
		or 	$re_bad 
		or 	$re_bae  
	)  
	) 
		or 	$re_baf 
		or 	$re_bag  
	)  
	) 
}

private rule capa_persist_via_Winlogon_Helper_DLL_registry_key : CAPA T1547_004  { 
  meta: 
 	description = "persist via Winlogon Helper DLL registry key (converted from capa rule)"
	namespace = "persistence/registry/winlogon-helper"
	author = "0x534a@mailbox.org"
	scope = "function"
	attack = "Persistence::Boot or Logon Autostart Execution::Winlogon Helper DLL [T1547.004]"
	hash = "9ff8e68343cc29c1036650fc153e69f7"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/winlogon-helper/persist-via-winlogon-helper-dll-registry-key.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_bah = { 01 00 00 80 } // HKEY_CURRENT_USER
	$num_bai = { 02 00 00 80 } // HKEY_LOCAL_MACHINE
	$re_baj = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon/ nocase ascii wide 
	$re_bak = /Notify/ nocase ascii wide 
	$re_bal = /Userinit/ nocase ascii wide 
	$re_bam = /Shell/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			capa_set_registry_value

		or $num_bah 
		or $num_bai  
	) 
		and 	$re_baj 
		and  (
			$re_bak 
		or 	$re_bal 
		or 	$re_bam  
	)  
	) 
}

private rule capa_compiled_to_the__NET_platform : CAPA  { 
  meta: 
 	description = "compiled to the .NET platform (converted from capa rule)"
	namespace = "runtime/dotnet"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	hash = "b9f5bd514485fb06da39beff051b9fdc"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/runtime/dotnet/compiled-to-the-net-platform.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/mscoree/i, /_CorExeMain/) 
		or 	pe.imports(/mscoree/i, /_corexemain/) 
		or 	pe.imports(/mscoree/i, /_CorDllMain/) 
		or 	pe.imports(/mscoree/i, /_cordllmain/)  
	) 
}

private rule capa_get_COMSPEC_environment_variable : CAPA  { 
  meta: 
 	description = "get COMSPEC environment variable (converted from capa rule)"
	namespace = "host-interaction/environment-variable"
	author = "matthew.williams@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-comspec-environment-variable.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_ban = "COMSPEC" ascii wide
	$str_bao = "%COMSPEC%" ascii wide
 
  condition:
    capa_pe_file and
 (
			capa_query_environment_variable

		and  (
			$str_ban 
		or 	$str_bao  
	)  
	) 
}

private rule capa_packed_with_MaskPE : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with MaskPE (converted from capa rule)"
	namespace = "anti-analysis/packer/maskpe"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-maskpe.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bap in pe.sections : ( bap.name == ".MaskPE" )  
	) 
}

private rule capa_add_file_to_cabinet_file : CAPA  { 
  meta: 
 	description = "add file to cabinet file (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	references = "https://docs.microsoft.com/en-us/windows/win32/msi/cabinet-files"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/add-file-to-cabinet-file.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/cabinet/i, /FCIAddFile/)  
	) 
}

private rule capa_reference_Quad9_DNS_server : CAPA  { 
  meta: 
 	description = "reference Quad9 DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-quad9-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_baq = "9.9.9.9" ascii wide
	$str_bar = "149.112.112.112" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_baq 
		or 	$str_bar  
	) 
}

private rule capa_run_PowerShell_expression : CAPA T1059_001  { 
  meta: 
 	description = "run PowerShell expression (converted from capa rule)"
	namespace = "load-code/powershell/"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	attack = "Execution::Command and Scripting Interpreter::PowerShell [T1059.001]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/run-powershell-expression.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bas = / iex\(/ nocase ascii wide 
	$re_bat = / iex / nocase ascii wide 
	$re_bau = /Invoke-Expression/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			$re_bas 
		or 	$re_bat 
		or 	$re_bau  
	)  
	) 
}

private rule capa_get_file_size : CAPA T1083  { 
  meta: 
 	description = "get file size (converted from capa rule)"
	namespace = "host-interaction/file-system/meta"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::File and Directory Discovery [T1083]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-file-size.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /GetFileSize/) 
		or 	pe.imports(/kernel32/i, /GetFileSizeEx/)  
	) 
}

private rule capa_open_cabinet_file : CAPA  { 
  meta: 
 	description = "open cabinet file (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	references = "https://docs.microsoft.com/en-us/windows/win32/msi/cabinet-files"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/open-cabinet-file.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/cabinet/i, /FCICreate/)  
	) 
}

private rule capa_packed_with_Dragon_Armor : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with Dragon Armor (converted from capa rule)"
	namespace = "anti-analysis/packer/dragon-armor"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-dragon-armor.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bav in pe.sections : ( bav.name == "DAStub" )  
	) 
}

private rule capa_hooked_by_API_Override : CAPA  { 
  meta: 
 	description = "hooked by API Override (converted from capa rule)"
	namespace = "executable/hooked/api-override"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
	references = "http://jacquelin.potier.free.fr/winapioverride32/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/hooked-by-api-override.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any baw in pe.sections : ( baw.name == ".winapi" )  
	) 
}

private rule capa_get_service_handle : CAPA  { 
  meta: 
 	description = "get service handle (converted from capa rule)"
	author = "moritz.raabe@fireeye.com"
	lib = "True"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-service-handle.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /CreateService/) 
		or 	pe.imports(/advapi32/i, /OpenService/)  
	) 
}

private rule capa_packed_with_Neolite : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with Neolite (converted from capa rule)"
	namespace = "anti-analysis/packer/neolite"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-neolite.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bax in pe.sections : ( bax.name == ".neolite" ) 
		or 	for any bay in pe.sections : ( bay.name == ".neolit" )  
	) 
}

private rule capa_encrypt_data_using_Salsa20_or_ChaCha : CAPA T1027  { 
  meta: 
 	description = "encrypt data using Salsa20 or ChaCha (converted from capa rule)"
	namespace = "data-manipulation/encryption/salsa20"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	references = "http://cr.yp.to/snuffle/ecrypt.c"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/encrypt-data-using-salsa20-or-chacha.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	 // part of key setup
	$str_baz = "expand 32-byte k = sigma" ascii wide
	$str_bba = "expand 16-byte k = tau" ascii wide
	$str_bbb = "expand 32-byte kexpand 16-byte k" ascii wide
	$str_bbc = "expa" ascii wide
	$str_bbd = "nd 3" ascii wide
	$str_bbe = "2-by" ascii wide
	$str_bbf = "te k" ascii wide
	$num_bbg = { 65 78 70 61 }
	$num_bbh = { 6E 64 20 33 }
	$num_bbi = { 32 2D 62 79 }
	$num_bbj = { 74 65 20 6B }
 
  condition:
    capa_pe_file and
 (
			$str_baz 
		or 	$str_bba 
		or 	$str_bbb 
		or  (
			$str_bbc 
		and 	$str_bbd 
		and 	$str_bbe 
		and 	$str_bbf  
	) 
		or  (
		$num_bbg 
		and $num_bbh 
		and $num_bbi 
		and $num_bbj  
	)  
	) 
}

private rule capa_listen_for_remote_procedure_calls : CAPA  { 
  meta: 
 	description = "listen for remote procedure calls (converted from capa rule)"
	namespace = "communication/rpc/server"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/listen-for-remote-procedure-calls.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/rpcrt4/i, /RpcServerListen/)  
	) 
}

private rule capa_enumerate_internet_cache : CAPA  { 
  meta: 
 	description = "enumerate internet cache (converted from capa rule)"
	namespace = "host-interaction/internet/cache"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/enumerate-internet-cache.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/wininet/i, /FindFirstUrlCacheEntry/)  
	) 
}

private rule capa_reference_Verisign_DNS_server : CAPA  { 
  meta: 
 	description = "reference Verisign DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-verisign-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bbm = "64.6.64.6" ascii wide
	$str_bbn = "64.6.65.6" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bbm 
		or 	$str_bbn  
	) 
}

private rule capa_packaged_as_a_NSIS_installer : CAPA  { 
  meta: 
 	description = "packaged as a NSIS installer (converted from capa rule)"
	namespace = "executable/installer/nsis"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	references = "https://nsis.sourceforge.io/Main_Page"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-nsis-installer.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bbo = /http:\/\/nsis\.sf\.net/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_bbo  
	) 
}

private rule capa_reference_AliDNS_DNS_server : CAPA  { 
  meta: 
 	description = "reference AliDNS DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.alidns.com/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-alidns-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bbp = "223.5.5.5" ascii wide
	$str_bbq = "223.6.6.6" ascii wide
	$str_bbr = "2400:3200::1" ascii wide
	$str_bbs = "2400:3200:baba::1" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bbp 
		or 	$str_bbq 
		or 	$str_bbr 
		or 	$str_bbs  
	) 
}

private rule capa_get_networking_parameters : CAPA T1016  { 
  meta: 
 	description = "get networking parameters (converted from capa rule)"
	namespace = "host-interaction/network"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-networking-parameters.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/iphlpapi/i, /GetNetworkParams/)  
	) 
}

private rule capa_packed_with_TSULoader : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with TSULoader (converted from capa rule)"
	namespace = "anti-analysis/packer/tsuloader"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-tsuloader.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bbx in pe.sections : ( bbx.name == ".tsuarch" ) 
		or 	for any bby in pe.sections : ( bby.name == ".tsustub" )  
	) 
}

private rule capa_packaged_as_a_WinZip_self_extracting_archive : CAPA  { 
  meta: 
 	description = "packaged as a WinZip self-extracting archive (converted from capa rule)"
	namespace = "executable/installer/winzip"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-winzip-self-extracting-archive.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bbz in pe.sections : ( bbz.name == "_winzip_" )  
	) 
}

private rule capa_get_file_version_info : CAPA T1083  { 
  meta: 
 	description = "get file version info (converted from capa rule)"
	namespace = "host-interaction/file-system/meta"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::File and Directory Discovery [T1083]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-file-version-info.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/version/i, /GetFileVersionInfo/) 
		or 	pe.imports(/version/i, /GetFileVersionInfoEx/)  
	)  
	) 
}

private rule capa_packed_with_RPCrypt : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with RPCrypt (converted from capa rule)"
	namespace = "anti-analysis/packer/rpcrypt"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-rpcrypt.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bcd in pe.sections : ( bcd.name == "RCryptor" ) 
		or 	for any bce in pe.sections : ( bce.name == ".RCrypt" )  
	) 
}

private rule capa_get_proxy : CAPA T1016  { 
  meta: 
 	description = "get proxy (converted from capa rule)"
	namespace = "host-interaction/network/proxy"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-proxy.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bcf = "ProxyServer" ascii wide
 
  condition:
    capa_pe_file and
 (
			capa_create_or_open_registry_key

		and 	$str_bcf  
	) 
}

private rule capa_reference_DNS_over_HTTPS_endpoints : CAPA  { 
  meta: 
 	description = "reference DNS over HTTPS endpoints (converted from capa rule)"
	namespace = "communication/dns"
	author = "markus.neis@swisscom.com / @markus_neis"
	scope = "file"
	references = "https://github.com/curl/curl/wiki/DNS-over-HTTPS"
	hash = "749e7becf00fccc6dff324a83976dc0d"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-dns-over-https-endpoints.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bcg = /https:\/\/doh.seby.io:8443\/dns-query.{,1000}/ nocase ascii wide 
	$re_bch = /https:\/\/family.cloudflare-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bci = /https:\/\/free.bravedns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bcj = /https:\/\/doh.familyshield.opendns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bck = /https:\/\/doh-de.blahdns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bcl = /https:\/\/adblock.mydns.network\/dns-query.{,1000}/ nocase ascii wide 
	$re_bcm = /https:\/\/bravedns.com\/configure.{,1000}/ nocase ascii wide 
	$re_bcn = /https:\/\/cloudflare-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bco = /https:\/\/commons.host.{,1000}/ nocase ascii wide 
	$re_bcp = /https:\/\/dns.aa.net.uk\/dns-query.{,1000}/ nocase ascii wide 
	$re_bcq = /https:\/\/dns.alidns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bcr = /https:\/\/dns-asia.wugui.zone\/dns-query.{,1000}/ nocase ascii wide 
	$re_bcs = /https:\/\/dns.containerpi.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bct = /https:\/\/dns.containerpi.com\/doh\/family-filter\/.{,1000}/ nocase ascii wide 
	$re_bcu = /https:\/\/dns.containerpi.com\/doh\/secure-filter\/.{,1000}/ nocase ascii wide 
	$re_bcv = /https:\/\/dns.digitale-gesellschaft.ch\/dns-query.{,1000}/ nocase ascii wide 
	$re_bcw = /https:\/\/dns.dnshome.de\/dns-query.{,1000}/ nocase ascii wide 
	$re_bcx = /https:\/\/dns.dns-over-https.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bcy = /https:\/\/dns.dnsoverhttps.net\/dns-query.{,1000}/ nocase ascii wide 
	$re_bcz = /https:\/\/dns.flatuslifir.is\/dns-query.{,1000}/ nocase ascii wide 
	$re_bda = /https:\/\/dnsforge.de\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdb = /https:\/\/dns.google\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdc = /https:\/\/dns.nextdns.io\/<config_id>.{,1000}/ nocase ascii wide 
	$re_bdd = /https:\/\/dns.rubyfish.cn\/dns-query.{,1000}/ nocase ascii wide 
	$re_bde = /https:\/\/dns.switch.ch\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdf = /https:\/\/dns.twnic.tw\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdg = /https:\/\/dns.wugui.zone\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdh = /https:\/\/doh-2.seby.io\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdi = /https:\/\/doh.42l.fr\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdj = /https:\/\/doh.applied-privacy.net\/query.{,1000}/ nocase ascii wide 
	$re_bdk = /https:\/\/doh.armadillodns.net\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdl = /https:\/\/doh.captnemo.in\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdm = /https:\/\/doh.centraleu.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdn = /https:\/\/doh.cleanbrowsing.org\/doh\/family-filter\/.{,1000}/ nocase ascii wide 
	$re_bdo = /https:\/\/doh.crypto.sx\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdp = /https:\/\/doh.dnslify.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdq = /https:\/\/doh.dns.sb\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdr = /https:\/\/dohdot.coxlab.net\/dns-query.{,1000}/ nocase ascii wide 
	$re_bds = /https:\/\/doh.eastas.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdt = /https:\/\/doh.eastau.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdu = /https:\/\/doh.eastus.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdv = /https:\/\/doh.ffmuc.net\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdw = /https:\/\/doh.libredns.gr\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdx = /https:\/\/doh.li\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdy = /https:\/\/doh.northeu.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bdz = /https:\/\/doh.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bea = /https:\/\/doh.powerdns.org.{,1000}/ nocase ascii wide 
	$re_beb = /https:\/\/doh.tiarap.org\/dns-query.{,1000}/ nocase ascii wide 
	$re_bec = /https:\/\/doh.tiar.app\/dns-query.{,1000}/ nocase ascii wide 
	$re_bed = /https:\/\/doh.westus.pi-dns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bee = /https:\/\/doh.xfinity.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_bef = /https:\/\/example.doh.blockerdns.com\/dns-query.{,1000}/ nocase ascii wide 
	$re_beg = /https:\/\/fi.doh.dns.snopyta.org\/dns-query.{,1000}/ nocase ascii wide 
	$re_beh = /https:\/\/ibksturm.synology.me\/dns-query.{,1000}/ nocase ascii wide 
	$re_bei = /https:\/\/ibuki.cgnat.net\/dns-query.{,1000}/ nocase ascii wide 
	$re_bej = /https:\/\/jcdns.fun\/dns-query.{,1000}/ nocase ascii wide 
	$re_bek = /https:\/\/jp.tiarap.org\/dns-query.{,1000}/ nocase ascii wide 
	$re_bel = /https:\/\/jp.tiar.app\/dns-query.{,1000}/ nocase ascii wide 
	$re_bem = /https:\/\/odvr.nic.cz\/doh.{,1000}/ nocase ascii wide 
	$re_ben = /https:\/\/ordns.he.net\/dns-query.{,1000}/ nocase ascii wide 
	$re_beo = /https:\/\/rdns.faelix.net\/.{,1000}/ nocase ascii wide 
	$re_bep = /https:\/\/resolver-eu.lelux.fi\/dns-query.{,1000}/ nocase ascii wide 
	$re_beq = /https:\/\/doh-jp.blahdns.com\/dns-query.{,1000}/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_bcg 
		or 	$re_bch 
		or 	$re_bci 
		or 	$re_bcj 
		or 	$re_bck 
		or 	$re_bcl 
		or 	$re_bcm 
		or 	$re_bcn 
		or 	$re_bco 
		or 	$re_bcp 
		or 	$re_bcq 
		or 	$re_bcr 
		or 	$re_bcs 
		or 	$re_bct 
		or 	$re_bcu 
		or 	$re_bcv 
		or 	$re_bcw 
		or 	$re_bcx 
		or 	$re_bcy 
		or 	$re_bcz 
		or 	$re_bda 
		or 	$re_bdb 
		or 	$re_bdc 
		or 	$re_bdd 
		or 	$re_bde 
		or 	$re_bdf 
		or 	$re_bdg 
		or 	$re_bdh 
		or 	$re_bdi 
		or 	$re_bdj 
		or 	$re_bdk 
		or 	$re_bdl 
		or 	$re_bdm 
		or 	$re_bdn 
		or 	$re_bdo 
		or 	$re_bdp 
		or 	$re_bdq 
		or 	$re_bdr 
		or 	$re_bds 
		or 	$re_bdt 
		or 	$re_bdu 
		or 	$re_bdv 
		or 	$re_bdw 
		or 	$re_bdx 
		or 	$re_bdy 
		or 	$re_bdz 
		or 	$re_bea 
		or 	$re_beb 
		or 	$re_bec 
		or 	$re_bed 
		or 	$re_bee 
		or 	$re_bef 
		or 	$re_beg 
		or 	$re_beh 
		or 	$re_bei 
		or 	$re_bej 
		or 	$re_bek 
		or 	$re_bel 
		or 	$re_bem 
		or 	$re_ben 
		or 	$re_beo 
		or 	$re_bep 
		or 	$re_beq  
	) 
}

private rule capa_packed_with_Crunch : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with Crunch (converted from capa rule)"
	namespace = "anti-analysis/packer/crunch"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-crunch.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any ber in pe.sections : ( ber.name == "BitArts" )  
	) 
}

private rule capa_delete_registry_key_via_offline_registry_library : CAPA T1112 C0036_002 C0036_007  { 
  meta: 
 	description = "delete registry key via offline registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "johnk3r"
	scope = "function"
	attack = "Defense Evasion::Modify Registry [T1112]"
	mbc = "Operating System::Registry::Delete Registry Key [C0036.002]"
	mbc = "Operating System::Registry::Delete Registry Value [C0036.007]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/delete-registry-key-via-offline-registry-library.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_bes = /\bORDeleteKey(A|W)?\b/ ascii wide
	$api_bet = /\bORDeleteValue(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_bes 
		or 	$api_bet  
	) 
}

private rule capa_get_token_membership : CAPA T1033  { 
  meta: 
 	description = "get token membership (converted from capa rule)"
	namespace = "host-interaction/session"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Owner/User Discovery [T1033]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-token-membership.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /CheckTokenMembership/)  
	) 
}

private rule capa_packed_with_PECompact : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with PECompact (converted from capa rule)"
	namespace = "anti-analysis/packer/pecompact"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-pecompact.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any beu in pe.sections : ( beu.name == "PEC2TO" ) 
		or 	for any bev in pe.sections : ( bev.name == "PEC2" ) 
		or 	for any bew in pe.sections : ( bew.name == "pec" ) 
		or 	for any bex in pe.sections : ( bex.name == "pec1" ) 
		or 	for any bey in pe.sections : ( bey.name == "pec2" ) 
		or 	for any bez in pe.sections : ( bez.name == "pec3" ) 
		or 	for any bfa in pe.sections : ( bfa.name == "pec4" ) 
		or 	for any bfb in pe.sections : ( bfb.name == "pec5" ) 
		or 	for any bfc in pe.sections : ( bfc.name == "pec6" ) 
		or 	for any bfd in pe.sections : ( bfd.name == "PEC2MO" )  
	) 
}

private rule capa_packaged_as_a_CreateInstall_installer : CAPA  { 
  meta: 
 	description = "packaged as a CreateInstall installer (converted from capa rule)"
	namespace = "executable/installer/createinstall"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.createinstall.com/"
	references = "https://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-createinstall-installer.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bff in pe.sections : ( bff.name == ".gentee" )  
	) 
}

private rule capa_packed_with_Pepack : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with Pepack (converted from capa rule)"
	namespace = "anti-analysis/packer/pepack"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-pepack.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bfg in pe.sections : ( bfg.name == "PEPACK!!" )  
	) 
}

private rule capa_reference_Google_Public_DNS_server : CAPA  { 
  meta: 
 	description = "reference Google Public DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	references = "https://developers.google.com/speed/public-dns/docs/using"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-google-public-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bfl = "8.8.8.8" ascii wide
	$str_bfm = "8.8.4.4" ascii wide
	$str_bfn = "2001:4860:4860::8888" ascii wide
	$str_bfo = "2001:4860:4860::8844" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bfl 
		or 	$str_bfm 
		or 	$str_bfn 
		or 	$str_bfo  
	) 
}

private rule capa_linked_against_C___regex_library : CAPA  { 
  meta: 
 	description = "linked against C++ regex library (converted from capa rule)"
	namespace = "linking/static/cppregex"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-c-regex-library.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bfp = "regex_error(error_syntax)" ascii wide
	$str_bfq = "regex_error(error_collate): The expression contained an invalid collating element name." ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bfp 
		or 	$str_bfq  
	) 
}

private rule capa_packed_with_MEW : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with MEW (converted from capa rule)"
	namespace = "anti-analysis/packer/mew"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-mew.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bfv in pe.sections : ( bfv.name == "MEW" )  
	) 
}

private rule capa_reference_114DNS_DNS_server : CAPA  { 
  meta: 
 	description = "reference 114DNS DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.114dns.com/"
	references = "https://www.amazon.com/ask/questions/Tx27CUHKMM403NP"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-114dns-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bfw = "114.114.114.114" ascii wide
	$str_bfx = "114.114.115.115" ascii wide
	$str_bfy = "114.114.114.119" ascii wide
	$str_bfz = "114.114.115.119" ascii wide
	$str_bga = "114.114.114.110" ascii wide
	$str_bgb = "114.114.115.110" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bfw 
		or 	$str_bfx 
		or 	$str_bfy 
		or 	$str_bfz 
		or 	$str_bga 
		or 	$str_bgb  
	) 
}

private rule capa_migrate_process_to_active_window_station : CAPA  { 
  meta: 
 	description = "migrate process to active window station (converted from capa rule)"
	namespace = "host-interaction/gui/window-station"
	author = "william.ballenthin@fireeye.com"
	description = "set process to the active window station so it can receive GUI events. commonly seen in keyloggers."
	scope = "function"
	references = "https://www.installsetupconfig.com/win32programming/windowstationsdesktops13_1.html"
	references = "https://brianbondy.com/blog/100/understanding-windows-at-a-deeper-level-sessions-window-stations-and-desktops"
	references = "https://cboard.cprogramming.com/windows-programming/144588-[win7]-setwindowshookex-windows-service-setthreaddesktop.html"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/migrate-process-to-active-window-station.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_bgd = /\bOpenWindowStation(A|W)?\b/ ascii wide
	$str_bge = "winsta0" ascii wide
	$str_bgf = "WinSta0" ascii wide
	$api_bgg = /\bSetProcessWindowStation(A|W)?\b/ ascii wide
	$api_bgh = /\bOpenInputDesktop(A|W)?\b/ ascii wide
	$api_bgi = /\bSetThreadDesktop(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_bgd 
		and  (
			$str_bge 
		or 	$str_bgf  
	) 
		and 	$api_bgg 
		and 	$api_bgh 
		and 	$api_bgi  
	) 
}

private rule capa_packed_with_Epack : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with Epack (converted from capa rule)"
	namespace = "anti-analysis/packer/epack"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-epack.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bgj in pe.sections : ( bgj.name == "!Epack" )  
	) 
}

private rule capa_packaged_as_a_Pintool : CAPA  { 
  meta: 
 	description = "packaged as a Pintool (converted from capa rule)"
	namespace = "executable/pintool"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html"
	references = "https://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
	references = "https://www.blackhat.com/docs/asia-16/materials/asia-16-Sun-Break-Out-Of-The-Truman-Show-Active-Detection-And-Escape-Of-Dynamic-Binary-Instrumentation.pdf"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-pintool.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bgk in pe.sections : ( bgk.name == ".charmve" ) 
		or 	for any bgl in pe.sections : ( bgl.name == ".pinclie" )  
	) 
}

private rule capa_get_thread_local_storage_value : CAPA  { 
  meta: 
 	description = "get thread local storage value (converted from capa rule)"
	namespace = "host-interaction/process"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-thread-local-storage-value.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /TlsGetValue/)  
	) 
}

private rule capa_rebuilt_by_ImpRec : CAPA  { 
  meta: 
 	description = "rebuilt by ImpRec (converted from capa rule)"
	namespace = "executable/imprec"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/rebuilt-by-imprec.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bgn in pe.sections : ( bgn.name == ".mackt" )  
	) 
}

private rule capa_enumerate_threads : CAPA  { 
  meta: 
 	description = "enumerate threads (converted from capa rule)"
	namespace = "host-interaction/thread/list"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/enumerate-threads.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /Thread32First/) 
		and 	pe.imports(/kernel32/i, /Thread32Next/)  
	) 
}

private rule capa_reference_Comodo_Secure_DNS_server : CAPA  { 
  meta: 
 	description = "reference Comodo Secure DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-comodo-secure-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bgo = "8.26.56.26" ascii wide
	$str_bgp = "8.20.247.20" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bgo 
		or 	$str_bgp  
	) 
}

private rule capa_decrypt_data_via_SSPI : CAPA T1140  { 
  meta: 
 	description = "decrypt data via SSPI (converted from capa rule)"
	namespace = "data-manipulation/encryption"
	author = "matthew.williams@fireeye.com"
	scope = "basic block"
	attack = "Defense Evasion::Deobfuscate/Decode Files or Information [T1140]"
	references = "https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-decryptmessage"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/decrypt-data-via-sspi.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/secur32/i, /DecryptMessage/)  
	) 
}

private rule capa_reference_L3_DNS_server : CAPA  { 
  meta: 
 	description = "reference L3 DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.quora.com/What-is-a-4-2-2-1-DNS-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-l3-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bgr = "4.2.2.1" ascii wide
	$str_bgs = "4.2.2.2" ascii wide
	$str_bgt = "4.2.2.3" ascii wide
	$str_bgu = "4.2.2.4" ascii wide
	$str_bgv = "4.2.2.5" ascii wide
	$str_bgw = "4.2.2.6" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bgr 
		or 	$str_bgs 
		or 	$str_bgt 
		or 	$str_bgu 
		or 	$str_bgv 
		or 	$str_bgw  
	) 
}

private rule capa_packaged_as_a_Wise_installer : CAPA  { 
  meta: 
 	description = "packaged as a Wise installer (converted from capa rule)"
	namespace = "executable/installer/wiseinstall"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-wise-installer.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bgx = "WiseMain" ascii wide
	$re_bgy = /Wise Installation Wizard/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$str_bgx 
		or 	$re_bgy  
	) 
}

private rule capa_acquire_debug_privileges : CAPA T1134  { 
  meta: 
 	description = "acquire debug privileges (converted from capa rule)"
	namespace = "host-interaction/process/modify"
	author = "william.ballenthin@fireeye.com"
	scope = "basic block"
	attack = "Privilege Escalation::Access Token Manipulation [T1134]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/acquire-debug-privileges.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bhc = "SeDebugPrivilege" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bhc  
	) 
}

private rule capa_empty_the_recycle_bin : CAPA  { 
  meta: 
 	description = "empty the recycle bin (converted from capa rule)"
	namespace = "host-interaction/recycle-bin"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/empty-the-recycle-bin.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_bhd = /\bSHEmptyRecycleBin(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_bhd  
	) 
}

private rule capa_compare_security_identifiers : CAPA  { 
  meta: 
 	description = "compare security identifiers (converted from capa rule)"
	namespace = "host-interaction/sid"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/compare-security-identifiers.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /EqualSid/)  
	) 
}

private rule capa_query_remote_server_for_available_data : CAPA  { 
  meta: 
 	description = "query remote server for available data (converted from capa rule)"
	namespace = "communication"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/query-remote-server-for-available-data.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/wininet/i, /InternetQueryDataAvailable/)  
	) 
}

private rule capa_packed_with_enigma : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with enigma (converted from capa rule)"
	namespace = "anti-analysis/packer/enigma"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-enigma.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bhe in pe.sections : ( bhe.name == ".enigma1" ) 
		or 	for any bhf in pe.sections : ( bhf.name == ".enigma2" )  
	) 
}

private rule capa_initialize_hashing_via_WinCrypt : CAPA  { 
  meta: 
 	description = "initialize hashing via WinCrypt (converted from capa rule)"
	namespace = "data-manipulation/hashing"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/initialize-hashing-via-wincrypt.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /CryptCreateHash/)  
	) 
}

private rule capa_packed_with_StarForce : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with StarForce (converted from capa rule)"
	namespace = "anti-analysis/packer/starforce"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-starforce.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bhg in pe.sections : ( bhg.name == ".sforce3" )  
	) 
}

private rule capa_encrypt_data_via_SSPI : CAPA T1027  { 
  meta: 
 	description = "encrypt data via SSPI (converted from capa rule)"
	namespace = "data-manipulation/encryption"
	author = "matthew.williams@fireeye.com"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	references = "https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-encryptmessage"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/encrypt-data-via-sspi.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/secur32/i, /EncryptMessage/)  
	) 
}

private rule capa_packed_with_ProCrypt : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with ProCrypt (converted from capa rule)"
	namespace = "anti-analysis/packer/procrypt"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-procrypt.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bhh in pe.sections : ( bhh.name == "ProCrypt" )  
	) 
}

private rule capa_packed_with_WWPACK : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with WWPACK (converted from capa rule)"
	namespace = "anti-analysis/packer/wwpack"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-wwpack.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bhi in pe.sections : ( bhi.name == ".WWPACK" ) 
		or 	for any bhj in pe.sections : ( bhj.name == ".WWP32" )  
	) 
}

private rule capa_reference_Cloudflare_DNS_server : CAPA  { 
  meta: 
 	description = "reference Cloudflare DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-cloudflare-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bhk = "1.1.1.1" ascii wide
	$str_bhl = "1.0.0.1" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bhk 
		or 	$str_bhl  
	) 
}

private rule capa_get_system_firmware_table : CAPA  { 
  meta: 
 	description = "get system firmware table (converted from capa rule)"
	namespace = "host-interaction/hardware/firmware"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/Shared/Utils.cpp#L854"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-system-firmware-table.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /GetSystemFirmwareTable/)  
	) 
}

private rule capa_get_socket_information : CAPA T1016  { 
  meta: 
 	description = "get socket information (converted from capa rule)"
	namespace = "communication/socket"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-socket-information.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/ws2_32/i, /getsockname/)  
	) 
}

private rule capa_check_license_value : CAPA T1497_001  { 
  meta: 
 	description = "check license value (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Generic.cpp#L1224"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/check-license-value.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_bhm = /\bNtQueryLicenseValue(A|W)?\b/ ascii wide
	$str_bhn = "Kernel-VMDetection-Private" ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_bhm 
		and 	$str_bhn  
	) 
}

private rule capa_bypass_UAC_via_ICMLuaUtil : CAPA T1548_002  { 
  meta: 
 	description = "bypass UAC via ICMLuaUtil (converted from capa rule)"
	namespace = "host-interaction/uac/bypass"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
	references = "https://gist.github.com/hfiref0x/196af729106b780db1c73428b5a5d68d"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/bypass-uac-via-icmluautil.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bho = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide
	$bhp = { F9 C7 5F 3E 51 9A 67 43 90 63 A1 20 24 4F BE C7 } // T_CLSID_CMSTPLUA
	$str_bhq = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$str_bho 
		or 	$bhp  
	) 
		and 	$str_bhq  
	) 
}

private rule capa_reference_screen_saver_executable : CAPA T1546_002  { 
  meta: 
 	description = "reference screen saver executable (converted from capa rule)"
	namespace = "persistence/screensaver"
	author = "michael.hunhoff@fireeye.com"
	description = "SCRNSAVE.EXE registry value specifies the name of the screen saver executable file"
	scope = "function"
	attack = "Persistence::Event Triggered Execution::Screensaver [T1546.002]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-screen-saver-executable.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bhr = "SCRNSAVE.EXE" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bhr  
	) 
}

private rule capa_create_Restart_Manager_session : CAPA  { 
  meta: 
 	description = "create Restart Manager session (converted from capa rule)"
	namespace = "host-interaction/process"
	author = "michael.hunhoff@fireeye.com"
	description = "Windows Restart Manager can be used to close/unlock specific files, often abused by Ransomware"
	scope = "function"
	references = "https://www.carbonblack.com/blog/tau-threat-discovery-conti-ransomware/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/create-restart-manager-session.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/rstrtmgr/i, /RmStartSession/)  
	) 
}

private rule capa_reference_kornet_DNS_server : CAPA  { 
  meta: 
 	description = "reference kornet DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://whatismyipaddress.com/ip/168.126.63.1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-kornet-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bhs = "168.126.63.1" ascii wide // kns.kornet.net
 
  condition:
    capa_pe_file and
 (
			$str_bhs  
	) 
}

private rule capa_packed_with_Themida : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with Themida (converted from capa rule)"
	namespace = "anti-analysis/packer/themida"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-themida.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bht in pe.sections : ( bht.name == "Themida" ) 
		or 	for any bhu in pe.sections : ( bhu.name == ".Themida" ) 
		or 	for any bhv in pe.sections : ( bhv.name == "WinLicen" )  
	) 
}

private rule capa_impersonate_user : CAPA T1134_001  { 
  meta: 
 	description = "impersonate user (converted from capa rule)"
	namespace = "host-interaction/user"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Privilege Escalation::Access Token Manipulation::Token Impersonation/Theft [T1134.001]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/impersonate-user.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /LogonUser/) 
		or  (
			pe.imports(/userenv/i, /LoadUserProfile/)  
	)  
	) 
}

private rule capa_get_user_security_identifier : CAPA T1087  { 
  meta: 
 	description = "get user security identifier (converted from capa rule)"
	namespace = "host-interaction/sid"
	author = "michael.hunhoff@fireeye.com"
	scope = "basic block"
	attack = "Discovery::Account Discovery [T1087]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-user-security-identifier.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /LookupAccountName/) 
		or 	pe.imports(/advapi32/i, /LsaLookupNames/) 
		or 	pe.imports(/advapi32/i, /LsaLookupNames2/)  
	) 
}

private rule capa_read_raw_disk_data : CAPA  { 
  meta: 
 	description = "read raw disk data (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/read-raw-disk-data.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bhw = "\\\\.\\PhysicalDrive0" ascii wide
	$str_bhx = "\\\\.\\C:" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bhw 
		or 	$str_bhx  
	) 
}

private rule capa_bypass_UAC_via_scheduled_task_environment_variable : CAPA T1548_002  { 
  meta: 
 	description = "bypass UAC via scheduled task environment variable (converted from capa rule)"
	namespace = "host-interaction/uac/bypass"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
	references = "https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html"
	references = "https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/bypass-uac-via-scheduled-task-environment-variable.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bhy = "schtasks.exe" ascii wide
	$re_bhz = /Microsoft\\Windows\\DiskCleanup\\SilentCleanup/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$str_bhy 
		and 	$re_bhz 
		and 	capa_create_process
 
	) 
}

private rule capa_reference_AES_constants : CAPA T1027  { 
  meta: 
 	description = "reference AES constants (converted from capa rule)"
	namespace = "data-manipulation/encryption/aes"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-aes-constants.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$bif = { 50 A7 F4 51 53 65 41 7E } // d-0
	$big = { 63 7C 77 7B F2 6B 6F C5 } // s-box
	$bih = { 52 09 6A D5 30 36 A5 38 } // inv-s-box
 
  condition:
    capa_pe_file and
 (
			$bif 
		or 	$big 
		or 	$bih  
	) 
}

private rule capa_compiled_with_Nim : CAPA  { 
  meta: 
 	description = "compiled with Nim (converted from capa rule)"
	namespace = "compiler/nim"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/compiled-with-nim.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bii = /NimMain/ ascii wide 
	$re_bij = /NimMainModule/ ascii wide 
	$re_bik = /NimMainInner/ ascii wide 
	$re_bil = /io.nim$/ ascii wide 
	$re_bim = /fatal.nim$/ ascii wide 
	$re_bin = /system.nim$/ ascii wide 
	$re_bio = /alloc.nim$/ ascii wide 
	$re_bip = /osalloc.nim$/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_bii 
		or 	$re_bij 
		or 	$re_bik 
		or 	$re_bil 
		or 	$re_bim 
		or 	$re_bin 
		or 	$re_bio 
		or 	$re_bip  
	) 
}

private rule capa_hook_routines_via_microsoft_detours : CAPA  { 
  meta: 
 	description = "hook routines via microsoft detours (converted from capa rule)"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.fireeye.com/content/dam/fireeye-www/global/en/blog/threat-research/Flare-On%202017/Challenge7.pdf"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/hook-routines-via-microsoft-detours.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_biq = { 64 74 72 52 } // DETOUR_REGION_SIGNATURE
 
  condition:
    capa_pe_file and
 (
		$num_biq  
	) 
}

private rule capa_packed_with_SVKP : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with SVKP (converted from capa rule)"
	namespace = "anti-analysis/packer/svkp"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-svkp.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bir in pe.sections : ( bir.name == ".svkp" )  
	) 
}

private rule capa_flush_cabinet_file : CAPA  { 
  meta: 
 	description = "flush cabinet file (converted from capa rule)"
	namespace = "host-interaction/file-system"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	references = "https://docs.microsoft.com/en-us/windows/win32/msi/cabinet-files"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/flush-cabinet-file.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/cabinet/i, /FCIFlushFolder/) 
		or 	pe.imports(/cabinet/i, /FCIFlushCabinet/)  
	) 
}

private rule capa_enumerate_system_firmware_tables : CAPA  { 
  meta: 
 	description = "enumerate system firmware tables (converted from capa rule)"
	namespace = "host-interaction/hardware/firmware"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/Shared/Utils.cpp#L843"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/enumerate-system-firmware-tables.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /EnumSystemFirmwareTables/)  
	) 
}

private rule capa_reference_startup_folder : CAPA T1547_001  { 
  meta: 
 	description = "reference startup folder (converted from capa rule)"
	namespace = "persistence/startup-folder"
	author = "matthew.williams@fireeye.com"
	scope = "file"
	attack = "Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-startup-folder.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bis = /Start Menu\\Programs\\Startup/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_bis  
	) 
}

private rule capa_encrypt_or_decrypt_data_via_BCrypt : CAPA T1027 C0031 C0027  { 
  meta: 
 	description = "encrypt or decrypt data via BCrypt (converted from capa rule)"
	namespace = "data-manipulation/encryption"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Cryptography::Decrypt Data [C0031]"
	mbc = "Cryptography::Encrypt Data [C0027]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/encrypt-or-decrypt-data-via-bcrypt.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_bit = /\bBCryptDecrypt(A|W)?\b/ ascii wide
	$api_biu = /\bBCryptEncrypt(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$api_bit 
		or 	$api_biu  
	)  
	) 
}

private rule capa_connect_network_resource : CAPA  { 
  meta: 
 	description = "connect network resource (converted from capa rule)"
	namespace = "communication/http"
	author = "michael.hunhoff@fireeye.com"
	description = "connect to disk or print resource"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/connect-network-resource.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/mpr/i, /WNetAddConnection/) 
		or 	pe.imports(/mpr/i, /WNetAddConnection2/) 
		or 	pe.imports(/mpr/i, /WNetAddConnection3/)  
	)  
	) 
}

private rule capa_packed_with_Shrinker : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with Shrinker (converted from capa rule)"
	namespace = "anti-analysis/packer/shrinker"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-shrinker.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any biw in pe.sections : ( biw.name == ".shrink1" ) 
		or 	for any bix in pe.sections : ( bix.name == ".shrink2" ) 
		or 	for any biy in pe.sections : ( biy.name == ".shrink3" )  
	) 
}

private rule capa_packed_with_VProtect : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with VProtect (converted from capa rule)"
	namespace = "anti-analysis/packer/vprotect"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-vprotect.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any biz in pe.sections : ( biz.name == "VProtect" )  
	) 
}

private rule capa_packed_with_CCG : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with CCG (converted from capa rule)"
	namespace = "anti-analysis/packer/ccg"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-ccg.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bja in pe.sections : ( bja.name == ".ccg" )  
	) 
}

private rule capa_set_console_window_title : CAPA  { 
  meta: 
 	description = "set console window title (converted from capa rule)"
	namespace = "host-interaction/gui/console"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/set-console-window-title.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /SetConsoleTitle/)  
	) 
}

private rule capa_get_routing_table : CAPA T1016  { 
  meta: 
 	description = "get routing table (converted from capa rule)"
	namespace = "host-interaction/network/routing-table"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-routing-table.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/iphlpapi/i, /GetIpForwardTable/) 
		or 	pe.imports(/iphlpapi/i, /GetIpForwardTable2/)  
	) 
}

private rule capa_reference_Hurricane_Electric_DNS_server : CAPA  { 
  meta: 
 	description = "reference Hurricane Electric DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://dns.he.net/"
	references = "https://dnslytics.com/ip/216.66.1.2"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-hurricane-electric-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bjb = "216.218.130.2" ascii wide // ns1.he.net
	$str_bjc = "216.218.131.2" ascii wide // ns2.he.net
	$str_bjd = "216.218.132.2" ascii wide // ns3.he.net
	$str_bje = "216.66.1.2" ascii wide // ns4.he.net
	$str_bjf = "216.66.80.18" ascii wide // ns5.he.net
 
  condition:
    capa_pe_file and
 (
			$str_bjb 
		or 	$str_bjc 
		or 	$str_bjd 
		or 	$str_bje 
		or 	$str_bjf  
	) 
}

private rule capa_packed_with_Mpress : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with Mpress (converted from capa rule)"
	namespace = "anti-analysis/packer/mpress"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-mpress.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bjg in pe.sections : ( bjg.name == ".MPRESS1" ) 
		or 	for any bjh in pe.sections : ( bjh.name == ".MPRESS2" )  
	) 
}

private rule capa_packaged_as_an_InstallShield_installer : CAPA  { 
  meta: 
 	description = "packaged as an InstallShield installer (converted from capa rule)"
	namespace = "executable/installer/installshield"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-an-installshield-installer.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bji = "InstallShield" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bji  
	) 
}

private rule capa_mine_cryptocurrency : CAPA T1496  { 
  meta: 
 	description = "mine cryptocurrency (converted from capa rule)"
	namespace = "impact/cryptocurrency"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	attack = "Impact::Resource Hijacking [T1496]"
	references = "https://github.com/ctxis/CAPE/blob/master/modules/signatures/cryptomining.py"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/mine-cryptocurrency.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bjj = "stratum+tcp://" ascii wide
	$str_bjk = "xmrig" ascii wide
	$str_bjl = "xmr-stak" ascii wide
	$str_bjm = "supportxmr.com:" ascii wide
	$str_bjn = "dwarfpool.com:" ascii wide
	$str_bjo = "minergate" ascii wide
	$str_bjp = "xmr." ascii wide
	$str_bjq = "monero." ascii wide
	$str_bjr = "Bitcoin" ascii wide
	$str_bjs = "Bitcoin" ascii wide
	$str_bjt = "BitcoinGold" ascii wide
	$str_bju = "BtcCash" ascii wide
	$str_bjv = "Ethereum" ascii wide
	$str_bjw = "BlackCoin" ascii wide
	$str_bjx = "ByteCoin" ascii wide
	$str_bjy = "EmerCoin" ascii wide
	$str_bjz = "ReddCoin" ascii wide
	$str_bka = "Peercoin" ascii wide
	$str_bkb = "Ripple" ascii wide
	$str_bkc = "Miota" ascii wide
	$str_bkd = "Cardano" ascii wide
	$str_bke = "Lisk" ascii wide
	$str_bkf = "Stratis" ascii wide
	$str_bkg = "Waves" ascii wide
	$str_bkh = "Qtum" ascii wide
	$str_bki = "Stellar" ascii wide
	$str_bkj = "ViaCoin" ascii wide
	$str_bkk = "Electroneum" ascii wide
	$str_bkl = "Dash" ascii wide
	$str_bkm = "Doge" ascii wide
	$str_bkn = "Monero" ascii wide
	$str_bko = "Graft" ascii wide
	$str_bkp = "Zcash" ascii wide
	$str_bkq = "Ya.money" ascii wide
	$str_bkr = "Ya.disc" ascii wide
	$str_bks = "Steam" ascii wide
	$str_bkt = "vk.cc" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bjj 
		or 	$str_bjk 
		or 	$str_bjl 
		or 	$str_bjm 
		or 	$str_bjn 
		or 	$str_bjo 
		or 	$str_bjp 
		or 	$str_bjq 
		or 	$str_bjr 
		or 	$str_bjs 
		or 	$str_bjt 
		or 	$str_bju 
		or 	$str_bjv 
		or 	$str_bjw 
		or 	$str_bjx 
		or 	$str_bjy 
		or 	$str_bjz 
		or 	$str_bka 
		or 	$str_bkb 
		or 	$str_bkc 
		or 	$str_bkd 
		or 	$str_bke 
		or 	$str_bkf 
		or 	$str_bkg 
		or 	$str_bkh 
		or 	$str_bki 
		or 	$str_bkj 
		or 	$str_bkk 
		or 	$str_bkl 
		or 	$str_bkm 
		or 	$str_bkn 
		or 	$str_bko 
		or 	$str_bkp 
		or 	$str_bkq 
		or 	$str_bkr 
		or 	$str_bks 
		or 	$str_bkt  
	) 
}

private rule capa_packed_with_SeauSFX : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with SeauSFX (converted from capa rule)"
	namespace = "anti-analysis/packer/seausfx"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-seausfx.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bku in pe.sections : ( bku.name == ".seau" )  
	) 
}

private rule capa_debug_build : CAPA  { 
  meta: 
 	description = "debug build (converted from capa rule)"
	namespace = "executable/pe/debug"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/debug-build.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bkv = "Assertion failed!" ascii wide
	$str_bkw = "Assertion failed:" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bkv 
		or 	$str_bkw  
	) 
}

private rule capa_packed_with_Simple_Pack : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with Simple Pack (converted from capa rule)"
	namespace = "anti-analysis/packer/simple-pack"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-simple-pack.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bkx in pe.sections : ( bkx.name == ".spack" )  
	) 
}

private rule capa_resolve_function_by_hash : CAPA T1027_005  { 
  meta: 
 	description = "resolve function by hash (converted from capa rule)"
	namespace = "linking/runtime-linking"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information::Indicator Removal from Tools [T1027.005]"
	references = "https://www.fireeye.com/blog/threat-research/2012/11/precalculated-string-hashes-reverse-engineering-shellcode.html"
	references = "https://pastebin.com/ci5XYW4P"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/resolve-function-by-hash.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_bky = { 5B BC 4A 6A } // ROR13(kernel32.dll)
	$num_bkz = { 5D 68 FA 3C } // ROR13(ntdll.dll)
	$num_bla = { 8E 4E 0E EC } // ROR13(LoadLibraryA)
	$num_blb = { AA FC 0D 7C } // ROR13(GetProcAddress)
	$num_blc = { 54 CA AF 91 } // ROR13(VirtualAlloc)
	$num_bld = { B8 0A 4C 53 } // ROR13(NtFlushInstructionCache)
	$num_ble = { 1A 06 7F FF } // ROR13(RtlExitUserThread)
	$num_blf = { EF CE E0 60 } // ROR13(ExitThread)
 
  condition:
    capa_pe_file and
 (
		$num_bky 
		or $num_bkz 
		or $num_bla 
		or $num_blb 
		or $num_blc 
		or $num_bld 
		or $num_ble 
		or $num_blf  
	) 
}

private rule capa_hash_data_via_BCrypt : CAPA T1027 C0029  { 
  meta: 
 	description = "hash data via BCrypt (converted from capa rule)"
	namespace = "data-manipulation/hashing"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Cryptography::Cryptographic Hash [C0029]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/hash-data-via-bcrypt.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_blg = /\bBCryptHash(A|W)?\b/ ascii wide
	$api_blh = /\bBCryptHashData(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$api_blg 
		or  (
			$api_blh  
	)  
	)  
	) 
}

private rule capa_delete_internet_cache : CAPA  { 
  meta: 
 	description = "delete internet cache (converted from capa rule)"
	namespace = "host-interaction/internet/cache"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/delete-internet-cache.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			capa_enumerate_internet_cache

		and 	pe.imports(/wininet/i, /DeleteUrlCacheEntry/)  
	) 
}

private rule capa_reference_OpenDNS_DNS_server : CAPA  { 
  meta: 
 	description = "reference OpenDNS DNS server (converted from capa rule)"
	namespace = "communication/dns"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.techradar.com/news/best-dns-server"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-opendns-dns-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_blj = "208.67.222.222" ascii wide
	$str_blk = "208.67.220.220" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_blj 
		or 	$str_blk  
	) 
}

private rule capa_read_process_memory : CAPA  { 
  meta: 
 	description = "read process memory (converted from capa rule)"
	namespace = "host-interaction/process"
	author = "matthew.williams@fireeye.com"
	author = "@_re_fox"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/read-process-memory.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /ReadProcessMemory/)  
	) 
}

private rule capa_linked_against_XZip : CAPA C0060  { 
  meta: 
 	description = "linked against XZip (converted from capa rule)"
	namespace = "linking/static/xzip"
	author = "moritz.raabe@fireeye.com"
	scope = "file"
	mbc = "Data::Compression Library [C0060]"
	references = "https://github.com/ValveSoftware/source-sdk-2013/blob/master/sp/src/public/XZip.cpp"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-xzip.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bll = "ct_init: length != 256" ascii wide
	$str_blm = "ct_init: dist != 256" ascii wide
	$str_bln = "ct_init: 256+dist != 512" ascii wide
	$str_blo = "bit length overflow" ascii wide
	$str_blp = "code %d bits %d->%d" ascii wide
	$str_blq = "inconsistent bit counts" ascii wide
	$str_blr = "gen_codes: max_code %d " ascii wide
	$str_bls = "dyn trees: dyn %ld, stat %ld" ascii wide
	$str_blt = "bad pack level" ascii wide
	$str_blu = "Code too clever" ascii wide
	$str_blv = "unknown zip result code" ascii wide
	$str_blw = "Culdn't duplicate handle" ascii wide
	$str_blx = "File not found in the zipfile" ascii wide
	$str_bly = "Still more data to unzip" ascii wide
	$str_blz = "Caller: the file had already been partially unzipped" ascii wide
	$str_bma = "Caller: can only get memory of a memory zipfile" ascii wide
	$str_bmb = "Zip-bug: internal initialisation not completed" ascii wide
	$str_bmc = "Zip-bug: an internal error during flation" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bll 
		or 	$str_blm 
		or 	$str_bln 
		or 	$str_blo 
		or 	$str_blp 
		or 	$str_blq 
		or 	$str_blr 
		or 	$str_bls 
		or 	$str_blt 
		or 	$str_blu 
		or 	$str_blv 
		or 	$str_blw 
		or 	$str_blx 
		or 	$str_bly 
		or 	$str_blz 
		or 	$str_bma 
		or 	$str_bmb 
		or 	$str_bmc  
	) 
}

private rule capa_compiled_from_EPL : CAPA  { 
  meta: 
 	description = "compiled from EPL (converted from capa rule)"
	namespace = "compiler/epl"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.hexacorn.com/blog/2019/02/13/pe-files-and-the-easy-programming-language-epl/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/compiled-from-epl.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bmd = "GetNewSock" ascii wide
	$str_bme = "Software\\FlySky\\E\\Install" ascii wide
	$str_bmf = "Not found the kernel library or the kernel library is invalid!" ascii wide
	$str_bmg = "Failed to allocate memory!" ascii wide
	$str_bmh = "/ MADE BY E COMPILER – WUTAO" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bmd 
		or 	$str_bme 
		or 	$str_bmf 
		or 	$str_bmg 
		or 	$str_bmh 
		or 	for any bmi in pe.sections : ( bmi.name == ".ecode" ) 
		or 	for any bmj in pe.sections : ( bmj.name == ".edata" ) 
		or 	pe.imports(/krnln/i, /fne/) 
		or 	pe.imports(/krnln/i, /fnr/) 
		or 	pe.imports(/eAPI/i, /fne/) 
		or 	pe.imports(/RegEx/i, /fnr/)  
	) 
}

private rule capa_get_session_information : CAPA T1033  { 
  meta: 
 	description = "get session information (converted from capa rule)"
	namespace = "host-interaction/session"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Owner/User Discovery [T1033]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-session-information.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/wtsapi32/i, /WTSQuerySessionInformation/)  
	) 
}

private rule capa_packed_with_Perplex : CAPA T1027_002 F0001  { 
  meta: 
 	description = "packed with Perplex (converted from capa rule)"
	namespace = "anti-analysis/packer/perplex"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
	mbc = "Anti-Static Analysis::Software Packing [F0001]"
	references = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-perplex.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bmk in pe.sections : ( bmk.name == ".perplex" )  
	) 
}

private rule capa_compiled_with_Go : CAPA  { 
  meta: 
 	description = "compiled with Go (converted from capa rule)"
	namespace = "compiler/go"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	hash = "49a34cfbeed733c24392c9217ef46bb6"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/go/compiled-with-go.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bml = "Go build ID:" ascii wide
	$str_bmm = "go.buildid" ascii wide
	$str_bmn = "Go buildinf:" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bml 
		or 	$str_bmm 
		or 	$str_bmn  
	) 
}

private rule capa_compiled_with_ps2exe : CAPA  { 
  meta: 
 	description = "compiled with ps2exe (converted from capa rule)"
	namespace = "compiler/ps2exe"
	author = "@_re_fox"
	scope = "file"
	references = "https://github.com/ikarstein/ps2exe"
	hash = "8775ed26068788279726e08ff9665aab"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/ps2exe/compiled-with-ps2exe.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bmo = "PS2EXEApp" ascii wide
	$str_bmp = "PS2EXE" ascii wide
	$str_bmq = "PS2EXE_Host" ascii wide
 
  condition:
    capa_pe_file and
 (
			capa_compiled_to_the__NET_platform

		and 	$str_bmo 
		and 	$str_bmp 
		and 	$str_bmq  
	) 
}

private rule capa_compiled_with_MinGW_for_Windows : CAPA  { 
  meta: 
 	description = "compiled with MinGW for Windows (converted from capa rule)"
	namespace = "compiler/mingw"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	hash = "5b3968b47eb16a1cb88525e3b565eab1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/mingw/compiled-with-mingw-for-windows.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bmr = "Mingw runtime failure:" ascii wide
	$str_bms = "_Jv_RegisterClasses" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bmr 
		and 	$str_bms  
	) 
}

private rule capa_compiled_from_Visual_Basic : CAPA  { 
  meta: 
 	description = "compiled from Visual Basic (converted from capa rule)"
	namespace = "compiler/vb"
	author = "@williballenthin"
	scope = "file"
	hash = "9bca6b99e7981208af4c7925b96fb9cf"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/vb/compiled-from-visual-basic.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bmt = /VB5!.{,1000}/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_bmt 
		and 	pe.imports(/msvbvm60/i, /ThunRTMain/)  
	) 
}

private rule capa_compiled_with_pyarmor : CAPA T1059_006  { 
  meta: 
 	description = "compiled with pyarmor (converted from capa rule)"
	namespace = "compiler/pyarmor"
	author = "@stvemillertime, @itreallynick"
	scope = "file"
	attack = "Execution::Command and Scripting Interpreter::Python [T1059.006]"
	attack = "Defense Evasion::Obfuscated Files or Information::Software Packing [1027.002]"
	references = "https://twitter.com/stvemillertime/status/1349032548580483073"
	hash = "a0fb20bc9aa944c3a0a6c4545c195818"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/pyarmor/compiled-with-pyarmor.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bmx = "pyarmor_runtimesh" ascii wide
	$str_bmy = "PYARMOR" ascii wide
	$str_bmz = "__pyarmor__" ascii wide
	$str_bna = "PYARMOR_SIGNATURE" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bmx 
		or 	$str_bmy 
		or 	$str_bmz 
		or 	$str_bna  
	) 
}

private rule capa_compiled_with_exe4j : CAPA  { 
  meta: 
 	description = "compiled with exe4j (converted from capa rule)"
	namespace = "compiler/exe4j"
	author = "johnk3r"
	scope = "file"
	hash = "6b25f1e754ef486bbb28a66d46bababe"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/exe4j/compiled-with-exe4j.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bnb = "exe4j_log" ascii wide
	$str_bnc = "install4j_log" ascii wide
	$str_bnd = "exe4j_java_home" ascii wide
	$str_bne = "install4j" ascii wide
	$str_bnf = "exe4j.isinstall4j" ascii wide
	$re_bng = /com\/exe4j\/runtime\/exe4jcontroller/ nocase ascii wide 
	$re_bnh = /com\/exe4j\/runtime\/winlauncher/ nocase ascii wide 
	$str_bni = "EXE4J_LOG" ascii wide
	$str_bnj = "INSTALL4J_LOG" ascii wide
	$str_bnk = "EXE4J_JAVA_HOME" ascii wide
	$str_bnl = "INSTALL4J" ascii wide
	$str_bnm = "EXE4J.ISINSTALL4J" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bnb 
		or 	$str_bnc 
		or 	$str_bnd 
		or 	$str_bne 
		or 	$str_bnf 
		or 	$re_bng 
		or 	$re_bnh 
		or 	$str_bni 
		or 	$str_bnj 
		or 	$str_bnk 
		or 	$str_bnl 
		or 	$str_bnm  
	) 
}

private rule capa_compiled_with_AutoIt : CAPA T1059  { 
  meta: 
 	description = "compiled with AutoIt (converted from capa rule)"
	namespace = "compiler/autoit"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	attack = "Execution::Command and Scripting Interpreter [T1059]"
	hash = "55D77AB16377A8A314982F723FCC6FAE"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/autoit/compiled-with-autoit.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bnn = "AutoIt has detected the stack has become corrupt.\n\nStack corruption typically occurs when either the wrong calling convention is used or when the function is called with the wrong number of arguments.\n\nAutoIt supports the __stdcall (WINAPI) and __cdecl calling conventions.  The __stdcall (WINAPI) convention is used by default but __cdecl can be used instead.  See the DllCall() documentation for details on changing the calling convention." ascii wide
	$str_bno = "AutoIt Error" ascii wide
	$re_bnp = />>>AUTOIT SCRIPT<<</ ascii wide 
	$str_bnq = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
	$str_bnr = "#requireadmin" ascii wide
	$str_bns = "#OnAutoItStartRegister" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bnn 
		or 	$str_bno 
		or 	$re_bnp 
		or 	$str_bnq 
		or 	$str_bnr 
		or 	$str_bns  
	) 
}

private rule capa_compiled_with_Borland_Delphi : CAPA  { 
  meta: 
 	description = "compiled with Borland Delphi (converted from capa rule)"
	namespace = "compiler/delphi"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	hash = "4BDD67FF852C221112337FECD0681EAC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/delphi/compiled-with-borland-delphi.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bnt = "Borland C++ - Copyright 2002 Borland Corporation" ascii wide
	$re_bnu = /SOFTWARE\\Borland\\Delphi\\RTL/ ascii wide 
	$str_bnv = "Sysutils::Exception" ascii wide
	$str_bnw = "TForm1" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bnt 
		or 	$re_bnu 
		or 	$str_bnv 
		or 	$str_bnw 
		or 	pe.imports(/BORLNDMM/i, /DLL/)  
	) 
}

private rule capa_compiled_with_dmd : CAPA  { 
  meta: 
 	description = "compiled with dmd (converted from capa rule)"
	namespace = "compiler/d"
	author = "@_re_fox"
	scope = "file"
	references = "https://github.com/dlang/dmd"
	hash = "321338196a46b600ea330fc5d98d0699"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/d/compiled-with-dmd.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			for any bnx in pe.sections : ( bnx.name == "._deh" ) 
		and 	for any bny in pe.sections : ( bny.name == ".tp" ) 
		and 	for any bnz in pe.sections : ( bnz.name == ".dp" ) 
		and 	for any boa in pe.sections : ( boa.name == ".minfo" )  
	) 
}

private rule capa_compiled_with_py2exe : CAPA  { 
  meta: 
 	description = "compiled with py2exe (converted from capa rule)"
	namespace = "compiler/py2exe"
	author = "@_re_fox"
	scope = "basic block"
	hash = "ed888dc2f04f5eac83d6d14088d002de"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/py2exe/compiled-with-py2exe.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bob = "PY2EXE_VERBOSE" ascii wide
	$api_boc = /\bgetenv(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bob 
		and 	$api_boc  
	) 
}

private rule capa_identify_ATM_dispenser_service_provider : CAPA  { 
  meta: 
 	description = "identify ATM dispenser service provider (converted from capa rule)"
	namespace = "targeting/automated-teller-machine"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://doc.axxonsoft.com/confluence/display/atm70en/Configuring+the+connection+to+the+dispenser+service+provider"
	hash = "b2ad4409323147b63e370745e5209996"
	hash = "1f094dd65be477d15d871e72f0fdce5e"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/identify-atm-dispenser-service-provider.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bod = "CurrencyDispenser1" ascii wide
	$str_boe = "CDM30" ascii wide
	$str_bof = "DBD_AdvFuncDisp" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bod 
		or 	$str_boe 
		or 	$str_bof  
	) 
}

private rule capa_load_NCR_ATM_library : CAPA  { 
  meta: 
 	description = "load NCR ATM library (converted from capa rule)"
	namespace = "targeting/automated-teller-machine/ncr"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.pcworld.com/article/2824572/leaked-programming-manual-may-help-criminals-develop-more-atm-malware.html"
	hash = "971e599e6e707349eccea2fd4c8e5f67"
	hash = "4bdd67ff852c221112337fecd0681eac"
	hash = "32d1f4b9c0cf2bb9512d88d27ca23c07"
	hash = "dc9eb40429d6fa2f15cd34479cb320c8"
	hash = "5b3968b47eb16a1cb88525e3b565eab1"
	hash = "dc4dc746d8a14060fb5fc7edd4ef5282"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/ncr/load-ncr-atm-library.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bog = "MSXFS.dll" ascii wide
	$str_boh = "msxfs.dll" ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/msxfs/i, /dll/) 
		or 	$str_bog 
		or 	$str_boh  
	) 
}

private rule capa_reference_NCR_ATM_library_routines : CAPA  { 
  meta: 
 	description = "reference NCR ATM library routines (converted from capa rule)"
	namespace = "targeting/automated-teller-machine/ncr"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	references = "https://www.pcworld.com/article/2824572/leaked-programming-manual-may-help-criminals-develop-more-atm-malware.html"
	hash = "84a1212f4a91066babcf594d87a85894"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/ncr/reference-ncr-atm-library-routines.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_boi = "msxfs.dll" ascii wide
	$str_boj = "WFSCleanUp" ascii wide
	$str_bok = "WFSClose" ascii wide
	$str_bol = "WFSExecute" ascii wide
	$str_bom = "WFSFreeResult" ascii wide
	$str_bon = "WFSGetInfo" ascii wide
	$str_boo = "WFSLock" ascii wide
	$str_bop = "WFSOpen" ascii wide
	$str_boq = "WFSRegister" ascii wide
	$str_bor = "WFSStartUp" ascii wide
	$str_bos = "WFSUnlock" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_boi 
		or 	pe.imports(/msxfs/i, /WFSCleanUp/) 
		or 	$str_boj 
		or 	pe.imports(/msxfs/i, /WFSClose/) 
		or 	$str_bok 
		or 	pe.imports(/msxfs/i, /WFSExecute/) 
		or 	$str_bol 
		or 	pe.imports(/msxfs/i, /WFSFreeResult/) 
		or 	$str_bom 
		or 	pe.imports(/msxfs/i, /WFSGetInfo/) 
		or 	$str_bon 
		or 	pe.imports(/msxfs/i, /WFSLock/) 
		or 	$str_boo 
		or 	pe.imports(/msxfs/i, /WFSOpen/) 
		or 	$str_bop 
		or 	pe.imports(/msxfs/i, /WFSRegister/) 
		or 	$str_boq 
		or 	pe.imports(/msxfs/i, /WFSStartUp/) 
		or 	$str_bor 
		or 	pe.imports(/msxfs/i, /WFSUnlock/) 
		or 	$str_bos  
	) 
}

private rule capa_reference_Diebold_ATM_routines : CAPA  { 
  meta: 
 	description = "reference Diebold ATM routines (converted from capa rule)"
	namespace = "targeting/automated-teller-machine/diebold-nixdorf"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.fireeye.com/blog/threat-research/2017/01/new_ploutus_variant.html"
	hash = "b2ad4409323147b63e370745e5209996"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/diebold-nixdorf/reference-diebold-atm-routines.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bot = "DBD_AdvFuncDisp" ascii wide
	$str_bou = "DBD_EPP4" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bot 
		or 	$str_bou  
	) 
}

private rule capa_load_Diebold_Nixdorf_ATM_library : CAPA  { 
  meta: 
 	description = "load Diebold Nixdorf ATM library (converted from capa rule)"
	namespace = "targeting/automated-teller-machine/diebold-nixdorf"
	author = "william.ballenthin@fireeye.com"
	scope = "file"
	references = "https://www.vkremez.com/2017/12/lets-learn-cutlet-atm-malware-internals.html"
	hash = "658b0502b53f718bd0611a638dfd5969"
	hash = "8683c43f1e22363ce98f0a89ca4ed389"
	hash = "953bc3e68f0a49c6ade30b52a2bfaaab"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/diebold-nixdorf/load-diebold-nixdorf-atm-library.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bov = "CSCWCNG.dll" ascii wide
	$str_bow = "CscCngStatusWrite" ascii wide
	$str_box = "CscCngCasRefInit" ascii wide
	$str_boy = "CscCngEncryption" ascii wide
	$str_boz = "CscCngRecovery" ascii wide
	$str_bpa = "CscCngService" ascii wide
	$str_bpb = "CscCngOpen" ascii wide
	$str_bpc = "CscCngReset" ascii wide
	$str_bpd = "CscCngClose" ascii wide
	$str_bpe = "CscCngDispense" ascii wide
	$str_bpf = "CscCngTransport" ascii wide
	$str_bpg = "CscCngStatusRead" ascii wide
	$str_bph = "CscCngInit" ascii wide
	$str_bpi = "CscCngGetRelease" ascii wide
	$str_bpj = "CscCngLock" ascii wide
	$str_bpk = "CscCngUnlock" ascii wide
	$str_bpl = "CscCngShutter" ascii wide
	$str_bpm = "CscCngPowerOff" ascii wide
	$str_bpn = "CscCngSelStatus" ascii wide
	$str_bpo = "CscCngBim" ascii wide
	$str_bpp = "CscCngConfigure" ascii wide
	$str_bpq = "CscCngStatistics" ascii wide
	$str_bpr = "CscCngControl" ascii wide
	$str_bps = "CscCngPsm" ascii wide
	$str_bpt = "CscCngGetTrace" ascii wide
	$str_bpu = "CscCngOptimization" ascii wide
	$str_bpv = "CscCngSelftest" ascii wide
	$str_bpw = "CscCngEco" ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/cscwcng/i, /dll/) 
		or 	$str_bov 
		or 	pe.imports(/cscwcng/i, /CscCngStatusWrite/) 
		or 	pe.imports(/cscwcng/i, /CscCngCasRefInit/) 
		or 	pe.imports(/cscwcng/i, /CscCngEncryption/) 
		or 	pe.imports(/cscwcng/i, /CscCngRecovery/) 
		or 	pe.imports(/cscwcng/i, /CscCngService/) 
		or 	pe.imports(/cscwcng/i, /CscCngOpen/) 
		or 	pe.imports(/cscwcng/i, /CscCngReset/) 
		or 	pe.imports(/cscwcng/i, /CscCngClose/) 
		or 	pe.imports(/cscwcng/i, /CscCngDispense/) 
		or 	pe.imports(/cscwcng/i, /CscCngTransport/) 
		or 	pe.imports(/cscwcng/i, /CscCngStatusRead/) 
		or 	pe.imports(/cscwcng/i, /CscCngInit/) 
		or 	pe.imports(/cscwcng/i, /CscCngGetRelease/) 
		or 	pe.imports(/cscwcng/i, /CscCngLock/) 
		or 	pe.imports(/cscwcng/i, /CscCngUnlock/) 
		or 	pe.imports(/cscwcng/i, /CscCngShutter/) 
		or 	pe.imports(/cscwcng/i, /CscCngPowerOff/) 
		or 	pe.imports(/cscwcng/i, /CscCngSelStatus/) 
		or 	pe.imports(/cscwcng/i, /CscCngBim/) 
		or 	pe.imports(/cscwcng/i, /CscCngConfigure/) 
		or 	pe.imports(/cscwcng/i, /CscCngStatistics/) 
		or 	pe.imports(/cscwcng/i, /CscCngControl/) 
		or 	pe.imports(/cscwcng/i, /CscCngPsm/) 
		or 	pe.imports(/cscwcng/i, /CscCngGetTrace/) 
		or 	pe.imports(/cscwcng/i, /CscCngOptimization/) 
		or 	pe.imports(/cscwcng/i, /CscCngSelftest/) 
		or 	pe.imports(/cscwcng/i, /CscCngEco/) 
		or 	$str_bow 
		or 	$str_box 
		or 	$str_boy 
		or 	$str_boz 
		or 	$str_bpa 
		or 	$str_bpb 
		or 	$str_bpc 
		or 	$str_bpd 
		or 	$str_bpe 
		or 	$str_bpf 
		or 	$str_bpg 
		or 	$str_bph 
		or 	$str_bpi 
		or 	$str_bpj 
		or 	$str_bpk 
		or 	$str_bpl 
		or 	$str_bpm 
		or 	$str_bpn 
		or 	$str_bpo 
		or 	$str_bpp 
		or 	$str_bpq 
		or 	$str_bpr 
		or 	$str_bps 
		or 	$str_bpt 
		or 	$str_bpu 
		or 	$str_bpv 
		or 	$str_bpw  
	) 
}

private rule capa_initialize_WinHTTP_library : CAPA C0002_008  { 
  meta: 
 	description = "initialize WinHTTP library (converted from capa rule)"
	namespace = "communication/http"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::WinHTTP [C0002.008]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/initialize-winhttp-library.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/winhttp/i, /WinHttpOpen/)  
	) 
}

private rule capa_set_HTTP_header : CAPA C0002_013  { 
  meta: 
 	description = "set HTTP header (converted from capa rule)"
	namespace = "communication/http"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Set Header [C0002.013]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/set-http-header.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/winhttp/i, /WinHttpAddRequestHeaders/)  
	) 
}

private rule capa_initialize_IWebBrowser2 : CAPA C0002_010  { 
  meta: 
 	description = "initialize IWebBrowser2 (converted from capa rule)"
	namespace = "communication/http"
	author = "matthew.williams@fireeye.com"
	scope = "basic block"
	mbc = "Communication::HTTP Communication::IWebBrowser [C0002.010]"
	hash = "395EB0DDD99D2C9E37B6D0B73485EE9C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/initialize-iwebbrowser2.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$bpx = { 01 DF 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 } // CLSID_InternetExplorer
	$bpy = { 61 16 0C D3 AF CD D0 11 8A 3E 00 C0 4F C9 E2 6E } // IID_IWebBrowser2
 
  condition:
    capa_pe_file and
 (
			pe.imports(/ole32/i, /CoCreateInstance/) 
		and 	$bpx 
		and 	$bpy  
	) 
}

private rule capa_read_HTTP_header : CAPA C0002_014  { 
  meta: 
 	description = "read HTTP header (converted from capa rule)"
	namespace = "communication/http"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Read Header [C0002.014]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/read-http-header.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/winhttp/i, /WinHttpQueryHeaders/)  
	) 
}

private rule capa_send_HTTP_response : CAPA C0002_016  { 
  meta: 
 	description = "send HTTP response (converted from capa rule)"
	namespace = "communication/http/server"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Send Response [C0002.016]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/server/send-http-response.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/httpapi/i, /HttpSendHttpResponse/)  
	) 
}

private rule capa_start_HTTP_server : CAPA C0002_018  { 
  meta: 
 	description = "start HTTP server (converted from capa rule)"
	namespace = "communication/http/server"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Start Server [C0002.018]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/server/start-http-server.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/httpapi/i, /HttpInitialize/)  
	) 
}

private rule capa_receive_HTTP_response : CAPA C0002_017  { 
  meta: 
 	description = "receive HTTP response (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Get Response [C0002.017]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/receive-http-response.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/winhttp/i, /WinHttpReceiveResponse/) 
		or  (
			pe.imports(/winhttp/i, /WinHttpReadData/)  
	)  
	) 
}

private rule capa_create_HTTP_request : CAPA C0002_012  { 
  meta: 
 	description = "create HTTP request (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Create Request [C0002.012]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/create-http-request.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/wininet/i, /InternetOpen/)  
	) 
}

private rule capa_connect_to_URL : CAPA C0002_004  { 
  meta: 
 	description = "connect to URL (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Open URL [C0002.004]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/connect-to-url.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/wininet/i, /InternetOpenUrl/)  
	) 
}

private rule capa_send_file_via_HTTP : CAPA C0002_005  { 
  meta: 
 	description = "send file via HTTP (converted from capa rule)"
	namespace = "communication/http/client"
	author = "matthew.williams@fireeye.com"
	scope = "basic block"
	mbc = "Communication::HTTP Communication::Send Data [C0002.005]"
	hash = "EAAD7DFC78304B977D3844CC63577152"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/send-file-via-http.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/wininet/i, /InternetWriteFile/)  
	) 
}

private rule capa_download_URL_to_file : CAPA C0002_006  { 
  meta: 
 	description = "download URL to file (converted from capa rule)"
	namespace = "communication/http/client"
	author = "matthew.williams@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Download URL [C0002.006]"
	hash = "F5C93AC768C8206E87544DDD76B3277C"
	hash = "Practical Malware Analysis Lab 20-01.exe_:0x401040"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/download-url-to-file.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/urlmon/i, /URLDownloadToFile/) 
		or 	pe.imports(/urlmon/i, /URLDownloadToCacheFile/)  
	) 
}

private rule capa_prepare_HTTP_request : CAPA C0002_012  { 
  meta: 
 	description = "prepare HTTP request (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Create Request [C0002.012]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/prepare-http-request.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/winhttp/i, /WinHttpOpenRequest/)  
	) 
}

private rule capa_read_data_from_Internet : CAPA C0002_017  { 
  meta: 
 	description = "read data from Internet (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Get Response [C0002.017]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/read-data-from-internet.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/wininet/i, /InternetReadFile/) 
		or 	pe.imports(/wininet/i, /InternetReadFileEx/)  
	)  
	) 
}

private rule capa_connect_to_HTTP_server : CAPA C0002_009  { 
  meta: 
 	description = "connect to HTTP server (converted from capa rule)"
	namespace = "communication/http/client"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Connect to Server [C0002.009]"
	hash = "6f99a2c8944cb02ff28c6f9ced59b161"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/connect-to-http-server.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/wininet/i, /InternetConnect/)  
	) 
}

private rule capa_send_file_using_FTP_via_wininet : CAPA C0004_001 C0004_002  { 
  meta: 
 	description = "send file using FTP via wininet (converted from capa rule)"
	namespace = "communication/ftp/send"
	author = "michael.hunhof@fireeye.com"
	scope = "function"
	mbc = "Communication::FTP Communication::Send File [C0004.001]"
	mbc = "Communication::FTP Communication::WinINet [C0004.002]"
	hash = "Practical Malware Analysis Lab 20-02.exe_:0x401380"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/ftp/send/send-file-using-ftp-via-wininet.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/wininet/i, /FtpPutFile/)  
	) 
}

private rule capa_send_ICMP_echo_request : CAPA C0014_002  { 
  meta: 
 	description = "send ICMP echo request (converted from capa rule)"
	namespace = "communication/icmp"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::ICMP Communication::Echo Request [C0014.002]"
	references = "https://docs.microsoft.com/en-us/windows/win32/api/icmpapi/"
	hash = "al-khaser_x86.exe_:0x449510"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/icmp/send-icmp-echo-request.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_bqb = /\bIcmpSendEcho(A|W)?\b/ ascii wide
	$api_bqc = /\bIcmpSendEcho2(A|W)?\b/ ascii wide
	$api_bqd = /\bIcmpSendEcho2Ex(A|W)?\b/ ascii wide
	$api_bqe = /\bIcmp6SendEcho2(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$api_bqb 
		or 	$api_bqc 
		or 	$api_bqd 
		or 	$api_bqe  
	)  
	) 
}

private rule capa_initialize_Winsock_library : CAPA C0001_009  { 
  meta: 
 	description = "initialize Winsock library (converted from capa rule)"
	namespace = "communication/socket"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::Socket Communication::Initialize Winsock Library [C0001.009]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/socket/initialize-winsock-library.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/ws2_32/i, /WSAStartup/)  
	) 
}

private rule capa_get_socket_status : CAPA T1016 C0001_012  { 
  meta: 
 	description = "get socket status (converted from capa rule)"
	namespace = "communication/socket"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	mbc = "Communication::Socket Communication::Get Socket Status [C0001.012]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/socket/get-socket-status.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/ws2_32/i, /select/)  
	) 
}

private rule capa_set_socket_configuration : CAPA C0001_001  { 
  meta: 
 	description = "set socket configuration (converted from capa rule)"
	namespace = "communication/socket"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::Socket Communication::Set Socket Config [C0001.001]"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/socket/set-socket-configuration.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/ws2_32/i, /setsockopt/) 
		or 	pe.imports(/ws2_32/i, /ioctlsocket/)  
	) 
}

private rule capa_receive_data_on_socket : CAPA C0001_006  { 
  meta: 
 	description = "receive data on socket (converted from capa rule)"
	namespace = "communication/socket/receive"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Communication::Socket Communication::Receive Data [C0001.006]"
	hash = "Practical Malware Analysis Lab 01-01.dll_:0x10001010"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/socket/receive/receive-data-on-socket.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/ws2_32/i, /recv/) 
		or 	pe.imports(/ws2_32/i, /recvfrom/) 
		or 	pe.imports(/ws2_32/i, /WSARecv/) 
		or 	pe.imports(/ws2_32/i, /WSARecvDisconnect/) 
		or 	pe.imports(/ws2_32/i, /WSARecvEx/) 
		or 	pe.imports(/ws2_32/i, /WSARecvFrom/) 
		or 	pe.imports(/ws2_32/i, /WSARecvMsg/)  
	) 
}

private rule capa_send_data_on_socket : CAPA C0001_007  { 
  meta: 
 	description = "send data on socket (converted from capa rule)"
	namespace = "communication/socket/send"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Communication::Socket Communication::Send Data [C0001.007]"
	hash = "Practical Malware Analysis Lab 01-01.dll_:0x10001010"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/socket/send/send-data-on-socket.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/ws2_32/i, /send/) 
		or 	pe.imports(/ws2_32/i, /sendto/) 
		or 	pe.imports(/ws2_32/i, /WSASend/) 
		or 	pe.imports(/ws2_32/i, /WSASendMsg/) 
		or 	pe.imports(/ws2_32/i, /WSASendTo/)  
	) 
}

private rule capa_create_pipe : CAPA C0003_001  { 
  meta: 
 	description = "create pipe (converted from capa rule)"
	namespace = "communication/named-pipe/create"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Communication::Interprocess Communication::Create Pipe [C0003.001]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10003a13"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/named-pipe/create/create-pipe.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /CreatePipe/) 
		or 	pe.imports(/kernel32/i, /CreateNamedPipe/)  
	) 
}

private rule capa_connect_pipe : CAPA C0003_002  { 
  meta: 
 	description = "connect pipe (converted from capa rule)"
	namespace = "communication/named-pipe/connect"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::Interprocess Communication::Connect Pipe [C0003.002]"
	hash = "152d4c9f63efb332ccb134c6953c0104"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/named-pipe/connect/connect-pipe.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /ConnectNamedPipe/) 
		or 	pe.imports(/kernel32/i, /CallNamedPipe/)  
	) 
}

private rule capa_read_pipe : CAPA C0003_003  { 
  meta: 
 	description = "read pipe (converted from capa rule)"
	namespace = "communication/named-pipe/read"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	description = "PeekNamedPipe isn't required to read from a pipe; however, pipes are often utilized to capture the output of a cmd.exe process. In a multi-thread instance, a new thread is created that calls PeekNamedPipe and ReadFile to obtain the command output."
	scope = "function"
	mbc = "Communication::Interprocess Communication::Read Pipe [C0003.003]"
	hash = "Practical Malware Analysis Lab 14-02.exe_:0x4014C0"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/named-pipe/read/read-pipe.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/kernel32/i, /PeekNamedPipe/) 
		and 	pe.imports(/kernel32/i, /ReadFile/)  
	) 
		or 	pe.imports(/kernel32/i, /TransactNamedPipe/) 
		or 	pe.imports(/kernel32/i, /CallNamedPipe/)  
	) 
}

private rule capa_access_PE_header : CAPA T1129  { 
  meta: 
 	description = "access PE header (converted from capa rule)"
	namespace = "load-code/pe"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Execution::Shared Modules [T1129]"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/load-code/pe/access-pe-header.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_bqf = /\bRtlImageNtHeader(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_bqf 
		or 	pe.imports(/ntdll/i, /RtlImageNtHeaderEx/)  
	) 
}

private rule capa_acquire_credentials_from_Windows_Credential_Manager : CAPA T1555_004  { 
  meta: 
 	description = "acquire credentials from Windows Credential Manager (converted from capa rule)"
	namespace = "collection"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores::Windows Credential Manager [T1555.004]"
	hash = "c56af5561e3f20bed435fb4355cffc29"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/acquire-credentials-from-windows-credential-manager.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bqg = ".vcrd" ascii wide
	$str_bqh = "*.vcrd" ascii wide
	$str_bqi = "Policy.vpol" ascii wide
	$re_bqj = /AppData\\Local\\Microsoft\\(Vault|Credentials)/ ascii wide 
	$api_bqk = /\bCredEnumerate(A|W)?\b/ ascii wide
	$re_bql = /vaultcmd(\.exe)?/ ascii wide 
	$re_bqm = /\/listcreds:/ ascii wide 
	$re_bqn = /"Windows Credentials"/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$str_bqg 
		or 	$str_bqh 
		or 	$str_bqi 
		or 	$re_bqj 
		or 	$api_bqk 
		or  (
		 (
			$re_bql 
		or 	$re_bqm 
		or 	$re_bqn  
	)  
	)  
	) 
}

private rule capa_get_geographical_location : CAPA T1614  { 
  meta: 
 	description = "get geographical location (converted from capa rule)"
	namespace = "collection"
	author = "moritz.raabe"
	scope = "function"
	attack = "Discovery::System Location Discovery [T1614]"
	hash = "9879D201DC5ACA863F357184CD1F170E"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/get-geographical-location.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_bqo = /\bGetLocaleInfo(A|W)?\b/ ascii wide
	$api_bqp = /\bGetLocaleInfoEx(A|W)?\b/ ascii wide
	$re_bqq = /geolocation/ nocase ascii wide 
	$re_bqr = /geo-location/ nocase ascii wide 
	$re_bqs = /\bcity/ nocase ascii wide 
	$re_bqt = /region_code/ nocase ascii wide 
	$re_bqu = /region_name/ nocase ascii wide 
	$re_bqv = /\bcountry/ nocase ascii wide 
	$re_bqw = /country_code/ nocase ascii wide 
	$re_bqx = /countrycode/ nocase ascii wide 
	$re_bqy = /country_name/ nocase ascii wide 
	$re_bqz = /continent_code/ nocase ascii wide 
	$re_bra = /continent_name/ nocase ascii wide 
	$re_brb = /\blatitude/ nocase ascii wide 
	$re_brc = /\blongitude/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$api_bqo 
		or 	$api_bqp 
		or 	$re_bqq 
		or 	$re_bqr 
		or 	$re_bqs 
		or 	$re_bqt 
		or 	$re_bqu 
		or 	$re_bqv 
		or 	$re_bqw 
		or 	$re_bqx 
		or 	$re_bqy 
		or 	$re_bqz 
		or 	$re_bra 
		or 	$re_brb 
		or 	$re_brc  
	) 
}

private rule capa_log_keystrokes_via_polling : CAPA T1056_001 F0002_002  { 
  meta: 
 	description = "log keystrokes via polling (converted from capa rule)"
	namespace = "collection/keylog"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Collection::Input Capture::Keylogging [T1056.001]"
	mbc = "Collection::Keylogging::Polling [F0002.002]"
	hash = "Practical Malware Analysis Lab 11-03.dll_:0x10001030"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/keylog/log-keystrokes-via-polling.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/user32/i, /GetAsyncKeyState/) 
		or 	pe.imports(/user32/i, /GetKeyState/) 
		or 	pe.imports(/user32/i, /GetKeyboardState/) 
		or 	pe.imports(/user32/i, /VkKeyScan/) 
		or 	pe.imports(/user32/i, /VkKeyScanEx/) 
		or 	pe.imports(/user32/i, /GetKeyNameText/)  
	) 
}

private rule capa_log_keystrokes : CAPA T1056_001  { 
  meta: 
 	description = "log keystrokes (converted from capa rule)"
	namespace = "collection/keylog"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Collection::Input Capture::Keylogging [T1056.001]"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/keylog/log-keystrokes.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_bre = /\bSetWindowsHookEx(A|W)?\b/ ascii wide
	$api_brf = /\bGetKeyState(A|W)?\b/ ascii wide
	$api_brg = /\bRegisterHotKey(A|W)?\b/ ascii wide
	$api_brh = /\bUnregisterHotKey(A|W)?\b/ ascii wide
	$api_bri = /\bCallNextHookEx(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$api_bre 
		and 	$api_brf  
	) 
		or  (
			$api_brg 
		and 	pe.imports(/user32/i, /keybd_event/) 
		and 	$api_brh  
	) 
		or  (
			$api_bri 
		and 	pe.imports(/user32/i, /GetKeyNameText/) 
		and 	pe.imports(/user32/i, /GetAsyncKeyState/) 
		and 	pe.imports(/user32/i, /GetForgroundWindow/)  
	) 
		or 	pe.imports(/user32/i, /AttachThreadInput/) 
		or 	pe.imports(/user32/i, /MapVirtualKey/)  
	) 
}

private rule capa_capture_microphone_audio : CAPA T1123  { 
  meta: 
 	description = "capture microphone audio (converted from capa rule)"
	namespace = "collection/microphone"
	author = "@_re_fox"
	scope = "function"
	attack = "Collection::Audio Capture [T1123]"
	hash = "a70052c45e907820187c7e6bcdc7ecca"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/microphone/capture-microphone-audio.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_brj = /\bmciSendString(A|W)?\b/ ascii wide
	$re_brk = /\bopen/ nocase ascii wide 
	$re_brl = /waveaudio/ nocase ascii wide 
	$re_brm = /\brecord/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$api_brj 
		and 	$re_brk 
		and 	$re_brl 
		and 	$re_brm  
	) 
}

private rule capa_get_domain_trust_relationships : CAPA T1482  { 
  meta: 
 	description = "get domain trust relationships (converted from capa rule)"
	namespace = "collection/network"
	author = "johnk3r"
	scope = "function"
	attack = "Discovery::Domain Trust Discovery  [T1482]"
	hash = "0796f1c1ea0a142fc1eb7109a44c86cb"
	hash = "0731679c5f99e8ee65d8b29a3cabfc6b"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/network/get-domain-trust-relationships.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_brn = /nltest/ nocase ascii wide 
	$re_bro = /\/domain_trusts/ nocase ascii wide 
	$re_brp = /\/dclist/ nocase ascii wide 
	$re_brq = /\/all_trusts/ nocase ascii wide 
	$api_brr = /\bDsEnumerateDomainTrusts(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$re_brn 
		and  (
			$re_bro 
		or 	$re_brp 
		or 	$re_brq  
	)  
	) 
		or 	$api_brr  
	) 
}

private rule capa_capture_network_configuration_via_ipconfig : CAPA T1016  { 
  meta: 
 	description = "capture network configuration via ipconfig (converted from capa rule)"
	namespace = "collection/network"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	hash = "7204e3efc2434012e13ca939db0d0b02"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/network/capture-network-configuration-via-ipconfig.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_brs = /ipconfig(\.exe)?/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_brs 
		and 	pe.imports(/msvcr100/i, /system/)  
	) 
}

private rule capa_capture_public_ip : CAPA T1016  { 
  meta: 
 	description = "capture public ip (converted from capa rule)"
	namespace = "collection/network"
	author = "@_re_fox"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	hash = "84f1b049fa8962b215a77f51af6714b3"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/network/capture-public-ip.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_brt = /\bInternetOpen(A|W)?\b/ ascii wide
	$api_bru = /\bInternetOpenUrl(A|W)?\b/ ascii wide
	$api_brv = /\bInternetReadFile(A|W)?\b/ ascii wide
	$re_brw = /bot\.whatismyipaddress\.com/ ascii wide 
	$re_brx = /ipinfo\.io\/ip/ ascii wide 
	$re_bry = /checkip\.dyndns\.org/ ascii wide 
	$re_brz = /ifconfig\.me/ ascii wide 
	$re_bsa = /ipecho\.net\/plain/ ascii wide 
	$re_bsb = /api\.ipify\.org/ ascii wide 
	$re_bsc = /checkip\.amazonaws\.com/ ascii wide 
	$re_bsd = /icanhazip\.com/ ascii wide 
	$re_bse = /wtfismyip\.com\/text/ ascii wide 
	$re_bsf = /api\.myip\.com/ ascii wide 
	$re_bsg = /ip\-api\.com\/line/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$api_brt 
		and 	$api_bru 
		and 	$api_brv 
		and  (
			$re_brw 
		or 	$re_brx 
		or 	$re_bry 
		or 	$re_brz 
		or 	$re_bsa 
		or 	$re_bsb 
		or 	$re_bsc 
		or 	$re_bsd 
		or 	$re_bse 
		or 	$re_bsf 
		or 	$re_bsg  
	)  
	) 
}

private rule capa_gather_cuteftp_information : CAPA T1555  { 
  meta: 
 	description = "gather cuteftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://en.wikipedia.org/wiki/CuteFTP"
	references = "https://www.globalscape.com/cuteftp"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-cuteftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bsh = /\\sm\.dat/ ascii wide 
	$re_bsi = /\\GlobalSCAPE\\CuteFTP/ nocase ascii wide 
	$re_bsj = /\\GlobalSCAPE\\CuteFTP Pro/ nocase ascii wide 
	$re_bsk = /\\CuteFTP/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_bsh 
		and  (
			$re_bsi 
		or 	$re_bsj 
		or 	$re_bsk  
	)  
	) 
}

private rule capa_gather_ftprush_information : CAPA T1555  { 
  meta: 
 	description = "gather ftprush information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.wftpserver.com/ftprush.htm"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftprush-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bsl = /\\FTPRush/ ascii wide 
	$re_bsm = /RushSite\.xml/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_bsl 
		and 	$re_bsm  
	) 
}

private rule capa_gather_smart_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather smart-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.smartftp.com/en-us/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-smart-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bsn = /\\SmartFTP/ ascii wide 
	$str_bso = ".xml" ascii wide
	$re_bsp = /Favorites\.dat/ nocase ascii wide 
	$re_bsq = /History\.dat/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			$re_bsn 
		and 	$str_bso 
		and 	$re_bsp 
		and 	$re_bsq  
	)  
	) 
}

private rule capa_gather_cyberduck_information : CAPA T1555  { 
  meta: 
 	description = "gather cyberduck information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://cyberduck.io/ftp/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-cyberduck-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bsr = /\\Cyberduck/ ascii wide 
	$str_bss = "user.config" ascii wide
	$str_bst = ".duck" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_bsr 
		and  (
			$str_bss 
		or 	$str_bst  
	)  
	) 
}

private rule capa_gather_ws_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather ws-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ipswitch.com/ftp-server"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ws-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bsu = /\\Ipswitch\\WS_FTP/ ascii wide 
	$re_bsv = /\\win\.ini/ ascii wide 
	$re_bsw = /WS_FTP/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_bsu 
		and 	$re_bsv 
		and 	$re_bsw  
	) 
}

private rule capa_gather_fling_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather fling-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.nchsoftware.com/fling/index.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-fling-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bsx = /SOFTWARE\\NCH Software\\Fling\\Accounts/ ascii wide 
	$str_bsy = "FtpPassword" ascii wide
	$str_bsz = "_FtpPassword" ascii wide
	$str_bta = "FtpServer" ascii wide
	$str_btb = "FtpUserName" ascii wide
	$str_btc = "FtpDirectory" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_bsx 
		or  (
			$str_bsy 
		and 	$str_bsz 
		and 	$str_bta 
		and 	$str_btb 
		and 	$str_btc  
	)  
	) 
}

private rule capa_gather_directory_opus_information : CAPA T1555  { 
  meta: 
 	description = "gather directory-opus information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.gpsoft.com.au/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-directory-opus-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_btd = /\\GPSoftware\\Directory Opus/ ascii wide 
	$str_bte = ".oxc" ascii wide
	$str_btf = ".oll" ascii wide
	$str_btg = "ftplast.osd" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_btd 
		and 	$str_bte 
		and 	$str_btf 
		and 	$str_btg  
	) 
}

private rule capa_gather_coreftp_information : CAPA T1555  { 
  meta: 
 	description = "gather coreftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.coreftp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-coreftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bth = /Software\\FTPWare\\COREFTP\\Sites/ ascii wide 
	$str_bti = "Host" ascii wide
	$str_btj = "User" ascii wide
	$str_btk = "Port" ascii wide
	$str_btl = "PthR" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_bth 
		or  (
			$str_bti 
		and 	$str_btj 
		and 	$str_btk 
		and 	$str_btl  
	)  
	) 
}

private rule capa_gather_wise_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather wise-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.wise-ftp.de/en/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-wise-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_btm = "wiseftpsrvs.ini" ascii wide
	$str_btn = "wiseftp.ini" ascii wide
	$str_bto = "wiseftpsrvs.bin" ascii wide
	$str_btp = "wiseftpsrvs.bin" ascii wide
	$re_btq = /\\AceBIT/ ascii wide 
	$re_btr = /Software\\AceBIT/ ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			$str_btm 
		and 	$str_btn 
		and 	$str_bto  
	) 
		or  (
			$str_btp 
		and  (
			$re_btq 
		or 	$re_btr  
	)  
	)  
	) 
}

private rule capa_gather_winzip_information : CAPA T1555  { 
  meta: 
 	description = "gather winzip information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.winzip.com/win/en/pages/old-brands/nico-mak-computing/index.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-winzip-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bts = /Software\\Nico Mak Computing\\WinZip\\FTP/ ascii wide 
	$re_btt = /Software\\Nico Mak Computing\\WinZip\\mru\\jobs/ ascii wide 
	$str_btu = "Site" ascii wide
	$str_btv = "UserID" ascii wide
	$str_btw = "xflags" ascii wide
	$str_btx = "Port" ascii wide
	$str_bty = "Folder" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$re_bts 
		and 	$re_btt  
	) 
		or  (
			$str_btu 
		and 	$str_btv 
		and 	$str_btw 
		and 	$str_btx 
		and 	$str_bty  
	)  
	) 
}

private rule capa_gather_southriver_webdrive_information : CAPA T1555  { 
  meta: 
 	description = "gather southriver-webdrive information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://southrivertech.com/products/webdriveclient/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-southriver-webdrive-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_btz = /Software\\South River Technologies\\WebDrive\\Connections/ ascii wide 
	$str_bua = "PassWord" ascii wide
	$str_bub = "UserName" ascii wide
	$str_buc = "RootDirectory" ascii wide
	$str_bud = "Port" ascii wide
	$str_bue = "ServerType" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_btz 
		or  (
			$str_bua 
		and 	$str_bub 
		and 	$str_buc 
		and 	$str_bud 
		and 	$str_bue  
	)  
	) 
}

private rule capa_gather_freshftp_information : CAPA T1555  { 
  meta: 
 	description = "gather freshftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-freshftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_buf = "FreshFTP" ascii wide
	$str_bug = ".SMF" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_buf 
		and 	$str_bug  
	) 
}

private rule capa_gather_fasttrack_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather fasttrack-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.fasttracksoft.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-fasttrack-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_buh = "FastTrack" ascii wide
	$str_bui = "ftplist.txt" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$str_buh 
		and 	$str_bui  
	)  
	) 
}

private rule capa_gather_classicftp_information : CAPA T1555  { 
  meta: 
 	description = "gather classicftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.nchsoftware.com/classic/index.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-classicftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_buj = /Software\\NCH Software\\ClassicFTP\\FTPAccounts/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_buj  
	) 
}

private rule capa_gather_softx_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather softx-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.softx.org/ftp.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-softx-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_buk = /Software\\FTPClient\\Sites/ ascii wide 
	$re_bul = /Software\\SoftX.org\\FTPClient\\Sites/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_buk 
		or 	$re_bul  
	) 
}

private rule capa_gather_ffftp_information : CAPA T1555  { 
  meta: 
 	description = "gather ffftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www2.biglobe.ne.jp/sota/ffftp-e.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ffftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bum = /Software\\Sota\\FFFTP\\Options/ ascii wide 
	$re_bun = /Software\\Sota\\FFFTP/ ascii wide 
	$re_buo = /CredentialSalt/ ascii wide 
	$re_bup = /CredentialCheck/ ascii wide 
	$str_buq = "Password" ascii wide
	$str_bur = "UserName" ascii wide
	$str_bus = "HostAdrs" ascii wide
	$str_but = "RemoteDir" ascii wide
	$str_buu = "Port" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
		 (
			$re_bum 
		or 	$re_bun  
	) 
		and  (
			$re_buo 
		or 	$re_bup  
	)  
	) 
		or  (
			$str_buq 
		and 	$str_bur 
		and 	$str_bus 
		and 	$str_but 
		and 	$str_buu  
	)  
	) 
}

private rule capa_gather_ftpshell_information : CAPA T1555  { 
  meta: 
 	description = "gather ftpshell information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ftpshell.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpshell-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_buv = "FTPShell" ascii wide
	$str_buw = "ftpshell.fsi" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_buv 
		and 	$str_buw  
	) 
}

private rule capa_gather_winscp_information : CAPA T1555  { 
  meta: 
 	description = "gather winscp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://winscp.net/eng/download.php"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-winscp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bux = "Password" ascii wide
	$str_buy = "HostName" ascii wide
	$str_buz = "UserName" ascii wide
	$str_bva = "RemoteDirectory" ascii wide
	$str_bvb = "PortNumber" ascii wide
	$str_bvc = "FSProtocol" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bux 
		and 	$str_buy 
		and 	$str_buz 
		and 	$str_bva 
		and 	$str_bvb 
		and 	$str_bvc  
	) 
}

private rule capa_gather_frigate3_information : CAPA T1555  { 
  meta: 
 	description = "gather frigate3 information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.frigate3.com/index.php"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-frigate3-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bvd = /FtpSite\.xml/ ascii wide 
	$re_bve = /\\Frigate3/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_bvd 
		and 	$re_bve  
	) 
}

private rule capa_gather_staff_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather staff-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.gsa-online.de/product/staffftp/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-staff-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bvf = "Staff-FTP" ascii wide
	$str_bvg = "sites.ini" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bvf 
		and 	$str_bvg  
	) 
}

private rule capa_gather_xftp_information : CAPA T1555  { 
  meta: 
 	description = "gather xftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.netsarang.com/en/xftp-download/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-xftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bvh = ".xfp" ascii wide
	$re_bvi = /\\NetSarang/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$str_bvh 
		and 	$re_bvi  
	) 
}

private rule capa_gather_ftpnow_information : CAPA T1555  { 
  meta: 
 	description = "gather ftpnow information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpnow-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bvp = "FTPNow" ascii wide
	$str_bvq = "FTP Now" ascii wide
	$str_bvr = "sites.xml" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bvp 
		and 	$str_bvq 
		and 	$str_bvr  
	) 
}

private rule capa_gather_ftpgetter_information : CAPA T1555  { 
  meta: 
 	description = "gather ftpgetter information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ftpgetter.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpgetter-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bvs = "servers.xml" ascii wide
	$re_bvt = /\\FTPGetter/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$str_bvs 
		and 	$re_bvt  
	) 
}

private rule capa_gather_nova_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather nova-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-nova-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bvu = "NovaFTP.db" ascii wide
	$re_bvv = /\\INSoftware\\NovaFTP/ ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			$str_bvu 
		and 	$re_bvv  
	)  
	) 
}

private rule capa_gather_ftp_explorer_information : CAPA T1555  { 
  meta: 
 	description = "gather ftp-explorer information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.ftpx.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftp-explorer-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bvw = /profiles\.xml/ ascii wide 
	$re_bvx = /Software\\FTP Explorer\\FTP Explorer\\Workspace\\MFCToolBar-224/ ascii wide 
	$re_bvy = /Software\\FTP Explorer\\Profiles/ ascii wide 
	$re_bvz = /\\FTP Explorer/ ascii wide 
	$str_bwa = "Password" ascii wide
	$str_bwb = "Host" ascii wide
	$str_bwc = "Login" ascii wide
	$str_bwd = "InitialPath" ascii wide
	$str_bwe = "PasswordType" ascii wide
	$str_bwf = "Port" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$re_bvw 
		and  (
			$re_bvx 
		or 	$re_bvy 
		or 	$re_bvz  
	)  
	) 
		or  (
			$str_bwa 
		and 	$str_bwb 
		and 	$str_bwc 
		and 	$str_bwd 
		and 	$str_bwe 
		and 	$str_bwf  
	)  
	) 
}

private rule capa_gather_bitkinex_information : CAPA T1555  { 
  meta: 
 	description = "gather bitkinex information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.bitkinex.com/ftp/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-bitkinex-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bwg = /bitkinex\.ds/ ascii wide 
	$re_bwh = /\\BitKinex/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_bwg 
		and 	$re_bwh  
	) 
}

private rule capa_gather_turbo_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather turbo-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.tbsoftinc.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-turbo-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bwi = "addrbk.dat" ascii wide
	$str_bwj = "quick.dat" ascii wide
	$re_bwk = /installpath/ ascii wide 
	$re_bwl = /Software\\TurboFTP/ ascii wide 
	$re_bwm = /\\TurboFTP/ ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			$str_bwi 
		and 	$str_bwj  
	) 
		or  (
			$re_bwk 
		and  (
			$re_bwl 
		or 	$re_bwm  
	)  
	)  
	) 
}

private rule capa_gather_nexusfile_information : CAPA T1555  { 
  meta: 
 	description = "gather nexusfile information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.xiles.app/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-nexusfile-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bwn = "NexusFile" ascii wide
	$str_bwo = "ftpsite.ini" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bwn 
		and 	$str_bwo  
	) 
}

private rule capa_gather_ftp_voyager_information : CAPA T1555  { 
  meta: 
 	description = "gather ftp-voyager information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.serv-u.com/free-tools/ftp-voyager-ftp-client-for-windows"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftp-voyager-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bwp = /\\RhinoSoft.com/ ascii wide 
	$str_bwq = "FTPVoyager.ftp" ascii wide
	$str_bwr = "FTPVoyager.qc" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_bwp 
		and 	$str_bwq 
		and 	$str_bwr  
	) 
}

private rule capa_gather_blazeftp_information : CAPA T1555  { 
  meta: 
 	description = "gather blazeftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.slimjet.com/blazeftp/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-blazeftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bws = "BlazeFtp" ascii wide
	$str_bwt = "site.dat" ascii wide
	$str_bwu = "LastPassword" ascii wide
	$str_bwv = "LastAddress" ascii wide
	$str_bww = "LastUser" ascii wide
	$str_bwx = "LastPort" ascii wide
	$re_bwy = /Software\\FlashPeak\\BlazeFtp\\Settings/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$str_bws 
		and 	$str_bwt 
		and  (
			$str_bwu 
		or 	$str_bwv 
		or 	$str_bww 
		or 	$str_bwx 
		or 	$re_bwy  
	)  
	) 
}

private rule capa_gather_ftp_commander_information : CAPA T1555  { 
  meta: 
 	description = "gather ftp-commander information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ftpcommander.com/free.htm"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftp-commander-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bwz = /FTP Navigator/ ascii wide 
	$re_bxa = /FTP Commander/ ascii wide 
	$str_bxb = "ftplist.txt" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$re_bwz 
		or 	$re_bxa  
	) 
		and  (
			$str_bxb  
	)  
	) 
}

private rule capa_gather_filezilla_information : CAPA T1555  { 
  meta: 
 	description = "gather filezilla information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://filezilla-project.org/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-filezilla-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bxc = /\\sitemanager\.xml/ ascii wide 
	$re_bxd = /\\recentservers\.xml/ ascii wide 
	$re_bxe = /\\filezilla.xml/ ascii wide 
	$re_bxf = /Software\\FileZilla/ ascii wide 
	$str_bxg = "Install_Dir" ascii wide
	$re_bxh = /Software\\FileZilla Client/ ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			$re_bxc 
		and 	$re_bxd 
		and 	$re_bxe  
	) 
		or  (
			$re_bxf 
		and 	$str_bxg 
		and 	$re_bxh  
	)  
	) 
}

private rule capa_gather_global_downloader_information : CAPA T1555  { 
  meta: 
 	description = "gather global-downloader information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "http://www.actysoft.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-global-downloader-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bxi = /\\Global Downloader/ ascii wide 
	$str_bxj = "SM.arch" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_bxi 
		and 	$str_bxj  
	) 
}

private rule capa_gather_direct_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather direct-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.coffeecup.com/software/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-direct-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bxk = /Software\\CoffeeCup Software\\Internet\\Profiles/ ascii wide 
	$re_bxl = /\\CoffeeCup Software/ ascii wide 
	$str_bxm = "Password" ascii wide
	$str_bxn = "HostName" ascii wide
	$str_bxo = "Port" ascii wide
	$str_bxp = "Username" ascii wide
	$str_bxq = "HostDirName" ascii wide
	$str_bxr = "FTP destination server" ascii wide
	$str_bxs = "FTP destination user" ascii wide
	$str_bxt = "FTP destination password" ascii wide
	$str_bxu = "FTP destination port" ascii wide
	$str_bxv = "FTP destination catalog" ascii wide
	$str_bxw = "FTP profiles" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_bxk 
		or 	$re_bxl 
		or  (
			$str_bxm 
		and 	$str_bxn 
		and 	$str_bxo 
		and 	$str_bxp 
		and 	$str_bxq  
	) 
		or  (
			$str_bxr 
		and 	$str_bxs 
		and 	$str_bxt 
		and 	$str_bxu 
		and 	$str_bxv 
		and 	$str_bxw  
	)  
	) 
}

private rule capa_gather_faststone_browser_information : CAPA T1555  { 
  meta: 
 	description = "gather faststone-browser information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.faststone.org/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-faststone-browser-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bxx = /FastStone Browser/ ascii wide 
	$str_bxy = "FTPList.db" ascii wide
 
  condition:
    capa_pe_file and
 (
			$re_bxx 
		and 	$str_bxy  
	) 
}

private rule capa_gather_ultrafxp_information : CAPA T1555  { 
  meta: 
 	description = "gather ultrafxp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ultrafxp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bxz = /UltraFXP/ ascii wide 
	$re_bya = /\\sites\.xml/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_bxz 
		and 	$re_bya  
	) 
}

private rule capa_gather_netdrive_information : CAPA T1555  { 
  meta: 
 	description = "gather netdrive information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.netdrive.net/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-netdrive-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_byb = "NDSites.ini" ascii wide
	$re_byc = /\\NetDrive/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$str_byb 
		and 	$re_byc  
	) 
}

private rule capa_gather_total_commander_information : CAPA T1555  { 
  meta: 
 	description = "gather total-commander information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ghisler.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-total-commander-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_byd = /Software\\Ghisler\\Total Commander/ ascii wide 
	$re_bye = /Software\\Ghisler\\Windows Commander/ ascii wide 
	$str_byf = "FtpIniName" ascii wide
	$str_byg = "wcx_ftp.ini" ascii wide
	$re_byh = /\\GHISLER/ ascii wide 
	$str_byi = "InstallDir" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$re_byd 
		or 	$re_bye  
	) 
		and  (
			$str_byf 
		or 	$str_byg 
		or 	$re_byh 
		or 	$str_byi  
	)  
	) 
}

private rule capa_gather_ftpinfo_information : CAPA T1555  { 
  meta: 
 	description = "gather ftpinfo information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.ftpinfo.ru/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpinfo-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_byj = "ServerList.xml" ascii wide
	$str_byk = "DataDir" ascii wide
	$re_byl = /Software\\MAS-Soft\\FTPInfo\\Setup/ ascii wide 
	$re_bym = /FTPInfo/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$str_byj 
		and 	$str_byk 
		and  (
			$re_byl 
		or 	$re_bym  
	)  
	) 
}

private rule capa_gather_flashfxp_information : CAPA T1555  { 
  meta: 
 	description = "gather flashfxp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.flashfxp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-flashfxp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_byn = /Software\\FlashFXP/ ascii wide 
	$re_byo = /DataFolder/ ascii wide 
	$re_byp = /Install Path/ ascii wide 
	$re_byq = /\\Sites.dat/ ascii wide 
	$re_byr = /\\Quick.dat/ ascii wide 
	$re_bys = /\\History.dat/ ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			$re_byn 
		and 	$re_byo 
		and 	$re_byp  
	) 
		or  (
			$re_byq 
		and 	$re_byr 
		and 	$re_bys  
	)  
	) 
}

private rule capa_gather_securefx_information : CAPA T1555  { 
  meta: 
 	description = "gather securefx information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.vandyke.com/products/securefx/index.html"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-securefx-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_byt = /\\Sessions/ ascii wide 
	$str_byu = ".ini" ascii wide
	$re_byv = /Config Path/ ascii wide 
	$re_byw = /_VanDyke\\Config\\Sessions/ ascii wide 
	$re_byx = /Software\\VanDyke\\SecureFX/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_byt 
		and 	$str_byu 
		and 	$re_byv 
		and  (
			$re_byw 
		or 	$re_byx  
	)  
	) 
}

private rule capa_gather_robo_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather robo-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.robo-ftp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-robo-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_byy = /SOFTWARE\\Robo-FTP/ ascii wide 
	$re_byz = /\\FTPServers/ ascii wide 
	$re_bza = /FTP File/ ascii wide 
	$str_bzb = "FTP Count" ascii wide
	$str_bzc = "Password" ascii wide
	$str_bzd = "ServerName" ascii wide
	$str_bze = "UserID" ascii wide
	$str_bzf = "PortNumber" ascii wide
	$str_bzg = "InitialDirectory" ascii wide
	$str_bzh = "ServerType" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$re_byy 
		and  (
			$re_byz 
		or 	$re_bza 
		or 	$str_bzb  
	)  
	) 
		or  (
			$str_bzc 
		and 	$str_bzd 
		and 	$str_bze 
		and 	$str_bzf 
		and 	$str_bzg 
		and 	$str_bzh  
	)  
	) 
}

private rule capa_gather_bulletproof_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather bulletproof-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://bpftp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-bulletproof-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bzi = ".dat" ascii wide
	$str_bzj = ".bps" ascii wide
	$re_bzk = /Software\\BPFTP\\Bullet Proof FTP\\Main/ ascii wide 
	$re_bzl = /Software\\BulletProof Software\\BulletProof FTP Client\\Main/ ascii wide 
	$re_bzm = /Software\\BulletProof Software\\BulletProof FTP Client\\Options/ ascii wide 
	$re_bzn = /Software\\BPFTP\\Bullet Proof FTP\\Options/ ascii wide 
	$re_bzo = /Software\\BPFTP/ ascii wide 
	$str_bzp = "LastSessionFile" ascii wide
	$str_bzq = "SitesDir" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$str_bzi 
		and 	$str_bzj  
	) 
		or  (
		 (
			$re_bzk 
		or 	$re_bzl 
		or 	$re_bzm 
		or 	$re_bzn 
		or 	$re_bzo  
	) 
		and  (
			$str_bzp 
		or 	$str_bzq  
	)  
	)  
	) 
}

private rule capa_gather_alftp_information : CAPA T1555  { 
  meta: 
 	description = "gather alftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://en.wikipedia.org/wiki/ALFTP"
	references = "https://www.altools.co.kr/Main/Default.aspx"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-alftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bzr = "ESTdb2.dat" ascii wide
	$str_bzs = "QData.dat" ascii wide
	$re_bzt = /\\Estsoft\\ALFTP/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$str_bzr 
		and 	$str_bzs 
		and 	$re_bzt  
	) 
}

private rule capa_gather_expandrive_information : CAPA T1555  { 
  meta: 
 	description = "gather expandrive information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.expandrive.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-expandrive-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_bzu = /Software\\ExpanDrive\\Sessions/ ascii wide 
	$re_bzv = /Software\\ExpanDrive/ ascii wide 
	$re_bzw = /ExpanDrive_Home/ ascii wide 
	$re_bzx = /\\drives\.js/ ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			$re_bzu 
		or 	$re_bzv  
	) 
		and  (
			$re_bzw 
		or 	$re_bzx  
	)  
	) 
}

private rule capa_gather_goftp_information : CAPA T1555  { 
  meta: 
 	description = "gather goftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.goftp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-goftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_bzy = "GoFTP" ascii wide
	$str_bzz = "Connections.txt" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_bzy 
		and 	$str_bzz  
	) 
}

private rule capa_gather_3d_ftp_information : CAPA T1555  { 
  meta: 
 	description = "gather 3d-ftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	references = "https://www.3dftp.com/"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-3d-ftp-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_caa = "3D-FTP" ascii wide
	$str_cab = "sites.ini" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_caa 
		and 	$str_cab  
	) 
}

private rule capa_reference_SQL_statements : CAPA T1213  { 
  meta: 
 	description = "reference SQL statements (converted from capa rule)"
	namespace = "collection/database/sql"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Collection::Data from Information Repositories [T1213]"
	hash = "5F66B82558CA92E54E77F216EF4C066C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/database/sql/reference-sql-statements.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_cah = /SELECT.{,1000}FROM.{,1000}WHERE/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_cah  
	) 
}

private rule capa_reference_WMI_statements : CAPA T1213  { 
  meta: 
 	description = "reference WMI statements (converted from capa rule)"
	namespace = "collection/database/wmi"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Collection::Data from Information Repositories [T1213]"
	hash = "al-khaser_x86.exe_:0x433490"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/database/wmi/reference-wmi-statements.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_cai = /SELECT\s+\*\s+FROM\s+CIM_./ ascii wide 
	$re_caj = /SELECT\s+\*\s+FROM\s+Win32_./ ascii wide 
	$re_cak = /SELECT\s+\*\s+FROM\s+MSAcpi_./ ascii wide 
 
  condition:
    capa_pe_file and
 (
			$re_cai 
		or 	$re_caj 
		or 	$re_cak  
	) 
}

private rule capa_write_and_execute_a_file : CAPA B0023  { 
  meta: 
 	description = "write and execute a file (converted from capa rule)"
	namespace = "c2/file-transfer"
	maec_malware_category = "launcher"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Execution::Install Additional Program [B0023]"
	hash = "9324D1A8AE37A36AE560C37448C9705A"
	hash = "Practical Malware Analysis Lab 01-04.exe_:0x4011FC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/c2/file-transfer/write-and-execute-a-file.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			capa_write_file

		and 	capa_create_process
 
	) 
}

private rule capa_self_delete_via_COMSPEC_environment_variable : CAPA T1070_004 F0007_001  { 
  meta: 
 	description = "self delete via COMSPEC environment variable (converted from capa rule)"
	namespace = "anti-analysis/anti-forensic/self-deletion"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Indicator Removal on Host::File Deletion [T1070.004]"
	mbc = "Defense Evasion::Self Deletion::COMSPEC Environment Variable [F0007.001]"
	hash = "Practical Malware Analysis Lab 14-02.exe_:0x401880"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-forensic/self-deletion/self-delete-via-comspec-environment-variable.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_cam = /\/c\s*del\s*/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			capa_get_COMSPEC_environment_variable

		and 	capa_create_process

		and 	$re_cam  
	) 
}

private rule capa_check_for_windows_sandbox_via_process_name : CAPA T1497_001 B0009  { 
  meta: 
 	description = "check for windows sandbox via process name (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LloydLabs/wsb-detect"
	hash = "773290480d5445f11d3dc1b800728966"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-process-name.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_cap = "CExecSvc.exe" ascii wide
 
  condition:
    capa_pe_file and
 (
			capa_enumerate_processes

		and 	$str_cap  
	) 
}

private rule capa_get_CPU_information : CAPA T1082  { 
  meta: 
 	description = "get CPU information (converted from capa rule)"
	namespace = "host-interaction/hardware/cpu"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/cpu/get-cpu-information.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_cbe = /Hardware\\Description\\System\\CentralProcessor/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			capa_query_or_enumerate_registry_value

		and 	$re_cbe  
	) 
}

private rule capa_disable_code_signing : CAPA T1553_006  { 
  meta: 
 	description = "disable code signing (converted from capa rule)"
	namespace = "host-interaction/bootloader"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Subvert Trust Controls::Code Signing Policy Modification [T1553.006]"
	hash = "0596C4EA5AA8DEF47F22C85D75AACA95"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/bootloader/disable-code-signing.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_cbi = /\bbcdedit(\.exe)? -set TESTSIGNING ON/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			capa_create_process

		and 	$re_cbi  
	) 
}

private rule capa_find_taskbar : CAPA B0043  { 
  meta: 
 	description = "find taskbar (converted from capa rule)"
	namespace = "host-interaction/gui/taskbar/find"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Discovery::Taskbar Discovery [B0043]"
	hash = "B7841B9D5DC1F511A93CC7576672EC0C"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/taskbar/find/find-taskbar.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_cbj = "Shell_TrayWnd" ascii wide
 
  condition:
    capa_pe_file and
 (
			$str_cbj 
		and 	capa_find_graphical_window
 
	) 
}

private rule capa_check_mutex : CAPA C0043  { 
  meta: 
 	description = "check mutex (converted from capa rule)"
	namespace = "host-interaction/mutex"
	author = "moritz.raabem@fireeye.com"
	scope = "basic block"
	mbc = "Process::Check Mutex [C0043]"
	hash = "Practical Malware Analysis Lab 01-01.dll_:0x10001010"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/mutex/check-mutex.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			pe.imports(/kernel32/i, /OpenMutex/) 
		or 	capa_create_mutex
 
	)  
	) 
}

private rule capa_linked_against_Go_process_enumeration_library : CAPA T1057 T1518  { 
  meta: 
 	description = "linked against Go process enumeration library (converted from capa rule)"
	namespace = "host-interaction/process/list"
	author = "joakim@intezer.com"
	description = "Enumerating processes using a Go library"
	scope = "file"
	attack = "Discovery::Process Discovery [T1057]"
	attack = "Discovery::Software Discovery [T1518]"
	references = "https://pkg.go.dev/github.com/mitchellh/go-ps"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-process-enumeration-library.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_cdu = "github.com/mitchellh/go-ps.FindProcess" ascii wide
	$str_cdv = "github.com/mitchellh/go-ps.Processes" ascii wide
 
  condition:
    capa_pe_file and
 (
			capa_compiled_with_Go

		and  (
		 (
			$str_cdu 
		or 	$str_cdv  
	)  
	)  
	) 
}

private rule capa_linked_against_Go_WMI_library : CAPA T1213  { 
  meta: 
 	description = "linked against Go WMI library (converted from capa rule)"
	namespace = "collection/database/wmi"
	author = "joakim@intezer.com"
	description = "StackExchange's WMI library is used to interact with WMI."
	scope = "file"
	attack = "Collection::Data from Information Repositories [T1213]"
	references = "https://github.com/StackExchange/wmi"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-wmi-library.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_ceh = "github.com/StackExchange/wmi.CreateQuery" ascii wide
	$str_cei = "github.com/StackExchange/wmi.Query" ascii wide
 
  condition:
    capa_pe_file and
 (
			capa_compiled_with_Go

		and  (
		 (
			$str_ceh 
		or 	$str_cei  
	)  
	)  
	) 
}

private rule capa_check_for_windows_sandbox_via_mutex : CAPA T1497_001 B0009  { 
  meta: 
 	description = "check for windows sandbox via mutex (converted from capa rule)"
	namespace = "anti-analysis/anti-vm/vm-detection"
	author = "@_re_fox"
	scope = "function"
	attack = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
	mbc = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
	references = "https://github.com/LloydLabs/wsb-detect"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/check-for-windows-sandbox-via-mutex.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_cen = "WindowsSandboxMutex" ascii wide
 
  condition:
    capa_pe_file and
 (
			capa_check_mutex

		and 	$str_cen  
	) 
}

private rule capa_linked_against_Go_registry_library : CAPA  { 
  meta: 
 	description = "linked against Go registry library (converted from capa rule)"
	namespace = "host-interaction/registry"
	author = "joakim@intezer.com"
	description = "Uses a Go library for interacting with the Windows registry."
	scope = "file"
	references = "https://github.com/golang/sys"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-registry-library.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_ceo = "golang.org/x/sys/windows/registry.Key.Close" ascii wide
	$str_cep = "github.com/golang/sys/windows/registry.Key.Close" ascii wide
 
  condition:
    capa_pe_file and
 (
			capa_compiled_with_Go

		and  (
			$str_ceo 
		or 	$str_cep  
	)  
	) 
}

private rule capa_capture_screenshot_in_Go : CAPA T1113 E1113_m01  { 
  meta: 
 	description = "capture screenshot in Go (converted from capa rule)"
	namespace = "collection/screenshot"
	author = "joakim@intezer.com"
	description = "Detects screenshot capability via WinAPI for Go files."
	scope = "file"
	attack = "Collection::Screen Capture [T1113]"
	mbc = "Collection::Screen Capture::WinAPI [E1113.m01]"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/capture-screenshot-in-go.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_cev = "syscall.NewLazyDLL" ascii wide // Dynamic loading of DLLs
	$re_cew = /user32.dll/ ascii wide 
	$re_cex = /GetWindowDC/ ascii wide 
	$re_cey = /GetDC/ ascii wide 
	$re_cez = /gdi32.dll/ ascii wide 
	$re_cfa = /BitBlt/ ascii wide 
	$re_cfb = /GetDIBits/ ascii wide 
	$re_cfc = /CreateCompatibleDC/ ascii wide 
 
  condition:
    capa_pe_file and
 (
			capa_compiled_with_Go

		and  (
		 (
			$str_cev 
		and  (
		 (
			$re_cew 
		and  (
			$re_cex 
		or 	$re_cey  
	)  
	) 
		or  (
			$re_cez 
		and  (
			$re_cfa 
		or 	$re_cfb  
	)  
	)  
	) 
		and 	$re_cfc  
	)  
	)  
	) 
}

private rule capa_linked_against_Go_static_asset_library : CAPA  { 
  meta: 
 	description = "linked against Go static asset library (converted from capa rule)"
	namespace = "executable/resource"
	author = "joakim@intezer.com"
	description = "Detects if the Go file includes an static assets."
	scope = "file"
	references = "https://github.com/rakyll/statik"
	references = "https://github.com/gobuffalo/packr"
	references = "https://github.com/GeertJohan/go.rice"
	references = "https://github.com/kevinburke/go-bindata"
	references = "https://github.com/lu4p/binclude"
	references = "https://github.com/omeid/go-resources"
	references = "https://github.com/pyros2097/go-embed"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-static-asset-library.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_cfe = "github.com/rakyll/statik/fs.IsDefaultNamespace" ascii wide
	$str_cff = "github.com/rakyll/statik/fs.RegisterWithNamespace" ascii wide
	$str_cfg = "github.com/rakyll/statik/fs.NewWithNamespace" ascii wide
	$str_cfh = "github.com/rakyll/statik/fs.Register" ascii wide
	$str_cfi = "github.com/gobuffalo/packr.NewBox" ascii wide
	$str_cfj = "github.com/markbates/pkger.Open" ascii wide
	$str_cfk = "github.com/markbates/pkger.Include" ascii wide
	$str_cfl = "github.com/markbates/pkger.Parse" ascii wide
	$str_cfm = "github.com/GeertJohan/go.rice.FindBox" ascii wide
	$str_cfn = "github.com/GeertJohan/go.rice.MustFindBox" ascii wide
	$re_cfo = /\/bindata\.go/ ascii wide  // go-bindata
	$re_cfp = /\.Asset/ ascii wide 
	$str_cfq = "github.com/lu4p/binclude.Include" ascii wide
	$str_cfr = "github.com/omeid/go-resources" ascii wide
	$str_cfs = "github.com/pyros2097/go-embed" ascii wide
 
  condition:
    capa_pe_file and
 (
			capa_compiled_with_Go

		and  (
		 (
			$str_cfe 
		or 	$str_cff 
		or 	$str_cfg 
		or 	$str_cfh  
	) 
		or  (
			$str_cfi  
	) 
		or  (
			$str_cfj 
		or 	$str_cfk 
		or 	$str_cfl  
	) 
		or  (
			$str_cfm 
		or 	$str_cfn  
	) 
		or  (
			$re_cfo 
		and 	$re_cfp  
	) 
		or  (
			$str_cfq  
	) 
		or  (
			$str_cfr  
	) 
		or  (
			$str_cfs  
	)  
	)  
	) 
}

private rule capa_receive_data : CAPA B0030_002  { 
  meta: 
 	description = "receive data (converted from capa rule)"
	namespace = "communication"
	author = "william.ballenthin@fireeye.com"
	description = "all known techniques for receiving data from a potential C2 server"
	scope = "function"
	mbc = "Command and Control::C2 Communication::Receive Data [B0030.002]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/receive-data.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			capa_receive_data_on_socket

		or 	capa_read_data_from_Internet

		or 	capa_download_URL_to_file
 
	) 
}

private rule capa_send_HTTP_request : CAPA C0002_003  { 
  meta: 
 	description = "send HTTP request (converted from capa rule)"
	namespace = "communication/http/client"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Communication::HTTP Communication::Send Request [C0002.003]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	hash = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/send-http-request.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_cfy = /HTTP/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
		 (
			pe.imports(/wininet/i, /HttpOpenRequest/) 
		or 	pe.imports(/wininet/i, /InternetConnect/)  
	) 
		and  (
			pe.imports(/wininet/i, /HttpSendRequest/) 
		or 	pe.imports(/wininet/i, /HttpSendRequestEx/)  
	)  
	) 
		or  (
			pe.imports(/winhttp/i, /WinHttpSendRequest/) 
		and 	pe.imports(/winhttp/i, /WinHttpWriteData/)  
	) 
		or  (
			capa_send_data_on_socket

		and 	$re_cfy  
	)  
	) 
}

private rule capa_write_pipe : CAPA C0003_004  { 
  meta: 
 	description = "write pipe (converted from capa rule)"
	namespace = "communication/named-pipe/write"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	mbc = "Communication::Interprocess Communication::Write Pipe [C0003.004]"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/named-pipe/write/write-pipe.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
		 (
			capa_create_pipe

		or 	capa_connect_pipe
 
	) 
		and 	pe.imports(/kernel32/i, /WriteFile/)  
	) 
		or 	pe.imports(/kernel32/i, /TransactNamedPipe/) 
		or 	pe.imports(/kernel32/i, /CallNamedPipe/)  
	) 
}

private rule capa_download_and_write_a_file : CAPA T1105 B0030_003  { 
  meta: 
 	description = "download and write a file (converted from capa rule)"
	namespace = "c2/file-transfer"
	maec_malware_category = "downloader"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Command and Control::Ingress Tool Transfer [T1105]"
	mbc = "Command and Control::C2 Communication::Server to Client File Transfer [B0030.003]"
	hash = "5D7C34B6854D48D3DA4F96B71550A221"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/c2/file-transfer/download-and-write-a-file.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			capa_receive_data

		and 	capa_write_file
 
	) 
}

private rule capa_create_container : CAPA T1610  { 
  meta: 
 	description = "create container (converted from capa rule)"
	namespace = "host-interaction/container/docker"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Execution::Deploy Container [T1610]"
	references = "https://docs.docker.com/engine/api/v1.24/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/create-container.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_cjh = /\bdocker(\.exe)? create/ ascii wide 
	$re_cji = /\bdocker(\.exe)? start/ ascii wide 
	$re_cjj = /\/v1\.[0-9]{1,2}\/containers\/create/ ascii wide  // docker API endpoint, e.g., /v1.24/containers/create
	$re_cjk = /\/v1\.[0-9]{1,2}\/containers\/[0-9a-fA-F]+\/start/ ascii wide  // docker API endpoint, e.g., /v1.24/containers/e90e34656806/start
 
  condition:
    capa_pe_file and
 (
			$re_cjh 
		or 	$re_cji 
		or  (
			capa_send_HTTP_request

		and 	$re_cjj  
	) 
		or  (
			capa_send_HTTP_request

		and 	$re_cjk  
	)  
	) 
}

private rule capa_list_containers : CAPA T1609  { 
  meta: 
 	description = "list containers (converted from capa rule)"
	namespace = "host-interaction/container/docker"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Discovery::Container and Resource Discovery [T1609]"
	references = "https://docs.docker.com/engine/api/v1.24/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/list-containers.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_cjp = /\bdocker(\.exe)? ps/ ascii wide 
	$re_cjq = /\/v1\.[0-9]{1,2}\/containers\/json/ ascii wide  // docker API endpoint, e.g., /v1.24/containers/json?all=1&before=8dfafdbc3a40&size=1
 
  condition:
    capa_pe_file and
 (
			$re_cjp 
		or  (
			capa_send_HTTP_request

		and 	$re_cjq  
	)  
	) 
}

private rule capa_receive_and_write_data_from_server_to_client : CAPA  { 
  meta: 
 	description = "receive and write data from server to client (converted from capa rule)"
	namespace = "c2/file-transfer"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/receive-and-write-data-from-server-to-client.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			capa_receive_data

		and 	capa_write_file
 
	) 
}

private rule capa_build_Docker_image : CAPA T1612  { 
  meta: 
 	description = "build Docker image (converted from capa rule)"
	namespace = "host-interaction/container/docker"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Defense Evasion::Build Image on Host [T1612]"
	references = "https://docs.docker.com/engine/api/v1.24/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/build-docker-image.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_cke = /\bdocker(\.exe)? build/ ascii wide 
	$re_ckf = /\/v1\.[0-9]{1,2}\/build/ ascii wide  // docker API endpoint, e.g., /v1.24/build
 
  condition:
    capa_pe_file and
 (
			$re_cke 
		or  (
			capa_send_HTTP_request

		and 	$re_ckf  
	)  
	) 
}

private rule capa_run_in_container : CAPA T1609  { 
  meta: 
 	description = "run in container (converted from capa rule)"
	namespace = "host-interaction/container/docker"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	attack = "Execution::Container Administration Command [T1609]"
	references = "https://docs.docker.com/engine/api/v1.24/"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/run-in-container.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_ckg = /\bdocker(\.exe)? exec/ ascii wide 
	$re_ckh = /\bkubectl(\.exe)? exec/ ascii wide 
	$re_cki = /\bkubectl(\.exe)? run/ ascii wide 
	$re_ckj = /\/v1\.[0-9]{1,2}\/containers\/[0-9a-fA-F]+\/exec/ ascii wide  // docker API endpoint, e.g., /v1.24/containers/e90e34656806/exec
	$re_ckk = /\/v1\.[0-9]{1,2}\/exec\/[0-9a-fA-F]+\/start/ ascii wide  // docker API endpoint, e.g., /v1.24/exec/e90e34656806/start
 
  condition:
    capa_pe_file and
 (
			$re_ckg 
		or 	$re_ckh 
		or 	$re_cki 
		or  (
			capa_send_HTTP_request

		and 	$re_ckj  
	) 
		or  (
			capa_send_HTTP_request

		and 	$re_ckk  
	)  
	) 
}

private rule capa_send_HTTP_request_with_Host_header : CAPA  { 
  meta: 
 	description = "send HTTP request with Host header (converted from capa rule)"
	namespace = "communication/http"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/send-http-request-with-host-header.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_ckl = /Host:/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			capa_send_HTTP_request

		and 	$re_ckl  
	) 
}

private rule capa_make_an_HTTP_request_with_a_Cookie : CAPA  { 
  meta: 
 	description = "make an HTTP request with a Cookie (converted from capa rule)"
	namespace = "communication/http/client"
	author = "anamaria.martinezgom@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/make-an-http-request-with-a-cookie.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_cks = /Cookie:/ nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
			capa_send_HTTP_request

		and 	$re_cks  
	) 
}

private rule capa_send_data : CAPA B0030_001  { 
  meta: 
 	description = "send data (converted from capa rule)"
	namespace = "communication"
	author = "william.ballenthin@fireeye.com"
	description = "all known techniques for sending data to a potential C2 server"
	scope = "function"
	mbc = "Command and Control::C2 Communication::Send Data [B0030.001]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/send-data.yml"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			capa_send_HTTP_request

		or 	capa_send_data_on_socket

		or 	capa_send_file_via_HTTP
 
	) 
}

private rule capa_read_and_send_data_from_client_to_server : CAPA  { 
  meta: 
 	description = "read and send data from client to server (converted from capa rule)"
	namespace = "c2/file-transfer"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/read-and-send-data-from-client-to-server.yml"
	capa_nursery = "True"
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			capa_read_file

		and 	capa_send_data
 
	) 
}

private rule capa_create_reverse_shell : CAPA T1059_003 B0022_001  { 
  meta: 
 	description = "create reverse shell (converted from capa rule)"
	namespace = "c2/shell"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Execution::Command and Scripting Interpreter::Windows Command Shell [T1059.003]"
	mbc = "Impact::Remote Access::Reverse Shell [B0022.001]"
	hash = "C91887D861D9BD4A5872249B641BC9F9"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/c2/shell/create-reverse-shell.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
		 (
			capa_create_pipe

		and 	pe.imports(/kernel32/i, /PeekNamedPipe/) 
		and 	pe.imports(/kernel32/i, /CreateProcess/) 
		and 	pe.imports(/kernel32/i, /ReadFile/) 
		and 	pe.imports(/kernel32/i, /WriteFile/)  
	) 
		or  (
			capa_create_process

		and 	capa_read_pipe

		and 	capa_write_pipe
 
	)  
	) 
}

private rule capa_delete_file : CAPA C0047  { 
  meta: 
 	description = "delete file (converted from capa rule)"
	namespace = "host-interaction/file-system/delete"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "File System::Delete File [C0047]"
	hash = "946A99F36A46D335DEC080D9A4371940"
	hash = "31600AD0D1A7EA615690DF111AE36C73"
	hash = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/delete/delete-file.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_cpz = /\bDeleteFileTransacted(A|W)?\b/ ascii wide
	$api_cqa = /\bNtDeleteFile(A|W)?\b/ ascii wide
	$api_cqb = /\bZwDeleteFile(A|W)?\b/ ascii wide
	$api_cqc = /\bremove(A|W)?\b/ ascii wide
	$api_cqd = /\b_wremove(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /DeleteFile/) 
		or 	$api_cpz 
		or 	$api_cqa 
		or 	$api_cqb 
		or 	$api_cqc 
		or 	$api_cqd  
	) 
}

private rule capa_check_if_file_exists : CAPA T1083  { 
  meta: 
 	description = "check if file exists (converted from capa rule)"
	namespace = "host-interaction/file-system/exists"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::File and Directory Discovery [T1083]"
	hash = "31600AD0D1A7EA615690DF111AE36C73"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/exists/check-if-file-exists.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/shlwapi/i, /PathFileExists/)  
	) 
}

private rule capa_copy_file : CAPA C0045  { 
  meta: 
 	description = "copy file (converted from capa rule)"
	namespace = "host-interaction/file-system/copy"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "File System::Copy File [C0045]"
	hash = "Practical Malware Analysis Lab 01-01.exe_:0x401440"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/copy/copy-file.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_cqf = /\bCopyFile2(A|W)?\b/ ascii wide
	$api_cqg = /\bCopyFileTransacted(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /CopyFile/) 
		or 	pe.imports(/kernel32/i, /CopyFileEx/) 
		or 	$api_cqf 
		or 	$api_cqg  
	) 
}

private rule capa_run_as_service : CAPA E1480_m07  { 
  meta: 
 	description = "run as service (converted from capa rule)"
	namespace = "host-interaction/service"
	author = "moritz.raabe@fireeye.com"
	author = "michael.hunhoff@fireeye.com"
	scope = "file"
	mbc = "Anti-Behavioral Analysis::Execution Guardrails::Runs as Service [E1480.m07]"
	hash = "Practical Malware Analysis Lab 03-02.dll_"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/service/run-as-service.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.exports("ServiceMain")  
	) 
}

private rule capa_get_disk_size : CAPA T1082  { 
  meta: 
 	description = "get disk size (converted from capa rule)"
	namespace = "host-interaction/hardware/storage"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Discovery::System Information Discovery [T1082]"
	references = "https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Generic.cpp#L347"
	hash = "al-khaser_x86.exe_:0x4343D0"
	hash = "al-khaser_x86.exe_:0x434010"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/storage/get-disk-size.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_cqm = /SELECT\s+\*\s+FROM\s+Win32_LogicalDisk/ nocase ascii wide 
	$re_cqn = /SELECT\s+\*\s+FROM\s+Win32_DiskDrive\s+WHERE\s+\(SerialNumber\s+IS\s+NOT\s+NULL\)\s+AND\s+\(MediaType\s+LIKE\s+\'Fixed\s+hard\s+disk\%\'\)/ nocase ascii wide 
	$str_cqo = "Size" ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /GetDiskFreeSpace/) 
		or 	pe.imports(/kernel32/i, /GetDiskFreeSpaceEx/) 
		or  (
		 (
			$re_cqm 
		or 	$re_cqn  
	) 
		and 	$str_cqo  
	)  
	) 
}

private rule capa_interact_with_driver_via_control_codes : CAPA T1569_002  { 
  meta: 
 	description = "interact with driver via control codes (converted from capa rule)"
	namespace = "host-interaction/driver"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Execution::System Services::Service Execution [T1569.002]"
	hash = "Practical Malware Analysis Lab 10-03.exe_:0x401000"
	hash = "9412A66BC81F51A1FA916AC47C77E02AC1A7C9DFF543233ED70AA265EF6A1E76"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/driver/interact-with-driver-via-control-codes.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_cqp = /\bDeviceIoControl(A|W)?\b/ ascii wide
	$api_cqq = /\bNtUnloadDriver(A|W)?\b/ ascii wide
	$api_cqr = /\bZwUnloadDriver(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_cqp 
		or 	$api_cqq 
		or 	$api_cqr  
	) 
}

private rule capa_get_local_IPv4_addresses : CAPA T1016  { 
  meta: 
 	description = "get local IPv4 addresses (converted from capa rule)"
	namespace = "host-interaction/network/address"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Network Configuration Discovery [T1016]"
	hash = "Practical Malware Analysis Lab 05-01.dll_:0x100037e6"
	hash = "4C0553285D724DCAF5909924B4E3E90A"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/address/get-local-ipv4-addresses.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_cqu = /\bGetAdaptersAddresses(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$api_cqu  
	)  
	) 
}

private rule capa_get_session_user_name : CAPA T1033 T1087  { 
  meta: 
 	description = "get session user name (converted from capa rule)"
	namespace = "host-interaction/session"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Discovery::System Owner/User Discovery [T1033]"
	attack = "Discovery::Account Discovery [T1087]"
	hash = "Practical Malware Analysis Lab 14-01.exe_:0x401285"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/session/get-session-user-name.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  condition:
    capa_pe_file and
 (
			pe.imports(/advapi32/i, /GetUserName/) 
		or 	pe.imports(/secur32/i, /GetUserNameEx/)  
	) 
}

private rule capa_encrypt_data_using_Sosemanuk : CAPA T1027 E1027_m05 C0027_008  { 
  meta: 
 	description = "encrypt data using Sosemanuk (converted from capa rule)"
	namespace = "data-manipulation/encryption/sosemanuk"
	author = "@recvfrom"
	description = "Looks for cryptographic constants associated with the Sosemanuk stream cipher"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::Sosemanuk [C0027.008]"
	references = "https://labs.sentinelone.com/enter-the-maze-demystifying-an-affiliate-involved-in-maze-snow/"
	hash = "ea7bb99e03606702c1cbe543bb32b27e"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/sosemanuk/encrypt-data-using-sosemanuk.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$cqy = { 00 00 00 00 E1 9F CF 13 6B 97 37 26 8A 08 F8 35 D6 87 6E 4C 37 18 A1 5F BD 10 59 6A 5C 8F 96 79 05 A7 DC 98 E4 38 13 8B 6E 30 EB BE 8F AF 24 AD D3 20 B2 D4 32 BF 7D C7 B8 B7 85 F2 59 28 4A E1 0A E7 11 99 EB 78 DE 8A 61 70 26 BF 80 EF E9 AC DC 60 7F D5 3D FF B0 C6 B7 F7 48 F3 56 68 87 E0 0F 40 CD 01 EE DF 02 12 64 D7 FA 27 85 48 35 34 D9 C7 A3 4D 38 58 6C 5E B2 50 94 6B 53 CF 5B 78 } // mul_a
	$cqz = { 00 00 00 00 13 CF 9F E1 26 37 97 6B 35 F8 08 8A 4C 6E 87 D6 5F A1 18 37 6A 59 10 BD 79 96 8F 5C 98 DC A7 05 8B 13 38 E4 BE EB 30 6E AD 24 AF 8F D4 B2 20 D3 C7 7D BF 32 F2 85 B7 B8 E1 4A 28 59 99 11 E7 0A 8A DE 78 EB BF 26 70 61 AC E9 EF 80 D5 7F 60 DC C6 B0 FF 3D F3 48 F7 B7 E0 87 68 56 01 CD 40 0F 12 02 DF EE 27 FA D7 64 34 35 48 85 4D A3 C7 D9 5E 6C 58 38 6B 94 50 B2 78 5B CF 53 } // mul_a_4byte_array_le
	$cra = { 00 00 00 00 18 0F 40 CD 30 1E 80 33 28 11 C0 FE 60 3C A9 66 78 33 E9 AB 50 22 29 55 48 2D 69 98 C0 78 FB CC D8 77 BB 01 F0 66 7B FF E8 69 3B 32 A0 44 52 AA B8 4B 12 67 90 5A D2 99 88 55 92 54 29 F0 5F 31 31 FF 1F FC 19 EE DF 02 01 E1 9F CF 49 CC F6 57 51 C3 B6 9A 79 D2 76 64 61 DD 36 A9 E9 88 A4 FD F1 87 E4 30 D9 96 24 CE C1 99 64 03 89 B4 0D 9B 91 BB 4D 56 B9 AA 8D A8 A1 A5 CD 65 } // mul_ia
	$crb = { 00 00 00 00 CD 40 0F 18 33 80 1E 30 FE C0 11 28 66 A9 3C 60 AB E9 33 78 55 29 22 50 98 69 2D 48 CC FB 78 C0 01 BB 77 D8 FF 7B 66 F0 32 3B 69 E8 AA 52 44 A0 67 12 4B B8 99 D2 5A 90 54 92 55 88 31 5F F0 29 FC 1F FF 31 02 DF EE 19 CF 9F E1 01 57 F6 CC 49 9A B6 C3 51 64 76 D2 79 A9 36 DD 61 FD A4 88 E9 30 E4 87 F1 CE 24 96 D9 03 64 99 C1 9B 0D B4 89 56 4D BB 91 A8 8D AA B9 65 CD A5 A1 } // mul_ia_4byte_array_le
 
  condition:
    capa_pe_file and
 (
			$cqy 
		or 	$cqz 
		or 	$cra 
		or 	$crb  
	) 
}

private rule capa_encrypt_data_using_DES : CAPA T1027 E1027_m05 C0027_004  { 
  meta: 
 	description = "encrypt data using DES (converted from capa rule)"
	namespace = "data-manipulation/encryption/des"
	author = "@_re_fox"
	scope = "basic block"
	attack = "Defense Evasion::Obfuscated Files or Information [T1027]"
	mbc = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
	mbc = "Cryptography::Encrypt Data::3DES [C0027.004]"
	hash = "91a12a4cf437589ba70b1687f5acad19"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/des/encrypt-data-using-des.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$crc = { 0E 04 0D 01 02 0F 0B 08 03 0A 06 0C 05 09 00 07 00 0F 07 04 0E 02 0D 01 0A 06 0C 0B 09 05 03 08 04 01 0E 08 0D 06 02 0B 0F 0C 09 07 03 0A 05 00 0F 0C 08 02 04 09 01 07 05 0B 03 0E 0A 00 06 0D } // SBOX S1
	$crd = { 0F 01 08 0E 06 0B 03 04 09 07 02 0D 0C 00 05 0A 03 0D 04 07 0F 02 08 0E 0C 00 01 0A 06 09 0B 05 00 0E 07 0B 0A 04 0D 01 05 08 0C 06 09 03 02 0F 0D 08 0A 01 03 0F 04 02 0B 06 07 0C 00 05 0E 09 } // SBOX S2
	$cre = { 0A 00 09 0E 06 03 0F 05 01 0D 0C 07 0B 04 02 08 0D 07 00 09 03 04 06 0A 02 08 05 0E 0C 0B 0F 01 0D 06 04 09 08 0F 03 00 0B 01 02 0C 05 0A 0E 07 01 0A 0D 00 06 09 08 07 04 0F 0E 03 0B 05 02 0C } // SBOX S3
	$crf = { 07 0D 0E 03 00 06 09 0A 01 02 08 05 0B 0C 04 0F 0D 08 0B 05 06 0F 00 03 04 07 02 0C 01 0A 0E 09 0A 06 09 00 0C 0B 07 0D 0F 01 03 0E 05 02 08 04 03 0F 00 06 0A 01 0D 08 09 04 05 0B 0C 07 02 0E } // SBOX S4
	$crg = { 02 0C 04 01 07 0A 0B 06 08 05 03 0F 0D 00 0E 09 0E 0B 02 0C 04 07 0D 01 05 00 0F 0A 03 09 08 06 04 02 01 0B 0A 0D 07 08 0F 09 0C 05 06 03 00 0E 0B 08 0C 07 01 0E 02 0D 06 0F 00 09 0A 04 05 03 } // SBOX S5
	$crh = { 0C 01 0A 0F 09 02 06 08 00 0D 03 04 0E 07 05 0B 0A 0F 04 02 07 0C 09 05 06 01 0D 0E 00 0B 03 08 09 0E 0F 05 02 08 0C 03 07 00 04 0A 01 0D 0B 06 04 03 02 0C 09 05 0F 0A 0B 0E 01 07 06 00 08 0D } // SBOX S6
	$cri = { 04 0B 02 0E 0F 00 08 0D 03 0C 09 07 05 0A 06 01 0D 00 0B 07 04 09 01 0A 0E 03 05 0C 02 0F 08 06 01 04 0B 0D 0C 03 07 0E 0A 0F 06 08 00 05 09 02 06 0B 0D 08 01 04 0A 07 09 05 00 0F 0E 02 03 0C } // SBOX S7
	$crj = { 0D 02 08 04 06 0F 0B 01 0A 09 03 0E 05 00 0C 07 01 0F 0D 08 0A 03 07 04 0C 05 06 0B 00 0E 09 02 07 0B 04 01 09 0C 0E 02 00 06 0A 0D 0F 03 05 08 02 01 0E 07 04 0A 08 0D 0F 0C 09 00 03 05 06 0B } // SBOX S8
	$crk = { 39 31 29 21 19 11 09 01 3A 32 2A 22 1A 12 0A 02 3B 33 2B 23 1B 13 0B 03 3C 34 2C 24 3F 37 2F 27 1F 17 0F 07 3E 36 2E 26 1E 16 0E 06 3D 35 2D 25 1D 15 0D 05 1C 14 0C 04 } // PC1
	$crl = { 0E 11 0B 18 01 05 03 1C 0F 06 15 0A 17 13 0C 04 1A 08 10 07 1B 14 0D 02 29 34 1F 25 2F 37 1E 28 33 2D 21 30 2C 31 27 38 22 35 2E 2A 32 24 1D 20 } // PC2
	$crm = { 3A 32 2A 22 1A 12 0A 02 3C 34 2C 24 1C 14 0C 04 3E 36 2E 26 1E 16 0E 06 40 38 30 28 20 18 10 08 39 31 29 21 19 11 09 01 3B 33 2B 23 1B 13 0B 03 3D 35 2D 25 1D 15 0D 05 3F 37 2F 27 1F 17 0F 07 } // Initial Permutation
	$crn = { 28 08 30 10 38 18 40 20 27 07 2F 0F 37 17 3F 1F 26 06 2E 0E 36 16 3E 1E 25 05 2D 0D 35 15 3D 1D 24 04 2C 0C 34 14 3C 1C 23 03 2B 0B 33 13 3B 1B 22 02 2A 0A 32 12 3A 1A 21 01 29 09 31 11 39 19 } // Final Permutation
	$cro = { 20 01 02 03 04 05 04 05 06 07 08 09 08 09 0A 0B 0C 0D 0C 0D 0E 0F 10 11 10 11 12 13 14 15 14 15 16 17 18 19 18 19 1A 1B 1C 1D 1C 1D 1E 1F 20 01 } // DES Expansion
	$crp = { 10 07 14 15 1D 0C 1C 11 01 0F 17 1A 05 12 1F 0A 02 08 18 0E 20 1B 03 09 13 0D 1E 06 16 0B 04 19 } // PBOX
 
  condition:
    capa_pe_file and
 (
			$crc 
		or 	$crd 
		or 	$cre 
		or 	$crf 
		or 	$crg 
		or 	$crh 
		or 	$cri 
		or 	$crj 
		or 	$crk 
		or 	$crl 
		or 	$crm 
		or 	$crn 
		or 	$cro 
		or 	$crp  
	) 
}

private rule capa_hash_data_with_CRC32 : CAPA C0032_001  { 
  meta: 
 	description = "hash data with CRC32 (converted from capa rule)"
	namespace = "data-manipulation/checksum/crc32"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Data::Checksum::CRC32 [C0032.001]"
	hash = "2D3EDC218A90F03089CC01715A9F047F"
	hash = "7D28CB106CB54876B2A5C111724A07CD"
	hash = "7EFF498DE13CC734262F87E6B3EF38AB"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/checksum/crc32/hash-data-with-crc32.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_cru = /\bRtlComputeCrc32(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			$api_cru  
	) 
}

private rule capa_hash_data_using_SHA1 : CAPA C0029_002  { 
  meta: 
 	description = "hash data using SHA1 (converted from capa rule)"
	namespace = "data-manipulation/hashing/sha1"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	mbc = "Cryptography::Cryptographic Hash::SHA1 [C0029.002]"
	hash = "D063B1804E8D2BB26BD2E097141C1BBC"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/sha1/hash-data-using-sha1.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_crv = { 01 23 45 67 }
	$num_crw = { 89 AB CD EF }
	$num_crx = { FE DC BA 98 }
	$num_cry = { 76 54 32 10 }
	$num_crz = { F0 E1 D2 C3 }
 
  condition:
    capa_pe_file and
 (
		 (
		$num_crv 
		and $num_crw 
		and $num_crx 
		and $num_cry 
		and $num_crz  
	)  
	) 
}

private rule capa_hash_data_using_tiger : CAPA C0029_005  { 
  meta: 
 	description = "hash data using tiger (converted from capa rule)"
	namespace = "data-manipulation/hashing/tiger"
	author = "@_re_fox"
	scope = "basic block"
	mbc = "Cryptography::Cryptographic Hash::Tiger [C0029.005]"
	hash = "0761142efbda6c4b1e801223de723578"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/tiger/hash-data-using-tiger.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$csb = { 5E 0C E9 F7 7C B1 AA 02 EC A8 43 E2 03 4B 42 AC D3 FC D5 0D E3 5B CD 72 3A 7F F9 F6 93 9B 01 6D 93 91 1F D2 FF 78 99 CD E2 29 80 70 C9 A1 73 75 C3 83 2A 92 6B 32 64 B1 70 58 91 04 EE 3E 88 46 E6 EC 03 71 05 E3 AC EA 5C 53 A3 08 B8 69 41 C5 7C C4 DE 8D 91 54 E7 4C 0C F4 0D DC DF F4 A2 0A FA BE 4D A7 18 6F B7 10 6A AB D1 5A 23 B6 CC C6 FF E2 2F 57 21 61 72 13 1E 92 9D 19 6F 8C 48 1A CA 07 00 DA F4 F9 C9 4B C7 41 52 E8 F6 E6 F5 26 B6 47 59 EA DB 79 90 85 92 8C 9E C9 C5 85 18 4F 4B 86 6F A9 1E 76 8E D7 7D C1 B5 } // sbox1
	$csc = { 38 21 A1 05 5A BE A6 E6 98 7C F8 B4 A5 22 A1 B5 90 69 0B 14 89 60 3C 56 D5 5D 1F 39 2E CB 46 4C 34 94 B7 C9 DB AD 32 D9 F5 AF 15 20 E4 70 EA 08 F1 8C 47 3E 67 A6 65 D7 99 8D 27 AB 7E 75 FB C4 92 06 6E 2D 86 C6 11 DF 16 3B 7F 0D F1 84 EB DD 04 EA 65 A6 04 F6 2E 6F B3 DF E0 F0 0F 0F 8E 4A 51 BA BC 3D F8 EE ED A5 1E 37 A4 0E 2A 0A 4F FC 29 84 B3 5C A8 1D 3E E8 E2 1C 1B BA 82 F8 8F DC 0D E8 53 83 5E 50 45 CD 17 07 DB D4 00 9A D1 18 01 81 F3 A5 ED CF A0 34 F2 CA 87 88 51 7E E7 0B 36 51 C4 B3 38 14 34 1E F9 CC 89 } // sbox2
	$csd = { 9B F3 DA F1 2F CC 9F F4 81 92 F2 6F C6 D5 7F 48 3F A8 DC FC 67 06 A3 E8 63 CE FC D2 E3 4B 9B 2C C2 BB FB 93 4B F7 3F DA 66 BA 70 FE D2 65 A1 2F D4 93 0E 97 79 E2 03 A1 71 5E E4 B0 77 EC CD BE 97 E4 85 39 72 1E B4 CF 17 50 F7 5E 02 AA 0A B7 E0 B8 40 38 F0 09 23 D4 79 85 89 35 D0 1A FC 8E C5 AB B2 E2 0B 92 C6 96 72 91 5A 37 63 41 AF 66 FB 27 71 CA DC AB 74 21 41 FF 72 4A A6 CE 3C B3 A5 66 30 08 33 49 4A F0 F5 9A 28 D7 CD 0A 97 8D 5E C2 C8 31 E0 E8 96 8F 47 5D 87 76 22 C0 FE F3 DD 90 61 05 10 F3 7B EC 91 14 0F } // sbox3
	$cse = { 55 3C 32 26 85 60 0E 5B F5 59 1B FA A9 C1 46 1A FA 8F 4C 7C A1 45 E2 A9 D7 55 29 DB 59 51 CA 65 C2 AF 35 CE 76 0A DB 05 45 3D 11 A9 7E C7 EA 81 0D 0A AC B6 8A F8 8E 52 FF E3 7B 59 53 A2 9E A0 56 CD 48 AC B3 DF 0D 43 6F E4 5C F4 7A A6 B3 C4 5E D0 E2 FB D8 CF CE 4E F0 35 99 B3 10 6F F5 3E C6 19 D6 9C 82 D6 22 0B 69 20 DF 74 0A 46 FD 17 40 ED 10 85 8E CC F8 6C A7 CA 6E 3A BF 24 C8 D6 49 70 81 1A 58 3D 24 61 A2 63 C1 BB B6 AC 8B 04 32 CC 44 7D C2 8A A3 D9 AB 10 F4 AA 5B FF DD 7F 4B 82 04 A8 5A 49 6D AD 94 9F 8C } // sbox4
 
  condition:
    capa_pe_file and
 (
			$csb 
		or 	$csc 
		or 	$csd 
		or 	$cse  
	) 
}

private rule capa_hash_data_using_murmur3 : CAPA C0030_001  { 
  meta: 
 	description = "hash data using murmur3 (converted from capa rule)"
	namespace = "data-manipulation/hashing/murmur"
	author = "william.ballenthin@fireeye.com"
	scope = "function"
	mbc = "Data::Non-Cryptographic Hash::MurmurHash [C0030.001]"
	references = "https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp"
	hash = "c66172b12971a329f8d5ff01665f204b"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/murmur/hash-data-using-murmur3.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_csh = { 6B CA EB 85 } // 32-bit finalization mix constant 1
	$num_csi = { 35 AE B2 C2 } // 32-bit finalization mix constant 2
	$num_csj = { CD 8C 55 ED D7 AF 51 FF } // 64-bit finalization mix constant 1
	$num_csk = { 53 EC 85 1A FE B9 CE C4 } // 64-bit finalization mix constant 2
	$num_csl = { 51 2D 9E CC } // c1 32-bit hash
	$num_csm = { 93 35 87 1B } // c2 32-bit hash
	$num_csn = { 1B 96 9B 23 } // 32-bit c1 for 128-bit hash
	$num_cso = { 89 97 0E AB } // 32-bit c2 for 128-bit hash
	$num_csp = { E5 4A B3 38 } // 32-bit c3 for 128-bit hash
	$num_csq = { 93 8B E3 A1 } // 32-bit c4 for 128-bit hash
	$num_csr = { D5 53 42 11 91 7B C3 87 } // 64-bit c1 for 128-bit hash
	$num_css = { 7F 93 45 27 43 AD F5 4C } // 64-bit c2 for 128-bit hash
 
  condition:
    capa_pe_file and
 (
		 (
		$num_csh 
		and $num_csi  
	) 
		or  (
		$num_csj 
		and $num_csk  
	) 
		or  (
		$num_csl 
		and $num_csm  
	) 
		or  (
		$num_csn 
		and $num_cso 
		and $num_csp 
		and $num_csq  
	) 
		or  (
		$num_csr 
		and $num_css  
	)  
	) 
}

private rule capa_persist_via_Windows_service : CAPA T1543_003 T1569_002  { 
  meta: 
 	description = "persist via Windows service (converted from capa rule)"
	namespace = "persistence/service"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	attack = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
	attack = "Execution::System Services::Service Execution [T1569.002]"
	hash = "Practical Malware Analysis Lab 03-02.dll_:0x10004706"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/service/persist-via-windows-service.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$re_csv = /\bsc(\.exe)?$/ nocase ascii wide 
	$re_csw = /create / nocase ascii wide 
	$re_csx = /\bsc(\.exe)? create/ nocase ascii wide 
	$re_csy = /New-Service / nocase ascii wide 
 
  condition:
    capa_pe_file and
 (
		 (
			capa_create_process

		and  (
		 (
			$re_csv 
		and 	$re_csw  
	) 
		or 	$re_csx 
		or 	$re_csy  
	)  
	)  
	) 
}

private rule capa_move_file : CAPA  { 
  meta: 
 	description = "move file (converted from capa rule)"
	namespace = "host-interaction/file-system/move"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/move-file.yml"
	capa_nursery = "True"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$api_cth = /\bMoveFileWithProgress(A|W)?\b/ ascii wide
	$api_cti = /\bMoveFileTransacted(A|W)?\b/ ascii wide
	$api_ctj = /\brename(A|W)?\b/ ascii wide
	$api_ctk = /\b_wrename(A|W)?\b/ ascii wide
 
  condition:
    capa_pe_file and
 (
			pe.imports(/kernel32/i, /MoveFile/) 
		or 	pe.imports(/kernel32/i, /MoveFileEx/) 
		or 	$api_cth 
		or 	$api_cti 
		or 	$api_ctj 
		or 	$api_ctk  
	) 
}

private rule capa_hash_data_with_MD5 : CAPA  { 
  meta: 
 	description = "hash data with MD5 (converted from capa rule)"
	namespace = "data-manipulation/hashing/md5"
	author = "moritz.raabe@fireeye.com"
	scope = "function"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/hash-data-with-md5.yml"
	capa_nursery = "True"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$num_ctr = { 01 23 45 67 }
	$num_cts = { 89 AB CD EF }
	$num_ctt = { FE DC BA 98 }
	$num_ctu = { 76 54 32 10 }
	$num_ctv = { F0 E1 D2 C3 }
 
  condition:
    capa_pe_file and
 (
		 (
		$num_ctr 
		and $num_cts 
		and $num_ctt 
		and $num_ctu 
		and not $num_ctv   
	)  
	) 
}

private rule capa_capture_screenshot : CAPA T1113 E1113_m01  { 
  meta: 
 	description = "capture screenshot (converted from capa rule)"
	namespace = "collection/screenshot"
	author = "moritz.raabe@fireeye.com"
	author = "@_re_fox"
	author = "michael.hunhoff@fireeye.com"
	scope = "function"
	attack = "Collection::Screen Capture [T1113]"
	mbc = "Collection::Screen Capture::WinAPI [E1113.m01]"
	hash = "BFB9B5391A13D0AFD787E87AB90F14F5"
	hash = "7204e3efc2434012e13ca939db0d0b02"
	hash = "50D5EE1CE2CA5E30C6B1019EE64EEEC2"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/screenshot/capture-screenshot.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_cud = "DISPLAY" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
		 (
			pe.imports(/user32/i, /GetWindowDC/) 
		or 	pe.imports(/user32/i, /GetDC/) 
		or  (
			pe.imports(/gdi32/i, /CreateDCA/) 
		and 	$str_cud  
	)  
	) 
		and  (
			pe.imports(/gdi32/i, /BitBlt/) 
		or 	pe.imports(/gdi32/i, /GetDIBits/)  
	) 
		and 	pe.imports(/gdi32/i, /CreateCompatibleDC/) 
		and 	pe.imports(/gdi32/i, /CreateCompatibleBitmap/)  
	)  
	) 
}

private rule capa_gather_leapftp_information : CAPA T1555  { 
  meta: 
 	description = "gather leapftp information (converted from capa rule)"
	namespace = "collection/file-managers"
	author = "@_re_fox"
	scope = "function"
	attack = "Credential Access::Credentials from Password Stores [T1555]"
	hash = "5a2f620f29ca2f44fc22df67b674198f"
	reference = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-leapftp-information.yml"
	comment = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
	date = "2021-05-17"
	minimum_yara = "3.8"
	license = "Apache-2.0 License"

  strings: 
 	$str_cue = "InstallPath" ascii wide
	$str_cuf = "DataDir" ascii wide
	$str_cug = "sites.dat" ascii wide
	$str_cuh = "sites.ini" ascii wide
 
  condition:
    capa_pe_file and
 (
		 (
			$str_cue 
		and 	$str_cuf 
		and 	$str_cug 
		and 	$str_cuh  
	)  
	) 
}


// converted rules              : 403
//   among those are incomplete : 20
// unconverted rules            : 149


