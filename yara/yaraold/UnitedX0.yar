/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "pe"


/* Anthem Deep Panda APT */

rule Anthem_DeepPanda_sl_txt_packed {
	meta:
		description = "Anthem Hack Deep Panda - ScanLine sl-txt-packed"
		author = "Florian Roth"
		date = "2015/02/08"
		hash = "ffb1d8ea3039d3d5eb7196d27f5450cac0ea4f34"
	strings:
		$s0 = "Command line port scanner" fullword wide
		$s1 = "sl.exe" fullword wide
		$s2 = "CPports.txt" fullword ascii
		$s3 = ",GET / HTTP/.}" fullword ascii
		$s4 = "Foundstone Inc." fullword wide
		$s9 = " 2002 Foundstone Inc." fullword wide
		$s15 = ", Inc. 2002" fullword ascii
		$s20 = "ICMP Time" fullword ascii
	condition:
		all of them
}

rule Anthem_DeepPanda_lot1 {
	meta:
		description = "Anthem Hack Deep Panda - lot1.tmp-pwdump"
		author = "Florian Roth"
		date = "2015/02/08"
		hash = "5d201a0fb0f4a96cefc5f73effb61acff9c818e1"
	strings:
		$s0 = "Unable to open target process: %d, pid %d" fullword ascii
		$s1 = "Couldn't delete target executable from remote machine: %d" fullword ascii
		$s2 = "Target: Failed to load SAM functions." fullword ascii
		$s5 = "Error writing the test file %s, skipping this share" fullword ascii
		$s6 = "Failed to create service (%s/%s), error %d" fullword ascii
		$s8 = "Service start failed: %d (%s/%s)" fullword ascii
		$s12 = "PwDump.exe" fullword ascii
		$s13 = "GetAvailableWriteableShare returned an error of %ld" fullword ascii
		$s14 = ":\\\\.\\pipe\\%s" fullword ascii
		$s15 = "Couldn't copy %s to destination %s. (Error %d)" fullword ascii
		$s16 = "dump logon session" fullword ascii
		$s17 = "Timed out waiting to get our pipe back" fullword ascii
		$s19 = "SetNamedPipeHandleState failed, error %d" fullword ascii
		$s20 = "%s\\%s.exe" fullword ascii
	condition:
		10 of them
}

rule Anthem_DeepPanda_htran_exe {
	meta:
		description = "Anthem Hack Deep Panda - htran-exe"
		author = "Florian Roth"
		date = "2015/02/08"
		hash = "38e21f0b87b3052b536408fdf59185f8b3d210b9"
	strings:
		$s0 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
		$s1 = "[-] Gethostbyname(%s) error:%s" fullword ascii
		$s2 = "e:\\VS 2008 Project\\htran\\Release\\htran.pdb" fullword ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s5 = "[-] ERROR: Must supply logfile name." fullword ascii
		$s6 = "[-] There is a error...Create a new connection." fullword ascii
		$s7 = "[+] Accept a Client on port %d from %s" fullword ascii
		$s8 = "======================== htran V%s =======================" fullword ascii
		$s9 = "[-] Socket Listen error." fullword ascii
		$s10 = "[-] ERROR: open logfile" fullword ascii
		$s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s12 = "[+] Make a Connection to %s:%d ......" fullword ascii
		$s14 = "Recv %5d bytes from %s:%d" fullword ascii
		$s15 = "[+] OK! I Closed The Two Socket." fullword ascii
		$s16 = "[+] Waiting another Client on port:%d...." fullword ascii
		$s17 = "[+] Accept a Client on port %d from %s ......" fullword ascii
		$s20 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
	condition:
		10 of them
}

rule Anthem_DeepPanda_Trojan_Kakfum {
	meta:
		description = "Anthem Hack Deep Panda - Trojan.Kakfum sqlsrv32.dll"
		author = "Florian Roth"
		date = "2015/02/08"
		hash1 = "ab58b6aa7dcc25d8f6e4b70a24e0ccede0d5f6129df02a9e61293c1d7d7640a2"
		hash2 = "c6c3bb72896f8f0b9a5351614fd94e889864cf924b40a318c79560bbbcfa372f"
	strings:
		$s0 = "%SystemRoot%\\System32\\svchost.exe -k sqlserver" fullword ascii
		$s1 = "%s\\sqlsrv32.dll" fullword ascii
		$s2 = "%s\\sqlsrv64.dll" fullword ascii
		$s3 = "%s\\%d.tmp" fullword ascii
		$s4 = "ServiceMaix" fullword ascii
		$s15 = "sqlserver" fullword ascii
	condition:
		all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule APT9002Code : APT9002 Family 
{
    meta:
        description = "9002 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        // start code block
        $ = { B9 7A 21 00 00 BE ?? ?? ?? ?? 8B F8 ?? ?? ?? F3 A5 }
        // decryption from other variant with multiple start threads
        $ = { 8A 14 3E 8A 1C 01 32 DA 88 1C 01 8B 54 3E 04 40 3B C2 72 EC }
  
    condition:
        any of them
}

rule APT9002Strings : APT9002 Family
{
    meta:
        description = "9002 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "POST http://%ls:%d/%x HTTP/1.1"
        $ = "%%TEMP%%\\%s_p.ax" wide ascii
        $ = "%TEMP%\\uid.ax" wide ascii
        $ = "%%TEMP%%\\%s.ax" wide ascii
        // also triggers on surtr $ = "mydll.dll\x00DoWork"
        $ = "sysinfo\x00sysbin01"
        $ = "\\FlashUpdate.exe"
        
    condition:
       any of them
}

rule APT9002 : Family
{
    meta:
        description = "9002"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        APT9002Code or APT9002Strings
}

rule FE_APT_9002 : RAT
{
    meta:
        Author      = "FireEye Labs"
        Date        = "2013/11/10"
        Description = "Strings inside"
        Reference   = "Useful link"

    strings:
        $mz = { 4d 5a }
        $a = "rat_UnInstall" wide ascii

    condition:
        ($mz at 0) and $a
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule crime_win_rat_AlienSpy
{
meta:
	description = "Alien Spy Remote Access Trojan"
	author = "General Dynamics Fidelis Cybersecurity Solutions - Threat Research Team"
	reference_1 = "www.fidelissecurity.com/sites/default/files/FTA_1015_Alienspy_FINAL.pdf"
	reference_2 = "www.fidelissecurity.com/sites/default/files/AlienSpy-Configs2_1_2.csv"
	date = "2015-04-04"
	filetype = "Java"
	hash_1 = "075fa0567d3415fbab3514b8aa64cfcb"
	hash_2 = "818afea3040a887f191ee9d0579ac6ed"
	hash_3 = "973de705f2f01e82c00db92eaa27912c"
	hash_4 = "7f838907f9cc8305544bd0ad4cfd278e"
	hash_5 = "071e12454731161d47a12a8c4b3adfea"
	hash_6 = "a7d50760d49faff3656903c1130fd20b"
	hash_7 = "f399afb901fcdf436a1b2a135da3ee39"
	hash_8 = "3698a3630f80a632c0c7c12e929184fb"
	hash_9 = "fdb674cadfa038ff9d931e376f89f1b6"

   strings:
		
        $sa_1 = "META-INF/MANIFEST.MF"
        $sa_2 = "Main.classPK"
        $sa_3 = "plugins/Server.classPK"
        $sa_4 = "IDPK"
		
        $sb_1 = "config.iniPK"
        $sb_2 = "password.iniPK"
        $sb_3 = "plugins/Server.classPK"
        $sb_4 = "LoadStub.classPK"
        $sb_5 = "LoadStubDecrypted.classPK"
        $sb_7 = "LoadPassword.classPK"
        $sb_8 = "DecryptStub.classPK"
        $sb_9 = "ClassLoaders.classPK"
		
        $sc_1 = "config.xml"
        $sc_2 = "options"
        $sc_3 = "plugins"
        $sc_4 = "util"
        $sc_5 = "util/OSHelper"
        $sc_6 = "Start.class"
        $sc_7 = "AlienSpy"
        $sc_8 = "PK"
	
  condition:
    
	uint16(0) == 0x4B50 and filesize < 800KB and ( (all of ($sa_*)) or (all of ($sb_*)) or (all of ($sc_*)) )
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-09-03
	Identifier: Carbanak Rules
*/

/* Rule Set ----------------------------------------------------------------- */

rule Carbanak_0915_1 {
	meta:
		description = "Carbanak Malware"
		author = "Florian Roth"
		reference = "https://www.csis.dk/en/csis/blog/4710/"
		date = "2015-09-03"
		score = 70
	strings:
		$s1 = "evict1.pdb" fullword ascii
		$s2 = "http://testing.corp 0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule Carbanak_0915_2 {
	meta:
		description = "Carbanak Malware"
		author = "Florian Roth"
		reference = "https://www.csis.dk/en/csis/blog/4710/"
		date = "2015-09-03"
		score = 70
	strings:
		$x1 = "8Rkzy.exe" fullword wide

		$s1 = "Export Template" fullword wide
		$s2 = "Session folder with name '%s' already exists." fullword ascii
		$s3 = "Show Unconnected Endpoints (Ctrl+U)" fullword ascii
		$s4 = "Close All Documents" fullword wide
		$s5 = "Add &Resource" fullword ascii
		$s6 = "PROCEXPLORER" fullword wide /* Goodware String - occured 1 times */
		$s7 = "AssocQueryKeyA" fullword ascii /* Goodware String - occured 4 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and ( $x1 or all of ($s*) )
}

rule Carbanak_0915_3 {
	meta:
		description = "Carbanak Malware"
		author = "Florian Roth"
		reference = "https://www.csis.dk/en/csis/blog/4710/"
		date = "2015-09-03"
		score = 70
	strings:
		$s1 = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww" fullword ascii
		$s2 = "SHInvokePrinterCommandA" fullword ascii
		$s3 = "Ycwxnkaj" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "pe"

rule Careto_SGH {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto SGH component signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
		date = "2014/02/11"
	strings:
		$m1 = "PGPsdkDriver" ascii wide fullword
		$m2 = "jpeg1x32" ascii wide fullword
		$m3 = "SkypeIE6Plugin" ascii wide fullword
		$m4 = "CDllUninstall" ascii wide fullword
	condition:
		2 of them
}

rule Careto_OSX_SBD {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto OSX component signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
		date = "2014/02/11"
	strings:
		/* XORed "/dev/null strdup() setuid(geteuid())" */
		$1 = {FF 16 64 0A 7E 1A 63 4D 21 4D 3E 1E 60 0F 7C 1A 65 0F 74 0B 3E 1C 7F 12}
	condition:
		all of them
}

rule Careto_CnC {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto CnC communication signature"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
		date = "2014/02/11"
	strings:
		$1 = "cgi-bin/commcgi.cgi" ascii wide
		$2 = "Group" ascii wide
		$3 = "Install" ascii wide
		$4 = "Bn" ascii wide
	condition:
		all of them
}

rule Careto_CnC_domains {
	meta:
		author = "AlienVault (Alberto Ortega)"
		description = "TheMask / Careto known command and control domains"
		reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
		date = "2014/02/11"
	strings:
		$1 = "linkconf.net" ascii wide nocase
		$2 = "redirserver.net" ascii wide nocase
		$3 = "swupdt.com" ascii wide nocase
	condition:
		any of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "pe"

rule APT_DeputyDog_Fexel
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$180 = "180.150.228.102" wide ascii
	$0808cmd = {25 30 38 78 30 38 78 00 5C 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 [2-6] 43 00 61 00 6E 00 27 00 74 00 20 00 6F 00 70 00 65 00 6E 00 20 00 73 00 68 00 65 00 6C 00 6C 00 21}
	$cUp = "Upload failed! [Remote error code:" nocase wide ascii
	$DGGYDSYRL = {00 44 47 47 59 44 53 59 52 4C 00}
	$GDGSYDLYR = "GDGSYDLYR_%" wide ascii
condition:
	any of them
}

rule APT_DeputyDog
{
    meta:
        Author      = "FireEye Labs"
        Date        = "2013/09/21"
        Description = "detects string seen in samples used in 2013-3893 0day attacks"
        Reference   = "https://www.fireeye.com/blog/threat-research/2013/09/operation-deputydog-zero-day-cve-2013-3893-attack-against-japanese-targets.html"

    strings:
        $mz = {4d 5a}
        $a = "DGGYDSYRL"

    condition:
        ($mz at 0) and $a
}/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule apt_duqu2_loaders {

meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect Duqu 2.0 samples"
	last_modified = "2015-06-09"
	version = "1.0"

strings:
	$a1="{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
	$a2="\\\\.\\pipe\\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
	$a4="\\\\.\\pipe\\{AB6172ED-8105-4996-9D2A-597B5F827501}" wide
	$a5="Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" wide
	$a8="SELECT `Data` FROM `Binary` WHERE `Name`=’%s%i'" wide
	$a9="SELECT `Data` FROM `Binary` WHERE `Name`=’CryptHash%i'" wide
	$a7="SELECT `%s` FROM `%s` WHERE `%s`=’CAData%i'" wide
	
	$b1="MSI.dll"
	$b2="msi.dll"
	$b3="StartAction"

	$c1="msisvc_32@" wide
	$c2="PROP=" wide
	$c3="-Embedding" wide
	$c4="S:(ML;;NW;;;LW)" wide

	$d1 = "NameTypeBinaryDataCustomActionActionSourceTargetInstallExecuteSequenceConditionSequencePropertyValueMicrosoftManufacturer" nocase
	$d2 = {2E 3F 41 56 3F 24 5F 42 69 6E 64 40 24 30 30 58 55 3F 24 5F 50 6D 66 5F 77 72 61 70 40 50 38 43 4C 52 ?? 40 40 41 45 58 58 5A 58 56 31 40 24 24 24 56 40 73 74 64 40 40 51 41 56 43 4C 52 ?? 40 40 40 73 74 64 40 40}

condition:
	( (uint16(0) == 0x5a4d) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) ) and filesize < 100000 )

	or 

	( (uint32(0) == 0xe011cfd0) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) or (any of ($d*)) ) and filesize < 20000000 )
}


rule apt_duqu2_drivers {

meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect Duqu 2.0 drivers"
	last_modified = "2015-06-09"
	version = "1.0"

strings:
	$a1="\\DosDevices\\port_optimizer" wide nocase
	$a2="romanian.antihacker"
	$a3="PortOptimizerTermSrv" wide
	$a4="ugly.gorilla1"

	$b1="NdisIMCopySendCompletePerPacketInfo"
	$b2="NdisReEnumerateProtocolBindings"
	$b3="NdisOpenProtocolConfiguration"

condition:
	uint16(0) == 0x5A4D and (any of ($a*) ) and (2 of ($b*)) and filesize < 100000
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule bin_ndisk {
	meta:
		description = "Hacking Team Disclosure Sample - file ndisk.sys"
		author = "Florian Roth"
		reference = "https://www.virustotal.com/en/file/a03a6ed90b89945a992a8c69f716ec3c743fa1d958426f4c50378cca5bef0a01/analysis/1436184181/"
		date = "2015-07-07"
		hash = "cf5089752ba51ae827971272a5b761a4ab0acd84"
	strings:
		$s1 = "\\Registry\\Machine\\System\\ControlSet00%d\\services\\ndisk.sys" fullword wide 
		$s2 = "\\Registry\\Machine\\System\\ControlSet00%d\\Enum\\Root\\LEGACY_NDISK.SYS" fullword wide 
		$s3 = "\\Driver\\DeepFrz" fullword wide
		$s4 = "Microsoft Kernel Disk Manager" fullword wide 
		$s5 = "ndisk.sys" fullword wide
		$s6 = "\\Device\\MSH4DEV1" fullword wide
		$s7 = "\\DosDevices\\MSH4DEV1" fullword wide
		$s8 = "built by: WinDDK" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 6 of them
}

rule Hackingteam_Elevator_DLL {
	meta:
		description = "Hacking Team Disclosure Sample - file elevator.dll"
		author = "Florian Roth"
		reference = "http://t.co/EG0qtVcKLh"
		date = "2015-07-07"
		hash = "b7ec5d36ca702cc9690ac7279fd4fea28d8bd060"
	strings:
		$s1 = "\\sysnative\\CI.dll" fullword ascii 
		$s2 = "setx TOR_CONTROL_PASSWORD" fullword ascii 
		$s3 = "mitmproxy0" fullword ascii 
		$s4 = "\\insert_cert.exe" fullword ascii
		$s5 = "elevator.dll" fullword ascii
		$s6 = "CRTDLL.DLL" fullword ascii
		$s7 = "fail adding cert" fullword ascii
		$s8 = "DownloadingFile" fullword ascii 
		$s9 = "fail adding cert: %s" fullword ascii
		$s10 = "InternetOpenA fail" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 6 of them
}

rule HackingTeam_Elevator_EXE {
	meta:
		description = "Hacking Team Disclosure Sample - file elevator.exe"
		author = "Florian Roth"
		reference = "Hacking Team Disclosure elevator.c"
		date = "2015-07-07"
		hash1 = "40a10420b9d49f87527bc0396b19ec29e55e9109e80b52456891243791671c1c"
		hash2 = "92aec56a859679917dffa44bd4ffeb5a8b2ee2894c689abbbcbe07842ec56b8d"
		hash = "9261693b67b6e379ad0e57598602712b8508998c0cb012ca23139212ae0009a1"
	strings:
		$x1 = "CRTDLL.DLL" fullword ascii
		$x2 = "\\sysnative\\CI.dll" fullword ascii
		$x3 = "\\SystemRoot\\system32\\CI.dll" fullword ascii
		$x4 = "C:\\\\Windows\\\\Sysnative\\\\ntoskrnl.exe" fullword ascii /* PEStudio Blacklist: strings */

		$s1 = "[*] traversing processes" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "_getkprocess" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "[*] LoaderConfig %p" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "loader.obj" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3" ascii /* PEStudio Blacklist: strings */
		$s6 = "[*] token restore" fullword ascii /* PEStudio Blacklist: strings */
		$s7 = "elevator.obj" fullword ascii
		$s8 = "_getexport" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of ($x*) and 3 of ($s*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule MiniDionis_readerView {
	meta:
		description = "MiniDionis Malware - file readerView.exe / adobe.exe"
		author = "Florian Roth"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
		date = "2015-07-20"
		/* Original Hash */
		hash1 = "ee5eb9d57c3611e91a27bb1fc2d0aaa6bbfa6c69ab16e65e7123c7c49d46f145"
		/* Derived Samples */
		hash2 = "a713982d04d2048a575912a5fc37c93091619becd5b21e96f049890435940004"
		hash3 = "88a40d5b679bccf9641009514b3d18b09e68b609ffaf414574a6eca6536e8b8f"
		hash4 = "97d8725e39d263ed21856477ed09738755134b5c0d0b9ae86ebb1cdd4cdc18b7"
		hash5 = "ed7abf93963395ce9c9cba83a864acb4ed5b6e57fd9a6153f0248b8ccc4fdb46"
		hash6 = "56ac764b81eb216ebed5a5ad38e703805ba3e1ca7d63501ba60a1fb52c7ebb6e"
	strings:
		$s1 = "%ws_out%ws" fullword wide /* score: '8.00' */
		$s2 = "dnlibsh" fullword ascii /* score: '7.00' */

		$op0 = { 0f b6 80 68 0e 41 00 0b c8 c1 e1 08 0f b6 c2 8b } /* Opcode */
		$op1 = { 8b ce e8 f8 01 00 00 85 c0 74 41 83 7d f8 00 0f } /* Opcode */
		$op2 = { e8 2f a2 ff ff 83 20 00 83 c8 ff 5f 5e 5d c3 55 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of ($s*) and 1 of ($op*)
}

/* Related - SFX files or packed files with typical malware content -------- */

rule Malicious_SFX1 {
	meta:
		description = "SFX with voicemail content"
		author = "Florian Roth"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
		date = "2015-07-20"
		hash = "c0675b84f5960e95962d299d4c41511bbf6f8f5f5585bdacd1ae567e904cb92f"
	strings:
		$s0 = "voicemail" ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s1 = ".exe" ascii
	condition:
		uint16(0) == 0x4b50 and filesize < 1000KB and $s0 in (3..80) and $s1 in (3..80) 
}

rule Malicious_SFX2 {
	meta:
		description = "SFX with adobe.exe content"
		author = "Florian Roth"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
		date = "2015-07-20"
		hash = "502e42dc99873c52c3ca11dd3df25aad40d2b083069e8c22dd45da887f81d14d"
	strings:
		$s1 = "adobe.exe" fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00' */
		$s2 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00' */
		$s3 = "GETPASSWORD1" fullword wide /* PEStudio Blacklist: strings */ /* score: '23.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule MiniDionis_VBS_Dropped {
	meta:
		description = "Dropped File - 1.vbs"
		author = "Florian Roth"
		reference = "https://malwr.com/analysis/ZDc4ZmIyZDI4MTVjNGY5NWI0YzE3YjIzNGFjZTcyYTY/"
		date = "2015-07-21"
		hash = "97dd1ee3aca815eb655a5de9e9e8945e7ba57f458019be6e1b9acb5731fa6646"
	strings:
		$s1 = "Wscript.Sleep 5000" ascii
		$s2 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii
		$s3 = "Set WshShell = CreateObject(\"WScript.Shell\")" ascii
		$s4 = "If(FSO.FileExists(\"" ascii
		$s5 = "then FSO.DeleteFile(\".\\" ascii
	condition:
		filesize < 1KB and all of them and $s1 in (0..40)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule MirageStrings : Mirage Family
{
    meta:
        description = "Mirage Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "Neo,welcome to the desert of real." wide ascii
        $ = "/result?hl=en&id=%s"
        
    condition:
       any of them
}

rule Mirage : Family
{
    meta:
        description = "Mirage"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        MirageStrings
}

rule Mirage_APT : APT Backdoor Rat
{
    meta:
        Author      = "Silas Cutler"
        Date        = "yyyy/mm/dd"
        Description = "Malware related to APT campaign"
        Reference   = "Useful link"
    
    strings:
        $a1 = "welcome to the desert of the real"
        $a2 = "Mirage"
        $b = "Encoding: gzip"
        $c = /\/[A-Za-z]*\?hl=en/

    condition: 
        (($a1 or $a2) or $b) and $c
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Backdoor_APT_Mongal
{
meta:
	author = "@patrickrolsen"
	maltype = "Backdoor.APT.Mongall"
	version = "0.1"
	reference = "fd69a799e21ccb308531ce6056944842" 
	date = "01/04/2014"
strings:
	$author  = "author user"
	$title   = "title Vjkygdjdtyuj" nocase
	$comp    = "company ooo"
	$cretime = "creatim\\yr2012\\mo4\\dy19\\hr15\\min10"
	$passwd  = "password 00000000"
condition:
        all of them
}

rule MongalCode : Mongal Family 
{
    meta:
        description = "Mongal code features"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
    
    strings:
        // gettickcount value checking
        $ = { 8B C8 B8 D3 4D 62 10 F7 E1 C1 EA 06 2B D6 83 FA 05 76 EB }
        
    condition:
        any of them
}

rule MongalStrings : Mongal Family
{
    meta:
        description = "Mongal Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
        
    strings:
        $ = "NSCortr.dll"
        $ = "NSCortr1.dll"
        $ = "Sina.exe"
        
    condition:
        any of them
}

rule Mongal : Family
{
    meta:
        description = "Mongal"
        author = "Seth Hardy"
        last_modified = "2014-07-15"
        
    condition:
        MongalCode or MongalStrings
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule APT_NGO_wuaclt
{
   meta:
    author = "AlienVault Labs"
  strings:
    $a = "%%APPDATA%%\\Microsoft\\wuauclt\\wuauclt.dat"
    $b = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    $c = "/news/show.asp?id%d=%d"
    
	$d = "%%APPDATA%%\\Microsoft\\wuauclt\\"
	$e = "0l23kj@nboxu"
	
	$f = "%%s.asp?id=%%d&Sid=%%d"
	$g = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SP Q%%d)"
	$h = "Cookies: UseID=KGIOODAOOK%%s"

  condition:
    ($a and $b and $c) or ($d and $e) or ($f and $g and $h)
}

rule APT_NGO_wuaclt_PDF
{
    	meta:
        	author = "AlienVault Labs"

	strings:
		$pdf  = "%PDF" nocase
		$comment = {3C 21 2D 2D 0D 0A 63 57 4B 51 6D 5A 6C 61 56 56 56 56 56 56 56 56 56 56 56 56 56 63 77 53 64 63 6A 4B 7A 38 35 6D 37 4A 56 6D 37 4A 46 78 6B 5A 6D 5A 6D 52 44 63 5A 58 41 73 6D 5A 6D 5A 7A 42 4A 31 79 73 2F 4F 0D 0A}
	
	condition:
		$pdf at 0 and $comment in (0..200)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule apt_sofacy_xtunnel {
    meta:
        author = "Claudio Guarnieri"
        description = "Sofacy Malware - German Bundestag"
        score = 75
    strings:
        $xaps = ":\\PROJECT\\XAPS_"
        $variant11 = "XAPS_OBJECTIVE.dll" $variant12 = "start"
        $variant21 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0"
        $variant22 = "is you live?"
        $mix1 = "176.31.112.10"
        $mix2 = "error in select, errno %d" $mix3 = "no msg"
        $mix4 = "is you live?"
        $mix5 = "127.0.0.1"
        $mix6 = "err %d"
        $mix7 = "i`m wait"
        $mix8 = "hello"
        $mix9 = "OpenSSL 1.0.1e 11 Feb 2013" $mix10 = "Xtunnel.exe"
    condition:
        ((uint16(0) == 0x5A4D) or (uint16(0) == 0xCFD0)) and (($xaps) or (all of ($variant1*)) or (all of ($variant2*)) or (6 of ($mix*))) 
}

rule Sofacy_Bundestag_Winexe {
    meta:
        description = "Winexe tool used by Sofacy group in Bundestag APT"
        author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        hash = "5130f600cd9a9cdc82d4bad938b20cbd2f699aadb76e7f3f1a93602330d9997d"
        score = 70
    strings:
        $s1 = "\\\\.\\pipe\\ahexec" fullword ascii 
        $s2 = "implevel" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 115KB and all of them
}

rule Sofacy_Bundestag_Mal2 {
    meta:
        description = "Sofacy Group Malware Sample 2"
        author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        hash = "566ab945f61be016bfd9e83cc1b64f783b9b8deb891e6d504d3442bc8281b092"
        score = 70
    strings:
        $x1 = "PROJECT\\XAPS_OBJECTIVE_DLL\\" ascii
        $x2 = "XAPS_OBJECTIVE.dll" fullword ascii

        $s1 = "i`m wait" fullword ascii 
    condition:
        uint16(0) == 0x5a4d and ( 1 of ($x*) ) and $s1
}

rule Sofacy_Bundestag_Mal3 {
    meta:
        description = "Sofacy Group Malware Sample 3"
        author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        hash = "5f6b2a0d1d966fc4f1ed292b46240767f4acb06c13512b0061b434ae2a692fa1"
        score = 70
    strings:
        $s1 = "shell\\open\\command=\"System Volume Information\\USBGuard.exe\" install" fullword ascii 
        $s2 = ".?AVAgentModuleRemoteKeyLogger@@" fullword ascii 
        $s3 = "<font size=4 color=red>process isn't exist</font>" fullword ascii 
        $s4 = "<font size=4 color=red>process is exist</font>" fullword ascii 
        $s5 = ".winnt.check-fix.com" fullword ascii 
        $s6 = ".update.adobeincorp.com" fullword ascii 
        $s7 = ".microsoft.checkwinframe.com" fullword ascii
        $s8 = "adobeincorp.com" fullword wide 
        $s9 = "# EXC: HttpSender - Cannot create Get Channel!" fullword ascii 

        $x1 = "User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:20.0) Gecko/20100101 Firefox/" wide 
        $x2 = "User-Agent: Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/2" wide 
        $x3 = "C:\\Windows\\System32\\cmd.exe" fullword wide 
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and (
            2 of ($s*) or 
            ( 1 of ($s*) and all of ($x*) )
        ) 
}

rule Sofacy_Bundestag_Batch {
    meta:
        description = "Sofacy Bundestags APT Batch Script"
        author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        score = 70
    strings:
        $s1 = "for %%G in (.pdf, .xls, .xlsx, .doc, .docx) do (" ascii 
        $s2 = "cmd /c copy"
        $s3 = "forfiles"
    condition:
        filesize < 10KB and all of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


/* Rule Set ----------------------------------------------------------------- */
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-04
	Identifier: Terracotta APT
	Comment: Reduced Rule Set
*/
rule Apolmy_Privesc_Trojan {
	meta:
		description = "Apolmy Privilege Escalation Trojan used in APT Terracotta"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 80
		hash = "d7bd289e6cee228eb46a1be1fcdc3a2bd5251bc1eafb59f8111756777d8f373d"
	strings:
		$s1 = "[%d] Failed, %08X" fullword ascii
		$s2 = "[%d] Offset can not fetched." fullword ascii
		$s3 = "PowerShadow2011" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule Mithozhan_Trojan {
	meta:
		description = "Mitozhan Trojan used in APT Terracotta"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		hash = "8553b945e2d4b9f45c438797d6b5e73cfe2899af1f9fd87593af4fd7fb51794a"
	strings:
		$s1 = "adbrowser" fullword wide 
		$s2 = "IJKLlGdmaWhram0vn36BgIOChYR3L45xcHNydXQvhmloa2ptbH8voYCDTw==" fullword ascii
		$s3 = "EFGHlGdmaWhrL41sf36BgIOCL6R3dk8=" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule RemoteExec_Tool {
	meta:
		description = "Remote Access Tool used in APT Terracotta"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		hash = "a550131e106ff3c703666f15d55d9bc8c816d1cb9ac1b73c2e29f8aa01e53b78"
	strings:
		$s0 = "cmd.exe /q /c \"%s\"" fullword ascii 
		$s1 = "\\\\.\\pipe\\%s%s%d" fullword ascii 
		$s2 = "This is a service executable! Couldn't start directly." fullword ascii 
		$s3 = "\\\\.\\pipe\\TermHlp_communicaton" fullword ascii 
		$s4 = "TermHlp_stdout" fullword ascii 
		$s5 = "TermHlp_stdin" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 75KB and 4 of ($s*)
}

/* Super Rules ------------------------------------------------------------- */

rule LiuDoor_Malware_1 {
	meta:
		description = "Liudoor Trojan used in Terracotta APT"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		super_rule = 1
		hash1 = "deed6e2a31349253143d4069613905e1dfc3ad4589f6987388de13e33ac187fc"
		hash2 = "4575e7fc8f156d1d499aab5064a4832953cd43795574b4c7b9165cdc92993ce5"
		hash3 = "ad1a507709c75fe93708ce9ca1227c5fefa812997ed9104ff9adfec62a3ec2bb"
	strings:
		$s1 = "svchostdllserver.dll" fullword ascii 
		$s2 = "SvcHostDLL: RegisterServiceCtrlHandler %S failed" fullword ascii 
		$s3 = "\\nbtstat.exe" fullword ascii
		$s4 = "DataVersionEx" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule LiuDoor_Malware_2 {
	meta:
		description = "Liudoor Trojan used in Terracotta APT"
		author = "Florian Roth"
		reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
		date = "2015-08-04"
		score = 70
		super_rule = 1
		hash1 = "f3fb68b21490ded2ae7327271d3412fbbf9d705c8003a195a705c47c98b43800"
		hash2 = "e42b8385e1aecd89a94a740a2c7cd5ef157b091fabd52cd6f86e47534ca2863e"
	strings:
		$s0 = "svchostdllserver.dll" fullword ascii 
		$s1 = "Lpykh~mzCCRv|mplpykCCHvq{phlCC\\jmmzqkIzmlvpqCC" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule SNOWGLOBE_Babar_Malware {
	meta:
		description = "Detects the Babar Malware used in the SNOWGLOBE attacks - file babar.exe"
		author = "Florian Roth"
		reference = "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france"
		date = "2015/02/18"
		hash = "27a0a98053f3eed82a51cdefbdfec7bb948e1f36"
		score = 80
	strings:
		$mz = { 4d 5a }
		$z0 = "admin\\Desktop\\Babar64\\Babar64\\obj\\DllWrapper" ascii fullword
		$z1 = "User-Agent: Mozilla/4.0 (compatible; MSI 6.0;" ascii fullword
		$z2 = "ExecQueryFailled!" fullword ascii
		$z3 = "NBOT_COMMAND_LINE" fullword
		$z4 = "!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]" fullword

		$s1 = "/s /n %s \"%s\"" fullword ascii
		$s2 = "%%WINDIR%%\\%s\\%s" fullword ascii
		$s3 = "/c start /wait " fullword ascii
		$s4 = "(D;OICI;FA;;;AN)(A;OICI;FA;;;BG)(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)" ascii

		$x1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii
		$x2 = "%COMMON_APPDATA%" fullword ascii
		$x4 = "CONOUT$" fullword ascii
		$x5 = "cmd.exe" fullword ascii
		$x6 = "DLLPATH" fullword ascii
	condition:
		( $mz at 0 ) and filesize < 1MB and
		(
			( 1 of ($z*) and 1 of ($x*) ) or
			( 3 of ($s*) and 4 of ($x*) )
		)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule BangatCode : Bangat Family 
{
    meta:
        description = "Bangat code features"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
    
    strings:
        // dec [ebp + procname], push eax, push edx, call get procaddress
        $ = { FE 4D ?? 8D 4? ?? 50 5? FF }
    
    condition:
        any of them
}

rule BangatStrings : Bangat Family
{
    meta:
        description = "Bangat Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    strings:
        $lib1 = "DreatePipe"
        $lib2 = "HetSystemDirectoryA"
        $lib3 = "SeleaseMutex"
        $lib4 = "DloseWindowStation"
        $lib5 = "DontrolService"
        $file = "~hhC2F~.tmp"
        $mc = "~_MC_3~"

    condition:
       all of ($lib*) or $file or $mc
}

rule Bangat : Family
{
    meta:
        description = "Bangat"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    condition:
        BangatCode or BangatStrings
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule BlackShades_3 : Trojan
{
    meta:
        description = "BlackShades RAT"
	author = "botherder https://github.com/botherder"

    strings:
        $mod1 = /(m)odAPI/
        $mod2 = /(m)odAudio/
        $mod3 = /(m)odBtKiller/
        $mod4 = /(m)odCrypt/
        $mod5 = /(m)odFuctions/
        $mod6 = /(m)odHijack/
        $mod7 = /(m)odICallBack/
        $mod8 = /(m)odIInet/
        $mod9 = /(m)odInfect/
        $mod10 = /(m)odInjPE/
        $mod11 = /(m)odLaunchWeb/
        $mod12 = /(m)odOS/
        $mod13 = /(m)odPWs/
        $mod14 = /(m)odRegistry/
        $mod15 = /(m)odScreencap/
        $mod16 = /(m)odSniff/
        $mod17 = /(m)odSocketMaster/
        $mod18 = /(m)odSpread/
        $mod19 = /(m)odSqueezer/
        $mod20 = /(m)odSS/
        $mod21 = /(m)odTorrentSeed/

        $tmr1 = /(t)mrAlarms/
        $tmr2 = /(t)mrAlive/
        $tmr3 = /(t)mrAnslut/
        $tmr4 = /(t)mrAudio/
        $tmr5 = /(t)mrBlink/
        $tmr6 = /(t)mrCheck/
        $tmr7 = /(t)mrCountdown/
        $tmr8 = /(t)mrCrazy/
        $tmr9 = /(t)mrDOS/
        $tmr10 = /(t)mrDoWork/
        $tmr11 = /(t)mrFocus/
        $tmr12 = /(t)mrGrabber/
        $tmr13 = /(t)mrInaktivitet/
        $tmr14 = /(t)mrInfoTO/
        $tmr15 = /(t)mrIntervalUpdate/
        $tmr16 = /(t)mrLiveLogger/
        $tmr17 = /(t)mrPersistant/
        $tmr18 = /(t)mrScreenshot/
        $tmr19 = /(t)mrSpara/
        $tmr20 = /(t)mrSprid/
        $tmr21 = /(t)mrTCP/
        $tmr22 = /(t)mrUDP/
        $tmr23 = /(t)mrWebHide/

    condition:    
        10 of ($mod*) or 10 of ($tmr*)
}

rule BlackShades2 : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="26/06/2013"
		description="BlackShades Server"
		
	strings:
		$signature1={62 73 73 5F 73 65 72 76 65 72}
		$signature2={43 4C 49 43 4B 5F 44 45 4C 41 59 00 53 43 4B 5F 49 44}
		$signature3={6D 6F 64 49 6E 6A 50 45}
		
	condition:
		$signature1 and $signature2 and $signature3
}

rule BlackShades_4 : rat
{
	meta:
		description = "BlackShades"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0" 

	strings:
		$a = { 42 00 6C 00 61 00 63 00 6B 00 73 00 68 00 61 00 64 00 65 00 73 }
		$b = { 36 00 3C 00 32 00 20 00 32 00 32 00 26 00 31 00 39 00 3E 00 1D 00 17 00 17 00 1C 00 07 00 1B 00 03 00 07 00 28 00 23 00 0C 00 1D 00 10 00 1B 00 12 00 00 00 28 00 37 00 10 00 01 00 06 00 11 00 0B 00 07 00 22 00 11 00 17 00 00 00 1D 00 1B 00 0B 00 2F 00 26 00 01 00 0B }
		$c = { 62 73 73 5F 73 65 72 76 65 72 }
		$d = { 43 4C 49 43 4B 5F 44 45 4C 41 59 00 53 43 4B 5F 49 44 }
		$e = { 6D 6F 64 49 6E 6A 50 45 }
		$apikey = "f45e373429c0def355ed9feff30eff9ca21eec0fafa1e960bea6068f34209439"

	condition:
		any of ($a, $b, $c, $d, $e) or $apikey		
}


rule BlackShades : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="26/06/2013"
		description="BlackShades Server"
		
	strings:
		$signature1={62 73 73 5F 73 65 72 76 65 72}
		$signature2={43 4C 49 43 4B 5F 44 45 4C 41 59 00 53 43 4B 5F 49 44}
		$signature3={6D 6F 64 49 6E 6A 50 45}
		
	condition:
		$signature1 and $signature2 and $signature3
}

rule BlackShades_25052015
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
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Bolonyokte : rat 
{
	meta:
		description = "UnknownDotNet RAT - Bolonyokte"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-02-01"
		filetype = "memory"
		version = "1.0" 

	strings:
		$campaign1 = "Bolonyokte" ascii wide
		$campaign2 = "donadoni" ascii wide
		
		$decoy1 = "nyse.com" ascii wide
		$decoy2 = "NYSEArca_Listing_Fees.pdf" ascii wide
		$decoy3 = "bf13-5d45cb40" ascii wide
		
		$artifact1 = "Backup.zip"  ascii wide
		$artifact2 = "updates.txt" ascii wide
		$artifact3 = "vdirs.dat" ascii wide
		$artifact4 = "default.dat"
		$artifact5 = "index.html"
		$artifact6 = "mime.dat"
		
		$func1 = "FtpUrl"
		$func2 = "ScreenCapture"
		$func3 = "CaptureMouse"
		$func4 = "UploadFile"

		$ebanking1 = "Internet Banking" wide
		$ebanking2 = "(Online Banking)|(Online banking)"
		$ebanking3 = "(e-banking)|(e-Banking)" nocase
		$ebanking4 = "login"
		$ebanking5 = "en ligne" wide
		$ebanking6 = "bancaires" wide
		$ebanking7 = "(eBanking)|(Ebanking)" wide
		$ebanking8 = "Anmeldung" wide
		$ebanking9 = "internet banking" nocase wide
		$ebanking10 = "Banking Online" nocase wide
		$ebanking11 = "Web Banking" wide
		$ebanking12 = "Power"

	condition:
		any of ($campaign*) or 2 of ($decoy*) or 2 of ($artifact*) or all of ($func*) or 3 of ($ebanking*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Casper_Backdoor_x86 {
	meta:
		description = "Casper French Espionage Malware - Win32/ProxyBot.B - x86 Payload http://goo.gl/VRJNLo"
		author = "Florian Roth"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/05"
		hash = "f4c39eddef1c7d99283c7303c1835e99d8e498b0"
		score = 80
	strings:
		$s1 = "\"svchost.exe\"" fullword wide
		$s2 = "firefox.exe" fullword ascii
		$s3 = "\"Host Process for Windows Services\"" fullword wide
		
		$x1 = "\\Users\\*" fullword ascii
		$x2 = "\\Roaming\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
		$x3 = "\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
		$x4 = "\\Documents and Settings\\*" fullword ascii
		
		$y1 = "%s; %S=%S" fullword wide
		$y2 = "%s; %s=%s" fullword ascii
		$y3 = "Cookie: %s=%s" fullword ascii
		$y4 = "http://%S:%d" fullword wide
		
		$z1 = "http://google.com/" fullword ascii
		$z2 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)" fullword ascii
		$z3 = "Operating System\"" fullword wide
	condition:
		( all of ($s*) ) or
		( 3 of ($x*) and 2 of ($y*) and 2 of ($z*) )
}

rule Casper_EXE_Dropper {
	meta:
		description = "Casper French Espionage Malware - Win32/ProxyBot.B - Dropper http://goo.gl/VRJNLo"
		author = "Florian Roth"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/05"
		hash = "e4cc35792a48123e71a2c7b6aa904006343a157a"
		score = 80
	strings:
		$s0 = "<Command>" fullword ascii
		$s1 = "</Command>" fullword ascii
		$s2 = "\" /d \"" fullword ascii
		$s4 = "'%s' %s" fullword ascii
		$s5 = "nKERNEL32.DLL" fullword wide
		$s6 = "@ReturnValue" fullword wide
		$s7 = "ID: 0x%x" fullword ascii
		$s8 = "Name: %S" fullword ascii
	condition:
		7 of them
}

rule Casper_Included_Strings {
	meta:
		description = "Casper French Espionage Malware - String Match in File - http://goo.gl/VRJNLo"
		author = "Florian Roth"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/06"
		score = 50
	strings:
		$a0 = "cmd.exe /C FOR /L %%i IN (1,1,%d) DO IF EXIST"
		$a1 = "& SYSTEMINFO) ELSE EXIT"
		
		$mz = { 4d 5a }
		$c1 = "domcommon.exe" wide fullword							// File Name
		$c2 = "jpic.gov.sy" fullword 								// C2 Server
		$c3 = "aiomgr.exe" wide fullword							// File Name
		$c4 = "perfaudio.dat" fullword								// Temp File Name
		$c5 = "Casper_DLL.dll" fullword								// Name 
		$c6 = { 7B 4B 59 DE 37 4A 42 26 59 98 63 C6 2D 0F 57 40 } 	// Decryption Key
		$c7 = "{4216567A-4512-9825-7745F856}" fullword 				// Mutex
	condition:
		all of ($a*) or
		( $mz at 0 ) and ( 1 of ($c*) )
}

rule Casper_SystemInformation_Output {
	meta:
		description = "Casper French Espionage Malware - System Info Output - http://goo.gl/VRJNLo"
		author = "Florian Roth"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/06"
		score = 70	
	strings:
		$a0 = "***** SYSTEM INFORMATION ******"
		$a1 = "***** SECURITY INFORMATION ******"
		$a2 = "Antivirus: "
		$a3 = "Firewall: "
		$a4 = "***** EXECUTION CONTEXT ******"
		$a5 = "Identity: "
		$a6 = "<CONFIG TIMESTAMP="
	condition:
		all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule CookiesStrings : Cookies Family
{
    meta:
        description = "Cookies Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $zip1 = "ntdll.exePK"
        $zip2 = "AcroRd32.exePK"
        $zip3 = "Setup=ntdll.exe\x0d\x0aSilent=1\x0d\x0a"
        $zip4 = "Setup=%temp%\\AcroRd32.exe\x0d\x0a"
        $exe1 = "Leave GetCommand!"
        $exe2 = "perform exe success!"
        $exe3 = "perform exe failure!"
        $exe4 = "Entry SendCommandReq!"
        $exe5 = "Reqfile not exist!"
        $exe6 = "LeaveDealUpfile!"
        $exe7 = "Entry PostData!"
        $exe8 = "Leave PostFile!"
        $exe9 = "Entry PostFile!"
        $exe10 = "\\unknow.zip" wide ascii
        $exe11 = "the url no respon!"
        
    condition:
      (2 of ($zip*)) or (2 of ($exe*))
}

rule Cookies : Family
{
    meta:
        description = "Cookies"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    condition:
        CookiesStrings
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule cxpidStrings : cxpid Family
{
    meta:
        description = "cxpid Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    strings:
        $ = "/cxpid/submit.php?SessionID="
        $ = "/cxgid/"
        $ = "E21BC52BEA2FEF26D005CF"
        $ = "E21BC52BEA39E435C40CD8"
        $ = "                   -,L-,O+,Q-,R-,Y-,S-"
        
    condition:
       any of them
}

rule cxpidCode : cxpid Family 
{
    meta:
        description = "cxpid code features"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
    
    strings:
        $entryjunk = { 55 8B EC B9 38 04 00 00 6A 00 6A 00 49 75 F9 }
    
    condition:
        any of them
}

rule cxpid : Family
{
    meta:
        description = "cxpid"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    condition:
        cxpidCode or cxpidStrings
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule DarkComet_2
{
    meta:
        description = "DarkComet RAT"
	author = "botherder https://github.com/botherder"

    strings:
        $bot1 = /(#)BOT#OpenUrl/ wide ascii
        $bot2 = /(#)BOT#Ping/ wide ascii
        $bot3 = /(#)BOT#RunPrompt/ wide ascii
        $bot4 = /(#)BOT#SvrUninstall/ wide ascii
        $bot5 = /(#)BOT#URLDownload/ wide ascii
        $bot6 = /(#)BOT#URLUpdate/ wide ascii
        $bot7 = /(#)BOT#VisitUrl/ wide ascii
        $bot8 = /(#)BOT#CloseServer/ wide ascii

        $ddos1 = /(D)DOSHTTPFLOOD/ wide ascii
        $ddos2 = /(D)DOSSYNFLOOD/ wide ascii
        $ddos3 = /(D)DOSUDPFLOOD/ wide ascii

        $keylogger1 = /(A)ctiveOnlineKeylogger/ wide ascii
        $keylogger2 = /(U)nActiveOnlineKeylogger/ wide ascii
        $keylogger3 = /(A)ctiveOfflineKeylogger/ wide ascii
        $keylogger4 = /(U)nActiveOfflineKeylogger/ wide ascii

        $shell1 = /(A)CTIVEREMOTESHELL/ wide ascii
        $shell2 = /(S)UBMREMOTESHELL/ wide ascii
        $shell3 = /(K)ILLREMOTESHELL/ wide ascii

    condition:
        4 of ($bot*) or all of ($ddos*) or all of ($keylogger*) or all of ($shell*)
}

rule DarkComet : rat
{
	meta:
		description = "DarkComet" 
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0" 

	strings:
		$a = "#BEGIN DARKCOMET DATA --"
		$b = "#EOF DARKCOMET DATA --"
		$c = "DC_MUTEX-"
		$k1 = "#KCMDDC5#-890"
		$k2 = "#KCMDDC51#-890"

	condition:
		any of them
}
rule DarkComet_3
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

rule DarkComet_Keylogger_File
{
	meta:
		author = "Florian Roth"
		description = "Looks like a keylogger file created by DarkComet Malware"
		date = "25.07.14"
		reference = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		score = 50
	strings:
		$magic = "::"
		$entry = /\n:: [A-Z]/
		$timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/
	condition:
		($magic at 0) and #entry > 10 and #timestamp > 10
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Trojan_Derusbi {
    meta:
        Author = "RSA_IR"
        Date     = "4Sept13"
        File     = "derusbi_variants v 1.3"
        MD5      = " c0d4c5b669cc5b51862db37e972d31ec "

    strings:
        $b1 = {8b 15 ?? ?? ?? ?? 8b ce d3 ea 83 c6 ?? 30 90 ?? ?? ?? ?? 40 3b 05 ?? ?? ?? ?? 72 ??}
        $b2 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E F7 5D 88 2E 0C A2 88 2E 4B 5D 88 2E F3 5D 88 2E}
        $b3 = {4E E6 40 BB}
        $b4 = {B1 19 BF 44}
        $b5 = {6A F5 44 3D ?? ?? 00 00 27 AF D4 3D 69 F5 44 3D 6E F5 44 3D 95 0A 44 3D D2 F5 44 3D 6A F5 44 3D}
        $b6 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E}
        $b7 = {D6 D5 A4 A3 ?? ?? 00 00 9B 8F 34 A3 D5 D5 A4 A3 D2 D5 A4 A3 29 2A A4 A3}
        $b8 = {C3 76 33 9F ?? ?? 00 00 8E 2C A3 9F C0 76 33 9F C7 76 33 9F 3C 89 33 9F}

    condition:
        2 of ($b1, $b2, $b3, $b4) and 1 of ($b5, $b6, $b7, $b8)
}

rule APT_Derusbi_DeepPanda
{
meta:
	author = "ThreatConnect Intelligence Research Team"
	reference = "http://www.crowdstrike.com/sites/default/files/AdversaryIntelligenceReport_DeepPanda_0.pdf"
strings:
	$D = "Dom4!nUserP4ss" wide ascii
condition:
	$D
}


rule APT_Derusbi_Gen
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$2 = "273ce6-b29f-90d618c0" wide ascii
	$A = "Ace123dx" fullword wide ascii
	$A1 = "Ace123dxl!" fullword wide ascii
	$A2 = "Ace123dx!@#x" fullword wide ascii
	$C = "/Catelog/login1.asp" wide ascii
	$DF = "~DFTMP$$$$$.1" wide ascii
	$G = "GET /Query.asp?loginid=" wide ascii
	$L = "LoadConfigFromReg failded" wide ascii
	$L1 = "LoadConfigFromBuildin success" wide ascii
	$ph = "/photoe/photo.asp HTTP" wide ascii
	$PO = "POST /photos/photo.asp" wide ascii
	$PC = "PCC_IDENT" wide ascii
condition:
	any of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Dridex_Trojan_XML {
	meta:
		description = "Dridex Malware in XML Document"
		author = "Florian Roth @4nc4p"
		reference = "https://threatpost.com/dridex-banking-trojan-spreading-via-macros-in-xml-files/111503"
		date = "2015/03/08"
		hash1 = "88d98e18ed996986d26ce4149ae9b2faee0bc082"
		hash2 = "3b2d59adadf5ff10829bb5c27961b22611676395"
		hash3 = "e528671b1b32b3fa2134a088bfab1ba46b468514"
		hash4 = "981369cd53c022b434ee6d380aa9884459b63350"
		hash5 = "96e1e7383457293a9b8f2c75270b58da0e630bea"
	strings:
		// can be ascii or wide formatted - therefore no restriction
		$c_xml      = "<?xml version="
		$c_word     = "<?mso-application progid=\"Word.Document\"?>"
		$c_macro    = "w:macrosPresent=\"yes\""
		$c_binary   = "<w:binData w:name="
		$c_0_chars  = "<o:Characters>0</o:Characters>"
		$c_1_line   = "<o:Lines>1</o:Lines>"
	condition:
		all of ($c*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule EnfalCode : Enfal Family 
{
    meta:
        description = "Enfal code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        // mov al, 20h; sub al, bl; add [ebx+esi], al; push esi; inc ebx; call edi; cmp ebx, eax
        $decrypt = { B0 20 2A C3 00 04 33 56 43 FF D7 3B D8 }
        
    condition:
        any of them
}

rule EnfalStrings : Enfal Family
{
    meta:
        description = "Enfal Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    strings:
        $ = "D:\\work\\\xe6\xba\x90\xe5\x93\xa5\xe5\x85\x8d\xe6\x9d\x80\\tmp\\Release\\ServiceDll.pdb"
        $ = "e:\\programs\\LuridDownLoader"
        $ = "LuridDownloader for Falcon"
        $ = "DllServiceTrojan"
        $ = "\\k\\\xe6\xa1\x8c\xe8\x9d\xa2\\"
        $ = "EtenFalcon\xef\xbc\x88\xe4\xbf\xae\xe6\x94\xb9\xef\xbc\x89"
        $ = "Madonna\x00Jesus"
        $ = "/iupw82/netstate"
        $ = "fuckNodAgain"
        $ = "iloudermao"
        $ = "Crpq2.cgi"
        $ = "Clnpp5.cgi"
        $ = "Dqpq3ll.cgi"
        $ = "dieosn83.cgi"
        $ = "Rwpq1.cgi"
        $ = "/Ccmwhite"
        $ = "/Cmwhite"
        $ = "/Crpwhite"
        $ = "/Dfwhite"
        $ = "/Query.txt"
        $ = "/Ufwhite"
        $ = "/cgl-bin/Clnpp5.cgi"
        $ = "/cgl-bin/Crpq2.cgi"
        $ = "/cgl-bin/Dwpq3ll.cgi"
        $ = "/cgl-bin/Owpq4.cgi"
        $ = "/cgl-bin/Rwpq1.cgi"
        $ = "/trandocs/mm/"
        $ = "/trandocs/netstat"
        $ = "NFal.exe"
        $ = "LINLINVMAN"
        $ = "7NFP4R9W"
        
    condition:
        any of them
}

rule Enfal : Family
{
    meta:
        description = "Enfal"
        author = "Seth Hardy"
        last_modified = "2014-06-19"
        
    condition:
        EnfalCode or EnfalStrings
}


rule Enfal_Malware {
	meta:
		description = "Detects a certain type of Enfal Malware"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/02/10"
		hash = "9639ec9aca4011b2724d8e7ddd13db19913e3e16"
		score = 60
	strings:
		$s0 = "POWERPNT.exe" fullword ascii
		$s1 = "%APPDATA%\\Microsoft\\Windows\\" fullword ascii
		$s2 = "%HOMEPATH%" fullword ascii
		$s3 = "Server2008" fullword ascii
		$s4 = "Server2003" fullword ascii
		$s5 = "Server2003R2" fullword ascii
		$s6 = "Server2008R2" fullword ascii
		$s9 = "%HOMEDRIVE%" fullword ascii
		$s13 = "%ComSpec%" fullword ascii
	condition:
		all of them
}

rule Enfal_Malware_Backdoor {
	meta:
		description = "Generic Rule to detect the Enfal Malware"
		author = "Florian Roth"
		date = "2015/02/10"
		super_rule = 1
		hash0 = "6d484daba3927fc0744b1bbd7981a56ebef95790"
		hash1 = "d4071272cc1bf944e3867db299b3f5dce126f82b"
		hash2 = "6c7c8b804cc76e2c208c6e3b6453cb134d01fa41"
		score = 60
	strings:
		$mz = { 4d 5a }
			
		$x1 = "Micorsoft Corportation" fullword wide
		$x2 = "IM Monnitor Service" fullword wide
		
		$s1 = "imemonsvc.dll" fullword wide
		$s2 = "iphlpsvc.tmp" fullword
		
		$z1 = "urlmon" fullword
		$z2 = "Registered trademarks and service marks are the property of their respec" wide		
		$z3 = "XpsUnregisterServer" fullword
		$z4 = "XpsRegisterServer" fullword
		$z5 = "{53A4988C-F91F-4054-9076-220AC5EC03F3}" fullword
	condition:
		( $mz at 0 ) and 
		( 
			1 of ($x*) or 
			( all of ($s*) and all of ($z*) )
		)
}
rule ce_enfal_cmstar_debug_msg
{
    meta:
        Author      = "rfalcone"
        Date        = "2015.05.10"
        Description = "Detects the static debug strings within CMSTAR"
        Reference   = "http://researchcenter.paloaltonetworks.com/2015/05/cmstar-downloader-lurid-and-enfals-new-cousin"

    strings:
        $d1 = "EEE\x0d\x0a" fullword
        $d2 = "TKE\x0d\x0a" fullword
        $d3 = "VPE\x0d\x0a" fullword
        $d4 = "VPS\x0d\x0a" fullword
        $d5 = "WFSE\x0d\x0a" fullword
        $d6 = "WFSS\x0d\x0a" fullword
        $d7 = "CM**\x0d\x0a" fullword

    condition:
        uint16(0) == 0x5a4d and all of ($d*)
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Exploit_MS15_077_078 {
	meta:
		description = "MS15-078 / MS15-077 exploit - generic signature"
		author = "Florian Roth"
		reference = "https://code.google.com/p/google-security-research/issues/detail?id=473&can=1&start=200"
		date = "2015-07-21"
		hash1 = "18e3e840a5e5b75747d6b961fca66a670e3faef252aaa416a88488967b47ac1c"
		hash2 = "0b5dc030e73074b18b1959d1cf7177ff510dbc2a0ec2b8bb927936f59eb3d14d"
		hash3 = "fc609adef44b5c64de029b2b2cff22a6f36b6bdf9463c1bd320a522ed39de5d9"
		hash4 = "ad6bb982a1ecfe080baf0a2b27950f989c107949b1cf02b6e0907f1a568ece15"
	strings:
		$s1 = "GDI32.DLL" fullword ascii
		$s2 = "atmfd.dll" fullword wide
		$s3 = "AddFontMemResourceEx" fullword ascii
		$s4 = "NamedEscape" fullword ascii
		$s5 = "CreateBitmap" fullword ascii
		$s6 = "DeleteObject" fullword ascii

		$op0 = { 83 45 e8 01 eb 07 c7 45 e8 } /* Opcode */
		$op1 = { 8d 85 24 42 fb ff 89 04 24 e8 80 22 00 00 c7 45 } /* Opcode */
		$op2 = { eb 54 8b 15 6c 00 4c 00 8d 85 24 42 fb ff 89 44 } /* Opcode */
		$op3 = { 64 00 88 ff 84 03 70 03 }
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of ($s*) or all of ($op*)
}

rule Exploit_MS15_077_078_HackingTeam {
	meta:
		description = "MS15-078 / MS15-077 exploit - Hacking Team code"
		author = "Florian Roth"
		date = "2015-07-21"
		super_rule = 1
		hash1 = "ad6bb982a1ecfe080baf0a2b27950f989c107949b1cf02b6e0907f1a568ece15"
		hash2 = "fc609adef44b5c64de029b2b2cff22a6f36b6bdf9463c1bd320a522ed39de5d9"
	strings:
		$s1 = "\\SystemRoot\\system32\\CI.dll" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "\\sysnative\\CI.dll" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "CRTDLL.DLL" fullword ascii
		$s5 = "\\sysnative" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "InternetOpenA coolio, trying open %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule FavoriteCode : Favorite Family 
{
    meta:
        description = "Favorite code features"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
    
    strings:
        // standard string hiding
        $ = { C6 45 ?? 3B C6 45 ?? 27 C6 45 ?? 34 C6 45 ?? 75 C6 45 ?? 6B C6 45 ?? 6C C6 45 ?? 3B C6 45 ?? 2F }
        $ = { C6 45 ?? 6F C6 45 ?? 73 C6 45 ?? 73 C6 45 ?? 76 C6 45 ?? 63 C6 45 ?? 65 C6 45 ?? 78 C6 45 ?? 65 }
    
    condition:
        any of them
}

rule FavoriteStrings : Favorite Family
{
    meta:
        description = "Favorite Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    strings:
        $string1 = "!QAZ4rfv"
        $file1 = "msupdater.exe"
        $file2 = "FAVORITES.DAT"
        
    condition:
       any of ($string*) or all of ($file*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule FlyingKitten : rat
{
    meta:
        Author      = "CrowdStrike, Inc"
        Date        = "2014/05/13"
        Description = "Flying Kitten RAT"
        Reference   = "http://blog.crowdstrike.com/cat-scratch-fever-crowdstrike-tracks-newly-reported-iranian-actor-flying-kitten"

    strings:
        $classpath = "Stealer.Properties.Resources.resources"
        $pdbstr = "\\Stealer\\obj\\x86\\Release\\Stealer.pdb"

    condition:
        all of them and uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x4550 and uint16(uint32(0x3C) + 0x16) & 0x2000 == 0 and ((uint16(uint32(0x3c)+24) == 0x010b and uint32(uint32(0x3c)+232) > 0) or (uint16(uint32(0x3c)+24) == 0x020b and uint32(uint32(0x3c)+248) > 0)) 

}

rule CSIT_14003_03 : installer
{ 
    meta:
        Author      = "CrowdStrike, Inc"
        Date        = "2014/05/13"
        Description = "Flying Kitten Installer"
        Reference   = "http://blog.crowdstrike.com/cat-scratch-fever-crowdstrike-tracks-newly-reported-iranian-actor-flying-kitten"

    strings:
        $exename = "IntelRapidStart.exe"
        $confname = "IntelRapidStart.exe.config"
        $cabhdr = { 4d 53 43 46 00 00 00 00 } 

    condition:
        all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule APT_WIN_Gh0st_ver
{
meta:
   author = "@BryanNolen"
   date = "2012-12"
   type = "APT"
   version = "1.1"
   ref = "Detection of Gh0st RAT server DLL component"
   ref1 = "http://www.mcafee.com/au/resources/white-papers/foundstone/wp-know-your-digital-enemy.pdf"
 strings:  
   $library = "deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly"
   $capability = "GetClipboardData"
   $capability1 = "capCreateCaptureWindowA"
   $capability2 = "CreateRemoteThread"
   $capability3 = "WriteProcessMemory"
   $capability4 = "LsaRetrievePrivateData"
   $capability5 = "AdjustTokenPrivileges"
   $function = "ResetSSDT"
   $window = "WinSta0\\Default"
   $magic = {47 6C 6F 62 61 6C 5C [5-9] 20 25 64}    /* $magic = "Gh0st" */
 condition:
   all of them
}

rule Gh0st
{
    meta:
        description = "Gh0st"
	author = "botherder https://github.com/botherder"

    strings:
        $ = /(G)host/
        $ = /(i)nflate 1\.1\.4 Copyright 1995-2002 Mark Adler/
        $ = /(d)eflate 1\.1\.4 Copyright 1995-2002 Jean-loup Gailly/
        $ = /(%)s\\shell\\open\\command/
        $ = /(G)etClipboardData/
        $ = /(W)riteProcessMemory/
        $ = /(A)djustTokenPrivileges/
        $ = /(W)inSta0\\Default/
        $ = /(#)32770/
        $ = /(#)32771/
        $ = /(#)32772/
        $ = /(#)32774/

    condition:
        all of them
}

rule gh0st

{

meta:
	author = "https://github.com/jackcr/"

   strings:
      $a = { 47 68 30 73 74 ?? ?? ?? ?? ?? ?? ?? ?? 78 9C }
      $b = "Gh0st Update"

   condition:
      any of them

}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule gholeeV1
{
    meta:
	 Author = "@GelosSnake"
    	 Date = "2014/08"
    	 Description = "Gholee first discovered variant "
	 Reference = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html" 

    strings:
    	 $a = "sandbox_avg10_vc9_SP1_2011"
    	 $b = "gholee"

    condition:
    	 all of them
}

rule gholeeV2
{
   meta:
	Author = "@GelosSnake"
	Date = "2015-02-12"
    	Description = "Gholee first discovered variant "
	Reference = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html" 

   strings:
	$string0 = "RichHa"
	$string1 = "         (((((                  H" wide
	$string2 = "1$1,141<1D1L1T1\\1d1l1t1"
	$string3 = "<8;$O' "
	$string4 = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]"
	$string5 = "jYPQTVTSkllZTTXRTUiHceWda/"
	$string6 = "urn:schemas-microsoft-com:asm.v1"
	$string7 = "8.848H8O8i8s8y8"
	$string8 = "wrapper3" wide
	$string9 = "pwwwwwwww"
	$string10 = "Sunday"
	$string11 = "YYuTVWh"
	$string12 = "DDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN"
	$string13 = "ytMMMMMMUbbrrrrrxxxxxxxxrriUMMMMMMMMMUuzt"
	$string15 = "wrapper3 Version 1.0" wide
	$string16 = "77A779"
	$string17 = "<C<G<M<R<X<"
	$string18 = "9 9-9N9X9s9"

    condition:
	18 of them
}

rule MW_gholee_v1 : v1
{
meta:
    Author = "@GelosSnake"
    description = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html"
    date = "2014-08"
    maltype = "Remote Access Trojan"
    sample_filetype = "dll"
    hash0 = "48573a150562c57742230583456b4c02"
   
strings:
    $a = "sandbox_avg10_vc9_SP1_2011"
    $b = "gholee"
   
condition:
    all of them
}
 
rule MW_gholee_v2 : v2
{
meta:
        author = "@GelosSnake"
        date = "2015-02-12"
        description = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html"
        hash0 = "05523761ca296ec09afdf79477e5f18d"
        hash1 = "08e424ac42e6efa361eccefdf3c13b21"
        hash2 = "5730f925145f1a1cd8380197e01d9e06"
        hash3 = "73461c8578dd9ab86d42984f30c04610"
        sample_filetype = "dll"
strings:
        $string0 = "RichHa"
        $string1 = "         (((((                  H" wide
        $string2 = "1$1,141<1D1L1T1\\1d1l1t1"
        $string3 = "<8;$O' "
        $string4 = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]"
        $string5 = "jYPQTVTSkllZTTXRTUiHceWda/"
        $string6 = "urn:schemas-microsoft-com:asm.v1"
        $string7 = "8.848H8O8i8s8y8"
        $string8 = "wrapper3" wide
        $string9 = "pwwwwwwww"
        $string10 = "Sunday"
        $string11 = "YYuTVWh"
        $string12 = "DDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN"
        $string13 = "ytMMMMMMUbbrrrrrxxxxxxxxrriUMMMMMMMMMUuzt"
        $string15 = "wrapper3 Version 1.0" wide
        $string16 = "77A779"
        $string17 = "<C<G<M<R<X<"
        $string18 = "9 9-9N9X9s9"
condition:
        18 of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule GlassesCode : Glasses Family 
{
    meta:
        description = "Glasses code features"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
        
    strings:
        $ = { B8 AB AA AA AA F7 E1 D1 EA 8D 04 52 2B C8 }
        $ = { B8 56 55 55 55 F7 E9 8B 4C 24 1C 8B C2 C1 E8 1F 03 D0 49 3B CA }
        
    condition:
        any of them
}

rule GlassesStrings : Glasses Family
{
    meta:
        description = "Strings used by Glasses"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
        
    strings:
        $ = "thequickbrownfxjmpsvalzydg"
        $ = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0; %s.%s)"
        $ = "\" target=\"NewRef\"></a>"
 
    condition:
        all of them

}

rule Glasses : Family
{
    meta:
        description = "Glasses family"
        author = "Seth Hardy"
        last_modified = "2014-07-22"
   
    condition:
        GlassesCode or GlassesStrings
        
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule Win32OPCHavex
{
    meta:
        Author      = "BAE Systems"
        Date        = "2014/06/23"
        Description = "Rule for identifying OPC version of HAVEX"
        Reference   = "www.f-secure.com/weblog/archives/00002718.html"

    strings:
        $mzhdr = "MZ"
        $dll = "7CFC52CD3F87.dll"
        $a1 = "Start finging of LAN hosts..." wide
        $a2 = "Finding was fault. Unexpective error" wide
        $a3 = "Was found %i hosts in LAN:" wide
        $a4 = "Hosts was't found." wide
        $a5 = "Start finging of OPC Servers..." wide
        $a6 = "Was found %i OPC Servers." wide
        $a7 = "OPC Servers not found. Programm finished" wide
        $a8 = "%s[%s]!!!EXEPTION %i!!!" wide
        $a9 = "Start finging of OPC Tags..." wide

    condition:
        $mzhdr at 0 and ($dll or (any of ($a*)))
}

rule Win32FertgerHavex
{
    meta:
        Author      = "BAE Systems"
        Date        = "2014/06/23"
        Description = "Rule for identifying Fertger version of HAVEX"
        Reference   = "www.f-secure.com/weblog/archives/00002718.html"

    strings:
        $mz = "MZ"
        $a1="\\\\.\\pipe\\mypipe-f" wide
        $a2="\\\\.\\pipe\\mypipe-h" wide
        $a3="\\qln.dbx" wide
        $a4="*.yls" wide
        $a5="\\*.xmd" wide
        $a6="fertger" wide
        $a7="havex"
    
    condition:
        $mz at 0 and 3 of ($a*) 
}

rule Havex_Trojan_PHP_Server
{
    meta:
        Author      = "Florian Roth"
        Date        = "2014/06/24"
        Description = "Detects the PHP server component of the Havex RAT"
        Reference   = "www.f-secure.com/weblog/archives/00002718.html"

    strings:
        $s1 = "havex--></body></head>"
        $s2 = "ANSWERTAG_START"
        $s3 = "PATH_BLOCKFILE"

    condition:
        all of them
} 

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule iexpl0reCode : iexpl0ree Family 
{
    meta:
        description = "iexpl0re code features"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
        
    strings:
        $ = { 47 83 FF 64 0F 8C 6D FF FF FF 33 C0 5F 5E 5B C9 C3 }
        $ = { 80 74 0D A4 44 41 3B C8 7C F6 68 04 01 00 00 }
        $ = { 8A C1 B2 07 F6 EA 30 04 31 41 3B 4D 10 7C F1 }
        $ = { 47 83 FF 64 0F 8C 79 FF FF FF 33 C0 5F 5E 5B C9 C3 }
        // 88h decrypt
        $ = { 68 88 00 00 00 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        $ = { BB 88 00 00 00 53 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        
    condition:
        any of them
}

rule iexpl0reStrings : iexpl0re Family
{
    meta:
        description = "Strings used by iexpl0re"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
        
    strings:
        $ = "%USERPROFILE%\\IEXPL0RE.EXE"
        $ = "\"<770j (("
        $ = "\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\IEXPL0RE.LNK"
        $ = "\\Documents and Settings\\%s\\Application Data\\Microsoft\\Internet Explorer\\IEXPL0RE.EXE"
        $ = "LoaderV5.dll"
        // stage 2
        $ = "POST /index%0.9d.asp HTTP/1.1"
        $ = "GET /search?n=%0.9d&"
        $ = "DUDE_AM_I_SHARP-3.14159265358979x6.626176"
        $ = "WHO_A_R_E_YOU?2.99792458x1.25663706143592"
        $ = "BASTARD_&&_BITCHES_%0.8x"
        $ = "c:\\bbb\\eee.txt"
        
    condition:
        any of them

}

rule iexpl0re : Family
{
    meta:
        description = "iexpl0re family"
        author = "Seth Hardy"
        last_modified = "2014-07-21"
   
    condition:
        iexpl0reCode or iexpl0reStrings
        
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule IMulerCode : IMuler Family 
{
    meta:
        description = "IMuler code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_tmpSpotlight = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 53 70 6F }
        $L4_TMPAAABBB = { C7 ?? ?? ?? ?? ?? 54 4D 50 41 C7 ?? ?? ?? ?? ?? 41 41 42 42 }
        $L4_FILEAGENTVer = { C7 ?? 46 49 4C 45 C7 ?? 04 41 47 45 4E }
        $L4_TMP0M34JDF8 = { C7 ?? ?? ?? ?? ?? 54 4D 50 30 C7 ?? ?? ?? ?? ?? 4D 33 34 4A }
        $L4_tmpmdworker = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 2E 6D 64 }
        
    condition:
        any of ($L4*)
}

rule IMulerStrings : IMuler Family
{
    meta:
        description = "IMuler Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    strings:
        $ = "/cgi-mac/"
        $ = "xnocz1"
        $ = "checkvir.plist"
        $ = "/Users/apple/Documents/mac back"
        $ = "iMuler2"
        $ = "/Users/imac/Desktop/macback/"
        $ = "xntaskz.gz"
        $ = "2wmsetstatus.cgi"
        $ = "launch-0rp.dat"
        $ = "2wmupload.cgi"
        $ = "xntmpz"
        $ = "2wmrecvdata.cgi"
        $ = "xnorz6"
        $ = "2wmdelfile.cgi"
        $ = "/LanchAgents/checkvir"
        $ = "0PERA:%s"
        $ = "/tmp/Spotlight"
        $ = "/tmp/launch-ICS000"
        
    condition:
        any of them
}

rule IMuler : Family
{
    meta:
        description = "IMuler"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    condition:
        IMulerCode or IMulerStrings
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Insta11Code : Insta11 Family 
{
    meta:
        description = "Insta11 code features"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
    
    strings:
        // jmp $+5; push 423h
        $jumpandpush = { E9 00 00 00 00 68 23 04 00 00 }
    
    condition:
        any of them
}

rule Insta11Strings : Insta11 Family
{
    meta:
        description = "Insta11 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    strings:
        $ = "XTALKER7"
        $ = "Insta11 Microsoft" wide ascii
        $ = "wudMessage"
        $ = "ECD4FC4D-521C-11D0-B792-00A0C90312E1"
        $ = "B12AE898-D056-4378-A844-6D393FE37956"
        
    condition:
       any of them
}

rule Insta11 : Family
{
    meta:
        description = "Insta11"
        author = "Seth Hardy"
        last_modified = "2014-06-23"
        
    condition:
        Insta11Code or Insta11Strings
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Intel_Virtualization_Wizard_exe {
  meta:
    author = "cabrel@zerklabs.com"
    description = "Dynamic DLL abuse executable"

    file_1_seen = "2013-05-21"
    file_1_sha256 = "7787757ae851f4a162f46f794be1532ab78e1928185212bdab83b3106f28c708"

  strings:
    $a = {4C 6F 61 64 53 54 52 49 4E 47}
    $b = {49 6E 69 74 69 61 6C 69 7A 65 4B 65 79 48 6F 6F 6B}
    $c = {46 69 6E 64 52 65 73 6F 75 72 63 65 73}
    $d = {4C 6F 61 64 53 54 52 49 4E 47 46 72 6F 6D 48 4B 43 55}
    $e = {68 63 63 75 74 69 6C 73 2E 44 4C 4C}
  condition:
    all of them
}

rule Intel_Virtualization_Wizard_dll {
  meta:
    author = "cabrel@zerklabs.com"
    description = "Dynamic DLL (Malicious)"

    file_1_seen = "2013-05-21"
    file_1_sha256 = "485ae043b6a5758789f1d33766a26d8b45b9fde09cde0512aa32d4bd1ee04f28"

  strings:
    $a = {48 3A 5C 46 61 73 74 5C 50 6C 75 67 28 68 6B 63 6D 64 29 5C}
    $b = {64 6C 6C 5C 52 65 6C 65 61 73 65 5C 48 69 6A 61 63 6B 44 6C 6C 2E 70 64 62}

  condition:
    ($a and $b) and Intel_Virtualization_Wizard_exe
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule KeyBoy_Dropper  
{  
    meta:
        Author      = "Rapid7 Labs"
        Date        = "2013/06/07"
        Description = "Strings inside"
        Reference   = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"

    strings:
        $1 = "I am Admin"  
        $2 = "I am User"  
        $3 = "Run install success!"  
        $4 = "Service install success!"  
        $5 = "Something Error!"  
        $6 = "Not Configed, Exiting"  

    condition:  
        all of them  
}

rule KeyBoy_Backdoor  
{
    meta:
        Author      = "Rapid7 Labs"
        Date        = "2013/06/07"
        Description = "Strings inside"
        Reference   = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"

    strings:  
        $1 = "$login$"  
        $2 = "$sysinfo$"  
        $3 = "$shell$"  
        $4 = "$fileManager$"  
        $5 = "$fileDownload$"  
        $6 = "$fileUpload$"  

    condition:  
        all of them  
} 
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"
rule KINS_dropper {
	meta:
		author = "AlienVault Labs aortega@alienvault.com"
		description = "Match protocol, process injects and windows exploit present in KINS dropper"
		reference = "http://goo.gl/arPhm3"
	strings:
		// Network protocol
		$n1 = "tid=%d&ta=%s-%x" fullword
		$n2 = "fid=%d" fullword
		$n3 = "%[^.].%[^(](%[^)])" fullword
		// Injects
		$i0 = "%s [%s %d] 77 %s"
		$i01 = "Global\\%s%x"
		$i1 = "Inject::InjectProcessByName()"
		$i2 = "Inject::CopyImageToProcess()"
		$i3 = "Inject::InjectProcess()"
		$i4 = "Inject::InjectImageToProcess()"
		$i5 = "Drop::InjectStartThread()"
		// UAC bypass
		$uac1 = "ExploitMS10_092"
		$uac2 = "\\globalroot\\systemroot\\system32\\tasks\\" ascii wide
		$uac3 = "<RunLevel>HighestAvailable</RunLevel>" ascii wide
	condition:
		2 of ($n*) and 2 of ($i*) and 2 of ($uac*)
}

rule KINS_DLL_zeus {
	meta:
		author = "AlienVault Labs aortega@alienvault.com"
		description = "Match default bot in KINS leaked dropper, Zeus"
		reference = "http://goo.gl/arPhm3"
	strings:
		// Network protocol
		$n1 = "%BOTID%" fullword
		$n2 = "%opensocks%" fullword
		$n3 = "%openvnc%" fullword
		$n4 = /Global\\(s|v)_ev/ fullword
		// Crypted strings
		$s1 = "\x72\x6E\x6D\x2C\x36\x7D\x76\x77"
		$s2 = "\x18\x04\x0F\x12\x16\x0A\x1E\x08\x5B\x11\x0F\x13"
		$s3 = "\x39\x1F\x01\x07\x15\x19\x1A\x33\x19\x0D\x1F"
		$s4 = "\x62\x6F\x71\x78\x63\x61\x7F\x69\x2D\x67\x79\x65"
		$s5 = "\x6F\x69\x7F\x6B\x61\x53\x6A\x7C\x73\x6F\x71"
	condition:
		all of ($n*) and 1 of ($s*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

/* LENOVO Superfish -------------------------------------------------------- */

rule VisualDiscovery_Lonovo_Superfish_SSL_Hijack {
	meta:
		description = "Lenovo Superfish SSL Interceptor - file VisualDiscovery.exe"
		author = "Florian Roth / improved by kbandla"
		reference = "https://twitter.com/4nc4p/status/568325493558272000"
		date = "2015/02/19"
		hash1 = "99af9cfc7ab47f847103b5497b746407dc566963"
		hash2 = "f0b0cd0227ba302ac9ab4f30d837422c7ae66c46"
		hash3 = "f12edf2598d8f0732009c5cd1df5d2c559455a0b"
		hash4 = "343af97d47582c8150d63cbced601113b14fcca6"
	strings:
		$mz = { 4d 5a }
		//$s1 = "VisualDiscovery.exe" fullword wide
		$s2 = "Invalid key length used to initialize BlowFish." fullword ascii
		$s3 = "GetPCProxyHandler" fullword ascii
		$s4 = "StartPCProxy" fullword ascii
		$s5 = "SetPCProxyHandler" fullword ascii
	condition:
		( $mz at 0 ) and filesize < 2MB and all of ($s*)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// Linux/Moose yara rules
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

private rule is_elf
{
    strings:
        $header = { 7F 45 4C 46 }

    condition:
        $header at 0
}

rule moose
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
}/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule LURK0Header : Family LURK0 {
	meta:
		description = "5 char code for LURK0"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = { C6 [5] 4C C6 [5] 55 C6 [5] 52 C6 [5] 4B C6 [5] 30 }

	condition:
		any of them
}

rule CCTV0Header : Family CCTV0 {
        meta:  
		description = "5 char code for LURK0"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"

	strings:
		//if its just one char a time
		$ = { C6 [5] 43 C6 [5] 43 C6 [5] 54 C6 [5] 56 C6 [5] 30 }
		// bit hacky but for when samples dont just simply mov 1 char at a time
		$ = { B0 43 88 [3] 88 [3] C6 [3] 54 C6 [3] 56 [0-12] (B0 30 | C6 [3] 30) }

	condition:
		any of them
}

rule SharedStrings : Family {
	meta:
		description = "Internal names found in LURK0/CCTV0 samples"
		author = "Katie Kleemola"
		last_updated = "07-22-2014"
	
	strings:
		// internal names
		$i1 = "Butterfly.dll"
		$i2 = /\\BT[0-9.]+\\ButterFlyDLL\\/
		$i3 = "ETClientDLL"

		// dbx
		$d1 = "\\DbxUpdateET\\" wide
		$d2 = "\\DbxUpdateBT\\" wide
		$d3 = "\\DbxUpdate\\" wide
		
		// other folders
		$mc1 = "\\Micet\\"

		// embedded file names
		$n1 = "IconCacheEt.dat" wide
		$n2 = "IconConfigEt.dat" wide

		$m1 = "\x00\x00ERXXXXXXX\x00\x00" wide
		$m2 = "\x00\x00111\x00\x00" wide
		$m3 = "\x00\x00ETUN\x00\x00" wide
		$m4 = "\x00\x00ER\x00\x00" wide

	condition:
		any of them //todo: finetune this

}

rule LURK0 : Family LURK0 {
	
	meta:
		description = "rule for lurk0"
		author = "Katie Kleemola"
		last_updated = "07-22-2014"

	condition:
		LURK0Header and SharedStrings

}


rule CCTV0 : Family CCTV0 {

	meta:
		description = "rule for cctv0"
		author = "Katie Kleemola"
		last_updated = "07-22-2014"

	condition:
		CCTV0Header and SharedStrings

}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule MacControlCode : MacControl Family 
{
    meta:
        description = "MacControl code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-17"
        
    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_Accept = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 3A 20 }
        $L4_AcceptLang = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 2D 4C }
        $L4_Pragma = { C7 ?? 50 72 61 67 C7 ?? 04 6D 61 3A 20 }
        $L4_Connection = { C7 ?? 43 6F 6E 6E C7 ?? 04 65 63 74 69 }
        $GEThgif = { C7 ?? 47 45 54 20 C7 ?? 04 2F 68 2E 67 }
        
    condition:
        all of ($L4*) or $GEThgif
}

rule MacControlStrings : MacControl Family
{
    meta:
        description = "MacControl Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-17"
        
    strings:
        $ = "HTTPHeadGet"
        $ = "/Library/launched"
        $ = "My connect error with no ip!"
        $ = "Send File is Failed"
        $ = "****************************You Have got it!****************************"
        
    condition:
        any of them
}

rule MacControl : Family
{
    meta:
        description = "MacControl"
        author = "Seth Hardy"
        last_modified = "2014-06-16"
        
    condition:
        MacControlCode or MacControlStrings
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule PoS_Malware_MalumPOS
{
    meta:
        author = "Trend Micro, Inc."
        date = "2015-05-25"
        description = "Used to detect MalumPOS memory dumper"
        sample_filtype = "exe"
    strings:
        $string1 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $string2 = "B)[0-9]{13,19}\\"
        $string3 = "[A-Za-z\\s]{0,30}\\/[A-Za-z\\s]{0,30}\\"
        $string4 = "TRegExpr(exec): ExecNext Without Exec[Pos]"
        $string5 = /Y:\\PROGRAMS\\.{20,300}\.pas/ 
    condition:
        all of ($string*)
}        

rule PoS_Malware_MalumPOS_Config
{
    meta:
        author = "Florian Roth"
        date = "2015-06-25"
        description = "MalumPOS Config File"
        reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/trend-micro-discovers-malumpos-targets-hotels-and-other-us-industries/"
    strings:
        $s1 = "[PARAMS]"
        $s2 = "Name="
        $s3 = "InterfacesIP="
        $s4 = "Port="
    condition:
        /* all of ($s*) and filename == "log.ini" and filesize < 20KB*/
        all of ($s*) and filesize < 20KB
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule Trojan_W32_Gh0stMiancha_1_0_0
{
    meta:
        Author      = "Context Threat Intelligence"
        Date        = "2014/01/27"
        Description = "Bytes inside"
        Reference   = "http://www.contextis.com/documents/30/TA10009_20140127_-_CTI_Threat_Advisory_-_The_Monju_Incident1.pdf"

    strings:
        $0x = { 57 5b 5a 5a 51 57 40 34 31 67 2e 31 70 34 5c 40 40 44 3b 25 3a 19 1e 5c 7b 67 60 2e 34 31 67 2e 31 70 19 1e 55 77 77 71 64 60 2e 34 3e 3b 3e 19 1e 57 7b 7a 60 71 7a 60 39 40 6d 64 71 2e 34 60 71 6c 60 3b 7c 60 79 78 19 1e 44 66 7b 6c 6d 39 57 7b 7a 7a 71 77 60 7d 7b 7a 2e 34 5f 71 71 64 39 55 78 7d 62 71 19 1e 57 7b 7a 60 71 7a 60 39 78 71 7a 73 60 7c 2e 34 24 19 1e 19 1e }
        $1 = { 5c e7 99 bd e5 8a a0 e9 bb 91 5c }
        $1x = { 48 f3 8d a9 f1 9e b4 fd af 85 48 }
        $2 = "DllCanLoadNow"
        $2x = { 50 78 78 57 75 7a 58 7b 75 70 5a 7b 63 }
        $3x = { 5a 61 79 76 71 66 34 7b 72 34 67 61 76 7f 71 6d 67 2e 34 31 70 } 
        $4 = "JXNcc2hlbGxcb3Blblxjb21tYW5k"
        $4x = { 5e 4c 5a 77 77 26 7c 78 76 53 6c 77 76 27 56 78 76 78 6c 7e 76 26 25 60 4d 43 21 7f }
        $5 = "SEFSRFdBUkVcREVTQ1JJUFRJT05cU3lzdGVtXENlbnRyYWxQcm9jZXNzb3JcMA=="
        $5x = { 47 51 52 47 46 52 70 56 41 7f 42 77 46 51 42 40 45 25 5e 5e 41 52 46 5e 40 24 21 77 41 27 78 6e 70 53 42 60 4c 51 5a 78 76 7a 46 6d 4d 43 6c 45 77 79 2d 7e 4e 4c 5a 6e 76 27 5e 77 59 55 29 29 }
        $6 = "C:\\Users\\why\\"
        $6x = { 57 2e 48 41 67 71 66 67 48 63 7c 6d 48 }
        $7 = "g:\\ykcx\\"
        $7x = { 73 2E 48 6D 7F 77 6C 48 }
        $8 = "(miansha)"
        $8x = { 3C 79 7D 75 7A 67 7C 75 3D }
        $9 = "server(\xE5\xA3\xB3)"
        $9x = { 7C 2E 48 26 24 25 27 3A 25 25 3A 26 21 48 67 71 66 62 71 66 3C F1 B7 A7 3D 48 46 71 78 71 75 67 71 48 67 71 66 62 71 66 3A 64 70 76 }
        $cfgDecode = { 8a ?? ?? 80 c2 7a 80 f2 19 88 ?? ?? 41 3b ce 7c ??}

   condition:
       any of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule NaikonCode : Naikon Family 
{
    meta:
        description = "Naikon code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
    
    strings:
        // decryption
        $ = { 0F AF C1 C1 E0 1F } // imul eax, ecx; shl eah, 1fh
        $ = { 35 5A 01 00 00} // xor eax, 15ah
        $ = { 81 C2 7F 14 06 00 } // add edx, 6147fh
    
    condition:
        all of them
}

rule NaikonStrings : Naikon Family
{
    meta:
        description = "Naikon Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "NOKIAN95/WEB"
        $ = "/tag=info&id=15"
        $ = "skg(3)=&3.2d_u1"
        $ = "\\Temp\\iExplorer.exe"
        $ = "\\Temp\\\"TSG\""
        
    condition:
       any of them
}

rule Naikon : Family
{
    meta:
        description = "Naikon"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        NaikonCode or NaikonStrings
}
rule Backdoor_Naikon_APT_Sample1 {
	meta:
		description = "Detects backdoors related to the Naikon APT"
		author = "Florian Roth"
		reference = "https://goo.gl/7vHyvh"
		date = "2015-05-14"
		hash = "d5716c80cba8554eb79eecfb4aa3d99faf0435a1833ec5ef51f528146c758eba"
		hash = "f5ab8e49c0778fa208baad660fe4fa40fc8a114f5f71614afbd6dcc09625cb96"
	strings:
		$x0 = "GET http://%s:%d/aspxabcdef.asp?%s HTTP/1.1" fullword ascii
		$x1 = "POST http://%s:%d/aspxabcdefg.asp?%s HTTP/1.1" fullword ascii
		$x2 = "greensky27.vicp.net" fullword ascii
		$x3 = "\\tempvxd.vxd.dll" fullword wide
		$x4 = "otna.vicp.net" fullword ascii
		$x5 = "smithking19.gicp.net" fullword ascii
		
		$s1 = "User-Agent: webclient" fullword ascii
		$s2 = "\\User.ini" fullword ascii
		$s3 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/200" ascii
		$s4 = "\\UserProfile.dll" fullword wide
		$s5 = "Connection:Keep-Alive: %d" fullword ascii
		$s6 = "Referer: http://%s:%d/" fullword ascii
		$s7 = "%s %s %s %d %d %d " fullword ascii
		$s8 = "%s--%s" fullword wide
		$s9 = "Run File Success!" fullword wide
		$s10 = "DRIVE_REMOTE" fullword wide
		$s11 = "ProxyEnable" fullword wide
		$s12 = "\\cmd.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and
		(
			1 of ($x*) or 7 of ($s*)
		)
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule nAspyUpdateCode : nAspyUpdate Family 
{
    meta:
        description = "nAspyUpdate code features"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
    
    strings:
        // decryption loop in dropper
        $ = { 8A 54 24 14 8A 01 32 C2 02 C2 88 01 41 4E 75 F4 }
        
    condition:
        any of them
}

rule nAspyUpdateStrings : nAspyUpdate Family
{
    meta:
        description = "nAspyUpdate Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    strings:
        $ = "\\httpclient.txt"
        $ = "password <=14"
        $ = "/%ldn.txt"
        $ = "Kill You\x00"
        
    condition:
        any of them
}

rule nAspyUpdate : Family
{
    meta:
        description = "nAspyUpdate"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    condition:
        nAspyUpdateCode or nAspyUpdateStrings
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule NetpassStrings : NetPass Variant {

        meta:
                description = "Identifiers for netpass variant"
                author = "Katie Kleemola"
                last_updated = "2014-05-29"

        strings:
                $exif1 = "Device Protect ApplicatioN" wide
                $exif2 = "beep.sys" wide //embedded exe name
                $exif3 = "BEEP Driver" wide //embedded exe description

                $string1 = "\x00NetPass Update\x00"
                $string2 = "\x00%s:DOWNLOAD\x00"
                $string3 = "\x00%s:UPDATE\x00"
                $string4 = "\x00%s:uNINSTALL\x00"

        condition:
                all of ($exif*) or any of ($string*)

}

rule NetPass : Variant {
        meta:
                description = "netpass variant"
                author = "Katie Kleemola"
                last_updated = "2014-07-08"
        condition:
                NetpassStrings
}

rule NetTravStrings : NetTraveler Family {


	meta:
        	description = "Identifiers for NetTraveler DLL"
		author = "Katie Kleemola"
        	last_updated = "2014-05-20"

	strings:
		//network strings
		$ = "?action=updated&hostid="
		$ = "travlerbackinfo"
		$ = "?action=getcmd&hostid="
		$ = "%s?action=gotcmd&hostid="
		$ = "%s?hostid=%s&hostname=%s&hostip=%s&filename=%s&filestart=%u&filetext="

		//debugging strings
		$ = "\x00Method1 Fail!!!!!\x00"
		$ = "\x00Method3 Fail!!!!!\x00"
		$ = "\x00method currect:\x00"
		$ = /\x00\x00[\w\-]+ is Running!\x00\x00/
		$ = "\x00OtherTwo\x00"

	condition:
		any of them

}

rule NetTravExports : NetTraveler Family {

	meta:
		description = "Export names for dll component"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"
	
	strings:
		//dll component exports
		$ = "?InjectDll@@YAHPAUHWND__@@K@Z"
		$ = "?UnmapDll@@YAHXZ"
		$ = "?g_bSubclassed@@3HA"
		
	condition:
		any of them
}

rule NetTraveler : Family {
	meta:
		description = "Nettravelr"
		author = "Katie Kleemola"
		last_updated = "2014-07-08"
	
	condition:
		NetTravExports or NetTravStrings or NetpassStrings

}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"
rule NetWiredRC_B : rat 
{
	meta:
		description = "NetWiredRC"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2014-12-23"
		filetype = "memory"
		version = "1.1" 

	strings:
		$mutex = "LmddnIkX"

		$str1 = "%s.Identifier"
		$str2 = "%d:%I64u:%s%s;"
		$str3 = "%s%.2d-%.2d-%.4d"
		$str4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
		$str5 = "%.2d/%.2d/%d %.2d:%.2d:%.2d"
		
		$klg1 = "[Backspace]"
		$klg2 = "[Enter]"
		$klg3 = "[Tab]"
		$klg4 = "[Arrow Left]"
		$klg5 = "[Arrow Up]"
		$klg6 = "[Arrow Right]"
		$klg7 = "[Arrow Down]"
		$klg8 = "[Home]"
		$klg9 = "[Page Up]"
		$klg10 = "[Page Down]"
		$klg11 = "[End]"
		$klg12 = "[Break]"
		$klg13 = "[Delete]"
		$klg14 = "[Insert]"
		$klg15 = "[Print Screen]"
		$klg16 = "[Scroll Lock]"
		$klg17 = "[Caps Lock]"
		$klg18 = "[Alt]"
		$klg19 = "[Esc]"
		$klg20 = "[Ctrl+%c]"

	condition: 
		$mutex or (1 of ($str*) and 1 of ($klg*))
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Njrat
{
    meta:
        description = "Njrat"
	author = "botherder https://github.com/botherder"

    strings:
        $string1 = /(F)romBase64String/
        $string2 = /(B)ase64String/
        $string3 = /(C)onnected/ wide ascii
        $string4 = /(R)eceive/
        $string5 = /(S)end/ wide ascii
        $string6 = /(D)ownloadData/ wide ascii
        $string7 = /(D)eleteSubKey/ wide ascii
        $string8 = /(g)et_MachineName/
        $string9 = /(g)et_UserName/
        $string10 = /(g)et_LastWriteTime/
        $string11 = /(G)etVolumeInformation/
        $string12 = /(O)SFullName/ wide ascii
        $string13 = /(n)etsh firewall/ wide
        $string14 = /(c)md\.exe \/k ping 0 & del/ wide
        $string15 = /(c)md\.exe \/c ping 127\.0\.0\.1 & del/ wide
        $string16 = /(c)md\.exe \/c ping 0 -n 2 & del/ wide
        $string17 = {7C 00 27 00 7C 00 27 00 7C}

    condition:
        10 of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule NSFreeCode : NSFree Family 
{
    meta:
        description = "NSFree code features"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
    
    strings:
        // push vars then look for MZ
        $ = { 53 56 57 66 81 38 4D 5A }
        // nops then look for PE\0\0
        $ = { 90 90 90 90 81 3F 50 45 00 00 }
    
    condition:
        all of them
}

rule NSFreeStrings : NSFree Family
{
    meta:
        description = "NSFree Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    strings:
        $ = "\\MicNS\\" nocase
        $ = "NSFreeDll" wide ascii
        // xor 0x58 dos stub
        $ = { 0c 30 31 2b 78 28 2a 37 3f 2a 39 35 78 3b 39 36 36 37 }
        
    condition:
       any of them
}

rule NSFree : Family
{
    meta:
        description = "NSFree"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    condition:
        NSFreeCode or NSFreeStrings
}


rule OpClandestineWolf

{
 
   meta:
        alert_severity = "HIGH"
        log = "false"
        author = "NDF"
        weight = 0
        alert = true
        source = " https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html"
        version = 1
	date = "2015-06-23"
	description = "Operation Clandestine Wolf signature based on OSINT from 06.23.15"
	hash0 = "1a4b710621ef2e69b1f7790ae9b7a288"
	hash1 = "917c92e8662faf96fffb8ffe7b7c80fb"
	hash2 = "975b458cb80395fa32c9dda759cb3f7b"
	hash3 = "3ed34de8609cd274e49bbd795f21acc4"
	hash4 = "b1a55ec420dd6d24ff9e762c7b753868"
	hash5 = "afd753a42036000ad476dcd81b56b754"
	hash6 = "fad20abf8aa4eda0802504d806280dd7"
	hash7 = "ab621059de2d1c92c3e7514e4b51751a"
	hash8 = "510b77a4b075f09202209f989582dbea"
	hash9 = "d1b1abfcc2d547e1ea1a4bb82294b9a3"
	hash10 = "4692337bf7584f6bda464b9a76d268c1"
	hash11 = "7cae5757f3ba9fef0a22ca0d56188439"
	hash12 = "1a7ba923c6aa39cc9cb289a17599fce0"
	hash13 = "f86db1905b3f4447eb5728859f9057b5"
	hash14 = "37c6d1d3054e554e13d40ea42458ebed"
	hash15 = "3e7430a09a44c0d1000f76c3adc6f4fa"
	hash16 = "98eb249e4ddc4897b8be6fe838051af7"
	hash17 = "1b57a7fad852b1d686c72e96f7837b44"
	hash18 = "ffb84b8561e49a8db60e0001f630831f"
	hash19 = "98eb249e4ddc4897b8be6fe838051af7"
	hash20 = "dfb4025352a80c2d81b84b37ef00bcd0"
	hash21 = "4457e89f4aec692d8507378694e0a3ba"
	hash22 = "48de562acb62b469480b8e29821f33b8"
	hash23 = "7a7eed9f2d1807f55a9308e21d81cccd"
	hash24 = "6817b29e9832d8fd85dcbe4af176efb6"

   strings:
	$s0 = "flash.Media.Sound()"
	$s1 = "call Kernel32!VirtualAlloc(0x1f140000hash$=0x10000hash$=0x1000hash$=0x40)"
	$s2 = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
	$s3 = "NetStream"

	condition:
		all of them
}



/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule PlugXStrings : PlugX Family
{
    meta:
        description = "PlugX Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-12"
        
    strings:
        $BootLDR = "boot.ldr" wide ascii
        $Dwork = "d:\\work" nocase
        $Plug25 = "plug2.5"
        $Plug30 = "Plug3.0"
        $Shell6 = "Shell6"
      
    condition:
        $BootLDR or ($Dwork and ($Plug25 or $Plug30 or $Shell6))
}

rule plugX : rat
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "PlugX RAT"
		date = "2014-05-13"
		filetype = "memory"
		version = "1.0" 
		ref1 = "https://github.com/mattulm/IR-things/blob/master/volplugs/plugx.py"
		
	strings:
		$v1a = { 47 55 4C 50 00 00 00 00 }
		$v1b = "/update?id=%8.8x" 
		$v1algoa = { BB 33 33 33 33 2B } 
		$v1algob = { BB 44 44 44 44 2B } 
		$v2a = "Proxy-Auth:" 
		$v2b = { 68 A0 02 00 00 } 
		$v2k = { C1 8F 3A 71 } 
		
	condition: 
		$v1a at 0 or $v1b or (($v2a or $v2b) and (($v1algoa and $v1algob) or $v2k))
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule poisonivy : rat
{
	meta:
		description = "Poison Ivy"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-02-01"
		filetype = "memory"
		version = "1.0" 
		ref1 = "https://code.google.com/p/volatility/source/browse/trunk/contrib/plugins/malware/poisonivy.py"

	strings:
		$a = { 53 74 75 62 50 61 74 68 ?? 53 4F 46 54 57 41 52 45 5C 43 6C 61 73 73 65 73 5C 68 74 74 70 5C 73 68 65 6C 6C 5C 6F 70 65 6E 5C 63 6F 6D 6D 61 6E 64 [22] 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 5C 41 63 74 69 76 65 20 53 65 74 75 70 5C 49 6E 73 74 61 6C 6C 65 64 20 43 6F 6D 70 6F 6E 65 6E 74 73 5C } 
		
	condition:
		$a
}

rule PoisonIvy_Generic_3 {
	meta:
		description = "PoisonIvy RAT Generic Rule"
		author = "Florian Roth"
		date = "2015-05-14"
		hash = "e1cbdf740785f97c93a0a7a01ef2614be792afcd"
	strings:
		$k1 = "Tiger324{" fullword ascii
		
		$s2 = "WININET.dll" fullword ascii
		$s3 = "mscoree.dll" fullword wide
		$s4 = "WS2_32.dll" fullword
		$s5 = "Explorer.exe" fullword wide
		$s6 = "USER32.DLL"
		$s7 = "CONOUT$"
		$s8 = "login.asp"
		
		$h1 = "HTTP/1.0"
		$h2 = "POST"
		$h3 = "login.asp"
		$h4 = "check.asp"
		$h5 = "result.asp"
		$h6 = "upload.asp"
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and
			( 
				$k1 or all of ($s*) or all of ($h*)
			)
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
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule BernhardPOS {
     meta:
          author = "Nick Hoffman / Jeremy Humble"
          last_update = "2015-07-14"
          source = "Morphick Inc."
          description = "BernhardPOS Credit Card dumping tool"
          reference = "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick"
          md5 = "e49820ef02ba5308ff84e4c8c12e7c3d"
          score = 70
     strings:
          $shellcode_kernel32_with_junk_code = { 33 c0 83 ?? ?? 83 ?? ?? 64 a1 30 00 00 00 83 ?? ?? 83 ?? ?? 8b 40 0c 83 ?? ?? 83 ?? ?? 8b 40 14 83 ?? ?? 83 ?? ?? 8b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 00 83 ?? ?? 83 ?? ?? 8b 40 10 83 ?? ?? }
          $mutex_name = "OPSEC_BERNHARD" 
          $build_path = "C:\\bernhard\\Debug\\bernhard.pdb" 
          $string_decode_routine = { 55 8b ec 83 ec 50 53 56 57 a1 ?? ?? ?? ?? 89 45 f8 66 8b 0d ?? ?? ?? ?? 66 89 4d fc 8a 15 ?? ?? ?? ?? 88 55 fe 8d 45 f8 50 ff ?? ?? ?? ?? ?? 89 45 f0 c7 45 f4 00 00 00 00 ?? ?? 8b 45 f4 83 c0 01 89 45 f4 8b 45 08 50 ff ?? ?? ?? ?? ?? 39 45 f4 ?? ?? 8b 45 08 03 45 f4 0f be 08 8b 45 f4 99 f7 7d f0 0f be 54 15 f8 33 ca 8b 45 08 03 45 f4 88 08 ?? ?? 5f 5e 5b 8b e5 5d }
     condition:
          any of them
 }
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule QuarianStrings : Quarian Family
{
    meta:
        description = "Quarian Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    strings:
        $ = "s061779s061750"
        $ = "[OnUpLoadFile]"
        $ = "[OnDownLoadFile]"
        $ = "[FileTransfer]"
        $ = "---- Not connect the Manager, so start UnInstall ----"
        $ = "------- Enter CompressDownLoadDir ---------"
        $ = "------- Enter DownLoadDirectory ---------"
        $ = "[HandleAdditionalData]"
        $ = "[mswsocket.dll]"
        $ = "msupdate.dll........Enter ThreadCmd!"
        $ = "ok1-1"
        $ = "msupdate_tmp.dll"
        $ = "replace Rpcss.dll successfully!"
        $ = "f:\\loadhiddendriver-mdl\\objfre_win7_x86\\i386\\intelnat.pdb"
        $ = "\\drivercashe\\" wide ascii
        $ = "\\microsoft\\windwos\\" wide ascii
        $ = "\\DosDevices\\LOADHIDDENDRIVER" wide ascii
        $ = "\\Device\\LOADHIDDENDRIVER" wide ascii
        $ = "Global\\state_maping" wide ascii
        $ = "E:\\Code\\2.0\\2.0_multi-port\\2.0\\ServerInstall_New-2010-0913_sp3\\msupdataDll\\Release\\msupdate_tmp.pdb"
        $ = "Global\\unInstall_event_1554_Ower" wide ascii
        
    condition:
       any of them
}

rule QuarianCode : Quarian Family 
{
    meta:
        description = "Quarian code features"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
    
    strings:
        // decrypt in intelnat.sys
        $ = { C1 E? 04 8B ?? F? C1 E? 05 33 C? }
        // decrypt in mswsocket.dll
        $ = { C1 EF 05 C1 E3 04 33 FB }
        $ = { 33 D8 81 EE 47 86 C8 61 }
        // loop in msupdate.dll
        $ = { FF 45 E8 81 45 EC CC 00 00 00 E9 95 FE FF FF }
    
    condition:
        any of them
}

rule Quarian : Family
{
    meta:
        description = "Quarian"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    condition:
        QuarianCode or QuarianStrings
}




/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule CryptoLocker_set1
{
meta:
	author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
	date = "2014-04-13"
	description = "Detection of Cryptolocker Samples"
	
strings:
	$string0 = "static"
	$string1 = " kscdS"
	$string2 = "Romantic"
	$string3 = "CompanyName" wide
	$string4 = "ProductVersion" wide
	$string5 = "9%9R9f9q9"
	$string6 = "IDR_VERSION1" wide
	$string7 = "  </trustInfo>"
	$string8 = "LookFor" wide
	$string9 = ":n;t;y;"
	$string10 = "        <requestedExecutionLevel level"
	$string11 = "VS_VERSION_INFO" wide
	$string12 = "2.0.1.0" wide
	$string13 = "<assembly xmlns"
	$string14 = "  <trustInfo xmlns"
	$string15 = "srtWd@@"
	$string16 = "515]5z5"
	$string17 = "C:\\lZbvnoVe.exe" wide
condition:
	12 of ($string*)
}

rule CryptoLocker_rule2
{
meta:
	author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
	date = "2014-04-14"
	description = "Detection of CryptoLocker Variants"
strings:
	$string0 = "2.0.1.7" wide
	$string1 = "    <security>"
	$string2 = "Romantic"
	$string3 = "ProductVersion" wide
	$string4 = "9%9R9f9q9"
	$string5 = "IDR_VERSION1" wide
	$string6 = "button"
	$string7 = "    </security>"
	$string8 = "VFileInfo" wide
	$string9 = "LookFor" wide
	$string10 = "      </requestedPrivileges>"
	$string11 = " uiAccess"
	$string12 = "  <trustInfo xmlns"
	$string13 = "last.inf"
	$string14 = " manifestVersion"
	$string15 = "FFFF04E3" wide
	$string16 = "3,31363H3P3m3u3z3"
condition:
	12 of ($string*)
}

rule SVG_LoadURL {
	meta:
		description = "Detects a tiny SVG file that loads an URL (as seen in CryptoWall malware infections)"
		author = "Florian Roth"
		reference = "http://goo.gl/psjCCc"
		date = "2015-05-24"
		hash1 = "ac8ef9df208f624be9c7e7804de55318"
		hash2 = "3b9e67a38569ebe8202ac90ad60c52e0"
		hash3 = "7e2be5cc785ef7711282cea8980b9fee"
		hash4 = "4e2c6f6b3907ec882596024e55c2b58b"
		score = 50
	strings:
		$s1 = "</svg>" nocase
		$s2 = "<script>" nocase
		$s3 = "location.href='http" nocase
	condition:
		all of ($s*) and filesize < 600
}
rule BackdoorFCKG: CTB_Locker_Ransomware
{
meta:
author = "ISG"
date = "2015-01-20"
reference = "https://blogs.mcafee.com/mcafee-labs/rise-backdoor-fckq-ctb-locker"
description = "CTB_Locker"

strings:
$string0 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
$stringl = "RNDBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 
$string2 = "keme132.DLL" 
$string3 = "klospad.pdb" 
condition:
3 of them 
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule RCS_Backdoor
{
    meta:
        description = "Hacking Team RCS Backdoor"
	author = "botherder https://github.com/botherder"

    strings:
        $filter1 = "$debug3"
        $filter2 = "$log2"
        $filter3 = "error2"

        $debug1 = /\- (C)hecking components/ wide ascii
        $debug2 = /\- (A)ctivating hiding system/ wide ascii
        $debug3 = /(f)ully operational/ wide ascii

        $log1 = /\- Browser activity \(FF\)/ wide ascii
        $log2 = /\- Browser activity \(IE\)/ wide ascii
        
        // Cause false positives.
        //$log3 = /\- About to call init routine at %p/ wide ascii
        //$log4 = /\- Calling init routine at %p/ wide ascii

        $error1 = /\[Unable to deploy\]/ wide ascii
        $error2 = /\[The system is already monitored\]/ wide ascii

    condition:
        (2 of ($debug*) or 2 of ($log*) or all of ($error*)) and not any of ($filter*)
}

rule RCS_Scout
{
    meta:
        description = "Hacking Team RCS Scout"
	author = "botherder https://github.com/botherder"

    strings:
        $filter1 = "$engine5"
        $filter2 = "$start4"
        $filter3 = "$upd2"
        $filter4 = "$lookma6"

        $engine1 = /(E)ngine started/ wide ascii
        $engine2 = /(R)unning in background/ wide ascii
        $engine3 = /(L)ocking doors/ wide ascii
        $engine4 = /(R)otors engaged/ wide ascii
        $engine5 = /(I)\'m going to start it/ wide ascii

        $start1 = /Starting upgrade\!/ wide ascii
        $start2 = /(I)\'m going to start the program/ wide ascii
        $start3 = /(i)s it ok\?/ wide ascii
        $start4 = /(C)lick to start the program/ wide ascii

        $upd1 = /(U)pdJob/ wide ascii
        $upd2 = /(U)pdTimer/ wide ascii

        $lookma1 = /(O)wning PCI bus/ wide
        $lookma2 = /(F)ormatting bios/ wide
        $lookma3 = /(P)lease insert a disk in drive A:/ wide
        $lookma4 = /(U)pdating CPU microcode/ wide
        $lookma5 = /(N)ot sure what's happening/ wide
        $lookma6 = /(L)ook ma, no thread id\! \\\\o\// wide        

    condition:
        (all of ($engine*) or all of ($start*) or all of ($upd*) or 4 of ($lookma*)) and not any of ($filter*)
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule RegSubDatCode : RegSubDat Family 
{
    meta:
        description = "RegSubDat code features"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
    
    strings:
        // decryption loop
        $ = { 80 34 3? 99 40 (3D FB 65 00 00 | 3B C6) 7? F? }
        // push then pop values
        $ = { 68 FF FF 7F 00 5? }
        $ = { 68 FF 7F 00 00 5? }
    
    condition:
        all of them
}

rule RegSubDatStrings : RegSubDat Family
{
    meta:
        description = "RegSubDat Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    strings:
        $avg1 = "Button"
        $avg2 = "Allow"
        $avg3 = "Identity Protection"
        $avg4 = "Allow for all"
        $avg5 = "AVG Firewall Asks For Confirmation"
        $mutex = "0x1A7B4C9F"
        
    condition:
       all of ($avg*) or $mutex
}

rule RegSubDat : Family
{
    meta:
        description = "RegSubDat"
        author = "Seth Hardy"
        last_modified = "2014-07-14"
        
    condition:
        RegSubDatCode or RegSubDatStrings
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule RooterCode : Rooter Family 
{
    meta:
        description = "Rooter code features"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
    
    strings:
        // xor 0x30 decryption
        $ = { 80 B0 ?? ?? ?? ?? 30 40 3D 00 50 00 00 7C F1 }
    
    condition:
        any of them
}

rule RooterStrings : Rooter Family
{
    meta:
        description = "Rooter Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    strings:
        $group1 = "seed\x00"
        $group2 = "prot\x00"
        $group3 = "ownin\x00"
        $group4 = "feed0\x00"
        $group5 = "nown\x00"

    condition:
       3 of ($group*)
}


rule Rooter : Family
{
    meta:
        description = "Rooter"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    condition:
        RooterCode or RooterStrings
}

rule RookieStrings : Rookie Family
{
    meta:
        description = "Rookie Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "RookIE/1.0"
        
    condition:
       any of them
}

rule RookieCode : Rookie Family 
{
    meta:
        description = "Rookie code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        // hidden AutoConfigURL
        $ = { C6 ?? ?? ?? 41 C6 ?? ?? ?? 75 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 43 C6 ?? ?? ?? 6F C6 ?? ?? ?? 6E C6 ?? ?? ?? 66 }
        // hidden ProxyEnable
        $ = { C6 ?? ?? ?? 50 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 78 C6 ?? ?? ?? 79 C6 ?? ?? ?? 45 C6 ?? ?? ?? 6E C6 ?? ?? ?? 61 }
        // xor on rand value?
        $ = { 8B 1D 10 A1 40 00 [18] FF D3 8A 16 32 D0 88 16 }

    condition:
        any of them
}

rule Rookie : Family
{
    meta:
        description = "Rookie"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        RookieCode or RookieStrings
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule SafeNetCode : SafeNet Family 
{
    meta:
        description = "SafeNet code features"
        author = "Seth Hardy"
        last_modified = "2014-07-16"
        
    strings:
        // add edi, 14h; cmp edi, 50D0F8h
        $ = { 83 C7 14 81 FF F8 D0 40 00 }
    condition:
        any of them
}

rule SafeNetStrings : SafeNet Family
{
    meta:
        description = "Strings used by SafeNet"
        author = "Seth Hardy"
        last_modified = "2014-07-16"
        
    strings:
        $ = "6dNfg8Upn5fBzGgj8licQHblQvLnUY19z5zcNKNFdsDhUzuI8otEsBODrzFCqCKr"
        $ = "/safe/record.php"
        $ = "_Rm.bat" wide ascii
        $ = "try\x0d\x0a\x09\x09\x09\x09  del %s" wide ascii
        $ = "Ext.org" wide ascii
        
    condition:
        any of them

}

rule SafeNet : Family
{
    meta:
        description = "SafeNet family"
        
    condition:
        SafeNetCode or SafeNetStrings
        
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Vinsula_Sayad_Binder : infostealer
{
    meta:
        Author      = "Vinsula, Inc"
        Date        = "2014/06/20"
        Description = "Sayad Infostealer Binder"
        Reference   = "http://vinsula.com/2014/07/20/sayad-flying-kitten-infostealer-malware/"

    strings: 
        $pdbstr = "\\Projects\\C#\\Sayad\\Source\\Binder\\obj\\Debug\\Binder.pdb" 
        $delphinativestr = "DelphiNative.dll" nocase
        $sqlite3str = "sqlite3.dll" nocase
        $winexecstr = "WinExec" 
        $sayadconfig = "base.dll" wide

    condition:
        all of them
}

rule Vinsula_Sayad_Client : infostealer
{
    meta:
        Author      = "Vinsula, Inc"
        Date        = "2014/06/20"
        Description = "Sayad Infostealer Client"
        Reference   = "http://vinsula.com/2014/07/20/sayad-flying-kitten-infostealer-malware/"

    strings: 
        $pdbstr = "\\Projects\\C#\\Sayad\\Source\\Client\\bin\\x86\\Debug\\Client.pdb" 
        $sayadconfig = "base.dll" wide
        $sqlite3str = "sqlite3.dll" nocase
        $debugstr01 = "Config loaded" wide
        $debugstr02 = "Config parsed" wide
        $debugstr03 = "storage uploader" wide
        $debugstr04 = "updater" wide
        $debugstr05 = "keylogger" wide
        $debugstr06 = "Screenshot" wide
        $debugstr07 = "sqlite found & start collectiong data" wide
        $debugstr08 = "Machine info collected" wide
        $debugstr09 = "browser ok" wide
        $debugstr10 = "messenger ok" wide
        $debugstr11 = "vpn ok" wide
        $debugstr12 = "ftp client ok" wide
        $debugstr13 = "ftp server ok" wide
        $debugstr14 = "rdp ok" wide
        $debugstr15 = "kerio ok" wide
        $debugstr16 = "skype ok" wide
        $debugstr17 = "serialize data ok" wide
        $debugstr18 = "Keylogged" wide

    condition:
        all of them
}/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule ScarhiknStrings : Scarhikn Family
{
    meta:
        description = "Scarhikn Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    strings:
        $ = "9887___skej3sd"
        $ = "haha123"
        
    condition:
       any of them
}



rule ScarhiknCode : Scarhikn Family 
{
    meta:
        description = "Scarhikn code features"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
    
    strings:
        // decryption
        $ = { 8B 06 8A 8B ?? ?? ?? ?? 30 0C 38 03 C7 55 43 E8 ?? ?? ?? ?? 3B D8 59 72 E7 }
        $ = { 8B 02 8A 8D ?? ?? ?? ?? 30 0C 30 03 C6 8B FB 83 C9 FF 33 C0 45 F2 AE F7 D1 49 3B E9 72 E2 }
    
    condition:
        any of them
}

rule Scarhikn : Family
{
    meta:
        description = "Scarhikn"
        author = "Seth Hardy"
        last_modified = "2014-06-25"
        
    condition:
        ScarhiknCode or ScarhiknStrings
}







/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Scieron
{
    meta:
        author = "Symantec Security Response"
        ref = "http://www.symantec.com/connect/tr/blogs/scarab-attackers-took-aim-select-russian-targets-2012"
        date = "22.01.15"

    strings:
        // .text:10002069 66 83 F8 2C                       cmp     ax, ','
        // .text:1000206D 74 0C                             jz      short loc_1000207B
        // .text:1000206F 66 83 F8 3B                       cmp     ax, ';'
        // .text:10002073 74 06                             jz      short loc_1000207B
        // .text:10002075 66 83 F8 7C                       cmp     ax, '|'
        // .text:10002079 75 05                             jnz     short loc_10002080
        $code1 = {66 83 F? 2C 74 0C 66 83 F? 3B 74 06 66 83 F? 7C 75 05}
        
        // .text:10001D83 83 F8 09                          cmp     eax, 9          ; switch 10 cases
        // .text:10001D86 0F 87 DB 00 00 00                 ja      loc_10001E67    ; jumptable 10001D8C default case
        // .text:10001D8C FF 24 85 55 1F 00+                jmp     ds:off_10001F55[eax*4] ; switch jump
        $code2 = {83 F? 09 0F 87 ?? 0? 00 00 FF 24}
        
        $str1  = "IP_PADDING_DATA" wide ascii
        $str2  = "PORT_NUM" wide ascii
        
    condition:
        all of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule skeleton_key_patcher
{
	meta:
		description = "Skeleton Key Patcher from Dell SecureWorks Report http://goo.gl/aAk3lN"
		author = "Dell SecureWorks Counter Threat Unit"
		reference = "http://goo.gl/aAk3lN"
		date = "2015/01/13"
		score = 70
	strings:
		$target_process = "lsass.exe" wide
		$dll1 = "cryptdll.dll"
		$dll2 = "samsrv.dll"

		$name = "HookDC.dll"

		$patched1 = "CDLocateCSystem"
		$patched2 = "SamIRetrievePrimaryCredentials"
		$patched3 = "SamIRetrieveMultiplePrimaryCredentials"
	condition:
		all of them
}

rule skeleton_key_injected_code
{
	meta:
		description = "Skeleton Key injected Code http://goo.gl/aAk3lN"
		author = "Dell SecureWorks Counter Threat Unit"
		reference = "http://goo.gl/aAk3lN"
		date = "2015/01/13"
		score = 70
	strings:
		$injected = { 33 C0 85 C9 0F 95 C0 48 8B 8C 24 40 01 00 00 48 33 CC E8 4D 02 00 00 48 81 C4 58 01 00 00 C3 }

		$patch_CDLocateCSystem = { 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B FA 8B F1 E8 ?? ?? ?? ?? 48 8B D7 8B CE 48 8B D8 FF 50 10 44 8B D8 85 C0 0F 88 A5 00 00 00 48 85 FF 0F 84 9C 00 00 00 83 FE 17 0F 85 93 00 00 00 48 8B 07 48 85 C0 0F 84 84 00 00 00 48 83 BB 48 01 00 00 00 75 73 48 89 83 48 01 00 00 33 D2 }

		$patch_SamIRetrievePrimaryCredential = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 49 8B F9 49 8B F0 48 8B DA 48 8B E9 48 85 D2 74 2A 48 8B 42 08 48 85 C0 74 21 66 83 3A 26 75 1B 66 83 38 4B 75 15 66 83 78 0E 73 75 0E 66 83 78 1E 4B 75 07 B8 A1 02 00 C0 EB 14 E8 ?? ?? ?? ?? 4C 8B CF 4C 8B C6 48 8B D3 48 8B CD FF 50 18 48 8B 5C 24 30 48 8B 6C 24 38 48 8B 74 24 40 48 83 C4 20 5F C3 }

		$patch_SamIRetrieveMultiplePrimaryCredential  = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 41 8B F9 49 8B D8 8B F2 8B E9 4D 85 C0 74 2B 49 8B 40 08 48 85 C0 74 22 66 41 83 38 26 75 1B 66 83 38 4B 75 15 66 83 78 0E 73 75 0E 66 83 78 1E 4B 75 07 B8 A1 02 00 C0 EB 12 E8 ?? ?? ?? ?? 44 8B CF 4C 8B C3 8B D6 8B CD FF 50 20 48 8B 5C 24 30 48 8B 6C 24 38 48 8B 74 24 40 48 83 C4 20 5F C3 }

	condition:
		any of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule RSharedStrings : Surtr Family {
	meta:
		description = "identifiers for remote and gmremote"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = "nView_DiskLoydb" wide
		$ = "nView_KeyLoydb" wide
		$ = "nView_skins" wide
		$ = "UsbLoydb" wide
		$ = "%sBurn%s" wide
		$ = "soul" wide

	condition:
		any of them

}

rule RemoteStrings : Remote Variant Surtr Family {
	meta:
		description = "indicators for remote.dll - surtr stage 2"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = "\x00Remote.dll\x00"
		$ = "\x00CGm_PlugBase::"
		$ = "\x00ServiceMain\x00_K_H_K_UH\x00"
		$ = "\x00_Remote_\x00" wide
	condition:
		any of them
}

rule GmRemoteStrings : GmRemote Variant Family Surtr {
	meta:
		description = "identifiers for gmremote: surtr stage 2"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
	
	strings:
		$ = "\x00x86_GmRemote.dll\x00"
		$ = "\x00D:\\Project\\GTProject\\Public\\List\\ListManager.cpp\x00"
		$ = "\x00GmShutPoint\x00"
		$ = "\x00GmRecvPoint\x00"
		$ = "\x00GmInitPoint\x00"
		$ = "\x00GmVerPoint\x00"
		$ = "\x00GmNumPoint\x00"
		$ = "_Gt_Remote_" wide
		$ = "%sBurn\\workdll.tmp" wide
	
	condition:
		any of them

}


rule GmRemote : Family Surtr Variant GmRemote {
	meta:
		description = "identifier for gmremote"
		author = "Katie Kleemola"
		last_updated = "07-25-2014"
	
	condition:
		RSharedStrings and GmRemoteStrings
}

rule Remote : Family Surtr Variant Remote {
	meta:
		description = "identifier for remote"
		author = "Katie Kleemola"
		last_updated = "07-25-2014"
	
	condition:
		RSharedStrings and RemoteStrings
}

rule SurtrStrings : Surtr Family {	
	meta: 
		author = "Katie Kleemola"
		description = "Strings for Surtr"
		last_updated = "2014-07-16"

	strings:
		$ = "\x00soul\x00"
		$ = "\x00InstallDll.dll\x00"
		$ = "\x00_One.dll\x00"
		$ = "_Fra.dll"
		$ = "CrtRunTime.log"
		$ = "Prod.t"
		$ = "Proe.t"
		$ = "Burn\\"
		$ = "LiveUpdata_Mem\\"

	condition:
		any of them

}

rule SurtrCode : Surtr Family {
	meta: 
		author = "Katie Kleemola"
		description = "Code features for Surtr Stage1"
		last_updated = "2014-07-16"
	
	strings:
		//decrypt config
		$ = { 8A ?? ?? 84 ?? ?? 74 ?? 3C 01 74 ?? 34 01 88 41 3B ?? 72 ?? }
		//if Burn folder name is not in strings
		$ = { C6 [3] 42 C6 [3] 75 C6 [3] 72 C6 [3] 6E C6 [3] 5C }
		//mov char in _Fire
		$ = { C6 [3] 5F C6 [3] 46 C6 [3] 69 C6 [3] 72 C6 [3] 65 C6 [3] 2E C6 [3] 64 }

	condition:
		any of them

}

rule Surtr : Family {
	meta:
		author = "Katie Kleemola"
		description = "Rule for Surtr Stage One"
		last_updated = "2014-07-16"

	condition:
		SurtrStrings or SurtrCode

}



/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule T5000Strings : T5000 Family
{
    meta:
        description = "T5000 Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-26"
        
    strings:
        $ = "_tmpR.vbs"
        $ = "_tmpg.vbs"
        $ = "Dtl.dat" wide ascii
        $ = "3C6FB3CA-69B1-454f-8B2F-BD157762810E"
        $ = "EED5CA6C-9958-4611-B7A7-1238F2E1B17E"
        $ = "8A8FF8AD-D1DE-4cef-B87C-82627677662E"
        $ = "43EE34A9-9063-4d2c-AACD-F5C62B849089"
        $ = "A8859547-C62D-4e8b-A82D-BE1479C684C9"
        $ = "A59CF429-D0DD-4207-88A1-04090680F714"
        $ = "utd_CE31" wide ascii
        $ = "f:\\Project\\T5000\\Src\\Target\\1 KjetDll.pdb"
        $ = "l:\\MyProject\\Vc 7.1\\T5000\\T5000Ver1.28\\Target\\4 CaptureDLL.pdb"
        $ = "f:\\Project\\T5000\\Src\\Target\\4 CaptureDLL.pdb"
        $ = "E:\\VS2010\\xPlat2\\Release\\InstRes32.pdb"
        
    condition:
       any of them
}

rule T5000 : Family
{
    meta:
        description = "T5000"
        author = "Seth Hardy"
        last_modified = "2014-06-26"
        
    condition:
        T5000Strings
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule VidgrabCode : Vidgrab Family 
{
    meta:
        description = "Vidgrab code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $divbyzero = { B8 02 00 00 00 48 48 BA 02 00 00 00 83 F2 02 F7 F0 }
        // add eax, ecx; xor byte ptr [eax], ??h; inc ecx
        $xorloop = { 03 C1 80 30 (66 | 58) 41 }
        $junk = { 8B 4? ?? 8B 4? ?? 03 45 08 52 5A }
        
    condition:
        all of them
}

rule VidgrabStrings : Vidgrab Family
{
    meta:
        description = "Vidgrab Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $ = "IDI_ICON5" wide ascii
        $ = "starter.exe"
        $ = "wmifw.exe"
        $ = "Software\\rar"
        $ = "tmp092.tmp"
        $ = "temp1.exe"
        
    condition:
       3 of them
}

rule Vidgrab : Family
{
    meta:
        description = "Vidgrab"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    condition:
        VidgrabCode or VidgrabStrings
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule WaterBug_wipbot_2013_core_PDF {
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 core PDF"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
	strings:
		$PDF = "%PDF-"
		$a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/ 
		$b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/
	condition:
		($PDF at 0) and #a > 150 and #b > 200
}

rule WaterBug_wipbot_2013_dll {
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot 2014 Down.dll component"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"		
	strings:
		$string1 = "/%s?rank=%s"
		$string2 = "ModuleStart\x00ModuleStop\x00start"
		$string3 = "1156fd22-3443-4344-c4ffff"
		//read file... error..
		$string4 = "read\x20file\x2E\x2E\x2E\x20error\x00\x00"
	condition:
		2 of them
}

rule WaterBug_wipbot_2013_core {
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot core + core; garbage appended data (PDF Exploit leftovers) + wipbot dropper; fake AdobeRd32 Error"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"			
	strings:
		$mz = "MZ"
		$code1 = { 89 47 0C C7 47 10 90 C2 04 00 C7 47 14 90 C2 10 00 C7 47 18 90 90 60 68 89 4F 1C C7 47 20 90 90 90 B8 89 4F 24 C7 47 28 90 FF D0 61 C7 47 2C 90 C2 04 00}
		$code2 = { 85 C0 75 25 8B 0B BF ?? ?? ?? ?? EB 17 69 D7 0D 66 19 00 8D BA 5F F3 6E 3C 89 FE C1 EE 10 89 F2 30 14 01 40 3B 43 04 72 E4}
		$code3 = {90 90 90 ?? B9 00 4D 5A 90 00 03 00 00 00 82 04} $code4 = {55 89 E5 5D C3 55 89 E5 83 EC 18 8B 45 08 85 C0}
	condition:
		$mz at 0 and (($code1 or $code2) or ($code3 and $code4))
}

rule WaterBug_turla_dropper {
	meta:
		description = "Symantec Waterbug Attack - Trojan Turla Dropper"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
	strings: 
		$a = {0F 31 14 31 20 31 3C 31 85 31 8C 31 A8 31 B1 31 D1 31 8B 32 91 32 B6 32 C4 32 6C 33 AC 33 10 34}
		$b = {48 41 4C 2E 64 6C 6C 00 6E 74 64 6C 6C 00 00 00 57 8B F9 8B 0D ?? ?? ?? ?? ?? C9 75 26 56 0F 20 C6 8B C6 25 FF FF FE FF 0F 22 C0 E8}
	condition: 
		all of them
}

rule WaterBug_fa_malware { 
	meta: 
		description = "Symantec Waterbug Attack - FA malware variant"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl"
	strings:
		$mz = "MZ"
		$string1 = "C:\\proj\\drivers\\fa _ 2009\\objfre\\i386\\atmarpd.pdb"
		$string2 = "d:\\proj\\cn\\fa64\\"
		$string3 = "sengoku_Win32.sys\x00"
		$string4 = "rk_ntsystem.c"
		$string5 = "\\uroboros\\"
		$string6 = "shell.{F21EDC09-85D3-4eb9-915F-1AFA2FF28153}"
	condition:
		($mz at 0) and (any of ($string*))
}


rule WaterBug_sav {
	meta: 
		description = "Symantec Waterbug Attack - SAV Malware"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://t.co/rF35OaAXrl" 	
	strings:
		$mz = "MZ"
		$code1a = { 8B 75 18 31 34 81 40 3B C2 72 F5 33 F6 39 7D 14 76 1B 8A 04 0E 88 04 0F 6A 0F 33 D2 8B C7 5B F7 F3 85 D2 75 01 }
		$code1b = { 8B 45 F8 40 89 45 F8 8B 45 10 C1 E8 02 39 45 F8 73 17 8B 45 F8 8B 4D F4 8B 04 81 33 45 20 8B 4D F8 8B 55 F4 89 04 8A EB D7 83 65 F8 00 83 65 EC 00 EB 0E 8B 45 F8 40 89 45 F8 8B 45 EC 40 89 45 EC 8B 45 EC	3B 45 10 73 27 8B 45 F4 03 45 F8 8B 4D F4 03 4D EC 8A 09 88 08 8B 45 F8 33 D2 6A 0F 59 F7 F1 85 D2 75 07 }
		$code1c = { 8A 04 0F 88 04 0E 6A 0F 33 D2 8B C6 5B F7 F3 85 D2 75 01 47 8B 45 14 46 47 3B F8 72 E3 EB 04 C6 04 08 00 48 3B C6 73 F7 33 C0 C1 EE 02 74 0B 8B 55 18 31 14 81 40 3B C6 72 F5 }
		$code2 =  { 29 5D 0C 8B D1 C1 EA 05 2B CA 8B 55 F4 2B C3 3D 00 00 00 01 89 0F 8B 4D 10 8D 94 91 00 03 00 00 73 17 8B 7D F8 8B 4D 0C 0F B6 3F C1 E1 08 0B CF C1 E0 08 FF 45 F8 89 4D 0C 8B 0A 8B F8 C1 EF 0B}
	condition:
		($mz at 0) and (($code1a or $code1b or $code1c) and $code2) 
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule WimmieShellcode : Wimmie Family 
{
    meta:
        description = "Wimmie code features"
        author = "Seth Hardy"
        last_modified = "2014-07-17"
        
    strings:
        // decryption loop
        $ = { 49 30 24 39 83 F9 00 77 F7 8D 3D 4D 10 40 00 B9 0C 03 00 00 }
        $xordecrypt = {B9 B4 1D 00 00 [8] 49 30 24 39 83 F9 00 }
        
    condition:
        any of them
}

rule WimmieStrings : Wimmie Family
{
    meta:
        description = "Strings used by Wimmie"
        author = "Seth Hardy"
        last_modified = "2014-07-17"
        
    strings:
        $ = "\x00ScriptMan"
        $ = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" wide ascii
        $ = "ProbeScriptFint" wide ascii
        $ = "ProbeScriptKids"
        
    condition:
        any of them

}

rule Wimmie : Family
{
    meta:
        description = "Wimmie family"
        author = "Seth Hardy"
        last_modified = "2014-07-17"
   
    condition:
        WimmieShellcode or WimmieStrings
        
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

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
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule WoolenGoldfish_Sample_1 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 60
		hash = "7ad0eb113bc575363a058f4bf21dbab8c8f7073a"
	strings:
		$s1 = "Cannot execute (%d)" fullword ascii
		$s16 = "SvcName" fullword ascii
	condition:
		all of them
}

rule WoolenGoldfish_Generic_1 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 90
		super_rule = 1
		hash0 = "5d334e0cb4ff58859e91f9e7f1c451ffdc7544c3"
		hash1 = "d5b2b30fe2d4759c199e3659d561a50f88a7fb2e"
		hash2 = "a42f1ad2360833baedd2d5f59354c4fc3820c475"
	strings:
		$x0 = "Users\\Wool3n.H4t\\"
		$x1 = "C-CPP\\CWoolger"
		$x2 = "NTSuser.exe" fullword wide

		$s1 = "107.6.181.116" fullword wide
		$s2 = "oShellLink.Hotkey = \"CTRL+SHIFT+F\"" fullword
		$s3 = "set WshShell = WScript.CreateObject(\"WScript.Shell\")" fullword
		$s4 = "oShellLink.IconLocation = \"notepad.exe, 0\"" fullword
		$s5 = "set oShellLink = WshShell.CreateShortcut(strSTUP & \"\\WinDefender.lnk\")" fullword
		$s6 = "wlg.dat" fullword
		$s7 = "woolger" fullword wide
		$s8 = "[Enter]" fullword
		$s9 = "[Control]" fullword
	condition:
		( 1 of ($x*) and 2 of ($s*) ) or
		( 6 of ($s*) )
}

rule WoolenGoldfish_Generic_2 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 90
		hash1 = "47b1c9caabe3ae681934a33cd6f3a1b311fd7f9f"
		hash2 = "62172eee1a4591bde2658175dd5b8652d5aead2a"
		hash3 = "7fef48e1303e40110798dfec929ad88f1ad4fbd8"
		hash4 = "c1edf6e3a271cf06030cc46cbd90074488c05564"
	strings:
		$s0 = "modules\\exploits\\littletools\\agent_wrapper\\release" ascii
	condition:
		all of them
}

rule WoolenGoldfish_Generic_3 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 90
		hash1 = "86222ef166474e53f1eb6d7e6701713834e6fee7"
		hash2 = "e8dbcde49c7f760165ebb0cb3452e4f1c24981f5"
	strings:
		$x1 = "... get header FATAL ERROR !!!  %d bytes read > header_size" fullword ascii
		$x2 = "index.php?c=%S&r=%x&u=1&t=%S" fullword wide
		$x3 = "connect_back_tcp_channel#do_connect:: Error resolving connect back hostname" fullword ascii

		$s0 = "kernel32.dll GetProcAddressLoadLibraryAws2_32.dll" fullword ascii
		$s1 = "Content-Type: multipart/form-data; boundary=%S" fullword wide
		$s2 = "Attempting to unlock uninitialized lock!" fullword ascii
		$s4 = "unable to load kernel32.dll" fullword ascii
		$s5 = "index.php?c=%S&r=%x" fullword wide
		$s6 = "%s len:%d " fullword ascii
		$s7 = "Encountered error sending syscall response to client" fullword ascii
		$s9 = "/info.dat" fullword ascii
		$s10 = "Error entering thread lock" fullword ascii
		$s11 = "Error exiting thread lock" fullword ascii
		$s12 = "connect_back_tcp_channel_init:: socket() failed" fullword ascii
	condition:
		( 1 of ($x*) ) or
		( 8 of ($s*) )
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule xRAT20
{
meta:
	author = "Rottweiler"
	date = "2015-08-20"
	description = "Identifies xRAT 2.0 samples"
	maltype = "Remote Access Trojan"
	hash0 = "cda610f9cba6b6242ebce9f31faf5d9c"
	hash1 = "60d7b0d2dfe937ac6478807aa7043525"
	hash2 = "d1b577fbfd25cc5b873b202cfe61b5b8"
	hash3 = "1820fa722906569e3f209d1dab3d1360"
	hash4 = "8993b85f5c138b0afacc3ff04a2d7871"
	hash5 = "0c231ed8a800b0f17f897241f1d5f4e3"
	hash5 = "0c231ed8a800b0f17f897241f1d5f4e3"
	hash1 = "60d7b0d2dfe937ac6478807aa7043525"
	hash8 = "2c198e3e0e299a51e5d955bb83c62a5e"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "GetDirectory: File not found" wide
	$string1 = "<>m__Finally8"
	$string2 = "Secure"
	$string3 = "ReverseProxyClient"
	$string4 = "DriveDisplayName"
	$string5 = "<IsError>k__BackingField"
	$string6 = "set_InstallPath"
	$string7 = "memcmp"
	$string8 = "urlHistory"
	$string9 = "set_AllowAutoRedirect"
	$string10 = "lpInitData"
	$string11 = "reader"
	$string12 = "<FromRawDataGlobal>d__f"
	$string13 = "mq.png" wide
	$string14 = "remove_KeyDown"
	$string15 = "ProtectedData"
	$string16 = "m_hotkeys"
	$string17 = "get_Hour"
	$string18 = "\\mozglue.dll" wide
condition:
	18 of them
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Xtreme
{
    meta:
        description = "Xtreme RAT"
	author = "botherder https://github.com/botherder"

    strings:
        $string1 = /(X)tremeKeylogger/ wide ascii
        $string2 = /(X)tremeRAT/ wide ascii
        $string3 = /(X)TREMEUPDATE/ wide ascii
        $string4 = /(S)TUBXTREMEINJECTED/ wide ascii

        $unit1 = /(U)nitConfigs/ wide ascii
        $unit2 = /(U)nitGetServer/ wide ascii
        $unit3 = /(U)nitKeylogger/ wide ascii
        $unit4 = /(U)nitCryptString/ wide ascii
        $unit5 = /(U)nitInstallServer/ wide ascii
        $unit6 = /(U)nitInjectServer/ wide ascii
        $unit7 = /(U)nitBinder/ wide ascii
        $unit8 = /(U)nitInjectProcess/ wide ascii

    condition:
        5 of them
}

rule xtreme_rat : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="23/02/2013"
		description="Xtreme RAT"
	
	strings:
		$signature1={58 00 54 00 52 00 45 00 4D 00 45} /*X.T.R.E.M.E*/
		
	condition:
		$signature1
}

rule XtremeRATCode : XtremeRAT Family 
{
    meta:
        description = "XtremeRAT code features"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
    
    strings:
        // call; fstp st
        $ = { E8 ?? ?? ?? ?? DD D8 }
        // hiding string
        $ = { C6 85 ?? ?? ?? ?? 4D C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 64 C6 85 ?? ?? ?? ?? 62 C6 85 ?? ?? ?? ?? 6D }
    
    condition:
        all of them
}

rule XtremeRATStrings : XtremeRAT Family
{
    meta:
        description = "XtremeRAT Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    strings:
        $ = "dqsaazere"
        $ = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32"
        
    condition:
       any of them
}

rule XtremeRAT : Family
{
    meta:
        description = "XtremeRAT"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    condition:
        XtremeRATCode or XtremeRATStrings
}

rule xtremrat : rat
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Xtrem RAT v3.5"
		date = "2012-07-12" 
		version = "1.0" 
		filetype = "memory"

	strings:
		$a = "XTREME" wide
		$b = "XTREMEBINDER" wide
		$c = "STARTSERVERBUFFER" wide
		$d = "SOFTWARE\\XtremeRAT" wide
		$e = "XTREMEUPDATE" wide
		$f = "XtremeKeylogger" wide
		$g = "myversion|3.5" wide
		$h = "xtreme rat" wide nocase
	condition:
		2 of them
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule YayihCode : Yayih Family 
{
    meta:
        description = "Yayih code features"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
    
    strings:
        //  encryption
        $ = { 80 04 08 7A 03 C1 8B 45 FC 80 34 08 19 03 C1 41 3B 0A 7C E9 }
    
    condition:
        any of them
}

rule YayihStrings : Yayih Family
{
    meta:
        description = "Yayih Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
        
    strings:
        $ = "/bbs/info.asp"
        $ = "\\msinfo.exe"
        $ = "%s\\%srcs.pdf"
        $ = "\\aumLib.ini"

    condition:
       any of them
}

rule Yayih : Family
{
    meta:
        description = "Yayih"
        author = "Seth Hardy"
        last_modified = "2014-07-11"
        
    condition:
        YayihCode or YayihStrings
}

