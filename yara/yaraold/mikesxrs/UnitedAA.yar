//more info at reversecodes.wordpress.com
rule DMALocker
{
    meta:
    Description = "Deteccion del ransomware DMA Locker desde la version 1.0 a la 4.0"
    Author = "SadFud"
    Date = "30/05/2016"
    
    strings:
    $uno = { 41 42 43 58 59 5a 31 31 }
	  $dos = { 21 44 4d 41 4c 4f 43 4b }
	  $tres = { 21 44 4d 41 4c 4f 43 4b 33 2e 30 }
	  $cuatro = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }
    
    condition:
    any of them
    
}
//More at reversecodes.wordpress.com
rule DMALocker4_0
{
    meta:
    Description = "Deteccion del ransomware DMA Locker version 4.0"
    Author = "SadFud"
    Date = "30/05/2016"
	Hash = "e3106005a0c026fc969b46c83ce9aeaee720df1bb17794768c6c9615f083d5d1"
    
    strings:
    $clave = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }
    
    condition:
    $clave 
    
}
rule Remcos_RAT
{
    meta:
    Description = "Deteccion del troyano Remcos"
    Author = "SadFud"
    Date = "08/08/2016"
	  Hash = "f467114dd637c817b4c982fad55fe019"
    
    strings:
    $a = { 52 45 4d 43 4f 53 }
	  $b = { 52 65 6d 63 6f 73 5f 4d 75 74 65 78 }
    
    condition:
    $a or $b 
    
}
rule Ripper_ATM
{
    meta:
    Description = "RIPPER ATM MALWARE"
    Author = "SadFud"
    Date = "02/09/2016"
    Hash = "cc85e8ca86c787a1c031e67242e23f4ef503840739f9cdc7e18a48e4a6773b38"
    references = "https://www.virustotal.com/es/file/cc85e8ca86c787a1c031e67242e23f4ef503840739f9cdc7e18a48e4a6773b38/analysis/"
    
    strings:
    $a = { 6b 65 72 6e 79 76 40 6a 61 62 62 69 6d 2e 63 6f 6d }
	  
    
    condition:
    $a 
    
}
rule Satana_Ransomware
{
    meta:
        Description = "Deteccion de ransomware Satana"
        Author = "SadFud"
        Date = "12/07/2016"
    
    strings:
        $satana = "!satana!" nocase

    condition:
        $satana
}
rule Malware_Gen_Vbs_Obfuscated
{
    meta:
    Description = "Deteccion de archivos visual basic script ofuscados"
    Author = "SadFud"
    Date = "28/05/2016"
    
    strings:
    $eg = { 45 78 65 63 75 74 65 47 6c 6f 62 61 6c } 
    $e = { 45 78 65 63 75 74 65 } 
    
    condition:
    $eg or $e
    
}/*
Yara Rule Set
Author: SECUINFRA Falcon Team
Date: 2022-06-23
Identifier: 0x03-yara_win-Bitter_T-APT-17
Reference: "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
*/

/* Rule Set —————————————————————– */

import "pe"
import "dotnet"

rule APT_Bitter_Almond_RAT {

meta:
description = "Detects Bitter (T-APT-17) Almond RAT (.NET)"
author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
tlp = "WHITE" reference = " https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
date = "2022-06-01" hash = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

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
}


/*
Yara Rule Set
Author: SECUINFRA Falcon Team
Date: 2022-06-23
Identifier: 0x03-yara_win-Bitter_T-APT-17
Reference: "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
*/

/* Rule Set —————————————————————– */

rule APT_Bitter_Maldoc_Verify {

meta:
description = "Detects Bitter (T-APT-17) shellcode in oleObject (CVE-2018-0798)"
author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
tlp = "WHITE"
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
}

/*
Yara Rule Set
Author: SECUINFRA Falcon Team
Date: 2022-06-23
Identifier: 0x03-yara_win-Bitter_T-APT-17
Reference: "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
*/

/* Rule Set —————————————————————– */
rule APT_Bitter_PDB_Paths {

meta:
description = "Detects Bitter (T-APT-17) PDB Paths"
author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
tlp = "WHITE"
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
}
/*
Yara Rule Set
Author: SECUINFRA Falcon Team
Date: 2022-06-23
Identifier: 0x03-yara_win-Bitter_T-APT-17
Reference: "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
*/

/* Rule Set —————————————————————– */

rule APT_Bitter_ZxxZ_Downloader {

meta:
description = "Detects Bitter (T-APT-17) ZxxZ Downloader"
author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
tlp = "WHITE"
reference = " https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
date = "2022-06-01"
hash0 = "91ddbe011f1129c186849cd4c84cf7848f20f74bf512362b3283d1ad93be3e42"
hash1 = "90fd32f8f7b494331ab1429712b1735c3d864c8c8a2461a5ab67b05023821787"
hash2 = "69b397400043ec7036e23c225d8d562fdcd3be887f0d076b93f6fcaae8f3dd61"
hash3 = "3fdf291e39e93305ebc9df19ba480ebd60845053b0b606a620bf482d0f09f4d3"
hash4 = "fa0ed2faa3da831976fee90860ac39d50484b20bee692ce7f0ec35a15670fa92"

strings:
// old ZxxZ samples / decrypted strings
$old0 = "MsMp" ascii
$old1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
$old2 = "&&user=" ascii
$old3 = "DN-S" ascii
$old4 = "RN_E" ascii

// new ZxxZ samples
$c2comm0 = "GET /" ascii
$c2comm1 = "profile" ascii
$c2comm2 = ".php?" ascii
$c2comm3 = "data=" ascii
$c2comm4 = "Update" ascii
$c2comm5 = "TTT" ascii

condition:
uint16(0) == 0x5a4d
and filesize > 39KB // Size on Disk/1.5
and filesize < 2MB // Size of Image*1.5

and (all of ($old*)) or (all of ($c2comm*))

}

rule Mirage_APT_Backdoor : APT Mirage Backdoor Rat MirageRat
{
    meta:
      author = "Silas Cutler (SCutler@SecureWorks.com)"
      version = "1.0"
      description = "Malware related to APT campaign"
      type = "APT Trojan / RAT / Backdoor"
      reference = "https://www.secureworks.com/research/the-mirage-campaign"

    strings:
      $a1 = "welcome to the desert of the real"
      $a2 = "Mirage"
      $b = "Encoding: gzip"
      $c = /\/[A-Za-z]*\?hl=en/
      
    condition: 
      (($a1 or $a2) or $b) and $c
}

rule skeleton_key_injected_code
{
	meta:
		author = "secureworks"
		reference = "https://www.secureworks.com/research/skeleton-key-malware-analysis"

	strings:
       $injected = { 33 C0 85 C9 0F 95 C0 48 8B 8C 24 40 01 00 00 48 33 CC E8 4D 02 00 
	   00 48 81 C4 58 01 00 00 C3 }
	   
	   $patch_CDLocateCSystem = { 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B FA 
	   8B F1 E8 ?? ?? ?? ?? 48 8B D7 8B CE 48 8B D8 FF 50 10 44 8B D8 85 C0 0F 88 A5 00 
	   00 00 48 85 FF 0F 84 9C 00 00 00 83 FE 17 0F 85 93 00 00 00 48 8B 07 48 85 C0 0F 
	   84 84 00 00 00 48 83 BB 48 01 00 00 00 75 73 48 89 83 48 01 00 00 33 D2 }
	   
	   $patch_SamIRetrievePrimaryCredential = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 
	   24 18 57 48 83 EC 20 49 8B F9 49 8B F0 48 8B DA 48 8B E9 48 85 D2 74 2A 48 8B 42 
	   08 48 85 C0 74 21 66 83 3A 26 75 1B 66 83 38 4B 75 15 66 83 78 0E 73 75 0E 66 83 
	   78 1E 4B 75 07 B8 A1 02 00 C0 EB 14 E8 ?? ?? ?? ?? 4C 8B CF 4C 8B C6 48 8B D3 48 
	   8B CD FF 50 18 48 8B 5C 24 30 48 8B 6C 24 38 48 8B 74 24 40 48 83 C4 20 5F C3 }
	   
	   $patch_SamIRetrieveMultiplePrimaryCredential  = { 48 89 5C 24 08 48 89 6C 24 10 
	   48 89 74 24 18 57 48 83 EC 20 41 8B F9 49 8B D8 8B F2 8B E9 4D 85 C0 74 2B 49 8B 
	   40 08 48 85 C0 74 22 66 41 83 38 26 75 1B 66 83 38 4B 75 15 66 83 78 0E 73 75 0E 
	   66 83 78 1E 4B 75 07 B8 A1 02 00 C0 EB 12 E8 ?? ?? ?? ?? 44 8B CF 4C 8B C3 8B D6 
	   8B CD FF 50 20 48 8B 5C 24 30 48 8B 6C 24 38 48 8B 74 24 40 48 83 C4 20 5F C3 }

	condition:
       any of them
}

rule skeleton_key_patcher
{
	meta:
		author = "secureworks"
		reference = "https://www.secureworks.com/research/skeleton-key-malware-analysis"

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
}rule njrat_08d
{
meta:
	author = "SenseCy"
	date = "23-12-2015"
	description = "Njrat v0.8d"
	reference = "https://blog.sensecy.com/2016/01/05/is-there-a-new-njrat-out-there/"
	sample_filetype = "exe"

strings:
	$string0 = "U0VFX01BU0tfTk9aT05FQ0hFQ0tT" wide
	$string1 = "netsh firewall delete allowedprogram" wide
	$string2 = "netsh firewall add allowedprogram" wide
	$string3 = "cmd.exe /k ping 0 & del" wide
    $string4 = "&explorer /root,\"%CD%" wide
	$string5 = "WScript.Shell" wide
	$string6 = "Microsoft.VisualBasic.CompilerServices"
	$string7 = "_CorExeMain"
	$string8 = { 6d 73 63 6f 72 65 65 2e 64 6c 6c }

condition:
	all of them
}rule ORXLocker
{
meta:
	author = "SenseCy"
	date = "30/08/15"
	description = "ORXLocker_yara_rule"
	reference = "https://blog.sensecy.com/2016/03/10/handling-a-ransomware-attack/"

strings:
	$string0 = {43 61 6e 27 74 20 63 6f 6d 70 6c 65 74 65 20 53 4f 43 4b 53 34 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 25 64 2e 25 64 2e 25 64 2e 25 64 3a 25 64 2e 20 28 25 64 29 2c 20 72 65 71 75 65 73 74 20 72 65 6a 65 63 74 65 64 20 62 65 63 61 75 73 65 20 74 68 65 20 63 6c 69 65 6e 74 20 70 72 6f 67 72 61 6d 20 61 6e 64 20 69 64 65 6e 74 64 20 72 65 70 6f 72 74 20 64 69 66 66 65 72 65 6e 74 20 75 73 65 72 2d 69 64 73 2e}
	$string1 = {43 61 6e 27 74 20 63 6f 6d 70 6c 65 74 65 20 53 4f 43 4b 53 35 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 25 30 32 78 25 30 32 78 3a 25 30 32 78 25 30 32 78 3a 25 30 32 78 25 30 32 78 3a 25 30 32 78 25 30 32 78 3a 25 30 32 78 25 30 32 78 3a 25 30 32 78 25 30 32 78 3a 25 30 32 78 25 30 32 78 3a 25 30 32 78 25 30 32 78 3a 25 64 2e 20 28 25 64 29}
	$string2 = {53 4f 43 4b 53 35 3a 20 73 65 72 76 65 72 20 72 65 73 6f 6c 76 69 6e 67 20 64 69 73 61 62 6c 65 64 20 66 6f 72 20 68 6f 73 74 6e 61 6d 65 73 20 6f 66 20 6c 65 6e 67 74 68 20 3e 20 32 35 35 20 5b 61 63 74 75 61 6c 20 6c 65 6e 3d 25 7a 75 5d}
	$string3 = {50 72 6f 78 79 20 43 4f 4e 4e 45 43 54 20 66 6f 6c 6c 6f 77 65 64 20 62 79 20 25 7a 64 20 62 79 74 65 73 20 6f 66 20 6f 70 61 71 75 65 20 64 61 74 61 2e 20 44 61 74 61 20 69 67 6e 6f 72 65 64 20 28 6b 6e 6f 77 6e 20 62 75 67 20 23 33 39 29}
	$string4 = {3c 61 20 68 72 65 66 3d 68 74 74 70 73 3a 2f 2f 72 6b 63 67 77 63 73 66 77 68 76 75 76 67 6c 69 2e 74 6f 72 32 77 65 62 2e 6f 72 67 3e 68 74 74 70 73 3a 2f 2f 72 6b 63 67 77 63 73 66 77 68 76 75 76 67 6c 69 2e 74 6f 72 32 77 65 62 2e 6f 72 67 3c 2f 61 3e 3c 62 72 3e}
	$string5 = {43 3a 5c 44 65 76 5c 46 69 6e 61 6c 5c 52 65 6c 65 61 73 65 5c 6d 61 69 6e 2e 70 64 62}
	$string6 = {2e 3f 41 56 3f 24 62 61 73 69 63 5f 6f 66 73 74 72 65 61 6d 40 44 55 3f 24 63 68 61 72 5f 74 72 61 69 74 73 40 44 40 73 74 64 40 40 40 73 74 64 40 40}
	$string7 = {2e 3f 41 56 3f 24 62 61 73 69 63 5f 69 6f 73 40 5f 57 55 3f 24 63 68 61 72 5f 74 72 61 69 74 73 40 5f 57 40 73 74 64 40 40 40 73 74 64 40 40}
	$string8 = "ttp://4rhfxsrzmzilheyj.onion/get.php?a=" wide
	$string9 = "\\Payment-Instructions.htm" wide

condition:
	all of them
}import "elf"

rule IDAnt_wanna : antidissemble antianalysis
{
	meta:
		author = "Tim 'diff' Strazzere <diff@sentinelone.com><strazz@gmail.com>"
		reference = "https://sentinelone.com/blogs/breaking-and-evading/"
		filetype = "elf"
		description = "Detect a misalligned program header which causes some analysis engines to fail"
		version = "1.0"
		date = "2015-12"
	condition:
		for any i in (0..elf.number_of_segments - 1) :(elf.segments[i].offset >= filesize) and elf.number_of_sections == 0 and elf.sh_entry_size == 0
}private rule _fat
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"

    //  0   belong      0xcafebabe
    //  >4  belong      1       Mach-O universal binary with 1 architecture
    //  >4  belong      >1
    //  >>4 belong      <20     Mach-O universal binary with %ld architectures
 
    strings:
        $fat = { CA FE BA BE }
 
    condition:
        $fat at 0 and uint32(4) < 0x14000000
}
 
private rule _macho
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"

    strings:
        $macho1 = { CE FA ED FE }   // Little Endian
        $macho2 = { CF FA ED FE }   // Little Endian 64
        $macho3 = { FE ED FA CE }   // Big Endian
        $macho4 = { FE ED FA CF }   // Big Endian 64
 
    condition:
        for any of ( $macho* ) : ( $ at 0 ) or _fat
}
 
rule lib_jb
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"

    strings:
        $import = "libguiinject.dylib"
 
    condition:
        _macho and $import
}
 
rule app_jb
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"

    strings:
        $import1 = "@executable_path/jailbreak" nocase
        $import2 = "@executable_path/patch" nocase
 
    condition:
        _macho and any of ( $import* )
}
 
rule ipa_jb
{
    meta:
        reference = "http://pastebin.com/2W0tyUAF"
        reference2 = "https://sentinelone.com/blogs/analysis-ios-guiinject-adware-library/"
        
    strings:
        $zip = "PK"
        $import1 = ".app/jailbreak" nocase
        $import2 = ".app/patch" nocase
 
    condition:
        $zip at 0 and any of ( $import* )
}/*

  Copyright
  =========
  Copyright (C) 2013 Trustwave Holdings, Inc.
 
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
 
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>

  ---------

  This YARA signature will attempt to detect instances of the newly discovered
  Apache iFrame injection module. Please take a minute to look at the references
  contained in the metadata section of the rule for further information.

  This signature attempts to identify the unique XTEA function used for config
  decryption. Additionally, it will attempt to identify the XTEA keys discovered
  in the samples already encountered by SpiderLabs.

*/
rule apacheInjectionXtea {
  meta:
    description = "Detection for new Apache injection module spotted in wild."
    in_the_wild = true
    reference1 = "http://blog.sucuri.net/2013/06/new-apache-module-injection.html"
    reference2 = "TBD"

  strings:
    $xteaFunction = { 8B 0F 8B 57 04 B8 F3 3A 62 CC 41 89 C0 41 89 C9 41 89 CA 41 C1 E8 0B 41 C1 E2 04 41 C1 E9 05 41 83 E0 03 45 31 D1 46 8B 04 86 41 01 C9 41 01 C0 05 47 86 C8 61 45 31 C8 44 29 C2 49 89 C0 41 83 E0 03 41 89 D1 41 89 D2 46 8B 04 86 41 C1 E9 05 41 C1 E2 04 45 31 D1 41 01 D1 41 01 C0 45 31 C8 44 29 C1 85 C0 75 A3 89 0F 89 57 04 C3 }
    $xteaKey1 = { 4A F5 5E 5E B9 8A E1 63 30 16 B6 15 23 51 66 03 }
    $xteaKey2 = { 68 2C 16 4A 30 A8 14 1F 1E AD 0D 24 E1 0E 10 01 }

  condition:
    $xteaFunction or any of ($xteaKey*)
}
/*

  Copyright
  =========
  Copyright (C) 2013 Trustwave Holdings, Inc.
 
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
 
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>

  ---------

  This YARA signature will attempt to detect instances of the newly discovered
  Apache iFrame injection module. Please take a minute to look at the references
  contained in the metadata section of the rule for further information.

  This signature attempts to identify the unique XTEA function used for config
  decryption. Additionally, it will attempt to identify the XTEA keys discovered
  in the samples already encountered by SpiderLabs.

*/
rule cherryPicker
{
    meta:
        author = "Trustwave SpiderLabs"
        date = "2015-11-17"
        description = "Used to detect Cherry Picker malware.  Blog: https://www.trustwave.com/Resources/SpiderLabs-Blog/Shining-the-Spotlight-on-Cherry-Picker-PoS-Malware/?page=1&year=0&month=0"
    strings:
        $string1 = "srch1mutex" nocase
        $string2 = "SYNC32TOOLBOX" nocase
        $string3 = "kb852310.dll"
        $config1 = "[config]" nocase
        $config2 = "timeout"
        $config3 = "r_cnt"
        $config4 = "f_passive"
        $config5 = "prlog"
    condition:
        any of ($string*) or all of ($config*)

}

rule cherryInstaller
{
    strings:
        $string1 = "(inject base: %08x)"
        $string2 = "injected ok"
        $string3 = "inject failed"
        $string4 = "-i name.dll - install path dll"
        $string5 = "-s name.dll procname|PID - inject dll into processes or PID"
        $fileinfect1 = "\\ServicePackFiles\\i386\\user32.dll"
        $fileinfect2 = "\\dllcache\\user32.dll"
        $fileinfect3 = "\\user32.tmp"

    condition:
        all of ($string*) or all of ($fileinfect*)
}rule Punkey
{
  meta:
    author = "Trustwave SpiderLabs"
    date = "2015-04-09"
    description = "Used to detect Punkey malware.  Blog: https://www.trustwave.com/Resources/SpiderLabs-Blog/New-POS-Malware-Emerges---Punkey/"
  strings:
    $pdb1 = "C:\\Documents and Settings\\Administrator\\Desktop\\Verios\\jusched\\jusched32.pdb" nocase
    $pdb2 = "C:\\Documents and Settings\\Administrator\\Desktop\\Verios\\jusched\\troi.pdb" nocase
    $pdb3 = "D:\\freelancer\\gale.kreeb\\jusched10-19\\jusched32.pdb" nocase
    $pdb4 = "D:\\freelancer\\gale.kreeb\\jusched10-19\\troi.pdb" nocase
    $pdb5 = "C:\\Users\\iptables\\Desktop\\x86\\jusched32.pdb" nocase
    $pdb6 = "C:\\Users\\iptables\\Desktop\\x86\\troi.pdb"
    $pdb7 = "C:\\Users\\iptables\\Desktop\\27 Octomber\\jusched10-27\\troi.pdb" nocase
    $pdb8 = "D:\\work\\visualstudio\\jusched\\dllx64.pdb" nocase
    $string0 = "explorer.exe" nocase
    $string1 = "jusched.exe" nocase
    $string2 = "dllx64.dll" nocase
    $string3 = "exportDataApi" nocase
    $memory1 = "troi.exe"
    $memory2 = "unkey="
    $memory3 = "key="
    $memory4 = "UPDATE"
    $memory5 = "RUN"
    $memory6 = "SCANNING"
    $memory7 = "86afc43868fea6abd40fbf6d5ed50905"
    $memory8 = "f4150d4a1ac5708c29e437749045a39a"

  condition:
    (any of ($pdb*)) or (all of ($str*)) or (all of ($mem*))
}
rule MauiRansomware
{
meta:
author= "Silas Cutler (Silas@Stairwell.com)"
description = "Detection for Maui Ransomware"
reference = "https://stairwell.com/wp-content/uploads/2022/07/Stairwell-Threat-Report-Maui-Ransomware.pdf"
version = "0.1"
strings:
$ = "Unable to read public key info." wide
$ = "it by <Godhead> using -maui option." wide
$ = "Incompatible public key version." wide
$ = "maui.key" wide
$ = "maui.evd" wide
$ = "Unable to encrypt private key" wide
$ = "Unable to create evidence file" wide
$ = "PROCESS_GOINGON[%d%% / %d%%]: %s" wide
$ = "demigod.key" wide
$ = "Usage: maui [-ptx] [PATH]" wide
$ = "-p dir: Set Log Directory (Default: Current Directory)" wide
$ = "-t n: Set Thread Count (Default: 1)" wide
$ = "-x: Self Melt (Default: No)" wide
// File header loading (x32-bit)
$ = { 44 24 24 44 49 56 45 ?? 44 24 28 01 00 00 00 ?? 44 24 2C 10 00 00 00 }
$ = { 44 4F 47 44 ?? ?? 04 01 00 00 00 }
condition:
3 of them or
(
uint32(filesize-8) == 0x00000001 and
uint32(filesize-12) == 0x5055424B
)
}
rule NK_GOLDBACKDOOR_generic_shellcode
{
meta:
author= "Silas Cutler (silas@Stairwell.com)"
description = "Generic detection for shellcode used to drop GOLDBACKDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
$ = { B9 8E 8A DD 8D 8B F0 E8 ?? ?? ?? ?? FF D0 }
$ = { B9 8E AB 6F 40 [1-10] 50 [1-10] E8 ?? ?? ?? ?? FF D0 }
condition:
all of them
}
rule NK_GOLDBACKDOOR_inital_shellcode
{
meta:
author= "Silas Cutler (silas@Stairwell.com)"
description = "Detection for initial shellcode loader used to deploy GOLDBACDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
//seg000:07600058 8D 85 70 FE FF FF lea eax, [ebp+var_190]
//seg000:0760005E C7 45 C4 25 6C 6F 63 mov dword ptr [ebp+var_3C],'col%'
//seg000:07600065 50 push eax
//...
//seg000:0760008F C7 45 D8 6F 6C 64 2E mov dword ptr [ebp+var_3C+14h], '.dlo'
//seg000:07600096 C7 45 DC 74 78 74 00 mov dword ptr [ebp+var_3C+18h], 'txt'
$ = { C7 45 C4 25 6C 6F 63 50 8D 45 C4 C7 45 C8 61 6C 61 70 8B F9 C7 45 CC 70 64 61 74 50 B9 BD 88 17 75 C7 45 D0 61 25 5C 6C 8B DA C7 45 D4 6F 67 5F 67 C7 45 D8 6F 6C 64 2E C7 45 DC 74 78 74 00 }
// Import loaders
$ = { 51 50 57 56 B9 E6 8E 85 35 E8 ?? ?? ?? ?? FF D0 }
$ = { 6A 40 68 00 10 00 00 52 6A 00 FF 75 E0 B9 E3 18 90 72 E8 ?? ?? ?? ?? FF D0}
condition:
all of them
}
rule NK_GOLDBACKDOOR_injected_shellcode
{
meta:
author= "Silas Cutler (silas@Stairwell.com)"
description = "Detection for injected shellcode that decodes GOLDBACKDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
$dec_routine = { 8A 19 57 8B FA 8B 51 01 83 C1 05 85 D2 74 0E 56 8B C1 8B F2 30 18 40 83 EE 01 75 F8 5E 57 }
$rtlfillmemory_load = {B9 4B 17 CD 5B 55 56 33 ED 55 6A 10 50 E8 86 00 00 00 FF D0}
$ = "StartModule"
$log_file_name = {C7 44 24 3C 25 6C 6F 63 50 8D 44 24 40 C7 44 24 44 61 6C 61 70 50 B9 BD 88 17 75 C7 44 24 4C 70 64 61 74 C7 44 24 50 61 25 5C 6C C7 44 24 54 6F 67 5F 67 C7 44 24 58 6F 6C 64 32 C7 44 24 5C 2E 74 78 74}
$ = { B9 8E 8A DD 8D 8B F0 E8 E9 FB FF FF FF D0 }
condition:
3 of them
}
rule NK_GOLDBACKDOOR_LNK
{
meta:
author= "Silas Cutler (silas@Stairwell.com)"
description = "Detection for LNK file used to deploy GOLDBACKDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
$ = "WINWORD.exe" wide nocase
$ = "$won11 =\"$temple=" wide
$ = "dirPath -Match 'System32' -or $dirPath -Match 'Program Files'" wide
condition:
2 of them and uint16(0) == 0x4c
}
rule NK_GOLDBACKDOOR_LNK_payload
{
meta:
author= "Silas Cutler (silas@Stairwell.com)"
description = "Detection for obfuscated Powershell contained in LNK file that deploys GOLDBACKDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
$ = "WriteByte($x0, $h-1, ($xmpw4[$h] -bxor $xmpw4[0]" ascii wide nocase
condition:
all of them
}
rule NK_GOLDBACKDOOR_Main
{
meta:
author= "Silas Cutler"
description = "Detection for Main component of GOLDBACKDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
$str1 = "could not exec bash command." wide
$str2 = "%userprofile%\\AppData" wide
$str3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.3112.113 Safari/537.36" wide
$str4 = "tickount: %d"
$str5 = "Service-0x" wide
$str6 = "Main Returned"
$b64_1 = "TwBuAGUARAByAHYAVQBwAGQAYQB0AGUAAAA="
$b64_2 = "aGFnZW50dHJheQ=="
$b64_3 = "YXBwbGljYXRpb24vdm5kLmdvb2dsZS1hcHBzLmZvbGRlcg=="
$pdb = "D:\\Development\\GOLD-BACKDOOR\\"
condition:
4 of them or ( $pdb and 1 of them )
}
rule NK_GOLDBACKDOOR_obf_payload
{
meta:
author= "Silas Cutler (silas@Stairwell.com)"
description = "Detection for encoded shellcode payload downloaded by LNK file that drops GOLDBACKDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
$init = { e6b3 6d0a 6502 1e67 0aee e7e6 e66b eac2 }
condition:
$init at 0
}

import "pe"
rule TTP_Mutation_StackPush_Windows_DLLs {
 meta:
   author = "Stairwell"
   description = "Searching for PE files with mutations of odd, rare, or interesting string equities. Here we look for strings from common PE strings, DLLs and functions in pseudo stack strings form, where the string pushed onto the stack 4 bytes at a time using PUSH 0x68, appearing in reverse four byte chunk order, where the PUSH which shows up as an ASCII letter h."
   reference = "https://stairwell.com/news/threat-research-detection-research-labeled-malware-corpus-yara-testing/"
 strings:
   $a0_kernel32dll = "h.dllhel32hkern" ascii nocase
   $a1_ws2_32dll = "hllh32.dhws2_" ascii nocase
   $a2_msvcrtdll = "hllhrt.dhmsvc" ascii nocase
   $a3_KernelBasedll = "hllhse.dhelBahKern" ascii nocase
   $a4_advapi32dll = "h.dllhpi32hadva" ascii nocase
   $a5_advapires32dll = "hdllhs32.hpirehadva" ascii nocase
   $a6_gdi32dll = "hlh2.dlhgdi3" ascii nocase
   $a7_gdiplusdll = "hdllhlus.hgdip" ascii nocase
   $a8_win32ksys = "hysh2k.shwin3" ascii nocase
   $a9_user32dll = "hllh32.dhuser" ascii nocase
   $a10_comctl32dll = "h.dllhtl32hcomc" ascii nocase
   $a11_commdlgdll = "hdllhdlg.hcomm" ascii nocase
   $a12_comdlg32dll = "h.dllhlg32hcomd" ascii nocase
   $a13_commctrldll = "h.dllhctrlhcomm" ascii nocase
   $a14_shelldll = "hlhl.dlhshel" ascii nocase
   $a15_shell32dll = "hdllhl32.hshel" ascii nocase
   $a16_shlwapidll = "hdllhapi.hshlw" ascii nocase
   $a17_netapi32dll = "h.dllhpi32hneta" ascii nocase
   $a18_shdocvwdll = "hdllhcvw.hshdo" ascii nocase
   $a19_mshtmldll = "hllhml.dhmsht" ascii nocase
   $a20_urlmondll = "hllhon.dhurlm" ascii nocase
   $a21_iphlpapidll = "h.dllhpapihiphl" ascii nocase
   $a22_httpapidll = "hdllhapi.hhttp" ascii nocase
   $a23_msvbvm60dll = "h.dllhvm60hmsvb" ascii nocase
   $a24_shfolderdll = "h.dllhlderhshfo" ascii nocase
   $a25_OLE32DLL = "hLh2.DLhOLE3" ascii nocase
   $a26_wininetdll = "hdllhnet.hwini" ascii nocase
   $a27_wsock32dll = "hdllhk32.hwsoc" ascii nocase
 condition:
   filesize < 15MB
   and uint16be(0) == 0x4d5a
   and 1 of them
}
/* 
This rule attempts to find passwords in memory for hotmail, yahoo, gmail, facebook, amazon, twitter.com, linkedin.com, ebay.com and perhaps others.

Use with volatility yarascan like this: "vol.py -f mymem.img --profile=myprofile yarascan --yara-file=browserpass.yar"
 */

rule browser_pass
{
    meta:
        author = "swood"
        description = "This module is intended for forensicators and pen-testers to find passwords in memory that can help their case/engagement." 
        //Use for good not evil!" 
        reference = "https://github.com/swoodsec/YARA-RULES/blob/master/browserpass.yar"

    strings:
        $1 = "Passwd="
        $2 = "passwd="
        $3 = "Password="
        $4 = "password="
        $5 = "Pwd="
        $6 = "pwd="
        $7 = "Pass="
        $8 = "pass="
        $9 = "session_password="
        $10 = "Session_Password="

    condition:
        any of them
}
import "pe"

rule Bannerjack
{
 	meta:
 		author = "Symantec Security Response"
 		date = "2015-07-01"
 		description = "Butterfly BannerJack hacktool"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"
 	strings:
 		$str_1 = "Usage: ./banner-jack [options]"
 		$str_2 = "-f: file.csv"
 		$str_3 = "-s: ip start"
 		$str_4 = "-R: timeout read (optional, default %d secs)"
 	condition:
 		all of them
}rule Cadelle_1
{
meta:
	author = "Symantec"
	reference = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
strings:
	$s1 = { 56 57 8B F8 8B F1 33 C0 3B F0 74 22 39 44 24 0C 74 18 0F B7 0F 66 3B C8 74 10 66 89 0A 42 42 47 47 4E FF 4C 24 0C 3B F0 75 E2 3B F0 75 07 4A 4A B8 7A 00 07 80 33 C9 5F 66 89 0A 5E C2 04 00}
	$s2 = "ntsvc32"
	$s3 = "ntbind32"
condition:
	$s1 and ($s2 or $s3)
}

rule Cadelle_2
{
meta:
	author = "Symantec"
	reference = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
strings:
	$s1  = "[EXECUTE]" wide ascii
	$s2  = "WebCamCapture" wide ascii
	$s3  = "</DAY>" wide ascii
	$s4  ="</DOCUMENT>" wide ascii
	$s5  = "<DOCUMENT>" wide ascii
	$s6  = "<DATETIME>" wide ascii
	$s7  = "Can't open file for reading :" wide ascii
	$s8  = "</DATETIME>" wide ascii
	$s9  = "</USERNAME>" wide ascii
	$s10 = "JpegFile :" wide ascii
	$s12 = "[SCROLL]" wide ascii
	$s13 = "<YEAR>" wide ascii
	$s14 = "CURRENT DATE" wide ascii
	$s15 = "</YEAR>" wide ascii
	$s16 = "</MONTH>" wide ascii
	$s17 = "<PRINTERNAME>" wide ascii
	$s18 = "</DRIVE>" wide ascii
	$s19 = "<DATATYPE>" wide ascii
	$s20 = "<MACADDRESS>" wide ascii
	$s21 = "FlashMemory" wide ascii
condition:
	12 of them
}

rule Cadelle_3
{
meta:
	author = "Symantec"
	reference = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
strings:
	$s1  = "SOFTWARE\\ntsvc32\\HDD" wide ascii
	$s2  = "SOFTWARE\\ntsvc32\\ROU" wide ascii
	$s3  = "SOFTWARE\\ntsvc32\\HST" wide ascii
	$s4  = "SOFTWARE\\ntsvc32\\FLS" wide ascii
	$s5  = "ntsvc32" wide ascii
	$s6  = ".Win$py." wide ascii
	$s7  = "C:\\users\\" wide ascii
	$s8  = "%system32%" wide ascii
	$s9  = "\\Local Settings\\Temp" wide ascii
	$s10 = "SVWATAUAVAW" wide ascii
	$s11 = "\\AppData\\Local" wide ascii
	$s12 = "\\AppData" wide ascii
condition:
	6 of them
}

rule Cadelle_4
{
meta:
	author = "Symantec"
	reference = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
strings:
	$s1 = "AppInit_DLLs" wide ascii
	$s2 = { 5C 00 62 00 61 00 63 00 6B 00 75 00 70 00 00 }
	$s3 = { 5C 00 75 00 70 00 64 00 61 00 74 00 65 00 00 }
	$s4 = "\\cmd.exe" wide ascii
condition:
	all of them
}rule comrat
{
	meta:
		author = "Symantec"
		malware = "COMRAT"		
        Reference="https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"

	strings:
		$mz = "MZ"
		$b = {C645????}
		$c = {C685??FEFFFF??}
		//$d = {FFA0??0?0000}
		$e = {89A8??00000068??00000056FFD78B}
		$f = {00004889????030000488B}
	
	condition:
		($mz at 0) and ((#c > 200 and #b > 200 ) /*or (#d > 40)*/ and (#e > 15 or #f > 30))
}rule Eventlog 
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01" 
		description = "Butterfly Eventlog hacktool"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$str_1= "wevtsvc.dll"
		$str_2= "Stealing %S.evtx handle ..."
		$str_3= "ElfChnk"
		$str_4= "-Dr Dump all logs from a channel or .evtx file (raw"

	condition: 
		all of them 
}rule fa
{
	meta:
 		author = "Symantec"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"

 	strings:
 		$mz = "MZ"
 		$string1 = "C:\\proj\\drivers\\fa _ 2009\\objfre\\i386\\atmarpd.pdb"

		$string2 = "d:\\proj\\cn\\fa64\\"
		$string3 = "sengoku _ Win32.sys\x00"
		$string4 = "rk _ ntsystem.c"
		$string5 = "\\uroboros\\"
		$string6 = "shell.{F21EDC09-85D3-4eb9-915F-1AFA2FF28153}"

	condition:
 		($mz at 0) and (any of ($string*))
}rule Hacktool 
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01" 
		description = "Butterfly hacktool"
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$str_1 = "\\\\.\\pipe\\winsession" wide 
		$str_2 = "WsiSvc" wide 
		$str_3 = "ConnectNamedPipe"
		$str_4 = "CreateNamedPipeW" 
		$str_5 = "CreateProcessAsUserW"
        
	condition: 
		all of them 
}private rule isPE
{
	meta:
		Author = "Symantec"
		Reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/Dragonfly_Threat_Against_Western_Energy_Suppliers.pdf"

 	condition:
 		uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x00004550
}rule jiripbot_ascii_str_decrypt 
{ 
	meta: 
		author ="Symantec Security Response"
		date ="2015-07-01" 
		description ="Butterfly Jiripbot hacktool" 
		reference ="https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"
	strings: 
		$decrypt_func = {85 FF 75 03 33 C0 C3 8B C7 8D 50 01 8A 08 40 84 C9 75 F9 2B C2 53 8B D8 80 7C 3B FF ?? 75 3E 83 3D ?? ?? ?? ?? 00 56 BE ?? ?? ?? ?? 75 11 56 FF 15 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 56 FF 15 ?? ?? ?? ?? 33 C0 85 DB 74 09 80 34 38 ?? 40 3B C3 72 F7 56 FF 15 ?? ?? ?? ?? 5E 8B C7 5B C3} 
	condition: 
		$decrypt_func 
}rule jiripbot_unicode_str_decrypt 
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01"
		description = "Butterfly Jiripbot Unicode hacktool"
        reference ="https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$decrypt = {85 ?? 75 03 33 C0 C3 8B ?? 8D 50 02 66 8B 08 83 C0 02 66 85 C9 75 F5 2B C2 D1 F8 57 8B F8 B8 ?? ?? ?? ?? 66 39 44 7E FE 75 43 83 3D ?? ?? ?? ?? 00 53 BB ?? ?? ?? ?? 75 11 53 FF 15 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 53 FF 15 ?? ?? ?? ?? 33 C0 85 FF 74 0E B9 ?? 00 00 00 66 31 0C 46 40 3B C7 72 F2 53 FF 15 ?? ?? ?? ?? 5B 8B C6 5F C3 } 
	condition: 
		$decrypt 
}
rule Trojan_Karagany
{
	meta:
		alias = "Dreamloader"
		Author = "Symantec"
		Reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/Dragonfly_Threat_Against_Western_Energy_Suppliers.pdf"

	strings:
		$s1 = "neosphere" wide ascii
		$s2 = "10000000000051200" wide ascii
		$v1 = "&fichier" wide ascii
		$v2 = "&identifiant" wide ascii
		$c1 = "xmonstart" wide ascii
		$c2 = "xmonstop" wide ascii
		$c3 = "xgetfile" wide ascii
		$c4 = "downadminexec" wide ascii
		$c5 = "xdiex" wide ascii
		$c6 = "xrebootx" wide ascii

	condition:
		isPE and (($s1 and $s2) or ($v1 and $v2) or (any of ($c*)))
}rule Kwampirs
{
 meta:
 copyright = "Symantec"
 reference = "https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia"
 family = "Kwampirs"
 description = "Kwampirs dropper and main payload components"
 strings:
$pubkey =
 {
 06 02 00 00 00 A4 00 00 52 53 41 31 00 08 00 00
 01 00 01 00 CD 74 15 BC 47 7E 0A 5E E4 35 22 A5
 97 0C 65 BE E0 33 22 F2 94 9D F5 40 97 3C 53 F9
 E4 7E DD 67 CF 5F 0A 5E F4 AD C9 CF 27 D3 E6 31
 48 B8 00 32 1D BE 87 10 89 DA 8B 2F 21 B4 5D 0A
 CD 43 D7 B4 75 C9 19 FE CC 88 4A 7B E9 1D 8C 11
 56 A6 A7 21 D8 C6 82 94 C1 66 11 08 E6 99 2C 33
 02 E2 3A 50 EA 58 D2 A7 36 EE 5A D6 8F 5D 5D D2
 9E 04 24 4A CE 4C B6 91 C0 7A C9 5C E7 5F 51 28
 4C 72 E1 60 AB 76 73 30 66 18 BE EC F3 99 5E 4B
 4F 59 F5 56 AD 65 75 2B 8F 14 0C 0D 27 97 12 71
 6B 49 08 84 61 1D 03 BA A5 42 92 F9 13 33 57 D9
 59 B3 E4 05 F9 12 23 08 B3 50 9A DA 6E 79 02 36
 EE CE 6D F3 7F 8B C9 BE 6A 7E BE 8F 85 B8 AA 82
 C6 1E 14 C6 1A 28 29 59 C2 22 71 44 52 05 E5 E6
 FE 58 80 6E D4 95 2D 57 CB 99 34 61 E9 E9 B3 3D
 90 DC 6C 26 5D 70 B4 78 F9 5E C9 7D 59 10 61 DF
 F7 E4 0C B3
 }
 
 $network_xor_key =
 {
 B7 E9 F9 2D F8 3E 18 57 B9 18 2B 1F 5F D9 A5 38
 C8 E7 67 E9 C6 62 9C 50 4E 8D 00 A6 59 F8 72 E0
 91 42 FF 18 A6 D1 81 F2 2B C8 29 EB B9 87 6F 58
 C2 C9 8E 75 3F 71 ED 07 D0 AC CE 28 A1 E7 B5 68
 CD CF F1 D8 2B 26 5C 31 1E BC 52 7C 23 6C 3E 6B
 8A 24 61 0A 17 6C E2 BB 1D 11 3B 79 E0 29 75 02
 D9 25 31 5F 95 E7 28 28 26 2B 31 EC 4D B3 49 D9
 62 F0 3E D4 89 E4 CC F8 02 41 CC 25 15 6E 63 1B
 10 3B 60 32 1C 0D 5B FA 52 DA 39 DF D1 42 1E 3E
 BD BC 17 A5 96 D9 43 73 3C 09 7F D2 C6 D4 29 83
 3E 44 44 6C 97 85 9E 7B F0 EE 32 C3 11 41 A3 6B
 A9 27 F4 A3 FB 2B 27 2B B6 A6 AF 6B 39 63 2D 91
 75 AE 83 2E 1E F8 5F B5 65 ED B3 40 EA 2A 36 2C
 A6 CF 8E 4A 4A 3E 10 6C 9D 28 49 66 35 83 30 E7
 45 0E 05 ED 69 8D CF C5 40 50 B1 AA 13 74 33 0F
 DF 41 82 3B 1A 79 DC 3B 9D C3 BD EA B1 3E 04 33
 }

$decrypt_string =
 {
 85 DB 75 09 85 F6 74 05 89 1E B0 01 C3 85 FF 74
 4F F6 C3 01 75 4A 85 F6 74 46 8B C3 D1 E8 33 C9
 40 BA 02 00 00 00 F7 E2 0F 90 C1 F7 D9 0B C8 51
 E8 12 28 00 00 89 06 8B C8 83 C4 04 33 C0 85 DB
 74 16 8B D0 83 E2 0F 8A 92 1C 33 02 10 32 14 38
 40 88 11 41 3B C3 72 EA 66 C7 01 00 00 B0 01 C3
 32 C0 C3
 }

 $init_strings =
 {
 55 8B EC 83 EC 10 33 C9 B8 0D 00 00 00 BA 02 00
 00 00 F7 E2 0F 90 C1 53 56 57 F7 D9 0B C8 51 E8
 B3 27 00 00 BF 05 00 00 00 8D 77 FE BB 4A 35 02
 10 2B DE 89 5D F4 BA 48 35 02 10 4A BB 4C 35 02
 10 83 C4 04 2B DF A3 C8 FC 03 10 C7 45 FC 00 00
 00 00 8D 4F FC 89 55 F8 89 5D F0 EB 06
 }

 condition:
 2 of them
}
rule Multipurpose 
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01" 
		description = "Butterfly Multipurpose hacktool" 
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"
	strings: 
		$str_1 = "dump %d|%d|%d|%d|%d|%d|%s|%d"
		$str_2 = "kerberos%d.dll"
		$str_3 = "\\\\.\\pipe\\lsassp" 
		$str_4 = "pth <PID:USER:DOMAIN:NTLM>: change" 
	condition: 
		all of them 
}rule Proxy
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01"
		description = "Butterfly proxy hacktool" 
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$str_1 = "-u user : proxy username" 
		$str_2 = "--pleh : displays help" 
		$str_3 = "-x ip/host : proxy ip or host" 
		$str_4 = "-m : bypass mutex check"
        
	condition: 
		all of them 
}rule remsec_encrypted_api
{
meta:
copyright = "Symantec"
strings:
$open_process =
/*
"OpenProcess
\
x00" in encrypted form
*/
{ 91 9A 8F B0 9C 90 8D AF 8C 8C 9A FF }
condition:
all of them
}rule remsec_executable_blob_32
{
meta:
copyright = "Symantec"
strings:
$code =
/*
31 06                       l0: xor     [esi], eax
83 C6 04                        add     esi, 4
D1 E8                           shr     eax, 1
73 05              
jnb     short l1
35 01 00 00 D0                  xor     eax, 0D0000001h
E2 F0                       l1: loop    l0
*/
{
31 06
83 C6 04
D1 E8
73 05
35 01 00 00 D0
E2 F0
}
condition:
all of them
}rule remsec_executable_blob_64
{
meta:
copyright = "Symantec"
strings:
$code =
/*
31 06                       l0: xor   
[rsi], eax
48 83 C6 04                     add     rsi, 4
D1 E8                           shr     eax, 1
73 05                           jnb     short l1
35 01 00 00 D0                  xor     eax, 0D00000
01h
E2 EF                       l1: loop    l0
*/
{
31 06
48 83 C6 04
D1 E8
73 05
35 01 00 00 D0
E2 EF
}
condition:
all of them
}rule 
remsec_executable_blob_parser
{
meta:
copyright = "Symantec"
strings:
$code =
/*
0F 82 ?? ?? 00 00               jb      l_0
80 7? 04 02                     cmp     byte ptr [r0+4], 2
0F 
85 ?? ?? 00 00               jnz     l_0
81 3? 02 AA 02 C1               cmp     dword ptr [r0], 
0C102AA02h
0F 85 ?? ?? 00 00               jnz     l_0
8B ?? 06                        mov     r1, [r0+6]
*/
{
( 0F 82 ?? ?? 00 00 | 72 ?? )
( 80 | 41 80 ) ( 7? | 7C 24 ) 04 02
( 0F 85 ?? ?? 00 00 | 75 ?? )
( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) 02 AA 02 C1
( 0F 85 ?? ?? 00 00 | 75 ?? )
( 8B | 41 
8B | 44 8B | 45 8B ) ( 4? | 5? | 6? | 7? | ?4 24 | 
?C 24 ) 06
}
condition:
all of them
}rule remsec_packer_A
{
meta:
copyright = "Symantec"
strings:
$code =
/*
69 ?? AB 00 00 00               imul    r0, 0ABh
81 C? CD 2B 00 00               add     r0, 2BCDh
F7 E?                           mul     r0
C1 E? 0D                        shr     r1, 0Dh
69 ?? 85 CF 00 00               imul    r1, 0CF85h
2B                              sub     r0, r1
*/
{
69 ( C? | D? | E? | F? ) AB 00 00 00
( 81 | 41 81 ) C? CD 2B 00 00
( F7 | 41 
F7 ) E?
( C1 | 41 C1 ) E? 0D
( 69 | 45 69 ) ( C? | D? | E? | F? ) 85 CF 00 00
( 29 | 41 29 | 44 29 | 45 29 | 2B | 41 2B | 44 2B | 45 2B )
}
condition:
all of them
}rule remsec_packer_B
{
meta:
copyright = "Symantec"
strings:
$code =
/*
48 8B 05 C4 2D 01 00            mov     rax, cs:LoadLibraryA
48 89 44 24 48                  mov     qword ptr 
[rsp+1B8h+descriptor+18h], rax
48 8B 05 A
0 2D 01 00            mov     rax, cs:GetProcAddress
48 8D 4C 24 30                  lea     rcx, 
[rsp+1B8h+descriptor]
48 89 44 2
4 50                  mov     qword ptr 
[rsp+1B8h+descriptor+20h], rax
48 8D 84 24 80 00 00 00         lea     rax, 
[rsp+1B8h+var_138]
C6 44 24 30 00                  mov     [rsp+1B8h+descriptor], 
0
48 89 44 24 60      
mov     qword ptr 
[rsp+1B8h+descriptor+30h], rax
48 8D 84 24 80 00 00 00         lea     rax, 
[rsp+1B8h+var_138]
C7 44 24 34 03 00 00 00         mov     dword ptr 
[rsp+1B8h+descriptor+4], 3
2B F8             
sub     edi, eax
48 89 5C 24 38                  mov     qword ptr 
[rsp+1B8h+descriptor+8], rbx
44 89 6C 24 40                  mov     dword ptr 
[rsp+1B8h+descriptor+10h], r13d
83 C7 08                    
add     edi, 8
89 7C 24 68                     mov     dword ptr 
[rsp+1B8h+descriptor+38h], edi
FF D5                           call    rbp
05 00 00 00 3A                  add     eax, 3A000000h
*/
{
48 8B 05 ?? ?? ?? ??
48 89 44 24 ??
48 8B 05 ?? ?? ?? ??
48 8D 4C 24 ??
48 89 44 24 ??
48 8D ( 45 ?? | 84 24 ?? ?? 00 00 )
( 44 88 6? 24 ?? | C6 44 24 ?? 00 )
48 89 44 24 ??
48 8D ( 45 ?? | 84 24 ?? ?? 00 00 )
C7 44 24 ?? 0? 00 00 00
2B ?8
48 89 ?C 24 ??
44 89 6? 24 ??
83 C? 08
89 ?C 24 ??
( FF | 41 FF ) D?
( 05 | 8D 88 ) 00 00 00 3A
}
condition:
all of them
}rule sav_dropper
{
	meta:
 		author = "Symantec"
 		malware = "SAV dropper"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
 	
    strings:
 		$mz = "MZ"
 		$a = /[a-z]{,10} _ x64.sys\x00hMZ\x00/
 	
    condition:
 		($mz at 0) and uint32(0x400) == 0x000000c3 and pe.number_of_sections == 6 and $a
}rule sav{
	meta:
 		author = "Symantec"
 		malware = "SAV"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers"

	strings:
		$mz = "MZ"
/*
8B 75 18 mov esi, [ebp+arg _ 10]
31 34 81 xor [ecx+eax*4], esi
40 inc eax
3B C2 cmp eax, edx
72 F5 jb short loc _ 9F342
33 F6 xor esi, esi
39 7D 14 cmp [ebp+arg _ C], edi
76 1B jbe short loc _ 9F36F
8A 04 0E mov al, [esi+ecx]
88 04 0F mov [edi+ecx], al
6A 0F push 0Fh
33 D2 xor edx, edx
8B C7 mov eax, edi
5B pop ebx
F7 F3 div ebx
85 D2 test edx, edx
75 01 jnz short loc _ 9F368
*/
	$code1a = { 8B 75 18 31 34 81 40 3B C2 72 F5 33 F6 39 7D 14 76 1B 8A 04 0E 88 04 0F 6A 0F 33 D2 8B C7 5B F7 F3 85 D2 75 01 }

/*
8B 45 F8 mov eax, [ebp+var _ 8]
40 inc eax
89 45 F8 mov [ebp+var _ 8], eax
8B 45 10 mov eax, [ebp+arg _ 8]
C1 E8 02 shr eax, 2
39 45 F8 cmp [ebp+var _ 8], eax
73 17 jnb short loc _ 4013ED
8B 45 F8 mov eax, [ebp+var _ 8]
8B 4D F4 mov ecx, [ebp+var _ C]
8B 04 81 mov eax, [ecx+eax*4]
33 45 20 xor eax, [ebp+arg _ 18]
8B 4D F8 mov ecx, [ebp+var _ 8]
8B 55 F4 mov edx, [ebp+var _ C]
89 04 8A mov [edx+ecx*4], eax
EB D7 jmp short loc _ 4013C4
83 65 F8 00 and [ebp+var _ 8], 0
83 65 EC 00 and [ebp+var _ 14], 0
EB 0E jmp short loc _ 401405
8B 45 F8 mov eax, [ebp+var _ 8]
40 inc eax
89 45 F8 mov [ebp+var _ 8], eax
8B 45 EC mov eax, [ebp+var _ 14]
40 inc eax
89 45 EC mov [ebp+var _ 14], eax
8B 45 EC mov eax, [ebp+var _ 14]
3B 45 10 cmp eax, [ebp+arg _ 8]
73 27 jnb short loc _ 401434
8B 45 F4 mov eax, [ebp+var _ C]
03 45 F8 add eax, [ebp+var _ 8]
8B 4D F4 mov ecx, [ebp+var _ C]
03 4D EC add ecx, [ebp+var _ 14]
8A 09 mov cl, [ecx]
88 08 mov [eax], cl
8B 45 F8 mov eax, [ebp+var _ 8]
33 D2 xor edx, edx
6A 0F push 0Fh
59 pop ecx
F7 F1 div ecx
85 D2 test edx, edx
75 07 jnz short loc _ 401432
*/

	$code1b = { 8B 45 F8 40 89 45 F8 8B 45 10 C1 E8 02 39 45 F8 73 17 8B 45 F8 8B 4D F4 8B 04 81 33 45 20 8B 4D F8 8B 55 F4 89 04 8A EB D7 83 65 F8 00 83 65 EC 00 EB 0E 8B 45 F8 40 89 45 F8 8B 45 EC 40 89 45 EC 8B 45 EC 3B 45 10 73 27 8B 45 F4 03 45 F8 8B 4D F4 03 4D EC 8A 09 88 08 8B 45 F8 33 D2 6A 0F 59 F7 F1 85 D2 75 07 }

/*
8A 04 0F mov al, [edi+ecx]
88 04 0E mov [esi+ecx], al
6A 0F push 0Fh
33 D2 xor edx, edx
8B C6 mov eax, esi
5B pop ebx
F7 F3 div ebx
85 D2 test edx, edx
75 01 jnz short loc _ B12FC
47 inc edi
8B 45 14 mov eax, [ebp+arg _ C]
46 inc esi
47 inc edi
3B F8 cmp edi, eax
72 E3 jb short loc _ B12E8
EB 04 jmp short loc _ B130B
C6 04 08 00 mov byte ptr [eax+ecx], 0
48 dec eax
3B C6 cmp eax, esi
73 F7 jnb short loc _ B1307
33 C0 xor eax, eax
C1 EE 02 shr esi, 2
74 0B jz short loc _ B1322
8B 55 18 mov edx, [ebp+arg _ 10]
31 14 81 xor [ecx+eax*4], edx
40 inc eax
3B C6 cmp eax, esi
72 F5 jb short loc _ B1317
*/

		$code1c = { 8A 04 0F 88 04 0E 6A 0F 33 D2 8B C6 5B F7 F3 85 D2 75 01 47 8B 45 14 46 47 3B F8 72 E3 EB 04 C6 04 08 00 48 3B C6 73 F7 33 C0 C1 EE 02 74 0B 8B 55 18 31 14 81 40 3B C6 72 F5}

/*
29 5D 0C sub [ebp+arg _ 4], ebx
8B D1 mov edx, ecx
C1 EA 05 shr edx, 5
2B CA sub ecx, edx
8B 55 F4 mov edx, [ebp+var _ C]
2B C3 sub eax, ebx
3D 00 00 00 01 cmp eax, 1000000h
89 0F mov [edi], ecx
8B 4D 10 mov ecx, [ebp+arg _ 8]
8D 94 91 00 03 00 00 lea edx, [ecx+edx*4+300h]
73 17 jnb short loc _ 9FC44
8B 7D F8 mov edi, [ebp+var _ 8]
8B 4D 0C mov ecx, [ebp+arg _ 4]
0F B6 3F movzx edi, byte ptr [edi]
C1 E1 08 shl ecx, 8
0B CF or ecx, edi
C1 E0 08 shl eax, 8
FF 45 F8 inc [ebp+var _ 8]
89 4D 0C mov [ebp+arg _ 4], ecx
8B 0A mov ecx, [edx]
8B F8 mov edi, eax
C1 EF 0B shr edi, 0Bh
*/

		$code2 = { 29 5D 0C 8B D1 C1 EA 05 2B CA 8B 55 F4 2B C3 3D 00 00 00 01 89 0F 8B 4D 10 8D 94 91 00 03 00 00 73 17 8B 7D F8 8B 4D 0C 0F B6 3F C1 E1 08 0B CF C1 E0 08 FF 45 F8 89 4D 0C 8B 0A 8B F8 C1 EF 0B}

	condition:
		($mz at 0) and (($code1a or $code1b or $code1c) and $code2)
}rule Securetunnel 
	{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01"
		description = "Butterfly Securetunnel hacktool"
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$str_1 = "KRB5CCNAME" 
		$str_2 = "SSH _ AUTH _ SOCK" 
		$str_3 = "f:l:u:cehR" 
		$str_4 = ".o+=*BOX@%&#/^SE"

	condition: 
		all of them 
}rule turla_dll
{
	
    meta:
 		Malware = "Trojan.Turla DLL"
 		author = "Symantec"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
        
	strings:
		$a = /([A-Za-z0-9]{2,10} _ ){,2}Win32\.dll\x00/

	condition:
		pe.exports("ee") and $a
}
rule turla_dropper
{
	meta:
 		Malware = "Trojan.Turla dropper"
 		author = "Symantec"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
 	
	strings:
		$a = {0F 31 14 31 20 31 3C 31 85 31 8C 31 A8 31 B1 31 D1 31 8B 32 91 32 B6 32 C4 32 6C 33 AC 33 10 34}
		$b = {48 41 4C 2E 64 6C 6C 00 6E 74 64 6C 6C 2E 64 6C 6C 00 00 00 57 8B F9 8B 0D ?? ?? ?? ?? ?? C9 75 26 56 0F 20 C6 8B C6 25 FF FF FE FF 0F 22 C0 E8}
        
	condition:
		all of them
}rule wipbot_2013_core_PDF
{
	meta:
		author = "Symantec"
		description = "Trojan.Wipbot 2014 core PDF"
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
 	strings:
 		$PDF = "%PDF-"
 		$a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/
 		$b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/

 	condition:
 		($PDF at 0) and #a > 150 and #b > 200
}rule wipbot_2013_core 
{
 	meta:
 		description = "core + core; garbage appended data (PDF Exploit leftovers) + wipbot dropper; fake AdobeRd32 Error"
 		Malware = "Trojan.Wipbot 2013 core component"
 		author = "Symantec"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"

 	strings:
 		$mz = "MZ"
	/*
 	8947 0C MOV DWORD PTR DS:[EDI+C], EAX
 	C747 10 90C20400 MOV DWORD PTR DS:[EDI+10], 4C290
 	C747 14 90C21000 MOV DWORD PTR DS:[EDI+14], 10C290
 	C747 18 90906068 MOV DWORD PTR DS:[EDI+18], 68609090
 	894F 1C MOV DWORD PTR DS:[EDI+1C], ECX
 	C747 20 909090B8 MOV DWORD PTR DS:[EDI+20], B8909090
 	894F 24 MOV DWORD PTR DS:[EDI+24], ECX
 	C747 28 90FFD061 MOV DWORD PTR DS:[EDI+28], 61D0FF90
 	C747 2C 90C20400 MOV DWORD PTR DS:[EDI+2C], 4C290
 	*/
 		$code1 = { 89 47 0C C7 47 10 90 C2 04 00 C7 47 14 90 C2 10 00 C7 47 18 90 90 60 68 89 4F 1C C7 47 20 90 90 90 B8 89 4F 24 C7 47 28 90 FF D0 61 C7 47 2C 90 C2 04 00}
 	/*
 	85C0 TEST EAX, EAX
 	75 25 JNZ SHORT 64106327.00403AF1
 	8B0B MOV ECX, DWORD PTR DS:[EBX]
 	BF ???????? MOV EDI, ????????
 	EB 17 JMP SHORT 64106327.00403AEC
 	69D7 0D661900 IMUL EDX, EDI, 19660D
 	8DBA 5FF36E3C LEA EDI, DWORD PTR DS:[EDX+3C6EF35F]
 	89FE MOV ESI, EDI
 	C1EE 10 SHR ESI, 10
 	89F2 MOV EDX, ESI
 	301401 XOR BYTE PTR DS:[ECX+EAX], DL
 	40 INC EAX
 	3B43 04 CMP EAX, DWORD PTR DS:[EBX+4]
 	72 E4 JB SHORT 64106327.00403AD5
 	*/
 		$code2 = { 85 C0 75 25 8B 0B BF ?? ?? ?? ?? EB 17 69 D7 0D 66 19 00 8D BA 5F F3 6E 3C 89 FE C1 EE 10 89 F2 30 14 01 40 3B 43 04 72 E4}
 		$code3 = {90 90 90 ?? B9 00 4D 5A 90 00 03 00 00 00 82 04}
		$code4 = {55 89 E5 5D C3 55 89 E5 83 EC 18 8B 45 08 85 C0}

 	condition:
 		$mz at 0 and (($code1 or $code2) or ($code3 and $code4))
}
rule wipbot_2013_dll 
{
 	meta:
 		author = "Symantec"
		description = "Trojan.Wipbot 2013 DLL"
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
 		description = "Down.dll component"
        
 	strings:
		$string1 = "/%s?rank=%s"
		$string2 = "ModuleStart\x00ModuleStop\x00start"
		$string3 = "1156fd22-3443-4344-c4ffff"
		//read file... error..
		$string4 = "read\x20file\x2E\x2E\x2E\x20error\x00\x00"

	condition:
		2 of them
}rule DarkComet_Config_Artifacts_Memory

{   

     meta:

           Description = "Looks for configuration artifacts from DarkComet. Works with memory dump and unpacked samples."

           filetype = "MemoryDump"         

           Author = "Ian Ahl @TekDefese"

           Date = "12-19-2013"

           reference = "http://www.tekdefense.com/news/2013/12/23/analyzing-darkcomet-in-memory.html"

     strings:

           $s0 = "GENCODE={" ascii

           $s1 = "MELT={" ascii

           $s2 = "COMBOPATH={" ascii

           $s3 = "NETDATA={" ascii

           $s4 = "PERSINST={" ascii

     condition:

           2 of them

}

 

rule DarkComet_Default_Mutex_Memory

{   

     meta:

           Description = "Looks for default DarkComet mutexs"

           filetype = "MemoryDump"              

           Author = "Ian Ahl @TekDefese"

           Date = "12-20-2013"

           reference = "http://www.tekdefense.com/news/2013/12/23/analyzing-darkcomet-in-memory.html"


     strings:

           $s = "DC_MUTEX-" ascii nocase

     condition:

           any of them

}

 

rule DarkComet_Keylogs_Memory

{   

     meta:

           Description = "Looks for key log artifacts"

           filetype = "MemoryDump"              

           Author = "Ian Ahl @TekDefese"

           Date = "12-20-2013"

           reference = "http://www.tekdefense.com/news/2013/12/23/analyzing-darkcomet-in-memory.html"


     strings:

           $s0 = "[<-]"

           $s1 = ":: Clipboard Change :"

           $s2 = "[LEFT]"

           $s4 = "[RIGHT]"

           $s5 = "[UP]"

           $s6 = "[DOWN]"

           $s7 = "[DEL]"

           $s8 = /::.{1,100}\(\d{1,2}:\d{1,2}:\d{1,2}\s\w{2}\)/  

     condition:

           any of them

}rule ammyy_cerber3 {
	meta:
		description = "Rule to detect Ammyy Admin / Cerber 3.0 Ransomware"
		author = "Rich Walchuck"
		source = "AA_v3.5.exe"
		md5 = "54d07ec77e3daaf32b2ba400f34dd370"
		sha1 = "3a99641ba00047e1be23dfae4fcf6242b8b8eb10"
		sha256 = "99b84137b5b8b3c522414e332526785e506ed2dbe557eafc40a7bcf47b623d88"
		date = "09/28/2016"
	strings:
		$s0 = "mailto:support@ammy.com" fullword ascii
		$s1 = "@$&%04\\Uninstall.exe" fullword ascii
		$s2 = "@$&%05\\encrypted.exe" fullword ascii
		$s3 = "http://www.ammy.com/" fullword ascii
		$s4 = "@$&%05\\AA_v3.exe" fullword ascii
		$s5 = "ammy 1.00 - Smart Install Maker" fullword ascii
		$s6 = "ammy 1.00 Installation" fullword wide
		$s7 = "Ammy" fullword wide
	condition:
		all of them
}
import "elf"

rule single_load_rwe
{
    meta:
        description = "Flags binaries with a single LOAD segment marked as RWE."
        family = "Stager"
        filetype = "ELF"
        hash = "711a06265c71a7157ef1732c56e02a992e56e9d9383ca0f6d98cd96a30e37299"

    condition:
        elf.number_of_segments == 1 and
        elf.segments[0].type == elf.PT_LOAD and
        elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}

rule fake_section_headers_conflicting_entry_point_address
{
    meta:
        description = "A fake sections header has been added to the binary."
        family = "Obfuscation"
        filetype = "ELF"
        hash = "a2301180df014f216d34cec8a6a6549638925ae21995779c2d7d2827256a8447"

    condition:
        elf.type == elf.ET_EXEC and
        elf.entry_point < filesize and // file scanning only
        elf.number_of_segments > 0 and
        elf.number_of_sections > 0 and
        not
        (
            for any i in (0..elf.number_of_segments):
            (
                (elf.segments[i].offset <= elf.entry_point) and
                ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and
                for any j in (0..elf.number_of_sections):
                (
                    elf.sections[j].offset <= elf.entry_point and
                    ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and
                    (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) ==
                    (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset))
                )
            )
        )
}

rule fake_dynamic_symbols
{
    meta:
        description = "A fake dynamic symbol table has been added to the binary"
        family = "Obfuscation"
        filetype = "ELF"
        hash = "51676ae7e151a0b906c3a8ad34f474cb5b65eaa3bf40bb09b00c624747bcb241"

    condition:
        elf.type == elf.ET_EXEC and
        elf.entry_point < filesize and // file scanning only
        elf.number_of_sections > 0 and
        elf.dynamic_section_entries > 0 and
        for any i in (0..elf.dynamic_section_entries):
        (
            elf.dynamic[i].type == elf.DT_SYMTAB and
            not
            (
                for any j in (0..elf.number_of_sections):
                (
                    elf.sections[j].type == elf.SHT_DYNSYM and
                    for any k in (0..elf.number_of_segments):
                    (
                        (elf.segments[k].virtual_address <= elf.dynamic[i].val) and
                        ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and
                        (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset
                    )
                )
            )
        )
}
rule fopo
{
    meta:
        description = "Free Online PHP Obfuscator"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "b96a81b71d69a9bcb5a3f9f4edccb4a3c7373159d8eda874e053b23d361107f0"
        hash = "bbe5577639233b5a83c4caebf807c553430cab230f9a15ec519670dd8be6a924"
        hash = "a698441f817a9a72908a0d93a34133469f33a7b34972af3e351bdccae0737d99"

    strings:
        $base64_decode = /\$[a-zA-Z0-9]+=\"\\(142|x62)\\(141|x61)\\(163|x73)\\(145|x65)\\(66|x36)\\(64|x34)\\(137|x5f)\\(144|x64)\\(145|x65)\\(143|x63)\\(157|x6f)\\(144|x64)\\(145|x65)\";@eval\(/

    condition:
        all of them
}
rule generic_jsp
{
    meta:
        description = "Generic JSP"
        family = "JSP Backdoor"
        filetype = "JSP"
        hash = "6517e4c8f19243298949711b48ae2eb0b6c764235534ab29603288bc5fa2e158"

    strings:
        $exec = /Runtime.getRuntime\(\).exec\(request.getParameter\(\"[a-zA-Z0-9]+\"\)\);/ ascii

    condition:
        all of them
}
import "elf"

rule Kaiten
{
    meta:
        description = "Linux IRC DDoS Malware"
        family = "Linux.Backdoor.Kaiten"
        filetype = "ELF"
        hash = "6b5386d96b90a4cb811c5ddd6f35f6b0d4c65c69c8160216077e7a0f43a8888d"
        hash = "965a9594ef80e7134e1a9e5a4cce0a3dce98636107d1f6410224386dfccb9d5b"
        hash = "2c772242de272bff1bb940b0687445739ec544aceec1bc5591a374a57cd652b5"

    strings:
        $irc = /(PING)|(PONG)|(NOTICE)|(PRIVMSG)/
        $kill = "Killing pid %d" nocase
        $subnet = "What kind of subnet address is that" nocase
        $version = /(Helel mod)|(Kaiten wa goraku)/
        $flood = "UDP <target> <port> <secs>" nocase

    condition:
        elf.type == elf.ET_EXEC and $irc and
        2 of ($kill, $subnet, $version, $flood)
}
rule eval_statement
{
    meta:
        description = "Obfuscated PHP eval statements"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "9da32d35a28d2f8481a4e3263e2f0bb3836b6aebeacf53cd37f2fe24a769ff52"
        hash = "8c1115d866f9f645788f3689dff9a5bacfbee1df51058b4161819c750cf7c4a1"
        hash = "14083cf438605d38a206be33542c7a4d48fb67c8ca0cfc165fa5f279a6d55361"

    strings:
        $obf = /eval[\( \t]+((base64_decode[\( \t]+)|(str_rot13[\( \t]+)|(gzinflate[\( \t]+)|(gzuncompress[\( \t]+)|(strrev[\( \t]+)|(gzdecode[\( \t]+))+/

    condition:
        all of them
}

rule hardcoded_urldecode
{
    meta:
        description = "PHP with hard coded urldecode call"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "79b22d7dbf49d8cfdc564936c8a6a1e2"
        hash = "38dc8383da0859dca82cf0c943dbf16d"

    strings:
        $obf = /urldecode[\t ]*\([\t ]*'(%[0-9a-fA-F][0-9a-fA-F])+'[\t ]*\)/

    condition:
        all of them
}

rule chr_obfuscation
{
    meta:
        description = "PHP with string building using hard coded values in chr()"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "d771409e152d0fabae45ea192076d45e"
        hash = "543624bec87272974384c8ab77f2357a"
        hash = "cf2ab009cbd2576a806bfefb74906fdf"

    strings:
        $obf = /\$[^=]+=[\t ]*(chr\([0-9]+\)\.?){2,}/

    condition:
        all of them
}
rule pbot
{
    meta:
        description = "PHP IRC Bot"
        family = "Backdoor.PHP.Pbot"
        filetype = "PHP"
        hash = "cd62b4c32f0327d06dd99648e44c85560416a40f6734429d3e89a4c5250fd28e"
        hash = "80fb661aac9fcfbb5ae356c5adc7d403bf15da9432b5e33fbbed938c42fdde3c"
        hash = "6873bcc7f3971c42564a5fb72d5963b1660c6ff53409e496695523c1115e9734"

    strings:
        $class = "class pBot" ascii
        $start = "function start(" ascii
        $ping = "PING" ascii
        $pong = "PONG" ascii

    condition:
        all of them
}
rule Tenablebot
{
	meta:
		author = "tenable"
		reference = "https://www.tenable.com/blog/threat-hunting-with-yara-and-nessus"
	strings:
		$channel = "#secret_tenable_bot_channel"
		$version = "Tenable Bot version 0.1"
		$version_command = "!version"
		$exec_command = "!exec"
		$user = "USER tenable_bot 8 * :doh!"
	condition:
		all of them
}import "pe"

rule UPX_Packed
{
	condition:
		pe.sections[0].name contains "UPX0" and
		pe.sections[1].name contains "UPX1"
}rule venom
{
    meta:
        description = "Venom Linux Rootkit"
        author = "Rich Walchuck"
        source = "https://security.web.cern.ch/security/venom.shtml"
        hash = "a5f4fc353794658a5ca2471686980569"
        date = "2017-01-31"

    strings:
        $string0 = "%%VENOM%OK%OK%%"
        $string1 = "%%VENOM%WIN%WN%%"
        $string2 = "%%VENOM%CTRL%MODE%%"
        $string3 = "%%VENOM%AUTHENTICATE%%"
        $string4 = "venom by mouzone"
        $string5 = "justCANTbeSTOPPED"

    condition:
        any of them
}
rule Havex_NetScan_Malware {
meta:
        description = "This rule will search for known indicators of a Havex Network Scan module infection. This module looks for hosts listening on known ICS-related ports to identify OPC or ICS systems and the file created when the scanning data is written."
        author = "M4r14ch1"
        reference = "https://github.com/M4r14ch1/Havex-Network-Scanner-Modules"
        date = "2015/12/21"
        strings:
                $s0 = "~tracedscn.yls" wide nocase //yls file created in temp directory
                $s1 = { 2B E2 ?? }      //Measuresoft ScadaPro
                $s2 = { 30 71 ?? }      //7-Technologies IGSS SCADA
               /* $s3 = { 0A F1 2? }      //Rslinx*/
            
        condition:
                $s0 and ($s1 or $s2 /*or $s3*/)
}

rule auriga : apt
{
    strings:
        $a = "%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x"
        $b = "auriga"
        $c = "McUpdate"
        $d = "download"
        $e = "upload"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule bouncer_dll : apt
{
    strings:
        $a = "select"
        $b = "%s: %s"
        $c = "sa:%s"
		$d = ";PWD="
		$e = "Computer Numbers: %d"
    condition:
        filesize < 350KB and (5 of ($a,$b,$c,$d,$e))
}

rule bouncer_exe : apt
{
    strings:
        $a = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg"
        $b = "dump"
        $c = "IDR_DATA%d"
    condition:
        filesize < 300KB and (3 of ($a,$b,$c))
}

rule bouncer2_exe : apt
{
    strings:
        $a = "asdfqwe123cxz"
        $b = "dump"
        $c = "loadlibrary kernel32 error %d"
    condition:
        filesize < 300KB and (3 of ($a,$b,$c))
}

rule calendar : apt
{
    strings:
        $a = "DownRun success"
        $b = "GoogleLogin auth="
        $c = "%s@gmail.com"
		$d = "log command"
		$e = "%s: %s"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule combos : apt
{
    strings:
        $a = "showthread.php?t="
        $b = "Getfile"
        $c = "Putfile"
		$d = "file://"
		$e = "https://%s"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule cookiebag : apt
{
    strings:
        $a = "?ID="
        $b = ".asp"
        $c = "clientkey"
		$d = "GetCommand"
		$e = "Set-Cookie:"
  	condition:
        filesize < 100KB and (5 of ($a,$b,$c,$d,$e))
}

rule dairy : apt
{
    strings:
        $a = "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c"
        $b = "Mozilla/4.0 (compatible; MSIE 7.0;)"
        $c = "dir %temp%"
		$d = "pklist"
		$e = "pkkill"
    condition:
        filesize < 100KB and (5 of ($a,$b,$c,$d,$e))
}

rule gdocupload : apt
{
    strings:
        $a = "CONOUT$"
        $b = "length=%d,time=%fsec,speed=%fk"
		$c = "%s%s%s"
		$d = "http://docs.google.com/?auth="
		$e = "x-fpp-command: 0"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule getmail : apt
{
    strings:
        $a = "Lu's Zany Message Store"
        $b = "IP"
		$c = "%s%i %s%i"
		$d = "-c key too long(MAX=16)"
		$e = "-f file name too long"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}


rule glooxmail : apt
{
    strings:
        $a = "This is gloox"
        $b = "Getfile Abrot!"
        $c = "glooxtest"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule goggles : apt
{
    strings:
        $a = "thequickbrownfxjmpsvalzydg"
        $b = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; %s.%s)"
    condition:
        filesize < 200KB and (2 of ($a,$b))
}

rule greencat : apt
{
    strings:
        $a = "computer name:"
        $b = "McUpdate"
        $c = "%s\\%d.bmp"
		$d = "version: %s v%d.%d build %d%s"
		$e = "Ca Incert"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule hacksfase : apt
{
    strings:
        $a = "!@#%$^#@!"
        $b = "Cann't create remote process!"
		$c = "tthacksfas@#$"
    condition:
        filesize < 300KB and (3 of ($a,$b,$c))
}

rule helauto : apt
{
    strings:
        $a = "D-o-w-n-l-o-a-d-f-i-l-e%s******%d@@@@@@%d"
        $b = "%*s %d %s"
		$c = "cmd /c net stop RasAuto"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule kurton : apt
{
    strings:
        $a = "HttpsUp||"
        $b = "!(*@)(!@PORT!(*@)(!@URL"
        $c = "root\\%s"
		$d = "HttpsFile||"
		$e = "Config service %s ok"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}


rule lightbolt : apt
{
    strings:
        $a = "bits.exe a all.jpg .\\ALL -hp%s"
        $b = "The %s store has been opened"
		$c = "Machine%d"
		$d = "Service%d"
		$e = "7z;ace;arj;bz2;cab;gz;jpeg;jpg;lha;lzh;mp3;rar;taz;tgz;z;zip"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule lightdart : apt
{
    strings:
        $a = "0123456789ABCDEF"
        $b = "ErrCode=%ld"
        $c = "ret.log"
        $d = "Microsoft Internet Explorer 6.0"
        $e = "szURL"
    condition:
        filesize < 200KB and (5 of ($a,$b,$c,$d,$e))
}

rule longrun : apt
{
    strings:
        $a = "%s\\%c%c%c%c%c%c%c"
        $b = "thequickbrownfxjmpsvalzydg"
    condition:
        filesize < 300KB and (2 of ($a,$b))
}

rule macromail : apt
{
    strings:
        $a = "get ok %d"
        $b = "put ok"
        $c = "GW-IP="
		$d = "messenger.hotmail.com"
		$e = "<d n=\"%s\">"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule manitsme : apt
{
    strings:
        $a = "rouji"
        $b = "Visual Studio"
        $c = "UglyGorilla"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c))
}

rule mapiget : apt
{
    strings:
        $a = "WNetCancelConnection2W"
        $b = "WNetAddConnection2W"
		$c = "%s -f:filename"
		$d = "CreateProcessWithLogonW"
		$e = "127.0.0.1"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule miniasp : apt
{
    strings:
        $a = ".asp?device_t=%s&key=%s&device_id=%s&cv=%s"
        $b = "result=%s"
        $c = "command=%s"
		$d = "wakeup="
    condition:
        filesize < 300KB and (4 of ($a,$b,$c,$d))
}

rule newsreels : apt
{
    strings:
        $a = "name=%s&userid=%04d&other=%c%s"
        $b = "thequickbrownfxjmpsvalzydg"
    condition:
        filesize < 300KB and (2 of ($a,$b))
}

rule seasalt : apt
{
    strings:
        $a = "%4d-%02d-%02d %02d:%02d:%02d"
        $b = "upfileok"
        $c = "upfileer"
		$d = "configserver"
    condition:
        filesize < 300KB and (4 of ($a,$b,$c,$d))
}

rule starsypound : apt
{
    strings:
        $a = "*(SY)# cmd"
        $b = "send = %d"
        $c = "cmd.exe"
		$d = "COMSPEC"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule sword : apt
{
    strings:
        $a = "Agent%ld"
        $b = "thequickbrownfxjmpsvalzydg"
        $c = "down:"
		$d = "exit"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule tabmsgsql : apt
{
    strings:
        $a = "accessip:%s"
        $b = "clientip:%s"
        $c = "Mozilla/4.0 (compatible; )"
		$d = "fromid:%s"
    condition:
        filesize < 300KB and (4 of ($a,$b,$c,$d))
}


rule tarsip : apt
{
    strings:
        $a = "%s/%s?%s"
        $b = "Mozilla/4.0 (compatible; MSIE 6.0;"
        $c = "Can not xo file!"
		$d = "cnnd"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule tarsip_eclipse : apt
{
    strings:
        $a = "Eclipse"
        $b = "PIGG"
        $c = "WAKPDT"
		$d = "show.asp?"
		$e = "flink?"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule warp : apt
{
    strings:
        $a = "Mozilla/4.0 (compatible; )"
        $b = "%u.%u.%u.%u"
        $c = "System info for machine"
		$d = "%2.2d-%2.2d-%4.4d %2.2d:%2.2d"
		$e = "https"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}

rule webc2_adspace : apt
{
    strings:
        $a = "ntshrui"
        $b = "Microsoft(R) Windows(R) Operating System"
    condition:
        filesize < 100KB and (2 of ($a,$b))
}


rule webc2_ausov : apt
{
    strings:
        $a = "ntshrui"
        $b = "Microsoft(R) Windows(R) Operating System"
    condition:
        filesize < 300KB and (2 of ($a,$b))
}

rule webc2_bolid : apt
{
    strings:
        $a = ".htmlEEEEEEEEEEEEEEEEEEEEEEEEEEEEsleep:"
        $b = "downloadcopy:"
		$c = "geturl:"
		$d = "Q3JlYXRlUHJvY2Vzc0E="
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}


rule webc2_clover : apt
{
    strings:
        $a = "m i c r o s o f t"
        $b = "Default.asp"
		$c = "background="
		$d = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule webc2_cson : apt
{
    strings:
        $a = "/Default.aspx?INDEX="
        $b = "/Default.aspx?ID="
		$c = "Windows+NT+5.1"
		$d = "<!--"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule webc2_div : apt
{
    strings:
        $a = "Microsoft Internet Explorer"
        $b = "Hello from MFC!"
		$c = "3DC76854-C328-43D7-9E07-24BF894F8EF5"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_greencat : apt
{
    strings:
        $a = "shell"
        $b = "getf/putf FileName <N>"
		$c = "kill </p|/s> <pid|ServiceName>"
		$d = "list </p|/s|/d>"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}

rule webc2_head : apt
{
    strings:
        $a = "<head>"
        $b = "</head>"
		$c = "connect %s"
		$d = "https://"
		$e = "Ready!"
    condition:
        filesize < 100KB and (5 of ($a,$b,$c,$d,$e))
}

rule webc2_kt3 : apt
{
    strings:
        $a = "*!Kt3+v| s:"
        $b = "*!Kt3+v| dne"
		$c = "*!Kt3+v|"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_qbp : apt
{
    strings:
        $a = "%t?%d-%d-%d="
        $b = "Hello@)!0"
		$c = "?id="
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_rave : apt
{
    strings:
        $a = "HTTP Mozilla/5.0(compatible+MSIE)"
        $b = "123!@#qweQWE"
		$c = "%s\\%s"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_table : apt
{
    strings:
        $a = "<![<endif>]--->"
        $b = "CreateThread() failed: %d"
		$c = "class="
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_ugx : apt
{
    strings:
        $a = "!@#dmc#@!"
        $b = "!@#tiuq#@!"
		$c = "!@#troppusnu#@!"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_y21k : apt
{
    strings:
        $a = "c2xlZXA="
        $b = "+Windows+NT+5.1"
		$c = "cXVpdA=="
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}

rule webc2_yahoo : apt
{
    strings:
        $a = "<yahoo sb="
        $b = "<yahoo ex="
		$c = "letusgo"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}rule MokerTrojan
{ 
meta:
 author = "malwarebytes"
 reference = "https://blog.malwarebytes.com/threat-analysis/2017/04/elusive-moker-trojan/"
strings:
 $mz = "MZ"
 $key = {3D FF 24 8B 92 C1 D6 9D}

condition: 
 $mz at 0 and uint32(uint32(0x3C)) == 0x455 and $key
}
rule zaccess_3
{
   meta:
      author = "josh"
      reference = "https://blog.malwarebytes.com/threat-analysis/2013/10/using-yara-to-attribute-malware/"
      description = "ZeroAccess Trojan, WaesColaweExport found"
   strings:
      $WaesColaweExport = { 55 8B EC 5? 0F B6 [5] 8A [5] 8? [1-2] 99 0F B6 [1] F7 [1] B? [4] 8? [2] 8? [2] 66 (8B|A1) [4-5] 66 2B [1] 0F B7 [1] (35|83 F0) [1-4] C1 E8 [1-4] 8B E5 5D C2 }
      $interface = "jjjinterface"
   condition:
      all of them
}
import "pe"

	rule MSLRHv032afakePCGuard4xxemadicius
	{
	strings:
			$a0 = { FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 58 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EnigmaProtector1XSukhovVladimirSergeNMarkin
	{
	strings:
			$a0 = { 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 00 00 52 65 67 43 6C 6F 73 65 4B 65 79 00 00 00 53 79 73 46 72 65 65 53 74 72 69 6E 67 00 00 00 43 72 65 61 74 65 46 6F 6E 74 41 00 00 00 53 68 65 6C 6C 45 78 65 63 75 74 65 41 00 00 }

	condition:
			$a0
	}
	
	
	rule SPLayerv008
	{
	strings:
			$a0 = { 8D 40 00 B9 ?? ?? ?? ?? 6A ?? 58 C0 0C ?? ?? 48 ?? ?? 66 13 F0 91 3B D9 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule DxPackV086Dxd
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule FSGv110EngdulekxtMicrosoftVisualC60
	{
	strings:
			$a0 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 }
	$a1 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE }
	$a2 = { 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 ?? ?? 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00 }
	$a3 = { C1 CE 10 C1 F6 0F 68 00 ?? ?? 00 2B FA 5B 23 F9 8D 15 80 ?? ?? 00 E8 01 00 00 00 B6 5E 0B }
	$a4 = { D1 E9 03 C0 68 80 ?? ?? 00 EB 02 CD 20 5E 40 BB F4 00 00 00 33 CA 2B C7 0F B6 16 EB 01 3E }
	$a5 = { E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE 80 ?? ?? 00 EB 02 61 E9 68 F4 00 00 00 C1 C8 }
	$a6 = { EB 01 4D 83 F6 4C 68 80 ?? ?? 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38 }
	$a7 = { EB 02 AB 35 EB 02 B5 C6 8D 05 80 ?? ?? 00 C1 C2 11 BE F4 00 00 00 F7 DB F7 DB 0F BE 38 E8 }
	$a8 = { EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 }
	$a9 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? ?? BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point) or $a3 at (pe.entry_point) or $a4 at (pe.entry_point) or $a5 at (pe.entry_point) or $a6 at (pe.entry_point) or $a7 at (pe.entry_point) or $a8 at (pe.entry_point) or $a9 at (pe.entry_point) 
	}
	
	
	rule TPPpackclane
	{
	strings:
			$a0 = { E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 ?? E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtMicrosoftVisualC6070
	{
	strings:
			$a0 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27 }
	$a1 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? ?? EB 02 CD 20 03 D3 8D 35 F4 00 }
	$a2 = { 87 FE E8 02 00 00 00 98 CC 5F BB 80 ?? ?? 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3 }
	$a3 = { F7 D8 40 49 EB 02 E0 0A 8D 35 80 ?? ?? ?? 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80 }
	$a4 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point) or $a3 at (pe.entry_point) or $a4 at (pe.entry_point)
	}
	
	
	rule Thinstall24x25xJititSoftware
	{
	strings:
			$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? BD ?? ?? ?? ?? 03 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule LocklessIntroPack
	{
	strings:
			$a0 = { 2C E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 06 89 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03faketElock061FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 F3 EB FF E0 83 C0 28 50 E8 00 00 00 00 5E B3 33 8D 46 0E 8D 76 31 28 18 F8 73 00 C3 8B FE B9 3C 02 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeStealth275aWebtoolMaster
	{
	strings:
			$a0 = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEArmor046Hying
	{
	strings:
			$a0 = { E8 AA 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 5C ?? ?? 00 6F ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }
	$a1 = { E8 AA 00 00 00 2D ?? ?? ?? 00 00 00 00 00 00 00 00 3D }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule eXPressorv13CGSoftLabs
	{
	strings:
			$a0 = { 45 78 50 72 2D 76 2E 31 2E 33 2E }
	$a1 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E 2E B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 13 A1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 89 ?? ?? E9 ?? ?? 00 00 C7 05 }

	condition:
			$a0 or $a1 at (pe.entry_point)
	}
	
	
	rule Upackv032BetaDwing
	{
	strings:
			$a0 = { BE 88 01 ?? ?? AD 50 ?? ?? AD 91 F3 A5 }
	$a1 = { BE 88 01 ?? ?? AD 50 ?? AD 91 ?? F3 A5 }

	condition:
			$a0 or $a1
	}
	
	
	rule MSLRHV031emadicius
	{
	strings:
			$a0 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv184
	{
	strings:
			$a0 = { 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PCGuardforWin32v500SofProBlagojeCeklic
	{
	strings:
			$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 ?? ?? ?? 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
rule WiseInstallerStub
	{
	strings:
			$a0 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF }
	$a1 = { 55 8B EC 81 EC ?? 04 00 00 53 56 57 6A ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? 40 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 ?? 20 }
	$a2 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2
	}
	rule AnskyaNTPackerGeneratorAnskya
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 53 B8 88 1D 00 10 E8 C7 FA FF FF 6A 0A 68 20 1E 00 10 A1 14 31 00 10 50 E8 71 FB FF FF 8B D8 85 DB 74 2F 53 A1 14 31 00 10 50 E8 97 FB FF FF 85 C0 74 1F 53 A1 14 31 00 10 50 E8 5F FB FF FF 85 C0 74 0F 50 E8 5D FB FF FF 85 C0 74 05 E8 70 FC FF FF 5B E8 F2 F6 FF FF 00 00 48 45 41 52 54 }

	condition:
			$a0
	}
	
	
	rule ThinstallVirtualizationSuite30493080ThinstallCompany
	{
	strings:
			$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 2C 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }
	$a1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 2C 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule NsPack14byNorthStarLiuXingPing
	{
	strings:
			$a0 = { 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 }

	condition:
			$a0
	}
	
	
	rule FSGv110EngbartxtWatcomCCEXE
	{
	strings:
			$a0 = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AcidCrypt
	{
	strings:
			$a0 = { 60 B9 ?? ?? ?? 00 BA ?? ?? ?? 00 BE ?? ?? ?? 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
	$a1 = { BE ?? ?? ?? ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
rule PackanoidArkanoid
	{
	strings:
			$a0 = { BF 00 10 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DAEMONProtectv067
	{
	strings:
			$a0 = { 60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D 61 }

	condition:
			$a0 at (pe.entry_point)
	}
	
/*	
	rule MEW11SEv12NorthfoxHCC
	{
	strings:
			$a0 = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
*/

	rule EmbedPEV100V124cyclotron
	{
	strings:
			$a0 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule VProtectorV10Avcasm
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 8A 8E 40 00 68 C6 8E 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EncryptPE2200481022005314WFS
	{
	strings:
			$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 7A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02JDPack1xJDProtect09Anorganix
	{
	strings:
			$a0 = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EmbedPEV1Xcyclotron
	{
	strings:
			$a0 = { 83 EC 50 60 68 ?? ?? ?? ?? E8 ?? ?? 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EncryptPEV220070411WFS
	{
	strings:
			$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 1B 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01MicrosoftVisualBasic60DLLAnorganix
	{
	strings:
			$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 5A 68 90 90 90 90 68 90 90 90 90 52 E9 90 90 FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPack14Liuxingping
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 ?? ?? 40 00 2D ?? ?? 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule VxTrivial46
	{
	strings:
			$a0 = { B4 4E B1 20 BA ?? ?? CD 21 BA ?? ?? B8 ?? 3D CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule STUDRC410JamieEditionScanTimeUnDetectablebyMarjinZ
	{
	strings:
			$a0 = { 68 2C 11 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30 00 00 00 38 00 00 00 00 00 00 00 37 BB 71 EC A4 E1 98 4C 9B FE 8F 0F FA 6A 07 F6 00 00 00 00 00 00 01 00 00 00 20 20 46 6F 72 20 73 74 75 64 00 20 54 6F 00 00 00 00 06 00 00 00 CC 1A 40 00 07 00 00 00 D4 18 40 00 07 00 00 00 7C 18 40 00 07 00 00 00 2C 18 40 00 07 00 00 00 E0 17 40 00 56 42 35 21 F0 1F 2A 00 00 00 00 00 00 00 00 00 00 00 00 00 7E 00 00 00 00 00 00 00 00 00 00 00 00 00 0A 00 09 04 00 00 00 00 00 00 E8 13 40 00 F4 13 40 00 00 F0 30 00 00 FF FF FF 08 00 00 00 01 00 00 00 00 00 00 00 E9 00 00 00 04 11 40 00 04 11 40 00 C8 10 40 00 78 00 00 00 7C 00 00 00 81 00 00 00 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 61 61 61 00 53 74 75 64 00 00 73 74 75 64 00 00 01 00 01 00 30 16 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 B4 16 40 00 10 30 40 00 07 00 00 00 24 12 40 00 0E 00 20 00 00 00 00 00 1C 9E 21 00 EC 11 40 00 5C 10 40 00 E4 1A 40 00 2C 34 40 00 68 17 40 00 58 17 40 00 78 17 40 00 8C 17 40 00 8C 10 40 00 62 10 40 00 92 10 40 00 F8 1A 40 00 24 19 40 00 98 10 40 00 9E 10 40 00 77 04 18 FF 04 1C FF 05 00 00 24 01 00 0D 14 00 78 1C 40 00 48 21 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxSonikYouth
	{
	strings:
			$a0 = { 8A 16 02 00 8A 07 32 C2 88 07 43 FE C2 81 FB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXShit006
	{
	strings:
			$a0 = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SetupFactoryv6003SetupLauncher
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 90 61 40 00 68 70 3B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 14 61 40 00 33 D2 8A D4 89 15 5C 89 40 00 8B C8 81 E1 FF 00 00 00 89 0D 58 89 40 00 C1 E1 08 03 CA 89 0D 54 89 40 00 C1 E8 10 A3 50 89 }

	condition:
			$a0
	}
	
	
	rule CrypKeyV61XDLLCrypKeyCanadaInc
	{
	strings:
			$a0 = { 83 3D ?? ?? ?? ?? 00 75 34 68 ?? ?? ?? ?? E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VcAsmProtectorVcAsm
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompact2xxSlimLoaderBitSumTechnologies
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ENIGMAProtectorV11V12SukhovVladimir
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule yodasProtectorv10bAshkbizDanehkar
	{
	strings:
			$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 00 00 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEDiminisherv01
	{
	strings:
			$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 }
	$a1 = { 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule SOFTWrapperforWin9xNTEvaluationVersion
	{
	strings:
			$a0 = { E8 00 00 00 00 5D 8B C5 2D ?? ?? ?? 00 50 81 ED 05 00 00 00 8B C5 2B 85 03 0F 00 00 89 85 03 0F 00 00 8B F0 03 B5 0B 0F 00 00 8B F8 03 BD 07 0F 00 00 83 7F 0C 00 74 2B 56 57 8B 7F 10 03 F8 8B 76 10 03 F0 83 3F 00 74 0C 8B 1E 89 1F 83 C6 04 83 C7 04 EB EF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov200
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 00 02 41 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov201
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 08 02 41 00 68 04 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule FreeJoinerSmallbuild014021024027GlOFF
	{
	strings:
			$a0 = { E8 ?? ?? FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SDProtector1xRandyLi
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NSISInstallerNullSoft
	{
	strings:
			$a0 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? ?? ?? C6 44 24 14 20 FF 15 30 70 40 00 53 FF 15 80 72 40 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEXv099
	{
	strings:
			$a0 = { 60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule IMPPacker10MahdiHezavehiIMPOSTER
	{
	strings:
			$a0 = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 }

	condition:
			$a0
	}
	
	
	rule PEProtectv09
	{
	strings:
			$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3 }
	$a1 = { E9 ?? 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 20 28 43 29 6F }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	
	rule nbuildv10soft
	{
	strings:
			$a0 = { B9 ?? ?? BB ?? ?? C0 ?? ?? 80 ?? ?? 43 E2 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01StelthPE101Anorganix
	{
	strings:
			$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 BA ?? ?? ?? ?? FF E2 BA E0 10 40 00 B8 68 24 1A 40 89 02 83 C2 03 B8 40 00 E8 EE 89 02 83 C2 FD FF E2 2D 3D 5B 20 48 69 64 65 50 45 20 5D 3D 2D 90 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule IProtect10FxSubdllmodebyFuXdas
	{
	strings:
			$a0 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 53 75 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 60 E8 00 00 00 00 5D 81 ED B6 13 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 A8 13 40 00 8D 85 81 13 40 00 50 FF B5 A8 13 40 00 E8 92 00 00 00 0B C0 74 13 89 85 A4 13 40 00 8D 85 8E 13 40 00 50 FF 95 A4 13 40 00 8B 85 AC 13 40 00 89 44 24 1C 61 FF E0 8B 7C 24 04 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 98 13 40 00 89 20 89 68 04 8D 9D 4F 14 40 00 89 58 08 64 89 25 00 00 00 00 81 E7 00 00 FF FF 66 81 3F 4D 5A 75 0F 8B F7 03 76 3C 81 3E 50 45 00 00 75 02 EB 17 81 EF 00 00 01 00 81 FF 00 00 00 70 73 07 BF 00 00 F7 BF EB 02 EB D3 97 64 8F 05 00 00 00 00 83 C4 04 C2 04 00 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 98 13 40 00 89 20 89 68 04 8D 9D 4F 14 40 00 89 58 08 64 89 25 00 00 00 00 8B 74 24 0C 66 81 3E 4D 5A 74 05 E9 8A 00 00 00 03 76 3C 81 3E 50 45 00 00 74 02 EB 7D 8B 7C 24 10 B9 96 00 00 00 32 C0 F2 AE 8B CF 2B 4C 24 10 8B 56 78 03 54 24 0C 8B 5A 20 03 5C 24 0C 33 C0 8B 3B 03 7C 24 0C 8B 74 24 10 51 F3 A6 75 05 83 C4 04 EB 0A 59 83 C3 04 40 3B 42 18 75 E2 3B 42 18 75 02 EB 35 8B 72 24 03 74 24 0C 52 BB 02 00 00 00 33 D2 F7 E3 5A 03 C6 33 C9 66 8B 08 8B 7A 1C 33 D2 BB 04 00 00 00 8B C1 F7 E3 03 44 24 0C 03 C7 8B 00 03 44 24 0C EB 02 33 C0 64 8F 05 00 00 00 00 83 C4 04 C2 08 00 E8 B5 FA FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSVisualCv8DLLhsmallsig2
	{
	strings:
			$a0 = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 ?? ?? 00 00 83 FE 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSVisualCv8DLLhsmallsig1
	{
	strings:
			$a0 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 ?? ?? ?? FF 5D E9 D6 FE FF FF CC CC CC CC CC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RCryptorv16xVaska
	{
	strings:
			$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule UPXv20MarkusLaszloReiser
	{
	strings:
			$a0 = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 }

	condition:
			$a0
	}
	
	
	rule BladeJoinerv15
	{
	strings:
			$a0 = { 55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv133Engdulekxt
	{
	strings:
			$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF }
	$a1 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule FSGv13
	{
	strings:
			$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv12
	{
	strings:
			$a0 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv11
	{
	strings:
			$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv10
	{
	strings:
			$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv120EngdulekxtMicrosoftVisualC6070
	{
	strings:
			$a0 = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SuperDAT
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 40 F3 42 00 68 A4 BF 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 08 F2 42 00 33 D2 8A D4 89 15 60 42 43 00 8B C8 81 E1 FF 00 00 00 89 0D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv200alpha38
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 80 B8 BF 10 00 10 01 74 7A C6 80 BF 10 00 10 01 9C 55 53 51 57 52 56 8D 98 0F 10 00 10 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 8B F8 50 8B 33 8B 53 14 03 F2 8B 4B 0C 03 CA 8D 85 B7 10 00 10 FF 73 04 8F }

	condition:
			$a0
	}
	
	
	rule RCryptor16cVaska
	{
	strings:
			$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule TheGuardLibrary
	{
	strings:
			$a0 = { 50 E8 ?? ?? ?? ?? 58 25 ?? F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeCryptor01build001GlOFF
	{
	strings:
			$a0 = { 8B 04 24 40 90 83 C0 07 80 38 90 90 74 02 EB FF 68 26 ?? ?? 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 FF E4 90 8B 04 24 64 A3 00 00 00 00 8B 64 24 08 90 83 C4 08 }

	condition:
			$a0
	}
	
	rule PseudoSigner02BJFNT12Anorganix
	{
	strings:
			$a0 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DingBoysPElockPhantasmv08
	{
	strings:
			$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Thinstall2736Jitit
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 58 BB F3 1C 00 00 2B C3 50 68 00 00 40 00 68 00 26 00 00 68 CC 00 00 00 E8 C1 FE FF FF E9 97 FF FF FF CC CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UnnamedScrambler11Cp0ke
	{
	strings:
			$a0 = { 55 8B EC 83 C4 E4 53 56 33 C0 89 45 E4 89 45 E8 89 45 EC B8 C0 47 00 10 E8 4F F3 FF FF BE 5C 67 00 10 33 C0 55 68 D2 4A 00 10 64 FF 30 64 89 20 E8 EB DE FF FF E8 C6 F8 FF FF BA E0 4A 00 10 B8 CC 67 00 10 E8 5F F8 FF FF 8B D8 8B D6 8B C3 8B 0D CC 67 00 10 E8 3A DD FF FF 8B 46 50 8B D0 B8 D4 67 00 10 E8 5B EF FF FF B8 D4 67 00 10 E8 09 EF FF FF 8B D0 8D 46 14 8B 4E 50 E8 14 DD FF FF 8B 46 48 8B D0 B8 D8 67 00 ?? ?? ?? ?? ?? FF B8 D8 67 00 10 E8 E3 EE FF FF 8B D0 8B C6 8B 4E 48 E8 EF DC FF FF FF 76 5C FF 76 58 FF 76 64 FF 76 60 B9 D4 67 00 10 8B 15 D8 67 00 10 A1 D4 67 00 10 E8 76 F6 FF FF A1 D4 67 00 10 E8 5C EE FF FF 8B D0 B8 CC 67 00 10 E8 CC F7 FF FF 8B D8 B8 DC 67 00 10 }

	condition:
			$a0
	}
	
	
	rule y0dasCrypterv1xModified
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7 AC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov252b2
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 B0 ?? ?? ?? 68 60 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 24 }

	condition:
			$a0 at (pe.entry_point)
	}
		rule Upackv036betaDwing
	{
	strings:
			$a0 = { BE E0 11 ?? ?? FF 36 E9 C3 00 00 00 48 01 ?? ?? 0B 01 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C }
	$a1 = { BE E0 11 ?? ?? FF 36 E9 C3 00 00 00 48 01 ?? ?? 0B 01 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 82 8E FE FF FF 58 8B 4E 40 5F E3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	rule VxNecropolis
	{
	strings:
			$a0 = { 50 FC AD 33 C2 AB 8B D0 E2 F8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WinUpackv039finalrelocatedimagebaseByDwingc2005h2
	{
	strings:
			$a0 = { 60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv1061bAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }

	condition:
			$a0 at (pe.entry_point)
	}
	
/*	
	rule MEW11SEv12
	{
	strings:
			$a0 = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
*/	
	
	
	rule aPackv062
	{
	strings:
			$a0 = { 1E 06 8C C8 8E D8 ?? ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B6 }

	condition:
			$a0 at (pe.entry_point)
	}
	
/*	
	rule MEW11SEv11
	{
	strings:
			$a0 = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
*/	
	
	rule tElockv071
	{
	strings:
			$a0 = { 60 E8 ED 10 00 00 C3 83 }

	condition:
			$a0 at (pe.entry_point)
	}

	
	rule tElockv070
	{
	strings:
			$a0 = { 60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Ningishzida10CyberDoom
	{
	strings:
			$a0 = { 9C 60 96 E8 00 00 00 00 5D 81 ED 03 25 40 00 B9 04 1B 00 00 8D BD 4B 25 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }

	condition:
			$a0 at (pe.entry_point)
	}
	rule ASProtectSKE21xdllAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PAVCryptorPawningAntiVirusCryptormasha_dev
	{
	strings:
			$a0 = { 53 56 57 55 BB 2C ?? ?? 70 BE 00 30 00 70 BF 20 ?? ?? 70 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 00 70 00 74 06 FF 15 54 30 00 70 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 1C 30 00 70 80 7B 28 01 76 05 83 3E 00 74 22 8B 43 10 85 C0 74 1B FF 15 14 30 00 70 8B 53 10 8B 42 10 3B 42 04 74 0A 85 C0 74 06 50 E8 8F FA FF FF FF 15 20 30 00 70 80 7B 28 01 75 03 FF 53 24 80 7B 28 00 74 05 E8 35 FF FF FF 83 3B 00 75 17 83 3D 10 ?? ?? 70 00 74 06 FF 15 10 ?? ?? 70 8B 06 50 E8 A9 FA FF FF 8B 03 56 8B F0 8B FB B9 0B 00 00 00 F3 A5 5E E9 73 FF FF FF 5D 5F 5E 5B C3 A3 00 30 00 70 E8 26 FF FF FF C3 90 8F 05 04 30 00 70 E9 E9 FF FF FF C3 }

	condition:
			$a0
	}
	
	
	rule ExeShieldCryptor13RCTomCommander
	{
	strings:
			$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 8C 21 40 00 B9 51 2D 40 00 81 E9 E6 21 40 00 8B D5 81 C2 E6 21 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CrinklerV01V02RuneLHStubbeandAskeSimonChristensen
	{
	strings:
			$a0 = { B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxGRUNT4Family
	{
	strings:
			$a0 = { E8 1C 00 8D 9E 41 01 40 3E 8B 96 14 03 B9 EA 00 87 DB F7 D0 31 17 83 C3 02 E2 F7 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule nPackV112002006BetaNEOxuinC
	{
	strings:
			$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 EC 01 00 00 E8 F8 06 00 00 E8 03 06 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxEddie1800
	{
	strings:
			$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E 8B FE 33 C0 50 8E D8 C4 ?? ?? ?? 2E ?? ?? ?? ?? 2E }

	condition:
			$a0 at (pe.entry_point)
	}
	rule EncryptPEV22006115WFS
	{
	strings:
			$a0 = { 45 50 45 3A 20 45 6E 63 72 79 70 74 50 45 20 56 32 2E 32 30 30 36 2E 31 2E 31 35 }

	condition:
			$a0
	}
	
	
	rule PrincessSandyv10eMiNENCEProcessPatcherPatch
	{
	strings:
			$a0 = { 68 27 11 40 00 E8 3C 01 00 00 6A 00 E8 41 01 00 00 A3 00 20 40 00 8B 58 3C 03 D8 0F B7 43 14 0F B7 4B 06 8D 7C 18 18 81 3F 2E 4C 4F 41 74 0B 83 C7 28 49 75 F2 E9 A7 00 00 00 8B 5F 0C 03 1D 00 20 40 00 89 1D 04 20 40 00 8B FB 83 C7 04 68 4C 20 40 00 68 08 }

	condition:
			$a0
	}
	
	
	rule aPackv082
	{
	strings:
			$a0 = { 1E 06 8C CB BA ?? ?? 03 DA 8D ?? ?? ?? FC 33 F6 33 FF 48 4B 8E C0 8E DB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NJoiner01AsmVersionNEX
	{
	strings:
			$a0 = { 6A 00 68 00 14 40 00 68 00 10 40 00 6A 00 E8 14 00 00 00 6A 00 E8 13 00 00 00 CC FF 25 AC 12 40 00 FF 25 B0 12 40 00 FF 25 B4 12 40 00 FF 25 B8 12 40 00 FF 25 BC 12 40 00 FF 25 C0 12 40 00 FF 25 C4 12 40 00 FF 25 C8 12 40 00 FF 25 CC 12 40 00 FF 25 D0 12 40 00 FF 25 D4 12 40 00 FF 25 D8 12 40 00 FF 25 DC 12 40 00 FF 25 E4 12 40 00 FF 25 EC 12 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsiduim1304ObsiduimSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule PseudoSigner02FSG131Anorganix
	{
	strings:
			$a0 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01CodeSafe20Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01NorthStarPEShrinker13Anorganix
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ocBat2Exe10OC
	{
	strings:
			$a0 = { 55 8B EC B9 08 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 58 3C 40 00 E8 6C FA FF FF 33 C0 55 68 8A 3F 40 00 64 FF 30 64 89 20 6A 00 6A 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 81 E9 FF FF 8B 45 EC E8 41 F6 FF FF 50 E8 F3 FA FF FF 8B F8 83 FF FF 0F 84 83 02 00 00 6A 02 6A 00 6A EE 57 E8 FC FA FF FF 6A 00 68 60 99 4F 00 6A 12 68 18 57 40 00 57 E8 E0 FA FF FF 83 3D 60 99 4F 00 12 0F 85 56 02 00 00 8D 45 E4 50 8D 45 E0 BA 18 57 40 00 B9 40 42 0F 00 E8 61 F4 FF FF 8B 45 E0 B9 12 00 00 00 BA 01 00 00 00 E8 3B F6 FF FF 8B 45 E4 8D 55 E8 E8 04 FB ?? ?? ?? ?? E8 B8 58 99 4F 00 E8 67 F3 FF FF 33 C0 A3 60 99 4F 00 8D 45 DC 50 B9 05 00 00 00 BA 01 00 00 00 A1 58 99 4F 00 E8 04 F6 FF FF 8B 45 DC BA A4 3F 40 00 E8 E3 F4 FF FF }

	condition:
			$a0
	}
	
	
	rule ASDPack20asd
	{
	strings:
			$a0 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8D 49 00 1F 01 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 90 }
	$a1 = { 5B 43 83 7B 74 00 0F 84 08 00 00 00 89 43 14 E9 }
	$a2 = { 8B 44 24 04 56 57 53 E8 CD 01 00 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 }

	condition:
			$a0 or $a1 or $a2 at (pe.entry_point)
	}
	
	
	rule EXECryptor2021protectedIAT
	{
	strings:
			$a0 = { A4 ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? 94 ?? ?? ?? D8 ?? ?? ?? 00 00 00 00 FF FF FF FF B8 ?? ?? ?? D4 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 60 ?? ?? ?? 70 ?? ?? ?? 84 ?? ?? ?? 00 00 00 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 }

	condition:
			$a0
	}
	rule ShrinkWrapv14
	{
	strings:
			$a0 = { 58 60 8B E8 55 33 F6 68 48 01 ?? ?? E8 49 01 ?? ?? EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UnknownbySMT
	{
	strings:
			$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 83 ?? ?? 57 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01VOBProtectCD5Anorganix
	{
	strings:
			$a0 = { 36 3E 26 8A C0 60 E8 00 00 00 00 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SimplePack10Xbagie
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA 6A 00 FF 93 ?? ?? 00 00 89 C5 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 8B 86 88 00 00 00 09 C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThemidaWinLicenseV18XV19XOreansTechnologies
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 05 89 48 01 61 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEjoinerAmok
	{
	strings:
			$a0 = { A1 14 A1 40 00 C1 E0 02 A3 18 A1 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EmbedPEv124cyclotron
	{
	strings:
			$a0 = { 83 EC 50 60 68 ?? ?? ?? ?? E8 CB FF 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElockv04xv05x
	{
	strings:
			$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 79 01 ?? ?? 59 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov301v305
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DingBoysPElockv007
	{
	strings:
			$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 23 35 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule mPack003DeltaAziz
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 33 C0 89 45 F0 B8 A8 76 00 10 E8 67 C4 FF FF 33 C0 55 68 C2 78 00 10 64 FF 30 64 89 20 8D 55 F0 33 C0 E8 93 C8 FF FF 8B 45 F0 E8 87 CB FF FF A3 08 A5 00 10 33 C0 55 68 A5 78 00 10 64 FF 30 64 89 20 A1 08 A5 00 10 E8 FA C9 FF FF 83 F8 FF 75 0A E8 88 B2 FF FF E9 1B 01 00 00 C7 05 14 A5 00 10 32 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 C9 C9 FF FF BA 14 A5 00 10 A1 08 A5 00 10 B9 04 00 00 00 E8 C5 C9 FF FF 83 3D 14 A5 00 10 32 77 0A E8 47 B2 FF FF E9 DA 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 92 C9 FF FF BA 18 A5 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule SixtoFourv10
	{
	strings:
			$a0 = { 50 55 4C 50 83 ?? ?? FC BF ?? ?? BE ?? ?? B5 ?? 57 F3 A5 C3 33 ED }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeJoinerSmallbuild029GlOFF
	{
	strings:
			$a0 = { 50 32 C4 8A C3 58 E8 DE FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThemidaWinLicenseV1XNoCompressionSecureEngineOreansTechnologies
	{
	strings:
			$a0 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? ?? ?? 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule WinUpackv030betaByDwing
	{
	strings:
			$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 }
	$a1 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 }

	condition:
			$a0 or $a1
	}
	
	
	rule Armadillov260b2
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 90 ?? ?? ?? 68 24 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 60 ?? ?? ?? 33 D2 8A D4 89 15 3C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov260b1
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 50 ?? ?? ?? 68 74 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeLockerv10IonIce
	{
	strings:
			$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 3E 8F 85 6C 00 00 00 3E 8F 85 68 00 00 00 3E 8F 85 64 00 00 00 3E 8F 85 60 00 00 00 3E 8F 85 5C 00 00 00 3E 8F 85 58 00 00 00 3E 8F 85 54 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackV10betaap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PellesC300400450EXEX86CRTDLL
	{
	strings:
			$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 E8 C7 45 FC ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 BE ?? ?? ?? ?? EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule BeRoEXEPackerv100LZBRRBeRoFarbrausch
	{
	strings:
			$a0 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov190a
	{
	strings:
			$a0 = { 55 8B EC 64 FF 68 10 F2 40 00 68 14 9B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv305c4Modified
	{
	strings:
			$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule APatchGUIv11
	{
	strings:
			$a0 = { 52 31 C0 E8 FF FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeSafeguardv10simonzh
	{
	strings:
			$a0 = { C0 5D EB 4E EB 47 DF 69 4E 58 DF 59 74 F3 EB 01 DF 75 EE 9A 59 9C 81 C1 E2 FF FF FF EB 01 DF 9D FF E1 E8 51 E8 EB FF FF FF DF 22 3F 9A C0 81 ED 19 18 40 00 EB 48 EB 47 DF 69 4E 58 DF 59 79 EE EB 01 DF 78 E9 DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE }

	condition:
			$a0
	}
	
	
	rule PseudoSigner01CDCopsIIAnorganix
	{
	strings:
			$a0 = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakeVIRUSIWormHybrisFEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 EB 16 A8 54 00 00 47 41 42 4C 4B 43 47 43 00 00 00 00 00 00 52 49 53 00 FC 68 4C 70 40 00 FF 15 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium1322ObsidiumSoftware
	{
	strings:
			$a0 = { EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 04 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PrivateEXEProtector20SetiSoft
	{
	strings:
			$a0 = { 89 ?? ?? 38 00 00 00 8B ?? 00 00 00 00 81 ?? ?? ?? ?? ?? 89 ?? 00 00 00 00 81 ?? 04 00 00 00 81 ?? 04 00 00 00 81 ?? 00 00 00 00 0F 85 D6 FF FF FF }

	condition:
			$a0
	}
	
	
	rule NTkrnlSecureSuite01015DLLNTkrnlSoftware
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 8B 44 24 04 05 ?? ?? ?? ?? 50 E8 01 00 00 00 C3 C3 }

	condition:
			$a0
	}
	
	
	rule UPXHiTv001DJSiba
	{
	strings:
			$a0 = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }

	condition:
			$a0
	}
	
	
	rule Vpackerttui
	{
	strings:
			$a0 = { 89 C6 C7 45 E0 01 00 00 00 F7 03 00 00 FF FF 75 18 0F B7 03 50 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 EB 13 53 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 83 C7 04 FF 45 E0 4E 75 C4 8B F3 83 3E 00 75 88 8B 45 E4 8B 40 10 03 45 DC 8B 55 14 83 C2 20 89 02 68 00 80 00 00 6A 00 8B 45 D4 50 FF 55 EC 8B 55 DC 8B 42 3C 03 45 DC 83 C0 04 8B D8 83 C3 14 8D 45 E0 50 6A 40 68 00 10 00 00 52 FF 55 E8 8D 43 60 }

	condition:
			$a0
	}
	
	
	rule IProtect10FxlibdllmodebyFuXdas
	{
	strings:
			$a0 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 4C 69 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 60 E8 00 00 00 00 5D 81 ED 71 10 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 63 10 40 00 8D 85 3C 10 40 00 50 FF B5 63 10 40 00 E8 92 00 00 00 0B C0 74 13 89 85 5F 10 40 00 8D 85 49 10 40 00 50 FF 95 5F 10 40 00 8B 85 67 10 40 00 89 44 24 1C 61 FF E0 8B 7C 24 04 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 53 10 40 00 89 20 89 68 04 8D 9D 0A 11 40 00 89 58 08 64 89 25 00 00 00 00 81 E7 00 00 FF FF 66 81 3F 4D 5A 75 0F 8B F7 03 76 3C 81 3E 50 45 00 00 75 02 EB 17 81 EF 00 00 01 00 81 FF 00 00 00 70 73 07 BF 00 00 F7 BF EB 02 EB D3 97 64 8F 05 00 00 00 00 83 C4 04 C2 04 00 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 53 10 40 00 89 20 89 68 04 8D 9D 0A 11 40 00 89 58 08 64 89 25 00 00 00 00 8B 74 24 0C 66 81 3E 4D 5A 74 05 E9 8A 00 00 00 03 76 3C 81 3E 50 45 00 00 74 02 EB 7D 8B 7C 24 10 B9 96 00 00 00 32 C0 F2 AE 8B CF 2B 4C 24 10 8B 56 78 03 54 24 0C 8B 5A 20 03 5C 24 0C 33 C0 8B 3B 03 7C 24 0C 8B 74 24 10 51 F3 A6 75 05 83 C4 04 EB 0A 59 83 C3 04 40 3B 42 18 75 E2 3B 42 18 75 02 EB 35 8B 72 24 03 74 24 0C 52 BB 02 00 00 00 33 D2 F7 E3 5A 03 C6 33 C9 66 8B 08 8B 7A 1C 33 D2 BB 04 00 00 00 8B C1 F7 E3 03 44 24 0C 03 C7 8B 00 03 44 24 0C EB 02 33 C0 64 8F 05 00 00 00 00 83 C4 04 C2 08 00 E8 FA FD FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	rule PseudoSigner02DxPack10Anorganix
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SecureEXE30ZipWorx
	{
	strings:
			$a0 = { E9 B8 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule eXPressorv12CGSoftLabs
	{
	strings:
			$a0 = { 45 78 50 72 2D 76 2E 31 2E 32 2E }
	$a1 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? ?? 2B 05 84 ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 16 A1 ?? ?? ?? ?? 03 05 80 ?? ?? ?? 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 68 04 }
	$a2 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? ?? 2B 05 84 ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 16 A1 ?? ?? ?? ?? 03 05 80 ?? ?? ?? 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 68 04 01 00 00 8D 85 F0 FE FF FF 50 6A 00 FF 15 }

	condition:
			$a0 or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
	}
	
	
	rule NullsoftPIMPInstallSystemv13x
	{
	strings:
			$a0 = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Enigmaprotector110111VladimirSukhov
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 }
	$a1 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 FF 15 89 C4 61 EB 2E EA EB 2B 83 04 24 03 EB 01 00 31 C0 EB 01 85 64 FF 30 EB 01 83 64 89 20 EB 02 CD 20 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 90 58 61 EB 01 3E EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 01 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 05 F6 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 B9 3D 1A }

	condition:
			$a0 or $a1
	}
	
	
	rule PECompactv140b5v140b6
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 8A 11 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxExplosion1000
	{
	strings:
			$a0 = { E8 ?? ?? 5E 1E 06 50 81 ?? ?? ?? 56 FC B8 21 35 CD 21 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 26 ?? ?? ?? ?? ?? ?? 74 ?? 8C D8 48 8E D8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PKZIPSFXv11198990
	{
	strings:
			$a0 = { FC 2E 8C 0E ?? ?? A1 ?? ?? 8C CB 81 C3 ?? ?? 3B C3 72 ?? 2D ?? ?? 2D ?? ?? FA BC ?? ?? 8E D0 FB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEBundlev20b5v23
	{
	strings:
			$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 01 AD ?? ?? ?? ?? 01 AD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PUNiSHERV15DemoFEUERRADER
	{
	strings:
			$a0 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule HACKSTOPv110v111
	{
	strings:
			$a0 = { B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 2F CD 21 B0 ?? B4 4C CD 21 50 B8 ?? ?? 58 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium1336ObsidiumSoftware
	{
	strings:
			$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 }

	condition:
			$a0
	}
	
	
	rule DualseXeEncryptor10bDual
	{
	strings:
			$a0 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 3A 04 00 00 89 28 33 FF 8D 85 80 03 00 00 8D 8D 3A 04 00 00 2B C8 8B 9D 8A 04 00 00 E8 24 02 00 00 8D 9D 58 03 00 00 8D B5 7F 03 00 00 46 80 3E 00 74 24 56 FF 95 58 05 00 00 46 80 3E 00 75 FA 46 80 3E 00 74 E7 50 56 50 FF 95 5C 05 00 00 89 03 58 83 C3 04 EB E3 8D 85 69 02 00 00 FF D0 8D 85 56 04 00 00 50 68 1F 00 02 00 6A 00 8D 85 7A 04 00 00 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MarjinZEXEScramblerSEbyMarjinZ
	{
	strings:
			$a0 = { E8 A3 02 00 00 E9 35 FD FF FF FF 25 C8 20 00 10 6A 14 68 C0 21 00 10 E8 E4 01 00 00 FF 35 7C 33 00 10 8B 35 8C 20 00 10 FF D6 59 89 45 E4 83 F8 FF 75 0C FF 75 08 FF 15 88 20 00 10 59 EB 61 6A 08 E8 02 03 00 00 59 83 65 FC 00 FF 35 7C 33 00 10 FF D6 89 45 E4 FF 35 78 33 00 10 FF D6 89 45 E0 8D 45 E0 50 8D 45 E4 50 FF 75 08 E8 D1 02 00 00 89 45 DC FF 75 E4 8B 35 74 20 00 10 FF D6 A3 7C 33 00 10 FF 75 E0 FF D6 83 C4 1C A3 78 33 00 10 C7 45 FC FE FF FF FF E8 09 00 00 00 8B 45 DC E8 A0 01 00 00 C3 }

	condition:
			$a0
	}
	
	
	rule nPack111502006BetaNEOx
	{
	strings:
			$a0 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DingBoysPElockPhantasmv15b3
	{
	strings:
			$a0 = { 9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED 5B 53 40 00 B0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ShellModify01pll621
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 98 66 41 00 68 3C 3D 41 00 64 A1 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01MacromediaFlashProjector60Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Packman0001Bubbasoft
	{
	strings:
			$a0 = { 0F 85 ?? FF FF FF 8D B3 ?? ?? ?? ?? EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36 0B F6 75 02 8B F7 03 F3 03 FB EB 1B D1 C1 D1 E9 73 05 0F B7 C9 EB 05 03 CB 8D 49 02 50 51 50 FF 55 04 AB 58 83 C6 04 8B 0E 85 C9 75 DF 5E 83 C6 14 8B 7E 10 85 FF 75 BC 8D 8B 00 }

	condition:
			$a0
	}
	
	
	rule aPackv098bDSESnotsaved
	{
	strings:
			$a0 = { 8C CB BA ?? ?? 03 DA FC 33 F6 33 FF 4B 8E DB 8D ?? ?? ?? 8E C0 B9 ?? ?? F3 A5 4A 75 }

	condition:
			$a0
	}
	
	
	rule ASProtectvIfyouknowthisversionpostonPEiDboardh2
	{
	strings:
			$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule Aluwainv809
	{
	strings:
			$a0 = { 8B EC 1E E8 ?? ?? 9D 5E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AntiDote12DLLDemoSISTeam
	{
	strings:
			$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF }

	condition:
			$a0
	}
	
	
	rule MSLRHv032afakeMicrosoftVisualCemadicius
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 83 C4 0C 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SoftwareCompressV12BGSoftwareProtectTechnologies
	{
	strings:
			$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Themida1201OreansTechnologies
	{
	strings:
			$a0 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? 35 09 89 95 ?? ?? 35 09 89 B5 ?? ?? 35 09 89 85 ?? ?? 35 09 83 BD ?? ?? 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 }

	condition:
			$a0
	}
	
	
	rule PECompactv126b1v126b2
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? 05 0E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Cruncherv10
	{
	strings:
			$a0 = { 2E ?? ?? ?? ?? 2E ?? ?? ?? B4 30 CD 21 3C 03 73 ?? BB ?? ?? 8E DB 8D ?? ?? ?? B4 09 CD 21 06 33 C0 50 CB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AntiDote1214SEDLLSISTeam
	{
	strings:
			$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC 11 DB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASProtectSKE21xexeAlexeySolodovnikov
	{
	strings:
			$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule DBPEv210DingBoy
	{
	strings:
			$a0 = { EB 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? EB 58 75 73 65 72 33 32 2E 64 6C 6C ?? 4D 65 73 73 61 67 65 42 6F 78 41 ?? 6B 65 72 6E 65 6C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPacKV37LiuXingPing
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 80 39 01 0F ?? ?? ?? 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElock099tE
	{
	strings:
			$a0 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WinZipSelfExtractor22personaleditionWinZipComputing
	{
	strings:
			$a0 = { 53 FF 15 58 70 40 00 B3 22 38 18 74 03 80 C3 FE 40 33 D2 8A 08 3A CA 74 10 3A CB 74 07 40 8A 08 3A CA 75 F5 38 10 74 01 40 52 50 52 52 FF 15 5C 70 40 00 50 E8 15 FB FF FF 50 FF 15 8C 70 40 00 5B }

	condition:
			$a0 at (pe.entry_point)
	}
/*	
	rule Securom7SonyDADC
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 8B ?? ?? ?? ?? 0A ?? ?? ?? ?? ?? ?? E8 }

	condition:
			$a0 at (pe.entry_point)
	}
*/	
	
	rule ZipWorxSecureEXEv25ZipWORXTechnologiesLLC
	{
	strings:
			$a0 = { E9 B8 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 53 65 63 75 72 65 45 58 45 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 28 63 29 20 32 30 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackFullEdition117iBoxaPLibAp0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 79 29 00 00 8D 9D 2C 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Alloyv1x2000
	{
	strings:
			$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 46 23 40 ?? 0B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeJoiner153Stubengine171GlOFF
	{
	strings:
			$a0 = { E8 02 FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A8 10 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule PseudoSigner02MicrosoftVisualC70DLLAnorganix
	{
	strings:
			$a0 = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EYouDiDaiYueHeiFengGao
	{
	strings:
			$a0 = { 55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 57 0F 31 8B D8 0F 31 8B D0 2B D3 C1 EA 10 B8 ?? ?? ?? ?? 0F 6E C0 B8 ?? ?? ?? ?? 0F 6E C8 0F F5 C1 0F 7E C0 0F 77 03 C2 ?? ?? ?? ?? ?? FF E0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptorV21Xsoftcompletecom
	{
	strings:
			$a0 = { 83 C6 14 8B 55 FC E9 ?? FF FF FF }
	$a1 = { E9 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 }

	condition:
			$a0 or $a1 at (pe.entry_point)
	}
	
	
	rule PCShrinkerv045
	{
	strings:
			$a0 = { BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule yodasProtectorV1033AshkbizDanehkar
	{
	strings:
			$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2D E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SoftSentryv211
	{
	strings:
			$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv120EngdulekxtBorlandDelphiBorlandC
	{
	strings:
			$a0 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakeStonesPEEncryptor20FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 53 51 52 56 57 55 E8 00 00 00 00 5D 81 ED 42 30 40 00 FF 95 32 35 40 00 B8 37 30 40 00 03 C5 2B 85 1B 34 40 00 89 85 27 34 40 00 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov300
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RCryptorv11Vaska
	{
	strings:
			$a0 = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 }
	$a1 = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

	condition:
			$a0 or $a1
	}
	
	
	rule Fusion10jaNooNi
	{
	strings:
			$a0 = { 68 04 30 40 00 68 04 30 40 00 E8 09 03 00 00 68 04 30 40 00 E8 C7 02 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UpxLock1012CyberDoomTeamXBoBBobSoft
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PCPEEncryptorAlphapreview
	{
	strings:
			$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 ?? 2B 8D EE 32 40 00 83 E9 0B 89 8D F2 32 40 ?? 80 BD D1 32 40 ?? 01 0F 84 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxKeypress1212
	{
	strings:
			$a0 = { E8 ?? ?? E8 ?? ?? E8 ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EA ?? ?? ?? ?? 1E 33 DB 8E DB BB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SoftwareCompressv12BGSoftwareProtectTechnologies
	{
	strings:
			$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 1A 0F 41 00 89 44 24 1C 61 C2 04 00 E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPackV14LiuXingPing
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VProtectorV11Avcasm
	{
	strings:
			$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium1300ObsidiumSoftware
	{
	strings:
			$a0 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 22 EB 02 ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 47 26 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule XXPack01bagie
	{
	strings:
			$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 00 68 00 ?? ?? ?? C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeLocker10IonIce
	{
	strings:
			$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule yodasProtectorV101AshkbizDanehkar
	{
	strings:
			$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED D5 E4 41 00 8B D5 81 C2 23 E5 41 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule ASPackv2001AlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 72 05 00 00 EB 4C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule USERNAMEv300
	{
	strings:
			$a0 = { FB 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 8C C8 2B C1 8B C8 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 33 C0 8E D8 06 0E 07 FC 33 F6 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule nSpackV2xLiuXingPing
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 }

	condition:
			$a0
	}
	
	
	rule GameGuardv20065xxdllsignbyhot_UNP
	{
	strings:
			$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 BA 4C 00 00 00 80 7C 24 08 01 0F 85 ?? 01 00 00 60 BE 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upack_PatchoranyVersionDwing
	{
	strings:
			$a0 = { 60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PCPECalpha
	{
	strings:
			$a0 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B CD 81 ?? ?? ?? ?? ?? 2B ?? ?? ?? ?? ?? 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv305c4Unextractable
	{
	strings:
			$a0 = { 03 05 00 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Escargot01finalMeat
	{
	strings:
			$a0 = { EB 04 40 30 2E 31 60 68 61 ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 92 ?? ?? ?? 8B 00 FF D0 50 B8 CD ?? ?? ?? 81 38 DE C0 37 13 75 2D 68 C9 ?? ?? ?? 6A 40 68 00 ?? 00 00 68 00 00 ?? ?? B8 96 ?? ?? ?? 8B 00 FF D0 8B 44 24 F0 8B 4C 24 F4 EB 05 49 C6 04 01 40 0B C9 75 F7 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B 46 0C BB 00 00 ?? ?? 03 C3 50 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MetrowerksCodeWarriorv20GUI
	{
	strings:
			$a0 = { 55 89 E5 53 56 83 EC 44 55 B8 FF FF FF FF 50 50 68 ?? ?? 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 }

	condition:
			$a0
	}
	
	
	rule UnnamedScrambler21Beta211p0ke
	{
	strings:
			$a0 = { 55 8B EC B9 15 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? 3A ?? ?? E8 ?? EE FF FF 33 C0 55 68 ?? 43 ?? ?? 64 FF 30 64 89 20 BA ?? 43 ?? ?? B8 E4 64 ?? ?? E8 0F FD FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? EE FF FF BA E8 64 ?? ?? 8B C3 8B 0D E4 64 ?? ?? E8 ?? D7 FF FF B8 F8 ?? ?? ?? BA 04 00 00 00 E8 ?? EF FF FF 33 C0 A3 F8 ?? ?? ?? BB ?? ?? ?? ?? C7 45 EC E8 64 ?? ?? C7 45 E8 ?? ?? ?? ?? C7 45 E4 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? B8 E0 ?? ?? ?? BA 04 00 00 00 E8 ?? EF FF FF 68 F4 01 00 00 E8 ?? EE FF FF 83 7B 04 00 75 0B 83 3B 00 0F 86 ?? 07 00 00 EB 06 0F 8E ?? 07 00 00 8B 03 8B D0 B8 E4 ?? ?? ?? E8 ?? E5 FF FF B8 E4 ?? ?? ?? E8 ?? E3 FF FF 8B D0 8B 45 EC 8B 0B E8 }

	condition:
			$a0
	}
	
	
	rule NoodleCryptv20
	{
	strings:
			$a0 = { EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 }
	$a1 = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	
	rule PoPa001PackeronPascalbagie
	{
	strings:
			$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 A4 3E 00 10 E8 30 F6 FF FF 33 C0 55 68 BE 40 00 10 ?? ?? ?? ?? 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 62 E7 FF FF 8B 45 EC E8 32 F2 FF FF 50 E8 B4 F6 FF FF A3 64 66 00 10 33 D2 55 68 93 40 00 10 64 FF 32 64 89 22 83 3D 64 66 00 10 FF 0F 84 3A 01 00 00 6A 00 6A 00 6A 00 A1 64 66 00 10 50 E8 9B F6 FF FF 83 E8 10 50 A1 64 66 00 10 50 E8 BC F6 FF FF 6A 00 68 80 66 00 10 6A 10 68 68 66 00 10 A1 64 66 00 10 50 E8 8B F6 FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule BlindSpot10s134k
	{
	strings:
			$a0 = { 55 8B EC 81 EC 50 02 00 00 8D 85 B0 FE FF FF 53 56 A3 90 12 40 00 57 8D 85 B0 FD FF FF 68 00 01 00 00 33 F6 50 56 FF 15 24 10 40 00 56 68 80 00 00 00 6A 03 56 56 8D 85 B0 FD FF FF 68 00 00 00 80 50 FF 15 20 10 40 00 56 56 68 00 08 00 00 50 89 45 FC FF 15 1C 10 40 00 8D 45 F8 8B 1D 18 10 40 00 56 50 6A 34 FF 35 90 12 40 00 FF 75 FC FF D3 85 C0 0F 84 7F 01 00 00 39 75 F8 0F 84 76 01 00 00 A1 90 12 40 00 66 8B 40 30 66 3D 01 00 75 14 8D 85 E4 FE FF FF 68 04 01 00 00 50 FF 15 14 10 40 00 EB 2C 66 3D 02 00 75 14 8D 85 E4 FE FF FF 50 68 04 01 00 00 FF 15 10 10 40 00 EB 12 8D 85 E4 FE FF FF 68 04 01 00 00 50 FF 15 0C 10 40 00 8B 3D 08 10 40 00 8D 85 E4 FE FF FF 68 54 10 40 00 50 }

	condition:
			$a0
	}
	
	
	rule GamehouseMediaProtectorVersionUnknown
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 00 00 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElockv042
	{
	strings:
			$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 52 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEStealthv274WebToolMaster
	{
	strings:
			$a0 = { EB 00 EB 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 90 E8 00 00 00 00 5D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEManagerVersion301994cSolarDesigner
	{
	strings:
			$a0 = { B4 30 1E 06 CD 21 2E ?? ?? ?? BF ?? ?? B9 ?? ?? 33 C0 2E ?? ?? 47 E2 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule Upackv02BetaDwing
	{
	strings:
			$a0 = { BE 88 01 ?? ?? AD 8B F8 95 A5 33 C0 33 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DEFv100Engbartxt
	{
	strings:
			$a0 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AnslymCrypter
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A 68 30 1C 05 10 A1 60 56 05 10 50 E8 68 47 FB FF 8B D8 85 DB 0F 84 B6 02 00 00 53 A1 60 56 05 10 50 E8 F2 48 FB FF 8B F0 85 F6 0F 84 A0 02 00 00 E8 F3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ARMProtectorv02SMoKE
	{
	strings:
			$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 09 20 40 00 EB 02 83 09 8D B5 9A 20 40 00 EB 02 83 09 BA 0B 12 00 00 EB 01 00 8D 8D A5 32 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CrypKeyV56XDLLKenonicControlsLtd
	{
	strings:
			$a0 = { 8B 1D ?? ?? ?? ?? 83 FB 00 75 0A E8 ?? ?? ?? ?? E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEiDBundlev102v104BoBBobSoft
	{
	strings:
			$a0 = { 60 E8 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxHeloween1172
	{
	strings:
			$a0 = { E8 ?? ?? 5E 81 EE ?? ?? 56 50 06 0E 1F 8C C0 01 ?? ?? 01 ?? ?? 80 ?? ?? ?? ?? 8B ?? ?? A3 ?? ?? 8A ?? ?? A2 ?? ?? B8 ?? ?? CD 21 3D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PackedwithPKLITEv150withCRCcheck1
	{
	strings:
			$a0 = { 1F B4 09 BA ?? ?? CD 21 B8 ?? ?? CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Pe123v2006412
	{
	strings:
			$a0 = { 8B C0 60 9C E8 01 00 00 00 C3 53 E8 72 00 00 00 50 E8 1C 03 00 00 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DropperCreatorV01Conflict
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 8D 05 ?? ?? ?? ?? 29 C5 8D 85 ?? ?? ?? ?? 31 C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 }

	condition:
			$a0
	}
	
	
	rule XCRv013
	{
	strings:
			$a0 = { 93 71 08 ?? ?? ?? ?? ?? ?? ?? ?? 8B D8 78 E2 ?? ?? ?? ?? 9C 33 C3 ?? ?? ?? ?? 60 79 CE ?? ?? ?? ?? E8 01 ?? ?? ?? ?? 83 C4 04 E8 AB FF FF FF ?? ?? ?? ?? 2B E8 ?? ?? ?? ?? 03 C5 FF 30 ?? ?? ?? ?? C6 ?? EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule XCRv012
	{
	strings:
			$a0 = { 60 9C E8 ?? ?? ?? ?? 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule InnoSetupModulev129
	{
	strings:
			$a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 E0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov3xx
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule dUP2xPatcherwwwdiablo2oo2cjbnet
	{
	strings:
			$a0 = { 8B CB 85 C9 74 ?? 80 3A 01 74 08 AC AE 75 0A 42 49 EB EF 47 46 42 49 EB E9 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner02PEProtect09Anorganix
	{
	strings:
			$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule pscrambler12byp0ke
	{
	strings:
			$a0 = { 55 8B EC B9 04 00 00 00 6A 00 6A 00 49 75 F9 51 53 ?? ?? ?? ?? 10 E8 2D F3 FF FF 33 C0 55 68 E8 31 00 10 64 FF 30 64 89 20 8D 45 E0 E8 53 F5 FF FF 8B 45 E0 8D 55 E4 E8 30 F6 FF FF 8B 45 E4 8D 55 E8 E8 A9 F4 FF FF 8B 45 E8 8D 55 EC E8 EE F7 FF FF 8B 55 EC B8 C4 54 00 10 E8 D9 EC FF FF 83 3D C4 54 00 10 00 0F 84 05 01 00 00 80 3D A0 40 00 10 00 74 41 A1 C4 54 00 10 E8 D9 ED FF FF E8 48 E0 FF FF 8B D8 A1 C4 54 00 10 E8 C8 ED FF FF 50 B8 C4 54 00 10 E8 65 EF FF FF 8B D3 59 E8 69 E1 FF FF 8B C3 E8 12 FA FF FF 8B C3 E8 33 E0 FF FF E9 AD 00 00 00 B8 05 01 00 00 E8 0C E0 FF FF 8B D8 53 68 05 01 00 00 E8 57 F3 FF FF 8D 45 DC 8B D3 E8 39 ED FF FF 8B 55 DC B8 14 56 00 10 B9 00 32 00 10 E8 BB ED FF FF 8B 15 14 56 00 10 B8 C8 54 00 10 E8 53 E5 FF FF BA 01 00 00 00 B8 C8 54 00 10 E8 8C E8 FF FF E8 DF E0 FF FF 85 C0 75 52 6A 00 A1 C4 54 00 10 E8 3B ED FF FF 50 B8 C4 54 00 10 E8 D8 EE FF FF 8B D0 B8 C8 54 00 10 59 E8 3B E6 FF FF E8 76 E0 FF FF B8 C8 54 00 10 E8 4C E6 FF FF E8 67 E0 FF FF 6A 00 6A 00 6A 00 A1 14 56 00 10 E8 53 EE FF FF 50 6A 00 6A 00 E8 41 F3 FF FF 80 3D 9C 40 00 10 00 74 05 E8 EF FB FF FF 33 C0 5A 59 59 64 89 10 68 EF 31 00 10 8D 45 DC BA 05 00 00 00 E8 7D EB FF FF C3 E9 23 E9 FF FF EB EB 5B E8 63 EA FF FF 00 00 00 FF FF FF FF 08 00 00 00 74 65 6D 70 2E 65 78 65 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor2223compressedcodewwwstrongbitcom
	{
	strings:
			$a0 = { E8 00 00 00 00 58 ?? ?? ?? ?? ?? 8B 1C 24 81 EB ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 6A 04 68 00 10 00 00 50 6A 00 B8 C4 ?? ?? ?? 8B 04 18 FF D0 59 BA ?? ?? ?? ?? 01 DA 52 53 50 89 C7 89 D6 FC F3 A4 B9 ?? ?? ?? ?? 01 D9 FF D1 58 8B 1C 24 68 00 80 00 00 6A 00 50 }
	$a1 = { E8 00 00 00 00 58 ?? ?? ?? ?? ?? 8B 1C 24 81 EB ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 6A 04 68 00 10 00 00 50 6A 00 B8 C4 ?? ?? ?? 8B 04 18 FF D0 59 BA ?? ?? ?? ?? 01 DA 52 53 50 89 C7 89 D6 FC F3 A4 B9 ?? ?? ?? ?? 01 D9 FF D1 58 8B 1C 24 68 00 80 00 00 6A 00 50 B8 C8 ?? ?? ?? 8B 04 18 FF D0 59 58 5B 83 EB 05 C6 03 B8 43 89 03 83 C3 04 C6 03 C3 09 C9 74 46 89 C3 E8 A0 00 00 00 FC AD 83 F8 FF 74 38 53 89 CB 01 C3 01 0B 83 C3 04 AC 3C FE 73 07 25 FF 00 00 00 EB ED 81 C3 FE 00 00 00 09 C0 7A 09 66 AD 25 FF FF 00 00 EB DA AD 4E 25 FF FF FF 00 3D FF FF FF 00 75 CC ?? ?? ?? ?? ?? C3 }

	condition:
			$a0 or $a1
	}
	
	
	rule Armadillov265b1
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 38 ?? ?? ?? 68 40 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 F4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackV112V114aPlib043ap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF EB 0F FF ?? ?? ?? FF ?? ?? ?? D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB }

	condition:
			$a0
	}
	
	
	rule PolyCryptPE214b215JLabSoftwareCreationshoep
	{
	strings:
			$a0 = { 91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB }

	condition:
			$a0
	}
	rule yodasProtector10xAshkbizDanehkar
	{
	strings:
			$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upack_UnknownDLLDwing
	{
	strings:
			$a0 = { 60 E8 09 00 00 00 17 CD 00 00 E9 06 02 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AINEXEv21
	{
	strings:
			$a0 = { A1 ?? ?? 2D ?? ?? 8E D0 BC ?? ?? 8C D8 36 A3 ?? ?? 05 ?? ?? 36 A3 ?? ?? 2E A1 ?? ?? 8A D4 B1 04 D2 EA FE C9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AppProtectorSilentTeam
	{
	strings:
			$a0 = { E9 97 00 00 00 0D 0A 53 69 6C 65 6E 74 20 54 65 61 6D 20 41 70 70 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 72 65 61 74 65 64 20 62 79 20 53 69 6C 65 6E 74 20 53 6F 66 74 77 61 72 65 0D 0A 54 68 65 6E 6B 7A 20 74 6F 20 44 6F 63 68 74 6F 72 20 58 0D 0A 0D 0A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RODHighTECHAyman
	{
	strings:
			$a0 = { 60 8B 15 1D 13 40 00 F7 E0 8D 82 83 19 00 00 E8 58 0C 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ICrypt10byBuGGz
	{
	strings:
			$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 70 3B 00 10 E8 3C FA FF FF 33 C0 55 68 6C 3C 00 10 64 FF 30 64 89 20 6A 0A 68 7C 3C 00 10 A1 50 56 00 10 50 E8 D8 FA FF FF 8B D8 53 A1 50 56 00 10 50 E8 0A FB FF FF 8B F8 53 A1 50 56 00 10 50 E8 D4 FA FF FF 8B D8 53 E8 D4 FA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 64 56 00 10 E8 25 F6 FF FF B8 64 56 00 10 E8 13 F6 FF FF 8B CF 8B D6 E8 E6 FA FF FF 53 E8 90 FA FF FF 8D 4D EC BA 8C 3C 00 10 A1 64 56 00 10 E8 16 FB FF FF 8B 55 EC B8 64 56 00 10 E8 C5 F4 FF FF B8 64 56 00 10 E8 DB F5 FF FF E8 56 FC FF FF 33 C0 5A 59 59 64 89 10 68 73 3C 00 10 8D 45 EC E8 4D F4 FF FF C3 E9 E3 EE FF FF EB F0 5F 5E 5B E8 4D F3 FF FF 00 53 45 54 ?? ?? ?? ?? 00 FF FF FF FF 08 00 00 00 76 6F 74 72 65 63 6C 65 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEPackv099
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 83 ED 06 80 BD E0 04 ?? ?? 01 0F 84 F2 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackV115V117LZMA430ap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 83 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB 14 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxQuake518
	{
	strings:
			$a0 = { 1E 06 8C C8 8E D8 ?? ?? ?? ?? ?? ?? ?? B8 21 35 CD 21 81 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv305c4UnextractableVirusShield
	{
	strings:
			$a0 = { 03 05 40 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium13013ObsidiumSoftware
	{
	strings:
			$a0 = { EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 13 26 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule ObsidiumV130XObsidiumSoftware
	{
	strings:
			$a0 = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B ?? ?? ?? EB 04 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MetrowerksCodeWarriorv20Console
	{
	strings:
			$a0 = { 55 89 E5 55 B8 FF FF FF FF 50 50 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 }

	condition:
			$a0
	}
	
	
	rule PESpinv07Cyberbob
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SimpleUPXCryptorV3042005MANtiCORE
	{
	strings:
			$a0 = { 60 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? ?? ?? ?? ?? E2 FA 61 68 ?? ?? ?? ?? C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WinRAR32bitSFXModule
	{
	strings:
			$a0 = { E9 ?? ?? 00 00 00 00 00 00 90 90 90 ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule iPBProtect013017forgot
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakeASPack211demadicius
	{
	strings:
			$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv036alphaDwing
	{
	strings:
			$a0 = { AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0 }

	condition:
			$a0
	}
	
	
	rule CrinklerV03V04RuneLHStubbeandAskeSimonChristensen
	{
	strings:
			$a0 = { B8 00 00 42 00 31 DB 43 EB 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DingBoysPElockPhantasmv10v11
	{
	strings:
			$a0 = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactV2XBitsumTechnologies
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule CRYPTVersion17cDismember
	{
	strings:
			$a0 = { 0E 17 9C 58 F6 ?? ?? 74 ?? E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxXPEH4768
	{
	strings:
			$a0 = { E8 ?? ?? 5B 81 ?? ?? ?? 50 56 57 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B8 01 00 50 B8 ?? ?? 50 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECrypt32v102
	{
	strings:
			$a0 = { E8 00 00 00 00 5B 83 ?? ?? EB ?? 52 4E 44 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01PESHiELD025Anorganix
	{
	strings:
			$a0 = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NETDLLMicrosoft
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 44 6C 6C 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 ?? 00 00 FF 25 }

	condition:
			$a0
	}
	
	
	rule MSLRH
	{
	strings:
			$a0 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule BeRoEXEPackerv100DLLLZMABeRoFarbrausch
	{
	strings:
			$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02ExeSmasherAnorganix
	{
	strings:
			$a0 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ObsidiumV125ObsidiumSoftware
	{
	strings:
			$a0 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
    
    	rule ASPackv107bDLLAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MicroJoiner17coban2k
	{
	strings:
			$a0 = { BF 00 10 40 00 8D 5F 21 6A 0A 58 6A 04 59 60 57 E8 8E 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakeVOBProtectCDFEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 5F 81 EF 00 00 00 00 BE 00 00 40 00 8B 87 00 00 00 00 03 C6 57 56 8C A7 00 00 00 00 FF 10 89 87 00 00 00 00 5E 5F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CelsiusCrypt21Z3r0
	{
	strings:
			$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 84 92 44 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 84 92 44 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D C4 92 44 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D AC 92 44 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 77 C2 00 00 90 90 90 90 90 90 90 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 1C 1A 01 00 89 C1 8B 45 08 8B 55 E8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 8D 45 E8 FF 00 EB BF 83 7D F0 00 74 34 80 7D EF 00 74 2E 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 DD 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 EB C6 C7 44 24 04 00 00 00 00 8B 45 10 89 04 24 E8 AE 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 7F 0C 0F B6 45 EF 83 E0 01 88 45 E7 EB 04 C6 45 E7 00 0F B6 45 E7 88 45 EF 0F B6 45 EF C9 C3 }
	$a1 = { 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 1C 1A 01 00 89 C1 8B 45 08 8B 55 E8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 8D 45 E8 FF 00 EB BF 83 7D F0 00 74 34 80 7D EF 00 74 2E 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 DD 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 EB C6 C7 44 24 04 00 00 00 00 8B 45 10 89 04 24 E8 AE 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 7F 0C 0F B6 45 EF 83 E0 01 88 45 E7 EB 04 C6 45 E7 00 0F B6 45 E7 88 45 EF 0F B6 45 EF C9 C3 }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	
	rule Armadillov260
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 D0 ?? ?? ?? 68 34 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 68 ?? ?? ?? 33 D2 8A D4 89 15 84 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov261
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 28 ?? ?? ?? 68 E4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 0C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakeASPack212emadicius
	{
	strings:
			$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 A0 02 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RatPackerGluestub
	{
	strings:
			$a0 = { 40 20 FF 00 00 00 00 00 00 00 ?? BE 00 60 40 00 8D BE 00 B0 FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CreateInstallv200335
	{
	strings:
			$a0 = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40 }

	condition:
			$a0
	}
	
	
	rule SPECb3
	{
	strings:
			$a0 = { 5B 53 50 45 43 5D E8 ?? ?? ?? ?? 5D 8B C5 81 ED 41 24 40 ?? 2B 85 89 26 40 ?? 83 E8 0B 89 85 8D 26 40 ?? 0F B6 B5 91 26 40 ?? 8B FD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SPECb2
	{
	strings:
			$a0 = { 55 57 51 53 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 09 89 85 ?? ?? ?? ?? 0F B6 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser
	{
	strings:
			$a0 = { FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner01MicrosoftVisualBasic5060Anorganix
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXModifiedStubbFarbrauschConsumerConsulting
	{
	strings:
			$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule E2CbyDoP
	{
	strings:
			$a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? FC 57 F3 A5 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SVKProtectorv111
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PCShrinkerv071
	{
	strings:
			$a0 = { 9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Petite21
	{
	strings:
			$a0 = { 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 }

	condition:
			$a0
	}
	
	
	rule BeRoEXEPackerv100DLLLZBRRBeRoFarbrausch
	{
	strings:
			$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule hmimysPackerV12hmimys
	{
	strings:
			$a0 = { E8 95 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5E AD 50 AD 50 97 AD 50 AD 50 AD 50 E8 C0 01 00 00 AD 50 AD 93 87 DE B9 ?? ?? ?? ?? E3 1D 8A 07 47 04 ?? 3C ?? 73 F7 8B 07 3C ?? 75 F3 B0 00 0F C8 05 ?? ?? ?? ?? 2B C7 AB E2 E3 AD 85 C0 74 2B 97 56 FF 13 8B E8 AC 84 C0 75 FB 66 AD 66 85 C0 74 E9 AC 83 EE 03 84 C0 74 08 56 55 FF 53 04 AB EB E4 AD 50 55 FF 53 04 AB EB E0 C3 8B 0A 3B 4A 04 75 0A C7 42 10 01 00 00 00 0C FF C3 }

	condition:
			$a0 at (pe.entry_point)
	}
rule EnigmaProtector131Build20070615DllSukhovVladimirSergeNMarkin
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 81 ED ?? ?? ?? ?? E9 49 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 8A 84 24 28 00 00 00 80 F8 01 0F 84 07 00 00 00 B8 ?? ?? ?? ?? FF E0 E9 04 00 00 00 ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 81 C0 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 30 10 40 49 0F 85 F6 FF FF FF E9 04 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PureBasicDLLNeilHodgson
	{
	strings:
			$a0 = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule HPA
	{
	strings:
			$a0 = { E8 ?? ?? 5E 8B D6 83 ?? ?? 83 ?? ?? 06 0E 1E 0E 1F 33 FF 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov310
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upack012betaDwing
	{
	strings:
			$a0 = { BE 48 01 40 00 AD ?? ?? ?? A5 ?? C0 33 C9 ?? ?? ?? ?? ?? ?? ?? F3 AB ?? ?? 0A ?? ?? ?? ?? AD 50 97 51 ?? 87 F5 58 8D 54 86 5C ?? D5 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B6 5F FF C1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxNcuLi1688
	{
	strings:
			$a0 = { 0E 1E B8 55 AA CD 21 3D 49 4C 74 ?? 0E 0E 1F 07 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VProtectorvcasm
	{
	strings:
			$a0 = { 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 47 44 49 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 53 6C 65 65 70 00 00 00 47 65 74 56 65 72 73 69 6F 6E 00 00 00 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 00 00 47 65 74 53 74 61 72 74 75 70 49 6E 66 6F 41 00 00 00 47 65 74 41 43 50 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 47 65 74 44 43 00 00 00 52 65 6C 65 61 73 65 44 43 00 00 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 00 00 44 65 73 74 72 6F 79 57 69 6E 64 6F 77 00 00 00 53 65 74 50 69 78 65 6C }
	$a1 = { 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 47 44 49 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 53 6C 65 65 70 00 00 00 47 65 74 56 65 72 73 69 6F 6E 00 00 00 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 00 00 47 65 74 53 74 61 72 74 75 70 49 6E 66 6F 41 00 00 00 47 65 74 41 43 50 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 47 65 74 44 43 00 00 00 52 65 6C 65 61 73 65 44 43 00 00 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 00 00 44 65 73 74 72 6F 79 57 69 6E 64 6F 77 00 00 00 53 65 74 50 69 78 65 6C 00 00 00 00 }
	$a2 = { 00 00 00 00 55 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 64 69 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 47 65 74 44 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 52 65 6C 65 61 73 65 44 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 }

	condition:
			$a0 or $a1 or $a2
	}
	rule XPackv142
	{
	strings:
			$a0 = { 72 ?? C3 8B DE 83 ?? ?? C1 ?? ?? 8C D8 03 C3 8E D8 8B DF 83 ?? ?? C1 ?? ?? 8C C0 03 C3 8E C0 C3 }

	condition:
			$a0
	}
	
	
	rule W32JeefoPEFileInfector
	{
	strings:
			$a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A 02 A1 C8 ?? ?? ?? FF D0 E8 ?? ?? ?? ?? C9 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeSplitter13SplitCryptMethodBillPrisonerTPOC
	{
	strings:
			$a0 = { 15 10 05 23 14 56 57 57 48 12 0B 16 66 66 66 66 66 66 66 66 66 02 C7 56 66 66 66 ED 26 6A ED 26 6A ED 66 E3 A6 69 E2 39 64 66 66 ED 2E 56 E6 5F 0D 12 61 E6 5F 2D 12 64 8D 81 E6 1F 6A 55 12 64 8D B9 ED 26 7E A5 33 ED 8A 8D 69 21 03 12 36 14 09 05 27 02 02 14 03 15 15 27 ED 2B 6A ED 13 6E ED B8 65 10 5A EB 10 7E EB 10 06 ED 50 65 95 30 ED 10 46 65 95 55 B4 ED A0 ED 50 65 95 37 ED 2B 6A EB DF AB 76 26 66 3F DF 68 66 66 66 9A 95 C0 6D AF 13 64 }
	$a1 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 B9 ?? ?? ?? ?? 8D 85 1D 10 40 00 80 30 66 40 E2 FA 8F 98 67 66 66 ?? ?? ?? ?? ?? ?? ?? 66 }

	condition:
			$a0 or $a1 at (pe.entry_point)
	}
	
	
	rule AntiDote12BetaDemoSISTeam
	{
	strings:
			$a0 = { 68 69 D6 00 00 E8 C6 FD FF FF 68 69 D6 00 00 E8 BC FD FF FF 83 C4 08 E8 A4 FF FF FF 84 C0 74 2F 68 04 01 00 00 68 B0 21 60 00 6A 00 FF 15 08 10 60 00 E8 29 FF FF FF 50 68 88 10 60 00 68 78 10 60 00 68 B0 21 60 00 E8 A4 FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 90 90 90 90 90 90 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv211bAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor224StrongbitSoftCompleteDevelopmenth1
	{
	strings:
			$a0 = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor224StrongbitSoftCompleteDevelopmenth2
	{
	strings:
			$a0 = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 ?? 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor224StrongbitSoftCompleteDevelopmenth3
	{
	strings:
			$a0 = { 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
			$a0
	}
	
	
	rule ProActivateV10XTurboPowerSoftwareCompany
	{
	strings:
			$a0 = { 55 8B EC B9 0E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? ?? ?? ?? 90 90 90 90 90 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 A1 ?? ?? ?? ?? 83 C0 05 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0D 00 00 00 E8 85 E2 FF FF 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 7A 81 3D ?? ?? ?? ?? 43 52 43 33 75 6E 81 3D ?? ?? ?? ?? 32 40 7E 7E 75 62 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 56 81 3D ?? ?? ?? ?? 43 52 43 33 75 4A 81 3D ?? ?? ?? ?? 32 40 7E 7E 75 3E 81 3D ?? ?? ?? ?? 21 7E 7E 40 75 32 81 3D ?? ?? ?? ?? 43 52 43 33 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PackMasterv10
	{
	strings:
			$a0 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED D3 22 40 00 E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
	$a1 = { 60 E8 01 ?? ?? ?? E8 83 C4 04 E8 01 ?? ?? ?? E9 5D 81 ED D3 22 40 ?? E8 04 02 ?? ?? E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule DBPEv153
	{
	strings:
			$a0 = { 9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? B0 ?? E8 ?? ?? ?? ?? 5E 83 C6 11 B9 27 ?? ?? ?? 30 06 46 49 75 FA }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeJoiner152Stubengine16GlOFF
	{
	strings:
			$a0 = { E8 46 FD FF FF 50 E8 0C 00 00 00 FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASProtectv12AlexeySolodovnikovh1
	{
	strings:
			$a0 = { 90 60 E8 1B 00 00 00 E9 FC 8D B5 0F 06 00 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB 04 5D 45 55 C3 E9 ?? ?? ?? 00 }

	condition:
			$a0
	}
	
	
	rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualCx
	{
	strings:
			$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PENightMare2Beta
	{
	strings:
			$a0 = { 60 E9 ?? ?? ?? ?? EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule MinGWGCC3x
	{
	strings:
			$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? ?? E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? 55 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PIRITv15
	{
	strings:
			$a0 = { B4 4D CD 21 E8 ?? ?? FD E8 ?? ?? B4 51 CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Reg2Exe224byJanVorel
	{
	strings:
			$a0 = { 6A 00 E8 CF 20 00 00 A3 F4 45 40 00 E8 CB 20 00 00 6A 0A 50 6A 00 FF 35 F4 45 40 00 E8 07 00 00 00 50 E8 BB 20 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 F8 45 40 00 E8 06 19 00 00 83 C4 0C 8B 44 24 04 A3 FC 45 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 8C 20 00 00 A3 F8 45 40 00 E8 02 20 00 00 E8 32 1D 00 00 E8 20 19 00 00 E8 A3 16 00 00 68 01 00 00 00 68 38 46 40 00 68 00 00 00 00 8B 15 38 46 40 00 E8 71 4F 00 00 B8 00 00 10 00 BB 01 00 00 00 E8 82 4F 00 00 FF 35 48 41 40 00 B8 00 01 00 00 E8 9D 15 00 00 8D 0D 1C 46 40 00 5A E8 82 16 00 00 68 00 01 00 00 FF 35 1C 46 40 00 E8 24 20 00 00 A3 24 46 40 00 FF 35 48 41 40 00 FF 35 24 46 40 00 FF 35 1C 46 40 00 E8 DC 10 00 00 8D 0D 14 46 40 00 5A E8 4A 16 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SVKProtectorv13xEngPavolCerven
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThinstallEmbedded2609Jitit
	{
	strings:
			$a0 = { E8 00 00 00 00 58 BB AD 19 00 00 2B C3 50 68 ?? ?? ?? ?? 68 B0 1C 00 00 68 80 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXcrypterarchphaseNWC
	{
	strings:
			$a0 = { BF ?? ?? ?? 00 81 FF ?? ?? ?? 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 ?? ?? 00 FF E3 BE ?? ?? ?? 00 FF E6 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule StarForceProtectionDriverProtectionTechnology
	{
	strings:
			$a0 = { 57 68 ?? 0D 01 00 68 00 ?? ?? 00 E8 50 ?? FF FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FishPEV10Xhellfish
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 ?? ?? 00 00 ?? ?? ?? ?? 00 00 02 00 00 00 A0 00 00 18 01 00 00 ?? ?? ?? ?? 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 C0 00 00 40 39 00 00 ?? ?? ?? ?? 00 00 08 00 00 00 00 01 00 C8 06 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECrypter
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D EB 26 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElockv051
	{
	strings:
			$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule LY_WGKXwwwszleyucom
	{
	strings:
			$a0 = { 4D 79 46 75 6E 00 62 73 }

	condition:
			$a0
	}
	
	
	rule ASProtect13321RegisteredAlexeySolodovnikov
	{
	strings:
			$a0 = { 68 01 ?? ?? ?? E8 01 00 00 00 C3 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackV111ap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtMicrosoftVisualC4xLCCWin321x
	{
	strings:
			$a0 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule dePACKdeNULL
	{
	strings:
			$a0 = { EB 01 DD 60 68 00 ?? ?? ?? 68 ?? ?? 00 00 E8 ?? 00 00 00 }
	$a1 = { EB 01 DD 60 68 00 ?? ?? ?? 68 ?? ?? ?? 00 E8 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? D2 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule EXECryptorv1401
	{
	strings:
			$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakePELockNT204emadicius
	{
	strings:
			$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 03 CD 20 EB EB 03 CD 20 03 61 9D 83 C4 04 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	rule PELockNTv203
	{
	strings:
			$a0 = { EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Reg2Exe220221byJanVorel
	{
	strings:
			$a0 = { 6A 00 E8 7D 12 00 00 A3 A0 44 40 00 E8 79 12 00 00 6A 0A 50 6A 00 FF 35 A0 44 40 00 E8 0F 00 00 00 50 E8 69 12 00 00 CC CC CC CC CC CC CC CC CC 68 2C 02 00 00 68 00 00 00 00 68 B0 44 40 00 E8 3A 12 00 00 83 C4 0C 8B 44 24 04 A3 B8 44 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 32 12 00 00 A3 B0 44 40 00 68 F4 01 00 00 68 BC 44 40 00 FF 35 B8 44 40 00 E8 1E 12 00 00 B8 BC 44 40 00 89 C1 8A 30 40 80 FE 5C 75 02 89 C1 80 FE 00 75 F1 C6 01 00 E8 EC 18 00 00 E8 28 16 00 00 E8 4A 12 00 00 68 00 FA 00 00 68 08 00 00 00 FF 35 B0 44 40 00 E8 E7 11 00 00 A3 B4 44 40 00 8B 15 D4 46 40 00 E8 65 0A 00 00 BB 00 00 10 00 B8 01 00 00 00 E8 72 0A 00 00 74 09 C7 00 01 00 00 00 83 C0 04 A3 D4 46 40 00 FF 35 B4 44 40 00 E8 26 05 00 00 8D 0D B8 46 40 00 5A E8 CF 0F 00 00 FF 35 B4 44 40 00 FF 35 B8 46 40 00 E8 EE 06 00 00 8D 0D B4 46 40 00 5A E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PELockNTv201
	{
	strings:
			$a0 = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PELockNTv204
	{
	strings:
			$a0 = { EB ?? CD ?? ?? ?? ?? ?? CD ?? ?? ?? ?? ?? EB ?? EB ?? EB ?? EB ?? CD ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 50 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXFreakv01BorlandDelphiHMX0101
	{
	strings:
			$a0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 }
	$a1 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 34 50 45 00 ?? ?? ?? 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 40 00 00 C0 00 00 ?? ?? ?? ?? 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? 77 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 77 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule Obsidium13017Obsidiumsoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Petite22c199899IanLuck
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 68 00 00 ?? ?? 8B 3C 24 8B 30 66 81 C7 80 07 8D 74 06 08 89 38 8B 5E 10 50 56 6A 02 68 80 08 00 00 57 6A ?? 6A 06 56 6A 04 68 80 08 00 00 57 FF D3 83 EE 08 59 F3 A5 59 66 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PluginToExev101BoBBobSoft
	{
	strings:
			$a0 = { E8 00 00 00 00 29 C0 5D 81 ED C6 41 40 00 50 8F 85 71 40 40 00 50 FF 95 A5 41 40 00 89 85 6D 40 40 00 FF 95 A1 41 40 00 50 FF 95 B5 41 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 B9 41 40 00 89 85 75 40 40 00 EB 6C 6A 01 8F 85 71 40 40 00 6A 58 6A 40 FF 95 A9 41 40 00 89 85 69 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 A9 41 40 00 89 47 1C C7 07 58 00 00 00 C7 47 20 00 08 00 00 C7 47 18 01 00 00 00 C7 47 34 04 10 88 00 8D 8D B9 40 40 00 89 4F 0C 8D 8D DB 40 40 00 89 4F 30 FF B5 69 40 40 00 FF 95 95 41 40 00 FF 77 1C 8F 85 75 40 40 00 8B 9D 6D 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 75 40 40 00 6A 00 81 C3 ?? ?? 00 00 FF D3 83 C4 10 83 BD 71 40 40 00 00 74 10 FF 77 1C FF 95 AD 41 40 00 57 FF 95 AD 41 40 00 6A 00 FF 95 9D 41 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Enigmaprotector110unregistered
	{
	strings:
			$a0 = { 60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89 }
	$a1 = { 60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89 E9 51 0B C4 80 BC 7E 35 09 37 E7 C9 3D C9 45 C9 4D 74 92 BA E4 E9 24 6B DF 3E 0E 38 0C 49 10 27 80 51 A1 8E 3A A3 C8 AE 3B 1C 35 }

	condition:
			$a0 or $a1
	}
	
	
	rule Obsidium1341ObsidiumSoftware
	{
	strings:
			$a0 = { EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 C3 27 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WebCopsDLLLINKDataSecurity
	{
	strings:
			$a0 = { A8 BE 58 DC D6 CC C4 63 4A 0F E0 02 BB CE F3 5C 50 23 FB 62 E7 3D 2B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01PackMaster10PEXCloneAnorganix
	{
	strings:
			$a0 = { 60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv037v038BetaStripbaserelocationtableOptionDwing
	{
	strings:
			$a0 = { 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 }

	condition:
			$a0
	}
	
	
	rule AHTeamEPProtector03fakeSVKP13xFEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 00 00 00 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule InstallShieldCustom
	{
	strings:
			$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? 41 00 8B F0 85 F6 75 08 6A FF FF 15 ?? ?? 41 00 8A 06 57 8B 3D ?? ?? 41 00 3C 22 75 1B 56 FF D7 8B F0 8A 06 3C 22 74 04 84 C0 75 F1 80 3E 22 75 15 56 FF D7 8B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Petitevafterv14
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8D ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeToolsv21EncruptorbyDISMEMBER
	{
	strings:
			$a0 = { E8 ?? ?? 5D 83 ?? ?? 1E 8C DA 83 ?? ?? 8E DA 8E C2 BB ?? ?? BA ?? ?? 85 D2 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NTkrnlSecureSuiteNTkrnlteam
	{
	strings:
			$a0 = { 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }

	condition:
			$a0
	}
	
	
	rule PESpinv0b
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 26 E8 01 00 00 00 EA 5A 33 C9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VXTibsZhelatinStormWormvariant
	{
	strings:
			$a0 = { FF 74 24 1C 58 8D 80 ?? ?? 77 04 50 68 62 34 35 04 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakePEX099emadicius
	{
	strings:
			$a0 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED FF 22 40 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NSPack3xLiuXingPing
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv25RetailBitsumTechnologies
	{
	strings:
			$a0 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WARNINGTROJANXiaoHui
	{
	strings:
			$a0 = { 60 9C E8 00 00 00 00 5D B8 ?? 85 40 00 2D ?? 85 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NFOv10
	{
	strings:
			$a0 = { 8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8 8C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PMODEWv112116121133DOSextender
	{
	strings:
			$a0 = { FC 16 07 BF ?? ?? 8B F7 57 B9 ?? ?? F3 A5 06 1E 07 1F 5F BE ?? ?? 06 0E A4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AaseCrypterbysantasdad
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 53 B8 A0 3E 00 10 E8 93 DE FF FF 68 F8 42 00 10 E8 79 DF FF FF 68 00 43 00 10 68 0C 43 00 10 E8 42 DF FF FF 50 E8 44 DF FF FF A3 98 66 00 10 83 3D 98 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 1C 43 00 10 6A 00 E8 4B DF FF FF 68 2C 43 00 10 68 0C 43 ?? ?? ?? ?? DF FF FF 50 E8 0E DF FF FF A3 94 66 00 10 83 3D 94 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 38 43 00 10 6A 00 E8 15 DF FF FF 68 48 43 00 10 68 0C 43 00 10 E8 D6 DE FF FF 50 E8 D8 DE FF FF A3 A0 66 00 10 83 3D A0 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 58 43 00 10 6A 00 E8 DF DE FF FF 68 6C 43 00 10 68 0C 43 00 10 E8 A0 DE FF FF 50 E8 A2 DE FF FF }

	condition:
			$a0
	}
	
	
	rule aPackv098bJibz
	{
	strings:
			$a0 = { 93 07 1F 05 ?? ?? 8E D0 BC ?? ?? EA }

	condition:
			$a0
	}
	
	
	rule UPackv011Dwing
	{
	strings:
			$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 1C F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 03 B3 00 8D 1C 5B 8D 9C 9E 0C 10 00 00 B0 01 67 E3 29 8B D7 }

	condition:
			$a0
	}
	rule NsPacKNetLiuXingPing
	{
	strings:
			$a0 = { 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 BB 01 47 65 74 53 79 73 74 65 6D 49 6E 66 6F 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 5E 00 5F 43 6F 72 ?? ?? ?? 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C }

	condition:
			$a0
	}
	
	
	rule PseudoSigner02PENightMare2BetaAnorganix
	{
	strings:
			$a0 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01MicrosoftVisualC60DebugVersionAnorganix
	{
	strings:
			$a0 = { 55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DJoinv07publicRC4encryptiondrmist
	{
	strings:
			$a0 = { C6 05 ?? ?? 40 00 00 C6 05 ?? ?? 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXv103v104
	{
	strings:
			$a0 = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEDiminisherV01Teraphy
	{
	strings:
			$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv305c4ExtrPasswcheckVirshield
	{
	strings:
			$a0 = { 03 05 C0 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeGuarderv18Exeiconcom
	{
	strings:
			$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule codeCrypter031Tibbar
	{
	strings:
			$a0 = { 50 58 53 5B 90 BB ?? ?? ?? 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPv073betaap0x
	{
	strings:
			$a0 = { 60 8B DD E8 00 00 00 00 5D 95 32 C0 95 89 9D 80 00 00 00 B8 42 31 40 00 BB 41 30 40 00 2B C3 03 C5 33 D2 8A 10 40 B9 ?? ?? 00 00 8B F9 30 10 8A 10 40 49 75 F8 64 EF 86 3D 30 00 00 0F B9 FF 4B 89 52 5C 4C BD 77 C2 0C CE 88 4E 2D E8 00 00 00 5D 0D DB 5E 56 }

	condition:
			$a0
	}
/*	
	rule XtremeProtectorv105
	{
	strings:
			$a0 = { E9 ?? ?? 00 00 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
*/	
	
	rule PEnguinCryptv10
	{
	strings:
			$a0 = { B8 93 ?? ?? 00 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 00 00 58 5D BB 00 00 40 00 33 C9 33 C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule MetrowerksCodeWarriorDLLv20
	{
	strings:
			$a0 = { 55 89 E5 53 56 57 8B 75 0C 8B 5D 10 83 FE 01 74 05 83 FE 02 75 12 53 56 FF 75 08 E8 6E FF FF FF 09 C0 75 04 31 C0 EB 21 53 56 FF 75 08 E8 ?? ?? ?? ?? 89 C7 09 F6 74 05 83 FE 03 75 0A 53 56 FF 75 08 E8 47 FF FF FF 89 F8 8D 65 F4 5F 5E 5B 5D C2 0C 00 C9 }

	condition:
			$a0
	}
	
	
	rule PECrc32088ZhouJinYu
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED B6 A4 45 00 8D BD B0 A4 45 00 81 EF 82 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv123b3v1241
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 08 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Noodlecrypt2rsc
	{
	strings:
			$a0 = { EB 01 9A E8 76 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPack120BasicEditionLZMAAp0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 9C 0C 00 00 EB 0C 8B 85 98 0C 00 00 89 85 9C 0C 00 00 8D B5 C4 0C 00 00 8D 9D 82 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 2D 0C 00 00 89 85 94 0C 00 00 E8 59 01 00 00 EB 20 60 8B 85 9C 0C 00 00 FF B5 94 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01PENightMare2BetaAnorganix
	{
	strings:
			$a0 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakeXtremeProtector105FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E8 00 00 00 00 5D 81 00 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackv118BasicDLLLZMAAp0x
	{
	strings:
			$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A }

	condition:
			$a0 at (pe.entry_point)
	}
	rule CrypKeyv5v6
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? 58 83 E8 05 50 5F 57 8B F7 81 EF ?? ?? ?? ?? 83 C6 39 BA ?? ?? ?? ?? 8B DF B9 0B ?? ?? ?? 8B 06 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule InnoSetupModulev109a
	{
	strings:
			$a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ObsidiumV1300ObsidiumSoftware
	{
	strings:
			$a0 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 }
	$a1 = { EB 04 ?? ?? ?? ?? E8 ?? 00 00 00 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	rule PCryptv351
	{
	strings:
			$a0 = { 50 43 52 59 50 54 FF 76 33 2E 35 31 00 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThinstallEmbedded2312Jitit
	{
	strings:
			$a0 = { 6A 00 FF 15 ?? ?? ?? ?? E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv305c4Extractable
	{
	strings:
			$a0 = { 03 05 00 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule RLPackAp0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 CD 09 00 00 89 85 14 0A 00 00 EB 14 60 FF B5 14 0A }
	$a1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 EB 09 00 00 89 85 3A 0A 00 00 EB 14 60 FF B5 3A 0A }
	$a2 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 0C 00 00 EB 03 0C 00 00 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 47 02 00 00 EB 03 15 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 9B 0A }
	$a3 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 CD 09 00 00 89 85 ?? ?? ?? ?? EB 14 60 FF B5 14 0A }
	$a4 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85 ?? ?? ?? ?? EB 14 60 FF B5 3A 0A }
	$a5 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 ?? ?? ?? ?? EB 03 ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 9B 0A }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point) or $a3 at (pe.entry_point) or $a4 at (pe.entry_point) or $a5 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02VOBProtectCD5Anorganix
	{
	strings:
			$a0 = { 36 3E 26 8A C0 60 E8 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
		rule PESpinv04x
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B }

	condition:
			$a0
	}
	
	
	rule PseudoSigner02WatcomCCDLLAnorganix
	{
	strings:
			$a0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule yodasCrypter13AshkbizDanehkar
	{
	strings:
			$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule D1NS1GD1N
	{
	strings:
			$a0 = { 18 37 00 00 00 00 00 00 01 00 0A 00 00 00 18 00 00 80 00 00 00 00 ?? ?? 18 37 00 00 00 00 02 00 00 00 88 00 00 80 38 00 00 80 96 00 00 80 50 00 00 80 00 00 00 00 ?? ?? 18 37 00 00 00 00 00 00 01 00 00 00 00 00 68 00 00 00 00 00 00 00 ?? ?? 18 37 00 00 00 00 00 00 01 00 00 00 00 00 78 00 00 00 B0 F0 00 00 10 00 00 00 00 00 00 00 00 00 00 00 C0 F0 00 00 60 00 00 00 00 00 00 00 00 00 00 00 06 00 44 00 56 00 43 00 4C 00 41 00 4C 00 0B 00 50 00 41 00 43 00 4B 00 41 00 47 00 45 00 49 00 4E 00 46 00 4F 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule FSGv110EngdulekxtMicrosoftVisualC6070ASM
	{
	strings:
			$a0 = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule ASPackv102aAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01MinGWGCC2xAnorganix
	{
	strings:
			$a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov253
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 54 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }
	$a1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 40 ?? ?? ?? ?? 68 54 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 58 33 D2 8A D4 89 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	rule Armadillov252
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? E0 ?? ?? ?? ?? 68 D4 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 38 }
	$a1 = { 55 8B EC 6A FF 68 E0 ?? ?? ?? 68 D4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 38 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule Armadillov251
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov250
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium1331ObsidiumSoftware
	{
	strings:
			$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 02 ?? ?? E8 5F 27 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CExev10a
	{
	strings:
			$a0 = { 55 8B EC 81 EC 0C 02 ?? ?? 56 BE 04 01 ?? ?? 8D 85 F8 FE FF FF 56 50 6A ?? FF 15 54 10 40 ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule DIETv144v145f
	{
	strings:
			$a0 = { F8 9C 06 1E 57 56 52 51 53 50 0E FC 8C C8 BA ?? ?? 03 D0 52 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv098
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D7 84 40 ?? 87 DD 8B 85 5C 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv099
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 ?? 87 DD 8B 85 B4 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPacKV30LiuXingPing
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? ?? ?? 66 8B 06 66 83 F8 00 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtMicrosoftVisualBasic5060
	{
	strings:
			$a0 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv090
	{
	strings:
			$a0 = { EB 06 68 ?? ?? 40 00 C3 9C 60 BD ?? ?? 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv092
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD A5 4F 40 ?? F3 AA 01 AD 04 51 40 ?? FF B5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv094
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PeX099bartCrackPl
	{
	strings:
			$a0 = { E9 F5 ?? ?? ?? 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ObsidiumV1304ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 ?? 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SoftwareCompressv14LITEBGSoftwareProtectTechnologies
	{
	strings:
			$a0 = { E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00 29 04 24 8B 04 24 89 85 5D 1A 41 00 58 8B 85 5D 1A 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 03 D0 8B 4A 58 89 8D 49 1A 41 00 8B 4A 5C 89 8D 4D 1A 41 00 8B 4A 60 89 8D 55 1A }
	$a1 = { E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00 29 04 24 8B 04 24 89 85 5D 1A 41 00 58 8B 85 5D 1A 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 03 D0 8B 4A 58 89 8D 49 1A 41 00 8B 4A 5C 89 8D 4D 1A 41 00 8B 4A 60 89 8D 55 1A 41 00 8B 4A 64 89 8D 51 1A 41 00 8B 4A 74 89 8D 59 1A 41 00 68 00 20 00 00 E8 D2 00 00 00 50 8D 8D 00 1C 41 00 50 51 E8 1B 00 00 00 83 C4 08 58 8D 78 74 8D B5 49 1A 41 00 B9 18 00 00 00 F3 A4 05 A4 00 00 00 50 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 4D 1A 41 00 89 44 24 1C 61 C2 04 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	rule FixupPakv120
	{
	strings:
			$a0 = { 55 E8 00 00 00 00 5D 81 ED ?? ?? 00 00 BE 00 ?? 00 00 03 F5 BA 00 00 ?? ?? 2B D5 8B DD 33 C0 AC 3C 00 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F B6 C8 3C 00 74 06 3C 01 74 09 EB 0A 66 AD 0F B7 C8 EB 03 AD 8B C8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ARCSFXArchive
	{
	strings:
			$a0 = { 8C C8 8C DB 8E D8 8E C0 89 ?? ?? ?? 2B C3 A3 ?? ?? 89 ?? ?? ?? BE ?? ?? B9 ?? ?? BF ?? ?? BA ?? ?? FC AC 32 C2 8A D8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MoleBoxv230Teggo
	{
	strings:
			$a0 = { 42 04 E8 ?? ?? 00 00 A3 ?? ?? ?? 00 8B 4D F0 8B 11 89 15 ?? ?? ?? 00 ?? 45 FC A3 ?? ?? ?? 00 5F 5E 8B E5 5D C3 CC CC CC CC CC CC CC CC CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 20 61 58 FF D0 E8 ?? ?? 00 00 CC CC CC CC CC CC CC }

	condition:
			$a0
	}
	
	
	rule VxIgor
	{
	strings:
			$a0 = { 1E B8 CD 7B CD 21 81 FB CD 7B 75 03 E9 87 00 33 DB 0E 1F 8C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FACRYPTv10
	{
	strings:
			$a0 = { B9 ?? ?? B3 ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 49 43 32 E4 03 D0 E3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01WATCOMCCEXEAnorganix
	{
	strings:
			$a0 = { E9 00 00 00 00 90 90 90 90 57 41 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackV115V117aPlib043ap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EmbedPEv113cyclotron
	{
	strings:
			$a0 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 }

	condition:
			$a0 at (pe.entry_point)
	}
	
rule eXcaliburv103forgotus
	{
	strings:
			$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 20 45 78 63 61 6C 69 62 75 72 20 28 63 29 20 62 79 20 66 6F 72 67 6F 74 2F 75 53 2F 44 46 43 47 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Petite14
	{
	strings:
			$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }

	condition:
			$a0
	}
	rule Petite12
	{
	strings:
			$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Petite13
	{
	strings:
			$a0 = { 66 9C 60 50 8D 88 00 F0 00 00 8D 90 04 16 00 00 8B DC 8B E1 }

	condition:
			$a0
	}
	
/*	
	rule StarForceV1XV3XStarForceCopyProtectionSystem
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
*/	
	
	rule Upack021betaDwing
	{
	strings:
			$a0 = { BE 88 01 40 00 AD 8B F8 6A 04 95 A5 33 C0 AB 48 AB F7 D8 59 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WebCopsEXELINKDataSecurity
	{
	strings:
			$a0 = { EB 03 05 EB 02 EB FC 55 EB 03 EB 04 05 EB FB EB 53 E8 04 00 00 00 72 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02FSG10Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThemidaOreansTechnologies2004
	{
	strings:
			$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxNumberOne
	{
	strings:
			$a0 = { F9 07 3C 53 6D 69 6C 65 3E E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WinKriptv10MrCrimson
	{
	strings:
			$a0 = { 33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 83 C0 08 EB D5 61 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElockv085f
	{
	strings:
			$a0 = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RosAsm2050aBetov
	{
	strings:
			$a0 = { 55 8B EC 60 8B 5D 08 B9 08 00 00 00 BF ?? ?? ?? ?? 83 C7 07 FD 8A C3 24 0F 04 30 3C 39 76 02 04 07 AA C1 EB 04 E2 EE FC 68 00 10 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 61 8B E5 5D C2 04 00 }

	condition:
			$a0
	}
	
	
	rule Obsidium13021ObsidiumSoftware
	{
	strings:
			$a0 = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 26 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule ASPackv211dAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv211cAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ACProtect14xRISCOsoft
	{
	strings:
			$a0 = { 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 }

	condition:
			$a0
	}
	
	
	rule SplashBitmapv100BoBBobsoft
	{
	strings:
			$a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 6A 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEZipv10byBaGIE
	{
	strings:
			$a0 = { D9 D0 F8 74 02 23 DB F5 F5 50 51 52 53 8D 44 24 10 50 55 56 57 D9 D0 22 C9 C1 F7 A0 55 66 C1 C8 B0 5D 81 E6 FF FF FF FF F8 77 07 52 76 03 72 01 90 5A C1 E0 60 90 BD 1F 01 00 00 87 E8 E2 07 E3 05 17 5D 47 E4 42 41 7F 06 50 66 83 EE 00 58 25 FF FF FF FF 51 }

	condition:
			$a0
	}
	rule LamerStopv10ccStefanEsser
	{
	strings:
			$a0 = { E8 ?? ?? 05 ?? ?? CD 21 33 C0 8E C0 26 ?? ?? ?? 2E ?? ?? ?? 26 ?? ?? ?? 2E ?? ?? ?? BA ?? ?? FA }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ACProtectV14Xrisco
	{
	strings:
			$a0 = { 60 E8 01 00 00 00 7C 83 04 24 06 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxGRUNT2Family
	{
	strings:
			$a0 = { 48 E2 F7 C3 51 53 52 E8 DD FF 5A 5B 59 C3 B9 00 00 E2 FE C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakeMicrosoftVisualC70FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 00 8B F4 89 3E 56 FF 15 ?? ?? ?? ?? 8B 4E ?? 89 0D ?? ?? ?? 00 8B 46 00 A3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule InstallStub32bit
	{
	strings:
			$a0 = { 55 8B EC 81 EC 14 ?? 00 00 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 29 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule VcasmProtector10evcasm
	{
	strings:
			$a0 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakePEBundle20x24xemadicius
	{
	strings:
			$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 83 BD 9C 38 40 00 01 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov190b4
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 08 E2 40 00 68 B4 96 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXv103v104Modified
	{
	strings:
			$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPackV2XLiuXingPing
	{
	strings:
			$a0 = { 6E 73 70 61 63 6B 24 40 }

	condition:
			$a0
	}
	
	
	rule ThemidaWinLicenseV1000V1800OreansTechnologies
	{
	strings:
			$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PACKWINv101p
	{
	strings:
			$a0 = { 8C C0 FA 8E D0 BC ?? ?? FB 06 0E 1F 2E ?? ?? ?? ?? 8B F1 4E 8B FE 8C DB 2E ?? ?? ?? ?? 8E C3 FD F3 A4 53 B8 ?? ?? 50 CB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PECompactv110b1
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 ?? 87 DD 8B 85 AD 63 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MicroJoiner15coban2k
	{
	strings:
			$a0 = { BF 05 10 40 00 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ANDpakk2018byDmitryANDAndreev
	{
	strings:
			$a0 = { FC BE D4 00 40 00 BF 00 ?? ?? 00 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD 00 FB FF FF 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv110b2
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 94 60 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv110b5
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 49 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NJoy10NEX
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 B8 9C 3B 40 00 E8 8C FC FF FF 6A 00 68 E4 39 40 00 6A 0A 6A 00 E8 40 FD FF FF E8 EF F5 FF FF 8D 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv110b7
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB 14 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv110b6
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 ?? 00 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB B7 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule KBysPacker028BetaShoooo
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5E 83 EE 0A 8B 06 03 C2 8B 08 89 4E F3 83 EE 0F 56 52 8B F0 AD AD 03 C2 8B D8 6A 04 BF 00 10 00 00 57 57 6A 00 FF 53 08 5A 59 BD 00 80 00 00 55 6A 00 50 51 52 50 89 06 AD AD 03 C2 50 AD 03 C2 FF D0 6A 04 57 AD 50 6A 00 FF 53 }

	condition:
			$a0
	}
	
	
	rule nPack113002006BetaNEOx
	{
	strings:
			$a0 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8 2D 02 00 00 E8 DD 06 00 00 E8 2C 06 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule PseudoSigner02BorlandC1999Anorganix
	{
	strings:
			$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 ?? ?? ?? ?? A3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv100bAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SEAAXEv22
	{
	strings:
			$a0 = { FC BC ?? ?? 0E 1F A3 ?? ?? E8 ?? ?? A1 ?? ?? 8B ?? ?? ?? 2B C3 8E C0 B1 03 D3 E3 8B CB BF ?? ?? 8B F7 F3 A5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PureBasic4xDLLNeilHodgson
	{
	strings:
			$a0 = { 83 7C 24 08 01 75 0E 8B 44 24 04 A3 ?? ?? ?? 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEPackerv70byTurboPowerSoftware
	{
	strings:
			$a0 = { 1E 06 8C C3 83 ?? ?? 2E ?? ?? ?? ?? B9 ?? ?? 8C C8 8E D8 8B F1 4E 8B FE }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxSYP
	{
	strings:
			$a0 = { 47 8B C2 05 1E 00 52 8B D0 B8 02 3D CD 21 8B D8 5A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DSHIELD
	{
	strings:
			$a0 = { 06 E8 ?? ?? 5E 83 EE ?? 16 17 9C 58 B9 ?? ?? 25 ?? ?? 2E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule kkrunchy023alphaRyd
	{
	strings:
			$a0 = { BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 8D 9D A0 08 00 00 E8 ?? 00 00 00 8B 45 10 EB 42 8D 9D A0 04 00 00 E8 ?? 00 00 00 49 49 78 40 8D 5D 20 74 03 83 C3 40 31 D2 42 E8 ?? 00 00 00 8D 0C 48 F6 C2 10 74 F3 41 91 8D 9D A0 08 00 00 E8 ?? 00 00 00 3D 00 08 00 00 83 D9 FF 83 F8 60 83 D9 FF 89 45 10 56 89 FE 29 C6 F3 A4 5E EB 90 BE ?? ?? ?? 00 BB ?? ?? ?? 00 55 46 AD 85 C0 74 ?? 97 56 FF 13 85 C0 74 16 95 AC 84 C0 75 FB 38 06 74 E8 78 ?? 56 55 FF 53 04 AB 85 C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule NJoy12NEX
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 B8 A4 32 40 00 E8 E8 F1 FF FF 6A 00 68 54 2A 40 00 6A 0A 6A 00 E8 A8 F2 FF FF E8 C7 EA FF FF 8D 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AntiDote12DemoSISTeam
	{
	strings:
			$a0 = { E8 F7 FE FF FF 05 CB 22 00 00 FF E0 E8 EB FE FF FF 05 BB 19 00 00 FF E0 E8 BD 00 00 00 08 B2 62 00 01 52 17 0C 0F 2C 2B 20 7F 52 79 01 30 07 17 29 4F 01 3C 30 2B 5A 3D C7 26 11 26 06 59 0E 78 2E 10 14 0B 13 1A 1A 3F 64 1D 71 33 57 21 09 24 8B 1B 09 37 08 61 0F 1D 1D 2A 01 87 35 4C 07 39 0B }

	condition:
			$a0
	}
	
	
	rule EXE32Packv137
	{
	strings:
			$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED 4C 8E 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXE32Packv136
	{
	strings:
			$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED CC 8D 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AINEXEv230
	{
	strings:
			$a0 = { 0E 07 B9 ?? ?? BE ?? ?? 33 FF FC F3 A4 A1 ?? ?? 2D ?? ?? 8E D0 BC ?? ?? 8C D8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule ThinstallEmbedded20XJitit
	{
	strings:
			$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptorv151x
	{
	strings:
			$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 C1 ?? ?? ?? FE C3 31 C0 64 FF 30 64 89 20 CC C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidiumv1304ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 }
	$a1 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? E8 3B 26 00 00 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule CopyProtectorv20
	{
	strings:
			$a0 = { 2E A2 ?? ?? 53 51 52 1E 06 B4 ?? 1E 0E 1F BA ?? ?? CD 21 1F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXE32Packv139
	{
	strings:
			$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED EC 8D 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXE32Packv138
	{
	strings:
			$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B DB 74 01 BE 5D 8B D5 81 ED DC 8D 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtBorlandC1999
	{
	strings:
			$a0 = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule ThinstallEmbedded2547V2600Jitit
	{
	strings:
			$a0 = { E8 00 00 00 00 58 BB BC 18 00 00 2B C3 50 68 ?? ?? ?? ?? 68 60 1B 00 00 68 60 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv131Engdulekxt
	{
	strings:
			$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule SDProtectorBasicProEdition110RandyLi
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 50 83 EC 08 64 A1 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 83 C4 08 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 64 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Petite12c1998IanLuck
	{
	strings:
			$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0A 00 0B 00 0D 00 0F 00 11 00 13 00 17 00 1B 00 1F 00 23 00 2B 00 33 00 3B 00 43 00 53 00 63 00 73 00 83 00 A3 00 C3 00 E3 00 02 01 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 01 02 02 02 }

	condition:
			$a0 at (pe.entry_point)
	}
		
	rule PcSharev40
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 90 34 40 00 68 B6 28 40 00 64 A1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VProtector0X12Xvcasm
	{
	strings:
			$a0 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 }

	condition:
			$a0
	}
/*    
	rule PKLITE32v11
	{
	strings:
			$a0 = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 00 00 00 5D C2 0C 00 8B 45 0C 57 56 53 8B 5D 10 }
	$a1 = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D 10 }
	$a2 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 00 00 00 00 E8 }
	$a3 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 44 24 0C 50 }
	$a4 = { 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31 }

	condition:
			$a0 at (pe.entry_point) or $a1 or $a2 at (pe.entry_point) or $a3 at (pe.entry_point) or $a4 at (pe.entry_point)
	}
	
*/	
	rule STNPEE113
	{
	strings:
			$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 97 3B 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SoftDefenderV11xRandyLi
	{
	strings:
			$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule CDCopsII
	{
	strings:
			$a0 = { 53 60 BD ?? ?? ?? ?? 8D 45 ?? 8D 5D ?? E8 ?? ?? ?? ?? 8D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPack11BasicEditionap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXE32Packv13x
	{
	strings:
			$a0 = { 3B ?? 74 02 81 83 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 ?? ?? ?? ?? ?? 02 81 ?? ?? E8 ?? ?? ?? ?? 3B 74 01 ?? 5D 8B D5 81 ED }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule VxInvoluntary1349
	{
	strings:
			$a0 = { BA ?? ?? B9 ?? ?? 8C DD ?? 8C C8 ?? 8E D8 8E C0 33 F6 8B FE FC ?? ?? AD ?? 33 C2 AB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WinZip32bit6x
	{
	strings:
			$a0 = { FF 15 FC 81 40 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPacKV36LiuXingPing
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 83 38 01 0F 84 47 02 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02LCCWin321xAnorganix
	{
	strings:
			$a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECrypt10ReBirth
	{
	strings:
			$a0 = { 90 90 60 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 4E 28 40 00 8B F7 AC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NJoy11NEX
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 B8 0C 3C 40 00 E8 24 FC FF FF 6A 00 68 28 3A 40 00 6A 0A 6A 00 E8 D8 FC FF FF E8 7F F5 FF FF 8D 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEcryptbyarchphase
	{
	strings:
			$a0 = { 55 8B EC 83 C4 E0 53 56 33 C0 89 45 E4 89 45 E0 89 45 EC ?? ?? ?? ?? 64 82 40 00 E8 7C C7 FF FF 33 C0 55 68 BE 84 40 00 64 FF 30 64 89 20 68 CC 84 40 00 ?? ?? ?? ?? 00 A1 10 A7 40 00 50 E8 1D C8 FF FF 8B D8 85 DB 75 39 E8 3A C8 FF FF 6A 00 6A 00 68 A0 A9 40 00 68 00 04 00 00 50 6A 00 68 00 13 00 00 E8 FF C7 FF FF 6A 00 68 E0 84 40 00 A1 A0 A9 40 00 50 6A 00 E8 ?? ?? ?? ?? E9 7D 01 00 00 53 A1 10 A7 40 00 50 E8 42 C8 FF FF 8B F0 85 F6 75 18 6A 00 68 E0 84 40 00 68 E4 84 40 00 6A 00 E8 71 C8 FF FF E9 53 01 00 00 53 6A 00 E8 2C C8 FF FF A3 ?? ?? ?? ?? 83 3D 48 A8 40 00 00 75 18 6A 00 68 E0 84 40 00 68 F8 84 40 00 6A 00 E8 43 C8 FF FF E9 25 01 00 00 56 E8 F8 C7 FF FF A3 4C A8 40 00 A1 48 A8 40 00 E8 91 A1 FF FF 8B D8 8B 15 48 A8 40 00 85 D2 7C 16 42 33 C0 8B 0D 4C A8 40 00 03 C8 8A 09 8D 34 18 88 0E 40 4A 75 ED 8B 15 48 A8 40 00 85 D2 7C 32 42 33 C0 8D 34 18 8A 0E 80 F9 01 75 05 C6 06 FF EB 1C 8D 0C 18 8A 09 84 ?? ?? ?? ?? ?? 00 EB 0E 8B 0D 4C A8 40 00 03 C8 0F B6 09 49 88 0E 40 4A 75 D1 8D ?? ?? ?? ?? E8 A5 A3 FF FF 8B 45 E8 8D 55 EC E8 56 D5 FF FF 8D 45 EC BA 18 85 40 00 E8 79 BA FF FF 8B 45 EC E8 39 BB FF FF 8B D0 B8 54 A8 40 00 E8 31 A6 FF FF BA 01 00 00 00 B8 54 A8 40 00 E8 12 A9 FF FF E8 DD A1 FF FF 68 50 A8 40 00 8B D3 8B 0D 48 A8 40 00 B8 54 A8 40 00 E8 56 A7 FF FF E8 C1 A1 FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule CrunchPEv30xx
	{
	strings:
			$a0 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? FF 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule LameCryptLaZaRus
	{
	strings:
			$a0 = { 60 66 9C BB 00 ?? ?? 00 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 B8 ?? ?? 40 00 FF E0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPack29NorthStar
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8A 06 3C 00 74 12 8B F5 8D B5 ?? ?? FF FF 8A 06 3C 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule BeRoEXEPackerv100LZBRSBeRoFarbrausch
	{
	strings:
			$a0 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtBorlandC
	{
	strings:
			$a0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB }
	$a1 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule VIRUSIWormKLEZ
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 40 D2 40 ?? 68 04 AC 40 ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 BC D0 }

	condition:
			$a0
	}
	
	
	rule YZPack12UsAr
	{
	strings:
			$a0 = { 4D 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PseudoSigner02LocklessIntroPackAnorganix
	{
	strings:
			$a0 = { 2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PKLITE3211
	{
	strings:
			$a0 = { 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv20bartxt
	{
	strings:
			$a0 = { 87 25 ?? ?? ?? 00 61 94 55 A4 B6 80 FF 13 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakeSVKP111emadicius
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 64 A0 23 00 00 00 83 C5 06 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtMASM32TASM32MicrosoftVisualBasic
	{
	strings:
			$a0 = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor239DLLminimumprotection
	{
	strings:
			$a0 = { 51 68 ?? ?? ?? ?? 87 2C 24 8B CD 5D 81 E1 ?? ?? ?? ?? E9 ?? ?? ?? 00 89 45 F8 51 68 ?? ?? ?? ?? 59 81 F1 ?? ?? ?? ?? 0B 0D ?? ?? ?? ?? 81 E9 ?? ?? ?? ?? E9 ?? ?? ?? 00 81 C2 ?? ?? ?? ?? E8 ?? ?? ?? 00 87 0C 24 59 51 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C E9 ?? ?? ?? 00 F7 D6 2B D5 E9 ?? ?? ?? 00 87 3C 24 8B CF 5F 87 14 24 1B CA E9 ?? ?? ?? 00 83 C4 08 68 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? 00 E9 ?? ?? ?? 00 50 8B C5 87 04 24 8B EC 51 0F 88 ?? ?? ?? 00 FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 99 03 04 24 E9 ?? ?? ?? 00 C3 81 D5 ?? ?? ?? ?? 9C E9 ?? ?? ?? 00 81 FA ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 15 81 CB ?? ?? ?? ?? 81 F3 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 87 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule Frusionbiff
	{
	strings:
			$a0 = { 83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule OpenSourceCodeCrypterp0ke
	{
	strings:
			$a0 = { 55 8B EC B9 09 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 34 44 40 00 E8 28 F8 FF FF 33 C0 55 68 9F 47 40 00 64 FF 30 64 89 20 BA B0 47 40 00 B8 1C 67 40 00 E8 07 FD FF FF 8B D8 85 DB 75 07 6A 00 E8 C2 F8 FF FF BA 28 67 40 00 8B C3 8B 0D 1C 67 40 00 E8 F0 E0 FF FF BE 01 00 00 00 B8 2C 68 40 00 E8 E1 F0 FF FF BF 0A 00 00 00 8D 55 EC 8B C6 E8 92 FC FF FF 8B 4D EC B8 2C 68 40 00 BA BC 47 40 00 E8 54 F2 FF FF A1 2C 68 40 00 E8 52 F3 FF FF 8B D0 B8 20 67 40 00 E8 A2 FC FF FF 8B D8 85 DB 0F 84 52 02 00 00 B8 24 67 40 00 8B 15 20 67 40 00 E8 78 F4 FF FF B8 24 67 40 00 E8 7A F3 FF FF 8B D0 8B C3 8B 0D 20 67 40 00 E8 77 E0 FF FF 8D 55 E8 A1 24 67 40 00 E8 42 FD FF FF 8B 55 E8 B8 24 67 40 00 }

	condition:
			$a0
	}
	
	
	rule QrYPt0rbyNuTraL
	{
	strings:
			$a0 = { 80 F9 00 0F 84 8D 01 00 00 8A C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 C1 3C F3 75 89 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BA D9 04 00 00 E8 00 00 00 00 5F 81 C7 16 01 00 00 80 2C 3A 01 }
	$a1 = { 86 18 CC 64 FF 35 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 89 25 00 00 00 00 BB 00 00 F7 BF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B8 78 56 34 12 87 03 E8 CD FE FF FF E8 B3 }
	$a2 = { EB 00 E8 B5 00 00 00 E9 2E 01 00 00 64 FF 35 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 89 25 00 00 00 00 8B 44 24 04 }

	condition:
			$a0 or $a1 or $a2 at (pe.entry_point)
	}
	
	
	rule EXECryptor2xxmaxcompressedresources
	{
	strings:
			$a0 = { 55 8B EC 83 C4 EC FC 53 57 56 89 45 FC 89 55 F8 89 C6 89 D7 66 81 3E 4A 43 0F 85 23 01 00 00 83 C6 0A C7 45 F4 08 00 00 00 31 DB BA 00 00 00 80 43 31 C0 E8 11 01 00 00 73 0E 8B 4D F0 E8 1F 01 00 00 02 45 EF AA EB E9 E8 FC 00 00 00 0F 82 97 00 00 00 E8 F1 00 00 00 73 5B B9 04 00 00 00 E8 FD 00 00 00 48 74 DE 0F 89 C7 00 00 00 E8 D7 00 00 00 73 1B 55 BD 00 01 00 00 E8 D7 00 00 00 88 07 47 4D 75 F5 E8 BF 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 C8 00 00 00 83 C0 07 89 45 F0 C6 45 EF 00 83 F8 08 74 89 E8 A9 00 00 00 88 45 EF E9 7C FF FF FF B9 07 00 00 00 E8 A2 00 00 00 50 }

	condition:
			$a0
	}
	
	
	rule Upackv024v028AlphaDwing
	{
	strings:
			$a0 = { BE 88 01 40 00 AD ?? ?? 95 AD 91 F3 A5 AD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThinstallEmbedded24222428Jitit
	{
	strings:
			$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D 9B 1A 00 00 B9 84 1A 00 00 BA 14 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD E0 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? 81 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SVKProtectorv1051
	{
	strings:
			$a0 = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakeZCode101FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PEPacker
	{
	strings:
			$a0 = { FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ProgramProtectorXPv10
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SimplePack111Method2NTbagieTMX
	{
	strings:
			$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032aemadicius
	{
	strings:
			$a0 = { E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 }
	$a1 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 }
	$a2 = { E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF FF FF 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C }

	condition:
			$a0 or $a1 or $a2 at (pe.entry_point)
	}
	
	
	rule VxHafen1641
	{
	strings:
			$a0 = { E8 ?? ?? 01 ?? ?? ?? CE CC 25 ?? ?? 25 ?? ?? 25 ?? ?? 40 51 D4 ?? ?? ?? CC 47 CA ?? ?? 46 8A CC 44 88 CC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NativeUDPacker11ModdedPoisonIvyShellcodeokkixot
	{
	strings:
			$a0 = { 31 C0 31 DB 31 C9 EB 0E 6A 00 6A 00 6A 00 6A 00 FF 15 28 41 40 00 FF 15 94 40 40 00 89 C7 68 88 13 00 00 FF 15 98 40 40 00 FF 15 94 40 40 00 81 C7 88 13 00 00 39 F8 73 05 E9 84 00 00 00 6A 40 68 00 10 00 00 FF 35 04 30 40 00 6A 00 FF 15 A4 40 40 00 89 C7 FF 35 04 30 40 00 68 CA 10 40 00 50 FF 15 A8 40 40 00 6A 40 68 00 10 00 00 FF 35 08 30 40 00 6A 00 FF 15 A4 40 40 00 89 C6 68 00 30 40 00 FF 35 04 30 40 00 57 FF 35 08 30 40 00 50 6A 02 FF 15 4E 41 40 00 6A 00 6A 00 6A 00 56 6A 00 6A 00 FF 15 9C 40 40 00 50 6A 00 6A 00 6A 11 50 FF 15 4A 41 40 00 58 6A FF 50 FF 15 AC 40 40 00 6A 00 FF 15 A0 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor2xxcompressedresources
	{
	strings:
			$a0 = { 56 57 53 31 DB 89 C6 89 D7 0F B6 06 89 C2 83 E0 1F C1 EA 05 74 2D 4A 74 15 8D 5C 13 02 46 C1 E0 08 89 FA 0F B6 0E 46 29 CA 4A 29 C2 EB 32 C1 E3 05 8D 5C 03 04 46 89 FA 0F B7 0E 29 CA 4A 83 C6 02 EB 1D C1 E3 04 46 89 C1 83 E1 0F 01 CB C1 E8 05 73 07 43 89 F2 01 DE EB 06 85 DB 74 0E EB A9 56 89 D6 89 D9 F3 A4 31 DB 5E EB 9D 89 F0 5B 5F 5E C3 }

	condition:
			$a0
	}
	
	
	rule NXPEPackerv10
	{
	strings:
			$a0 = { FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PolyBoxCAnskya
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 53 56 B8 E4 41 00 10 E8 3A E1 FF FF 33 C0 55 68 11 44 00 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 6A 0A 68 20 44 00 10 A1 1C 71 00 10 50 E8 CC E1 ?? ?? ?? ?? 85 DB 0F 84 77 01 00 00 53 A1 1C 71 00 10 50 E8 1E E2 FF FF 8B F0 85 F6 0F 84 61 01 00 00 53 A1 1C 71 00 10 50 E8 E0 E1 FF FF 85 C0 0F 84 4D 01 00 00 50 E8 DA E1 FF FF 8B D8 85 DB 0F 84 3D 01 00 00 56 B8 70 80 00 10 B9 01 00 00 00 8B 15 98 41 00 10 E8 9E DE FF FF 83 C4 04 A1 70 80 00 10 8B CE 8B D3 E8 E1 E1 FF FF 6A 00 6A 00 A1 70 80 00 10 B9 30 44 00 10 8B D6 E8 F8 FD FF FF }

	condition:
			$a0
	}
	
	
	rule UPolyXv05
	{
	strings:
			$a0 = { 55 8B EC ?? 00 BD 46 00 8B ?? B9 ?? 00 00 00 80 ?? ?? 51 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a1 = { 83 EC 04 89 14 24 59 BA ?? 00 00 00 52 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
	$a2 = { BB 00 BD 46 00 83 EC 04 89 1C 24 ?? B9 ?? 00 00 00 80 33 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a3 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 ?? 00 BD 46 00 83 EC 04 89 ?? 24 B9 ?? 00 00 00 81 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a4 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 ?? 00 BD 46 00 ?? B9 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a5 = { EB 01 C3 ?? 00 BD 46 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0 or $a1 or $a2 or $a3 or $a4 or $a5
	}
	
	
	rule beriav007publicWIPsymbiont
	{
	strings:
			$a0 = { 83 EC 18 53 8B 1D 00 30 ?? ?? 55 56 57 68 30 07 00 00 33 ED 55 FF D3 8B F0 3B F5 74 0D 89 AE 20 07 00 00 E8 88 0F 00 00 EB 02 33 F6 6A 10 55 89 35 30 40 ?? ?? FF D3 8B F0 3B F5 74 09 89 2E E8 3C FE FF FF EB 02 33 F6 6A 18 55 89 35 D8 43 ?? ?? FF D3 8B F0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PCGuardv405dv410dv415d
	{
	strings:
			$a0 = { FC 55 50 E8 00 00 00 00 5D EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule asscrypterbysantasdad
	{
	strings:
			$a0 = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 98 40 00 10 E8 AC EA FF FF 33 C0 55 68 78 51 00 10 64 ?? ?? ?? ?? 20 6A 0A 68 88 51 00 10 A1 E0 97 00 10 50 E8 D8 EA FF FF 8B D8 53 A1 E0 97 00 10 50 E8 12 EB FF FF 8B F8 53 A1 E0 97 00 10 50 E8 DC EA FF FF 8B D8 53 E8 DC EA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 F0 97 00 10 E8 C9 E7 FF FF B8 F0 97 00 10 E8 B7 E7 FF FF 8B CF 8B D6 E8 EE EA FF FF 53 E8 98 EA FF FF 8D 4D EC BA 9C 51 00 10 A1 F0 97 00 10 E8 22 EB FF FF 8B 55 EC B8 F0 97 00 10 E8 89 E6 FF FF B8 F0 97 00 10 E8 7F E7 FF FF E8 6E EC FF FF 33 C0 5A 59 59 64 89 10 68 7F 51 00 10 8D 45 EC E8 11 E6 FF FF C3 E9 FF DF FF FF EB F0 5F 5E 5B E8 0D E5 FF FF 00 53 45 54 54 49 4E 47 53 00 00 00 00 FF FF FF FF 1C 00 00 00 45 4E 54 45 52 20 59 4F 55 52 20 4F 57 4E 20 50 41 53 53 57 4F 52 44 20 48 45 52 45 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CopyControlv303
	{
	strings:
			$a0 = { CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1 3C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110Engbartxt
	{
	strings:
			$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Elanguage
	{
	strings:
			$a0 = { E8 06 00 00 00 50 E8 ?? 01 00 00 55 8B EC 81 C4 F0 FE FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXELOCK66615
	{
	strings:
			$a0 = { BA ?? ?? BF ?? ?? EB ?? EA ?? ?? ?? ?? 79 ?? 7F ?? 7E ?? 1C ?? 48 78 ?? E3 ?? 45 14 ?? 5A E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AdysGluev010
	{
	strings:
			$a0 = { 2E 8C 06 ?? ?? 0E 07 33 C0 8E D8 BE ?? ?? BF ?? ?? FC B9 ?? ?? 56 F3 A5 1E 07 5F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SVKProtectorv132
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PKLITEv114v115v1203
	{
	strings:
			$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B ?? ?? ?? 72 ?? B4 09 BA ?? 01 CD 21 CD 20 4E 6F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SafeGuardV10Xsimonzh2000
	{
	strings:
			$a0 = { E8 00 00 00 00 EB 29 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 59 9C 81 C1 E2 FF FF FF EB 01 ?? 9D FF E1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEiDBundlev102v103DLLBoBBobSoft
	{
	strings:
			$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeJoinerSmallbuild023GlOFF
	{
	strings:
			$a0 = { E8 E1 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PrivatePersonalPackerPPP102ConquestOfTroycom
	{
	strings:
			$a0 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9 }

	condition:
			$a0
	}
	rule DIETv102bv110av120
	{
	strings:
			$a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? 3B FC 72 ?? B4 4C CD 21 FD F3 A5 FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXECLiPSElayer
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium1334ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 }
	$a1 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PKLITEv150Devicedrivercompression
	{
	strings:
			$a0 = { B4 09 BA 14 01 CD 21 B8 00 4C CD 21 F8 9C 50 53 51 52 56 57 55 1E 06 BB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxGrazie883
	{
	strings:
			$a0 = { 1E 0E 1F 50 06 BF 70 03 B4 1A BA 70 03 CD 21 B4 47 B2 00 BE 32 04 CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PROTECTEXECOMv60
	{
	strings:
			$a0 = { 1E B4 30 CD 21 3C 02 73 ?? CD 20 BE ?? ?? E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ENIGMAProtectorSukhovVladimir
	{
	strings:
			$a0 = { 45 6E 69 67 6D 61 20 70 72 6F 74 65 63 74 6F 72 20 76 31 }

	condition:
			$a0
	}
	
	
	rule CRYPToCRACksPEProtectorV093LukasFleischer
	{
	strings:
			$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv147v150
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 5B 12 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PocketPCMIB
	{
	strings:
			$a0 = { E8 FF BD 27 14 00 BF AF 18 00 A4 AF 1C 00 A5 AF 20 00 A6 AF 24 00 A7 AF ?? ?? ?? 0C 00 00 00 00 18 00 A4 8F 1C 00 A5 8F 20 00 A6 8F ?? ?? ?? 0C 24 00 A7 8F ?? ?? ?? 0C 25 20 40 00 14 00 BF 8F 08 00 E0 03 18 00 BD 27 ?? FF BD 27 18 00 ?? AF ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv305c4ExtractableVirusShield
	{
	strings:
			$a0 = { 03 05 40 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxNoon1163
	{
	strings:
			$a0 = { E8 ?? ?? 5B 50 56 B4 CB CD 21 3C 07 ?? ?? 81 ?? ?? ?? 2E ?? ?? 4D 5A ?? ?? BF 00 01 89 DE FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PuNkMoD1xPuNkDuDe
	{
	strings:
			$a0 = { 94 B9 ?? ?? 00 00 BC ?? ?? ?? ?? 80 34 0C }

	condition:
			$a0
	}
	
	
	rule PECrypt32Consolev10v101v102
	{
	strings:
			$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule InnoSetupModulev2018
	{
	strings:
			$a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8 }

	condition:
			$a0
	}
	
	
	rule Nakedbind10nakedcrew
	{
	strings:
			$a0 = { 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B 4D 5A 74 08 81 EB 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPacKV31LiuXingPing
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule AntiVirusVaccinev103
	{
	strings:
			$a0 = { FA 33 DB B9 ?? ?? 0E 1F 33 F6 FC AD 35 ?? ?? 03 D8 E2 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxKuku448
	{
	strings:
			$a0 = { AE 75 ED E2 F8 89 3E ?? ?? BA ?? ?? 0E 07 BF ?? ?? EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASProtectv12xNewStrain
	{
	strings:
			$a0 = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SimpleUPXCryptorv3042005OnelayerencryptionMANtiCORE
	{
	strings:
			$a0 = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AntiDote10Demo12SISTeam
	{
	strings:
			$a0 = { 00 00 00 00 09 01 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 DB 01 47 65 74 56 65 72 73 69 6F 6E 45 78 41 00 73 01 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 00 7A 03 57 61 69 74 46 6F 72 53 69 6E 67 6C 65 4F 62 6A 65 63 74 00 BF 02 52 65 73 75 6D 65 54 68 72 65 61 64 00 00 29 03 53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 94 03 57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 00 6B 03 56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 00 00 A6 02 52 65 61 64 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 CA 01 47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 62 00 43 72 65 61 74 65 50 72 6F 63 65 73 73 41 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C }

	condition:
			$a0
	}
	
	
	rule FSGv110EngbartxtWinRARSFX
	{
	strings:
			$a0 = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }
	$a1 = { EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule BJFntv11b
	{
	strings:
			$a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThinstallEmbedded26202623Jitit
	{
	strings:
			$a0 = { E8 00 00 00 00 58 BB AC 1E 00 00 2B C3 50 68 ?? ?? ?? ?? 68 B0 21 00 00 68 C4 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SLVc0deProtector11xSLVICU
	{
	strings:
			$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RJoinerbyVaskaSignfrompinch250320071700
	{
	strings:
			$a0 = { E8 03 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 6C 10 40 00 FF 25 70 10 40 00 FF 25 74 10 40 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AverCryptor10os1r1s
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 75 17 40 00 8B BD 9C 18 40 00 8B 8D A4 18 40 00 B8 BC 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 A0 18 40 00 33 C0 51 33 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 A0 18 40 00 8B 85 A8 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 BC 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 98 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule nSpackV23LiuXingPing
	{
	strings:
			$a0 = { 9C 60 70 61 63 6B 24 40 }

	condition:
			$a0
	}
	
	
	rule SENDebugProtector
	{
	strings:
			$a0 = { BB ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 29 ?? ?? 4E E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule xPEP03xxIkUg
	{
	strings:
			$a0 = { 55 53 56 51 52 57 E8 16 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AntiDote14SESISTeam
	{
	strings:
			$a0 = { 68 90 03 00 00 E8 C6 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50 E8 AC FD FF FF 50 E8 A6 FD FF FF 68 69 D6 00 00 E8 9C FD FF FF 50 E8 96 FD FF FF 50 E8 90 FD FF FF 83 C4 20 E8 78 FF FF FF 84 C0 74 4F 68 04 01 00 00 68 10 22 60 00 6A 00 FF 15 08 10 60 00 68 90 03 00 00 E8 68 FD FF FF 68 69 D6 00 00 E8 5E FD FF FF 50 E8 58 FD FF FF 50 E8 52 FD FF FF E8 DD FE FF FF 50 68 A4 10 60 00 68 94 10 60 00 68 10 22 60 00 E8 58 FD FF FF 83 C4 20 33 C0 C2 10 00 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPack30NorthStar
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ORiENV212FisunAV
	{
	strings:
			$a0 = { E9 5D 01 00 00 CE D1 CE CD 0D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPackv23NorthStar
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD }
	$a1 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 56 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 54 03 00 00 03 D9 50 53 E8 9D 02 00 00 61 }

	condition:
			$a0 or $a1
	}
	
	
	rule ObsidiumV1342ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 C3 27 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SplashBitmapv100WithUnpackCodeBoBBobsoft
	{
	strings:
			$a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 6A 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule KBySV028shoooo
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ObsidiumV12XObsidiumSoftware
	{
	strings:
			$a0 = { E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPackV13LiuXingPing
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01PENinja131Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidiumv1300ObsidiumSoftware
	{
	strings:
			$a0 = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B }
	$a1 = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B 50 EB 03 8A 0B 93 33 C0 EB 02 28 B9 8B 00 EB 01 04 C3 EB 04 65 B3 54 0A E9 FA 00 00 00 EB 01 A2 E8 D5 FF FF FF EB 02 2B 49 EB 03 7C 3E 76 58 EB 04 B8 94 92 56 EB 01 72 64 67 8F 06 00 00 EB 02 23 72 83 C4 04 EB 02 A9 CB E8 47 26 00 00 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule Feokt
	{
	strings:
			$a0 = { 89 25 A8 11 40 00 BF ?? ?? ?? 00 31 C0 B9 ?? ?? ?? 00 29 F9 FC F3 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule NTkrnlSecureSuite01015NTkrnlSoftware
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 }

	condition:
			$a0
	}
	
	
	rule PEPROTECT09
	{
	strings:
			$a0 = { E9 CF 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXERefactorV01random
	{
	strings:
			$a0 = { 55 8B EC 81 EC 90 0B 00 00 53 56 57 E9 58 8C 01 00 55 53 43 41 54 49 4F 4E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CrunchPEv40
	{
	strings:
			$a0 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 E9 06 ?? ?? 89 85 E1 06 ?? ?? FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 }

	condition:
			$a0
	}
	
	
	rule NullsoftPIMPInstallSystemv1x
	{
	strings:
			$a0 = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Pohernah100byKas
	{
	strings:
			$a0 = { 58 60 E8 00 00 00 00 5D 81 ED 20 25 40 00 8B BD 86 25 40 00 8B 8D 8E 25 40 00 6B C0 05 83 F0 04 89 85 92 25 40 00 83 F9 00 74 2D 81 7F 1C AB 00 00 00 75 1E 8B 77 0C 03 B5 8A 25 40 00 31 C0 3B 47 10 74 0E 50 8B 85 92 25 40 00 30 06 58 40 46 EB ED 83 C7 28 49 EB CE 8B 85 82 25 40 00 89 44 24 1C 61 FF E0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule dUP2diablo2oo2
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 3C 01 75 19 BE ?? ?? ?? ?? 68 00 02 00 00 56 68 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01ASPack2xxHeuristicAnorganix
	{
	strings:
			$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule eXpressorv145CGSoftLabs
	{
	strings:
			$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule hmimysProtectv10
	{
	strings:
			$a0 = { E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 }
	$a1 = { E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 00 00 00 }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	
	rule VProtectorV10Evcasm
	{
	strings:
			$a0 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01LCCWin32DLLAnorganix
	{
	strings:
			$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CodeCryptv014b
	{
	strings:
			$a0 = { E9 C5 02 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PellesC450DLLX86CRTLIB
	{
	strings:
			$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 85 DB 75 0D 83 3D ?? ?? ?? ?? 00 75 04 31 C0 EB 57 83 FB 01 74 05 83 FB 02 75 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EEXEVersion112
	{
	strings:
			$a0 = { B4 30 CD 21 3C 03 73 ?? BA 1F 00 0E 1F B4 09 CD 21 B8 FF 4C CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule FSGv120EngdulekxtMASM32TASM32
	{
	strings:
			$a0 = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEDiminisherv01Teraphy
	{
	strings:
			$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 50 E8 02 01 00 00 8B FD 8D 9D 9A 33 40 00 8B 1B 8D 87 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02VBOX43MTEAnorganix
	{
	strings:
			$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SEAAXE
	{
	strings:
			$a0 = { FC BC ?? ?? 0E 1F E8 ?? ?? 26 A1 ?? ?? 8B 1E ?? ?? 2B C3 8E C0 B1 ?? D3 E3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UpackV010V011Dwing
	{
	strings:
			$a0 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 ?? F3 AB C1 E0 ?? B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C ?? 73 ?? B0 ?? 3C ?? 72 02 2C ?? 50 0F B6 5F FF C1 E3 ?? B3 ?? 8D 1C 5B 8D ?? ?? ?? ?? ?? ?? B0 ?? 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakePCGuard403415FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SimplePack111Method1bagieTMX
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC }
	$a1 = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC F3 A5 89 C1 83 E1 03 F3 A4 5F 5E 8B 04 24 89 EA 03 57 0C E8 3F 01 00 00 58 68 00 40 00 00 FF 77 10 50 FF 93 3C 03 00 00 83 C7 28 4E 75 9E BE ?? ?? ?? ?? 09 F6 0F 84 0C 01 00 00 01 EE 8B 4E 0C 09 C9 0F 84 FF 00 00 00 01 E9 89 CF 57 FF 93 30 03 00 00 09 C0 75 3D 6A 04 68 00 10 00 00 68 00 10 00 00 6A 00 FF 93 38 03 00 00 89 C6 8D 83 6F 02 00 00 57 50 56 FF 93 44 03 00 00 6A 10 6A 00 56 6A 00 FF 93 48 03 00 00 89 E5 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule MASM32
	{
	strings:
			$a0 = { 6A ?? 68 00 30 40 00 68 ?? 30 40 00 6A 00 E8 07 00 00 00 6A 00 E8 06 00 00 00 FF 25 08 20 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SoftDefenderv10v11
	{
	strings:
			$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD ?? 59 9C 50 74 0A 75 08 E8 59 C2 04 ?? 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 ?? ?? ?? ?? 58 05 BA 01 ?? ?? 03 C8 74 BE 75 BC E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule XtremeProtectorv106
	{
	strings:
			$a0 = { B8 ?? ?? ?? 00 B9 75 ?? ?? 00 50 51 E8 05 00 00 00 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF 00 00 00 02 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VcasmProtector1112vcasm
	{
	strings:
			$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidiumv1111
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 E7 1C 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule VxEddie1530
	{
	strings:
			$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? 50 06 56 1E 33 C0 50 1F C4 ?? ?? ?? 2E ?? ?? ?? ?? 2E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule KBySV028DLLshoooo
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 03 C2 FF E0 ?? ?? ?? ?? 60 E8 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEncrypt10JunkCode
	{
	strings:
			$a0 = { 60 9C BE 00 10 40 00 8B FE B9 ?? ?? ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 E9 ?? ?? ?? FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEPasswordv02SMTSMF
	{
	strings:
			$a0 = { E8 04 ?? ?? ?? 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 ?? 81 EF ?? ?? ?? ?? 83 EF 05 89 AD 88 27 40 ?? 8D 9D 07 29 40 ?? 8D B5 62 28 40 ?? 46 80 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EncryptPE22006710220061025WFS
	{
	strings:
			$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RCryptorv16Vaska
	{
	strings:
			$a0 = { 33 D0 68 ?? ?? ?? ?? FF D2 }
	$a1 = { 33 D0 68 ?? ?? ?? ?? FF D2 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PEPaCKv10CCopyright1998byANAKiN
	{
	strings:
			$a0 = { C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 20 2D 3D FE 20 50 45 2D 50 41 43 4B 20 76 31 2E 30 20 2D FE 2D 20 28 43 29 20 43 6F 70 }

	condition:
			$a0
	}
	
	
	rule YodasProtectorv1032Beta2AshkbizDanehkar
	{
	strings:
			$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxMTEnonencrypted
	{
	strings:
			$a0 = { F7 D9 80 E1 FE 75 02 49 49 97 A3 ?? ?? 03 C1 24 FE 75 02 48 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01FSG131Anorganix
	{
	strings:
			$a0 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv212AlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
	$a1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule Upack022023betaDwing
	{
	strings:
			$a0 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 }
	$a1 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 59 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 }
	$a2 = { AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 ?? 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 }

	condition:
			$a0 or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01CodeLockAnorganix
	{
	strings:
			$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PKLITEv100c1
	{
	strings:
			$a0 = { 2E 8C 1E ?? ?? 8B 1E ?? ?? 8C DA 81 C2 ?? ?? 3B DA 72 ?? 81 EB ?? ?? 83 EB ?? FA 8E D3 BC ?? ?? FB FD BE ?? ?? 8B FE }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakenSPack13emadicius
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D3 FE FF FF 8B 06 83 F8 00 74 11 8D B5 DF FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PKLITEv100c2
	{
	strings:
			$a0 = { BA ?? ?? A1 ?? ?? 2D ?? ?? 8C CB 81 C3 ?? ?? 3B C3 77 ?? 05 ?? ?? 3B C3 77 ?? B4 09 BA ?? ?? CD 21 CD 20 90 }
	
 condition:
			$a0 at (pe.entry_point)
	}
	
	rule kkrunchyv017FGiesen
	{
	strings:
			$a0 = { FC FF 4D 08 31 D2 8D 7D 30 BE }

	condition:
			$a0
	}
	
	
	rule ACProtectv190gRiscosoftwareInc
	{
	strings:
			$a0 = { 60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPX293300LZMAMarkusOberhumerLaszloMolnarJohnReiser
	{
	strings:
			$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium133720070623ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 27 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 F7 26 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv2000AlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 70 05 00 00 EB 4C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov4000053SiliconRealmsToolworks
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 20 8B 4B 00 68 80 E4 48 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4B 00 33 D2 8A D4 89 15 A4 A1 4B 00 8B C8 81 E1 FF 00 00 00 89 0D A0 A1 4B 00 C1 E1 08 03 CA 89 0D 9C A1 4B 00 C1 E8 10 A3 98 A1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov160a
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 98 71 40 00 68 48 2D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ACProtectUltraProtect10X20XRiSco
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 55 53 45 52 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 6F 72 74 5F 45 6E 64 73 73 00 }

	condition:
			$a0
	}
	
	
	rule Thinstall3035Jtit
	{
	strings:
			$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }
	$a1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 C3 B9 08 00 00 00 E8 01 00 00 00 C3 33 C0 E8 E1 FF FF FF 13 C0 E2 F7 C3 33 C9 41 E8 D4 FF FF FF 13 C9 E8 CD FF FF FF 72 F2 C3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}

		rule PENinjav10DzAkRAkerTNT
	{
	strings:
			$a0 = { BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThinstallEmbedded19XJitit
	{
	strings:
			$a0 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 ?? ?? ?? ?? 50 E8 87 FC FF FF 59 59 A1 ?? ?? ?? ?? 8B 40 10 03 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptorv13045
	{
	strings:
			$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }
	$a1 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule Obsidium1338ObsidiumSoftware
	{
	strings:
			$a0 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 57 27 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPV073betaap0x
	{
	strings:
			$a0 = { 2E 72 6C 70 00 00 00 00 00 50 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 }

	condition:
			$a0
	}
	
	
	rule yCv13byAshkbizDanehkar
	{
	strings:
			$a0 = { 55 8B EC 81 EC C0 00 00 00 53 56 57 8D BD 40 FF FF FF B9 30 00 00 00 B8 CC CC CC CC F3 AB 60 E8 00 00 00 00 5D 81 ED 84 52 41 00 B9 75 5E 41 00 81 E9 DE 52 41 00 8B D5 81 C2 DE 52 41 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

	condition:
			$a0
	}
	
	
	rule PCPECalphapreview
	{
	strings:
			$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AlexProtectorv10Alex
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Shrinkv10
	{
	strings:
			$a0 = { 50 9C FC BE ?? ?? BF ?? ?? 57 B9 ?? ?? F3 A4 8B ?? ?? ?? BE ?? ?? BF ?? ?? F3 A4 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHPack01FEUERRADER
	{
	strings:
			$a0 = { 60 68 54 ?? ?? 00 B8 48 ?? ?? 00 FF 10 68 B3 ?? ?? 00 50 B8 44 ?? ?? 00 FF 10 68 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SentinelSuperProAutomaticProtectionv640Safenet
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1 ?? ?? ?? ?? 0F 94 C1 85 C0 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 15 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule DxPack10
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Pohernah103byKas
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 2A 27 40 00 31 C0 40 83 F0 06 40 3D 40 1F 00 00 75 07 BE 6A 27 40 00 EB 02 EB EB 8B 85 9E 28 40 00 83 F8 01 75 17 31 C0 01 EE 3D 99 00 00 00 74 0C 8B 8D 86 28 40 00 30 0E 40 46 EB ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ObsidiumV1258ObsidiumSoftware
	{
	strings:
			$a0 = { EB 01 ?? E8 ?? 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule nPackv11150200BetaNEOx
	{
	strings:
			$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? 00 E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PerlApp602ActiveState
	{
	strings:
			$a0 = { 68 2C EA 40 00 FF D3 83 C4 0C 85 C0 0F 85 CD 00 00 00 6A 09 57 68 20 EA 40 00 FF D3 83 C4 0C 85 C0 75 12 8D 47 09 50 FF 15 1C D1 40 00 59 A3 B8 07 41 00 EB 55 6A 08 57 68 14 EA 40 00 FF D3 83 C4 0C 85 C0 75 11 8D 47 08 50 FF 15 1C D1 40 00 59 89 44 24 10 EB 33 6A 09 57 68 08 EA 40 00 FF D3 83 C4 0C 85 C0 74 22 6A 08 57 68 FC E9 40 00 FF D3 83 C4 0C 85 C0 74 11 6A 0B 57 68 F0 E9 40 00 FF D3 83 C4 0C 85 C0 75 55 }
	$a1 = { 68 9C E1 40 00 FF 15 A4 D0 40 00 85 C0 59 74 0F 50 FF 15 1C D1 40 00 85 C0 59 89 45 FC 75 62 6A 00 8D 45 F8 FF 75 0C F6 45 14 01 50 8D 45 14 50 E8 9B 01 00 00 83 C4 10 85 C0 0F 84 E9 00 00 00 8B 45 F8 83 C0 14 50 FF D6 85 C0 59 89 45 FC 75 0E FF 75 14 FF 15 78 D0 40 00 E9 C9 00 00 00 68 8C E1 40 00 FF 75 14 50 }

	condition:
			$a0 or $a1
	}
	
	
	rule UPXProtectorv10x2
	{
	strings:
			$a0 = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }

	condition:
			$a0
	}
	
	
	rule ThinstallEmbedded2501Jitit
	{
	strings:
			$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D A8 1A 00 00 B9 6D 1A 00 00 BA 21 1B 00 00 BE 00 10 00 00 BF C0 53 00 00 BD F0 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? 81 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CodeVirtualizer1310OreansTechnologies
	{
	strings:
			$a0 = { 60 9C FC E8 00 00 00 00 5F 81 EF ?? ?? ?? ?? 8B C7 81 C7 ?? ?? ?? ?? 3B 47 2C 75 02 EB 2E 89 47 2C B9 A7 00 00 00 EB 05 01 44 8F ?? 49 0B C9 75 F7 83 7F 40 00 74 15 8B 77 40 03 F0 EB 09 8B 1E 03 D8 01 03 83 C6 04 83 3E 00 75 F2 8B 74 24 24 8B DE 03 F0 B9 01 00 00 00 33 C0 F0 0F B1 4F 30 75 F7 AC }

	condition:
			$a0
	}
	
	
	rule VProtector13Xvcasm
	{
	strings:
			$a0 = { 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 60 8B B4 24 24 00 00 00 8B BC 24 28 00 00 00 FC C6 C2 80 33 DB A4 C6 C3 02 E8 A9 00 00 00 0F 83 F1 FF FF FF 33 C9 E8 9C 00 00 00 0F 83 2D 00 00 00 33 C0 E8 8F 00 00 00 0F 83 37 00 00 00 C6 C3 02 41 C6 C0 10 E8 7D 00 00 00 10 C0 0F 83 F3 FF FF FF }
	$a1 = { E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 FF FF C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 }

	condition:
			$a0 or $a1 at (pe.entry_point)
	}
	
	
	rule Packman0001bubba
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SimplePackV11XV12XMethod1bagie
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD ?? ?? ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEEncryptv40bJunkCode
	{
	strings:
			$a0 = { 66 ?? ?? 00 66 83 ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEQuake006forgat
	{
	strings:
			$a0 = { E8 A5 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? ?? 00 5B ?? ?? 00 6E ?? ?? 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule Kryptonv02
	{
	strings:
			$a0 = { 8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule AHTeamEPProtector03fakePELockNT204FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule eXPressorPacK150XCGSoftLabs
	{
	strings:
			$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C ?? 75 23 8B 45 08 A3 ?? ?? ?? ?? 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 04 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule D1S1Gv11BetaScrambledEXED1N
	{
	strings:
			$a0 = { E8 07 00 00 00 E8 1E 00 00 00 C3 90 58 89 C2 89 C2 25 00 F0 FF FF 50 83 C0 55 8D 00 FF 30 8D 40 04 FF 30 52 C3 8D 40 00 55 8B EC 83 C4 E8 53 56 57 8B 4D 10 8B 45 08 89 45 F8 8B 45 0C 89 45 F4 8D 41 61 8B 38 8D 41 65 8B 00 03 C7 89 45 FC 8D 41 69 8B 00 03 C7 8D 51 6D 8B 12 03 D7 83 C1 71 8B 09 03 CF 2B CA 72 0A 41 87 D1 80 31 FF 41 4A 75 F9 89 45 F0 EB 71 8B }

	condition:
			$a0
	}
	
	
	rule ReversingLabsProtector074betaAp0x
	{
	strings:
			$a0 = { 68 00 00 41 00 E8 01 00 00 00 C3 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ACProtect109gRiscosoftwareInc
	{
	strings:
			$a0 = { 60 F9 50 E8 01 00 00 00 7C 58 58 49 50 E8 01 00 00 00 7E 58 58 79 04 66 B9 B8 72 E8 01 00 00 00 7A 83 C4 04 85 C8 EB 01 EB C1 F8 BE 72 03 73 01 74 0F 81 01 00 00 00 F9 EB 01 75 F9 E8 01 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NorthStarPEShrinker13Liuxingping
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule eXPressorV13CGSoftLabs
	{
	strings:
			$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeJoinerSmallbuild035GlOFF
	{
	strings:
			$a0 = { 51 33 CB 86 C9 59 E8 9E FD FF FF 66 87 DB 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upack020betaDwing
	{
	strings:
			$a0 = { BE 88 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPX20030XMarkusOberhumerLaszloMolnarJohnReiser
	{
	strings:
			$a0 = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D ?? ?? ?? ?? ?? 8B 07 09 C0 74 3C 8B 5F 04 8D ?? ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF ?? ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 57 48 F2 AE 55 FF ?? ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB E1 FF ?? ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? ?? ?? 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }

	condition:
			$a0
	}
	
	
	rule WinUpackv039finalByDwingc2005h1
	{
	strings:
			$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UnnamedScrambler12Bp0ke
	{
	strings:
			$a0 = { 55 8B EC 83 C4 D8 53 56 57 33 C0 89 45 D8 89 45 DC 89 45 E0 89 45 E4 89 45 E8 B8 70 3A 40 00 E8 C4 EC FF FF 33 C0 55 68 5C 3F 40 00 64 FF 30 64 89 20 E8 C5 D7 FF FF E8 5C F5 FF FF B8 20 65 40 00 33 C9 BA 04 01 00 00 E8 D3 DB FF FF 68 04 01 00 00 68 20 65 40 00 6A 00 FF 15 10 55 40 00 BA 6C 3F 40 00 B8 14 55 40 00 E8 5A F4 FF FF 85 C0 0F 84 1B 04 00 00 BA 18 55 40 00 8B 0D 14 55 40 00 E8 16 D7 FF FF 8B 05 88 61 40 00 8B D0 B8 54 62 40 00 E8 D4 E3 FF FF B8 54 62 40 00 E8 F2 E2 FF FF 8B D0 B8 18 55 40 00 8B 0D 88 61 40 00 E8 E8 D6 FF FF FF 35 34 62 40 00 FF 35 30 62 40 00 FF 35 3C 62 40 00 FF 35 38 62 40 00 8D 55 E8 A1 88 61 40 00 E8 E3 F0 FF FF 8B 55 E8 }

	condition:
			$a0
	}
	
	
	rule Upack010012betaDwing
	{
	strings:
			$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEArmorV07Xhying
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 55 56 81 C5 ?? ?? ?? ?? 55 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
		
	rule LauncherGeneratorv103
	{
	strings:
			$a0 = { 68 00 20 40 00 68 10 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 68 F0 22 40 00 6A 00 E8 93 00 00 00 85 C0 0F 84 7E 00 00 00 B8 00 00 00 00 3B 05 68 20 40 00 74 13 6A ?? 68 60 23 40 00 68 20 23 40 00 6A 00 E8 83 00 00 00 A1 58 20 40 00 3B 05 6C 20 40 00 }

	condition:
			$a0
	}
	
	
	rule yodasProtector102103AshkbizDanehkar
	{
	strings:
			$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule NakedPacker10byBigBoote
	{
	strings:
			$a0 = { 60 FC 0F B6 05 34 ?? ?? ?? 85 C0 75 31 B8 50 ?? ?? ?? 2B 05 04 ?? ?? ?? A3 30 ?? ?? ?? A1 00 ?? ?? ?? 03 05 30 ?? ?? ?? A3 38 ?? ?? ?? E8 9A 00 00 00 A3 50 ?? ?? ?? C6 05 34 ?? ?? ?? 01 83 3D 50 ?? ?? ?? 00 75 07 61 FF 25 38 ?? ?? ?? 61 FF 74 24 04 6A 00 FF 15 44 ?? ?? ?? 50 FF 15 40 ?? ?? ?? C3 FF 74 24 04 6A 00 FF 15 44 ?? ?? ?? 50 FF 15 48 ?? ?? ?? C3 8B 4C 24 04 56 8B 74 24 10 57 85 F6 8B F9 74 0D 8B 54 24 10 8A 02 88 01 }

	condition:
			$a0
	}
	
	
	rule tElockv080
	{
	strings:
			$a0 = { 60 E8 F9 11 00 00 C3 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01YodasProtector102Anorganix
	{
	strings:
			$a0 = { E8 03 00 00 00 EB 01 90 90 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VProtector11Xvcasm
	{
	strings:
			$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 00 00 00 EB E6 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
		rule FSGv110EngdulekxtMASM32
	{
	strings:
			$a0 = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Pohernah102byKas
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED DE 26 40 00 8B BD 05 28 40 00 8B 8D 0D 28 40 00 B8 25 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 09 28 40 00 31 C0 51 31 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 09 28 40 00 8B 85 11 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 25 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 01 28 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3 }

	condition:
			$a0 at (pe.entry_point)
	}

	
	rule ActiveMARK5xTrymediaSystemsInc
	{
	strings:
			$a0 = { 20 2D 2D 4D 50 52 4D 4D 47 56 41 2D 2D 00 75 73 65 72 33 32 2E 64 6C 6C 00 4D 65 73 73 61 67 65 42 6F 78 41 00 54 68 69 73 20 61 70 70 6C 69 63 61 74 69 6F 6E 20 63 61 6E 6E 6F 74 20 72 75 6E 20 77 69 74 68 20 61 6E 20 61 63 74 69 76 65 20 64 65 62 75 67 }

	condition:
			$a0
	}
	
	
	rule RCryptorv20HideEPVaska
	{
	strings:
			$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 DC 20 ?? 00 F7 D1 83 F1 FF E8 00 00 00 00 F7 D1 83 F1 FF C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule Armadillov172v173
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 E8 C1 ?? ?? 68 F4 86 ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AsCryptv01SToRM2
	{
	strings:
			$a0 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 83 ?? ?? E2 }

	condition:
			$a0
	}
	
	rule AsCryptv01SToRM3
	{
	strings:
			$a0 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 51 ?? ?? ?? 01 00 00 00 83 ?? ?? E2 }

	condition:
			$a0
	}
	
	rule ASProtectV2XDLLAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 03 00 00 00 E9 ?? ?? 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ?? ?? ?? ?? 03 DD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AsCryptv01SToRM4
	{
	strings:
			$a0 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 E2 }

	condition:
			$a0
	}
/*    
	rule AsCryptv01SToRM5
	{
	strings:
			$a0 = { 83 ?? ?? E2 ?? ?? E2 ?? FF }

	condition:
			$a0
	}

*/

	rule yzpack20UsAr
	{
	strings:
			$a0 = { 25 ?? ?? ?? ?? 61 87 CC 55 45 45 55 81 ED CA 00 00 00 55 A4 B3 02 FF 14 24 73 F8 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 1F B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3C AA EB DC FF 54 24 04 2B CB 75 0F FF 54 24 08 EB 27 AC D1 E8 74 30 13 C9 EB 1B 91 48 C1 E0 08 AC FF 54 24 08 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 99 BD ?? ?? ?? ?? FF 65 28 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PasswordprotectormySMT
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? 5D 8B FD 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 46 80 ?? ?? 74 }

	condition:
			$a0 at (pe.entry_point)
	}

	rule ObsidiumV1258V133XObsidiumSoftware
	{
	strings:
			$a0 = { EB 01 ?? E8 ?? 00 00 00 EB 02 ?? ?? EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule ReflexiveArcadeWrapper
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 98 68 42 00 68 14 FA 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 F8 50 42 00 33 D2 8A D4 89 15 3C E8 42 00 8B C8 81 E1 FF 00 00 00 89 0D 38 E8 42 00 C1 E1 08 03 CA 89 0D 34 E8 42 00 C1 E8 10 A3 30 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxTrojanTelefoon
	{
	strings:
			$a0 = { 60 1E E8 3B 01 BF CC 01 2E 03 3E CA 01 2E C7 05 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv030betaDwing
	{
	strings:
			$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule VxACMEClonewarMutant
	{
	strings:
			$a0 = { FC AD 3D FF FF 74 20 E6 42 8A C4 E6 42 E4 61 0C 03 E6 61 AD B9 40 1F E2 FE }

	condition:
			$a0 at (pe.entry_point)
	}
/*	
	rule Mew11SEv12EngNorthfox
	{
	strings:
			$a0 = { E9 ?? ?? ?? FF 0C ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 0C }

	condition:
			$a0 at (pe.entry_point)
	}
*/	
	rule Armadillov2xxCopyMemII
	{
	strings:
			$a0 = { 6A ?? 8B B5 ?? ?? ?? ?? C1 E6 04 8B 85 ?? ?? ?? ?? 25 07 ?? ?? 80 79 05 48 83 C8 F8 40 33 C9 8A 88 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 81 E2 07 ?? ?? 80 79 05 4A 83 CA F8 42 33 C0 8A 82 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule TPACKv05cm1
	{
	strings:
			$a0 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 8E FE }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEStealthv271
	{
	strings:
			$a0 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED B0 27 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule TPACKv05cm2
	{
	strings:
			$a0 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 CE FD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule ExeJoiner10Yodaf2f
	{
	strings:
			$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv101bAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MacromediaWindowsFlashProjectorPlayerv30
	{
	strings:
			$a0 = { 55 8B EC 83 EC 44 56 FF 15 94 13 42 00 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E 06 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PESpinV11cyberbob
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPack118aPlib043ap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DotFixNiceProtectvna
	{
	strings:
			$a0 = { 60 E8 55 00 00 00 8D BD 00 10 40 00 68 ?? ?? ?? 00 03 3C 24 8B F7 90 68 31 10 40 00 9B DB E3 55 DB 04 24 8B C7 DB 44 24 04 DE C1 DB 1C 24 8B 1C 24 66 AD 51 DB 04 24 90 90 DA 8D 77 10 40 00 DB 1C 24 D1 E1 29 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv032betaDwing
	{
	strings:
			$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PackItBitch10archphase
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 28 ?? ?? ?? 35 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 41 ?? ?? ?? 50 ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? ?? ?? 79 ?? ?? ?? 7D ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule JDPack2xJDPack
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 68 51 40 00 68 04 25 40 00 64 A1 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RPolyCryptv10personalpolycryptorsignfrompinch
	{
	strings:
			$a0 = { 50 58 97 97 60 61 8B 04 24 80 78 F3 6A E8 00 00 00 00 58 E8 00 00 00 00 58 91 91 EB 00 0F 85 6B F4 76 6F E8 00 00 00 00 83 C4 04 E8 00 00 00 00 58 90 E8 00 00 00 00 83 C4 04 8B 04 24 80 78 F1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv031betaDwing
	{
	strings:
			$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 }

	condition:
			$a0 at (pe.entry_point)
	}

	rule Packmanv0001
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? ?? FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01PEPack099Anorganix
	{
	strings:
			$a0 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor239minimumprotection
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? E9 ?? ?? ?? FF 50 C1 C8 18 89 05 ?? ?? ?? ?? C3 C1 C0 18 51 E9 ?? ?? ?? FF 84 C0 0F 84 6A F9 FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF E8 CF E9 FF FF B8 01 00 00 00 E9 ?? ?? ?? FF 2B D0 68 A0 36 80 D4 59 81 C9 64 98 FF 99 E9 ?? ?? ?? FF 84 C0 0F 84 8E EC FF FF E9 ?? ?? ?? FF C3 87 3C 24 5F 8B 00 03 45 FC 83 C0 18 E9 ?? ?? ?? FF 87 0C 24 59 B8 01 00 00 00 D3 E0 23 D0 E9 02 18 00 00 0F 8D DB 00 00 00 C1 E8 14 E9 CA 00 00 00 9D 87 0C 24 59 87 1C 24 68 AE 73 B9 96 E9 C5 10 00 00 0F 8A ?? ?? ?? ?? E9 ?? ?? ?? FF 81 FD F5 FF 8F 07 E9 4F 10 00 00 C3 E9 5E 12 00 00 87 3C 24 E9 ?? ?? ?? FF E8 ?? ?? ?? FF 83 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 8D 55 EC B8 ?? ?? ?? ?? E9 ?? ?? ?? FF E8 A7 1A 00 00 E8 2A CB FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF 59 89 45 E0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtMicrosoftVisualC60ASM
	{
	strings:
			$a0 = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule HaspdongleAlladin
	{
	strings:
			$a0 = { 50 53 51 52 57 56 8B 75 1C 8B 3E ?? ?? ?? ?? ?? 8B 5D 08 8A FB ?? ?? 03 5D 10 8B 45 0C 8B 4D 14 8B 55 18 80 FF 32 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SafeDiscv4
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F }

	condition:
			$a0
	}
	
	
	rule PKLITEv112v115v1201
	{
	strings:
			$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 73 ?? 2D ?? ?? FA 8E D0 FB 2D ?? ?? 8E C0 50 B9 ?? ?? 33 FF 57 BE ?? ?? FC F3 A5 CB B4 09 BA ?? ?? CD 21 CD 20 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PKLITEv112v115v1202
	{
	strings:
			$a0 = { B8 ?? ?? BA ?? ?? 3B C4 73 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptorv153
	{
	strings:
			$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 ?? ?? 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 CC C3 }

	condition:
			$a0
	}
	rule MSLRHv032afakeEXE32Pack13xemadicius
	{
	strings:
			$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 56 3B D2 74 02 81 85 57 E8 00 00 00 00 3B DB 74 01 90 83 C4 14 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule eXpressorv11CGSoftLabs
	{
	strings:
			$a0 = { E9 15 13 00 00 E9 F0 12 00 00 E9 58 12 00 00 E9 AF 0C 00 00 E9 AE 02 00 00 E9 B4 0B 00 00 E9 E0 0C 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPackV11LiuXingPing
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PrivatePersonalPackerPPPv102ConquestOfTroycom
	{
	strings:
			$a0 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxHorse1776
	{
	strings:
			$a0 = { E8 ?? ?? 5D 83 ?? ?? 06 1E 26 ?? ?? ?? ?? BF ?? ?? 1E 0E 1F 8B F7 01 EE B9 ?? ?? FC F3 A6 1F 1E 07 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEShit
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 83 F9 00 7E 06 80 30 ?? 40 E2 F5 E9 ?? ?? ?? FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DrWebVirusFindingEngineInSoftEDVSysteme
	{
	strings:
			$a0 = { B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PluginToExev100BoBBobSoft
	{
	strings:
			$a0 = { E8 00 00 00 00 29 C0 5D 81 ED D1 40 40 00 50 FF 95 B8 40 40 00 89 85 09 40 40 00 FF 95 B4 40 40 00 89 85 11 40 40 00 50 FF 95 C0 40 40 00 8A 08 80 F9 22 75 07 50 FF 95 C4 40 40 00 89 85 0D 40 40 00 8B 9D 09 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 0D 40 40 00 6A 00 81 C3 ?? ?? ?? 00 FF D3 83 C4 10 FF 95 B0 40 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RCryptorv15PrivateVaska
	{
	strings:
			$a0 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NeoLitev200
	{
	strings:
			$a0 = { 8B 44 24 04 23 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PKLITEv200bextra
	{
	strings:
			$a0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 02 00 72 ?? B4 09 BA ?? ?? CD 21 B8 01 4C CD 21 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EA ?? ?? ?? ?? F3 A5 C3 59 2D ?? ?? 8E D0 51 2D ?? ?? 50 80 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Crunch5Fusion4
	{
	strings:
			$a0 = { EB 15 03 ?? ?? ?? 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 55 E8 }

	condition:
			$a0
	}
	
	
	rule MSLRHv032afakePEBundle023xemadicius
	{
	strings:
			$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEMangle
	{
	strings:
			$a0 = { 60 9C BE ?? ?? ?? ?? 8B FE B9 ?? ?? ?? ?? BB 44 52 4F 4C AD 33 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv302v302av304Relocationspack
	{
	strings:
			$a0 = { BE ?? ?? BF ?? ?? B9 ?? ?? 8C CD 81 ED ?? ?? 8B DD 81 EB ?? ?? 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXProtectorv10x
	{
	strings:
			$a0 = { EB EC ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NorthStarPEShrinkerv13byLiuxingping
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 73 ?? FF FF 8B 06 83 F8 00 74 11 8D B5 7F ?? FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 4F ?? FF FF 2B D0 89 95 4F ?? FF FF 01 95 67 ?? FF FF 8D B5 83 ?? FF FF 01 }

	condition:
			$a0
	}
	rule CodeCryptv015b
	{
	strings:
			$a0 = { E9 31 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackFullEdition117Ap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv100
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB C4 84 40 ?? 87 DD 8B 85 49 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakeASProtect10FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 01 00 00 00 90 5D 81 ED 00 00 00 00 BB 00 00 00 00 03 DD 2B 9D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule KGCryptvxx
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 64 A1 30 ?? ?? ?? 84 C0 74 ?? 64 A1 20 ?? ?? ?? 0B C0 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxKBDflags1024
	{
	strings:
			$a0 = { 8B EC 2E 89 2E 24 03 BC 00 04 8C D5 2E 89 2E 22 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule yodasProtectorV102AshkbizDanehkar
	{
	strings:
			$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 23 3F 42 00 8B D5 81 C2 72 3F 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3A 66 42 00 81 E9 1D 40 42 00 8B D5 81 C2 1D 40 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 C3 1F 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium1311ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 }

	condition:
			$a0 at (pe.entry_point)
	}
	
		rule PseudoSigner01MicrosoftVisualC620Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 55 8B EC 83 EC 50 53 56 57 BE 90 90 90 90 8D 7D F4 A5 A5 66 A5 8B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MEGALITEv120a
	{
	strings:
			$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 2D 73 ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
/*	
	rule tElock09910privatetE
	{
	strings:
			$a0 = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
*/

	rule GoatsMutilatorV16Goat_e0f
	{
	strings:
			$a0 = { E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillo430aSiliconRealmsToolworks
	{
	strings:
			$a0 = { 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 41 4E 53 49 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 73 27 20 61 6E 64 20 27 25 73 27 00 00 00 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 55 4E 49 43 }

	condition:
			$a0
	}
	
	
	rule Upackv038betaDwing
	{
	strings:
			$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }
	$a1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 D2 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 97 FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 51 59 46 AD 85 C0 74 1F }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	rule DCryptPrivate09bdrmist
	{
	strings:
			$a0 = { B9 ?? ?? ?? 00 E8 00 00 00 00 58 68 ?? ?? ?? 00 83 E8 0B 0F 18 00 D0 00 48 E2 FB C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule kkrunchyV02XRyd
	{
	strings:
			$a0 = { BD ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? ?? 57 BE ?? ?? ?? ?? 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SkDUndetectabler3NoFSG2MethodSkD
	{
	strings:
			$a0 = { 55 8B EC 81 EC 10 02 00 00 68 00 02 00 00 8D 85 F8 FD FF FF 50 6A 00 FF 15 38 10 00 01 50 FF 15 3C 10 00 01 8D 8D F8 FD FF FF 51 E8 4F FB FF FF 83 C4 04 8B 15 ?? 16 00 01 52 A1 ?? 16 00 01 50 E8 50 FF FF FF 83 C4 08 A3 ?? 16 00 01 C7 85 F4 FD FF FF 00 00 00 00 EB 0F 8B 8D F4 FD FF FF 83 C1 01 89 8D F4 FD FF FF 8B 95 F4 FD FF FF 3B 15 ?? 16 00 01 73 1C 8B 85 F4 FD FF FF 8B 0D ?? 16 00 01 8D 54 01 07 81 FA 74 10 00 01 75 02 EB 02 EB C7 8B 85 F4 FD FF FF 50 E8 ?? 00 00 00 83 C4 04 89 85 F0 FD FF FF 8B 8D F0 FD FF FF 89 4D FC C7 45 F8 00 00 00 00 EB 09 8B 55 F8 83 C2 01 89 55 F8 8B 45 F8 3B 85 F4 FD FF FF 73 15 8B 4D FC 03 4D F8 8B 15 ?? 16 00 01 03 55 F8 8A 02 88 01 EB D7 83 3D ?? 16 00 01 00 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NTPacker10ErazerZ
	{
	strings:
			$a0 = { 55 8B EC 83 C4 E0 53 33 C0 89 45 E0 89 45 E4 89 45 E8 89 45 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 8D 4D EC BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FC FF FF 8B 55 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 8D 4D E8 BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FE FF FF 8B 55 E8 B8 ?? ?? 40 00 E8 ?? ?? FF FF B8 ?? ?? 40 00 E8 ?? FB FF FF 8B D8 A1 ?? ?? 40 00 BA ?? ?? 40 00 E8 ?? ?? FF FF 75 26 8B D3 A1 ?? ?? 40 00 E8 ?? ?? FF FF 84 C0 75 2A 8D 55 E4 33 C0 E8 ?? ?? FF FF 8B 45 E4 8B D3 E8 ?? ?? FF FF EB 14 8D 55 E0 33 C0 E8 ?? ?? FF FF 8B 45 E0 8B D3 E8 ?? ?? FF FF 6A 00 E8 ?? ?? FF FF 33 C0 5A 59 59 64 89 10 68 ?? ?? 40 00 8D 45 E0 BA 04 00 00 00 E8 ?? ?? FF FF C3 E9 ?? ?? FF FF EB EB 5B E8 ?? ?? FF FF 00 00 00 FF FF FF FF 01 00 00 00 25 00 00 00 FF FF FF FF 01 00 00 00 5C 00 00 00 FF FF FF FF 06 00 00 00 53 45 52 56 45 52 00 00 FF FF FF FF 01 00 00 00 31 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SexeCrypter11bysantasdad
	{
	strings:
			$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 D8 39 00 10 E8 30 FA FF FF 33 C0 55 68 D4 3A 00 10 64 FF 30 64 89 ?? ?? ?? ?? E4 3A 00 10 A1 00 57 00 10 50 E8 CC FA FF FF 8B D8 53 A1 00 57 00 10 50 E8 FE FA FF FF 8B F8 53 A1 00 57 00 10 50 E8 C8 FA FF FF 8B D8 53 E8 C8 FA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 14 57 00 10 E8 AD F6 FF FF B8 14 57 00 10 E8 9B F6 FF FF 8B CF 8B D6 E8 DA FA FF FF 53 E8 84 FA FF FF 8D 4D EC BA F8 3A 00 10 A1 14 57 00 10 E8 0A FB FF FF 8B 55 EC B8 14 57 00 10 E8 65 F5 FF FF B8 14 57 00 10 E8 63 F6 FF FF E8 52 FC FF FF 33 C0 5A 59 59 64 89 10 68 DB 3A 00 10 8D 45 EC E8 ED F4 FF FF C3 E9 83 EF FF FF EB F0 5F 5E 5B E8 ED F3 FF FF 00 53 45 54 54 49 4E 47 53 00 00 00 00 FF FF FF FF 12 00 00 00 6B 75 74 68 37 36 67 62 62 67 36 37 34 76 38 38 67 79 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxGotcha879
	{
	strings:
			$a0 = { E8 ?? ?? 5B 81 EB ?? ?? 9C FC 2E ?? ?? ?? ?? ?? ?? ?? 8C D8 05 ?? ?? 2E ?? ?? ?? ?? 50 2E ?? ?? ?? ?? ?? ?? 8B C3 05 ?? ?? 8B F0 BF 00 01 B9 20 00 F3 A4 0E B8 00 01 50 B8 DA DA CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule MZ0oPE106bTaskFall
	{
	strings:
			$a0 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 }
	$a1 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4C 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule SoftDefenderv11xRandyLi
	{
	strings:
			$a0 = { 74 07 75 05 ?? ?? ?? ?? ?? 74 1F 75 1D ?? 68 ?? ?? ?? 00 59 9C 50 74 0A 75 08 ?? 59 C2 04 00 ?? ?? ?? E8 F4 FF FF FF ?? ?? ?? 78 0F 79 0D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv010v012BetaDwing
	{
	strings:
			$a0 = { BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakeBorlandDelphi6070FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 53 8B D8 33 C0 A3 00 00 00 00 6A 00 E8 00 00 00 FF A3 00 00 00 00 A1 00 00 00 00 A3 00 00 00 00 33 C0 A3 00 00 00 00 33 C0 A3 00 00 00 00 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule STProtectorV15SilentSoftware
	{
	strings:
			$a0 = { 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 }

	condition:
			$a0
	}
	
	
		rule ASPackv105bAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor226minimumprotection
	{
	strings:
			$a0 = { 50 68 ?? ?? ?? ?? 58 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 E8 ?? ?? ?? 00 89 45 F8 E9 ?? ?? ?? ?? 0F 83 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 14 24 5A 57 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 58 81 C0 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? 81 C8 ?? ?? ?? ?? 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? ?? C3 BF ?? ?? ?? ?? 81 CB ?? ?? ?? ?? BA ?? ?? ?? ?? 52 E9 ?? ?? ?? 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 34 24 5E 66 8B 00 66 25 ?? ?? E9 ?? ?? ?? ?? 8B CD 87 0C 24 8B EC 51 89 EC 5D 8B 05 ?? ?? ?? ?? 09 C0 E9 ?? ?? ?? ?? 59 81 C1 ?? ?? ?? ?? C1 C1 ?? 23 0D ?? ?? ?? ?? 81 F9 ?? ?? ?? ?? E9 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 13 D0 0B F9 E9 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 8B 64 24 08 31 C0 64 8F 05 00 00 00 00 5A E9 ?? ?? ?? ?? 3C A4 0F 85 ?? ?? ?? 00 8B 45 FC 66 81 38 ?? ?? 0F 84 05 00 00 00 E9 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 3C 24 5F 31 DB 31 C9 31 D2 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 89 45 FC 33 C0 89 45 F4 83 7D FC 00 E9 ?? ?? ?? ?? 53 52 8B D1 87 14 24 81 C0 ?? ?? ?? ?? 0F 88 ?? ?? ?? ?? 3B CB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEProtector093CRYPToCRACk
	{
	strings:
			$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 75 09 83 EC 04 0F 85 DD 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PellesC300400450EXEX86CRTLIB
	{
	strings:
			$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 02 E8 ?? ?? ?? ?? 59 A3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackv118BasicaPLibAp0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule vfpexeNcV500WangJianGuo
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeJoiner153Stubengine17GlOFF
	{
	strings:
			$a0 = { E8 33 FD FF FF 50 E8 0D 00 00 00 CC FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule TheHypersprotectorTheHyper
	{
	strings:
			$a0 = { 55 8B EC 83 EC 14 8B FC E8 14 00 00 00 ?? ?? 01 01 ?? ?? 01 01 ?? ?? ?? 00 ?? ?? 01 01 ?? ?? 02 01 5E E8 0D 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8B 46 04 FF 10 8B D8 E8 0D 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 07 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ANDpakk2006DmitryAndreev
	{
	strings:
			$a0 = { 60 FC BE D4 00 40 00 BF 00 10 00 01 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD 00 FB FF FF 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3 }

	condition:
			$a0
	}
	
	
	rule Thinstall2628Jtit
	{
	strings:
			$a0 = { E8 00 00 00 00 58 BB 34 1D 00 00 2B C3 50 68 00 00 40 00 68 00 40 00 00 68 BC 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 }
	$a1 = { E8 00 00 00 00 58 BB 34 1D 00 00 2B C3 50 68 00 00 40 00 68 00 40 00 00 68 BC 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}

	rule UPXModifierv01x
	{
	strings:
			$a0 = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium1333ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 }
	$a1 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 27 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PureBasic4xNeilHodgson
	{
	strings:
			$a0 = { 68 ?? ?? 00 00 68 00 00 00 00 68 ?? ?? ?? 00 E8 ?? ?? ?? 00 83 C4 0C 68 00 00 00 00 E8 ?? ?? ?? 00 A3 ?? ?? ?? 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? ?? ?? 00 A3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxAugust16thIronMaiden
	{
	strings:
			$a0 = { BA 79 02 03 D7 B4 1A CD 21 B8 24 35 CD 21 5F 57 89 9D 4E 02 8C 85 50 02 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VProtector10Xvcasm
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 E8 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 05 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEPACK099
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 80 BD E0 04 00 00 01 0F 84 F2 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Freshbindv20gFresh
	{
	strings:
			$a0 = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 1C A0 41 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXSCRAMBLER306OnToL
	{
	strings:
			$a0 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE ?? ?? ?? ?? 83 EC 04 89 34 24 B9 80 00 00 00 81 36 ?? ?? ?? ?? 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompact2xxBitSumTechnologies
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PESpinv01Cyberbob
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
	$a1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 B3 28 40 00 8B 42 3C 03 C2 89 85 BD 28 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D D1 28 40 00 53 8F 85 C4 27 40 00 BB ?? 00 00 00 B9 A5 08 00 00 8D BD 75 29 40 00 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D BD AA 30 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 07 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D C4 28 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 59 81 C1 1D 00 00 00 52 51 C1 E9 05 23 D1 FF }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule VxEddie2100
	{
	strings:
			$a0 = { E8 ?? ?? 4F 4F 0E E8 ?? ?? 47 47 1E FF ?? ?? CB E8 ?? ?? 84 C0 ?? ?? 50 53 56 57 1E 06 B4 51 CD 21 8E C3 ?? ?? ?? ?? ?? ?? ?? 8B F2 B4 2F CD 21 AC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NETexecutableMicrosoft
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 00 00 00 FF 25 }

	condition:
			$a0
	}
	
/*	
	rule tElockv099
	{
	strings:
			$a0 = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? 02 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? 02 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
*/	
	
	rule tElockv098
	{
	strings:
			$a0 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AZProtect0001byAlexZakaAZCRC
	{
	strings:
			$a0 = { EB 70 FC 60 8C 80 4D 11 00 70 25 81 00 40 0D 91 BB 60 8C 80 4D 11 00 70 21 81 1D 61 0D 81 00 40 CE 60 8C 80 4D 11 00 70 25 81 25 81 25 81 25 81 29 61 41 81 31 61 1D 61 00 40 B7 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 60 BE 00 ?? ?? 00 BF 00 00 40 00 EB 17 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 FF 25 ?? ?? ?? 00 8B C6 03 C7 8B F8 57 55 8B EC 05 7F 00 00 00 50 E8 E5 FF FF FF BA 8C ?? ?? 00 89 02 E9 1A 01 00 00 ?? 00 00 00 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 47 65 74 56 6F 6C 75 6D 65 49 6E 66 6F 72 6D 61 74 69 6F 6E 41 00 4D 65 73 73 61 67 65 42 6F 78 41 00 45 78 69 74 50 72 6F 63 65 73 73 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 }
	$a1 = { FC 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 8B C2 C1 C0 10 66 8B C1 C3 F0 DA 55 8B EC 53 56 33 C9 33 DB 8B 4D 0C 8B 55 10 8B 75 08 4E 4A 83 FB 08 72 05 33 DB 43 EB 01 43 33 C0 8A 04 31 8A 24 13 2A C4 88 04 31 E2 E6 5E 5B C9 C2 0C }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	
	rule UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser
	{
	strings:
			$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 }
	$a1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule MEW510Northfox
	{
	strings:
			$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule tElockv090
	{
	strings:
			$a0 = { E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium1258ObsidiumSoftware
	{
	strings:
			$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 7B 21 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SVKProtectorv132EngPavolCerven
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeSplitter12BillPrisonerTPOC
	{
	strings:
			$a0 = { E9 95 02 00 00 64 A1 00 00 00 00 83 38 FF 74 04 8B 00 EB F7 8B 40 04 C3 55 8B EC B8 00 00 00 00 8B 75 08 81 E6 00 00 FF FF B9 06 00 00 00 56 56 E8 B0 00 00 00 5E 83 F8 01 75 06 8B C6 C9 C2 04 00 81 EE 00 00 01 00 E2 E5 C9 C2 04 00 55 8B EC 8B 75 0C 8B DE 03 76 3C 8D 76 18 8D 76 60 8B 36 03 F3 56 8B 76 20 03 F3 33 D2 8B C6 8B 36 03 F3 8B 7D 08 B9 0E 00 00 00 FC F3 A6 0B C9 75 02 EB 08 }

	condition:
			$a0
	}
	
	
	rule COPv10c1988
	{
	strings:
			$a0 = { BF ?? ?? BE ?? ?? B9 ?? ?? AC 32 ?? ?? ?? AA E2 ?? 8B ?? ?? ?? EB ?? 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv25RetailSlimLoaderBitsumTechnologies
	{
	strings:
			$a0 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Morphinev27Holy_FatherRatter29A
	{
	strings:
			$a0 = { 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	$a1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 }

	condition:
			$a0 or $a1
	}
	
	
	rule diPackerV1XdiProtectorSoftware
	{
	strings:
			$a0 = { 0F 00 2D E9 01 00 A0 E3 68 01 00 EB 8C 00 00 EB 2B 00 00 EB 00 00 20 E0 1C 10 8F E2 8E 20 8F E2 00 30 A0 E3 67 01 00 EB 0F 00 BD E8 00 C0 8F E2 00 F0 9C E5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01REALBasicAnorganix
	{
	strings:
			$a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PPCPROTECT11XAlexeyGorchakov
	{
	strings:
			$a0 = { FF 5F 2D E9 20 00 9F E5 00 00 90 E5 18 00 8F E5 18 00 9F E5 00 00 90 E5 10 00 8F E5 01 00 A0 E3 00 00 00 EB 02 00 00 EA 04 F0 1F E5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule nPackV111502006BetaNEOxuinC
	{
	strings:
			$a0 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EnigmaProtector11X13XSukhovVladimirSergeNMarkin
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 01 00 00 00 9A 83 C4 10 8B E5 5D E9 }

	condition:
			$a0
	}
	
	
	rule HardlockdongleAlladin
	{
	strings:
			$a0 = { 5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 00 00 00 00 5C 5C 2E 5C 46 45 6E 74 65 44 65 76 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule Armadillov190c
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 10 F2 40 00 68 74 9D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upack_PatchDwing
	{
	strings:
			$a0 = { 81 3A 00 00 00 02 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeJoinerV10Yodaf2f
	{
	strings:
			$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PCShrink071beta
	{
	strings:
			$a0 = { 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtMASM32TASM32
	{
	strings:
			$a0 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B }
	$a1 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PEiDBundlev101BoBBobSoft
	{
	strings:
			$a0 = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPX072
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AdFlt2
	{
	strings:
			$a0 = { 68 00 01 9C 0F A0 0F A8 60 FD 6A 00 0F A1 BE ?? ?? AD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPack120BasicEditionaPLibAp0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00 EB 1B 8B 85 92 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 9E 05 00 00 00 74 0E 83 BD A2 05 00 00 00 74 05 E8 D6 01 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AsCryptv01SToRM1
	{
	strings:
			$a0 = { 81 ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? ?? 83 ?? ?? E2 ?? EB }

	condition:
			$a0
	}
	
	
	rule SmartEMicrosoft
	{
	strings:
			$a0 = { EB 15 03 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 8F 07 00 00 89 85 83 07 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 2F 06 00 00 E8 8E 04 00 00 49 0F 88 23 06 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PE_Admin10EncryptPE12003518SoldFlyingCat
	{
	strings:
			$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 90 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
	$a1 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 90 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	rule MacromediaWindowsFlashProjectorPlayerv40
	{
	strings:
			$a0 = { 83 EC 44 56 FF 15 24 41 43 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPack32v100v111v112v120
	{
	strings:
			$a0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VProtectorV11vcasm
	{
	strings:
			$a0 = { B8 1A ED 41 00 B9 EC EB 41 00 50 51 E8 74 00 00 00 E8 51 6A 00 00 58 83 E8 10 B9 B3 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MaskPE16yzkzero
	{
	strings:
			$a0 = { 36 81 2C 24 ?? ?? ?? 00 C3 60 }

	condition:
			$a0
	}
	
	
	rule bambam001bedrock
	{
	strings:
			$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 ?? ?? ?? ?? E8 6C FD FF FF B9 05 00 00 00 8B F3 BF ?? ?? ?? ?? 53 F3 A5 E8 8D 05 00 00 8B 3D ?? ?? ?? ?? A1 ?? ?? ?? ?? 66 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B CF 89 45 E8 89 0D ?? ?? ?? ?? 66 89 55 EC 8B 41 3C 33 D2 03 C1 83 C4 10 66 8B 48 06 66 8B 50 14 81 E1 FF FF 00 00 8D 5C 02 18 8D 41 FF 85 C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01MEW11SE10Anorganix
	{
	strings:
			$a0 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASProtectv20
	{
	strings:
			$a0 = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner01BorlandDelphi6070Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ObsidiumV12ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 77 1E 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01PEProtect09Anorganix
	{
	strings:
			$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPack32v1x
	{
	strings:
			$a0 = { 53 55 8B E8 33 DB EB 60 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ChSfxsmallv11
	{
	strings:
			$a0 = { BA ?? ?? E8 ?? ?? 8B EC 83 EC ?? 8C C8 BB ?? ?? B1 ?? D3 EB 03 C3 8E D8 05 ?? ?? 89 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXModifiedStubcFarbrauschConsumerConsulting
	{
	strings:
			$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PseudoSigner02NorthStarPEShrinker13Anorganix
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElockv098tE
	{
	strings:
			$a0 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtMicrosoftVisualBasicMASM32
	{
	strings:
			$a0 = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv022v023BetaDwing
	{
	strings:
			$a0 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxVirusConstructorbased
	{
	strings:
			$a0 = { BB ?? ?? B9 ?? ?? 2E ?? ?? ?? ?? 43 43 ?? ?? 8B EC CC 8B ?? ?? 81 ?? ?? ?? 06 1E B8 ?? ?? CD 21 3D ?? ?? ?? ?? 8C D8 48 8E D8 }
	$a1 = { E8 ?? ?? 5D 81 ?? ?? ?? 06 1E E8 ?? ?? E8 ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B4 4A BB FF FF CD 21 83 ?? ?? B4 4A CD 21 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PESHiELD02
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02Gleam100Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DBPEv233DingBoy
	{
	strings:
			$a0 = { EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01PEtite2xlevel0Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 B8 00 90 90 00 6A 00 68 90 90 90 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule EPack14litefinalby6aHguT
	{
	strings:
			$a0 = { 33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElock098tE
	{
	strings:
			$a0 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E ?? ?? 00 00 00 00 00 00 00 00 00 3E ?? ?? 00 2E ?? ?? 00 26 ?? ?? 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 36 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UnnamedScrambler10p0ke
	{
	strings:
			$a0 = { 55 8B EC 83 C4 EC 53 56 33 C0 89 45 ?? ?? ?? ?? 40 00 E8 11 F4 FF FF BE 30 6B 40 00 33 C0 55 68 C9 42 40 00 64 FF 30 64 89 20 E8 C9 FA FF FF BA D8 42 40 00 8B ?? ?? ?? ?? FF FF 8B D8 B8 28 6B 40 00 8B 16 E8 37 F0 FF FF B8 2C 6B 40 00 8B 16 E8 2B F0 FF FF B8 28 6B 40 00 E8 19 F0 FF FF 8B D0 8B C3 8B 0E E8 42 E3 FF FF BA DC 42 40 00 8B C6 E8 2A FA FF FF 8B D8 B8 20 6B 40 00 8B 16 E8 FC EF FF FF B8 24 6B 40 00 8B 16 E8 F0 EF FF FF B8 20 6B 40 00 E8 DE EF FF FF 8B D0 8B C3 8B 0E E8 07 E3 FF FF 6A 00 6A 19 6A 00 6A 32 A1 28 6B 40 00 E8 59 EF FF FF 83 E8 05 03 C0 8D 55 EC E8 94 FE FF FF 8B 55 EC B9 24 6B 40 00 A1 20 6B 40 00 E8 E2 F6 FF FF 6A 00 6A 19 6A 00 6A 32 }

	condition:
			$a0
	}
	
	
	rule WARNINGTROJANADinjector
	{
	strings:
			$a0 = { 90 61 BE 00 20 44 00 8D BE 00 F0 FB FF C7 87 9C E0 04 00 6A F0 8A 5E 57 83 CD FF EB 0E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule TopSpeedv3011989
	{
	strings:
			$a0 = { 1E BA ?? ?? 8E DA 8B ?? ?? ?? 8B ?? ?? ?? FF ?? ?? ?? 50 53 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CodeCryptv0164
	{
	strings:
			$a0 = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D 34 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXHiT001DJSiba
	{
	strings:
			$a0 = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner01ASProtectAnorganix
	{
	strings:
			$a0 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PocketPCARM
	{
	strings:
			$a0 = { F0 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 ?? 00 00 EB 07 30 A0 E1 06 20 A0 E1 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB F0 40 BD E8 ?? 00 00 EA ?? 40 2D E9 ?? ?? 9F E5 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 9F E5 00 ?? ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule AnskyaBinderv11Anskya
	{
	strings:
			$a0 = { BE ?? ?? ?? 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VProtectorV10Bvcasm
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SecurePE1Xwwwdeepzoneorg
	{
	strings:
			$a0 = { 8B 04 24 E8 00 00 00 00 5D 81 ED 4C 2F 40 00 89 85 61 2F 40 00 8D 9D 65 2F 40 00 53 C3 00 00 00 00 8D B5 BA 2F 40 00 8B FE BB 65 2F 40 00 B9 C6 01 00 00 AD 2B C3 C1 C0 03 33 C3 AB 43 81 FB 8E 2F 40 00 75 05 BB 65 2F 40 00 E2 E7 89 AD 1A 31 40 00 89 AD 55 34 40 00 89 AD 68 34 40 00 8D 85 BA 2F 40 00 50 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule yPv10bbyAshkbizDanehkar
	{
	strings:
			$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 C2 E8 03 00 00 00 EB 01 ?? AC ?? ?? ?? ?? ?? ?? ?? EB 01 E8 }

	condition:
			$a0
	}
	
	
	rule MSLRHv031a
	{
	strings:
			$a0 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F }
	$a1 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F CA C0 C7 91 0F CB C1 D9 0C 86 F9 86 D7 D1 D9 EB 01 A5 EB 01 11 EB 01 1D 0F C1 C2 0F CB 0F C1 C2 EB 01 A1 C0 E9 FD 0F C1 D1 EB 01 E3 0F CA 87 D9 EB 01 F3 0F CB 87 C2 0F C0 F9 D0 F7 EB 01 2F 0F C9 C0 DC C4 EB 01 35 0F CA D3 D1 86 C8 EB 01 01 0F C0 F5 87 C8 D0 DE EB 01 95 EB 01 E1 EB 01 FD EB 01 EC 87 D3 0F CB C1 DB 35 D3 E2 0F C8 86 E2 86 EC C1 FB 12 D2 EE 0F C9 D2 F6 0F CA 87 C3 C1 D3 B3 EB 01 BF D1 CB 87 C9 0F CA 0F C1 DB EB 01 44 C0 CA F2 0F C1 D1 0F CB EB 01 D3 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 }

	condition:
			$a0 or $a1 at (pe.entry_point)
	}
	
	
	rule Upackv039finalDwing
	{
	strings:
			$a0 = { 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 }
	$a1 = { FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF }

	condition:
			$a0 or $a1
	}
	
	
	rule vprotector12vcasm
	{
	strings:
			$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 }
	$a1 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 00 00 00 EB E6 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 E8 05 00 00 00 0F 01 EB 05 E8 EB FB 00 00 83 C4 04 E8 08 00 00 00 0F 01 83 C0 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule FakeNinjav28Spirit
	{
	strings:
			$a0 = { BA ?? ?? ?? ?? FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 }

	condition:
			$a0
	}
	
	
	rule PECompactv133
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 00 80 40 ?? 90 90 01 85 9E 80 40 ?? BB E8 0E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DragonArmorOrient
	{
	strings:
			$a0 = { BF 4C ?? ?? 00 83 C9 FF 33 C0 68 34 ?? ?? 00 F2 AE F7 D1 49 51 68 4C ?? ?? 00 E8 11 0A 00 00 83 C4 0C 68 4C ?? ?? 00 FF 15 00 ?? ?? 00 8B F0 BF 4C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 4C ?? ?? 00 8B D1 68 34 ?? ?? 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF 5C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 5C ?? ?? 00 E8 C0 09 00 00 8B 1D 04 ?? ?? 00 83 C4 0C 68 5C ?? ?? 00 56 FF D3 A3 D4 ?? ?? 00 BF 5C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 5C ?? ?? 00 8B D1 68 34 ?? ?? 00 C1 E9 02 F3 AB 8B CA 83 E1 }

	condition:
			$a0
	}
	rule ThemidaWinLicenseV1802OreansTechnologies
	{
	strings:
			$a0 = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SoftDefender1xRandyLi
	{
	strings:
			$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 E6 01 00 00 03 C8 74 BD 75 BB E8 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PellesC2x4xDLLPelleOrinius
	{
	strings:
			$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPX290LZMADelphistubMarkusOberhumerLaszloMolnarJohnReiser
	{
	strings:
			$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackV119aPlib043ap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VirogensPEShrinkerv014
	{
	strings:
			$a0 = { 9C 55 E8 ?? ?? ?? ?? 87 D5 5D 60 87 D5 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 57 56 AD 0B C0 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtBorlandDelphiBorlandC
	{
	strings:
			$a0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 }
	$a1 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
	$a2 = { EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01ACProtect109Anorganix
	{
	strings:
			$a0 = { 60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RCryptorV16dVaska
	{
	strings:
			$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule Upackv032BetaPatchDwing
	{
	strings:
			$a0 = { BE 88 01 ?? ?? AD 50 ?? AD 91 F3 A5 }

	condition:
			$a0
	}
	
	
	rule Apex30alpha500mhz
	{
	strings:
			$a0 = { 5F B9 14 00 00 00 51 BE 00 10 40 00 B9 00 ?? ?? 00 8A 07 30 06 46 E2 FB 47 59 E2 EA 68 ?? ?? ?? 00 C3 }

	condition:
			$a0
	}
	
	
	rule SimbiOZPoly21Extranger
	{
	strings:
			$a0 = { 55 50 8B C4 83 C0 04 C7 00 ?? ?? ?? ?? 58 C3 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov184
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 E8 C1 40 00 68 F4 86 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov183
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 64 84 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov182
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 74 81 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov180
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 E8 C1 00 00 68 F4 86 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeSplitter13SplitMethodBillPrisonerTPOC
	{
	strings:
			$a0 = { E8 00 00 00 00 5D 81 ED 08 12 40 00 E8 66 FE FF FF 55 50 8D 9D 81 11 40 00 53 8D 9D 21 11 40 00 53 6A 08 E8 76 FF FF FF 6A 40 68 00 30 00 00 68 00 01 00 00 6A 00 FF 95 89 11 40 00 89 85 61 10 40 00 50 68 00 01 00 00 FF 95 85 11 40 00 8D 85 65 10 40 00 50 FF B5 61 10 40 00 FF 95 8D 11 40 00 6A 00 68 80 00 00 00 6A 02 6A 00 ?? ?? ?? ?? 01 1F 00 FF B5 61 10 40 00 FF 95 91 11 40 00 89 85 72 10 40 00 6A 00 8D ?? ?? ?? ?? 00 50 FF B5 09 10 40 00 8D 85 F5 12 40 00 50 FF B5 72 10 40 00 FF 95 95 11 40 00 FF B5 72 10 40 00 FF 95 99 11 40 00 8D 85 0D 10 40 00 50 8D 85 1D 10 40 00 50 B9 07 00 00 00 6A 00 E2 FC }
	$a1 = { E9 FE 01 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 73 76 63 45 72 30 31 31 2E 74 6D 70 00 00 00 00 00 00 00 00 00 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 85 C0 0F 84 5F 02 00 00 8B 48 30 80 39 6B 74 07 80 39 4B 74 02 EB E7 80 79 0C 33 74 02 EB DF 8B 40 18 C3 }

	condition:
			$a0 or $a1 at (pe.entry_point)
	}
	
	
	rule RJoiner12aVaska
	{
	strings:
			$a0 = { 55 8B EC 81 EC 0C 01 00 00 8D 85 F4 FE FF FF 56 50 68 04 01 00 00 FF 15 0C 10 40 00 94 90 94 8D 85 F4 FE FF FF 50 FF 15 08 10 40 00 94 90 94 BE 00 20 40 00 94 90 94 83 3E FF 74 7D 53 57 33 DB 8D 7E 04 94 90 94 53 68 80 00 00 00 6A 02 53 6A 01 68 00 00 00 C0 57 FF 15 04 10 40 00 89 45 F8 94 90 94 8B 06 8D 74 06 04 94 90 94 8D 45 FC 53 50 8D 46 04 FF 36 50 FF 75 F8 FF 15 00 10 40 00 94 90 94 FF 75 F8 FF 15 10 10 40 00 94 90 94 8D 85 F4 FE FF FF 6A 0A 50 53 57 68 20 10 40 00 53 FF 15 18 10 40 00 94 90 94 8B 06 8D 74 06 04 94 90 94 83 3E FF 75 89 5F 5B 33 C0 5E C9 C2 10 00 CC CC 24 11 }

	condition:
			$a0
	}
	
	
	rule VxVirusConstructorIVPbased
	{
	strings:
			$a0 = { E9 ?? ?? E8 ?? ?? 5D ?? ?? ?? ?? ?? 81 ED ?? ?? ?? ?? ?? ?? E8 ?? ?? 81 FC ?? ?? ?? ?? 8D ?? ?? ?? BF ?? ?? 57 A4 A5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EncryptPE12003518WFS
	{
	strings:
			$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv168v184
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 7B 11 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SDProtectorProEdition116RandyLi
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 18 33 C0 89 41 04 89 41 }
	$a1 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 18 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 93 03 00 00 03 C8 74 C4 75 C2 E8 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	rule Reg2Exe222223byJanVorel
	{
	strings:
			$a0 = { 6A 00 E8 2F 1E 00 00 A3 C4 35 40 00 E8 2B 1E 00 00 6A 0A 50 6A 00 FF 35 C4 35 40 00 E8 07 00 00 00 50 E8 1B 1E 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 C8 35 40 00 E8 76 16 00 00 83 C4 0C 8B 44 24 04 A3 CC 35 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 EC 1D 00 00 A3 C8 35 40 00 E8 62 1D 00 00 E8 92 1A 00 00 E8 80 16 00 00 E8 13 14 00 00 68 01 00 00 00 68 08 36 40 00 68 00 00 00 00 8B 15 08 36 40 00 E8 71 3F 00 00 B8 00 00 10 00 BB 01 00 00 00 E8 82 3F 00 00 FF 35 48 31 40 00 B8 00 01 00 00 E8 0D 13 00 00 8D 0D EC 35 40 00 5A E8 F2 13 00 00 68 00 01 00 00 FF 35 EC 35 40 00 E8 84 1D 00 00 A3 F4 35 40 00 FF 35 48 31 40 00 FF 35 F4 35 40 00 FF 35 EC 35 40 00 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv120EngdulekxtBorlandDelphiMicrosoftVisualC
	{
	strings:
			$a0 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CrunchPE
	{
	strings:
			$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CICompressv10
	{
	strings:
			$a0 = { 6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeShieldv27b
	{
	strings:
			$a0 = { EB 06 68 40 85 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 87 DD 8B 85 E6 90 40 00 01 85 33 90 40 00 66 C7 85 30 90 40 00 90 90 01 85 DA 90 40 00 01 85 DE 90 40 00 01 85 E2 90 40 00 BB 7B 11 00 00 03 9D EA 90 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXInlinerv10byGPcH
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 }

	condition:
			$a0
	}
	
	
	rule PKLITEv114v120
	{
	strings:
			$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 20 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeToolsCOM2EXE
	{
	strings:
			$a0 = { E8 ?? ?? 5D 83 ED ?? 8C DA 2E 89 96 ?? ?? 83 C2 ?? 8E DA 8E C2 2E 01 96 ?? ?? 60 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThinstallEmbedded2545Jitit
	{
	strings:
			$a0 = { E8 F2 FF FF FF 50 68 ?? ?? ?? ?? 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxARCV4
	{
	strings:
			$a0 = { E8 00 00 5D 81 ED 06 01 81 FC 4F 50 74 0B 8D B6 86 01 BF 00 01 57 A4 EB 11 1E 06 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillo3X5XSiliconRealmsToolworks
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 60 33 C9 75 02 EB 15 EB 33 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakePESHiELD025emadicius
	{
	strings:
			$a0 = { 60 E8 2B 00 00 00 0D 0A 0D 0A 0D 0A 52 65 67 69 73 74 41 72 65 64 20 74 6F 3A 20 4E 4F 4E 2D 43 4F 4D 4D 45 52 43 49 41 4C 21 21 0D 0A 0D 0A 0D 00 58 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov252beta2
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? B0 ?? ?? ?? ?? 68 60 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 24 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CipherWallSelfExtratorDecryptorConsolev15
	{
	strings:
			$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PCShrinkerv029
	{
	strings:
			$a0 = { BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPacKV33LiuXingPing
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 00 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CopyMinderMicrocosmLtd
	{
	strings:
			$a0 = { 83 25 ?? ?? ?? ?? EF 6A 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Crunchv5BitArts
	{
	strings:
			$a0 = { EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 FC 07 00 00 89 85 E8 07 00 00 FF 74 24 2C E8 20 02 00 00 0F 82 94 06 00 00 E8 F3 04 00 00 49 0F 88 88 06 00 00 8B B5 E8 07 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PCShrinkerv020
	{
	strings:
			$a0 = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillo500SiliconRealmsToolworks
	{
	strings:
			$a0 = { E8 E3 40 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 44 15 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 36 13 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 C7 12 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 48 11 00 00 59 89 7D FC FF 75 08 E8 01 49 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 66 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 AF F9 FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 EE 0F 00 00 59 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SLVc0deProtector060SLVICU
	{
	strings:
			$a0 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD }

	condition:
			$a0
	}
	
	
	rule Kryptonv03
	{
	strings:
			$a0 = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CrackStopv101cStefanEsser1997
	{
	strings:
			$a0 = { B4 48 BB FF FF B9 EB 27 8B EC CD 21 FA FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Kryptonv05
	{
	strings:
			$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Kryptonv04
	{
	strings:
			$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PassLock2000v10EngMoonlightSoftware
	{
	strings:
			$a0 = { 55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 00 00 C7 43 60 01 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 83 EC 44 C7 04 24 44 00 00 00 C7 44 24 2C 00 00 00 00 54 FF 15 E8 61 40 00 B8 0A 00 00 00 F7 44 24 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv029Betav031BetaDwing
	{
	strings:
			$a0 = { BE 88 01 ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 }

	condition:
			$a0
	}
	
	
	rule AlexProtector10beta2byAlex
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 00 00 00 02 33 C0 EB 01 E9 C3 58 83 C4 04 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 50 64 FF 35 00 00 00 00 64 89 25 }

	condition:
			$a0
	}
	
	
	rule MoleBoxv254Teggo
	{
	strings:
			$a0 = { 00 8B 4D F0 8B 11 89 15 ?? ?? ?? 00 8B 45 FC A3 ?? ?? ?? 00 5F 5E 8B E5 5D C3 CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 24 61 58 58 FF D0 E8 ?? ?? 00 00 6A 00 FF 15 ?? ?? ?? 00 CC CC CC CC CC CC CC CC CC CC CC CC CC CC }

	condition:
			$a0
	}
	
	
	rule InstallShield2000
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 C4 ?? 53 56 57 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium1337ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PESpinv03Engcyberbob
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 }
	$a1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02PEPack099Anorganix
	{
	strings:
			$a0 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxVCL
	{
	strings:
			$a0 = { AC B9 00 80 F2 AE B9 04 00 AC AE 75 ?? E2 FA 89 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule VterminalV10XLeiPeng
	{
	strings:
			$a0 = { E8 00 00 00 00 58 05 ?? ?? ?? ?? 9C 50 C2 04 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEEncrypt10Liwuyue
	{
	strings:
			$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D 0F 05 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 5D EC 8B 41 18 8B C8 49 85 C9 72 5A 41 33 C0 8B D8 C1 E3 02 03 DA 8B 3B 03 3E 81 3F 47 65 74 50 75 40 8B DF 83 C3 04 81 3B 72 6F 63 41 75 33 8B DF 83 C3 08 81 3B 64 64 72 65 75 26 83 C7 0C 66 81 3F 73 73 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule InstallAnywhere61ZeroGSoftwareInc
	{
	strings:
			$a0 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }
	$a1 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule iLUCRYPTv4018exe
	{
	strings:
			$a0 = { 8B EC FA C7 ?? ?? ?? ?? 4C 4C C3 FB BF ?? ?? B8 ?? ?? 2E ?? ?? D1 C8 4F 81 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02ASProtectAnorganix
	{
	strings:
			$a0 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EncryptPEV22006710WFS
	{
	strings:
			$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 }
	$a1 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule Themida10xx18xxnocompressionOreansTechnologies
	{
	strings:
			$a0 = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 }
	$a1 = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8D 45 80 8B 5D 08 C7 85 7C FF FF FF 00 00 00 00 8B 8D 7C FF FF FF D1 C3 88 18 41 89 8D 7C FF FF FF 81 BD 7C FF FF FF 80 00 00 00 75 E3 C7 85 7C FF FF FF 00 00 00 00 8D BA ?? ?? ?? ?? 8D 75 80 8A 0E BB F4 01 00 00 B8 AB 37 54 78 D3 D0 8A 0F D3 D0 4B 75 F7 0F AF C3 47 46 8B 8D 7C FF FF FF 41 89 8D 7C FF FF FF 81 F9 80 00 00 00 75 D1 61 C9 C2 04 00 55 8B EC 83 C4 F0 8B 75 08 C7 45 FC 00 00 00 00 EB 04 FF 45 FC 46 80 3E 00 75 F7 BA 00 00 00 00 8B 75 08 8B 7D 0C EB 7F C7 45 F8 00 00 00 00 EB }

	condition:
			$a0 or $a1
	}
	
	
	rule StonesPEEncryptorv10
	{
	strings:
			$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 63 3A 40 ?? 2B 95 C2 3A 40 ?? 83 EA 0B 89 95 CB 3A 40 ?? 8D B5 CA 3A 40 ?? 0F B6 36 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PolyBoxDAnskya
	{
	strings:
			$a0 = { 55 8B EC 33 C9 51 51 51 51 51 53 33 C0 55 68 84 2C 40 00 64 FF 30 64 89 20 C6 45 FF 00 B8 B8 46 40 00 BA 24 00 00 00 E8 8C F3 FF FF 6A 24 BA B8 46 40 00 8B 0D B0 46 40 00 A1 94 46 40 00 E8 71 FB FF FF 84 C0 0F 84 6E 01 00 00 8B 1D D0 46 40 00 8B C3 83 C0 24 03 05 D8 46 40 00 3B 05 B4 46 40 00 0F 85 51 01 00 00 8D 45 F4 BA B8 46 40 00 B9 10 00 00 00 E8 A2 EC FF FF 8B 45 F4 BA 9C 2C 40 00 E8 F1 ED FF FF }

	condition:
			$a0
	}
	
	
	rule Mew10execoder10NorthfoxHCC
	{
	strings:
			$a0 = { 33 C0 E9 ?? ?? FF FF 6A ?? ?? ?? ?? ?? 70 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECrypt102
	{
	strings:
			$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DIETv100d
	{
	strings:
			$a0 = { FC 06 1E 0E 8C C8 01 ?? ?? ?? BA ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackV119LZMA430ap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ENIGMAProtectorV112SukhovVladimir
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 83 C5 FA 81 ED ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakeASPack212FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MacromediaWindowsFlashProjectorPlayerv50
	{
	strings:
			$a0 = { 83 EC 44 56 FF 15 70 61 44 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74 0C 3C 20 7F 08 8A 46 01 46 84 C0 75 F4 8D 44 24 04 C7 44 24 30 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule IDApplicationProtector12IDSecuritySuite
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED F2 0B 47 00 B9 19 22 47 00 81 E9 EA 0E 47 00 89 EA 81 C2 EA 0E 47 00 8D 3A 89 FE 31 C0 E9 D3 02 00 00 CC CC CC CC E9 CA 02 00 00 43 3A 5C 57 69 6E 64 6F 77 73 5C 53 6F 66 74 57 61 72 65 50 72 6F 74 65 63 74 6F 72 5C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv305c4ExtractablePasswordchecking
	{
	strings:
			$a0 = { 03 05 80 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule HASPHLProtectionV1XAladdin
	{
	strings:
			$a0 = { 55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 15 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 83 C4 04 E9 A5 00 00 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 }
	$a1 = { 55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 15 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 83 C4 04 E9 A5 00 00 00 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B 15 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule ASProtectv10
	{
	strings:
			$a0 = { 60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASProtectv11
	{
	strings:
			$a0 = { 60 E9 ?? 04 ?? ?? E9 ?? ?? ?? ?? ?? ?? ?? EE }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov275a
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner0132Lite003Anorganix
	{
	strings:
			$a0 = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 ?? ?? ?? ?? E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule VxDoom666
	{
	strings:
			$a0 = { E8 ?? ?? ?? 5E 83 EE ?? B8 CF 7B CD 21 3D CF 7B ?? ?? 0E 1F 81 C6 ?? ?? BF ?? ?? B9 ?? ?? FC F3 A4 06 1F 06 B8 ?? ?? 50 CB B4 48 BB 2C 00 CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxSpanz
	{
	strings:
			$a0 = { E8 00 00 5E 81 EE ?? ?? 8D 94 ?? ?? B4 1A CD 21 C7 84 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule BeRoEXEPackerv100DLLLZBRSBeRoFarbrausch
	{
	strings:
			$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Pksmart10b
	{
	strings:
			$a0 = { BA ?? ?? 8C C8 8B C8 03 C2 81 ?? ?? ?? 51 B9 ?? ?? 51 1E 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PELockv106
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule LaunchAnywherev4001
	{
	strings:
			$a0 = { 55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 C0 69 44 00 E8 E4 80 FF FF 59 E8 4E 29 00 00 E8 C9 0D 00 00 85 C0 75 08 6A FF E8 6E 2B 00 00 59 E8 A8 2C 00 00 E8 23 2E 00 00 FF 15 4C C2 44 00 89 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv033v034BetaDwing
	{
	strings:
			$a0 = { 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule GameGuardnProtect
	{
	strings:
			$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE ?? ?? ?? ?? 31 FF 74 06 61 E9 4A 4D 50 30 8D BE ?? ?? ?? ?? 31 C9 74 06 61 E9 4A 4D 50 30 B8 7D 00 00 00 39 C2 B8 4C 00 00 00 F7 D0 75 3F 64 A1 30 00 00 00 85 C0 78 23 8B 40 0C 8B 40 0C C7 40 20 00 10 00 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 85 C0 75 16 E9 12 00 00 00 31 C0 64 A0 20 00 00 00 85 C0 75 05 E9 01 00 00 00 61 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule yodasProtectorV1032AshkbizDanehkar
	{
	strings:
			$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 94 73 42 00 8B D5 81 C2 E3 73 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 BF A4 42 00 81 E9 8E 74 42 00 8B D5 81 C2 8E 74 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 63 29 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule nBinderv40
	{
	strings:
			$a0 = { 5C 6E 62 34 5F 74 6D 70 5F 30 31 33 32 34 35 34 33 35 30 5C 00 00 00 00 00 00 00 00 00 E9 55 43 4C FF 01 1A 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 8F F4 6A 70 35 A5 63 E9 A3 95 64 9E 32 88 DB 0E A4 B8 DC 79 }

	condition:
			$a0
	}
rule AnslymFUDCrypter
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EPExEPackV10EliteCodingGroup
	{
	strings:
			$a0 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule SimplePack12build3009Method2bagie
	{
	strings:
			$a0 = { 4D 5A 90 EB 01 00 52 E9 86 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule WinZip32bitSFXv6xmodule
	{
	strings:
			$a0 = { FF 15 ?? ?? ?? 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 38 08 74 06 40 80 38 00 75 F6 80 38 00 74 01 40 33 C9 ?? ?? ?? ?? FF 15 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxEinstein
	{
	strings:
			$a0 = { 00 42 CD 21 72 31 B9 6E 03 33 D2 B4 40 CD 21 72 19 3B C1 75 15 B8 00 42 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule VideoLanClient
	{
	strings:
			$a0 = { 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule CrunchPEv10xx
	{
	strings:
			$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 09 C6 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxTravJack883
	{
	strings:
			$a0 = { EB ?? 9C 9E 26 ?? ?? 51 04 ?? 7D ?? 00 ?? 2E ?? ?? ?? ?? 8C C8 8E C0 8E D8 80 ?? ?? ?? ?? 74 ?? 8A ?? ?? ?? BB ?? ?? 8A ?? 32 C2 88 ?? FE C2 43 81 }

	condition:
			$a0 at (pe.entry_point)
	}
/*	
	rule StarForceProActive11StarForceTechnology
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 57 }

	condition:
			$a0 at (pe.entry_point)
	}
*/	
	
	rule RSCsProcessPatcherv151
	{
	strings:
			$a0 = { 68 00 20 40 00 E8 C3 01 00 00 80 38 00 74 0D 66 81 78 FE 22 20 75 02 EB 03 40 EB EE 8B F8 B8 04 60 40 00 68 C4 20 40 00 68 D4 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 9F 01 00 00 85 C0 0F 84 39 01 00 00 BE 00 60 40 00 8B 06 A3 28 21 40 00 83 }

	condition:
			$a0
	}
	rule kryptor9
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SecuPackv15
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 ?? E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 ?? 64 FF 30 64 89 20 6A ?? 68 80 ?? ?? ?? 6A 03 6A ?? 6A 01 ?? ?? ?? 80 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule kryptor5
	{
	strings:
			$a0 = { E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule kryptor6
	{
	strings:
			$a0 = { E8 03 ?? ?? ?? E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ACProtectV13Xrisco
	{
	strings:
			$a0 = { 60 50 E8 01 00 00 00 75 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PELockNTv202c
	{
	strings:
			$a0 = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02MinGWGCC2xAnorganix
	{
	strings:
			$a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeBASIC016b
	{
	strings:
			$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 88 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 68 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 ?? ?? ?? 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 ?? ?? ?? 00 89 EC 5D C3 90 90 90 90 90 90 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}

	rule RCryptorv16bv16cVaska
	{
	strings:
			$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 }
	$a1 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule FileShield
	{
	strings:
			$a0 = { 50 1E EB ?? 90 00 00 8B D8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SDC12SelfDecryptingBinaryGeneratorbyClaesMNyberg
	{
	strings:
			$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 A0 91 40 00 E8 DB FE FF FF 55 89 E5 53 83 EC 14 8B 45 08 8B 00 8B 00 3D 91 00 00 C0 77 3B 3D 8D 00 00 C0 72 4B BB 01 00 00 00 C7 44 24 04 00 00 00 00 C7 04 24 08 00 00 00 E8 CE 24 00 00 83 F8 01 0F 84 C4 00 00 00 85 C0 0F 85 A9 00 00 00 31 C0 83 C4 14 5B 5D C2 04 00 3D 94 00 00 C0 74 56 3D 96 00 00 C0 74 1E 3D 93 00 00 C0 75 E1 EB B5 3D 05 00 00 C0 8D B4 26 00 00 00 00 74 43 3D 1D 00 00 C0 75 CA C7 44 24 04 00 00 00 00 C7 04 24 04 00 00 00 E8 73 24 00 00 83 F8 01 0F 84 99 00 00 00 85 C0 74 A9 C7 04 24 04 00 00 00 FF D0 B8 FF FF FF FF EB 9B 31 DB 8D 74 26 00 E9 69 FF FF FF C7 44 24 04 00 00 00 00 C7 04 24 0B 00 00 00 E8 37 24 00 00 83 F8 01 74 7F 85 C0 0F 84 6D FF FF FF C7 04 24 0B 00 00 00 8D 76 00 FF D0 B8 FF FF FF FF E9 59 FF FF FF C7 04 24 08 00 00 00 FF D0 B8 FF FF FF FF E9 46 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 08 00 00 00 E8 ED 23 00 00 B8 FF FF FF FF 85 DB 0F 84 25 FF FF FF E8 DB 15 00 00 B8 FF FF FF FF E9 16 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 04 00 00 00 E8 BD 23 00 00 B8 FF FF FF FF E9 F8 FE FF FF C7 44 24 04 01 00 00 00 C7 04 24 0B 00 00 00 E8 9F 23 00 00 B8 FF FF FF FF E9 DA FE FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PKLITEv1501
	{
	strings:
			$a0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 ?? BA ?? ?? CD 21 B8 ?? ?? CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Inbuildv10hard
	{
	strings:
			$a0 = { B9 ?? ?? BB ?? ?? 2E ?? ?? 2E ?? ?? 43 E2 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeShieldvxx
	{
	strings:
			$a0 = { 65 78 65 73 68 6C 2E 64 6C 6C C0 5D 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RCryptorv20Vaska
	{
	strings:
			$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? 02 00 00 F7 D1 83 F1 FF 59 BA 32 21 ?? 00 F7 D1 83 F1 FF F7 D1 83 F1 FF 80 02 E3 F7 D1 83 F1 FF C0 0A 05 F7 D1 83 F1 FF 80 02 6F F7 D1 83 F1 FF 80 32 A4 F7 D1 83 F1 FF 80 02 2D F7 D1 83 F1 FF 42 49 85 C9 75 CD 1C 4F 8D 5B FD 62 1E 1C 4F 8D 5B FD 4D 9D B9 ?? ?? ?? 1E 1C 4F 8D 5B FD 22 1C 4F 8D 5B FD 8E A2 B9 B9 E2 83 DB E2 E5 4D CD 1E BF 60 AB 1F 4D DB 1E 1E 3D 1E 92 1B 8E DC 7D EC A4 E2 4D E5 20 C6 CC B2 8E EC 2D 7D DC 1C 4F 8D 5B FD 83 56 8E E0 3A 7D D0 8E 9D 6E 7D D6 4D 25 06 C2 AB 20 CC 3A 4D 2D 9D 6B 0B 81 45 CC 18 4D 2D 1F A1 A1 6B C2 CC F7 E2 4D 2D 9E 8B 8B CC DE 2E 2D F7 1E AB 7D 45 92 30 8E E6 B9 7D D6 8E 9D 27 DA FD FD 1E 1E 8E DF B8 7D CF 8E A3 4D 7D DC 1C 4F 8D 5B FD 33 D7 1E 1E 1E A6 0B 41 A1 A6 42 61 6B 41 6B 4C 45 1E 21 F6 26 BC E2 62 1E 62 1E 62 1E 23 63 59 ?? 1E 62 1E 62 1E 33 D7 1E 1E 1E 85 6B C2 41 AB C2 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 20 33 9E 1E 1E 1E 85 A2 0B 8B C2 27 41 EB A1 A2 C2 1E C0 FD F0 FD 30 62 1E 33 7E 1E 1E 1E C6 2D 42 AB 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 C0 FD F0 8E 1D 1C 4F 8D 5B FD E0 00 33 5E 1E 1E 1E BF 0B EC C2 E6 42 A2 C2 45 1E C0 FD F0 FD 30 CE 36 CC F2 1C 4F 8D 5B FD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv125
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? F3 0D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule RCryptorv1Vaska
	{
	strings:
			$a0 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 }
	$a1 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PECompactv122
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB F3 08 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Packmanv10BrandonLaCombe
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA 8B E8 C6 06 E9 8B 43 0C 89 46 01 6A 04 68 00 10 00 00 FF 73 08 51 FF 55 08 8B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SpecialEXEPaswordProtectorV101EngPavolCerven
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeSmashervxx
	{
	strings:
			$a0 = { 9C FE 03 ?? 60 BE ?? ?? 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEArmor046ChinaCrackingGroup
	{
	strings:
			$a0 = { E8 AA 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 5C ?? ?? 00 6F ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VMProtect106107PolyTech
	{
	strings:
			$a0 = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }

	condition:
			$a0
	}
	
	
	rule USSR031bySpirit
	{
	strings:
			$a0 = { E8 00 00 00 00 5D 83 C5 12 55 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 8C C9 30 C9 E3 01 C3 BE 32 ?? ?? ?? B0 ?? 30 06 8A 06 46 81 FE 00 ?? ?? ?? 7C F3 }

	condition:
			$a0
	}
	
	
	rule PeCompact253DLLSlimLoaderBitSumTechnologies
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D 0B 6B 65 72 6E 6C 33 32 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule LameCryptv10
	{
	strings:
			$a0 = { 60 66 9C BB ?? ?? ?? ?? 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Cygwin32
	{
	strings:
			$a0 = { 55 89 E5 83 EC 04 83 3D }

	condition:
			$a0 at (pe.entry_point)
	}
	rule ASProtectv123RC4build0807exeAlexeySolodovnikov
	{
	strings:
			$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule Armadillov210b2
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 18 12 41 00 68 24 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov190
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 10 F2 40 00 68 64 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule eXPressorProtection150XCGSoftLabs
	{
	strings:
			$a0 = { EB 01 68 EB 01 ?? ?? ?? ?? 83 EC 0C 53 56 57 EB 01 ?? 83 3D ?? ?? ?? ?? 00 74 08 EB 01 E9 E9 56 01 00 00 EB 02 E8 E9 C7 05 ?? ?? ?? ?? 01 00 00 00 EB 01 C2 E8 E2 05 00 00 EB 02 DA 9F 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D0 59 59 EB 01 C8 EB 02 66 F0 68 ?? ?? ?? ?? E8 0E 05 00 00 59 EB 01 DD 83 65 F4 00 EB 07 8B 45 F4 40 89 45 F4 83 7D F4 61 73 1F EB 02 DA 1A 8B 45 F4 0F ?? ?? ?? ?? ?? ?? 33 45 F4 8B 4D F4 88 ?? ?? ?? ?? ?? EB 01 EB EB }

	condition:
			$a0
	}
	
	
	rule VxNecropolis1963
	{
	strings:
			$a0 = { B4 30 CD 21 3C 03 ?? ?? B8 00 12 CD 2F 3C FF B8 ?? ?? ?? ?? B4 4A BB 40 01 CD 21 ?? ?? FA 0E 17 BC ?? ?? E8 ?? ?? FB A1 ?? ?? 0B C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Shrinkv20
	{
	strings:
			$a0 = { E9 ?? ?? 50 9C FC BE ?? ?? 8B FE 8C C8 05 ?? ?? 8E C0 06 57 B9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02UPX06Anorganix
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PESpinV071cyberbob
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule XHider10GlobaL
	{
	strings:
			$a0 = { 55 8B EC 83 C4 EC 33 C0 89 45 EC B8 54 20 44 44 E8 DF F8 FF FF 33 C0 55 68 08 21 44 44 64 FF 30 64 89 20 8D 55 EC B8 1C 21 44 44 E8 E0 F9 FF FF 8B 55 EC B8 40 ?? ?? 44 E8 8B F5 FF FF 6A 00 6A 00 6A 02 6A 00 6A 01 68 00 00 00 40 A1 40 ?? ?? 44 E8 7E F6 FF FF 50 E8 4C F9 FF FF 6A 00 50 E8 4C F9 FF FF A3 28 ?? ?? 44 E8 CE FE FF FF 33 C0 5A 59 59 64 89 10 68 0F 21 44 44 8D 45 EC E8 F1 F4 FF FF C3 E9 BB F2 FF FF EB F0 E8 FC F3 FF FF FF FF FF FF 0E 00 00 00 63 3A 5C 30 30 30 30 30 30 31 2E 64 61 74 00 }
	$a1 = { 85 D2 74 23 8B 4A F8 41 7F 1A 50 52 8B 42 FC E8 30 00 00 00 89 C2 58 52 8B 48 FC E8 48 FB FF FF 5A 58 EB 03 FF 42 F8 87 10 85 D2 74 13 8B 4A F8 49 7C 0D FF 4A F8 75 08 8D 42 F8 E8 5C FA FF FF C3 8D 40 00 85 C0 7E 24 50 83 C0 0A 83 E0 FE 50 E8 2F FA FF FF 5A 66 C7 44 02 FE 00 00 83 C0 08 5A 89 50 FC C7 40 F8 01 00 00 00 C3 31 C0 C3 90 }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	
	rule PseudoSigner01MicrosoftVisualC70DLLAnorganix
	{
	strings:
			$a0 = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 ?? ?? ?? ?? E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEShieldV05Smoke
	{
	strings:
			$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED BC 1A 40 00 EB 01 00 8D B5 46 1B 40 00 BA B3 0A 00 00 EB 01 00 8D 8D F9 25 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 }
	$a1 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED BC 1A 40 00 EB 01 00 8D B5 46 1B 40 00 BA B3 0A 00 00 EB 01 00 8D 8D F9 25 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 90 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	rule UnnamedScrambler25Ap0ke
	{
	strings:
			$a0 = { 55 8B EC B9 0B 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 6C 3E 40 00 E8 F7 EA FF FF 33 C0 55 68 60 44 40 00 64 FF 30 64 89 20 BA 70 44 40 00 B8 B8 6C 40 00 E8 62 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 A1 EB FF FF BA E8 64 40 00 8B C3 8B 0D B8 6C 40 00 E8 37 D3 FF FF C7 05 BC 6C 40 00 0A 00 00 00 BB 68 6C 40 00 BE 90 6C 40 00 BF E8 64 40 00 B8 C0 6C 40 00 BA 04 00 00 00 E8 07 EC FF FF 83 3B 00 74 04 33 C0 89 03 8B D7 8B C6 E8 09 F3 FF FF 89 03 83 3B 00 0F 84 BB 04 00 00 B8 C0 6C 40 00 8B 16 E8 06 E2 FF FF B8 C0 6C 40 00 E8 24 E1 FF FF 8B D0 8B 03 8B 0E E8 D1 D2 FF FF 8B C7 A3 20 6E 40 00 8D 55 EC 33 C0 E8 0C D4 FF FF 8B 45 EC B9 1C 6E 40 00 BA 18 6E 40 00 }

	condition:
			$a0
	}
	
	
	rule Armadillov177
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 B0 71 40 00 68 6C 37 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxTrivial25
	{
	strings:
			$a0 = { B4 4E FE C6 CD 21 B8 ?? 3D BA ?? 00 CD 21 93 B4 40 CD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule KBySV022shoooo
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 ?? ?? ?? ?? E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule InnoSetupModule
	{
	strings:
			$a0 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43 }
	$a1 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	
	rule piritv15
	{
	strings:
			$a0 = { 5B 24 55 50 44 FB 32 2E 31 5D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SoftSentryv30
	{
	strings:
			$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 B0 06 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EncryptPEV22007411WFS
	{
	strings:
			$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 1B 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
		rule Armadillov19x
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov285
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASProtectvxx
	{
	strings:
			$a0 = { 60 ?? ?? ?? ?? ?? 90 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 DD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeShieldv17
	{
	strings:
			$a0 = { EB 06 68 90 1F 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Splasherv10v30
	{
	strings:
			$a0 = { 9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeCryptor01build002GlOFF
	{
	strings:
			$a0 = { 8B 04 24 40 90 83 C0 07 80 38 90 90 74 02 EB FF 90 68 27 ?? ?? 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 FF E4 90 8B 04 24 64 A3 00 00 00 00 8B 64 24 08 90 83 C4 08 }

	condition:
			$a0
	}
	
	
	rule EXEShieldV06SMoKE
	{
	strings:
			$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED D4 1A 40 00 EB 01 00 8D B5 5E 1B 40 00 BA A1 0B 00 00 EB 01 00 8D 8D FF 26 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 }
	$a1 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED D4 1A 40 00 EB 01 00 8D B5 5E 1B 40 00 BA A1 0B 00 00 EB 01 00 8D 8D FF 26 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 90 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02MicrosoftVisualBasic5060Anorganix
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPack118DllLZMA430ap0x
	{
	strings:
			$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 08 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule PKLITEv100v103
	{
	strings:
			$a0 = { B8 ?? ?? BA ?? ?? 8C DB 03 D8 3B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Shrinkerv34
	{
	strings:
			$a0 = { 83 3D B4 ?? ?? ?? ?? 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? 0B 00 00 83 C4 04 8B 75 08 A3 B4 ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF }
	$a1 = { BB ?? ?? BA ?? ?? 81 C3 07 00 B8 40 B4 B1 04 D3 E8 03 C3 8C D9 49 8E C1 26 03 0E 03 00 2B }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule Shrinkerv32
	{
	strings:
			$a0 = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 00 01 ?? ?? E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 1D 68 FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Shrinkerv33
	{
	strings:
			$a0 = { 83 3D ?? ?? ?? 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01JDPack1xJDProtect09Anorganix
	{
	strings:
			$a0 = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upack024027beta028alphaDwing
	{
	strings:
			$a0 = { BE 88 01 40 00 AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01LocklessIntroPackAnorganix
	{
	strings:
			$a0 = { 2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov250b3
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEBundlev02v20x
	{
	strings:
			$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SoftProtectwwwsoftprotectbyru
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? C7 00 00 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NTPackerV2XErazerZ
	{
	strings:
			$a0 = { 4B 57 69 6E 64 6F 77 73 00 10 55 54 79 70 65 73 00 00 3F 75 6E 74 4D 61 69 6E 46 75 6E 63 74 69 6F 6E 73 00 00 47 75 6E 74 42 79 70 61 73 73 00 00 B7 61 50 4C 69 62 75 00 00 00 }

	condition:
			$a0
	}
	
	
	rule SiliconRealmsInstallStub
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? 92 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D ?? ?? 40 00 C1 E1 08 03 CA 89 0D ?? ?? 40 00 C1 E8 10 A3 }

	condition:
			$a0
	}
	
	
	rule Armadillov430v440SiliconRealmsToolworks
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 40 ?? ?? 00 68 80 ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 ?? ?? 00 33 D2 8A D4 89 15 30 ?? ?? 00 8B C8 81 E1 FF 00 00 00 89 0D 2C ?? ?? 00 C1 E1 08 03 CA 89 0D 28 ?? ?? 00 C1 E8 10 A3 24 }
	$a1 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule MoleBoxv20
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? 60 E8 4F }

	condition:
			$a0
	}
	
	
	rule FucknJoyv10cUsAr
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 }
	$a1 = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 00 0B C0 0F 84 EC 00 00 00 89 85 4D 08 40 00 8D 85 51 08 40 00 50 FF B5 6C 08 40 00 E8 AF 02 00 00 0B C0 0F 84 CC 00 00 00 89 85 5C 08 40 00 8D 85 67 07 40 00 E8 7B 02 00 00 8D B5 C4 07 40 00 56 6A 64 FF 95 74 07 40 00 46 80 3E 00 75 FA C7 06 74 6D 70 2E 83 C6 04 C7 06 65 78 65 00 8D 85 36 07 40 00 E8 4C 02 00 00 33 DB 53 53 6A 02 53 53 68 00 00 00 40 8D 85 C4 07 40 00 50 FF 95 74 07 40 00 89 85 78 07 40 00 8D 85 51 07 40 00 E8 21 02 00 00 6A 00 8D 85 7C 07 40 00 50 68 00 ?? ?? 00 8D 85 F2 09 40 00 50 FF }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02VideoLanClientAnorganix
	{
	strings:
			$a0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
		rule SoftWrap
	{
	strings:
			$a0 = { 52 53 51 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 36 ?? ?? ?? E8 ?? 01 ?? ?? 60 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AI1Creator1Beta2byMZ
	{
	strings:
			$a0 = { E8 FE FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
			$a0
	}
	
	
	rule JAMv211
	{
	strings:
			$a0 = { 50 06 16 07 BE ?? ?? 8B FE B9 ?? ?? FD FA F3 2E A5 FB 06 BD ?? ?? 55 CB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv0978
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 ?? 87 DD 8B 85 A9 88 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Setup2GoInstallerStub
	{
	strings:
			$a0 = { 5B 53 45 54 55 50 5F 49 4E 46 4F 5D 0D 0A 56 65 72 }

	condition:
			$a0
	}
	
	
	rule themida1005httpwwworeanscom
	{
	strings:
			$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule yodasProtectorv1033exescrcomAshkbizDanehkar
	{
	strings:
			$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ORiENv211DEMO
	{
	strings:
			$a0 = { E9 5D 01 00 00 CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv0977
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 ?? 87 DD 8B 85 2A 87 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PESpinv13betaCyberbob
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RCryptorv13bVaska
	{
	strings:
			$a0 = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 }
	$a1 = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule mkfpackllydd
	{
	strings:
			$a0 = { E8 00 00 00 00 5B 81 EB 05 00 00 00 8B 93 9F 08 00 00 53 6A 40 68 00 10 00 00 52 6A 00 FF 93 32 08 00 00 5B 8B F0 8B BB 9B 08 00 00 03 FB 56 57 E8 86 08 00 00 83 C4 08 8D 93 BB 08 00 00 52 53 FF E6 }

	condition:
			$a0
	}
	
	
	rule PESpinV03cyberbob
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02BorlandDelphiSetupModuleAnorganix
	{
	strings:
			$a0 = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PELOCKnt204
	{
	strings:
			$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MacromediaWindowsFlashProjectorPlayerv60
	{
	strings:
			$a0 = { 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule IMPostorPack10MahdiHezavehi
	{
	strings:
			$a0 = { BE ?? ?? ?? 00 83 C6 01 FF E6 00 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? 02 ?? ?? 00 10 00 00 00 02 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PluginToExev102BoBBobSoft
	{
	strings:
			$a0 = { E8 00 00 00 00 29 C0 5D 81 ED 32 42 40 00 50 8F 85 DD 40 40 00 50 FF 95 11 42 40 00 89 85 D9 40 40 00 FF 95 0D 42 40 00 50 FF 95 21 42 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 25 42 40 00 89 85 E1 40 40 00 EB 6C 6A 01 8F 85 DD 40 40 00 6A 58 6A 40 FF 95 15 42 40 00 89 85 D5 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 15 42 40 00 89 47 1C C7 07 58 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PKLITEv120
	{
	strings:
			$a0 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 B4 4C CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PrivateexeProtectorV18SetiSoftTeam
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
			$a0
	}
	
	
	rule PENinjamodified
	{
	strings:
			$a0 = { 5D 8B C5 81 ED B2 2C 40 00 2B 85 94 3E 40 00 2D 71 02 00 00 89 85 98 3E 40 00 0F B6 B5 9C 3E 40 00 8B FD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DotFixNiceProtect21GPcHSoft
	{
	strings:
			$a0 = { E9 FF 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 B8 ?? ?? ?? ?? 03 C5 50 B8 ?? ?? ?? ?? 03 C5 FF 10 BB ?? ?? ?? ?? 03 DD 83 C3 0C 53 50 B8 ?? ?? ?? ?? 03 C5 FF 10 6A 40 68 00 10 00 00 FF 74 24 2C 6A 00 FF D0 89 44 24 1C 61 C3 }

	condition:
			$a0
	}
	
	
	rule EXEStealthv276WebToolMaster
	{
	strings:
			$a0 = { EB 65 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 59 4F 55 52 20 41 44 20 48 45 52 45 21 50 69 52 41 43 59 20 69 53 20 41 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor239DLLcompressedresources
	{
	strings:
			$a0 = { 50 68 ?? ?? ?? ?? 58 C1 C0 0F E9 ?? ?? ?? 00 87 04 24 58 89 45 FC E9 ?? ?? ?? FF FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 18 E9 ?? ?? ?? ?? 8B 55 08 09 42 F8 E9 ?? ?? ?? FF 83 7D F0 01 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 34 24 5E 8B 45 FC 33 D2 56 8B F2 E9 ?? ?? ?? 00 BA ?? ?? ?? ?? E8 ?? ?? ?? 00 A3 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 C3 83 C4 04 C3 E9 ?? ?? ?? FF 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? FF C1 C2 03 81 CA ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 03 C2 5A E9 ?? ?? ?? FF 81 E7 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 81 C7 ?? ?? ?? ?? 89 07 E9 ?? ?? ?? ?? 0F 89 ?? ?? ?? ?? 87 14 24 5A 50 C1 C8 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UnoPiX103110BaGiE
	{
	strings:
			$a0 = { 83 EC 04 C7 04 24 00 ?? ?? ?? C3 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 10 00 00 00 00 00 00 02 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv110b3
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 95 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule IonicWindSoftware
	{
	strings:
			$a0 = { 9B DB E3 9B DB E2 D9 2D 00 ?? ?? 00 55 89 E5 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SimplePackV11XMethod2bagie
	{
	strings:
			$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 }
	$a1 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

	condition:
			$a0 or $a1
	}
	
	
	rule PCGuardv500d
	{
	strings:
			$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 30 D2 40 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PESHiELDv0251
	{
	strings:
			$a0 = { 5D 83 ED 06 EB 02 EA 04 8D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule RLPackFullEdition117DLLaPLibAp0x
	{
	strings:
			$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 53 03 00 00 8D 9D 02 02 00 00 33 FF E8 ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv110b4
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 44 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02PEX099Anorganix
	{
	strings:
			$a0 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThinstallVirtualizationSuite30XThinstallCompany
	{
	strings:
			$a0 = { 9C 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 BA FE FF FF E9 ?? ?? ?? ?? CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA }
	$a1 = { 9C 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 BA FE FF FF E9 ?? ?? ?? ?? CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA ?? ?? ?? ?? 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 ?? ?? ?? ?? E8 DF 00 00 00 73 1B 55 BD ?? ?? ?? ?? E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule NullsoftInstallSystemv20
	{
	strings:
			$a0 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }

	condition:
			$a0
	}
	
	
	rule SLVc0deProtectorv11SLV
	{
	strings:
			$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C }
	$a1 = { E8 01 00 00 00 A0 5D EB 01 69 81 ED 5F 1A 40 00 8D 85 92 1A 40 00 F3 8D 95 83 1A 40 00 8B C0 8B D2 2B C2 83 E8 05 89 42 01 E8 FB FF FF FF 69 83 C4 08 E8 06 00 00 00 69 E8 F2 FF FF FF F3 B9 05 00 00 00 51 8D B5 BF 1A 40 00 8B FE B9 58 15 00 00 AC 32 C1 F6 }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	
	rule FreeJoinerSmallbuild031032GlOFF
	{
	strings:
			$a0 = { 50 32 ?? 66 8B C3 58 E8 ?? FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SLVc0deProtectorv06SLV
	{
	strings:
			$a0 = { E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 97 11 40 00 8D B5 EF 11 40 00 B9 FE 2D 00 00 8B FE AC F8 ?? ?? ?? ?? ?? ?? 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEArmor04600759hying
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 }

	condition:
			$a0
	}
	
	
	rule RpolycryptbyVaska2003071841
	{
	strings:
			$a0 = { 58 ?? ?? ?? ?? ?? ?? ?? E8 00 00 00 58 E8 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? 04 }

	condition:
			$a0
	}
	
	rule DBPEvxxxDingBoy
	{
	strings:
			$a0 = { EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SoftwareCompressBGSoftware
	{
	strings:
			$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv305c4UnextrPasswcheckVirshield
	{
	strings:
			$a0 = { 03 05 C0 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv0399Dwing
	{
	strings:
			$a0 = { 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 02 00 00 00 00 00 00 ?? 00 00 00 00 00 10 00 00 ?? 00 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? 00 14 00 00 00 00 ?? ?? 00 ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? 00 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? 00 ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 }
	$a1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }
	$a2 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 10 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 99 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
	}
	
	
	rule UPXModifiedstub
	{
	strings:
			$a0 = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 ?? ?? ?? FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Cryptic20Tughack
	{
	strings:
			$a0 = { B8 00 00 40 00 BB ?? ?? ?? 00 B9 00 10 00 00 BA ?? ?? ?? 00 03 D8 03 C8 03 D1 3B CA 74 06 80 31 ?? 41 EB F6 FF E3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule KGBSFX
	{
	strings:
			$a0 = { 60 BE 00 A0 46 00 8D BE 00 70 F9 FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv20betaJeremyCollake
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	

	rule DevCv4
	{
	strings:
			$a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 ?? ?? ?? 00 FF D0 E8 ?? FF FF FF }

	condition:
			$a0
	}
	
	
	rule DevCv5
	{
	strings:
			$a0 = { 55 89 E5 83 EC 14 6A ?? FF 15 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }

	condition:
			$a0
	}
	rule CRYPToCRACksPEProtectorV092LukasFleischer
	{
	strings:
			$a0 = { E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 ?? ?? 81 3E 50 45 00 00 75 26 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UpackV037Dwing
	{
	strings:
			$a0 = { 0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 10 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 }
	$a1 = { 60 E8 09 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 5E 87 0E }
	$a2 = { BE ?? ?? ?? ?? AD 50 FF ?? ?? EB }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
	}
    


	rule Obsidiumv13037ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 }

	condition:
			$a0 at (pe.entry_point)
	}
	
/*	
	rule EXECryptor2xSoftCompleteDevelopement
	{
	strings:
			$a0 = { A4 ?? ?? 00 00 00 00 00 FF FF FF FF 3C ?? ?? 00 94 ?? ?? 00 D8 ?? ?? 00 00 00 00 00 FF FF FF FF }

	condition:
			$a0
	}
	
*/

	rule VxCompiler
	{
	strings:
			$a0 = { 8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule BJFntv13
	{
	strings:
			$a0 = { EB ?? 3A ?? ?? 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakePEtite21emadicius
	{
	strings:
			$a0 = { B8 00 50 40 00 6A 00 68 BB 21 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 83 C4 04 61 66 9D 64 8F 05 00 00 00 00 83 C4 08 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXShitv01500mhz
	{
	strings:
			$a0 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 01 ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
	$a1 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
	$a2 = { E8 ?? ?? ?? ?? 5E 83 C6 ?? AD 89 C7 AD 89 C1 AD 30 07 47 E2 ?? AD FF E0 C3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
	}
	
	
	rule PackmanV0001Bubbasoft
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 58 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? 48 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DJoinv07publicxorencryptiondrmist
	{
	strings:
			$a0 = { C6 05 ?? ?? 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeJoinerSmallbuild033GlOFF
	{
	strings:
			$a0 = { 50 66 33 C3 66 8B C1 58 E8 AC FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule AnticrackSoftwareProtectorv109ACProtect
	{
	strings:
			$a0 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 83 04 24 06 C3 ?? ?? ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UnderGroundCrypterbyBooster2000
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 B8 74 3C 00 11 E8 94 F9 FF FF E8 BF FE FF FF E8 0A F3 FF FF 8B C0 }

	condition:
			$a0
	}
	
	
	rule MicroJoiner16coban2k
	{
	strings:
			$a0 = { 33 C0 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WiseInstallerStubv11010291
	{
	strings:
			$a0 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PrivateEXEProtector18
	{
	strings:
			$a0 = { BB DC EE 0D 76 D9 D0 8D 16 85 D8 90 D9 D0 }

	condition:
			$a0
	}
	
	
	rule SimpleUPXCryptorv3042005multilayerencryptionMANtiCORE
	{
	strings:
			$a0 = { 60 B8 ?? ?? ?? 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
	$a1 = { 60 B8 ?? ?? ?? ?? B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? ?? C3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule Themida1201compressedOreansTechnologies
	{
	strings:
			$a0 = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv155
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A2 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB 2D 12 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PolyCryptPE214b215JLabSoftwareCreationshsigned
	{
	strings:
			$a0 = { 50 6F 6C 79 43 72 79 70 74 20 50 45 20 28 63 29 20 32 30 30 34 2D 32 30 30 35 2C 20 4A 4C 61 62 53 6F 66 74 77 61 72 65 2E 00 50 00 43 00 50 00 45 }

	condition:
			$a0
	}
	
	rule PECompactv156
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 90 40 ?? 87 DD 8B 85 A2 90 40 ?? 01 85 03 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 9E 90 40 ?? BB 2D 12 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PGMPACKv013
	{
	strings:
			$a0 = { FA 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE ?? ?? BF ?? ?? E8 ?? ?? E8 ?? ?? BB ?? ?? BA ?? ?? 8A C3 8B F3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PGMPACKv014
	{
	strings:
			$a0 = { 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE ?? ?? BF ?? ?? E8 ?? ?? E8 ?? ?? BB ?? ?? BA ?? ?? 8A C3 8B F3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner0232Lite003Anorganix
	{
	strings:
			$a0 = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakePEtite22FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 B8 00 00 00 00 68 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MEW10byNorthfox
	{
	strings:
			$a0 = { 33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40 }

	condition:
			$a0
	}
	
	
	rule theWRAPbyTronDoc
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 48 D2 4B 00 E8 BC 87 F4 FF BB 04 0B 4D 00 33 C0 55 68 E8 D5 4B 00 64 FF 30 64 89 20 E8 9C F4 FF FF E8 F7 FB FF FF 6A 40 8D 55 F0 A1 F0 ED 4B 00 8B 00 E8 42 2E F7 FF 8B 4D F0 B2 01 A1 F4 C2 40 00 E8 F7 20 F5 FF 8B F0 B2 01 A1 B4 C3 40 00 E8 F1 5B F4 FF 89 03 33 D2 8B 03 E8 42 1E F5 FF 66 B9 02 00 BA FC FF FF FF 8B C6 8B 38 FF 57 0C BA B8 A7 4D 00 B9 04 00 00 00 8B C6 8B 38 FF 57 04 83 3D B8 A7 4D 00 00 0F 84 5E 01 00 00 8B 15 B8 A7 4D 00 83 C2 04 F7 DA 66 B9 02 00 8B C6 8B 38 FF 57 0C 8B 0D B8 A7 4D 00 8B D6 8B 03 E8 2B 1F F5 FF 8B C6 E8 B4 5B F4 FF 33 D2 8B 03 E8 DF 1D F5 FF BA F0 44 4E 00 B9 01 00 00 00 8B 03 8B 30 FF 56 04 80 3D F0 44 4E 00 0A 75 3F BA B8 A7 4D 00 B9 04 00 00 00 8B 03 8B 30 FF 56 04 8B 15 B8 A7 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Petitev211
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 66 9C 60 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Petitev212
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 66 9C 60 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MaskPEV20yzkzero
	{
	strings:
			$a0 = { B8 18 00 00 00 64 8B 18 83 C3 30 C3 40 3E 0F B6 00 C1 E0 ?? 83 C0 ?? 36 01 04 24 C3 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner01Morphine12Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EZIPv10
	{
	strings:
			$a0 = { E9 19 32 00 00 E9 7C 2A 00 00 E9 19 24 00 00 E9 FF 23 00 00 E9 1E 2E 00 00 E9 88 2E 00 00 E9 2C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule y0dasCrypterv12
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ChinaProtectdummy
	{
	strings:
			$a0 = { C3 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 56 8B ?? ?? ?? 6A 40 68 00 10 00 00 8D ?? ?? 50 6A 00 E8 ?? ?? ?? ?? 89 30 83 C0 04 5E C3 8B 44 ?? ?? 56 8D ?? ?? 68 00 40 00 00 FF 36 56 E8 ?? ?? ?? ?? 68 00 80 00 00 6A 00 56 E8 ?? ?? ?? ?? 5E C3 }

	condition:
			$a0
	}
	rule BopCryptv10
	{
	strings:
			$a0 = { 60 BD ?? ?? ?? ?? E8 ?? ?? 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MinkeV101Codius
	{
	strings:
			$a0 = { 26 3D 4F 38 C2 82 37 B8 F3 24 42 03 17 9B 3A 83 01 00 00 CC 00 00 00 00 06 00 00 00 01 64 53 74 75 62 00 10 55 54 79 70 65 73 00 00 C7 53 79 73 74 65 6D 00 00 81 53 79 73 49 6E 69 74 00 0C 4B 57 69 6E 64 6F 77 73 00 00 8A 75 46 75 6E 63 74 69 6F 6E 73 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner02BorlandDelphiDLLAnorganix
	{
	strings:
			$a0 = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule bambam004bedrock
	{
	strings:
			$a0 = { BF ?? ?? ?? ?? 83 C9 FF 33 C0 68 ?? ?? ?? ?? F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 11 0A 00 00 83 C4 0C 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F0 BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 BF ?? ?? ?? ?? 8B D1 68 ?? ?? ?? ?? C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 C0 09 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackFullEdition117DLLLZMAAp0x
	{
	strings:
			$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEtitev22
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEtitev20
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 18 8B CC 8D A0 54 BC ?? ?? 8B C3 8D 90 E0 15 ?? ?? 68 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule PEtitev21
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ElicenseSystemV4000ViaTechInc
	{
	strings:
			$a0 = { 00 00 00 00 63 79 62 00 65 6C 69 63 65 6E 34 30 2E 64 6C 6C 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule VProtectorV10Build20041213testvcasm
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 1A 89 40 00 68 56 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Themida18xxOreansTechnologies
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 }
	$a1 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule EXEJoinerv10
	{
	strings:
			$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MicroJoiner11coban2k
	{
	strings:
			$a0 = { BE 0C 70 40 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01FSG10Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov200b2200b3
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 00 F2 40 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RAZOR1911encruptor
	{
	strings:
			$a0 = { E8 ?? ?? BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElock051tE
	{
	strings:
			$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 00 00 59 EB 01 EB AC 54 E8 03 00 00 00 5C EB 08 8D 64 24 04 FF 64 24 FC 6A 05 D0 2C 24 72 01 E8 01 24 24 5C F7 DC EB 02 CD 20 8D 64 24 FE F7 DC EB 02 CD 20 FE C8 E8 00 00 00 00 32 C1 EB 02 82 0D AA EB 03 82 0D 58 EB 02 1D 7A 49 EB 05 E8 01 00 00 00 7F AE 14 7E A0 77 76 75 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SDProtectorBasicProEdition112RandyLi
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 7B 03 00 00 03 C8 74 C4 75 C2 E8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E2 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxFaxFreeTopo
	{
	strings:
			$a0 = { FA 06 33 C0 8E C0 B8 ?? ?? 26 ?? ?? ?? ?? 50 8C C8 26 ?? ?? ?? ?? 50 CC 58 9D 58 26 ?? ?? ?? ?? 58 26 ?? ?? ?? ?? 07 FB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PseudoSigner02MEW11SE10Anorganix
	{
	strings:
			$a0 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Joinersignfrompinch250320072010
	{
	strings:
			$a0 = { 81 EC 04 01 00 00 8B F4 68 04 01 00 00 56 6A 00 E8 7C 01 00 00 33 C0 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 56 E8 50 01 00 00 8B D8 6A 00 6A 00 6A 00 6A 02 6A 00 53 E8 44 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxSK
	{
	strings:
			$a0 = { CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEStubOEPv1x
	{
	strings:
			$a0 = { 40 48 BE 00 ?? ?? 00 40 48 60 33 C0 B8 ?? ?? ?? 00 FF E0 C3 C3 }

	condition:
			$a0
	}
	
	
	rule MoleBoxV23XMoleStudiocom
	{
	strings:
			$a0 = { E8 00 00 00 00 60 E8 4F 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxHymn1865
	{
	strings:
			$a0 = { E8 ?? ?? 5E 83 EE 4C FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 ?? ?? ?? FB 3B ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? 50 06 56 1E 0E 1F B8 00 C5 CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule kkrunchyRyd
	{
	strings:
			$a0 = { BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECryptv100v101
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CERBERUSv20
	{
	strings:
			$a0 = { 9C 2B ED 8C ?? ?? 8C ?? ?? FA E4 ?? 88 ?? ?? 16 07 BF ?? ?? 8E DD 9B F5 B9 ?? ?? FC F3 A5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor2117StrongbitSoftCompleteDevelopment
	{
	strings:
			$a0 = { BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01 }

	condition:
			$a0
	}
	
	
	rule WWPACKv303
	{
	strings:
			$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 BB ?? ?? 53 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule GHFProtectorpackonlyGPcH
	{
	strings:
			$a0 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 00 00 00 00 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 61 B9 FC FF FF FF 8B 1C 08 89 99 ?? ?? ?? ?? E2 F5 90 90 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 01 D6 8B 46 0C 85 C0 0F 84 87 00 00 00 01 D0 89 C3 50 B8 ?? ?? ?? ?? FF 10 85 C0 75 08 53 B8 ?? ?? ?? ?? FF 10 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 BA ?? ?? ?? ?? 8B 06 85 C0 75 03 8B 46 10 01 D0 03 05 ?? ?? ?? ?? 8B 18 8B 7E 10 01 D7 03 3D ?? ?? ?? ?? 85 DB 74 2B F7 C3 00 00 00 80 75 04 01 D3 43 43 81 E3 FF FF FF 0F 53 FF 35 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 89 07 83 05 ?? ?? ?? ?? 04 EB AE 83 C6 14 BA ?? ?? ?? ?? E9 6E FF FF FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 8B 15 ?? ?? ?? ?? 52 FF D0 61 BA ?? ?? ?? ?? FF E2 90 C3 }
	$a1 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 00 00 00 00 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	
	rule yzpackV11UsAr
	{
	strings:
			$a0 = { 60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 8D 40 7C 8B 40 3C 89 45 04 E8 F3 07 00 00 60 8B 5D 04 8B 73 3C 8B 74 33 78 03 F3 56 8B 76 20 03 F3 33 C9 49 92 41 AD 03 C3 52 33 FF 0F B6 10 38 F2 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxDanishtiny
	{
	strings:
			$a0 = { 33 C9 B4 4E CD 21 73 02 FF ?? BA ?? 00 B8 ?? 3D CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule UPXV194MarkusOberhumerLaszloMolnarJohnReiser
	{
	strings:
			$a0 = { FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

	condition:
			$a0
	}
	
	
	rule yzpack112UsAr
	{
	strings:
			$a0 = { 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 ?? ?? ?? ?? B4 09 BA 00 00 1F CD 21 B8 01 4C CD 21 40 00 00 00 50 45 00 00 4C 01 02 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 E0 00 ?? ?? 0B 01 ?? ?? ?? ?? 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule PseudoSigner02YodasProtector102Anorganix
	{
	strings:
			$a0 = { E8 03 00 00 00 EB 01 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
/*	
	rule StarForce30StarForceTechnology
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 63 }

	condition:
			$a0 at (pe.entry_point)
	}
*/	
	
	rule PseudoSigner02PESHiELD025Anorganix
	{
	strings:
			$a0 = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPacKV34V35LiuXingPing
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 01 0F 84 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule DualseXe10
	{
	strings:
			$a0 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 08 03 00 00 89 28 33 FF 8D 85 7D 02 00 00 8D 8D 08 03 00 00 2B C8 8B 9D 58 03 00 00 E8 1C 02 00 00 8D 9D 61 02 00 00 8D B5 7C 02 00 00 46 80 3E 00 74 24 56 FF 95 0A 04 00 00 46 80 3E 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NoodleCryptv200EngNoodleSpa
	{
	strings:
			$a0 = { EB 01 9A E8 76 00 00 00 EB 01 9A E8 65 00 00 00 EB 01 9A E8 7D 00 00 00 EB 01 9A E8 55 00 00 00 EB 01 9A E8 43 04 00 00 EB 01 9A E8 E1 00 00 00 EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 9A E8 25 00 00 00 EB 01 9A E8 02 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule SoftComp1xBGSoftPT
	{
	strings:
			$a0 = { E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 8B 04 24 89 85 2A 0F 41 00 58 8B 85 2A 0F 41 00 }

	condition:
			$a0
	}
	
	
	rule Petite13c1998IanLuck
	{
	strings:
			$a0 = { 9C 60 50 8D 88 00 ?? ?? ?? 8D 90 ?? ?? 00 00 8B DC 8B E1 68 00 00 ?? ?? 53 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 DA 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PENightMarev13
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D B9 ?? ?? ?? ?? 80 31 15 41 81 F9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillo50DllSiliconRealmsToolworks
	{
	strings:
			$a0 = { 83 7C 24 08 01 75 05 E8 DE 4B 00 00 FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ED FE FF FF 59 C2 0C 00 6A 0C 68 ?? ?? ?? ?? E8 E5 24 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 8F 15 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 20 15 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 D7 23 00 00 59 89 7D FC FF 75 08 E8 EC 53 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 2B C5 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 19 ED FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 7D 22 00 00 59 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ObsidiumV1350ObsidiumSoftware
	{
	strings:
			$a0 = { EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 20 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 ?? ?? ?? ?? EB 01 ?? EB 02 ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASProtectv123RC1
	{
	strings:
			$a0 = { 68 01 ?? ?? 00 E8 01 00 00 00 C3 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PUNiSHERv15DEMOFEUERRADERAHTeam
	{
	strings:
			$a0 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 81 2C 24 CA C2 41 00 EB 04 64 6B 88 18 5D E8 00 00 00 00 EB 04 64 6B 88 18 81 2C 24 86 00 00 00 EB 04 64 6B 88 18 8B 85 9C C2 41 00 EB 04 64 6B 88 18 29 04 24 EB 04 64 6B 88 18 EB 04 64 6B 88 18 8B 04 }
	$a1 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 81 2C 24 CA C2 41 00 EB 04 64 6B 88 18 5D E8 00 00 00 00 EB 04 64 6B 88 18 81 2C 24 86 00 00 00 EB 04 64 6B 88 18 8B 85 9C C2 41 00 EB 04 64 6B 88 18 29 04 24 EB 04 64 6B 88 18 EB 04 64 6B 88 18 8B 04 24 EB 04 64 6B 88 18 89 85 9C C2 41 00 EB 04 64 6B 88 18 58 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 C2 50 00 EB D3 5B F3 68 89 5C 24 48 5C 24 58 FF 8D 5C 24 58 5B 83 C3 4C 75 F4 5A 8D 71 78 75 09 81 F3 EB FF 52 BA 01 00 83 EB FC 4A FF 71 0F 75 19 8B 5C 24 00 00 81 33 50 53 8B 1B 0F FF C6 75 1B 81 F3 EB 87 1C 24 8B 8B 04 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 58 EB FF F0 EB FF C0 83 E8 FD EB FF 30 E8 C9 00 00 00 89 E0 EB FF D0 EB FF 71 0F 83 C0 01 EB FF 70 F0 71 EE EB FA EB 83 C0 14 EB FF 70 ED }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	rule PECompactv140b2v140b4
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 86 11 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NullsoftInstallSystemv198
	{
	strings:
			$a0 = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CryptoLockv202EngRyanThian
	{
	strings:
			$a0 = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 }
	$a1 = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }
	$a2 = { 60 BE ?? 90 40 00 8D BE ?? ?? FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
	}
	
	
	rule vfpexeNcv600WangJianGuo
	{
	strings:
			$a0 = { 60 E8 01 00 00 00 63 58 E8 01 00 00 00 7A 58 2D 0D 10 40 00 8D 90 C1 10 40 00 52 50 8D 80 49 10 40 00 5D 50 8D 85 65 10 40 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule XPEORv099b
	{
	strings:
			$a0 = { E8 00 00 00 00 5D 8B CD 81 ED 7A 29 40 00 89 AD 0F 6D 40 00 }
	$a1 = { E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PEiDBundlev100BoBBobSoft
	{
	strings:
			$a0 = { 60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PeCompact2253276BitSumTechnologies
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 C9 11 00 10 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 5A 8B F8 50 52 8B 33 8B 43 20 03 C2 8B 08 89 4B 20 8B 43 1C 03 C2 8B 08 89 4B 1C 03 F2 8B 4B 0C 03 CA 8D 43 1C 50 57 56 FF }

	condition:
			$a0
	}
	
	rule PseudoSigner02CodeLockAnorganix
	{
	strings:
			$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv100Engdulekxt
	{
	strings:
			$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01BorlandDelphi50KOLMCKAnorganix
	{
	strings:
			$a0 = { 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FlyCrypter10ut1lz
	{
	strings:
			$a0 = { 53 56 57 55 BB 2C ?? ?? 44 BE 00 30 44 44 BF 20 ?? ?? 44 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 44 44 00 74 06 FF 15 58 30 44 44 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 20 30 44 44 80 7B 28 01 76 05 83 3E 00 74 22 8B 43 10 85 C0 74 1B FF 15 18 30 44 44 8B 53 10 8B 42 10 3B 42 04 74 0A 85 C0 74 06 50 E8 2F FA FF FF FF 15 24 30 44 44 80 7B 28 01 75 03 FF 53 24 80 7B 28 00 74 05 E8 35 FF FF FF 83 3B 00 75 17 83 3D 10 ?? ?? 44 00 74 06 FF 15 10 ?? ?? 44 8B 06 50 E8 51 FA FF FF 8B 03 56 8B F0 8B FB B9 0B 00 00 00 F3 A5 5E E9 73 FF FF FF 5D 5F 5E 5B C3 A3 00 30 44 44 E8 26 FF FF FF C3 }
	$a1 = { 55 8B EC 83 C4 F0 53 B8 18 22 44 44 E8 7F F7 FF FF E8 0A F1 FF FF B8 09 00 00 00 E8 5C F1 FF FF 8B D8 85 DB 75 05 E8 85 FD FF FF 83 FB 01 75 05 E8 7B FD FF FF 83 FB 02 75 05 E8 D1 FD FF FF 83 FB 03 75 05 E8 87 FE FF FF 83 FB 04 75 05 E8 5D FD FF FF 83 FB 05 75 05 E8 B3 FD FF FF 83 FB 06 75 05 E8 69 FE FF FF 83 FB 07 75 05 E8 5F FE FF FF 83 FB 08 75 05 E8 95 FD FF FF 83 FB 09 75 05 E8 4B FE FF FF 5B E8 9D F2 FF FF 90 }

	condition:
			$a0 or $a1 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakePECompact14xemadicius
	{
	strings:
			$a0 = { EB 06 68 2E A8 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule muckisprotectorIImucki
	{
	strings:
			$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 6A 00 E8 85 C0 74 12 64 8B 3D 18 00 00 00 8B 7F 30 0F B6 47 02 85 C0 74 01 C3 C7 04 24 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule VcasmProtector10
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NullsoftInstallSystemv20b2v20b3
	{
	strings:
			$a0 = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 ?? ?? ?? 00 57 FF 15 ?? ?? 40 00 57 FF 15 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VProtectorV10Dvcasm
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 CA 31 41 00 68 06 32 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule GardianAngel10
	{
	strings:
			$a0 = { 06 8C C8 8E D8 8E C0 FC BF ?? ?? EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule eXpressorv12CGSoftLabs
	{
	strings:
			$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RSCsProcessPatcherv14
	{
	strings:
			$a0 = { E8 E1 01 00 00 80 38 22 75 13 80 38 00 74 2E 80 38 20 75 06 80 78 FF 22 74 18 40 EB ED 80 38 00 74 1B EB 19 40 80 78 FF 20 75 F9 80 38 00 74 0D EB 0B 40 80 38 00 74 05 80 38 22 74 00 8B F8 B8 04 60 40 00 68 00 20 40 00 C7 05 A2 20 40 00 44 00 00 00 68 92 }

	condition:
			$a0
	}
	
	
	rule Armadillov190b1
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 04 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule Armadillov190b2
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 F0 C1 40 00 68 A4 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov190b3
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 08 E2 40 00 68 94 95 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualCASM
	{
	strings:
			$a0 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Thinstall25xxJtit
	{
	strings:
			$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? 1A 00 00 B9 ?? 1A 00 00 BA ?? 1B 00 00 BE 00 10 00 00 BF ?? 53 00 00 BD ?? 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? ?? 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 }
	$a1 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? 1A 00 00 B9 ?? 1A 00 00 BA ?? 1B 00 00 BE 00 10 00 00 BF ?? 53 00 00 BD ?? 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? ?? 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3B F1 7C 04 3B F2 7C 02 89 2E 83 C6 04 3B F7 7C E3 58 50 68 00 00 40 00 68 80 5A }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule hmimysPacker10hmimys
	{
	strings:
			$a0 = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 }

	condition:
			$a0
	}
	
	
	rule ACProtectV20risco
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C3 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackV112V114LZMA430ap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB ?? 60 }

	condition:
			$a0
	}
	
	
	rule JDPack
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 06 ?? ?? ?? 89 95 ?? ?? ?? ?? 83 BD 45 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PESpinv1304Cyberbob
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ScObfuscatorSuperCRacker
	{
	strings:
			$a0 = { 60 33 C9 8B 1D ?? ?? ?? ?? 03 1D ?? ?? ?? ?? 8A 04 19 84 C0 74 09 3C ?? 74 05 34 ?? 88 04 19 41 3B 0D ?? ?? ?? ?? 75 E7 A1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 61 FF 25 ?? ?? ?? ?? 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule tElock098SpecialBuildforgotheXer
	{
	strings:
			$a0 = { E9 99 D7 FF FF 00 00 00 ?? ?? ?? ?? AA ?? ?? 00 00 00 00 00 00 00 00 00 CA }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01DEF10Anorganix
	{
	strings:
			$a0 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02REALBasicAnorganix
	{
	strings:
			$a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov260c
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 F4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 F4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov260a
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 94 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 B4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThemidaWinLicenseV10XV17XDLLOreansTechnologies
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? ?? ?? ?? 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 ?? 89 48 01 61 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule eXPressor12CGSoftLabs
	{
	strings:
			$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NeoLitev10
	{
	strings:
			$a0 = { 8B 44 24 04 8D 54 24 FC 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeBundlev30standardloader
	{
	strings:
			$a0 = { 00 00 00 00 60 BE 00 B0 42 00 8D BE 00 60 FD FF C7 87 B0 E4 02 00 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ProtectionPlusvxx
	{
	strings:
			$a0 = { 50 60 29 C0 64 FF 30 E8 ?? ?? ?? ?? 5D 83 ED 3C 89 E8 89 A5 14 ?? ?? ?? 2B 85 1C ?? ?? ?? 89 85 1C ?? ?? ?? 8D 85 27 03 ?? ?? 50 8B ?? 85 C0 0F 85 C0 ?? ?? ?? 8D BD 5B 03 ?? ?? 8D B5 43 03 ?? ?? E8 DD ?? ?? ?? 89 85 1F 03 ?? ?? 6A 40 68 ?? 10 ?? ?? 8B 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptorV22Xsoftcompletecom
	{
	strings:
			$a0 = { FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 00 }

	condition:
			$a0
	}
	
	
	rule ThinstallVirtualizationSuite30353043ThinstallCompany
	{
	strings:
			$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }

	condition:
			$a0 at (pe.entry_point)
	}
	rule PseudoSigner01CrunchPEHeuristicAnorganix
	{
	strings:
			$a0 = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv120EngdulekxtBorlandC
	{
	strings:
			$a0 = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEPACKv405v406
	{
	strings:
			$a0 = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 06 ?? ?? 8E C0 8B 0E ?? ?? 8B F9 4F 8B F7 FD F3 A4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PeStubOEPv1x
	{
	strings:
			$a0 = { 90 33 C9 33 D2 B8 ?? ?? ?? 00 B9 FF }
	$a1 = { E8 05 00 00 00 33 C0 40 48 C3 E8 05 }

	condition:
			$a0 or $a1
	}
	
	
	rule EXEShieldv01bv03bv03SMoKE
	{
	strings:
			$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEArmor049Hying
	{
	strings:
			$a0 = { 56 52 51 53 55 E8 15 01 00 00 32 ?? ?? 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv14x
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PocketPCSHA
	{
	strings:
			$a0 = { 86 2F 96 2F A6 2F B6 2F 22 4F 43 68 53 6B 63 6A 73 69 F0 7F 0B D0 0B 40 09 00 09 D0 B3 65 A3 66 93 67 0B 40 83 64 03 64 04 D0 0B 40 09 00 10 7F 26 4F F6 6B F6 6A F6 69 0B 00 F6 68 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 22 4F F0 7F 0A D0 06 D4 06 D5 0B 40 09 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule eXPressorV1451CGSoftLabs
	{
	strings:
			$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? 00 05 00 ?? ?? 00 A3 08 ?? ?? 00 A1 08 ?? ?? 00 B9 81 ?? ?? 00 2B 48 18 89 0D 0C ?? ?? 00 83 3D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Thinstall25
	{
	strings:
			$a0 = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D A7 1A 00 00 B9 6C 1A 00 00 BA 20 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD EC 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? 81 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SuckStopv111
	{
	strings:
			$a0 = { EB ?? ?? ?? BE ?? ?? B4 30 CD 21 EB ?? 9B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DEFv10
	{
	strings:
			$a0 = { BE ?? 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 }
	$a1 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? 10 40 00 C3 }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	
	rule UnnamedScrambler251Beta2252p0ke
	{
	strings:
			$a0 = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? ?? 40 00 E8 ?? EA FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 BA ?? ?? 40 00 B8 ?? ?? 40 00 E8 63 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? ?? FF FF BA ?? ?? 40 00 8B C3 8B 0D ?? ?? 40 00 E8 ?? ?? FF FF C7 05 ?? ?? 40 00 0A 00 00 00 BB ?? ?? 40 00 BE ?? ?? 40 00 BF ?? ?? 40 00 B8 ?? ?? 40 00 BA 04 00 00 00 E8 ?? EB FF FF 83 3B 00 74 04 33 C0 89 03 8B D7 8B C6 E8 0A F3 FF FF 89 03 83 3B 00 0F 84 F7 04 00 00 B8 ?? ?? 40 00 8B 16 E8 ?? E1 FF FF B8 ?? ?? 40 00 E8 ?? E0 FF FF 8B D0 8B 03 8B 0E E8 ?? ?? FF FF 8B C7 A3 ?? ?? 40 00 8D 55 EC 33 C0 E8 ?? D3 FF FF 8B 45 EC B9 ?? ?? 40 00 BA ?? ?? 40 00 E8 8B ED FF FF 3C 01 75 2B A1 }

	condition:
			$a0
	}
	
	
	rule Crunchv40
	{
	strings:
			$a0 = { EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 18 00 00 00 8B C5 55 60 9C 2B 85 E9 06 00 00 89 85 E1 06 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PrivateEXEProtector18SetiSoft
	{
	strings:
			$a0 = { A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 FF 31 F6 C3 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner02Armadillo300Anorganix
	{
	strings:
			$a0 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule hmimyssPEPack01hmimys
	{
	strings:
			$a0 = { E8 00 00 00 00 5D 83 ED 05 6A 00 FF 95 E1 0E 00 00 89 85 85 0E 00 00 8B 58 3C 03 D8 81 C3 F8 00 00 00 80 AD 89 0E 00 00 01 89 9D 63 0F 00 00 8B 4B 0C 03 8D 85 0E 00 00 8B 53 08 80 BD 89 0E 00 00 00 75 0C 03 8D 91 0E 00 00 2B 95 91 0E 00 00 89 8D 57 0F 00 00 89 95 5B 0F 00 00 8B 5B 10 89 9D 5F 0F 00 00 8B 9D 5F 0F 00 00 8B 85 57 0F 00 00 53 50 E8 B7 0B 00 00 89 85 73 0F 00 00 6A 04 68 00 10 00 00 50 6A 00 FF 95 E9 0E 00 00 89 85 6B 0F 00 00 6A 04 68 00 10 00 00 68 D8 7C 00 00 6A 00 FF 95 E9 0E 00 00 89 85 6F 0F 00 00 8D 85 67 0F 00 00 8B 9D 73 0F 00 00 8B 8D 6B 0F 00 00 8B 95 5B 0F 00 00 83 EA 0E 8B B5 57 0F 00 00 83 C6 0E 8B BD 6F 0F 00 00 50 53 51 52 56 68 D8 7C 00 00 57 E8 01 01 00 00 8B 9D 57 0F 00 00 8B 03 3C 01 75 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PECompactv146
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 60 12 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02XCR011Anorganix
	{
	strings:
			$a0 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEPACKLINKv360v364v365or50121
	{
	strings:
			$a0 = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 ?? ?? ?? 8E C0 8B ?? ?? ?? 8B ?? 4F 8B F7 FD F3 A4 50 B8 ?? ?? 50 CB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SpecialEXEPasswordProtectorv10
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RCryptor15Vaska
	{
	strings:
			$a0 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? ?? EB F3 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeJoiner10Yoda
	{
	strings:
			$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50 E8 E2 02 00 00 83 F8 FF 0F 84 6D 02 00 00 A3 0C 12 40 00 8B D8 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 E8 E3 02 00 00 6A 00 68 3C 12 40 00 6A 04 68 1E 12 40 00 FF 35 08 12 40 00 E8 C4 02 00 00 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackV119DllaPlib043ap0x
	{
	strings:
			$a0 = { 80 7C 24 08 01 0F 85 89 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CrypKeyV56XKenonicControlsLtd
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 00 75 07 6A 00 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Safe20
	{
	strings:
			$a0 = { 83 EC 10 53 56 57 E8 C4 01 00 }

	condition:
			$a0
	}
	
	
	rule MicrosoftVisualCV80
	{
	strings:
			$a0 = { 6A 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 94 00 00 00 53 6A 00 8B ?? ?? ?? ?? ?? FF D7 50 FF ?? ?? ?? ?? ?? 8B F0 85 F6 75 0A 6A 12 E8 ?? ?? ?? ?? 59 EB 18 89 1E 56 FF ?? ?? ?? ?? ?? 56 85 C0 75 14 50 FF D7 50 FF ?? ?? ?? ?? ?? B8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule MZ_Crypt10byBrainSt0rm
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 25 14 40 00 8B BD 77 14 40 00 8B 8D 7F 14 40 00 EB 28 83 7F 1C 07 75 1E 8B 77 0C 03 B5 7B 14 40 00 33 C0 EB 0C 50 8A A5 83 14 40 00 30 26 58 40 46 3B 47 10 76 EF 83 C7 28 49 0B C9 75 D4 8B 85 73 14 40 00 89 44 24 1C 61 FF E0 }

	condition:
			$a0
	}
	
	
	rule EPWv130
	{
	strings:
			$a0 = { 06 57 1E 56 55 52 51 53 50 2E 8C 06 08 00 8C C0 83 C0 10 2E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WindofCrypt10byDarkPressure
	{
	strings:
			$a0 = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 64 40 00 10 E8 28 EA FF FF 33 C0 55 68 CE 51 00 10 64 ?? ?? ?? ?? 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 F6 DB FF FF 8B 45 EC E8 12 E7 FF FF 50 E8 3C EA FF FF 8B D8 83 FB FF 0F 84 A6 00 00 00 6A 00 53 E8 41 EA FF FF 8B F0 81 EE 00 5E 00 00 6A 00 6A 00 68 00 5E 00 00 53 E8 52 EA FF FF B8 F4 97 00 10 8B D6 E8 2E E7 FF FF B8 F8 97 00 10 8B D6 E8 22 E7 FF FF 8B C6 E8 AB D8 FF FF 8B F8 6A 00 68 F0 97 00 10 56 A1 F4 97 00 10 50 53 E8 05 EA FF FF 53 E8 CF E9 FF FF B8 FC 97 00 10 BA E8 51 00 10 E8 74 EA FF FF A1 F4 97 00 10 85 C0 74 05 83 E8 04 8B 00 50 B9 F8 97 00 10 B8 FC 97 00 10 8B 15 F4 97 00 10 E8 D8 EA FF FF B8 FC 97 00 10 E8 5A EB FF FF 8B CE 8B 15 F8 97 00 10 8B C7 E8 EB E9 FF FF 8B C7 85 C0 74 05 E8 E4 EB FF FF 33 C0 5A 59 59 64 89 10 68 D5 51 00 10 8D 45 EC E8 BB E5 FF FF C3 E9 A9 DF FF FF EB F0 5F 5E 5B E8 B7 E4 FF FF 00 00 00 FF FF FF FF 0A 00 00 00 63 5A 6C 56 30 55 6C 6B 70 4D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NTKrnlPackerAshkbizDanehkar
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 }

	condition:
			$a0
	}
	rule PseudoSigner01LCCWin321xAnorganix
	{
	strings:
			$a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NME11Publicbyredlime
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 53 56 B8 30 35 14 13 E8 9A E6 FF FF 33 C0 55 68 6C 36 14 13 64 FF 30 64 89 20 B8 08 5C 14 13 BA 84 36 14 13 E8 7D E2 FF FF E8 C0 EA FF FF 8B 15 CC 45 14 13 A1 C8 45 14 13 E8 04 F8 FF FF 8B 15 D0 45 14 13 A1 C8 45 14 13 E8 F4 F7 FF FF 8B 15 CC 45 14 13 A1 C8 45 14 13 E8 2C F9 FF FF A3 F8 5A 14 13 8B 15 D0 45 14 13 A1 C8 45 14 13 E8 17 F9 FF FF A3 FC 5A 14 13 B8 04 5C 14 13 E8 20 FB FF FF 8B D8 85 DB 74 48 B8 00 5B 14 13 8B 15 C4 45 14 13 E8 1E E7 FF FF A1 04 5C 14 13 E8 A8 DA FF FF ?? ?? ?? ?? 5C 14 13 50 8B CE 8B D3 B8 00 5B 14 13 ?? ?? ?? ?? FF 8B C6 E8 DF FB FF FF 8B C6 E8 9C DA FF FF B8 00 5B 14 13 E8 72 E7 FF FF 33 C0 5A 59 59 64 89 10 68 73 36 14 13 C3 E9 0F DF FF FF EB F8 5E 5B E8 7E E0 FF FF 00 00 FF FF FF FF 0C 00 00 00 4E 4D 45 20 31 2E 31 20 53 74 75 62 }

	condition:
			$a0
	}
	
	
	rule PEtitev13
	{
	strings:
			$a0 = { 66 9C 60 50 8D 88 ?? F0 ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEtitev12
	{
	strings:
			$a0 = { 9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv134v140b1
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 00 80 ?? 40 90 90 01 85 9E 80 ?? 40 BB F8 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakeMSVC70DLLMethod3emadicius
	{
	strings:
			$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEtitev14
	{
	strings:
			$a0 = { 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B CC }
	$a1 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule SoftProtectSoftProtectbyru
	{
	strings:
			$a0 = { EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 60 E8 03 ?? ?? ?? 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 EB 01 83 9C EB 01 D5 EB 08 35 9D EB 01 89 EB 03 0B EB F7 E8 ?? ?? ?? ?? 58 E8 ?? ?? ?? ?? 59 83 01 01 80 39 5C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02CDCopsIIAnorganix
	{
	strings:
			$a0 = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPack118LZMA430ap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 ?? 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv108xAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02BorlandCDLLMethod2Anorganix
	{
	strings:
			$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ARMProtector01bySMoKE
	{
	strings:
			$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElock099cPrivateECLIPSEtE
	{
	strings:
			$a0 = { E9 3F DF FF FF 00 00 00 ?? ?? ?? ?? 04 ?? ?? 00 00 00 00 00 00 00 00 00 24 ?? ?? 00 14 ?? ?? 00 0C ?? ?? 00 00 00 00 00 00 00 00 00 31 ?? ?? 00 1C ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule XPack152164
	{
	strings:
			$a0 = { 8B EC FA 33 C0 8E D0 BC ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASProtectv123RC4build0807dllAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov253b3
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 D8 ?? ?? ?? 68 14 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Imploderv104BoBBobSoft
	{
	strings:
			$a0 = { 60 E8 A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PEiDBundlev100v101BoBBobSoft
	{
	strings:
			$a0 = { 60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule JExeCompressor10byArashVeyskarami
	{
	strings:
			$a0 = { 8D 2D D3 4A E5 14 0F BB F7 0F BA E5 73 0F AF D5 8D 0D 0C 9F E6 11 C0 F8 EF F6 DE 80 DC 5B F6 DA 0F A5 C1 0F C1 F1 1C F3 4A 81 E1 8C 1F 66 91 0F BE C6 11 EE 0F C0 E7 33 D9 64 F2 C0 DC 73 0F C0 D5 55 8B EC BA C0 1F 41 00 8B C2 B9 97 00 00 00 80 32 79 50 B8 02 00 00 00 50 03 14 24 58 58 51 2B C9 B9 01 00 00 00 83 EA 01 E2 FB 59 E2 E1 FF E0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Alloy4xPGWareLLC
	{
	strings:
			$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 A8 33 40 00 0B C0 0F 84 F6 01 00 00 89 85 2E 33 40 00 83 BD E8 32 40 00 01 74 0D 83 BD E4 32 40 00 01 74 2A 8B F8 EB 3E 68 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ThinstallV2403Jitit
	{
	strings:
			$a0 = { 6A 00 FF 15 20 50 40 00 E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 }
	$a1 = { 6A 00 FF 15 20 50 40 00 E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 57 BF 00 00 80 00 39 79 14 77 36 53 56 8B B1 29 04 00 00 8B 41 0C 8B 59 10 03 DB 8A 14 30 83 E2 01 0B D3 C1 E2 07 40 89 51 10 89 41 0C 0F B6 04 30 C1 61 14 08 D1 E8 09 41 10 39 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule FakeNinjav28AntiDebugSpirit
	{
	strings:
			$a0 = { 64 A1 18 00 00 00 EB 02 C3 11 8B 40 30 EB 01 0F 0F B6 40 02 83 F8 01 74 FE EB 01 E8 90 C0 FF FF EB 03 BD F4 B5 64 A1 30 00 00 00 0F B6 40 02 74 01 BA 74 E0 50 00 64 A1 30 00 00 00 83 C0 68 8B 00 EB 00 83 F8 70 74 CF EB 02 EB FE 90 90 90 0F 31 33 C9 03 C8 0F 31 2B C1 3D FF 0F 00 00 73 EA E8 08 00 00 00 C1 3D FF 0F 00 00 74 AA EB 07 E8 8B 40 30 EB 08 EA 64 A1 18 00 00 00 EB F2 90 90 90 BA ?? ?? ?? ?? FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 11 00 00 6A 00 6A 00 FF 35 70 11 40 00 FF 35 84 11 40 00 E8 25 11 00 00 FF }

	condition:
			$a0
	}
	rule ExeLockv100
	{
	strings:
			$a0 = { 06 8C C8 8E C0 BE ?? ?? 26 ?? ?? 34 ?? 26 ?? ?? 46 81 ?? ?? ?? 75 ?? 40 B3 ?? B3 ?? F3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEtitevxx
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EnigmaProtector10XSukhovVladimir
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 83 ?? ?? 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 83 C4 04 EB 02 ?? ?? 60 E8 24 00 00 00 00 00 ?? EB 02 ?? ?? 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 ?? ?? 89 C4 61 EB 2E ?? ?? ?? ?? ?? ?? ?? EB 01 ?? 31 C0 EB 01 ?? 64 FF 30 EB 01 ?? 64 89 20 EB 02 ?? ?? 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 ?? 58 61 EB 01 }

	condition:
			$a0
	}
	
	
	rule ThinstallEmbedded27172719Jitit
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 C1 FE FF FF E9 97 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv102bAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }
	$a1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PEProtect09byCristophGabler1998
	{
	strings:
			$a0 = { 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 }

	condition:
			$a0
	}
	
	
	rule VxPredator2448
	{
	strings:
			$a0 = { 0E 1F BF ?? ?? B8 ?? ?? B9 ?? ?? 49 ?? ?? ?? ?? 2A C1 4F 4F ?? ?? F9 CC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakeMSVC60DLLemadicius
	{
	strings:
			$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RCryptorv16dVaska
	{
	strings:
			$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 }
	$a1 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 90 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	
	rule Enigmaprotector112VladimirSukhov
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 FF 15 89 C4 61 EB 2E EA EB 2B 83 04 24 03 EB 01 00 31 C0 EB 01 85 64 FF 30 EB 01 83 64 89 20 EB 02 CD 20 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 90 58 61 EB 01 3E EB 04 ?? ?? ?? ?? B8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 01 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 05 F6 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 B9 44 1A }

	condition:
			$a0
	}
	
	
	rule hyingsPEArmorV076hying
	{
	strings:
			$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A ?? E8 A3 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule JDPackV200JDPack
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 ?? ?? ?? E8 01 00 00 00 ?? ?? ?? ?? ?? ?? 05 00 00 00 00 83 C4 0C 5D 60 E8 00 00 00 00 5D 8B D5 64 FF 35 00 00 00 00 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv01xv02xDwing
	{
	strings:
			$a0 = { BE 88 01 ?? ?? AD 8B F8 95 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VcasmProtectorV1Xvcasm
	{
	strings:
			$a0 = { EB ?? 5B 56 50 72 6F 74 65 63 74 5D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule kkrunchy023alpha2Ryd
	{
	strings:
			$a0 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF }
	$a1 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF ?? ?? ?? 01 31 C9 41 8D 74 09 01 B8 CA 8E 2A 2E 99 F7 F6 01 C3 89 D8 C1 E8 15 AB FE C1 75 E8 BE }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule PolyEnEV001LennartHedlund
	{
	strings:
			$a0 = { 50 6F 6C 79 45 6E 45 00 4D 65 73 73 61 67 65 42 6F 78 41 00 55 53 45 52 33 32 2E 64 6C 6C }

	condition:
			$a0
	}
	
	
	rule Winkriptv10
	{
	strings:
			$a0 = { 33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule TrainerCreationKitv5Trainer
	{
	strings:
			$a0 = { 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 68 25 45 40 00 E8 3C 02 00 00 50 6A 00 68 40 45 40 00 68 00 10 00 00 68 00 30 40 00 50 E8 54 02 00 00 58 50 E8 17 02 00 00 6A 00 E8 2E 02 00 00 A3 70 45 40 00 68 25 45 40 00 E8 2B 02 00 00 A3 30 45 40 }

	condition:
			$a0
	}
	
	
	rule EXEStealthv272
	{
	strings:
			$a0 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEStealthv273
	{
	strings:
			$a0 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 EB 16 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 60 90 E8 00 00 00 00 5D 81 ED F0 27 40 00 B9 15 00 00 00 83 C1 05 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 }

	condition:
			$a0
	}
	rule PseudoSigner02DEF10Anorganix
	{
	strings:
			$a0 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHpack01FEUERRADER
	{
	strings:
			$a0 = { 60 68 54 ?? ?? ?? B8 48 ?? ?? ?? FF 10 68 B3 ?? ?? ?? 50 B8 44 ?? ?? ?? FF 10 68 00 ?? ?? ?? 6A 40 FF D0 89 05 CA ?? ?? ?? 89 C7 BE 00 10 ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEStealthv274
	{
	strings:
			$a0 = { EB 00 EB 17 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 60 90 E8 00 00 00 00 5D 81 ED C4 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 }

	condition:
			$a0
	}
	
	
	rule ThinstallEmbedded22X2308Jitit
	{
	strings:
			$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 B9 FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PolyCryptorbySMTVersionv3v4
	{
	strings:
			$a0 = { EB ?? 28 50 6F 6C 79 53 63 72 79 70 74 20 ?? ?? ?? 20 62 79 20 53 4D 54 29 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ProtectSharewareV11eCompservCMS
	{
	strings:
			$a0 = { 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 ?? 01 00 00 01 00 30 00 34 00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 34 00 ?? 00 01 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule Upackv035alphaDwing
	{
	strings:
			$a0 = { 8B F2 8B CA 03 4C 19 1C 03 54 1A 20 }

	condition:
			$a0
	}
	
	
	rule ASPackv10801AlexeySolodovnikov
	{
	strings:
			$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D }
	$a1 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D }
	$a2 = { 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
	}
	
	
	rule ENIGMAProtectorV11SukhovVladimir
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 83 ?? ?? 81 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEncrypt20junkcode
	{
	strings:
			$a0 = { EB 25 00 00 F7 BF 00 00 00 00 00 00 00 00 00 00 12 00 E8 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 00 00 E8 00 00 00 00 5D 81 ED 2C 10 40 00 8D B5 14 10 40 00 E8 33 00 00 00 89 85 10 10 40 00 BF 00 00 40 00 8B F7 03 7F 3C 8B 4F 54 51 56 8D 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SimbiOZExtranger
	{
	strings:
			$a0 = { 50 60 E8 00 00 00 00 5D 81 ED 07 10 40 00 68 80 0B 00 00 8D 85 1F 10 40 00 50 E8 84 0B 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule InnoSetupModulev304betav306v307
	{
	strings:
			$a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C }

	condition:
			$a0
	}
	
	
	rule ASPackv107bAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE ?? ?? 80 BD 01 DE }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PROPACKv208emphasisonpackedsizelocked
	{
	strings:
			$a0 = { 83 EC ?? 8B EC BE ?? ?? FC E8 ?? ?? 05 ?? ?? 8B C8 E8 ?? ?? 8B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule HACKSTOPv110p1
	{
	strings:
			$a0 = { B4 30 CD 21 86 E0 3D 00 03 73 ?? B4 2F CD 21 B4 2A CD 21 B4 2C CD 21 B0 FF B4 4C CD 21 50 B8 ?? ?? 58 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AdysGlue110
	{
	strings:
			$a0 = { 2E ?? ?? ?? ?? 0E 1F BF ?? ?? 33 DB 33 C0 AC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxEddiebased1745
	{
	strings:
			$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC ?? 2E ?? ?? ?? ?? 4D 5A ?? ?? FA ?? 8B E6 81 ?? ?? ?? FB ?? 3B ?? ?? ?? ?? ?? 50 06 ?? 56 1E 8B FE 33 C0 ?? 50 8E D8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASDPackv10asd
	{
	strings:
			$a0 = { 55 8B EC 56 53 E8 5C 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 ?? ?? ?? 00 00 00 00 00 00 00 40 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 10 00 00 00 ?? 00 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5B 81 EB E6 1D 40 00 83 7D 0C 01 75 11 55 E8 4F 01 00 00 E8 6A 01 00 00 5D E8 2C 00 00 00 8B B3 1A 1E 40 00 03 B3 FA 1D 40 00 8B 76 0C AD 0B C0 74 0D FF 75 10 FF 75 0C FF 75 08 FF D0 EB EE B8 01 00 00 00 5B 5E C9 C2 0C 00 55 6A 00 FF 93 20 21 40 00 89 83 FA 1D 40 00 6A 40 68 00 10 00 00 FF B3 02 1E 40 00 6A 00 FF 93 2C 21 40 00 89 83 06 1E 40 00 8B 83 F2 1D 40 00 03 83 FA 1D 40 00 50 FF B3 06 1E 40 00 50 E8 6D 01 00 00 5F }

	condition:
			$a0
	}
	
	
	rule ORiENV1XV2XFisunAV
	{
	strings:
			$a0 = { 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F 74 65 63 74 69 6F 6E 20 73 79 73 74 65 6D }

	condition:
			$a0
	}
	
	
	rule StonesPEEncryptorv113
	{
	strings:
			$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 97 3B 40 ?? 2B 95 2D 3C 40 ?? 83 EA 0B 89 95 36 3C 40 ?? 01 95 24 3C 40 ?? 01 95 28 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv302v302aExtractable
	{
	strings:
			$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 33 C9 B1 ?? 51 06 06 BB ?? ?? 53 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ARMProtector03bySMoKE
	{
	strings:
			$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 13 24 40 00 EB 02 83 09 8D B5 A4 24 40 00 EB 02 83 09 BA 4B 15 00 00 EB 01 00 8D 8D EF 39 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 }

	condition:
			$a0
	}
	
	rule VxSlowload
	{
	strings:
			$a0 = { 03 D6 B4 40 CD 21 B8 02 42 33 D2 33 C9 CD 21 8B D6 B9 78 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AntiDote10BetaSISTeam
	{
	strings:
			$a0 = { E8 BB FF FF FF 84 C0 74 2F 68 04 01 00 00 68 C0 23 60 00 6A 00 FF 15 08 10 60 00 E8 40 FF FF FF 50 68 78 11 60 00 68 68 11 60 00 68 C0 23 60 00 E8 AB FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 66 8B 41 06 89 54 24 14 8D 68 FF 85 ED 7C 37 33 C0 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DzAPatcherv13Loader
	{
	strings:
			$a0 = { BF 00 40 40 00 99 68 48 20 40 00 68 00 20 40 00 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35 4C 20 40 00 E8 D2 00 00 00 6A 00 E8 BF 00 00 00 99 68 58 20 40 00 52 52 68 63 10 40 00 52 52 E8 DB 00 00 00 6A FF FF 35 }

	condition:
			$a0
	}
	
	
	rule CDSSS10beta1CyberDoom
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED CA 47 40 00 FF 74 24 20 E8 D3 03 00 00 0B C0 0F 84 13 03 00 00 89 85 B8 4E 40 00 66 8C D8 A8 04 74 0C C7 85 8C 4E 40 00 01 00 00 00 EB 12 64 A1 30 00 00 00 0F B6 40 02 0A C0 0F 85 E8 02 00 00 8D 85 F6 4C 40 00 50 FF B5 B8 4E 40 00 E8 FC 03 00 00 0B C0 0F 84 CE 02 00 00 E8 1E 03 00 00 89 85 90 4E 40 00 8D 85 03 4D 40 00 50 FF B5 B8 4E 40 00 E8 D7 03 00 00 0B C0 0F 84 A9 02 00 00 E8 F9 02 00 00 89 85 94 4E 40 00 8D 85 12 4D 40 00 50 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule y0dasCrypterv10
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED E7 1A 40 00 E8 A1 00 00 00 E8 D1 00 00 00 E8 85 01 00 00 F7 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule y0dasCrypterv11
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 8A 1C 40 00 B9 9E 00 00 00 8D BD 4C 23 40 00 8B F7 33 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NullsoftPiMPInstallSystemv1x
	{
	strings:
			$a0 = { 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 ?? ?? 40 00 50 56 FF 15 ?? ?? 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D ?? ?? 40 00 84 C0 74 ?? 3A C3 74 }

	condition:
			$a0
	}
	
	
	rule ExeBundlev30smallloader
	{
	strings:
			$a0 = { 00 00 00 00 60 BE 00 F0 40 00 8D BE 00 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXAlternativestub
	{
	strings:
			$a0 = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule EmbedPE113cyclotron
	{
	strings:
			$a0 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 B8 5E 2D C6 DA FD 48 63 05 3C 71 B8 5E 97 7C 36 7E 32 7C 08 4F 06 51 64 10 A3 F1 4E CF 25 CB 80 D2 99 54 46 ED E1 D3 46 86 2D 10 68 93 83 5C 46 4D 43 9B 8C D6 7C BB 99 69 97 71 2A 2F A3 38 6B 33 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor2223protectedIAT
	{
	strings:
			$a0 = { CC ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? B4 ?? ?? ?? 08 ?? ?? ?? 00 00 00 00 FF FF FF FF E8 ?? ?? ?? 04 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? 60 ?? ?? ?? 70 ?? ?? ?? 84 ?? ?? ?? 94 ?? ?? ?? A4 ?? ?? ?? 00 00 00 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 4D 65 73 73 61 67 65 42 6F 78 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner01Armadillo300Anorganix
	{
	strings:
			$a0 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptorvxxxx
	{
	strings:
			$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Morphinev33SilentSoftwareSilentShieldc2005
	{
	strings:
			$a0 = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 }
	$a1 = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }

	condition:
			$a0 or $a1
	}
	
	
	rule DEF10bartxt
	{
	strings:
			$a0 = { BE ?? ?? 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv0971v0976
	{
	strings:
			$a0 = { EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule PCShrinkv040b
	{
	strings:
			$a0 = { 9C 60 BD ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 6A ?? FF ?? ?? ?? ?? ?? 50 50 2D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakePECrypt102emadicius
	{
	strings:
			$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 05 50 E8 08 00 00 00 EA FF 58 EB 18 EB 01 0F EB 02 CD 20 EB 03 EA CD 20 58 58 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ORiENv211212FisunAlexander
	{
	strings:
			$a0 = { E9 5D 01 00 00 CE D1 CE ?? 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule StonesPEEncruptorv113
	{
	strings:
			$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASProtectv11MTEc
	{
	strings:
			$a0 = { 90 60 E8 1B ?? ?? ?? E9 FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CreateInstallStubvxx
	{
	strings:
			$a0 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WinZip32bitSFXv8xmodule
	{
	strings:
			$a0 = { 53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 74 01 40 ?? ?? ?? ?? FF 15 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upxv12MarcusLazlo
	{
	strings:
			$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 05 A4 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 F2 31 C0 40 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 E6 31 C9 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEPACKv10byANAKiN1998
	{
	strings:
			$a0 = { 74 ?? E9 ?? ?? ?? ?? 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule NeoLitev20
	{
	strings:
			$a0 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4E 65 6F 4C 69 74 65 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakeSpalsher1x3xFEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 9C 60 8B 44 24 24 E8 00 00 00 00 5D 81 ED 00 00 00 00 50 E8 ED 02 00 00 8C C0 0F 84 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv10803AlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD }
	$a1 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }
	$a2 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD }
	$a3 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point) or $a3 at (pe.entry_point)
	}
	
	
	rule VMProtect07x08PolyTech
	{
	strings:
			$a0 = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }

	condition:
			$a0
	}
	
	
	rule ExeShieldProtectorV36wwwexeshieldcom
	{
	strings:
			$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WerusCrypter10Kas
	{
	strings:
			$a0 = { 68 98 11 40 00 6A 00 E8 50 00 00 00 C9 C3 ED B3 FE FF FF 6A 00 E8 0C 00 00 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 A8 10 40 00 FF 25 B0 10 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 BB E8 12 40 00 80 33 05 E9 7D FF FF FF }

	condition:
			$a0
	}
	
	
	rule Themida10xx1800compressedengineOreansTechnologies
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
	$a1 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 5A ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 5A ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 AF 01 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule CHECKPRGc1992
	{
	strings:
			$a0 = { 33 C0 BE ?? ?? 8B D8 B9 ?? ?? BF ?? ?? BA ?? ?? 47 4A 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule eXPressor11CGSoftLabs
	{
	strings:
			$a0 = { E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxEddie1028
	{
	strings:
			$a0 = { E8 ?? ?? 5E FC 83 ?? ?? 81 ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E B8 FE 4B CD 21 81 FF BB 55 ?? ?? 07 ?? ?? ?? 07 B4 49 CD 21 BB FF FF B4 48 CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEQuakev006byfORGAT
	{
	strings:
			$a0 = { E8 A5 00 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 3D ?? 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? 00 00 5B ?? 00 00 6E ?? 00 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 }

	condition:
			$a0
	}
	
	
	rule LTCv13
	{
	strings:
			$a0 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElockv071b7
	{
	strings:
			$a0 = { 60 E8 48 11 00 00 C3 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElockv071b2
	{
	strings:
			$a0 = { 60 E8 44 11 00 00 C3 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UnknownJoinersignfrompinch260320070212
	{
	strings:
			$a0 = { 44 90 4C 90 B9 DE 00 00 00 BA 00 10 40 00 83 C2 03 44 90 4C B9 07 00 00 00 44 90 4C 33 C9 C7 05 08 30 40 00 00 00 00 00 90 68 00 01 00 00 68 21 30 40 00 6A 00 E8 C5 02 00 00 90 6A 00 68 80 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule DIETv100v100d
	{
	strings:
			$a0 = { BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule APEX_CBLTApex40500mhz
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule StealthPEv11
	{
	strings:
			$a0 = { BA ?? ?? ?? 00 FF E2 BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 03 B8 ?? ?? ?? ?? 89 02 83 C2 FD FF E2 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackFullEdition117DLLAp0x
	{
	strings:
			$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule Anti007V26LiuXingPing
	{
	strings:
			$a0 = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 57 72 69 74 65 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 }

	condition:
			$a0
	}
	
	
	rule AppEncryptorSilentTeam
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 1F 1F 40 00 B9 7B 09 00 00 8D BD 67 1F 40 00 8B F7 AC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VirogenCryptv075
	{
	strings:
			$a0 = { 9C 55 E8 EC 00 00 00 87 D5 5D 60 87 D5 80 BD 15 27 40 00 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov300a
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv300v301Extractable
	{
	strings:
			$a0 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 6A ?? 06 06 8C D3 83 ?? ?? 53 6A ?? FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxUddy2617
	{
	strings:
			$a0 = { 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? 8C C8 8E D8 8C ?? ?? ?? 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? 8C C8 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? B8 AB 9C CD 2F 3D 76 98 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PLINK8619841985
	{
	strings:
			$a0 = { FA 8C C7 8C D6 8B CC BA ?? ?? 8E C2 26 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv10804AlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 41 06 00 00 EB 41 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule aPackv098m
	{
	strings:
			$a0 = { 1E 06 8C C8 8E D8 05 ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B2 ?? BD ?? ?? 33 C9 50 A4 BB ?? ?? 3B F3 76 }

	condition:
			$a0
	}
	
	rule BamBamv001Bedrock
	{
	strings:
			$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 FB ?? ?? 00 E8 6C FD FF FF B9 05 00 00 00 8B F3 BF FB ?? ?? 00 53 F3 A5 E8 8D 05 00 00 8B 3D 03 ?? ?? 00 A1 2B ?? ?? 00 66 8B 15 2F ?? ?? 00 B9 80 ?? ?? 00 2B CF 89 45 E8 89 0D 6B ?? ?? 00 66 89 55 EC 8B 41 3C 33 D2 03 C1 }

	condition:
			$a0
	}
	
	
	rule PESHiELDv02v02bv02b2
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEStealthv27
	{
	strings:
			$a0 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEStealthv25
	{
	strings:
			$a0 = { 60 90 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D E8 00 00 00 00 5D 81 ED 40 1E 40 00 B9 99 09 00 00 8D BD 88 1E 40 00 8B F7 AC }

	condition:
			$a0
	}
	
	
	rule VxHaryanto
	{
	strings:
			$a0 = { 81 EB 2A 01 8B 0F 1E 5B 03 CB 0E 51 B9 10 01 51 CB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPRStripperv2xunpacked
	{
	strings:
			$a0 = { BB ?? ?? ?? ?? E9 ?? ?? ?? ?? 60 9C FC BF ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 AA 9D 61 C3 55 8B EC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01UPX06Anorganix
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Shrinker33
	{
	strings:
			$a0 = { 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

	condition:
			$a0
	}
	
	
	rule Shrinker32
	{
	strings:
			$a0 = { 55 8B EC 56 57 75 65 68 00 01 00 00 E8 F1 E6 FF FF 83 C4 04 }

	condition:
			$a0
	}
	
	
	rule Shrinker34
	{
	strings:
			$a0 = { 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 11 0B 00 00 83 C4 04 }

	condition:
			$a0
	}
	
	
	rule PESPinv13Cyberbob
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PECompactv160v165
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 ?? 87 DD 8B 85 D2 80 40 ?? 01 85 33 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 CE 80 40 ?? BB BB 12 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule eXPressorv120b
	{
	strings:
			$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? 00 2B 05 84 ?? ?? 00 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 00 74 16 A1 ?? ?? ?? 00 03 05 80 ?? ?? 00 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? 00 01 00 00 00 68 04 }

	condition:
			$a0
	}
	
	
	rule EPWv12
	{
	strings:
			$a0 = { 06 57 1E 56 55 52 51 53 50 2E ?? ?? ?? ?? 8C C0 05 ?? ?? 2E ?? ?? ?? 8E D8 A1 ?? ?? 2E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASProtectv12x
	{
	strings:
			$a0 = { 00 00 68 01 ?? ?? ?? C3 AA }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Packanoidv1Arkanoid
	{
	strings:
			$a0 = { BF ?? ?? ?? ?? BE ?? ?? ?? ?? E8 9D 00 00 00 B8 ?? ?? ?? ?? 8B 30 8B 78 04 BB ?? ?? ?? ?? 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EscargotV01Meat
	{
	strings:
			$a0 = { EB 04 40 30 2E 31 60 68 61 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SCObfuscatorSuperCRacker
	{
	strings:
			$a0 = { 60 33 C9 8B 1D 00 ?? ?? ?? 03 1D 08 ?? ?? ?? 8A 04 19 84 C0 74 09 3C ?? 74 05 34 ?? 88 04 19 41 3B 0D 04 ?? ?? ?? 75 E7 A1 08 ?? ?? ?? 01 05 0C ?? ?? ?? 61 FF 25 0C }

	condition:
			$a0
	}
	
	
	rule EXEStealth275WebtoolMaster
	{
	strings:
			$a0 = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PasswordProtectorcMiniSoft1992
	{
	strings:
			$a0 = { 06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxEddie2000
	{
	strings:
			$a0 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E 8B FE 33 C0 50 8E D8 C5 ?? ?? ?? B4 30 CD 21 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VideoLanClientUnknownCompiler
	{
	strings:
			$a0 = { 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule eXPressorv14CGSoftLabs
	{
	strings:
			$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 34 2E 2E B8 }
	$a1 = { 65 58 50 72 2D 76 2E 31 2E 34 2E }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	rule SkDUndetectablerPro20NoUPXMethodSkD
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 B8 FC 26 00 10 E8 EC F3 FF FF 6A 0F E8 15 F5 FF FF E8 64 FD FF FF E8 BB ED FF FF 8D 40 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RJcrushv100
	{
	strings:
			$a0 = { 06 FC 8C C8 BA ?? ?? 03 D0 52 BA ?? ?? 52 BA ?? ?? 03 C2 8B D8 05 ?? ?? 8E DB 8E C0 33 F6 33 FF B9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeShieldv27
	{
	strings:
			$a0 = { EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeShieldv29
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC ?? ?? ?? F8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEiDBundlev102v103BoBBobSoft
	{
	strings:
			$a0 = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtMicrosoftVisualC5060
	{
	strings:
			$a0 = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PUNiSHERV15FEUERRADER
	{
	strings:
			$a0 = { 3F 00 00 80 66 20 ?? 00 7E 20 ?? 00 92 20 ?? 00 A4 20 ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 }

	condition:
			$a0
	}
	
	
	rule ExcaliburV103forgot
	{
	strings:
			$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPack10betaap0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 F9 01 00 00 89 85 48 02 00 00 5B FF B5 }
	$a1 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 F9 01 00 00 89 85 48 02 00 00 5B FF B5 48 02 00 00 56 FF D3 83 C4 08 8B B5 48 02 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 83 C0 04 89 85 44 02 00 00 EB 7A 56 FF 95 F1 01 00 00 89 85 40 02 00 00 8B C6 EB 4F 8B 85 44 02 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 44 02 00 00 C7 00 20 20 20 00 EB 06 FF B5 44 02 00 00 FF B5 40 02 00 00 FF 95 F5 01 00 00 89 07 83 C7 04 8B 85 44 02 00 00 EB 01 40 80 38 00 75 FA 40 89 85 44 02 00 00 80 38 00 75 AC EB 01 46 80 3E 00 75 FA 46 40 8B 38 83 C0 04 89 85 44 02 00 00 80 3E 01 75 81 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 48 02 00 00 FF 95 FD 01 00 00 61 68 ?? ?? ?? ?? C3 60 8B 74 24 24 8B 7C }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	rule nMacrorecorder10
	{
	strings:
			$a0 = { 5C 6E 6D 72 5F 74 65 6D 70 2E 6E 6D 72 00 00 00 72 62 00 00 58 C7 41 00 10 F8 41 00 11 01 00 00 00 00 00 00 46 E1 00 00 46 E1 00 00 35 00 00 00 F6 88 41 00 }

	condition:
			$a0
	}
	
	
	rule PrivateEXEv20a
	{
	strings:
			$a0 = { 53 E8 00 00 00 00 5B 8B C3 2D }
	$a1 = { 06 60 C8 ?? ?? ?? 0E 68 ?? ?? 9A ?? ?? ?? ?? 3D ?? ?? 0F ?? ?? ?? 50 50 0E 68 ?? ?? 9A ?? ?? ?? ?? 0E }
	$a2 = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D ?? ?? ?? ?? 50 81 ?? ?? ?? ?? ?? 8B }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
	}
	
	
	rule PackmanV10BrandonLaCombe
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01PEX099Anorganix
	{
	strings:
			$a0 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PAKSFXArchive
	{
	strings:
			$a0 = { 55 8B EC 83 ?? ?? A1 ?? ?? 2E ?? ?? ?? 2E ?? ?? ?? ?? ?? 8C D7 8E C7 8D ?? ?? BE ?? ?? FC AC 3C 0D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv2xxAlexeySolodovnikov
	{
	strings:
			$a0 = { A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
	$a1 = { A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule SimbiOZ13Extranger
	{
	strings:
			$a0 = { 57 57 8D 7C 24 04 50 B8 00 ?? ?? ?? AB 58 5F C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule muckisprotectorImucki
	{
	strings:
			$a0 = { BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium1339ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 28 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 CF 27 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule LOCK98V10028keenvim
	{
	strings:
			$a0 = { 55 E8 00 00 00 00 5D 81 ?? ?? ?? ?? ?? EB 05 E9 ?? ?? ?? ?? EB 08 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule iPBProtectv013
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 FA 33 DB 89 5D F8 6A 02 EB 01 F8 58 5F 5E 5B 64 8B 25 00 00 00 00 64 8F 05 00 00 00 00 58 58 58 5D 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 }

	condition:
			$a0
	}
	
	
	rule PrivateEXEProtector197SetiSoft
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F4 FC 53 57 56 8B 74 24 20 8B 7C 24 24 66 81 3E 4A 43 0F 85 A5 02 00 00 83 C6 0A 33 DB BA 00 00 00 80 C7 44 24 14 08 00 00 00 43 8D A4 24 00 00 00 00 8B FF 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 2C 8B 4C 24 10 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 02 44 24 0C 88 07 47 EB C6 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 82 6E 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 83 DC 00 00 00 B9 04 00 00 00 33 C0 8D A4 24 00 00 00 00 8D 64 24 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 48 74 B1 0F 89 EF 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 42 BD 00 01 00 00 B9 08 00 00 00 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 88 07 47 4D 75 D6 }

	condition:
			$a0
	}
	
	
	rule ASPackv21AlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASPackv103bAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule FSGv20
	{
	strings:
			$a0 = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner01PEIntro10Anorganix
	{
	strings:
			$a0 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElockv099SpecialBuildheXerforgot
	{
	strings:
			$a0 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 ?? ?? 00 F5 ?? ?? 00 ED ?? ?? 00 00 00 00 00 00 00 00 00 12 ?? ?? 00 FD ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 }
	$a1 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 ?? ?? 00 F5 ?? ?? 00 ED ?? ?? 00 00 00 00 00 00 00 00 00 12 ?? ?? 00 FD ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule VxBackfont900
	{
	strings:
			$a0 = { E8 ?? ?? B4 30 CD 21 3C 03 ?? ?? B8 ?? ?? BA ?? ?? CD 21 81 FA ?? ?? ?? ?? BA ?? ?? 8C C0 48 8E C0 8E D8 80 ?? ?? ?? 5A ?? ?? 03 ?? ?? ?? 40 8E D8 80 ?? ?? ?? 5A ?? ?? 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CrunchPEv20xx
	{
	strings:
			$a0 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 55 BB ?? ?? ?? ?? 03 DD 53 64 67 FF 36 ?? ?? 64 67 89 26 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule Litev003a
	{
	strings:
			$a0 = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SimplePack1XMethod2bagie
	{
	strings:
			$a0 = { 4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
/*    
	rule PKLITE3211PKWAREInc
	{
	strings:
			$a0 = { 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 00 00 00 00 E8 ?? ?? ?? ?? E9 }

	condition:
			$a0 at (pe.entry_point)
	}
*/
	rule PEncryptv10
	{
	strings:
			$a0 = { 60 9C BE 00 10 40 00 8B FE B9 28 03 00 00 BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule BJFntv12RC
	{
	strings:
			$a0 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FishPEShield112116HellFish
	{
	strings:
			$a0 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 BD FE FF FF 89 45 DC E8 E1 FD FF FF 8B 00 03 45 DC 89 45 E4 E8 DC FE FF FF 8B D8 BA 8E 4E 0E EC 8B C3 E8 2E FF FF FF 89 45 F4 BA 04 49 32 D3 8B C3 E8 1F FF FF FF 89 45 F8 BA 54 CA AF 91 8B C3 E8 10 FF FF FF 89 45 F0 BA AC 33 06 03 8B C3 E8 01 FF FF FF 89 45 EC BA 1B C6 46 79 8B C3 E8 F2 FE FF FF 89 45 E8 BA AA FC 0D 7C 8B C3 E8 E3 FE FF FF 89 45 FC 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B }
	$a1 = { 60 E8 EA FD FF FF FF D0 C3 8D 40 00 ?? 00 00 00 2C 00 00 00 ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 ?? ?? 00 ?? ?? 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 00 00 ?? ?? ?? 00 40 ?? ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 40 ?? ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 40 }

	condition:
			$a0 or $a1 at (pe.entry_point)
	}
	
	
	rule CodeCryptv016bv0163b
	{
	strings:
			$a0 = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VOBProtectCD
	{
	strings:
			$a0 = { 5F 81 EF ?? ?? ?? ?? BE ?? ?? 40 ?? 8B 87 ?? ?? ?? ?? 03 C6 57 56 8C A7 ?? ?? ?? ?? FF 10 89 87 ?? ?? ?? ?? 5E 5F }

	condition:
			$a0 at (pe.entry_point)
	}
	rule diProtectorV1XdiProtectorSoftware
	{
	strings:
			$a0 = { 01 00 A0 E3 14 00 00 EB 00 00 20 E0 44 10 9F E5 03 2A A0 E3 40 30 A0 E3 AE 00 00 EB 30 00 8F E5 00 20 A0 E1 3A 0E 8F E2 00 00 80 E2 1C 10 9F E5 20 30 8F E2 0E 00 00 EB 14 00 9F E5 14 10 9F E5 7F 20 A0 E3 C5 00 00 EB 04 C0 8F E2 00 F0 9C E5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PrivateexeProtector20SetiSoftTeam
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule AHTeamEPProtector03fakekkryptor9kryptoraFEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 ?? ?? ?? ?? 5E B9 00 00 00 00 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEBundlev310
	{
	strings:
			$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD ?? ?? ?? ?? 40 00 01 }

	condition:
			$a0
	}
	
	
	rule NsPack34NorthStar
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PellesC280290EXEX86CRTLIB
	{
	strings:
			$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 ?? E8 ?? ?? ?? ?? 59 A3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackV115V117Dllap0x
	{
	strings:
			$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PellesC28x45xPelleOrinius
	{
	strings:
			$a0 = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Thinstallv2460Jitit
	{
	strings:
			$a0 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 F4 18 40 00 50 E8 87 FC FF FF 59 59 A1 94 1A 40 00 8B 40 10 03 05 90 1A 40 00 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 76 0C 00 00 D4 0C 00 00 1E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110Engdulekxt
	{
	strings:
			$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
	$a1 = { E8 01 00 00 00 ?? ?? E8 ?? 00 00 00 }
	$a2 = { EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
	}
	
	
	rule PECompactv2xx
	{
	strings:
			$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

	condition:
			$a0
	}
	
	
	rule ASPackv10802AlexeySolodovnikov
	{
	strings:
			$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillo440SiliconRealmsToolworks
	{
	strings:
			$a0 = { 31 2E 31 2E 34 00 00 00 C2 E0 94 BE 93 FC DE C6 B6 24 83 F7 D2 A4 92 77 40 27 CF EB D8 6F 50 B4 B5 29 24 FA 45 08 04 52 D5 1B D2 8C 8A 1E 6E FF 8C 5F 42 89 F1 83 B1 27 C5 69 57 FC 55 0A DD 44 BE 2A 02 97 6B 65 15 AA 31 E9 28 7D 49 1B DF B5 5D 08 A8 BA A8 }

	condition:
			$a0
	}
	rule Armadillov1xxv2xx
	{
	strings:
			$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule HACKSTOPv111c
	{
	strings:
			$a0 = { B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 ?? CD 21 B0 ?? B4 4C CD 21 53 BB ?? ?? 5B EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEStealth276UnregisteredWebtoolMaster
	{
	strings:
			$a0 = { EB ?? 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 53 68 61 72 65 77 61 72 65 20 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner02LCCWin32DLLAnorganix
	{
	strings:
			$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CDSSSv10Beta1CyberDoomTeamX
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED CA 47 40 00 FF 74 24 20 E8 D3 03 00 00 0B C0 0F 84 13 03 00 00 89 85 B8 4E 40 00 66 8C D8 A8 04 74 0C C7 85 8C 4E 40 00 01 00 00 00 EB 12 64 A1 30 00 00 00 0F B6 40 02 0A C0 0F 85 E8 02 00 00 8D 85 F6 4C 40 00 50 FF B5 B8 4E 40 00 E8 FC 03 00 00 0B C0 0F 84 CE 02 00 00 E8 1E 03 00 00 89 85 90 4E 40 00 8D 85 03 4D 40 00 50 FF B5 B8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElockv041x
	{
	strings:
			$a0 = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 50 8B FE 68 78 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ZCodeWin32PEProtectorv101
	{
	strings:
			$a0 = { E9 12 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9 FB FF FF FF C3 68 ?? ?? ?? ?? 64 FF 35 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ABCCryptor10byZloY
	{
	strings:
			$a0 = { 68 FF 64 24 F0 68 58 58 58 58 90 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 ?? ?? ?? ?? BF 00 ?? ?? ?? B9 00 ?? ?? ?? 80 37 ?? 47 39 CF 75 F8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BF 00 ?? ?? ?? B9 00 ?? ?? ?? 80 37 ?? 47 39 CF 75 F8 }

	condition:
			$a0
	}
	
	
	rule FSGv120EngdulekxtMicrosoftVisualC60
	{
	strings:
			$a0 = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SLVc0deProtectorv061SLV
	{
	strings:
			$a0 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 }
	$a1 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 9D 11 40 00 8D 95 B4 11 40 00 E8 CB 2E 00 00 33 C0 F7 F0 69 8D B5 05 12 40 00 B9 5D 2E 00 00 8B FE AC }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule FSG131dulekxt
	{
	strings:
			$a0 = { BE ?? ?? ?? 00 BF ?? ?? ?? 00 BB ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackFullEdition117aPLibAp0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 74 1F 00 00 8D 9D 1E 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 0F FF 74 37 04 FF 34 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule Crypter31SLESH
	{
	strings:
			$a0 = { 68 FF 64 24 F0 68 58 58 58 58 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner01VBOX43MTEAnorganix
	{
	strings:
			$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakeBJFNT13emadicius
	{
	strings:
			$a0 = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 EB 02 C7 05 EB 02 CD 20 E8 03 00 00 00 E9 EB 04 58 40 50 C3 61 9D 1F EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeCryptor02build002GlOFF
	{
	strings:
			$a0 = { 33 D2 90 1E 68 1B ?? ?? ?? 0F A0 1F 8B 02 90 50 54 8F 02 90 90 8E 64 24 08 FF E2 58 50 33 D2 52 83 F8 01 9B 40 8A 10 89 14 24 90 D9 04 24 90 D9 FA D9 5C 24 FC 8B 5C 24 FC 81 F3 C2 FC 1D 1C 75 E3 74 01 62 FF D0 90 5A 33 C0 8B 54 24 08 90 64 8F 00 90 83 C2 08 52 5C 5A }

	condition:
			$a0
	}
	
	
	rule PackItBitchV10archphase
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule nPackv11250BetaNEOx
	{
	strings:
			$a0 = { 83 3D 04 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 2E ?? ?? ?? 2B 05 08 ?? ?? ?? A3 00 ?? ?? ?? E8 9C 00 00 00 E8 04 02 00 00 E8 FB 06 00 00 E8 1B 06 00 00 A1 00 ?? ?? ?? C7 05 04 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UnpackedBSSFXArchivev19
	{
	strings:
			$a0 = { 1E 33 C0 50 B8 ?? ?? 8E D8 FA 8E D0 BC ?? ?? FB B8 ?? ?? CD 21 3C 03 73 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01VideoLanClientAnorganix
	{
	strings:
			$a0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01PECompact14Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 EB 06 68 90 90 90 90 C3 9C 60 E8 02 90 90 90 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PseudoSigner01DxPack10Anorganix
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Splice11byTw1stedL0gic
	{
	strings:
			$a0 = { 68 00 1A 40 00 E8 EE FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 ?? ?? ?? ?? ?? ?? 50 72 6F 6A 65 63 74 31 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 06 00 00 00 AC 29 40 00 07 00 00 00 BC 28 40 00 07 00 00 00 74 28 40 00 07 00 00 00 2C 28 40 00 07 00 00 00 08 23 40 00 01 00 00 00 38 21 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 8C 21 40 00 08 ?? 40 00 01 00 00 00 AC 19 40 00 00 00 00 00 00 00 00 00 00 00 00 00 AC 19 40 00 4F 00 43 00 50 00 00 00 E7 AF 58 2F 9A 4C 17 4D B7 A9 CA 3E 57 6F F7 76 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv140v145
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB C3 11 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillo300aSiliconRealmsToolworks
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NullsoftInstallSystemv20b4
	{
	strings:
			$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 }
	$a1 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 }

	condition:
			$a0 or $a1
	}
	
	
	rule PESHiELDv01bMTE
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B9 1B 01 ?? ?? D1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule BeRoEXEPackerV100BeRo
	{
	strings:
			$a0 = { BA ?? ?? ?? ?? 8D B2 ?? ?? ?? ?? 8B 46 ?? 85 C0 74 51 03 C2 8B 7E ?? 8B 1E 85 DB 75 02 8B DF 03 DA 03 FA 52 57 50 FF 15 ?? ?? ?? ?? 5F 5A 85 C0 74 2F 8B C8 8B 03 85 C0 74 22 0F BA F0 1F 72 04 8D 44 ?? ?? 51 52 57 50 51 FF 15 ?? ?? ?? ?? 5F 5A 59 85 C0 74 0B AB 83 C3 04 EB D8 83 C6 14 EB AA 61 C3 }

	condition:
			$a0
	}
	rule MSLRHv32aemadicius
	{
	strings:
			$a0 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SpecialEXEPaswordProtectorv101EngPavolCerven
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 00 00 8D 95 C6 77 00 00 8D 8D FF 77 00 00 55 68 00 20 00 00 51 52 6A 00 FF 95 04 7A 00 00 5D 6A 00 FF 95 FC 79 00 00 8D 8D 60 78 00 00 8D 95 85 01 00 00 55 68 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv166
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 5B 11 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv167
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 8B 11 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VIRUSIWormHybris
	{
	strings:
			$a0 = { EB 16 A8 54 ?? ?? 47 41 42 4C 4B 43 47 43 ?? ?? ?? ?? ?? ?? 52 49 53 ?? FC 68 4C 70 40 ?? FF 15 }

	condition:
			$a0
	}
	
	
	rule GPInstallv50332
	{
	strings:
			$a0 = { 55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 B8 C4 1C 41 00 E8 6B 3E FF FF 33 C0 55 68 76 20 41 00 64 FF 30 64 89 20 BA A0 47 41 00 33 C0 E8 31 0A FF FF 33 D2 A1 A0 }

	condition:
			$a0
	}
	
	
	rule PseudoSigner02PEIntro10Anorganix
	{
	strings:
			$a0 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov410SiliconRealmsToolworks
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 D0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 7C A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 78 A5 4C 00 C1 E1 08 03 CA 89 0D 74 A5 4C 00 C1 E8 10 A3 70 A5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AverCryptor102betaos1r1s
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 0C 17 40 00 8B BD 33 18 40 00 8B 8D 3B 18 40 00 B8 51 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 37 18 40 00 33 C0 51 33 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 37 18 40 00 8B 85 3F 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 51 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 2F 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule FSGv131
	{
	strings:
			$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv133
	{
	strings:
			$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule HidePE101BGCorp
	{
	strings:
			$a0 = { BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 F8 FF E2 0D 0A 2D 3D 5B 20 48 69 64 65 50 45 20 62 79 20 42 47 43 6F 72 70 20 5D 3D 2D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXEStealthv11
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED FB 1D 40 00 B9 7B 09 00 00 8B F7 AC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Thinstallvxx
	{
	strings:
			$a0 = { B8 EF BE AD DE 50 6A ?? FF 15 10 19 40 ?? E9 AD FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidium1200ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 3F 1E 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PrivatePersonalPackerPPP103ConquestOfTroycom
	{
	strings:
			$a0 = { E8 19 00 00 00 90 90 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VIRUSIWormBagle
	{
	strings:
			$a0 = { 6A 00 E8 95 01 00 00 E8 9F E6 FF FF 83 3D 03 50 40 00 00 75 14 68 C8 AF 00 00 E8 01 E1 FF FF 05 88 13 00 00 A3 03 50 40 00 68 5C 57 40 00 68 F6 30 40 00 FF 35 03 50 40 00 E8 B0 EA FF FF E8 3A FC FF FF 83 3D 54 57 40 00 00 74 05 E8 F3 FA FF FF 68 E8 03 00 }

	condition:
			$a0
	}
	
	
	rule RLPackv118BasicLZMAAp0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule StonesPEEncryptorv20
	{
	strings:
			$a0 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv029betaDwing
	{
	strings:
			$a0 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PseudoSigner02BJFNT11bAnorganix
	{
	strings:
			$a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXScramblerRCv1x
	{
	strings:
			$a0 = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECrypt15BitShapeSoftware
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 55 20 40 00 B9 7B 09 00 00 8D BD 9D 20 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Upackv021BetaDwing
	{
	strings:
			$a0 = { BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPXFreakV01HMX0101
	{
	strings:
			$a0 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UnnamedScrambler20p0ke
	{
	strings:
			$a0 = { 55 8B EC B9 0A 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 1C 2F 40 00 E8 C8 F1 FF FF 33 C0 55 68 FB 33 40 00 64 FF 30 64 89 20 BA 0C 34 40 00 B8 E4 54 40 00 E8 EF FE FF FF 8B D8 85 DB 75 07 6A 00 E8 5A F2 FF FF BA E8 54 40 00 8B C3 8B 0D E4 54 40 00 E8 74 E2 FF FF C7 05 20 6B 40 00 09 00 00 00 BB 98 69 40 00 C7 45 EC E8 54 40 00 C7 45 E8 31 57 40 00 C7 45 E4 43 60 40 00 BE D3 6A 40 00 BF E0 6A 40 00 83 7B 04 00 75 0B 83 3B 00 0F 86 AA 03 00 00 EB 06 0F 8E A2 03 00 00 8B 03 8B D0 B8 0C 6B 40 00 E8 C1 EE FF FF B8 0C 6B 40 00 E8 6F EE FF FF 8B D0 8B 45 EC 8B 0B E8 0B E2 FF FF 6A 00 6A 1E 6A 00 6A 2C A1 0C 6B 40 00 E8 25 ED FF FF 8D 55 E0 E8 15 FE FF FF 8B 55 E0 B9 10 6B 40 00 A1 0C 6B 40 00 }

	condition:
			$a0
	}
	
	
	rule HACKSTOPv100
	{
	strings:
			$a0 = { FA BD ?? ?? FF E5 6A 49 48 0C ?? E4 ?? 3F 98 3F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ExeShield36wwwexeshieldcom
	{
	strings:
			$a0 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Pe123v200644
	{
	strings:
			$a0 = { 8B C0 EB 01 34 60 EB 01 2A 9C EB 02 EA C8 E8 0F 00 00 00 EB 03 3D 23 23 EB 01 4A EB 01 5B C3 8D 40 00 53 EB 01 6C EB 01 7E EB 01 8F E8 15 01 00 00 50 E8 67 04 00 00 EB 01 9A 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SDProtectorV11xRandyLi
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule BobPackv100BoBBobSoft
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED ?? ?? ?? ?? E8 3D 00 00 00 89 85 ?? ?? ?? ?? 89 C2 B8 5D 0A 00 00 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DBPEv210
	{
	strings:
			$a0 = { 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 ?? E8 B0 EF FF FF 72 03 73 01 75 BE }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NsPackv31NorthStar
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 }
	$a1 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 68 00 80 00 00 6A 00 }

	condition:
			$a0 at (pe.entry_point) or $a1
	}
	
	rule SVKProtectorV13XPavolCerven
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E 00 74 03 46 EB F8 46 E2 E3 8B C5 8B 4C 24 20 2B 85 BD 02 00 00 89 85 B9 02 00 00 80 BD B4 02 00 00 01 75 06 8B 8D 0C 61 00 00 89 8D B5 02 00 00 8D 85 0E 03 00 00 8B DD FF E0 55 68 10 10 00 00 8D 85 B4 00 00 00 50 8D 85 B4 01 00 00 50 6A 00 FF 95 18 61 00 00 5D 6A FF FF 95 10 61 00 00 44 65 62 75 67 67 65 72 20 6F 72 20 74 6F 6F 6C 20 66 6F 72 20 6D 6F 6E 69 74 6F 72 69 6E 67 20 64 65 74 65 63 74 65 64 21 21 21 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakePECrypt102FEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02WATCOMCCEXEAnorganix
	{
	strings:
			$a0 = { E9 00 00 00 00 90 90 90 90 57 41 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PENinja
	{
	strings:
			$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UpackV036Dwing
	{
	strings:
			$a0 = { 0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 10 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 FF 76 08 FF 76 0C BE 1C 01 }
	$a1 = { BE ?? ?? ?? ?? FF 36 E9 C3 00 00 00 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule yodasProtectorv101AshkbizDanehkar
	{
	strings:
			$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPX050070
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 58 83 E8 3D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxVCLencrypted
	{
	strings:
			$a0 = { 01 B9 ?? ?? 81 34 ?? ?? 46 46 E2 F8 C3 }
	$a1 = { 01 B9 ?? ?? 81 35 ?? ?? 47 47 E2 F8 C3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule VxXRCV1015
	{
	strings:
			$a0 = { E8 ?? ?? 5E 83 ?? ?? 53 51 1E 06 B4 99 CD 21 80 FC 21 ?? ?? ?? ?? ?? 33 C0 50 8C D8 48 8E C0 1F A1 ?? ?? 8B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackv118BasicDLLaPLibAp0x
	{
	strings:
			$a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PellesC290300400DLLX86CRTLIB
	{
	strings:
			$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 BF 01 00 00 00 85 DB 75 10 83 3D ?? ?? ?? ?? 00 75 07 31 C0 E9 ?? ?? ?? ?? 83 FB 01 74 05 83 FB 02 75 ?? 85 FF 74 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UnnamedScrambler13Bp0ke
	{
	strings:
			$a0 = { 55 8B EC B9 08 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 98 56 00 10 E8 48 EB FF FF 33 C0 55 68 AC 5D 00 10 64 FF 30 64 89 20 6A 00 68 BC 5D 00 10 68 C4 5D 00 10 6A 00 E8 23 EC FF FF E8 C6 CE FF FF 6A 00 68 BC 5D 00 10 68 ?? ?? ?? ?? 6A 00 E8 0B EC FF FF E8 F2 F4 FF FF B8 08 BC 00 10 33 C9 BA 04 01 00 00 E8 C1 D2 FF FF 6A 00 68 BC 5D 00 10 68 E4 5D 00 10 6A 00 E8 E2 EB FF FF 68 04 01 00 00 68 08 BC 00 10 6A 00 FF 15 68 77 00 10 6A 00 68 BC 5D 00 10 68 FC 5D 00 10 6A 00 E8 BD EB FF FF BA 10 5E 00 10 B8 70 77 00 10 E8 CA F3 FF FF 85 C0 0F 84 F7 05 00 00 BA 74 77 00 10 8B 0D 70 77 00 10 E8 FE CD FF FF 6A 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule HyingsPEArmor075exeHyingCCG
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 ?? ?? 01 00 00 00 00 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 74 ?? ?? ?? 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule SimbiOZPolyCryptorvxxExtranger
	{
	strings:
			$a0 = { 55 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AVPACKv120
	{
	strings:
			$a0 = { 50 1E 0E 1F 16 07 33 F6 8B FE B9 ?? ?? FC F3 A5 06 BB ?? ?? 53 CB }

	condition:
			$a0 at (pe.entry_point)
	}
	rule Armadillov220
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 10 12 41 00 68 F4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule XPack167
	{
	strings:
			$a0 = { B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NullsoftInstallSystemv1xx
	{
	strings:
			$a0 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 }
	$a1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule BobSoftMiniDelphiBoBBobSoft
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 53 56 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 }
	$a1 = { 55 8B EC 83 C4 F0 53 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B8 ?? ?? ?? ?? E8 }
	$a2 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point) or $a2 at (pe.entry_point)
	}
	
	
	rule UltraProV10SafeNet
	{
	strings:
			$a0 = { A1 ?? ?? ?? ?? 85 C0 0F 85 3B 06 00 00 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv1242v1243
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 09 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SimplePack121build0909Method2bagie
	{
	strings:
			$a0 = { 4D 5A 90 EB 01 00 52 E9 8A 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule Obsidium13037ObsidiumSoftware
	{
	strings:
			$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxPhoenix927
	{
	strings:
			$a0 = { E8 00 00 5E 81 C6 ?? ?? BF 00 01 B9 04 00 F3 A4 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Petite14c199899IanLuck
	{
	strings:
			$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC 8D A0 54 BC 00 00 50 8B C3 8D 90 ?? 16 00 00 68 00 00 ?? ?? 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 D8 14 00 00 8B 44 24 18 F6 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule eXPressorV10CGSoftLabs
	{
	strings:
			$a0 = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RECryptv07xCruddRETh2
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B 17 33 55 58 89 17 83 C7 04 83 C1 FC EB EC 8B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PassEXEv20
	{
	strings:
			$a0 = { 06 1E 0E 0E 07 1F BE ?? ?? B9 ?? ?? 87 14 81 ?? ?? ?? EB ?? C7 ?? ?? ?? 84 00 87 ?? ?? ?? FB 1F 58 4A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RECryptv07xCruddRETh1
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 61 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WIBUKeyV410Ahttpwibucomus
	{
	strings:
			$a0 = { F7 05 ?? ?? ?? ?? FF 00 00 00 75 12 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Mew501NorthFoxHCC
	{
	strings:
			$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 00 ?? ?? 00 ?? ?? ?? 00 00 10 40 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01ExeSmasherAnorganix
	{
	strings:
			$a0 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UnnamedScrambler12C12Dp0ke
	{
	strings:
			$a0 = { 55 8B EC B9 05 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? 3A ?? ?? E8 ?? EC FF FF 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 E8 ?? D7 FF FF E8 ?? ?? FF FF B8 20 ?? ?? ?? 33 C9 BA 04 01 00 00 E8 ?? DB FF FF 68 04 01 00 00 68 20 ?? ?? ?? 6A 00 FF 15 10 ?? ?? ?? BA ?? ?? ?? ?? B8 14 ?? ?? ?? E8 ?? ?? FF FF 85 C0 0F 84 ?? 04 00 00 BA 18 ?? ?? ?? 8B 0D 14 ?? ?? ?? E8 ?? ?? FF FF 8B 05 88 ?? ?? ?? 8B D0 B8 54 ?? ?? ?? E8 ?? E3 FF FF B8 54 ?? ?? ?? E8 ?? E2 FF FF 8B D0 B8 18 ?? ?? ?? 8B 0D 88 ?? ?? ?? E8 ?? D6 FF FF FF 35 34 ?? ?? ?? FF 35 30 ?? ?? ?? FF 35 3C ?? ?? ?? FF 35 38 ?? ?? ?? 8D 55 E8 A1 88 ?? ?? ?? E8 ?? F0 FF FF 8B 55 E8 B9 54 }

	condition:
			$a0
	}
	
	
	rule AlexProtectorv04beta1byAlex
	{
	strings:
			$a0 = { 60 E8 01 00 00 00 C7 83 C4 04 33 C9 E8 01 00 00 00 68 83 C4 04 E8 01 00 00 00 68 83 C4 04 B9 ?? 00 00 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 01 00 00 00 C7 83 C4 04 8B 2C 24 83 C4 04 E8 01 00 00 00 A9 83 C4 04 81 ED 3C 13 40 00 E8 01 00 00 00 68 }

	condition:
			$a0
	}
	
	
	rule UG2002Cruncherv03b3
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? E8 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FishPEShield101HellFish
	{
	strings:
			$a0 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 AD FF FF FF 89 45 DC E8 C1 FE FF FF 8B 10 03 55 DC 89 55 E4 83 C0 04 8B 10 89 55 FC 83 C0 04 8B 10 89 55 F4 83 C0 04 8B 10 89 55 F8 83 C0 04 8B 10 89 55 F0 83 C0 04 8B 10 89 55 EC 83 C0 04 8B 00 89 45 E8 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B 46 C7 45 E0 00 00 00 00 83 7B 04 00 74 14 }
	$a1 = { 60 E8 12 FE FF FF C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 28 88 00 00 40 ?? 4B 00 00 00 02 00 00 00 A0 00 00 18 01 00 00 40 ?? 4C 00 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 40 ?? 4E 00 00 00 00 00 00 00 C0 00 00 40 39 00 00 40 ?? 4E 00 00 00 08 00 00 00 00 01 00 C8 06 00 00 40 }

	condition:
			$a0 or $a1 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01Neolite20Anorganix
	{
	strings:
			$a0 = { E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEIntrov10
	{
	strings:
			$a0 = { 8B 04 24 9C 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 45 40 ?? 80 BD 67 44 40 ?? ?? 0F 85 48 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Obsidiumv1250ObsidiumSoftware
	{
	strings:
			$a0 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule DevC4992BloodshedSoftware
	{
	strings:
			$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackV119DllLZMA430ap0x
	{
	strings:
			$a0 = { 80 7C 24 08 01 0F 85 C7 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule XJXPALLiNSoN
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 44 53 56 57 66 9C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule Armadillov220b1
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 30 12 41 00 68 A4 A5 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RCryptor20Vaska
	{
	strings:
			$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SentinelSuperProAutomaticProtectionv641Safenet
	{
	strings:
			$a0 = { A1 ?? ?? ?? ?? 55 8B ?? ?? ?? 85 C0 74 ?? 85 ED 75 ?? A1 ?? ?? ?? ?? 50 55 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 55 51 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 15 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 6A 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 01 00 00 00 5D C2 0C 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule TMTPascalv040
	{
	strings:
			$a0 = { 0E 1F 06 8C 06 ?? ?? 26 A1 ?? ?? A3 ?? ?? 8E C0 66 33 FF 66 33 C9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02CrunchPEHeuristicAnorganix
	{
	strings:
			$a0 = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakeMSVCDLLMethod4emadicius
	{
	strings:
			$a0 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VcAsmProtectorV10XVcAsm
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VBOXv42MTE
	{
	strings:
			$a0 = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakeUPX0896102105124emadicius
	{
	strings:
			$a0 = { 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualC
	{
	strings:
			$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
	$a1 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule VxHafen809
	{
	strings:
			$a0 = { E8 ?? ?? 1C ?? 81 EE ?? ?? 50 1E 06 8C C8 8E D8 06 33 C0 8E C0 26 ?? ?? ?? 07 3D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule RLPackFullEdition117LZMAAp0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 73 26 00 00 8D 9D 58 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01LTC13Anorganix
	{
	strings:
			$a0 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ACProtectv141
	{
	strings:
			$a0 = { 60 76 03 77 01 7B 74 03 75 01 78 47 87 EE E8 01 00 00 00 76 83 C4 04 85 EE EB 01 7F 85 F2 EB 01 79 0F 86 01 00 00 00 FC EB 01 78 79 02 87 F2 61 51 8F 05 19 38 01 01 60 EB 01 E9 E9 01 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule yodasProtectorV1031AshkbizDanehkar
	{
	strings:
			$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 74 72 42 00 8B D5 81 C2 C3 72 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3F A9 42 00 81 E9 6E 73 42 00 8B D5 81 C2 6E 73 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 98 2E 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElock096tE
	{
	strings:
			$a0 = { E9 59 E4 FF FF 00 00 00 00 00 00 00 ?? ?? ?? ?? EE ?? ?? 00 00 00 00 00 00 00 00 00 0E ?? ?? 00 FE ?? ?? 00 F6 ?? ?? 00 00 00 00 00 00 00 00 00 1B ?? ?? 00 06 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WerusCrypter10byKas
	{
	strings:
			$a0 = { BB E8 12 40 00 80 33 05 E9 7D FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule HEALTHv51byMuslimMPolyak
	{
	strings:
			$a0 = { 1E E8 ?? ?? 2E 8C 06 ?? ?? 2E 89 3E ?? ?? 8B D7 B8 ?? ?? CD 21 8B D8 0E 1F E8 ?? ?? 06 57 A1 ?? ?? 26 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PCGuardv303dv305d
	{
	strings:
			$a0 = { 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxNovember17768
	{
	strings:
			$a0 = { E8 ?? ?? 5E 81 EE ?? ?? 50 33 C0 8E D8 80 3E ?? ?? ?? 0E 1F ?? ?? FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule BeRoTinyPascalBeRo
	{
	strings:
			$a0 = { E9 ?? ?? ?? ?? 20 43 6F 6D 70 69 6C 65 64 20 62 79 3A 20 42 65 52 6F 54 69 6E 79 50 61 73 63 61 6C 20 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 32 30 30 36 2C 20 42 65 6E 6A 61 6D 69 6E 20 27 42 65 52 6F 27 20 52 6F 73 73 65 61 75 78 20 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PrivateexeProtector21522XSetiSoftTeam
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule Protectorv1111DDeMPEEnginev09DDeMCIv092
	{
	strings:
			$a0 = { 53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01XCR011Anorganix
	{
	strings:
			$a0 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Trivial173bySMTSMF
	{
	strings:
			$a0 = { EB ?? ?? 28 54 72 69 76 69 61 6C 31 37 33 20 62 79 20 53 4D 54 2F 53 4D 46 29 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ASProtectv11MTE
	{
	strings:
			$a0 = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WARNINGTROJANRobinPE
	{
	strings:
			$a0 = { 60 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PiCryptor10byScofield
	{
	strings:
			$a0 = { 55 8B EC 83 C4 EC 53 56 57 31 C0 89 45 EC B8 40 1E 06 00 E8 48 FA FF FF 33 C0 55 68 36 1F 06 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 31 C0 E8 4E F4 FF FF 8B 45 EC E8 F6 F7 FF FF 50 E8 CC FA FF FF 8B D8 83 FB FF 74 4E 6A 00 53 E8 CD FA FF FF 8B F8 81 EF AC 26 00 00 6A 00 6A 00 68 AC 26 00 00 53 E8 DE FA FF FF 89 F8 E8 E3 F1 FF FF 89 C6 6A 00 68 28 31 06 00 57 56 53 E8 AE FA FF FF 53 E8 80 FA FF FF 89 FA 81 EA 72 01 00 00 8B C6 E8 55 FE FF FF 89 C6 89 F0 09 C0 74 05 E8 A8 FB FF FF 31 C0 }
	$a1 = { 55 8B EC 83 C4 EC 53 56 57 31 C0 89 45 EC B8 40 1E 06 00 E8 48 FA FF FF 33 C0 55 68 36 1F 06 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 31 C0 E8 4E F4 FF FF 8B 45 EC E8 F6 F7 FF FF 50 E8 CC FA FF FF 8B D8 83 FB FF 74 4E 6A 00 53 E8 CD FA FF FF 8B F8 81 EF AC 26 00 00 6A 00 6A 00 68 AC 26 00 00 53 E8 DE FA FF FF 89 F8 E8 E3 F1 FF FF 89 C6 6A 00 68 28 31 06 00 57 56 53 E8 AE FA FF FF 53 E8 80 FA FF FF 89 FA 81 EA 72 01 00 00 8B C6 E8 55 FE FF FF 89 C6 89 F0 09 C0 74 05 E8 A8 FB FF FF 31 C0 5A 59 59 64 89 10 68 3D 1F 06 00 8D 45 EC E8 C3 F6 FF FF C3 }
	$a2 = { 89 55 F8 BB 01 00 00 00 8A 04 1F 24 0F 8B 55 FC 8A 14 32 80 E2 0F 32 C2 8A 14 1F 80 E2 F0 02 D0 88 14 1F 46 8D 45 F4 8B 55 FC E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 3B F0 7E 05 BE 01 00 00 00 43 FF 4D F8 75 C2 ?? ?? ?? ?? 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? C3 E9 }

	condition:
			$a0 or $a1 at (pe.entry_point) or $a2
	}
	
	
	rule PseudoSigner02MacromediaFlashProjector60Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakeWWPack321xemadicius
	{
	strings:
			$a0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 20 64 65 63 6F 6D 70 72 65 73 73 69 6F 6E 20 72 6F 75 74 69 6E 65 20 76 65 72 73 69 6F 6E 20 31 2E 31 32 0D 0A 28 63 29 20 31 39 39 38 20 50 69 6F 74 72 20 57 61 72 65 7A 61 6B 20 61 6E 64 20 52 61 66 61 6C 20 57 69 65 72 7A 62 69 63 6B 69 0D 0A 0D 0A 5D 5B 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEArmor07600765hying
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 00 08 00 00 00 00 00 00 00 60 E8 00 00 00 00 }

	condition:
			$a0
	}
	
	
	rule PECryptv102
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ILUCRYPTv4015exe
	{
	strings:
			$a0 = { 8B EC FA C7 46 F7 ?? ?? 42 81 FA ?? ?? 75 F9 FF 66 F7 }

	condition:
			$a0 at (pe.entry_point)
	}

	rule NJoy13NEX
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 B8 48 36 40 00 E8 54 EE FF FF 6A 00 68 D8 2B 40 00 6A 0A 6A 00 E8 2C EF FF FF E8 23 E7 FF FF 8D 40 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VBOXv43v46
	{
	strings:
			$a0 = { 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 }
	$a1 = { 90 03 C4 33 C4 33 C5 2B C5 33 C5 8B C5 ?? ?? 2B C5 48 ?? ?? 0B C0 86 E0 8C E0 ?? ?? 8C E0 86 E0 03 C4 40 }

	condition:
			$a0 or $a1
	}
	
	
	rule CodeLockvxx
	{
	strings:
			$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CipherWallSelfExtratorDecryptorGUIv15
	{
	strings:
			$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ARMProtectorv01bySMoKE
	{
	strings:
			$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 }

	condition:
			$a0
	}
	
	
	rule Upackv037betaDwing
	{
	strings:
			$a0 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }
	$a1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? ?? 14 00 00 00 00 ?? ?? ?? ?? ?? ?? 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 ?? ?? ?? ?? E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 D2 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 8E FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 51 59 46 AD 85 C0 74 1F }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	rule PrivateExeProtector1xsetisoft
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? B9 ?? 90 01 ?? BE ?? 10 40 ?? 68 50 91 41 ?? 68 01 ?? ?? ?? C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Petitev14
	{
	strings:
			$a0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule NullsoftInstallSystemv20a0
	{
	strings:
			$a0 = { 83 EC 0C 53 56 57 FF 15 B4 10 40 00 05 E8 03 00 00 BE E0 E3 41 00 89 44 24 10 B3 20 FF 15 28 10 40 00 68 00 04 00 00 FF 15 14 11 40 00 50 56 FF 15 10 11 40 00 80 3D E0 E3 41 00 22 75 08 80 C3 02 BE E1 E3 41 00 8A 06 8B 3D 14 12 40 00 84 C0 74 19 3A C3 74 }

	condition:
			$a0
	}
	
	
	rule Obsidium1332ObsidiumSoftware
	{
	strings:
			$a0 = { EB 01 ?? E8 2B 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 3B 27 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule modifiedHACKSTOPv111f
	{
	strings:
			$a0 = { 52 B4 30 CD 21 52 FA ?? FB 3D ?? ?? EB ?? CD 20 0E 1F B4 09 E8 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxKuku886
	{
	strings:
			$a0 = { 06 1E 50 8C C8 8E D8 BA 70 03 B8 24 25 CD 21 ?? ?? ?? ?? ?? 90 B4 2F CD 21 53 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxCIHVersion12TTITWIN95CIH
	{
	strings:
			$a0 = { 55 8D ?? ?? ?? 33 DB 64 87 03 E8 ?? ?? ?? ?? 5B 8D }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ShegerdDongleV478MSCo
	{
	strings:
			$a0 = { E8 32 00 00 00 B8 ?? ?? ?? ?? 8B 18 C1 CB 05 89 DA 36 8B 4C 24 0C }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule SDProtectRandyLi
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule SmokesCryptv12
	{
	strings:
			$a0 = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEncryptv31
	{
	strings:
			$a0 = { E9 ?? ?? ?? 00 F0 0F C6 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PEncryptv30
	{
	strings:
			$a0 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 8D B5 24 10 40 00 8B FE B9 0F 00 00 00 BB ?? ?? ?? ?? AD 33 C3 E2 FA }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RJoiner12byVaska250320071658
	{
	strings:
			$a0 = { 55 8B EC 81 EC 0C 02 00 00 8D 85 F4 FD FF FF 56 50 68 04 01 00 00 FF 15 14 10 40 00 90 8D 85 F4 FD FF FF 50 FF 15 10 10 40 00 90 BE 00 20 40 00 90 83 3E FF 0F 84 84 00 00 00 53 57 33 FF 8D 46 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Minke101byCodius
	{
	strings:
			$a0 = { 55 8B EC 83 C4 F0 53 ?? ?? ?? ?? ?? 10 E8 7A F6 FF FF BE 68 66 00 10 33 C0 55 68 DB 40 00 10 64 FF 30 64 89 20 E8 FA F8 FF FF BA EC 40 00 10 8B C6 E8 F2 FA FF FF 8B D8 B8 6C 66 00 10 8B 16 E8 88 F2 FF FF B8 6C 66 00 10 E8 76 F2 FF FF 8B D0 8B C3 8B 0E E8 E3 E4 FF FF E8 2A F9 FF FF E8 C1 F8 FF FF B8 6C 66 00 10 8B 16 E8 6D FA FF FF E8 14 F9 FF FF E8 AB F8 FF FF 8B 06 E8 B8 E3 FF FF 8B D8 B8 6C 66 00 10 E8 38 F2 FF FF 8B D3 8B 0E E8 A7 E4 FF ?? ?? ?? ?? C4 FB FF FF E8 E7 F8 FF FF 8B C3 E8 B0 E3 FF FF E8 DB F8 FF FF 33 C0 5A 59 59 64 89 10 68 E2 40 00 10 C3 E9 50 EB FF FF EB F8 5E 5B E8 BB EF FF FF 00 00 00 43 41 31 38 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CrypWrapvxx
	{
	strings:
			$a0 = { E8 B8 ?? ?? ?? E8 90 02 ?? ?? 83 F8 ?? 75 07 6A ?? E8 ?? ?? ?? ?? FF 15 49 8F 40 ?? A9 ?? ?? ?? 80 74 0E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WarningmaybeSimbyOZpolycryptorby3xpl01tver2xx250320072200
	{
	strings:
			$a0 = { 57 57 8D 7C 24 04 50 B8 00 D0 17 13 AB 58 5F C3 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WARNINGTROJANHuiGeZi
	{
	strings:
			$a0 = { 55 8B EC 81 C4 ?? FE FF FF 53 56 57 33 C0 89 85 ?? FE FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakeyodascryptor12emadicius
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC 90 2C 8A C0 C0 78 90 04 62 EB 01 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
			$a0 at (pe.entry_point)
	}
	rule EPv10
	{
	strings:
			$a0 = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 00 B8 40 00 03 00 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C ?? ?? ?? ?? C0 33 FE 8B 30 AC 30 D0 C1 F0 10 C2 D0 30 F0 30 C2 C1 AA 10 42 42 CA C1 E2 04 5F E9 5E B1 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule D1S1Gv11betaD1N
	{
	strings:
			$a0 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 01 00 0A 00 00 00 18 00 00 80 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 02 00 00 00 88 00 00 80 38 00 00 80 96 00 00 80 50 00 00 80 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 00 00 68 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 00 00 78 00 00 00 B0 ?? ?? 00 10 00 00 00 00 00 00 00 00 00 00 00 C0 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 06 00 44 00 56 00 43 00 4C 00 41 00 4C 00 0B 00 50 00 41 00 43 00 4B 00 41 00 47 00 45 00 49 00 4E 00 46 00 4F 00 00 00 }

	condition:
			$a0
	}
	
	
	rule PROPACKv208
	{
	strings:
			$a0 = { 8C D3 8E C3 8C CA 8E DA 8B 0E ?? ?? 8B F1 83 ?? ?? 8B FE D1 ?? FD F3 A5 53 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule BlackEnergyDDoSBotCrypter
	{
	strings:
			$a0 = { 55 ?? ?? 81 EC 1C 01 00 00 53 56 57 6A 04 BE 00 30 00 00 56 FF 35 00 20 11 13 6A 00 E8 ?? 03 00 00 ?? ?? 83 C4 10 ?? FF 89 7D F4 0F }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule HACKSTOPv113
	{
	strings:
			$a0 = { 52 B8 ?? ?? 1E CD 21 86 E0 3D ?? ?? 73 ?? CD 20 0E 1F B4 09 E8 ?? ?? 24 ?? EA }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FreeJoiner151GlOFF
	{
	strings:
			$a0 = { 90 87 FF 90 90 B9 2B 00 00 00 BA 07 10 40 00 83 C2 03 90 87 FF 90 90 B9 04 00 00 00 90 87 FF 90 33 C9 C7 05 09 30 40 00 00 00 00 00 68 00 01 00 00 68 21 30 40 00 6A 00 E8 B7 02 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 68 21 30 40 00 E8 8F 02 00 00 A3 19 30 40 00 90 87 FF 90 8B 15 09 30 40 00 81 C2 04 01 00 00 F7 DA 6A 02 6A 00 52 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PeXv099EngbartCrackPl
	{
	strings:
			$a0 = { E9 F5 00 00 00 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule HACKSTOPv119
	{
	strings:
			$a0 = { 52 BA ?? ?? 5A EB ?? 9A ?? ?? ?? ?? 30 CD 21 ?? ?? ?? D6 02 ?? ?? CD 20 0E 1F 52 BA ?? ?? 5A EB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule HACKSTOPv118
	{
	strings:
			$a0 = { 52 BA ?? ?? 5A EB ?? 9A ?? ?? ?? ?? 30 CD 21 ?? ?? ?? FD 02 ?? ?? CD 20 0E 1F 52 BA ?? ?? 5A EB }

	condition:
			$a0 at (pe.entry_point)
	}
	rule PKLITEv200b
	{
	strings:
			$a0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 02 00 72 ?? B4 09 BA ?? ?? CD 21 B8 01 4C CD 21 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 59 2D ?? ?? 8E D0 51 2D ?? ?? 8E C0 50 B9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PKLITEv200c
	{
	strings:
			$a0 = { 50 B8 ?? ?? BA ?? ?? 3B C4 73 ?? 8B C4 2D ?? ?? 25 ?? ?? 8B F8 B9 ?? ?? BE ?? ?? FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule MSLRHv032afakeNeolite20emadicius
	{
	strings:
			$a0 = { E9 A6 00 00 00 B0 7B 40 00 78 60 40 00 7C 60 40 00 00 00 00 00 B0 3F 00 00 12 62 40 00 4E 65 6F 4C 69 74 65 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 43 6F 6D 70 72 65 73 73 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 38 2C 31 39 39 39 20 4E 65 6F 57 6F 72 78 20 49 6E 63 0D 0A 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 37 2D 31 39 39 39 20 4C 65 65 20 48 61 73 69 75 6B 0D 0A 41 6C 6C 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2E 00 00 00 00 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv300v301Relocationspack
	{
	strings:
			$a0 = { BE ?? ?? BA ?? ?? BF ?? ?? B9 ?? ?? 8C CD 8E DD 81 ED ?? ?? 06 06 8B DD 2B DA 8B D3 FC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02CodeSafe20Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner02ZCode101Anorganix
	{
	strings:
			$a0 = { E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxCaz1204
	{
	strings:
			$a0 = { E8 ?? ?? 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ZealPack10Zeal
	{
	strings:
			$a0 = { C7 45 F4 00 00 40 00 C7 45 F0 ?? ?? ?? ?? 8B 45 F4 05 ?? ?? ?? ?? 89 45 F4 C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 89 4D FC 8B 55 FC 3B 55 F0 7D 22 8B 45 F4 03 45 FC 8A 08 88 4D F8 0F BE 55 F8 83 F2 0F 88 55 F8 8B 45 F4 03 45 FC 8A 4D F8 88 08 EB CD FF 65 F4 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule CPAV
	{
	strings:
			$a0 = { E8 ?? ?? 4D 5A B1 01 93 01 00 00 02 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackFullEdition117iBoxLZMAAp0x
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 67 30 00 00 8D 9D 66 03 00 00 33 FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule INCrypter03INinYbyz3e_NiFe
	{
	strings:
			$a0 = { 60 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8D 58 20 C7 03 00 00 00 00 E8 00 00 00 00 5D 81 ED 4D 16 40 00 8B 9D 0E 17 40 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 83 F8 01 75 05 03 DB C1 CB 10 8B 8D 12 17 40 00 8B B5 06 17 40 00 51 81 3E 2E 72 73 72 74 65 8B 85 16 17 40 00 E8 23 00 00 00 8B 85 1A 17 40 00 E8 18 00 00 00 8B 85 1E 17 40 00 E8 0D 00 00 00 8B 85 22 17 40 00 E8 02 00 00 00 EB 18 8B D6 3B 46 0C 72 0A 83 F9 01 74 0B 3B 46 34 72 06 BA 00 00 00 00 C3 58 83 FA 00 75 1A 8B 4E 10 8B 7E 0C 03 BD 02 17 40 00 83 F9 00 74 09 F6 17 31 0F 31 1F 47 E2 F7 59 83 C6 28 49 83 F9 00 75 88 8B 85 0A 17 40 00 89 44 24 1C 61 50 C3 }

	condition:
			$a0
	}
	
	
	rule MorphineV27Holy_FatherRatter29A
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 }

	condition:
			$a0
	}
    
/*    
	rule MicrosoftVisualCV80Debug
	{
	strings:
			$a0 = { E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? E9 }

	condition:
			$a0 at (pe.entry_point)
	}
*/	
	
	rule nBinderv361
	{
	strings:
			$a0 = { 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C 00 5C 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C }

	condition:
			$a0
	}
	
	
	rule MatrixDongleTDiGmbH
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 E8 B6 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? E8 00 00 00 00 5B 2B D9 8B F8 8B 4C 24 2C 33 C0 2B CF F2 AA 8B 3C 24 8B 0A 2B CF 89 5C 24 20 80 37 A2 47 49 75 F9 8D 64 24 04 FF 64 24 FC 60 C7 42 08 ?? ?? ?? ?? E8 C5 FF FF FF C3 C2 F7 29 4E 29 5A 29 E6 86 8A 89 63 5C A2 65 E2 A3 A2 }
	$a1 = { E8 00 00 00 00 E8 00 00 00 00 59 5A 2B CA 2B D1 E8 1A FF FF FF }

	condition:
			$a0 or $a1 at (pe.entry_point)
	}
	
	
	rule NullsoftInstallSystemv20RC2
	{
	strings:
			$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }

	condition:
			$a0
	}
	
	
	rule UnoPiX075BaGiE
	{
	strings:
			$a0 = { 60 E8 07 00 00 00 61 68 ?? ?? 40 00 C3 83 04 24 18 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 61 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule WWPACKv305c4UnextractablePasswordchecking
	{
	strings:
			$a0 = { 03 05 80 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule FSGv110EngdulekxtBorlandDelphi20
	{
	strings:
			$a0 = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Reg2Exe225byJanVorel
	{
	strings:
			$a0 = { 68 68 00 00 00 68 00 00 00 00 68 70 7D 40 00 E8 AE 20 00 00 83 C4 0C 68 00 00 00 00 E8 AF 52 00 00 A3 74 7D 40 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 9C 52 00 00 A3 70 7D 40 00 E8 24 50 00 00 E8 E2 48 00 00 E8 44 34 00 00 E8 54 28 00 00 E8 98 27 00 00 E8 93 20 00 00 68 01 00 00 00 68 D0 7D 40 00 68 00 00 00 00 8B 15 D0 7D 40 00 E8 89 8F 00 00 B8 00 00 10 00 68 01 00 00 00 E8 9A 8F 00 00 FF 35 A4 7F 40 00 68 00 01 00 00 E8 3A 23 00 00 8D 0D A8 7D 40 00 5A E8 5E 1F 00 00 FF 35 A8 7D 40 00 68 00 01 00 00 E8 2A 52 00 00 A3 B4 7D 40 00 FF 35 A4 7F 40 00 FF 35 B4 7D 40 00 FF 35 A8 7D 40 00 E8 5C 0C 00 00 8D 0D A0 7D 40 00 5A E8 26 1F 00 00 FF 35 }

	condition:
			$a0 at (pe.entry_point)
	}
	
/*	
	rule StarForceV3XDLLStarForceCopyProtectionSystem
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
*/	
	
	rule Armadillov420SiliconRealmsToolworks
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 F0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 84 A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 80 A5 4C 00 C1 E1 08 03 CA 89 0D 7C A5 4C 00 C1 E8 10 A3 78 A5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule DalKrypt10byDalKiT
	{
	strings:
			$a0 = { 68 00 10 40 00 58 68 ?? ?? ?? 00 5F 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB ?? ?? ?? 00 72 EB FF E7 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RCryptorv15Vaska
	{
	strings:
			$a0 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F }

	condition:
			$a0 at (pe.entry_point)
	}
	rule EXECryptor239compressedresources
	{
	strings:
			$a0 = { 51 68 ?? ?? ?? ?? 59 81 F1 12 3C CB 98 E9 53 2C 00 00 F7 D7 E9 EB 60 00 00 83 45 F8 02 E9 E3 36 00 00 F6 45 F8 20 0F 84 1E 21 00 00 55 E9 80 62 00 00 87 0C 24 8B E9 ?? ?? ?? ?? 00 00 23 C1 81 E9 ?? ?? ?? ?? 57 E9 ED 00 00 00 0F 88 ?? ?? ?? ?? E9 2C 0D 00 00 81 ED BB 43 CB 79 C1 E0 1C E9 9E 14 00 00 0B 15 ?? ?? ?? ?? 81 E2 2A 70 7F 49 81 C2 9D 83 12 3B E8 0C 50 00 00 E9 A0 16 00 00 59 5B C3 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 41 42 00 00 E9 93 33 00 00 31 DB 89 D8 59 5B C3 A1 ?? ?? ?? ?? 8A 00 2C 99 E9 82 30 00 00 0F 8A ?? ?? ?? ?? B8 01 00 00 00 31 D2 0F A2 25 FF 0F 00 00 E9 72 21 00 00 0F 86 57 0B 00 00 E9 ?? ?? ?? ?? C1 C0 03 E8 F0 36 00 00 E9 41 0A 00 00 81 F7 B3 6E 85 EA 81 C7 ?? ?? ?? ?? 87 3C 24 E9 74 52 00 00 0F 8E ?? ?? ?? ?? E8 5E 37 00 00 68 B1 74 96 13 5A E9 A1 04 00 00 81 D1 49 C0 12 27 E9 50 4E 00 00 C1 C8 1B 1B C3 81 E1 96 36 E5 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule GameGuardv20065xxexesignbyhot_UNP
	{
	strings:
			$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EnigmaProtectorv112LITE
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule MSLRHv01emadicius
	{
	strings:
			$a0 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 }
	$a1 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 }

	condition:
			$a0 or $a1 at (pe.entry_point)
	}
	
	
	rule Apex_cbeta500mhz
	{
	strings:
			$a0 = { 68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VProtector11A12vcasm
	{
	strings:
			$a0 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F 32 30 30 35 5F 33 5F 31 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 }

	condition:
			$a0
	}
	
	
	rule codeCrypter031
	{
	strings:
			$a0 = { 50 58 53 5B 90 BB ?? ?? 40 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }

	condition:
			$a0
	}
	
	
	rule PKTINYv10withTINYPROGv38
	{
	strings:
			$a0 = { 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? E9 ?? ?? E8 ?? ?? 83 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule AHTeamEPProtector03fakePESHiELD2xFEUERRADER
	{
	strings:
			$a0 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule RLPackFullEditionV11Xap0x
	{
	strings:
			$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 10 }

	condition:
			$a0
	}
	
	
	rule Excalibur103forgot
	{
	strings:
			$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule RLPack118DllaPlib043ap0x
	{
	strings:
			$a0 = { 80 7C 24 08 01 0F 85 5C 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01MicrosoftVisualC50MFCAnorganix
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Pohernah101byKas
	{
	strings:
			$a0 = { 60 E8 00 00 00 00 5D 81 ED F1 26 40 00 8B BD 18 28 40 00 8B 8D 20 28 40 00 B8 38 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 1C 28 40 00 31 C0 51 31 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 1C 28 40 00 8B 85 24 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 38 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 14 28 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Armadillov25xv26x
	{
	strings:
			$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PESpinv11Cyberbob
	{
	strings:
			$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Escargot01byueMeat
	{
	strings:
			$a0 = { EB 08 28 65 73 63 30 2E 31 29 60 68 2B ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 5C ?? ?? ?? 8B 00 FF D0 50 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B 46 0C BB 00 00 ?? ?? 03 C3 50 50 B8 54 ?? ?? ?? 8B 00 FF D0 5F 80 3F 00 74 06 C6 07 00 47 EB F5 33 FF 8B 16 0B D2 75 03 8B 56 10 03 D3 03 D7 8B 0A C7 02 00 00 00 00 0B C9 74 4B F7 C1 00 00 00 80 74 14 81 E1 FF FF 00 00 50 51 50 B8 50 }

	condition:
			$a0
	}
	
	
	rule EncryptPE2200461622006630WFS
	{
	strings:
			$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 7A 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule tElockv060
	{
	strings:
			$a0 = { E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01BorlandDelphi30Anorganix
	{
	strings:
			$a0 = { 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule ActiveMARKTMR5311140Trymedia
	{
	strings:
			$a0 = { 79 11 7F AB 9A 4A 83 B5 C9 6B 1A 48 F9 27 B4 25 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule PEBundlev244
	{
	strings:
			$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv120v1201
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 9A 70 40 }

	condition:
			$a0 at (pe.entry_point)
	}
    
rule ASPackv104bAlexeySolodovnikov
	{
	strings:
			$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? ?? 80 BD 08 9D }
	condition:
			$a0 at (pe.entry_point)
	}
	
rule MESSv120
	{
	strings:
			$a0 = { FA B9 ?? ?? F3 ?? ?? E3 ?? EB ?? EB ?? B6 }

	condition:
			$a0 at (pe.entry_point)
	}
/*    
	rule StelthPE101BGCorp
	{
	strings:
			$a0 = { BA ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
*/	

	rule RCryptorv13v14Vaska
	{
	strings:
			$a0 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 }
	$a1 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

	condition:
			$a0 at (pe.entry_point) or $a1 at (pe.entry_point)
	}
	
	
	rule ThinstallV27XJitit
	{
	strings:
			$a0 = { 9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule eXPressor120BetaPEPacker
	{
	strings:
			$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 EB ?? 45 78 50 72 2D 76 2E 31 2E 32 2E 2E }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule Packanoid10ackanoid
	{
	strings:
			$a0 = { BF 00 ?? 40 00 BE ?? ?? ?? 00 E8 9D 00 00 00 B8 ?? ?? ?? 00 8B 30 8B 78 04 BB ?? ?? ?? 00 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 5E EB DB B9 ?? ?? 00 00 BE 00 ?? ?? 00 EB 01 00 BF ?? ?? ?? 00 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	rule EncryptPE1200331812003518WFS
	{
	strings:
			$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv09781
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 49 87 40 ?? 87 DD 8B 85 CE 87 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PECompactv09782
	{
	strings:
			$a0 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 ?? 87 DD 8B 85 56 85 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule PseudoSigner01Gleam100Anorganix
	{
	strings:
			$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule UPackAltStubDwing
	{
	strings:
			$a0 = { 60 E8 09 00 00 00 C3 F6 00 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule VxModificationofHi924
	{
	strings:
			$a0 = { 50 53 51 52 1E 06 9C B8 21 35 CD 21 53 BB ?? ?? 26 ?? ?? 49 48 5B }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule EXECryptor226DLLminimumprotection
	{
	strings:
			$a0 = { 50 8B C6 87 04 24 68 ?? ?? ?? ?? 5E E9 ?? ?? ?? ?? 85 C8 E9 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 0F 81 ?? ?? ?? 00 81 FA ?? ?? ?? ?? 33 D0 E9 ?? ?? ?? 00 0F 8D ?? ?? ?? 00 81 D5 ?? ?? ?? ?? F7 D1 0B 15 ?? ?? ?? ?? C1 C2 ?? 81 C2 ?? ?? ?? ?? 9D E9 ?? ?? ?? ?? C1 E2 ?? C1 E8 ?? 81 EA ?? ?? ?? ?? 13 DA 81 E9 ?? ?? ?? ?? 87 04 24 8B C8 E9 ?? ?? ?? ?? 55 8B EC 83 C4 F8 89 45 FC 8B 45 FC 89 45 F8 8B 45 08 E9 ?? ?? ?? ?? 8B 45 E0 C6 00 00 FF 45 E4 E9 ?? ?? ?? ?? FF 45 E4 E9 ?? ?? ?? 00 F7 D3 0F 81 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 34 24 5E 8B 45 F4 E8 ?? ?? ?? 00 8B 45 F4 8B E5 5D C3 E9 }

	condition:
			$a0 at (pe.entry_point)
	}
	
	
	rule yodasProtector102AshkibizDanehlar
	{
	strings:
			$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 }

	condition:
			$a0 at (pe.entry_point)
	}
	rule ACProtectv135riscosoftwareIncAnticrackSoftware
	{
	strings:
			$a0 = { 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 53 45 52 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 47 65 74 50 72 6F 63 }

	condition:
			$a0
	}
	
	rule openxml_remote_content
{
 meta:
  ref = "https://www.defcon.org/html/defcon-22/dc-22-speakers.html#Crenshaw"
  author = "MalwareTracker.com @mwtracker"
  date = "Aug 10 2014"
  hash = "63ea878a48a7b0459f2e69c46f88f9ef"

  strings:
  $a = "schemas.openxmlformats.org" ascii nocase
  $b = "TargetMode=\"External\"" ascii nocase

  condition:
  all of them
}

rule theme_MH370 {
    meta:
	author = "MalwareTracker.com @mwtracker"
	reference = "http://blog.malwaretracker.com/2014/04/cve-2012-0158-in-mime-html-mso-format.html"
        version = "1.0"
        date = "2014-04-09"
    strings:
        $callsign1 = "MH370" ascii wide nocase fullword
        $callsign2 = "MAS370" ascii wide nocase fullword
        $desc1 = "Flight 370" ascii wide nocase fullword
    condition:
        any of them
}

rule doc_zws_flash {
    meta:
    ref ="2192f9b0209b7e7aa6d32a075e53126d"
    author = "MalwareTracker.com @mwtracker"
    date = "2013-01-11"

    strings:
        $header = {66 55 66 55 ?? ?? ?? 00 5A 57 53}
        $control = "CONTROL ShockwaveFlash.ShockwaveFlash"

    condition:
        all of them
}

rule apt_actor_tran_duy_linh
{
       meta:
		author = "MalwareTracker.com @mwtracker"
         	info = "OLE author"
       strings:
      		$auth = { 4E 6F 72 6D 61 6C 2E 64 6F 74 6D 00 1E 00 00 00 10 00 00 00 54 72 61 6E 20 44 75 79 20 4C 69 6E 68 }

       condition:
               	$auth
}

rule mime_mso
{
meta:
    comment = "mime mso detection"
    ref = "http://blog.malwaretracker.com/2015/03/return-of-mime-mso-now-with-macros.html"
    author = "@mwtracker"
strings:
	$a="application/x-mso"
	$b="MIME-Version"
	$c="ocxstg001.mso"
	$d="?mso-application"
condition:
	$a and $b or $c or $d
}


rule mime_mso_embedded_SuppData
{
meta:
    comment = "mime mso office obfuscation"
    ref = "http://blog.malwaretracker.com/2015/03/return-of-mime-mso-now-with-macros.html"
    hash = "77739ab6c20e9dfbeffa3e2e6960e156"
    author = "@mwtracker"
    date = "Mar 5 2015"

strings:
    $a = "docSuppData"
    $b = "binData"
    $c = "schemas.microsoft.com"

condition:
    all of them
}


rule mime_mso_embedded_ole
{
meta:
    comment = "mime mso office obfuscation"
    ref = "http://blog.malwaretracker.com/2015/03/return-of-mime-mso-now-with-macros.html"
    hash = "77739ab6c20e9dfbeffa3e2e6960e156"
    author = "@mwtracker"
    date = "Mar 5 2015"

strings:
    $a = "docOleData"
    $b = "binData"
    $c = "schemas.microsoft.com"

condition:
    all of them
}

rule mime_mso_vba_macros
{
meta:
    comment = "mime mso office obfuscation"
    ref = "http://blog.malwaretracker.com/2015/03/return-of-mime-mso-now-with-macros.html"
    hash = "77739ab6c20e9dfbeffa3e2e6960e156"
    author = "malwaretracker.com @mwtracker"
    date = "Mar 5 2015"

strings:
    $a = "macrosPresent=\"yes\""
    $b = "schemas.microsoft.com"

condition:
    all of them
}
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_Webshell_PL_ATRIUM_1
{
    meta:
        author = "Mandiant"
        date_created = "2021-04-16"
        md5 = "ca0175d86049fa7c796ea06b413857a3"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $s1 = "CGI::param("
        $s2 = "system("
        $s3 = /if[\x09\x20]{0,32}\(CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)\)\s{0,128}\{[\x09\x20]{0,32}print [\x22\x27]Cache-Control: no-cache\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}print [\x22\x27]Content-type: text\/html\\n\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}my \$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)[\x09\x20]{0,32};\s{0,128}system\([\x22\x27]\$/
    condition:
        all of them
}// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_Trojan_SH_ATRIUM_1
{
    meta:
        author = "Mandiant"
        date_created = "2021-04-16"
        md5 = "a631b7a8a11e6df3fccb21f4d34dbd8a"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $s1 = "CGI::param("
        $s2 = "Cache-Control: no-cache"
        $s3 = "system("
        $s4 = /sed -i [^\r\n]{1,128}CGI::param\([^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Cache-Control: no-cache[^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Content-type: text\/html[^\r\n]{1,128}my [^\r\n]{1,128}=[\x09\x20]{0,32}CGI::param\([^\r\n]{1,128}system\(/
    condition:
        all of them
}rule Backdoor_Win_C3_1
{
    meta:
        author = "FireEye"
        date_created = "2021-05-11"
        description = "Detection to identify the Custom Command and Control (C3) binaries."
        reference = "https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations"
        md5 = "7cdac4b82a7573ae825e5edb48f80be5"
    strings:
        $dropboxAPI = "Dropbox-API-Arg"
        $knownDLLs1 = "WINHTTP.dll" fullword
        $knownDLLs2 = "SHLWAPI.dll" fullword
        $knownDLLs3 = "NETAPI32.dll" fullword
        $knownDLLs4 = "ODBC32.dll" fullword
        $tokenString1 = { 5B 78 5D 20 65 72 72 6F 72 20 73 65 74 74 69 6E 67 20 74 6F 6B 65 6E }
        $tokenString2 = { 5B 78 5D 20 65 72 72 6F 72 20 63 72 65 61 74 69 6E 67 20 54 6F 6B 65 6E }
        $tokenString3 = { 5B 78 5D 20 65 72 72 6F 72 20 64 75 70 6C 69 63 61 74 69 6E 67 20 74 6F 6B 65 6E }
    condition:
        filesize < 5MB and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (((all of ($knownDLLs*)) and ($dropboxAPI or (1 of ($tokenString*)))) or (all of ($tokenString*)))
    }
rule FE_APT_Tool_Linux32_BLOODBANK_1
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-05-17" 
        sha256 = "8bd504ac5fb342d3533fbe0febe7de5c2adcf74a13942c073de6a9db810f9936" 
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html" 
    strings: 
        $sb1 = {0f b6 00 3c 75 [2-6] 8b 85 [4] 8d ?? 01 8b 85 [4] 01 ?? 0f b6 00 3c 73 [2-6] 8b 85 [4]  8d ?? 02 8b 85 [4] 01 ?? 0f b6 00 3c 65 [2-6] 8b 85 [4] 8d ?? 03 8b 85 [4] 01 ?? 0f b6 00 3c 72 [2-6] 8b 85 [4] 8d ?? 04 8b 85 [4] 01 ?? 0f b6 00 3c 40} 
        $sb2 = {0f b6 00 3c 70 [2-6] 8b 85 [4] 8d ?? 01 8b 85 [4] 01 ?? 0f b6 00 3c 61 [2-6] 8b 85 [4]  8d ?? 02 8b 85 [4] 01 ?? 0f b6 00 3c 73 [2-6] 8b 85 [4] 8d ?? 03 8b 85 [4] 01 ?? 0f b6 00 3c 73 [2-6] 8b 85 [4] 8d ?? 04 8b 85 [4] 01 ?? 0f b6 00 3c 77 [2-6] 8b 85 [4] 8d ?? 08 8b 85 [4] 01 ?? 0f b6 00 3c 40} 
        $ss1 = "\x00:%4d-%02d-%02d %02d:%02d:%02d  \x00" 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
}rule FE_APT_Tool_Linux_BLOODBANK_2 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-05-17" 
        sha256 = "8bd504ac5fb342d3533fbe0febe7de5c2adcf74a13942c073de6a9db810f9936" 
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html"  
    strings: 
        $ss1 = "\x00:%4d-%02d-%02d %02d:%02d:%02d  \x00" 
        $ss2 = "\x00ok!\x00" 
        $ss3 = "\x00\x0a\x0a%s:%s   \x00" 
        $ss4 = "\x00PRIMARY!%s   \x00" 
    condition: 
        (uint32(0) == 0x464c457f) and all of them 
}rule FE_APT_Tool_Linux32_BLOODMINE_1 
{ 
    meta: 
        author = "Mandiant" 
        date_created = "2021-05-17" 
        sha256 = "38705184975684c826be28302f5e998cdb3726139aad9f8a6889af34eb2b0385" 
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html" 
    strings: 
        $sb1 = { 6A 01 6A 03 68 [4] E8 [4-32] 50 E8 [4-32] 6A 01 5? 50 E8 [4-32] 50 E8 [4-32] 6A 01 5? 50 E8 [4-32] 6A 01 6A 01 68 [4] E8 [4-32] 8? [0-2] 01 A1 [4] 39 [2] 0F 8? }
        $sb2 = { 68 [4] FF B5 [4] E8 [4-16] 85 C0 7? ?? C7 05 [4] 01 00 00 00 E9 [4-32] 68 [4] FF B5 [4] E8 [4-16] 85 C0 7? ?? C7 05 [4] 02 00 00 00 E9 [4-32] 68 [4] FF B5 [4] E8 [4-16] 85 C0 7? ?? C7 05 [4] 03 00 00 00 E9 } 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
}rule FE_APT_Tool_Linux_BLOODMINE_2 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-05-17" 
        sha256 = "38705184975684c826be28302f5e998cdb3726139aad9f8a6889af34eb2b0385" 
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html" 
    strings: 
        $ss1 = "\x00[+]\x00" 
        $ss2 = "\x00%d-%d-%d-%d-%d-%d\x0a\x00" 
        $ss3 = "\x00[+]The count of saved logs: %d\x0a\x00" 
        $ss4 = "\x00[+]Remember to clear \"%s\", good luck!\x0a\x00" 
    condition: 
        (uint32(0) == 0x464c457f) and all of them 
}rule FE_APT_Tool_Linux32_CLEANPULSE_1 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-05-17" 
        sha256 = "9308cfbd697e4bf76fcc8ff71429fbdfe375441e8c8c10519b6a73a776801ba7" 
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html" 
    strings: 
        $sb1 = { A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 8B ?? 04 } 
        $sb2 = { 8B 00 0F B6 00 3C ?? 74 0F 8B ?? 04 83 C0 10 8B 00 0F B6 00 3C ?? 75 } 
        $ss1 = "\x00OK!\x00" 
        $ss2 = "\x00argv %d error!\x00" 
        $ss3 = "\x00ptrace_write\x00" 
        $ss4 = "\x00ptrace_attach\x00" 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
} rule FE_APT_Tool_Linux_CLEANPULSE_2 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-05-17" 
        sha256 = "9308cfbd697e4bf76fcc8ff71429fbdfe375441e8c8c10519b6a73a776801ba7" 
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html"  
    strings: 
        $sb1 = { 00 89 4C 24 08 FF 52 04 8D 00 } 
        $ss1 = "\x00OK!\x00" 
        $ss2 = "\x00argv %d error!\x00" 
        $ss3 = "\x00ptrace_write\x00" 
        $ss4 = "\x00ptrace_attach\x00" 
    condition: 
        (uint32(0) == 0x464c457f) and all of them 
}rule Dropper_Win_Darkside_1
{
    meta:
        author = "FireEye"
        date_created = "2021-05-11"
        description = "Detection for on the binary that was used as the dropper leading to DARKSIDE."
        reference = "https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations"
    strings:
        $CommonDLLs1 = "KERNEL32.dll" fullword
        $CommonDLLs2 = "USER32.dll" fullword
        $CommonDLLs3 = "ADVAPI32.dll" fullword
        $CommonDLLs4 = "ole32.dll" fullword
        $KeyString1 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 57 69 6E 64 6F 77 73 2E 43 6F 6D 6D 6F 6E 2D 43 6F 6E 74 72 6F 6C 73 22 20 76 65 72 73 69 6F 6E 3D 22 36 2E 30 2E 30 2E 30 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 22 }
        $KeyString2 = { 74 79 70 65 3D 22 77 69 6E 33 32 22 20 6E 61 6D 65 3D 22 4D 69 63 72 6F 73 6F 66 74 2E 56 43 39 30 2E 4D 46 43 22 20 76 65 72 73 69 6F 6E 3D 22 39 2E 30 2E 32 31 30 32 32 2E 38 22 20 70 72 6F 63 65 73 73 6F 72 41 72 63 68 69 74 65 63 74 75 72 65 3D 22 78 38 36 22 20 70 75 62 6C 69 63 4B 65 79 54 6F 6B 65 6E 3D 22 31 66 63 38 62 33 62 39 61 31 65 31 38 65 33 62 22 }
        $Slashes = { 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C 7C }
    condition:
        filesize < 2MB and filesize > 500KB and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (all of ($CommonDLLs*)) and (all of ($KeyString*)) and $Slashes
}

// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Webshell_PL_HARDPULSE 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"      
        md5 = "980cba9e82faf194edb6f3cc20dc73ff"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $r1 = /if[\x09\x20]{0,32}\(\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27]\w{1,64}[\x22\x27]\)\s{0,128}\{\s{1,128}my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}\x3b\s{1,128}unless[\x09\x20]{0,32}\(open\(\$\w{1,64},[\x09\x20]{0,32}\$\w{1,64}\)\)\s{0,128}\{\s{1,128}goto[\x09\x20]{1,32}\w{1,64}[\x09\x20]{0,32}\x3b\s{1,128}return[\x09\x20]{1,32}0[\x09\x20]{0,32}\x3b\s{0,128}\}/ 
        $r2 = /open[\x09\x20]{0,32}\(\*\w{1,64}[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>/ 
        $r3 = /if[\x09\x20]{0,32}\(\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27]\w{1,64}[\x22\x27]\)\s{0,128}\{\s{1,128}print[\x09\x20]{0,32}[\x22\x27]Content-type/ 
        $s1 = "CGI::request_method()" 
        $s2 = "CGI::param(" 
        $s3 = "syswrite(" 
        $s4 = "print $_" 
    condition: 
        all of them 
} rule LOCKBIT_Note_PE_v1

{
    meta:
    reference = "https://www.mandiant.com/resources/unc2165-shifts-to-evade-sanctions"
    
    strings:

 

        $onion = /http:\/\/lockbit[a-z0-9]{9,49}.onion/ ascii wide

        $note1 = "restore-my-files.txt" nocase ascii wide

        $note2 = /lockbit[_-](ransomware|note)\.hta/ nocase ascii wide

        $v2 = "LockBit_2_0_Ransom" nocase wide

 

    condition:

 

        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)

        and $onion

        and (all of ($note*)) and not $v2
}


rule LOCKBIT_Note_PE_v2

{
    meta:
    reference = "https://www.mandiant.com/resources/unc2165-shifts-to-evade-sanctions"
    
        strings:

 

        $onion = /http:\/\/lockbit[a-z0-9]{9,49}.onion/ ascii wide

        $note1 = "restore-my-files.txt" nocase ascii wide

        $note2 = /lockbit[_-](ransomware|note)\.hta/ nocase ascii wide

        $v2 = "LockBit_2_0_Ransom" nocase wide

 

    condition:

 

        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them

}


// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_Linux32_LOCKPICK_1
{
    meta:
        author = "Mandiant"
        date_created = "2021-04-16"
        md5 = "e8bfd3f5a2806104316902bbe1195ee8"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $sb1 = { 83 ?? 63 0F 84 [4] 8B 45 ?? 83 ?? 01 89 ?? 24 89 44 24 04 E8 [4] 85 C0 }
        $sb2 = { 83 [2] 63 74 ?? 89 ?? 24 04 89 ?? 24 E8 [4] 83 [2] 01 85 C0 0F [5] EB 00 8B ?? 04 83 F8 02 7? ?? 83 E8 01 C1 E0 02 83 C0 00 89 44 24 08 8D 83 [4] 89 44 24 04 8B ?? 89 04 24 E8 }
    condition:
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and (@sb1[1] < @sb2[1])
}rule MTI_Hunting_AsRockDriver_Exploit_Generic

{

          meta:

                    author = "Mandiant"

                    date = "03-23-2022"

                    description = "Searching for executables containing strings associated with AsRock driver Exploit."
                    
                    reference = "https://www.mandiant.com/resources/incontroller-state-sponsored-ics-tool"

   

          strings:

                    $dos_stub = "This program cannot be run in DOS mode"

                    $pdb_good = "c:\\asrock\\work\\asrocksdk_v0.0.69\\asrrw\\src\\driver\\src\\objfre_win7_amd64\\amd64\\AsrDrv103.pdb"

   

          condition:

                    all of them and (#dos_stub == 2) and (@pdb_good > @dos_stub[2])

}
rule MTI_Hunting_AsRockDriver_Exploit_PDB

{

          meta:

                    author = "Mandiant"

                    date = "03-23-2022"

                    description = "Searching for executables containing strings associated with AsRock driver Exploit."
                    
                    reference = "https://www.mandiant.com/resources/incontroller-state-sponsored-ics-tool"
   

          strings:

                    $dos_stub = "This program cannot be run in DOS mode"

                    $pdb_bad = "dev projects\\SignSploit1\\x64\\Release\\AsrDrv_exploit.pdb"

                    $pdb_good = "c:\\asrock\\work\\asrocksdk_v0.0.69\\asrrw\\src\\driver\\src\\objfre_win7_amd64\\amd64\\AsrDrv103.pdb"

   

          condition:

                    all of them and (@pdb_bad < @dos_stub[2]) and (#dos_stub == 2) and (@pdb_good > @dos_stub[2])

}
rule MTI_Hunting_INDUSTROYERv2_Bytes {

    meta:

        author = "Mandiant"

        date = "04-09-2022"

        description = "Searching for executables containing bytecode associated with the INDUSTROYER.V2 malware family."
        
        reference = "https://www.mandiant.com/resources/industroyer-v2-old-malware-new-tricks"

   

    strings:

        $bytes = {8B [2] 89 [2] 8B 0D [4] 89 [2] 8B 15 [4] 89 [2] A1 [4] 89 [2] 8B 0D [4] 89 [2] 8A 15 [4] 88 [2] 8D [2] 5? 8B [2] E8}

   

    condition:

        filesize < 3MB and

        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and

        $bytes

}
rule MTI_Hunting_INDUSTROYERv2_Strings {

    meta:

        author = "Mandiant"

        date = "04-09-2022"

        description = "Searching for executables containing strings associated with the INDUSTROYER.V2 malware family."
        
        reference = "https://www.mandiant.com/resources/industroyer-v2-old-malware-new-tricks"


    strings:

        $a1 = "M%X - %02d:%02d:%02d" nocase ascii wide

        $a2 = "%02hu:%02hu:%02hu:%04hu" nocase ascii wide

        $a3 = "%s M%X " nocase ascii wide

        $a4 = "%s: %d: %d" nocase ascii wide

        $a5 = "%s M%X %d (%s)" nocase ascii wide

        $a6 = "%s M%X SGCNT %d" nocase ascii wide

        $a7 = "%s ST%X %d" nocase ascii wide

        $a8 = "Current operation : %s" nocase ascii wide

        $a9 = "Sent=x%X | Received=x%X" nocase ascii wide

        $a10 = "ASDU:%u | OA:%u | IOA:%u | " nocase ascii wide

        $a11 = "Cause: %s (x%X) | Telegram type: %s (x%X" nocase ascii wide

 

        $b1 = "Length:%u bytes | " nocase ascii wide

        $b2 = "Unknown APDU format !!!" nocase ascii wide

        $b3 = "MSTR ->> SLV" nocase ascii wide

        $b4 = "MSTR <<- SLV" nocase ascii wide

 

    condition:

        filesize < 3MB and

        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and

        (1 of ($a*) and 1 of ($b*))

}
rule M_APT_Downloader_BEATDROP

{

    meta:

        author = "Mandiant"

        description = "Rule looking for BEATDROP malware"
        
        reference = "https://www.mandiant.com/resources/tracking-apt29-phishing-campaigns"

    strings:

        $ntdll1 = "ntdll" ascii fullword

        $ntdll2 = "C:\\Windows\\System32\\ntdll.dll" ascii fullword nocase

        $url1 = "api.trello.com" ascii

        $url2 = "/members/me/boards?key=" ascii

        $url3 = "/cards?key=" ascii

    condition:

        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 1MB and all of them

}

import "pe"

rule M_APT_Downloader_BOOMMIC {

  meta:

    author = "Mandiant"

    description = "Rule looking for BOOMMIC malware"
    
    reference = "https://www.mandiant.com/resources/tracking-apt29-phishing-campaigns"


       strings:

       $loc_10001000 = { 55 8B EC 8D 45 0C 50 8B 4D 08 51 6A 02 FF 15 [4] 85 C0 74 09 B8 01 00 00 00 EB 04 EB 02 33 C0 5D C3 }

       $loc_100012fd = {6A 00 8D 55 EC 52 8B 45 D4 50 6A 05 8B 4D E4 51 FF 15 }

       $func1 = "GetComputerNameExA" ascii

       $func2 = "HttpQueryInfoA" ascii

       condition:

       uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 1MB and

       (

              ($loc_10001000 and $func1) or

              ($loc_100012fd and $func2)

       )

}
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_Linux32_PACEMAKER 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"   
        md5 = "d7881c4de4d57828f7e1cab15687274b"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $s1 = "\x00/proc/%d/mem\x00" 
        $s2 = "\x00/proc/%s/maps\x00" 
        $s3 = "\x00/proc/%s/cmdline\x00" 
        $sb1 = { C7 44 24 08 10 00 00 00 C7 44 24 04 00 00 00 00 8D 45 E0 89 04 24 E8 [4] 8B 45 F4 83 C0 0B C7 44 24 08 10 00 00 00 89 44 24 04 8D 45 E0 89 04 24 E8 [4] 8D 45 E0 89 04 24 E8 [4] 85 C0 74 ?? 8D 45 E0 89 04 24 E8 [4] 85 C0 74 ?? 8D 45 E0 89 04 24 E8 [4] EB } 
        $sb2 = { 8B 95 [4] B8 [4] 8D 8D [4] 89 4C 24 10 8D 8D [4] 89 4C 24 0C 89 54 24 08 89 44 24 04 8D 85 [4] 89 04 24 E8 [4] C7 44 24 08 02 00 00 00 C7 44 24 04 00 00 00 00 8B 45 ?? 89 04 24 E8 [4] 89 45 ?? 8D 85 [4] 89 04 24 E8 [4] 89 44 24 08 8D 85 [4] 89 44 24 04 8B 45 ?? 89 04 24 E8 [4] 8B 45 ?? 89 45 ?? C7 45 ?? 00 00 00 00 [0-16] 83 45 ?? 01 8B 45 ?? 3B 45 0C } 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
} // Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_Linux_PACEMAKER 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"     
        md5 = "d7881c4de4d57828f7e1cab15687274b"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $s1 = "\x00Name:%s || Pwd:%s || AuthNum:%s\x0a\x00" 
        $s2 = "\x00/proc/%d/mem\x00" 
        $s3 = "\x00/proc/%s/maps\x00" 
        $s4 = "\x00/proc/%s/cmdline\x00" 
    condition: 
        (uint32(0) == 0x464c457f) and all of them 
}// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Webshell_PL_PULSECHECK_1 
{ 
    meta: 
        author = "Mandiant" 
        date_created = "2021-04-16"  
        sha256 = "a1dcdf62aafc36dd8cf64774dea80d79fb4e24ba2a82adf4d944d9186acd1cc1"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $r1 = /while[\x09\x20]{0,32}\(<\w{1,64}>\)[\x09\x20]{0,32}\{\s{1,256}\$\w{1,64}[\x09\x20]{0,32}\.=[\x09\x20]{0,32}\$_;\s{0,256}\}/ 
        $s1 = "use Crypt::RC4;" 
        $s2 = "use MIME::Base64" 
        $s3 = "MIME::Base64::decode(" 
        $s4 = "popen(" 
        $s5 = " .= $_;" 
        $s6 = "print MIME::Base64::encode(RC4(" 
        $s7 = "HTTP_X_" 
    condition: 
        $s1 and $s2 and (@s3[1] < @s4[1]) and (@s4[1] < @s5[1]) and (@s5[1] < @s6[1]) and (#s7 > 2) and $r1 
} // Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_PULSEJUMP_1
{
    meta:
        author = "Mandiant"
        date_created = "2021-04-16"
        md5 = "91ee23ee24e100ba4a943bb4c15adb4c"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $s1 = "open("
        $s2 = ">>/tmp/"
        $s3 = "syswrite("
        $s4 = /\}[\x09\x20]{0,32}elsif[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{1,32}eq[\x09\x20]{1,32}[\x22\x27](Radius|Samba|AD)[\x22\x27][\x09\x20]{0,32}\)\s{0,128}\{\s{0,128}@\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}&/
    condition:
        all of them
}rule QUIETEXIT_strings

{

    meta:

        author = "Mandiant"
        
        reference = "https://www.mandiant.com/resources/unc3524-eye-spy-email"

        date_created = "2022-01-13"

        date_modified = "2022-01-13"

        rev = 1

    strings:

        $s1 = "auth-agent@openssh.com"

        $s2 = "auth-%.8x-%d"

        $s3 = "Child connection from %s:%s"

        $s4 = "Compiled without normal mode, can't run without -i"

        $s5 = "cancel-tcpip-forward"

        $s6 = "dropbear_prng"

        $s7 = "cron"

    condition:

        uint32be(0) == 0x7F454C46 and filesize < 2MB and all of them

}
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_QUIETPULSE 
{
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"       
        md5 = "00575bec8d74e221ff6248228c509a16"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $s1 = /open[\x09\x20]{0,32}\(\*STDOUT[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>&CLIENT[\x22\x27]\)/ 
        $s2 = /open[\x09\x20]{0,32}\(\*STDERR[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>&CLIENT[\x22\x27]\)/ 
        $s3 = /socket[\x09\x20]{0,32}\(SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}PF_UNIX[\x09\x20]{0,32},[\x09\x20]{0,32}SOCK_STREAM[\x09\x20]{0,32},[\x09\x20]{0,32}0[\x09\x20]{0,32}\)[\x09\x20]{0,32};\s{0,128}unlink/ 
        $s4 = /bind[\x09\x20]{0,32}\([\x09\x20]{0,32}SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}sockaddr_un\(/ 
        $s5 = /listen[\x09\x20]{0,32}\([\x09\x20]{0,32}SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}SOMAXCONN[\x09\x20]{0,32}\)[\x09\x20]{0,32};/ 
        $s6 = /my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}fork\([\x09\x20]{0,32}\)[\x09\x20]{0,32};\s{1,128}if[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{0,32}==[\x09\x20]{0,32}0[\x09\x20]{0,32}\)[\x09\x20]{0,32}\{\s{1,128}exec\(/ 
    condition: 
        all of them 
} // Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_RADIALPULSE_1 
{
    meta: 
        author = "Mandiant" 
        date_created = "2021-04-16"       
        sha256 = "d72daafedf41d484f7f9816f7f076a9249a6808f1899649b7daa22c0447bb37b"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"        
    strings: 
        $s1 = "->getRealmInfo()->{name}" 
        $s2 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>/ 
        $s3 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]realm=\$/ 
        $s4 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]username=\$/ 
        $s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]password=\$/ 
    condition: 
        (@s1[1] < @s2[1]) and (@s2[1] < @s3[1]) and $s4 and $s5 
} // Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_RADIALPULSE_2 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"       
        md5 = "4a2a7cbc1c8855199a27a7a7b51d0117"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $s1 = "open(*fd," 
        $s2 = "syswrite(*fd," 
        $s3 = "close(*fd);" 
        $s4 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>\/tmp\/[\w.]{1,128}[\x22\x27]\);[\x09\x20]{0,32}syswrite\(\*fd,[\x09\x20]{0,32}/ 
        $s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27][\w]{1,128}=\$\w{1,128} ?[\x22\x27],[\x09\x20]{0,32}5000\)/ 
    condition: 
        all of them 
} // Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_RADIALPULSE_3 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"  
        md5 = "4a2a7cbc1c8855199a27a7a7b51d0117"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $s1 = "open(*fd," 
        $s2 = "syswrite(*fd," 
        $s3 = "close(*fd);" 
        $s4 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>\/tmp\/dsstartssh\.statementcounters[\x22\x27]\);[\x09\x20]{0,32}syswrite\(\*fd,[\x09\x20]{0,32}/ 
        $s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27][\w]{1,128}=\$username ?[\x22\x27],[\x09\x20]{0,32}\d{4}\)/ 
    condition: 
        all of them 
} rule Ransomware_Win_DARKSIDE_v1__1
{
    meta:
        author = "FireEye"
        reference = "https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations"
        date_created = "2021-03-22"
        description = "Detection for early versions of DARKSIDE ransomware samples based on the encryption mode configuration values"
		md5 = "1a700f845849e573ab3148daef1a3b0b"
    strings:
		$consts = { 80 3D [4] 01 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] 00 00 04 00 [1-10] 00 00 00 00 [1-30] 80 3D [4] 02 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] FF FF FF FF [1-10] FF FF FF FF [1-30] 03 00 00 00 [1-10] 03 00 00 00 }
	condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $consts
}
rule FE_APT_Webshell_PL_RAPIDPULSE_1
{
    meta:
        author = "Mandiant"  
        date_created = "2021-05-17"
    strings:
        $r1 = /my[\x09\x20]{1,32}@\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}split[\x09\x20]{0,32}\([\x09\x20]{0,32}\x2f\x2f/
        $r2 = /my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}MIME::Base64::decode_base64[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{0,32}\)[\x09\x20]{0,32};[\S\s]{0,128}my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}substr[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{0,32},[\x09\x20]{0,32}\d[\x09\x20]{0,32}\)[\x09\x20]{0,32};[\s\S]{0,64}return[\x09\x20]{1,32}\$/
        $s1 = "use MIME::Base64"
        $s2 = "CGI::param("
        $s3 = "popen"
        $s4 = "print CGI::header()"
        $s5 = "(0..255)"
    condition:
        (all of ($s*)) and (@r1[1] < @r2[1])
}rule REGEORG_Tuneller_generic

{

    meta:

        author = "Mandiant"
        
        reference = "https://www.mandiant.com/resources/unc3524-eye-spy-email"

        date_created = "2021-12-20"

        date_modified = "2021-12-20"

        md5 = "ba22992ce835dadcd06bff4ab7b162f9"

    strings:

        $s1 = "System.Net.IPEndPoint"

        $s2 = "Response.AddHeader"

        $s3 = "Request.InputStream.Read"

        $s4 = "Request.Headers.Get"

        $s5 = "Response.Write"

        $s6 = "System.Buffer.BlockCopy"

        $s7 = "Response.BinaryWrite"

        $s8 = "SocketException soex"

    condition:

        filesize < 1MB and 7 of them

}

// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Webshell_PL_SLIGHTPULSE_1
{
    meta:
        author = "Mandiant" 
        date_created = "2021-04-16"
        sha256 = "133631957d41eed9496ac2774793283ce26f8772de226e7f520d26667b51481a"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $r1 = /if[\x09\x20]{0,32}\(CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)[\x09\x20]{0,32}\)[\x09\x20]{0,32}\{[\x09\x20]{0,32}[\x09\x20]{0,32}\w{1,64}\([\x09\x20]{0,32}\)[\x09\x20]{0,32}\x3b[\x09\x20]{0,32}\}[\x09\x20]{0,32}elsif/
        $r2 = /system[\x09\x20]{0,32}\([\x09\x20]{0,32}[\x22\x27]\$\w{1,64}[\x09\x20]{0,32}>[\x09\x20]{0,32}\/tmp\/\d{1,10}[\x09\x20]{1,32}2[\x09\x20]{0,32}>[\x09\x20]{0,32}&1[\x22\x27][\x09\x20]{0,32}\)[\x09\x20]{0,32}\x3b\s{0,128}open[\x09\x20]{0,32}\([\x09\x20]{0,32}\*\w{1,64}[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27][\x09\x20]{0,32}<[\x09\x20]{0,32}\$\w{1,64}[\x22\x27][\x09\x20]{0,32}\)[\x09\x20]{0,32}\x3b\s{0,128}while[\x09\x20]{0,32}\([\x09\x20]{0,32}<[\x09\x20]{0,32}\w{1,64}[\x09\x20]{0,32}\>[\x09\x20]{0,32}\)[\x09\x20]{0,32}\{/
        $s1 = "CGI::param("
        $s2 = "system("
        $s3 = "Content-type: image/gif\\n\\n" nocase
    condition:
        all of them
}// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Backdoor_Linux32_SLOWPULSE_1 
{ 
    meta: 
        author = "Mandiant" 
        date_created = "2021-04-16"
        sha256 = "cd09ec795a8f4b6ced003500a44d810f49943514e2f92c81ab96c33e1c0fbd68"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"        
    strings: 
        $sb1 = {FC b9 [4] e8 00 00 00 00 5? 8d b? [4] 8b} 
        $sb2 = {f3 a6 0f 85 [4] b8 03 00 00 00 5? 5? 5?} 
        $sb3 = {9c 60 e8 00 00 00 00 5? 8d [5] 85 ?? 0f 8?} 
        $sb4 = {89 13 8b 51 04 89 53 04 8b 51 08 89 53 08} 
        $sb5 = {8d [5] b9 [4] f3 a6 0f 8?} 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
}

rule FE_APT_Backdoor_Linux32_SLOWPULSE_2
{ 
    meta: 
        author = "Strozfriedberg" 
        date_created = "2021-04-16"
        sha256 = "cd09ec795a8f4b6ced003500a44d810f49943514e2f92c81ab96c33e1c0fbd68"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"        
    strings: 
        $sig = /[\x20-\x7F]{16}([\x20-\x7F\x00]+)\x00.{1,32}\xE9.{3}\xFF\x00+[\x20-\x7F][\x20-\x7F\x00]{16}/ 

        // TOI_MAGIC_STRING 
        $exc1 = {ED C3 02 E9 98 56 E5 0C}
    condition:
        uint32(0) == 0x464C457F and (1 of ($sig*)) and (not (1 of ($exc*)))
}
// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Webshell_PL_STEADYPULSE_1
{  
    meta:  
        author = "Mandiant"  
        date_created = "2021-04-16"      
        sha256 = "168976797d5af7071df257e91fcc31ce1d6e59c72ca9e2f50c8b5b3177ad83cc"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"     
    strings:  
        $s1 = "parse_parameters" 
        $s2 = "s/\\+/ /g"  
        $s3 = "s/%(..)/pack("  
        $s4 = "MIME::Base64::encode($"  
        $s5 = "$|=1;" 
        $s6 = "RC4(" 
        $s7 = "$FORM{'cmd'}" 
    condition:  
        all of them  
}// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Tool_SH_THINBLOOD_1
{
    meta:
        author = "Mandiant" 
        date_created = "2021-04-16"
        sha256 = "1741dc0a491fcc8d078220ac9628152668d3370b92a8eae258e34ba28c6473b9"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $s1 = "sed -i \"s/.\\x00[^\\x00]*$2[^\\x00]*\\x09.\\x00//g"
        $s2 = "sed -i \"s/\\"
        $s3 = "\\x00[^\\x00]*$2[^\\x00]*\\x09\\x"
    condition:
        (filesize < 2048) and all of them
}// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Tool_Linux_THINBLOOD_1
{
    meta:
        author = "Mandiant" 
        date_created = "2021-04-16"
        sha256 = "88170125598a4fb801102ad56494a773895059ac8550a983fdd2ef429653f079"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $ss1 = "\x00Clearlog success!\x00"
        $ss2 = "\x00Select log file:%s\x0a\x00"
        $ss3 = "\x00clearlog success\x00"
        $ss4 = "\x00%s match %d records\x0a\x00"
    condition:
        (uint32(0) == 0x464c457f) and all of them
}rule FE_APT_Tool_Linux32_THINBLOOD_1
{
    meta:
        author = "Mandiant" 
        date_created = "2021-04-16"
        sha256 = "88170125598a4fb801102ad56494a773895059ac8550a983fdd2ef429653f079"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $sb1 = { E8 [4-32] 8? 10 [0-16] 89 ?? 24 04 89 04 24 E8 [4-32] 8B 00 89 04 24 E8 [4] E8 [4-32] C7 44 24 ?? 6D 76 20 00 [0-32] F3 AB [0-32] C7 44 24 ?? 72 6D 20 00 [0-32] F3 AB [0-32] 89 04 24 E8 [4-32] 89 04 24 E8 [4-32] 89 04 24 E8 [4-32] 89 04 24 E8 [4-16] 89 04 24 E8 }
    condition:
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them
}rule UNC3524_sha1

{

    meta:

        author = "Mandiant"
        
        reference = "https://www.mandiant.com/resources/unc3524-eye-spy-email"

        date_created = "2022-01-19"

        date_modified = "2022-01-19"

   strings:

        $h1 = { DD E5 D5 97 20 53 27 BF F0 A2 BA CD 96 35 9A AD 1C 75 EB 47 }

    condition:

        uint32be(0) == 0x7F454C46 and filesize < 10MB and all of them

}


import "pe"
rule DevilsTongue_HijackDll
{
meta:
description = "Detects SOURGUM's DevilsTongue hijack DLL"
reference = "https://www.microsoft.com/security/blog/2021/07/15/protecting-customers-from-a-private-sector-offensive-actor-using-0-day-exploits-and-devilstongue-malware/"
author = "Microsoft Threat Intelligence Center (MSTIC)"
date = "2021-07-15"
strings:
$str1 = "windows.old\\windows" wide
$str2 = "NtQueryInformationThread"
$str3 = "dbgHelp.dll" wide
$str4 = "StackWalk64"
$str5 = "ConvertSidToStringSidW"
$str6 = "S-1-5-18" wide
$str7 = "SMNew.dll" // DLL original name
// Call check in stack manipulation
// B8 FF 15 00 00   mov     eax, 15FFh
// 66 39 41 FA      cmp     [rcx-6], ax
// 74 06            jz      short loc_1800042B9
// 80 79 FB E8      cmp     byte ptr [rcx-5], 0E8h ; 'è'
$code1 = {B8 FF 15 00 00 66 39 41 FA 74 06 80 79 FB E8}
// PRNG to generate number of times to sleep 1s before exiting
// 44 8B C0 mov r8d, eax
// B8 B5 81 4E 1B mov eax, 1B4E81B5h
// 41 F7 E8 imul r8d
// C1 FA 05 sar edx, 5
// 8B CA    mov ecx, edx
// C1 E9 1F shr ecx, 1Fh
// 03 D1    add edx, ecx
// 69 CA 2C 01 00 00 imul ecx, edx, 12Ch
// 44 2B C1 sub r8d, ecx
// 45 85 C0 test r8d, r8d
// 7E 19    jle  short loc_1800014D0
$code2 = {44 8B C0 B8 B5 81 4E 1B 41 F7 E8 C1 FA 05 8B CA C1 E9 1F 03 D1 69 CA 2C 01 00 00 44 2B C1 45 85 C0 7E 19}
condition:
filesize < 800KB and
uint16(0) == 0x5A4D and
(pe.characteristics & pe.DLL) and
(
4 of them or
($code1 and $code2) or
(pe.imphash() == "9a964e810949704ff7b4a393d9adda60")
)
}
rule Trojan_Win32_PlaSrv : Platinum
{
  meta:
    author = "Microsoft"
    description = "Hotpatching Injector"
    original_sample_sha1 = "ff7f949da665ba8ce9fb01da357b51415634eaad"
    unpacked_sample_sha1 = "dff2fee984ba9f5a8f5d97582c83fca4fa1fe131"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $Section_name = ".hotp1"
    $offset_x59 = { C7 80 64 01 00 00 00 00 01 00 }

  condition:
    $Section_name and $offset_x59
}

rule Trojan_Win32_Platual : Platinum
{
  meta:
    author = "Microsoft"
    description = "Installer component"
    original_sample_sha1 = "e0ac2ae221328313a7eee33e9be0924c46e2beb9"
    unpacked_sample_sha1 = "ccaf36c2d02c3c5ca24eeeb7b1eae7742a23a86a"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $class_name = "AVCObfuscation"
    $scrambled_dir = { A8 8B B8 E3 B1 D7 FE 85 51 32 3E C0 F1 B7 73 99 }

  condition:$class_name and $scrambled_dir
}

rule Trojan_Win32_Plaplex : Platinum
{
  meta:
    author = "Microsoft"
    description = "Variant of the JPin backdoor"
    original_sample_sha1 = "ca3bda30a3cdc15afb78e54fa1bbb9300d268d66"
    unpacked_sample_sha1 = "2fe3c80e98bbb0cf5a0c4da286cd48ec78130a24"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $class_name1 = "AVCObfuscation"
    $class_name2 = "AVCSetiriControl"

  condition:$class_name1 and $class_name2
}

rule Trojan_Win32_Dipsind_B : Platinum
{
  meta:
    author = "Microsoft"
    description = "Dipsind Family"
    sample_sha1 = "09e0dfbb5543c708c0dd6a89fd22bbb96dc4ca1c"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $frg1 = {8D 90 04 01 00 00 33 C0 F2 AE F7 D1 2B F9 8B C1 8B F7 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 4D EC 8B 15 ?? ?? ?? ?? 89 91 ?? 07 00 00 }
    $frg2 = {68 A1 86 01 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA}
    $frg3 = {C0 E8 07 D0 E1 0A C1 8A C8 32 D0 C0 E9 07 D0 E0 0A C8 32 CA 80 F1 63}

  condition:
    $frg1 and $frg2 and $frg3
}

rule Trojan_Win32_PlaKeylog_B : Platinum
{
  meta:
    author = "Microsoft"
    description = "Keylogger component"
    original_sample_sha1 = "0096a3e0c97b85ca75164f48230ae530c94a2b77"
    unpacked_sample_sha1 = "6a1412daaa9bdc553689537df0a004d44f8a45fd"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $hook = {C6 06 FF 46 C6 06 25}
    $dasm_engine = {80 C9 10 88 0E 8A CA 80 E1 07 43 88 56 03 80 F9 05}

  condition:
    $hook and $dasm_engine
}

rule Trojan_Win32_Adupib : Platinum
{
  meta:
    author = "Microsoft"
    description = "Adupib SSL Backdoor"
    original_sample_sha1 = "d3ad0933e1b114b14c2b3a2c59d7f8a95ea0bcbd"
    unpacked_sample_sha1 = "a80051d5ae124fd9e5cc03e699dd91c2b373978b"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = "POLL_RATE"
    $str2 = "OP_TIME(end hour)"
    $str3 = "%d:TCP:*:Enabled"
    $str4 = "%s[PwFF_cfg%d]"
    $str5 = "Fake_GetDlgItemTextW: ***value***"

  condition:
    $str1 and $str2 and $str3 and $str4 and $str5
}

rule Trojan_Win32_PlaLsaLog : Platinum
{
  meta:
    author = "Microsoft"
    description = "Loader / possible incomplete LSA Password Filter"
    original_sample_sha1 = "fa087986697e4117c394c9a58cb9f316b2d9f7d8"
    unpacked_sample_sha1 = "29cb81dbe491143b2f8b67beaeae6557d8944ab4"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = {8A 1C 01 32 DA 88 1C 01 8B 74 24 0C 41 3B CE 7C EF 5B 5F C6 04 01 00 5E 81 C4 04 01 00 00 C3}
    $str2 = "PasswordChangeNotify"

  condition:
    $str1 and $str2
}

rule Trojan_Win32_Plagon : Platinum
{
  meta:
    author = "Microsoft"
    description = "Dipsind variant"
    original_sample_sha1 = "48b89f61d58b57dba6a0ca857bce97bab636af65"
    unpacked_sample_sha1 = "6dccf88d89ad7b8611b1bc2e9fb8baea41bdb65a"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = "VPLRXZHTU"
    $str2 = {64 6F 67 32 6A 7E 6C}
    $str3 = "Dqpqftk(Wou\"Isztk)"
    $str4 = "StartThreadAtWinLogon"

  condition:
    $str1 and $str2 and $str3 and $str4
}

rule Trojan_Win32_Plakelog : Platinum
{
  meta:
    author = "Microsoft"
    description = "Raw-input based keylogger"
    original_sample_sha1 = "3907a9e41df805f912f821a47031164b6636bd04"
    unpacked_sample_sha1 = "960feeb15a0939ec0b53dcb6815adbf7ac1e7bb2"
    activity_group = "Platinum"
    version = "1.0"
    last_modified= "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = "<0x02>" wide
    $str2 = "[CTR-BRK]" wide
    $str3 = "[/WIN]" wide
    $str4 = {8A 16 8A 18 32 DA 46 88 18 8B 15 08 E6 42 00 40 41 3B CA 72 EB 5E 5B}

  condition:
    $str1 and $str2 and $str3 and $str4
}

rule Trojan_Win32_Plainst : Platinum
{
  meta:
    author = "Microsoft"
    description = "Installer component"
    original_sample_sha1 = "99c08d31af211a0e17f92dd312ec7ca2b9469ecb"
    unpacked_sample_sha1 = "dcb6cf7cf7c8fdfc89656a042f81136bda354ba6"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = {66 8B 14 4D 18 50 01 10 8B 45 08 66 33 14 70 46 66 89 54 77 FE 66 83 7C 77 FE 00 75 B7 8B 4D FC 89 41 08 8D 04 36 89 41 0C 89 79 04}
    $str2 = {4b D391 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}

  condition:
    $str1 and $str2
}

rule Trojan_Win32_Plagicom : Platinum
{
  meta:
    author = "Microsoft"
    description = "Installer component"
    original_sample_sha1 = "99dcb148b053f4cef6df5fa1ec5d33971a58bd1e"
    unpacked_sample_sha1 = "c1c950bc6a2ad67488e675da4dfc8916831239a7"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = {C6 44 24 ?? 68 C6 44 24 ?? 4D C6 44 24 ?? 53 C6 44 24 ?? 56 C6 44 24 ?? 00}
    $str2 = "OUEMM/EMM"
    $str3 = {85 C9 7E 08 FE 0C 10 40 3B C1 7C F8 C3}

  condition:
    $str1 and $str2 and $str3
}

rule Trojan_Win32_Plaklog : Platinum
{
  meta:
    author = "Microsoft"
    description = "Hook-based keylogger"
    original_sample_sha1 = "831a5a29d47ab85ee3216d4e75f18d93641a9819"
    unpacked_sample_sha1 = "e18750207ddbd939975466a0e01bd84e75327dda"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = "++[%s^^unknown^^%s]++"
    $str2 = "vtfs43/emm"
    $str3 = {33 C9 39 4C 24 08 7E 10 8B 44 24 04 03 C1 80 00 08 41 3B 4C 24 08 7C F0 C3}

  condition:
    $str1 and $str2 and $str3
}

rule Trojan_Win32_Plapiio : Platinum
{
  meta:
    author = "Microsoft"
    description = "JPin backdoor"
    original_sample_sha1 = "3119de80088c52bd8097394092847cd984606c88"
    unpacked_sample_sha1 = "3acb8fe2a5eb3478b4553907a571b6614eb5455c"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = "ServiceMain"
    $str2 = "Startup"
    $str3 = {C6 45 ?? 68 C6 45 ?? 4D C6 45 ?? 53 C6 45 ?? 56 C6 45 ?? 6D C6 45 ?? 6D}

  condition:
    $str1 and $str2 and $str3
}

rule Trojan_Win32_Plabit : Platinum
{
  meta:
    author ="Microsoft"
    description = "Installer component"
    sample_sha1 = "6d1169775a552230302131f9385135d385efd166"
    activity_group = "Platinum"
    version= "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = {4b D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}
    $str2= "GetInstanceW"
    $str3 = {8B D0 83 E2 1F 8A 14 0A 30 14 30 40 3B 44 24 04 72 EE}

  condition:
    $str1 and $str2 and $str3
}

  rule Trojan_Win32_Placisc2 : Platinum
{
  meta:
    author = "Microsoft"
    description = "Dipsind variant"
    original_sample_sha1 = "bf944eb70a382bd77ee5b47548ea9a4969de0527"
    unpacked_sample_sha1 = "d807648ddecc4572c7b04405f496d25700e0be6e"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = {76 16 8B D0 83 E2 07 8A 4C 14 24 8A 14 18 32 D1 88 14 18 40 3B C7 72 EA }
    $str2 = "VPLRXZHTU"
    $str3 = "%d) Command:%s"
    $str4 = {0D 0A 2D 2D 2D 2D 2D 09 2D 2D 2D 2D 2D 2D 0D 0A}

  condition:
    $str1 and $str2 and $str3 and $str4
}

rule Trojan_Win32_Placisc3 : Platinum
{
  meta:
    author = "Microsoft"
    description = "Dipsind variant"
    original_sample_sha1 = "1b542dd0dacfcd4200879221709f5fa9683cdcda"
    unpacked_sample_sha1 = "bbd4992ee3f3a3267732151636359cf94fb4575d"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = {BA 6E 00 00 00 66 89 95 ?? ?? FF FF B8 73 00 00 00 66 89 85 ?? ?? FF FF B9 64 00 00 00 66 89 8D ?? ?? FF FF BA 65 00 00 00 66 89 95 ?? ?? FF FF B8 6C 00 00 00}
    $str2 = "VPLRXZHTU"
    $str3 = {8B 44 24 ?? 8A 04 01 41 32 C2 3B CF 7C F2 88 03}

  condition:$str1 and $str2 and $str3
}

rule Trojan_Win32_Placisc4 : Platinum
{
  meta:
    author = "Microsoft"
    description = "Installer for Dipsind variant"
    original_sample_sha1 = "3d17828632e8ff1560f6094703ece5433bc69586"
    unpacked_sample_sha1 = "2abb8e1e9cac24be474e4955c63108ff86d1a034"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = {8D 71 01 8B C6 99 BB 0A00 00 00 F7 FB 0F BE D2 0F BE 04 39 2B C2 88 04 39 84 C0 74 0A}
    $str2 = {6A 04 68 00 20 00 00 68 00 00 40 00 6A 00 FF D5}
    $str3 = {C6 44 24 ?? 64 C6 44 24 ?? 6F C6 44 24 ?? 67 C6 44 24 ?? 32 C6 44 24 ?? 6A}

  condition:
    $str1 and $str2 and $str3
}

rule Trojan_Win32_Plakpers : Platinum
{
  meta:
    author = "Microsoft"
    description = "Injector / loader component"
    original_sample_sha1 = "fa083d744d278c6f4865f095cfd2feabee558056"
    unpacked_sample_sha1 = "3a678b5c9c46b5b87bfcb18306ed50fadfc6372e"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = "MyFileMappingObject"
    $str2 = "[%.3u]  %s  %s  %s [%s:" wide
    $str3 = "%s\\{%s}\\%s" wide

  condition:
    $str1 and $str2 and $str3
}

rule Trojan_Win32_Plainst2 : Platinum
{
  meta:
    author = "Microsoft"
    description = "Zc tool"
    original_sample_sha1 = "3f2ce812c38ff5ac3d813394291a5867e2cddcf2"
    unpacked_sample_sha1 = "88ff852b1b8077ad5a19cc438afb2402462fbd1a"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = "Connected [%s:%d]..."
    $str2 = "reuse possible: %c"
    $str3 = "] => %d%%\x0a"

  condition:
    $str1 and $str2 and $str3
}

rule Trojan_Win32_Plakpeer : Platinum
{
  meta:
    author = "Microsoft"
    description = "Zc tool v2"
    original_sample_sha1 = "2155c20483528377b5e3fde004bb604198463d29"
    unpacked_sample_sha1 = "dc991ef598825daabd9e70bac92c79154363bab2"
    activity_group = "Platinum"
    version = "1.0"
    last_modified = "2016-04-12"
    reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"

  strings:
    $str1 = "@@E0020(%d)" wide
    $str2 = /exit.{0,3}@exit.{0,3}new.{0,3}query.{0,3}rcz.{0,3}scz/ wide
    $str3 = "---###---" wide
    $str4 = "---@@@---" wide

  condition:
    $str1 and $str2 and $str3 and $str4
}
rule blackenergy3_api_encode
{
    meta:
        author = "Mike Schladt"
        date = "2015-06-08"
        description = "matches api name encoding function for be3 persistence dll"
        md5 = "46649163C659CBA8A7D0D4075329EFA3"
        reference  = "https://www.f-secure.com/documents/996508/1030745/blackenergy_whitepaper.pdf"
        
    strings:
        $api_encode = {8B C2 C1 E8 09 32 E0 32 C4 32 E0 0F C8 66 8B CA 66 D1 E9 8A E1 33 C9 8A EA 66 D1 E9 8A C1 8B CA D1 E9 0F C9 0A C1 33 C9 8A 0B 33 C1 8B D0 43 EB CA}
        
    condition:
        $api_encode
        
}        

rule blackenergy3_push_bytes
{
    meta:
        author = "Mike Schladt"
        date = "2015-06-08"
        description = "matches push bytes used for api calls in be3 core files"
        md5 = "46649163C659CBA8A7D0D4075329EFA3"
        md5_2 = "78387651dd9608fcdf6bfb9df8b84db4"
        reference  = "https://www.f-secure.com/documents/996508/1030745/blackenergy_whitepaper.pdf"
        
    strings:        
        $push_4byte_1 = {68 EE EA C0 1F}
        $push_4byte_2 = {68 49 F3 A5 2C}
        $push_4byte_3 = {68 6B 43 59 4E}
        $push_4byte_4 = {68 E6 4B 59 4E}
        $push_4byte_5 = {68 6C 91 BA 4F}
        $push_4byte_6 = {68 8A 86 39 56}
        $push_4byte_7 = {68 9E 6D BD 5C}
        $push_4byte_8 = {68 FE 6A 7A 69}
        $push_4byte_9 = {68 A1 B0 5C 72}
        $push_4byte_10 = {68 60 A2 8A 76}
        $push_4byte_11 = {68 67 95 CD 77}
        $push_4byte_12 = {68 EB 3D 03 84}
        $push_4byte_13 = {68 19 2B 90 95}
        $push_4byte_14 = {68 62 67 8D A4}
        $push_4byte_15 = {68 AF 02 91 AB}
        $push_4byte_16 = {68 26 80 AC C8}
    
    condition:
        all of them
    
}

rule apt_win_blackenergy3_installer
{
    meta:
    
        author = "Mike Schladt"
        date = "2015-05-29"
        description = "Matches unique code block for import name construction "
        md5 = "78387651DD9608FCDF6BFB9DF8B84DB4"
        sha1 = "78636F7BBD52EA80D79B4E2A7882403092BBB02D"
        reference  = "https://www.f-secure.com/documents/996508/1030745/blackenergy_whitepaper.pdf"
        
    strings : 
    
        $import_names = { C7 45 D0 75 73 65 72 C7 45 D4 33 32 2E 64 66 C7 45 D8 6C 6C 88 5D DA C7 45 84 61 64 76 61 C7 45 88 70 69 33 32 C7 45 8C 2E 64 6C 6C 88 5D 90 C7 45 B8 77 69 6E 69 C7 45 BC 6E 65 74 2E C7 45 C0 64 6C 6C 00 C7 45 C4 77 73 32 5F C7 45 C8 33 32 2E 64 66 C7 45 CC 6C 6C 88 5D CE C7 45 94 73 68 65 6C C7 45 98 6C 33 32 2E C7 45 9C 64 6C 6C 00 C7 45 E8 70 73 61 70 C7 45 EC 69 2E 64 6C 66 C7 45 F0 6C 00 C7 85 74 FF FF FF 6E 65 74 61 C7 85 78 FF FF FF 70 69 33 32 C7 85 7C FF FF FF 2E 64 6C 6C 88 5D 80 C7 85 64 FF FF FF 6F 6C 65 61 C7 85 68 FF FF FF 75 74 33 32 C7 85 6C FF FF FF 2E 64 6C 6C 88 9D 70 FF FF FF C7 45 DC 6F 6C 65 33 C7 45 E0 32 2E 64 6C 66 C7 45 E4 6C 00 C7 45 A0 76 65 72 73 C7 45 A4 69 6F 6E 2E C7 45 A8 64 6C 6C 00 C7 85 54 FF FF FF 69 6D 61 67 C7 85 58 FF FF FF 65 68 6C 70 C7 85 5C FF FF FF 2E 64 6C 6C 88 9D 60 FF FF FF C7 45 AC 61 70 70 68 C7 45 B0 65 6C 70 2E C7 45 B4 64 6C 6C 00 C7 45 F4 2E 64 6C 6C 88 5D F8 }    
                      
    condition : 
        any of them

}

/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
rule mimikatz
{
	meta:
		description		= "mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Benjamin DELPY (gentilkiwi)"

	strings:
		$exe_x86_1		= { 89 71 04 89 [0-3] 30 8d 04 bd }
		$exe_x86_2		= { 89 79 04 89 [0-3] 38 8d 04 b5 }
		
		$exe_x64_1		= { 4c 03 d8 49 [0-3] 8b 03 48 89 }
		$exe_x64_2		= { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }

		$dll_1			= { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
		$dll_2			= { c7 0? 10 02 00 00 ?? 89 4? }
		
		$sys_x86		= { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64		= { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

	condition:
		(all of ($exe_x86_*)) or (all of ($exe_x64_*)) or (all of ($dll_*)) or (any of ($sys_*))
}


rule mimikatz_lsass_mdmp
{
	meta:
		description		= "LSASS minidump file for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$lsass			= "System32\\lsass.exe"	wide nocase

	condition:
		(uint32(0) == 0x504d444d) and $lsass
}


rule mimikatz_kirbi_ticket
{
	meta:
		description		= "KiRBi ticket for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$asn1			= { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }

	condition:
		$asn1 at 0
}


rule wce
{
	meta:
		description		= "wce"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Hernan Ochoa (hernano)"

	strings:
		$hex_legacy		= { 8b ff 55 8b ec 6a 00 ff 75 0c ff 75 08 e8 [0-3] 5d c2 08 00 }
		$hex_x86		= { 8d 45 f0 50 8d 45 f8 50 8d 45 e8 50 6a 00 8d 45 fc 50 [0-8] 50 72 69 6d 61 72 79 00 }
		$hex_x64		= { ff f3 48 83 ec 30 48 8b d9 48 8d 15 [0-16] 50 72 69 6d 61 72 79 00 }

	condition:
		any of them
}


rule lsadump
{
	meta:
		description		= "LSA dump programe (bootkey/syskey) - pwdump and others"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$str_sam_inc	= "\\Domains\\Account" ascii nocase
		$str_sam_exc	= "\\Domains\\Account\\Users\\Names\\" ascii nocase
		$hex_api_call	= {(41 b8 | 68) 00 00 00 02 [0-64] (68 | ba) ff 07 0f 00 }
		$str_msv_lsa	= { 4c 53 41 53 52 56 2e 44 4c 4c 00 [0-32] 6d 73 76 31 5f 30 2e 64 6c 6c 00 }
		$hex_bkey		= { 4b 53 53 4d [20-70] 05 00 01 00}

	condition:
		($str_sam_inc and not $str_sam_exc) or $hex_api_call or $str_msv_lsa or $hex_bkey
}

rule power_pe_injection
{
	meta:
		description		= "PowerShell with PE Reflective Injection"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$str_loadlib	= "0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9"
		
	condition:
		$str_loadlib
}/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/

rule Tinba2 {
        meta:
                author = "n3sfox <n3sfox@gmail.com>"
                date = "2015/11/07"
                description = "Tinba 2 (DGA) banking trojan"
                reference = "https://securityintelligence.com/tinba-malware-reloaded-and-attacking-banks-around-the-world"
                filetype = "memory"
                hash1 = "c7f662594f07776ab047b322150f6ed0"
                hash2 = "dc71ef1e55f1ddb36b3c41b1b95ae586"
                hash3 = "b788155cb82a7600f2ed1965cffc1e88"

        strings:
                $str1 = "MapViewOfFile"
                $str2 = "OpenFileMapping"
                $str3 = "NtCreateUserProcess"
                $str4 = "NtQueryDirectoryFile"
                $str5 = "RtlCreateUserThread"
                $str6 = "DeleteUrlCacheEntry"
                $str7 = "PR_Read"
                $str8 = "PR_Write"
                $pubkey = "BEGIN PUBLIC KEY"
                $code1 = {50 87 44 24 04 6A ?? E8}

        condition:
                all of ($str*) and $pubkey and $code1
}rule DebuggerCheck__API : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="IsDebuggerPresent"
	condition:
		any of them
}

rule DebuggerCheck__PEB : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="IsDebugged"
	condition:
		any of them
}

rule DebuggerCheck__GlobalFlags : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="NtGlobalFlags"
	condition:
		any of them
}

rule DebuggerCheck__QueryInfo : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="QueryInformationProcess"
	condition:
		any of them
}

rule DebuggerCheck__RemoteAPI : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="CheckRemoteDebuggerPresent"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////////
rule DebuggerHiding__Thread : AntiDebug DebuggerHiding {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="SetInformationThread"
	condition:
		any of them
}

rule DebuggerHiding__Active : AntiDebug DebuggerHiding {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="DebugActiveProcess"
	condition:
		any of them
}

rule DebuggerTiming__PerformanceCounter : AntiDebug DebuggerTiming {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="QueryPerformanceCounter"
	condition:
		any of them
}

rule DebuggerTiming__Ticks : AntiDebug DebuggerTiming {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="GetTickCount"
	condition:
		any of them
}

rule DebuggerOutput__String : AntiDebug DebuggerOutput {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="OutputDebugString"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////////
rule DebuggerException__UnhandledFilter : AntiDebug DebuggerException {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="SetUnhandledExceptionFilter"
	condition:
		any of them
}

rule DebuggerException__ConsoleCtrl : AntiDebug DebuggerException {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="GenerateConsoleCtrlEvent"
	condition:
		any of them
}

rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="SetConsoleCtrlHandler"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////////
rule ThreadControl__Context : AntiDebug ThreadControl {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="SetThreadContext"
	condition:
		any of them
}

rule DebuggerCheck__DrWatson : AntiDebug DebuggerCheck {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ ="__invoke__watson"
	condition:
		any of them
}

rule SEH__v3 : AntiDebug SEH {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = "____except__handler3"
		$ = "____local__unwind3"
	condition:
		any of them
}

rule SEH__v4 : AntiDebug SEH {
    // VS 8.0+
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = "____except__handler4"
		$ = "____local__unwind4"
		$ = "__XcptFilter"
	condition:
		any of them
}

rule SEH__vba : AntiDebug SEH {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = "vbaExceptHandler"
	condition:
		any of them
}

rule SEH__vectored : AntiDebug SEH {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = "AddVectoredExceptionHandler"
		$ = "RemoveVectoredExceptionHandler"
	condition:
		any of them
}

///////////////////////////////////////////////////////////////////////////// Patterns
rule DebuggerPattern__RDTSC : AntiDebug DebuggerPattern {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = {0F 31}
	condition:
		any of them
}

rule DebuggerPattern__CPUID : AntiDebug DebuggerPattern {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = {0F A2}
	condition:
		any of them
}

rule DebuggerPattern__SEH_Saves : AntiDebug DebuggerPattern {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = {64 ff 35 00 00 00 00}
	condition:
		any of them
}

rule DebuggerPattern__SEH_Inits : AntiDebug DebuggerPattern {
	meta:
		author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules"
		weight = 1
	strings:
		$ = {64 89 25 00 00 00 00}
	condition:
		any of them
}

rule elknot_xor : ELF PE DDoS XOR BillGates  
{
meta:  
    author = "liuya@360.cn"
    description = "elknot/Billgates variants with XOR like C2 encryption scheme"
	reference = "http://blog.netlab.360.com/new-elknot-billgates-variant-with-xor-like-c2-configuration-encryption-scheme/"
    date = "2015-09-12"

strings:  
   //md5=474429d9da170e733213940acc9a2b1c
   /*
   seg000:08130801 68 00 09 13 08                push    offset dword_8130900
   seg000:08130806 83 3D 30 17 13 08 02          cmp     ds:dword_8131730, 2
   seg000:0813080D 75 07                         jnz     short loc_8130816
   seg000:0813080F 81 04 24 00 01 00 00          add     dword ptr [esp], 100h
   seg000:08130816               loc_8130816:                           
   seg000:08130816 50                            push    eax
   seg000:08130817 E8 15 00 00 00                call    sub_8130831
   seg000:0813081C E9 C8 F6 F5 FF                jmp     near ptr 808FEE9h
   */
   $decrypt_c2_func_1 = {08 83 [5] 02 75 07 81 04 24 00 01 00 00 50 e8 [4] e9}

   // md5=2579aa65a28c32778790ec1c673abc49
   /*
   .rodata:08104D20 E8 00 00 00 00                call    $+5
   .rodata:08104D25 87 1C 24                      xchg    ebx, [esp+4+var_4] ;
   .rodata:08104D28 83 EB 05                      sub     ebx, 5
   .rodata:08104D2B 8D 83 00 FD FF FF             lea     eax, [ebx-300h]
   .rodata:08104D31 83 BB 10 CA 02 00 02          cmp   dword ptr [ebx+2CA10h], 2
   .rodata:08104D38 75 05                         jnz     short loc_8104D3F
   .rodata:08104D3A 05 00 01 00 00                add     eax, 100h
   .rodata:08104D3F               loc_8104D3F:                           
   .rodata:08104D3F 50                            push    eax
   .rodata:08104D40 FF 74 24 10                   push    [esp+8+strsVector]
   */
   $decrypt_c2_func_2 = {e8 00 00 00 00 87 [2] 83 eb 05 8d 83 [4] 83 bb [4] 02 75 05}

condition:  
    1 of ($decrypt_c2_func_*)
}
// Copyright (C) 2013 Claudio "nex" Guarnieri

rule embedded_macho
{
    meta:
        author = "nex"
        description = "Contains an embedded Mach-O file"

    strings:
        $magic1 = { ca fe ba be }
        $magic2 = { ce fa ed fe }
        $magic3 = { fe ed fa ce }
    condition:
        any of ($magic*) and not ($magic1 at 0) and not ($magic2 at 0) and not ($magic3 at 0)
}


// Copyright (C) 2013 Claudio "nex" Guarnieri

rule embedded_pe
{
    meta:
        author = "nex"
        description = "Contains an embedded PE32 file"

    strings:
        $a = "PE32"
        $b = "This program"
        $mz = { 4d 5a }
    condition:
        ($a and $b) and not ($mz at 0)
}

// Copyright (C) 2013 Claudio "nex" Guarnieri


rule embedded_win_api
{
    meta:
        author = "nex"
        description = "A non-Windows executable contains win32 API functions names"

    strings:
        $mz = { 4d 5a }
        $api1 = "CreateFileA"
        $api2 = "GetProcAddress"
        $api3 = "LoadLibraryA"
        $api4 = "WinExec"
        $api5 = "GetSystemDirectoryA"
        $api6 = "WriteFile"
        $api7 = "ShellExecute"
        $api8 = "GetWindowsDirectory"
        $api9 = "URLDownloadToFile"
        $api10 = "IsBadReadPtr"
        $api11 = "IsBadWritePtr"
        $api12 = "SetFilePointer"
        $api13 = "GetTempPath"
        $api14 = "GetWindowsDirectory"
    condition:
        not ($mz at 0) and any of ($api*)
}
 
 
 // Copyright (C) 2013 Claudio "nex" Guarnieri

rule vmdetect
{
    meta:
        author = "nex"
        description = "Possibly employs anti-virtualization techniques"

    strings:
        // Binary tricks
        $vmware = {56 4D 58 68}
        $virtualpc = {0F 3F 07 0B}
        $ssexy = {66 0F 70 ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F EF}
        $vmcheckdll = {45 C7 00 01}
        $redpill = {0F 01 0D 00 00 00 00 C3}

        // Random strings
        $vmware1 = "VMXh"
        $vmware2 = "Ven_VMware_" nocase
        $vmware3 = "Prod_VMware_Virtual_" nocase
        $vmware4 = "hgfs.sys" nocase
        $vmware5 = "mhgfs.sys" nocase
        $vmware6 = "prleth.sys" nocase
        $vmware7 = "prlfs.sys" nocase
        $vmware8 = "prlmouse.sys" nocase
        $vmware9 = "prlvideo.sys" nocase
        $vmware10 = "prl_pv32.sys" nocase
        $vmware11 = "vpc-s3.sys" nocase
        $vmware12 = "vmsrvc.sys" nocase
        $vmware13 = "vmx86.sys" nocase
        $vmware14 = "vmnet.sys" nocase
        $vmware15 = "vmicheartbeat" nocase
        $vmware16 = "vmicvss" nocase
        $vmware17 = "vmicshutdown" nocase
        $vmware18 = "vmicexchange" nocase
        $vmware19 = "vmdebug" nocase
        $vmware20 = "vmmouse" nocase
        $vmware21 = "vmtools" nocase
        $vmware22 = "VMMEMCTL" nocase
        $vmware23 = "vmx86" nocase
        $vmware24 = "vmware" nocase
        $virtualpc1 = "vpcbus" nocase
        $virtualpc2 = "vpc-s3" nocase
        $virtualpc3 = "vpcuhub" nocase
        $virtualpc4 = "msvmmouf" nocase
        $xen1 = "xenevtchn" nocase
        $xen2 = "xennet" nocase
        $xen3 = "xennet6" nocase
        $xen4 = "xensvc" nocase
        $xen5 = "xenvdb" nocase
        $xen6 = "XenVMM" nocase
        $virtualbox1 = "VBoxHook.dll" nocase
        $virtualbox2 = "VBoxService" nocase
        $virtualbox3 = "VBoxTray" nocase
        $virtualbox4 = "VBoxMouse" nocase
        $virtualbox5 = "VBoxGuest" nocase
        $virtualbox6 = "VBoxSF" nocase
        $virtualbox7 = "VBoxGuestAdditions" nocase
        $virtualbox8 = "VBOX HARDDISK"  nocase

        // MAC addresses
        $vmware_mac_1a = "00-05-69"
        $vmware_mac_1b = "00:05:69"
        $vmware_mac_1c = "000569"
        $vmware_mac_2a = "00-50-56"
        $vmware_mac_2b = "00:50:56"
        $vmware_mac_2c = "005056"
        $vmware_mac_3a = "00-0C-29" nocase
        $vmware_mac_3b = "00:0C:29" nocase
        $vmware_mac_3c = "000C29" nocase
        $vmware_mac_4a = "00-1C-14" nocase
        $vmware_mac_4b = "00:1C:14" nocase
        $vmware_mac_4c = "001C14" nocase
        $virtualbox_mac_1a = "08-00-27"
        $virtualbox_mac_1b = "08:00:27"
        $virtualbox_mac_1c = "080027"

    condition:
        any of them
}

import "pe"

rule shellcode
{
    meta:
        author = "nex"
        description = "Matched shellcode byte patterns"
        modified = "Glenn Edwards (@hiddenillusion)"
    strings:
        $s0 = { 64 8b 64 }
        $s1 = { 64 a1 30 }
        $s2 = { 64 8b 15 30 }
        $s3 = { 64 8b 35 30 }
        $s4 = { 55 8b ec 83 c4 }
        $s5 = { 55 8b ec 81 ec }
        $s6 = { 55 8b ec e8 }
        $s7 = { 55 8b ec e9 }
    condition:
        for any of ($s*) : ($ at pe.entry_point)	
}rule BernhardPOS {
   meta:
     author = "Nick Hoffman / Jeremy Humble"
     last_update = "2015-07-14"
     source = "Morphick Inc."
     description = "BernhardPOS Credit Card dumping tool"
     reference = "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick"
     md5 = "e49820ef02ba5308ff84e4c8c12e7c3d"
   strings:
     /*
     33C0        xor    eax, eax
     83C014        add    eax, 0x14
     83E814        sub    eax, 0x14
     64A130000000        mov    eax, dword ptr fs:[0x30]
     83C028        add    eax, 0x28
     83E828        sub    eax, 0x28
     8B400C        mov    eax, dword ptr [eax + 0xc]
     83C063        add    eax, 0x63
     83E863        sub    eax, 0x63
     8B4014        mov    eax, dword ptr [eax + 0x14]
     83C078        add    eax, 0x78
     83E878        sub    eax, 0x78
     8B00        mov    eax, dword ptr [eax]
     05DF030000        add    eax, 0x3df
     2DDF030000        sub    eax, 0x3df
     8B00        mov    eax, dword ptr [eax]
     83C057        add    eax, 0x57
     83E857        sub    eax, 0x57
     8B4010        mov    eax, dword ptr [eax + 0x10]
     83C063        add    eax, 0x63
     */
     $shellcode_kernel32_with_junk_code = { 33 c0 83 ?? ?? 83 ?? ?? 64 a1 30 00 00 00 83 ?? ?? 83 ?? ?? 8b 40 0c 83 ?? ?? 83 ?? ?? 8b 40 14 83 ?? ?? 83 ?? ?? 8b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 00 83 ?? ?? 83 ?? ?? 8b 40 10 83 ?? ?? }
     $mutex_name = "OPSEC_BERNHARD" 
     $build_path = "C:\\bernhard\\Debug\\bernhard.pdb" 
     /*
     55        push    ebp
     8BEC        mov    ebp, esp
     83EC50        sub    esp, 0x50
     53        push    ebx
     56        push    esi
     57        push    edi
     A178404100        mov    eax, dword ptr [0x414078]
     8945F8        mov    dword ptr [ebp - 8], eax
     668B0D7C404100        mov    cx, word ptr [0x41407c]
     66894DFC        mov    word ptr [ebp - 4], cx
     8A157E404100        mov    dl, byte ptr [0x41407e]
     8855FE        mov    byte ptr [ebp - 2], dl
     8D45F8        lea    eax, dword ptr [ebp - 8]
     50        push    eax
     FF150CB04200        call    dword ptr [0x42b00c]
     8945F0        mov    dword ptr [ebp - 0x10], eax
     C745F400000000        mov    dword ptr [ebp - 0xc], 0
     EB09        jmp    0x412864
     8B45F4        mov    eax, dword ptr [ebp - 0xc]
     83C001        add    eax, 1
     8945F4        mov    dword ptr [ebp - 0xc], eax
     8B4508        mov    eax, dword ptr [ebp + 8]
     50        push    eax
     FF150CB04200        call    dword ptr [0x42b00c]
     3945F4        cmp    dword ptr [ebp - 0xc], eax
     7D21        jge    0x412894
     8B4508        mov    eax, dword ptr [ebp + 8]
     0345F4        add    eax, dword ptr [ebp - 0xc]
     0FBE08        movsx    ecx, byte ptr [eax]
     8B45F4        mov    eax, dword ptr [ebp - 0xc]
     99        cdq
     F77DF0        idiv    dword ptr [ebp - 0x10]
     0FBE5415F8        movsx    edx, byte ptr [ebp + edx - 8]
     33CA        xor    ecx, edx
     8B4508        mov    eax, dword ptr [ebp + 8]
     0345F4        add    eax, dword ptr [ebp - 0xc]
     8808        mov    byte ptr [eax], cl
     EBC7        jmp    0x41285b
     5F        pop    edi
     5E        pop    esi
     5B        pop    ebx
     8BE5        mov    esp, ebp
     5D        pop    ebp
     */
     $string_decode_routine = { 55 8b ec 83 ec 50 53 56 57 a1 ?? ?? ?? ?? 89 45 f8 66 8b 0d ?? ?? ?? ?? 66 89 4d fc 8a 15 ?? ?? ?? ?? 88 55 fe 8d 45 f8 50 ff ?? ?? ?? ?? ?? 89 45 f0 c7 45 f4 00 00 00 00 ?? ?? 8b 45 f4 83 c0 01 89 45 f4 8b 45 08 50 ff ?? ?? ?? ?? ?? 39 45 f4 ?? ?? 8b 45 08 03 45 f4 0f be 08 8b 45 f4 99 f7 7d f0 0f be 54 15 f8 33 ca 8b 45 08 03 45 f4 88 08 ?? ?? 5f 5e 5b 8b e5 5d }
   condition:
     any of them
 }

import "pe"
rule Check_Debugger
{
	meta:
		Author = "Nick Hoffman"
		Description = "Looks for both isDebuggerPresent and CheckRemoteDebuggerPresent"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	condition:
		pe.imports("kernel32.dll","CheckRemoteDebuggerPresent") and 
		pe.imports("kernel32.dll","IsDebuggerPresent")
}rule Check_Dlls
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for common sandbox dlls"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$dll1 = "sbiedll.dll" wide nocase ascii fullword
		$dll2 = "dbghelp.dll" wide nocase ascii fullword
		$dll3 = "api_log.dll" wide nocase ascii fullword
		$dll4 = "dir_watch.dll" wide nocase ascii fullword
		$dll5 = "pstorec.dll" wide nocase ascii fullword
		$dll6 = "vmcheck.dll" wide nocase ascii fullword
		$dll7 = "wpespy.dll" wide nocase ascii fullword
	condition:
		2 of them
}import "pe"
rule Check_DriveSize
{
	meta:
		Author = "Nick Hoffman"
		Description = "Rule tries to catch uses of DeviceIOControl being used to get the drive size"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$physicaldrive = "\\\\.\\PhysicalDrive0" wide ascii nocase
		$dwIoControlCode = {68 5c 40 07 00 [0-5] FF 15} //push 7405ch ; push esi (handle) then call deviceoiocontrol IOCTL_DISK_GET_LENGTH_INFO	
	condition:
		pe.imports("kernel32.dll","CreateFileA") and 	
		pe.imports("kernel32.dll","DeviceIoControl") and 
		$dwIoControlCode and
		$physicaldrive
}import "pe"
rule Check_FilePaths
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for filepaths containing popular sandbox names"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings: 
		$path1 = "SANDBOX" wide ascii
		$path2 = "\\SAMPLE" wide ascii
		$path3 = "\\VIRUS" wide ascii
	condition:
		all of ($path*) and pe.imports("kernel32.dll","GetModuleFileNameA")
}rule Check_Qemu_Description
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for QEMU systembiosversion key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\Description\\System" nocase wide ascii
		$value = "SystemBiosVersion" nocase wide ascii
		$data = "QEMU" wide nocase ascii
	condition:
		all of them
}rule Check_Qemu_DeviceMap
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for Qemu reg keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$value = "Identifier" nocase wide ascii
		$data = "QEMU" wide nocase ascii
	condition:
		all of them
}import "pe"
rule Check_UserNames
{
	meta:
		Author = "Nick Hoffman"
		Description = "Looks for malware checking for common sandbox usernames"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$user1 = "MALTEST" wide ascii
		$user2 = "TEQUILABOOMBOOM" wide ascii
		$user3 = "SANDBOX" wide ascii
		$user4 = "VIRUS" wide ascii
		$user5 = "MALWARE" wide ascii
	condition:
		all of ($user*)  and pe.imports("advapi32.dll","GetUserNameA")
}rule Check_VBox_Description
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks Vbox description reg key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\Description\\System" nocase wide ascii
		$value = "SystemBiosVersion" nocase wide ascii
		$data = "VBOX" nocase wide ascii		
	condition:
		all of them
}rule Check_VBox_DeviceMap
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks Vbox registry keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$value = "Identifier" nocase wide ascii
		$data = "VBOX" nocase wide ascii
	condition:
		all of them
}rule Check_VBox_Guest_Additions
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of the guest additions registry key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" wide ascii nocase
	condition:
		any of them	
}rule Check_VBox_VideoDrivers
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for reg keys of Vbox video drivers"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\Description\\System" nocase wide ascii
		$value = "VideoBiosVersion" wide nocase ascii
		$data = "VIRTUALBOX" nocase wide ascii
	condition:
		all of them
}rule Check_VmTools
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of VmTools reg key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$tools = "SOFTWARE\\VMware, Inc.\\VMware Tools" nocase ascii wide
	condition:
		$tools
}rule Check_VMWare_DeviceMap
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of VmWare Registry Keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" wide ascii nocase
		$value = "Identifier" wide nocase ascii
		$data = "VMware" wide nocase ascii
	condition:
		all of them
}import "pe"
rule Check_Wine
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of Wine"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$wine = "wine_get_unix_file_name"
	condition:
		$wine and pe.imports("kernel32.dll","GetModuleHandleA")
}rule Dropper_Hancitor {
  meta:
    authors = "Nick Hoffman & Jeremy Humble - Morphick Inc."
    last_update = "2016-08-19"
    description = "rule to find unpacked Hancitor, useful against memory dumps"
    hash = "587a530cc82ff01d6b2d387d9b558299b0eb36e7e2c274cd887caa39fcc47c6f"
    ref = "http://www.morphick.com/resources/lab-blog/closer-look-hancitor"

  strings:
    /*
    .text:00401C02 83 FA 3A                                      cmp     edx, ':'
    .text:00401C05 75 6B                                         jnz     short loc_401C72
    .text:00401C07 B8 01 00 00 00                                mov     eax, 1
    .text:00401C0C 6B C8 00                                      imul    ecx, eax, 0
    .text:00401C0F 8B 55 08                                      mov     edx, [ebp+arg_0]
    .text:00401C12 0F BE 04 0A                                   movsx   eax, byte ptr [edx+ecx]
    .text:00401C16 83 F8 72                                      cmp     eax, 'r'
    .text:00401C19 74 50                                         jz      short loc_401C6B
    .text:00401C1B B9 01 00 00 00                                mov     ecx, 1
    .text:00401C20 6B D1 00                                      imul    edx, ecx, 0
    .text:00401C23 8B 45 08                                      mov     eax, [ebp+arg_0]
    .text:00401C26 0F BE 0C 10                                   movsx   ecx, byte ptr [eax+edx]
    .text:00401C2A 83 F9 75                                      cmp     ecx, 'u'
    .text:00401C2D 74 3C                                         jz      short loc_401C6B
    .text:00401C2F BA 01 00 00 00                                mov     edx, 1
    .text:00401C34 6B C2 00                                      imul    eax, edx, 0
    .text:00401C37 8B 4D 08                                      mov     ecx, [ebp+arg_0]
    .text:00401C3A 0F BE 14 01                                   movsx   edx, byte ptr [ecx+eax]
    .text:00401C3E 83 FA 64                                      cmp     edx, 'd'
    .text:00401C41 74 28                                         jz      short loc_401C6B
    .text:00401C43 B8 01 00 00 00                                mov     eax, 1
    .text:00401C48 6B C8 00                                      imul    ecx, eax, 0
    .text:00401C4B 8B 55 08                                      mov     edx, [ebp+arg_0]
    .text:00401C4E 0F BE 04 0A                                   movsx   eax, byte ptr [edx+ecx]
    .text:00401C52 83 F8 6C                                      cmp     eax, 'l'
    .text:00401C55 74 14                                         jz      short loc_401C6B
    .text:00401C57 B9 01 00 00 00                                mov     ecx, 1
    .text:00401C5C 6B D1 00                                      imul    edx, ecx, 0
    .text:00401C5F 8B 45 08                                      mov     eax, [ebp+arg_0]
    .text:00401C62 0F BE 0C 10                                   movsx   ecx, byte ptr [eax+edx]
    .text:00401C66 83 F9 6E                                      cmp     ecx, 'n'
    */

    $arg_parsing = { 83 f? ( 3a | 6c | 64 | 75 | 74 ) 7? ?? b? 01 00 00 00 6b ?? 00 8b ?? 08 0f be 0? ?? }

    /*   

    .text:00401116 B8 01 00 00 00                                mov     eax, 1
    .text:0040111B 85 C0                                         test    eax, eax
    .text:0040111D 74 49                                         jz      short loc_401168
    .text:0040111F 8B 0D 88 5B 40 00                             mov     ecx, dword_405B88
    .text:00401125 0F BE 11                                      movsx   edx, byte ptr [ecx]
    .text:00401128 83 FA 7C                                      cmp     edx, '|'
    .text:0040112B 74 0C                                         jz      short loc_401139
    .text:0040112D A1 88 5B 40 00                                mov     eax, dword_405B88
    .text:00401132 0F BE 08                                      movsx   ecx, byte ptr [eax]
    .text:00401135 85 C9                                         test    ecx, ecx
    .text:00401137 75 08                                         jnz     short loc_401141

    */

    $pipe_delimit = { b8 01 00 00 00 85 c0 7? ?? 8b 0d ?? ?? ?? ?? 0f be 11 83 fa 7c 7? }

    $fmt_string = "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(%s)"

    /*

    .text:00401AEE 83 FA 3C                                      cmp     edx, '<'
    .text:00401AF1 75 48                                         jnz     short loc_401B3B
    .text:00401AF3 B8 01 00 00 00                                mov     eax, 1
    .text:00401AF8 C1 E0 00                                      shl     eax, 0
    .text:00401AFB 0F BE 8C 05 FC FD FF FF                       movsx   ecx, [ebp+eax+Buffer]
    .text:00401B03 83 F9 21                                      cmp     ecx, '!'
    .text:00401B06 75 33                                         jnz     short loc_401B3B
    .text:00401B08 BA 01 00 00 00                                mov     edx, 1
    .text:00401B0D D1 E2                                         shl     edx, 1
    .text:00401B0F 0F BE 84 15 FC FD FF FF                       movsx   eax, [ebp+edx+Buffer]
    .text:00401B17 83 F8 64                                      cmp     eax, 'd'
    .text:00401B1A 75 1F                                         jnz     short loc_401B3B
    .text:00401B1C B9 01 00 00 00                                mov     ecx, 1
    .text:00401B21 6B D1 03                                      imul    edx, ecx, 3
    .text:00401B24 0F BE 84 15 FC FD FF FF                       movsx   eax, [ebp+edx+Buffer]
    .text:00401B2C 83 F8 6F                                      cmp     eax, 'o'

    */

    $connectivty_google_check = { 83 fa 3c 7? ?? b8 01 00 00 00 c1 e0 00 0f be 8c 05 fc fd ff ff 83 f9 21 7? ?? ba 01 00 00 00 d1 e2 0f be 84 15 fc fd ff ff 83 f8 64 7? ?? b9 01 00 00 00 6b d1 03 0f be 84 15 fc fd ff ff 83 f8 6f }

  condition:

    #arg_parsing > 1 or any of ($pipe_delimit, $fmt_string,$connectivty_google_check)

}rule korlia
{ 
meta:
author = "Nick Hoffman " 
company = "Morphick"
information = "korlia malware found in apt dump" 
ref = "http://www.morphick.com/resources/lab-blog/curious-korlia"

//case a
//b2 1f mov dl, 0x1f ; mov key (wildcard) 
// ----------------- 
//8A 86 98 40 00 71 mov al, byte ptr url[esi]
//BF 98 40 00 71 mov edi, offset url 
//32 C2 xor al, dl 
//83 C9 FF or ecx, 0FFFFFFFFh 
//88 86 98 40 00 71 mov byte ptr url[esi], al 
//33 C0 xor eax, eax 
//46 inc esi 
//F2 AE repne scasb 
//F7 D1 not ecx 
//49 dec ecx 
//3B F1 cmp esi, ecx 
//72 DE jb short loc_71001DE0

//case b (variant of loop a) 
//8A 8A 28 50 40 00 mov cl, byte_405028[edx] 
//BF 28 50 40 00 mov edi, offset byte_405028 
//32 CB xor cl, bl 
//33 C0 xor eax, eax 
//88 8A 28 50 40 00 mov byte_405028[edx], cl
//83 C9 FF or ecx, 0FFFFFFFFh 
//42 inc edx 
//F2 AE repne scasb 
//F7 D1 not ecx 
//49 dec ecx 
//3B D1 cmp edx, ecx 
//72 DE jb short loc_4047F2 

//case c (not a variant of the above loop) 
//8A 0C 28 mov cl, [eax+ebp] 
//80 F1 28 xor cl, 28h 
//88 0C 28 mov [eax+ebp], cl 
//8B 4C 24 14 mov ecx, [esp+0D78h+var_D64]
//40 inc eax 
//3B C1 cmp eax, ecx 
//7C EE jl short loc_404F1C 

strings:
$a = {b2 ?? 8A 86 98 40 00 71 BF 98 40 00 71 32 c2 83 C9 FF 88 86 98 40 00 71 33 C0 46 F2 AE F7 D1 49 3B F1} 
$b = {B3 ?? ?? ?? 8A 8A 28 50 40 00 BF 28 50 40 00 32 CB 33 C0 88 8A 28 50 40 00 83 C9 FF 42 F2 AE F7 D1 49 3B D1} 
$c = {8A 0C 28 80 F1 ?? 88 0C 28 8B 4C 24 14 40 3B C1} 
$d = {00 62 69 73 6F 6E 61 6C 00} //config marker "\x00bisonal\x00"
condition:
any of them 
}rule LogPOS
{
    meta:
        author = "Nick Hoffman - Morphick Security"
        description = "Detects Versions of LogPOS"
        md5 = "af13e7583ed1b27c4ae219e344a37e2b"
    strings:
        $mailslot = "\\\\.\\mailslot\\LogCC"
        $get = "GET /%s?encoding=%c&t=%c&cc=%I64d&process="
        //64A130000000      mov eax, dword ptr fs:[0x30]
        //8B400C        mov eax, dword ptr [eax + 0xc]
        //8B401C        mov eax, dword ptr [eax + 0x1c]
        //8B4008        mov eax, dword ptr [eax + 8]
        $sc = {64 A1 30 00 00 00 8B 40 0C 8B 40 1C 8B 40 08 }
    condition:
        $sc and 1 of ($mailslot,$get)
}
rule Mozart
{
   meta:
       author = "Nick Hoffman - Morphick Inc"
       description = "Detects samples of the Mozart POS RAM scraping utility"
   strings:
       $pdb = "z:\\Slender\\mozart\\mozart\\Release\\mozart.pdb" nocase wide ascii
       $output = {67 61 72 62 61 67 65 2E 74 6D 70 00}
       $service_name = "NCR SelfServ Platform Remote Monitor" nocase wide ascii
       $service_name_short = "NCR_RemoteMonitor"
       $encode_data = {B8 08 10 00 00 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 55 8B AC 24 14 10 00 00 89 84 24 0C 10 00 00 56 8B C5 33 F6 33 DB 8D 50 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C2 89 44 24 0C ?? ?? 8B 94 24 1C 10 00 00 57 8B FD 2B FA 89 7C 24 10 ?? ?? 8B 7C 24 10 8A 04 17 02 86 E0 BA 40 00 88 02 B8 ?? ?? ?? ?? 46 8D 78 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C7 3B F0 ?? ?? 33 F6 8B C5 43 42 8D 78 01 8A 08 40 84 C9 ?? ?? 2B C7 3B D8 ?? ?? 5F 8B B4 24 1C 10 00 00 8B C5 C6 04 33 00 8D 50 01 8A 08 40 84 C9 ?? ?? 8B 8C 24 20 10 00 00 2B C2 51 8D 54 24 14 52 50 56 E8 ?? ?? ?? ?? 83 C4 10 8B D6 5E 8D 44 24 0C 8B C8 5D 2B D1 5B 8A 08 88 0C 02 40 84 C9 ?? ?? 8B 8C 24 04 10 00 00 E8 ?? ?? ?? ?? 81 C4 08 10 00 00}
   condition:
      any of ($pdb, $output, $encode_data) or
      all of ($service*)
}
rule N3utrino
{
    meta:
        Author = "Nick Hoffman"
        Description = "Detects versions of Neutrino malware"
        ref = "http://www.morphick.com/resources/lab-blog/evening-n3utrino"

    strings:
        $post_host_information = "getcmd=1&uid=%s&os=%s&av=%s&nat=%s&version=%s&serial=%s&quality=%i"
        $post_cc_information = "dumpgrab=1&track_type=%s&track_data=%s&process_name=%s"
    $post_taskexec = "taskexec=1&task_id=%s"
    $post_taskfail = "taskfail=1&task_id=%s"
    
        $command1 = "loader"
        $command2 = "findfile"
        $command3 = "spread"
        $command4 = "archive"
        $command5 = "usb"
        $command6 = "botkiller"
        $command7 = "dwflood"
        $command8 = "keylogger"
    condition:
        4 of ($command*) or any of ($post*)
}rule encoded_vbs
{
	meta:
		author = "Niels Warnars"
		date = "2016/07/31"
		description = "Encoded .vbs detection"
		reference = "https://gallery.technet.microsoft.com/Encode-and-Decode-a-VB-a480d74c"
	strings:
		$begin_tag1 = "#@~^" 
		$begin_tag2 = "=="
		$end_tag = "==^#~@"
	condition:
	   $begin_tag1 at 0 and $begin_tag2 at 10 and $end_tag
}rule doc
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word 2003 file format detection"
	strings:
		$header = { D0 CF 11 E0 A1 B1 1A E1 }
		$str1 = "Microsoft Office Word"
		$str2 = "MSWordDoc"
		$str3 = "Word.Document.8"
	condition:
	   $header at 0 and any of ($str*) 
}

rule ppt
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "PowerPoint 2003 file format detection"
	strings:
		$header = { D0 CF 11 E0 A1 B1 1A E1 }
		$str = "Microsoft Office PowerPoint"
	condition:
	   $header at 0 and $str
}

rule xls
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Excel 2003 file format detection"
	strings:
		$header = { D0 CF 11 E0 A1 B1 1A E1 }
		$str1 = "Microsoft Excel"
		$str2 = "Excel.Sheet.8"
	condition:
	   $header at 0 and any of ($str*) 
}

rule docx
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word 2007 file format detection"
	strings:
		$header = { 50 4B 03 04 }
		$str = "document.xml"
	condition:
	   $header at 0 and $str
}

rule pptx
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "PowerPoint 2007 file format detection"
	strings:
		$header = { 50 4B 03 04 }
		$str = "presentation.xml"
	condition:
	   $header at 0 and $str
}

rule xlsx
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Excel 2007 file format detection"
	strings:
		$header = { 50 4B 03 04 }
		$str = "workbook.xml"
	condition:
	   $header at 0 and $str
}

rule xlsb
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Excel Binary Workbook file format detection"

	strings:
		$header = { 50 4B 03 04 }
		$str = "workbook.bin"
	condition:
	   $header at 0 and $str
}

rule rtf
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word RTF file format detection"
	strings:
		$header = "{\\rt"	
	condition:
	   $header at 0
}

rule word_xml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word XML file format detection"
	strings:
		$header = "<?xml"
		$str = "<?mso-application progid=\"Word.Document\"?>"
	condition:
	   $header at 0 and $str
}

rule ppt_xml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "PowerPoint XML file format detection"
	strings:
		$header = "<?xml"
		$str = "<?mso-application progid=\"PowerPoint.Show\"?>"
	condition:
	   $header at 0 and $str
}

rule excel_xml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Excel XML file format detection"
	strings:
		$header = "<?xml"
		$str = "<?mso-application progid=\"Excel.Sheet\"?>"
	condition:
	   $header at 0 and $str
}

rule mhtml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word/Excel MHTML file format detection"
	strings:
		$str1 = "MIME-Version:"
		$str2 = "Content-Location:"
		$email_str1 = "From:"
		$email_str2 = "Subject:"
	condition:
		all of ($str*) and not any of ($email_str*)
}
rule RANSOMWARE_RAA {

	meta:
		description = "Identifes samples containing JS dropper similar to RAA ransomware."
		author = "nshadov"
		reference = "https://malwr.com/analysis/YmE4MDNlMzk2MjY3NDdlYWE1NzFiOTNlYzVhZTlkM2Y/"
		date = "2016-06-15"
		hash = "535494aa6ce3ccef7346b548da5061a9"
		far = "unknown"
		frr = "unknown"
		
	strings:
		$sp0 = "CryptoJS.AES.decrypt" fullword ascii
		$sp1 = "RAA-SEP" fullword ascii
		$sb0 = "ActiveXObject(\"Scriptlet.TypeLib\")" fullword ascii
		$sb1 = "ActiveXObject(\"Scripting.FileSystemObject\")" fullword ascii
		$sb2 = "WScript.CreateObject(\"WScript.Shell\");" fullword ascii
		
	condition:
		filesize > 10KB and filesize < 800KB and ( (all of ($sp*)) or ( (all of ($sb*)) and 1 of ($sp*) ) )
		
	}// YARA rules compromised CCleaner
// NVISO 2017/09/18
// http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html
 
import "hash"
 
rule ccleaner_compromised_installer { 
    meta:
      author = "NVISIO"
      reference = "https://blog.nviso.be/2017/09/21/yara-rules-for-ccleaner-5-33/"
    condition:
        filesize == 9791816 and hash.sha256(0, filesize) == "1a4a5123d7b2c534cb3e3168f7032cf9ebf38b9a2a97226d0fdb7933cf6030ff"
}
 
rule ccleaner_compromised_application {
    meta:
      author = "NVISIO"
      reference = "https://blog.nviso.be/2017/09/21/yara-rules-for-ccleaner-5-33/"
    condition:
        filesize == 7781592 and hash.sha256(0, filesize) == "36b36ee9515e0a60629d2c722b006b33e543dce1c8c2611053e0651a0bfdb2e9" or
        filesize == 7680216 and hash.sha256(0, filesize) == "6f7840c77f99049d788155c1351e1560b62b8ad18ad0e9adda8218b9f432f0a9"
}
 
rule ccleaner_compromised_pdb {
    meta:
      author = "NVISIO"
      reference = "https://blog.nviso.be/2017/09/21/yara-rules-for-ccleaner-5-33/"
    strings:
        $a = "s:\\workspace\\ccleaner\\branches\\v5.33\\bin\\CCleaner\\Release\\CCleaner.pdb" 
        $b = "s:\\workspace\\ccleaner\\branches\\v5.33\\bin\\CCleaner\\ReleaseTV\\CCleaner.pdb" 
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and ($a or $b)
}

// YARA rules Office DDE
// NVISO 2017/10/10 - 2017/10/12
// https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/
  
rule Office_DDEAUTO_field {
  meta:
  	reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
  strings:
    $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee][Aa][Uu][Tt][Oo]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
  condition:
    $a
}
  
rule Office_DDE_field {
  meta:
  	reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
  strings:
    $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
  condition:
    $a
}
 
rule Office_OLE_DDEAUTO {
  meta:
  	reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
  strings:
    $a = /\x13\s*DDEAUTO\b[^\x14]+/ nocase
  condition:
    uint32be(0) == 0xD0CF11E0 and $a
}
 
rule Office_OLE_DDE {
  meta:
  	reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
  strings:
    $a = /\x13\s*DDE\b[^\x14]+/ nocase
  condition:
    uint32be(0) == 0xD0CF11E0 and $a
}
rule Andromeda
{
    meta:
        desc = "Andromeda dropper"
        family = "Andromeda"
        author = "OpenAnalysis.net"

    strings:
        $a1 = "Referer: https://www.bing.com/"
        $a2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"
        $a3 = "/last.so"
        $a4 = "30f5877bda910f27840f2e21461723f1"
        $a5 = "Global\\msiff0x1"


    condition:
        $a5 or ($a1 and $a2 and $a3) or ($a2 and $a4) or ($a1 and $a4)
}
rule wow32_exe
{
       meta:
              description = "wow32-exe"
              thread_level = 3
              in_the_wild = true
              reference = "https://www.optiv.com/blog/autoit-scripting-in-pos-malware"

       strings:
              $a = "avsupport@autoitscript.com" wide ascii
              $b = "compiled AutoIt script" wide ascii

       condition:
              $a and $b
}

rule cdosys_dll
{
       meta:
              description = "cdosys-dll"
              thread_level = 3
              in_the_wild = true
              reference = "https://www.optiv.com/blog/autoit-scripting-in-pos-malware"

       strings:
              $a = "Microsoft CDO for Windows Library" wide ascii
              $b = "CDOSYS.DLL" wide ascii

       condition:
              $a and $b
}

rule winhttp_exe
{
       meta:
              description = "winhttp-exe"
              thread_level = 3
              in_the_wild = true
              reference = "https://www.optiv.com/blog/autoit-scripting-in-pos-malware"

       strings:
              $a = "SeDebugPrivilege" wide ascii
              $b = "SearchInject" wide ascii
              $c = "Searcher.dll" wide ascii

       condition:
              $a and $b and $c
}

rule Searcher_dll
{
       meta:
              description = "Searcher-dll"
              thread_level = 3
              in_the_wild = true
              reference = "https://www.optiv.com/blog/autoit-scripting-in-pos-malware"

       strings:
              $a = "EncodePointer" wide ascii
              $b = "CONOUT$" wide ascii
              $c = "%s%i_%s_%i.log" wide ascii

       condition:
              $a and $b and $c
}
/*
	This Yara Rule is to be considered as "experimental"
	It reperesents a first attempt to detect BeEF hook function in memory
	It still requires further refinement 

*/

rule BeEF_browser_hooked {
	meta:
		description = "Yara rule related to hook.js, BeEF Browser hooking capability"
		author = "Pasquale Stirparo"
		date = "2015-10-07"
		hash1 = "587e611f49baf63097ad2421ad0299b7b8403169ec22456fb6286abf051228db"
	strings:
		$s0 = "mitb.poisonAnchor" wide ascii
		$s1 = "this.request(this.httpproto" wide ascii
		$s2 = "beef.logger.get_dom_identifier" wide ascii
		$s3 = "return (!!window.opera" wide ascii 
		$s4 = "history.pushState({ Be:\"EF\" }" wide ascii 
		$s5 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/10\\./)" wide ascii 
		$s6 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/11\\./)" wide ascii 
		$s7 = "window.navigator.userAgent.match(/Avant TriCore/)" wide ascii 
		$s8 = "window.navigator.userAgent.match(/Iceweasel" wide ascii 
		$s9 = "mitb.sniff(" wide ascii 
		$s10 = "Method XMLHttpRequest.open override" wide ascii 
		$s11 = ".browser.hasWebSocket" wide ascii 
		$s12 = ".mitb.poisonForm" wide ascii 
		$s13 = "resolved=require.resolve(file,cwd||" wide ascii 
		$s14 = "if (document.domain == domain.replace(/(\\r\\n|\\n|\\r)/gm" wide ascii 
		$s15 = "beef.net.request" wide ascii 
		$s16 = "uagent.search(engineOpera)" wide ascii 
		$s17 = "mitb.sniff" wide ascii
		$s18 = "beef.logger.start" wide ascii
	condition:
		all of them
}
/*
	Yara Rule Set
	Author: Pasquale Stirparo
	Date: 2015-10-08
	Identifier: src_ptheft
*/

/* Rule Set ----------------------------------------------------------------- */

rule src_ptheft_command {
	meta:
		description = "Auto-generated rule - file command.js"
		author = "Pasquale Stirparo"
		reference = "not set"
		date = "2015-10-08"
		hash = "49c0e5400068924ff87729d9e1fece19acbfbd628d085f8df47b21519051b7f3"
	strings:
		$s0 = "var lilogo = 'http://content.linkedin.com/etc/designs/linkedin/katy/global/clientlibs/img/logo.png';" fullword wide ascii /* score: '38.00' */
		$s1 = "dark=document.getElementById('darkenScreenObject'); " fullword wide ascii /* score: '21.00' */
		$s2 = "beef.execute(function() {" fullword wide ascii /* score: '21.00' */
		$s3 = "var logo  = 'http://www.youtube.com/yt/brand/media/image/yt-brand-standard-logo-630px.png';" fullword wide ascii /* score: '32.42' */
		$s4 = "description.text('Enter your Apple ID e-mail address and password');" fullword wide ascii /* score: '28.00' */
		$s5 = "sneakydiv.innerHTML= '<div id=\"edge\" '+edgeborder+'><div id=\"window_container\" '+windowborder+ '><div id=\"title_bar\" ' +ti" wide ascii /* score: '28.00' */
		$s6 = "var logo  = 'https://www.yammer.com/favicon.ico';" fullword wide ascii /* score: '27.42' */
		$s7 = "beef.net.send('<%= @command_url %>', <%= @command_id %>, 'answer='+answer);" fullword wide ascii /* score: '26.00' */
		$s8 = "var title = 'Session Timed Out <img src=\"' + lilogo + '\" align=right height=20 width=70 alt=\"LinkedIn\">';" fullword wide ascii /* score: '24.00' */
		$s9 = "var title = 'Session Timed Out <img src=\"' + logo + '\" align=right height=20 width=70 alt=\"YouTube\">';" fullword wide ascii /* score: '24.00' */
		$s10 = "var title = 'Session Timed Out <img src=\"' + logo + '\" align=right height=24 width=24 alt=\"Yammer\">';" fullword wide ascii /* score: '24.00' */
		$s11 = "var logobox = 'style=\"border:4px #84ACDD solid;border-radius:7px;height:45px;width:45px;background:#ffffff\"';" fullword wide ascii /* score: '21.00' */
		$s12 = "sneakydiv.innerHTML= '<br><img src=\\''+imgr+'\\' width=\\'80px\\' height\\'80px\\' /><h2>Your session has timed out!</h2><p>For" wide ascii /* score: '23.00' */
		$s13 = "inner.append(title, description, user,password);" fullword wide ascii /* score: '23.00' */
		$s14 = "sneakydiv.innerHTML= '<div id=\"window_container\" '+windowborder+ '><div id=\"windowmain\" ' +windowmain+ '><div id=\"title_bar" wide ascii /* score: '23.00' */
		$s15 = "sneakydiv.innerHTML= '<div id=\"window_container\" '+windowborder+ '><div id=\"windowmain\" ' +windowmain+ '><div id=\"title_bar" wide ascii /* score: '23.00' */
		$s16 = "answer = document.getElementById('uname').value+':'+document.getElementById('pass').value;" fullword wide ascii /* score: '22.00' */
		$s17 = "password.keydown(function(event) {" fullword wide ascii /* score: '21.01' */
	condition:
		13 of them
}rule PyInstaller_Binary
{
    meta:
        author = "ThreatStream Labs"
        desc = "Generic rule to identify PyInstaller Compiled Binaries"

    strings:
        $string0 = "zout00-PYZ.pyz"
        $string1 = "python"
        $string2 = "Python DLL"
        $string3 = "Py_OptimizeFlag"
        $string4 = "pyi_carchive"
        $string5 = ".manifest"
        $magic = { 00 4d 45 49 0c 0b 0a 0b 0e 00 }

    condition: 
        all of them
}rule anti_dbg {
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
}rule Neurevt {
        meta:
                author = "Venom23"
                date = "2013-06-21"
                description = "Neurevt Malware Sig"
                hash0 = "db9a816d58899f1ba92bc338e89f856a"
                hash1 = "d7b427ce3175fa7704da6b19a464938e"
                hash2 = "13027beb8aa5e891e8e641c05ccffde3"
                hash3 = "d1004b63d6d3cb90e6012c68e19ab453"
                hash4 = "a1286fd94984fd2de857f7b846062b5e"
                yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
        strings:
                $string0 = "BullGuard" wide
                $string1 = "cmd.exe" wide
                $string4 = "eUSERPROFILE" wide
                $string5 = "%c:\\%s.lnk" wide
                $string6 = "services.exe" wide
                $string9 = "Multiples archivos corruptos han sido encontrados en la carpeta \"Mis Documentos\". Para evitar perder" wide
                $string10 = "F-PROT Antivirus Tray application" wide
                $string12 = "-k NetworkService" wide
                $string13 = "firefox.exe"
                $string14 = "uWinMgr.exe" wide
                $string15 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.13) Gecko/20060410 Firefox/1.0.8"
                $string16 = "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11"
                $string18 = "Data Path" wide
        condition:
                10 of them
}rule Vinsula_Sayad_Binder : infostealer
{
	meta: 
		copyright = "Vinsula, Inc" 
		description = "Sayad Infostealer Binder" 
		version = "1.0" 
		actor = "Sayad Binder" 
		in_the_wild = true 
		reference = "http://vinsula.com/2014/07/20/sayad-flying-kitten-infostealer-malware/"

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
		copyright = "Vinsula, Inc" 
		description = "Sayad Infostealer Client" 
		version = "1.0" 
		actor = "Sayad Client" 
		in_the_wild = true 
		reference = "http://vinsula.com/2014/07/20/sayad-flying-kitten-infostealer-malware/"

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
}rule Banker
{
	meta:
		description = "Detects a Banker"
		author = "vitorafonso"
		sample = "e5df30b41b0c50594c2b77c1d5d6916a9ce925f792c563f692426c2d50aa2524"
		report = "https://blog.fortinet.com/2016/11/01/android-banking-malware-masquerades-as-flash-player-targeting-large-banks-and-popular-social-media-apps"

	strings:
		$a1 = "kill_on"
		$a2 = "intercept_down"
		$a3 = "send_sms"
		$a4 = "check_manager_status"
		$a5 = "browserappsupdate"
		$a6 = "YnJvd3NlcmFwcHN1cGRhdGU=" // browserappsupdate
		$a7 = "browserrestart"
		$a8 = "YnJvd3NlcnJlc3RhcnQ=" // browserrestart
		$a9 = "setMobileDataEnabled"
		$a10 = "adminPhone"

	condition:
		8 of ($a*)

}

rule Acecard
{
	meta:
		description = "Detects some acecard samples"
		author = "vitorafonso"
		sample = "0973da0f5cc7e4570659174612a650f3dbd93b3545f07bcc8b438af09dc257a9"
		report = "https://securelist.com/blog/research/73777/the-evolution-of-acecard/"

	strings:
		$a = "#control_number"
		$b = "client number"
		$c = "INTERCEPTING_INCOMING_ENABLED"
		$d = "#intercept_sms_start"
		$e = "#intercept_sms_stop"
		$f = "intercepted incoming sms"

	condition:
		all of them
}
rule dropper
{
	meta:
		description = "Detects a dropper"
		author = "vitorafonso"
		samples = "4144f5cf8d8b3e228ad428a6e3bf6547132171609893df46f342d6716854f329, e1afcf6670d000f86b9aea4abcec7f38b7e6294b4d683c04f0b4f7083b6b311e"

	strings:
		$a = "splitPayLoadFromDex"
		$b = "readDexFileFromApk"
		$c = "payload_odex"
		$d = "payload_libs"
		$e = "/payload.apk"
		$f = "makeApplication"

	condition:
		all of them

}
rule Exploit
{
	meta:
		description = "Detects some exploits"
		author = "vitorafonso"
		sample = "168f82516742a9580fb9d0c907140428f9d3837c88e0b3865002fd221b8154a1"

	strings:
		$a = "Ohh, that's make joke!"
		$b = "CoolXMainActivity"

	condition:
		all of them

}
rule shedun
{
	meta:
		description = "Detects libcrypt_sign used by shedun"
		author = "vitorafonso"
		sample = "919f1096bb591c84b4aaf964f0374765c3fccda355c2686751219926f2d50fab"

	strings:
		$a = "madana!!!!!!!!!"
		$b = "ooooop!!!!!!!!!!!"
		$c = "hehe you never know what happened!!!!"

	condition:
		all of them

}
rule apt_macOS_gimmick : StormCloud
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the macOS port of the GIMMICK malware."
        reference = "https://www.volexity.com/blog/2022/03/22/storm-cloud-on-the-horizon-gimmick-malware-strikes-at-macos/"
        date = "2021-10-18"
        hash1 = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 1

    strings:
        // Also seen in DAZZLESPY
        $s1 = "http://cgi1.apnic.net/cgi-bin/my-ip.php --connect-timeout 10 -m 20" wide ascii
        
        $json1 = "base_json" ascii wide
        $json2 = "down_json" ascii wide
        $json3 = "upload_json" ascii wide
        $json4 = "termin_json" ascii wide
        $json5 = "request_json" ascii wide
        $json6 = "online_json" ascii wide
        $json7 = "work_json" ascii wide

        $msg1 = "bash_pid: %d, FDS_CHILD: %d, FDS_PARENT: %d" ascii wide
        $msg2 = "pid %d is dead" ascii wide
        $msg3 = "exit with code %d" ascii wide
        $msg4 = "recv signal %d" ascii wide

        $cmd1 = "ReadCmdQueue" ascii wide
        $cmd2 = "read_cmd_server_timer" ascii wide
        $cmd3 = "enableProxys" ascii wide
        $cmd4 = "result_block" ascii wide
        $cmd5 = "createDirLock" ascii wide
        $cmd6 = "proxyLock" ascii wide
        $cmd7 = "createDirTmpItem" ascii wide
        $cmd8 = "dowfileLock" ascii wide
        $cmd9 = "downFileTmpItem" ascii wide
        $cmd10 = "filePathTmpItem" ascii wide
        $cmd11 = "uploadItems" ascii wide
        $cmd12 = "downItems" ascii wide
        $cmd13 = "failUploadItems" ascii wide
        $cmd14 = "failDownItems" ascii wide
        $cmd15 = "downloadCmds" ascii wide
        $cmd16 = "uploadFiles" ascii wide

    condition:
        $s1 or 
        5 of ($json*) or 
        3 of ($msg*) or 
        9 of ($cmd*)
}


rule apt_py_bluelight_ldr : InkySquid
{
    meta:
        author = "threatintel@volexity.com"
        description = "Python Loader used to execute the BLUELIGHT malware family."
        reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
        date = "2021-06-22"
        hash1 = "80269413be6ad51b8b19631b2f5559c9572842e789bbce031babe6e879d2e120"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "\"\".join(chr(ord(" ascii
        $s2 = "import ctypes " ascii
        $s3 = "ctypes.CFUNCTYPE(ctypes.c_int)" ascii
        $s4 = "ctypes.memmove" ascii
        $s5 = "python ended" ascii

    condition:
        all of them
}
rule apt_rb_rokrat_loader : InkySquid
{
    meta:
        author = "threatintel@volexity.com"
        description = "Ruby loader seen loading the ROKRAT malware family."
        reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
        date = "2021-06-22"
        hash1 = "5bc52f6c1c0d0131cee30b4f192ce738ad70bcb56e84180f464a5125d1a784b2"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $magic1 = "'https://update.microsoft.com/driverupdate?id=" ascii wide
        $magic2 = "sVHZv1mCNYDO0AzI';" ascii wide
        $magic3 = "firoffset..scupd.size" ascii wide
        $magic4 = /alias UrlFilter[0-9]{2,5} eval;"/
        
        // Original: 'Fiddle::Pointer' (Reversed)
        $s1 = "clRnbp9GU6oTZsRGZpZ"
        $s2 = "RmlkZGxlOjpQb2ludGVy"
        $s3 = "yVGdul2bQpjOlxGZklmR"
        $s4 = "XZ05WavBlO6UGbkRWaG"

    condition:
        any of ($magic*) or
        any of ($s*)
}
rule apt_win_bluelight : InkySquid
{
	meta:
		author = "threatintel@volexity.com"
		date = "2021-04-23"
		description = "The BLUELIGHT malware family. Leverages Microsoft OneDrive for network communications."
    reference = "https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/"
		hash1 = "7c40019c1d4cef2ffdd1dd8f388aaba537440b1bffee41789c900122d075a86d"
		hash2 = "94b71ee0861cc7cfbbae53ad2e411a76f296fd5684edf6b25ebe79bf6a2a600a"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		
	strings:
		$pdb1 = "\\Development\\BACKDOOR\\ncov\\"
		$pdb2 = "Release\\bluelight.pdb"

		$msg0 = "https://ipinfo.io" fullword
		$msg1 = "country" fullword
		$msg5 = "\"UserName\":\"" fullword
		$msg7 = "\"ComName\":\"" fullword
		$msg8 = "\"OS\":\"" fullword
		$msg9 = "\"OnlineIP\":\"" fullword
		$msg10 = "\"LocalIP\":\"" fullword
		$msg11 = "\"Time\":\"" fullword
		$msg12 = "\"Compiled\":\"" fullword
		$msg13 = "\"Process Level\":\"" fullword
		$msg14 = "\"AntiVirus\":\"" fullword
		$msg15 = "\"VM\":\"" fullword

	condition:
		any of ($pdb*) or 
		all of ($msg*) 
}
rule apt_win_bluelight_b : InkySquid
{
    meta:
        author = "threatintel@volexity.com"
        description = "North Korean origin malware which uses a custom Google App for c2 communications."
        reference = "https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/"
        date = "2021-06-21"
        hash1 = "837eaf7b736583497afb8bbdb527f70577901eff04cc69d807983b233524bfed"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $magic = "host_name: %ls, cookie_name: %s, cookie: %s, CT: %llu, ET: %llu, value: %s, path: %ls, secu: %d, http: %d, last: %llu, has: %d"
        
        $f1 = "%ls.INTEG.RAW" wide
        $f2 = "edb.chk" ascii
        $f3 = "edb.log" ascii
        $f4 = "edbres00001.jrs" ascii
        $f5 = "edbres00002.jrs" ascii
        $f6 = "edbtmp.log" ascii
        $f7 = "cheV01.dat" ascii
        
        $chrome1 = "Failed to get chrome cookie"
        $chrome2 = "mail.google.com, cookie_name: OSID"
        $chrome3 = ".google.com, cookie_name: SID,"
        $chrome4 = ".google.com, cookie_name: __Secure-3PSID,"
        $chrome5 = "Failed to get Edge cookie"
        $chrome6 = "google.com, cookie_name: SID,"
        $chrome7 = "google.com, cookie_name: __Secure-3PSID,"
        $chrome8 = "Failed to get New Edge cookie"
        $chrome9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
        $chrome10 = "Content-Type: application/x-www-form-urlencoded;charset=utf-8"
        $chrome11 = "Cookie: SID=%s; OSID=%s; __Secure-3PSID=%s"
        $chrome12 = "https://mail.google.com"
        $chrome13 = "result.html"
        $chrome14 = "GM_ACTION_TOKEN"
        $chrome15 = "GM_ID_KEY="
        $chrome16 = "/mail/u/0/?ik=%s&at=%s&view=up&act=prefs"
        $chrome17 = "p_bx_ie=1"
        $chrome18 = "myaccount.google.com, cookie_name: OSID"
        $chrome19 = "Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3"
        $chrome20 = "Content-Type: application/x-www-form-urlencoded;charset=utf-8"
        $chrome21 = "Cookie: SID=%s; OSID=%s; __Secure-3PSID=%s"
        $chrome22 = "https://myaccount.google.com"
        $chrome23 = "result.html"
        $chrome24 = "myaccount.google.com"
        $chrome25 = "/_/AccountSettingsUi/data/batchexecute"
        $chrome26 = "f.req=%5B%5B%5B%22BqLdsd%22%2C%22%5Btrue%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at="
        $chrome27 = "response.html"
        
        $msg1 = "https_status is %s"
        $msg2 = "Success to find GM_ACTION_TOKEN and GM_ID_KEY"
        $msg3 = "Failed to find GM_ACTION_TOKEN and GM_ID_KEY"
        $msg4 = "Failed HttpSendRequest to mail.google.com"
        $msg5 = "Success to enable imap"
        $msg6 = "Failed to enable imap"
        $msg7 = "Success to find SNlM0e"
        $msg8 = "Failed to find SNlM0e"
        $msg9 = "Failed HttpSendRequest to myaccount.google.com"
        $msg10 = "Success to enable thunder access"
        $msg11 = "Failed to enable thunder access"

        $keylogger_component1 = "[TAB]"
        $keylogger_component2 = "[RETURN]"
        $keylogger_component3 = "PAUSE"
        $keylogger_component4 = "[ESC]"
        $keylogger_component5 = "[PAGE UP]"
        $keylogger_component6 = "[PAGE DOWN]"
        $keylogger_component7 = "[END]"
        $keylogger_component8 = "[HOME]"
        $keylogger_component9 = "[ARROW LEFT]"
        $keylogger_component10 = "[ARROW UP]"
        $keylogger_component11 = "[ARROW RIGHT]"
        $keylogger_component12 = "[ARROW DOWN]"
        $keylogger_component13 = "[INS]"
        $keylogger_component14 = "[DEL]"
        $keylogger_component15 = "[WIN]"
        $keylogger_component16 = "[NUM *]"
        $keylogger_component17 = "[NUM +]"
        $keylogger_component18 = "[NUM ,]"
        $keylogger_component19 = "[NUM -]"
        $keylogger_component20 = "[NUM .]"
        $keylogger_component21 = "NUM /]"
        $keylogger_component22 = "[NUMLOCK]"
        $keylogger_component23 = "[SCROLLLOCK]"
        $keylogger_component24 = "Time: "
        $keylogger_component25 = "Window: "
        $keylogger_component26 = "CAPSLOCK+"
        $keylogger_component27 = "SHIFT+"
        $keylogger_component28 = "CTRL+"
        $keylogger_component29 = "ALT+"

    condition:
        $magic or 
        (
            all of ($f*) and 
            5 of ($keylogger_component*)
        ) or 
        24 of ($chrome*) or 
        4 of ($msg*) or 
        27 of ($keylogger_component*)
}
rule apt_win_decrok : InkySquid
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-06-23"
        description = "The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload."
        reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
        hash = "6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        
    strings:
        $v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}

        $av1 = "Select * From AntiVirusProduct" wide
        $av2 = "root\\SecurityCenter2" wide

        /* CreateThread..%02x */
        $funcformat = { 25 30 32 78 [0-10] 43 72 65 61 74 65 54 68 72 65 61 64 }

    condition:
        all of them
}



rule apt_win_flipflop_ldr : APT29
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-05-25"
        description = "A loader for the CobaltStrike malware family, which ultimately takes the first and second bytes of an embedded file, and flips them prior to executing the resulting payload."
        reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
        hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330" 
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "irnjadle"
        $s2 = "BADCFEHGJILKNMPORQTSVUXWZY"
        $s3 = "iMrcsofo taBesC yrtpgoarhpciP orived r1v0."

    condition:
        all of ($s*)
}
import "pe"

rule apt_win_freshfire : APT29
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-05-27"
        description = "The FRESHFIRE malware family. The malware acts as a downloader, pulling down an encrypted snippet of code from a remote source, executing it, and deleting it from the remote server."
        reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
        hash = "ad67aaa50fd60d02f1378b4155f69cffa9591eaeb80523489a2355512cc30e8c"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $uniq1 = "UlswcXJJWhtHIHrVqWJJ"
        $uniq2 = "gyibvmt\x00"

        $path1 = "root/time/%d/%s.json"
        $path2 = "C:\\dell.sdr"
        $path3 = "root/data/%d/%s.json" 

    condition:
        (
            pe.number_of_exports == 1 and
            pe.exports("WaitPrompt")
        ) or
        any of ($uniq*) or
        2 of ($path*)
}
rule apt_win_gimmick_dotnet_base : StormCloud
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the base version of GIMMICK in .NET."
        reference = "https://www.volexity.com/blog/2022/03/22/storm-cloud-on-the-horizon-gimmick-malware-strikes-at-macos/"
        date = "2020-03-16"
        hash1 = "b554bfe4c2da7d0ac42d1b4f28f4aae854331fd6d2b3af22af961f6919740234"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 1

    strings:
        $other1 = "srcStr is null" wide 
        $other2 = "srcBs is null " wide 
        $other3 = "Key cannot be null" wide 
        $other4 = "Faild to get target constructor, targetType=" wide 
        $other5 = "hexMoudule(public key) cannot be null or empty." wide 
        $other6 = "https://oauth2.googleapis.com/token" wide 

        $magic1 = "TWljcm9zb2Z0IUAjJCVeJiooKQ==" ascii wide
        $magic2 = "DAE47700E8CF3DAB0@" ascii wide 

    condition:
        5 of ($other*) or 
        any of ($magic*)
}
rule apt_win_rokload : InkySquid
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-06-23"
        description = "A shellcode loader used to decrypt and run an embedded executable."
        reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
        hash = "85cd5c3bb028fe6931130ccd5d0b0c535c01ce2bcda660a3b72581a1a5382904"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        
    strings:
        $bytes00 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 57 41 54 41 55 41 56 41 57 48 ?? ?? ?? b9 ?? ?? ?? ?? 33 ff e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 4c 8b e8 e8 ?? ?? ?? ?? 4c 8b f0 41 ff d6 b9 ?? ?? ?? ?? 44 8b f8 e8 ?? ?? ?? ?? 4c 8b e0 e8 ?? ?? ?? ?? 48 }
    
    condition:
        $bytes00 at 0
}
rule webshell_jsp_converge : Webshell
{
    meta:
        author = "threatintel@volexity.com"
        description = "File upload webshell observed in incident involving compromise of Confluence server."
        reference = "https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/"
        date = "2022-06-01"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        
    strings:
        $s1 = "if (request.getParameter(\"name\")!=null && request.getParameter(\"name\").length()!=0){" ascii

    condition:
        $s1
}
rule general_java_encoding_and_classloader : Webshells General
{
    meta:
        author = "threatintel@volexity.com"
        description = "Identifies suspicious java-based files which have all the ingredients required for a webshell."
        reference = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        date = "2022-04-07"
        hash1 = "0d5dc54ef77bc18c4c5582dca4619905605668cffcccc3829e43c6d3e14ef216"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 0

    strings:
        $s1 = "javax.crypto.spec.SecretKeySpec" ascii
        $s2 = "java/security/SecureClassLoader" ascii
        $s3 = "sun.misc.BASE64Decoder" ascii

    condition:
        filesize < 50KB and
        all of them
}
rule general_jsp_possible_tiny_fileuploader : General Webshells
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects small .jsp files which have possible file upload utility."
        reference = "https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/"
        date = "2022-06-01"
        hash1 = "4addb9bc9e5e1af8fda63589f6b3fc038ccfd651230fa3fa61814ad080e95a12"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        
    strings:
        // read a req parameter of some sort
        $required1 = "request." ascii
        // write a file
        $required2 = "java.io.FileOutputStream" ascii
        $required3 = ".write" ascii

        // do some form of decoding.
        $encoding1 = "java.util.Base64" ascii
        $encoding2 = "crypto.Cipher" ascii
        $encoding3 = ".misc.BASE64Decoder" ascii

    condition:
        (
            filesize < 4KB and
            all of ($required*) and
            any of ($encoding*)
        )
        or
        (
            filesize < 600 and
            all of ($required*)
        )
}

rule general_php_call_user_func : General Webshells
{
    meta:
        author = "threatintel@volexity.com"
        description = "Webshells using call_user_func against an object from a file input or POST variable."
        date = "2021-06-16"
        hash1 = "40b053a2f3c8f47d252b960a9807b030b463ef793228b1670eda89f07b55b252"
        reference = "https://zhuanlan.zhihu.com/p/354906657"
        reference2 = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 0

    strings:
        $s1 = "@call_user_func(new C()" wide ascii

    condition:
        $s1
}
rule general_php_fileinput_eval : Webshells General
{
    meta:
        author = "threatintel@volexity.com"
        description = "Look for PHP files which use file_get_contents and then shortly afterwards use an eval statement."
        reference = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        date = "2021-06-16"
        hash1 = "1a34c43611ee310c16acc383c10a7b8b41578c19ee85716b14ac5adbf0a13bd5"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 0

    strings:
        $s1 = "file_get_contents(\"php://input\");"
        $s2 = "eval("

    condition:
        $s2 in (@s1[1]..@s1[1]+512)
}
rule trojan_any_pupyrat_b : Commodity
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the PUPYRAT malware family, a cross-platform RAT written in Python."
        date = "2022-04-07"
        hash1 = "7474a6008b99e45686678f216af7d6357bb70a054c6d9b05e1817c8d80d536b4"
        reference = "https://github.com/n1nj4sec/pupy"
        reference2 = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 1

    strings:
        $elf1 = "LD_PRELOAD=%s HOOK_EXIT=%d CLEANUP=%d exec %s 1>/dev/null 2>/dev/null" ascii
        $elf2 = "reflective_inject_dll" fullword ascii
        $elf3 = "ld_preload_inject_dll" fullword ascii
        
        $pupy1 = "_pupy.error" ascii
        $pupy2 = "_pupy" ascii
        $pupy3 = "pupy://" ascii
        
        $s1 = "Args not passed" ascii
        $s2 = "Too many args" ascii
        $s3 = "Can't execute" ascii
        $s4 = "mexec:stdin" ascii
        $s5 = "mexec:stdout" ascii
        $s6 = "mexec:stderr" ascii
        $s7 = "LZMA error" ascii


    condition:
        any of ($elf*) or 
        all of ($pupy*) or 
        all of ($s*)
}
rule trojan_backwash_iis_scout : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "Simple backdoor which collects information about the IIS server it is installed on. It appears to the attacker refers to this components as 'XValidate' - i.e. to validate infected machines."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        date = "2021-11-17"
        hash1 = "6f44a9c13459533a1f3e0b0e698820611a18113c851f763797090b8be64fd9d5"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "SOAPRequest" ascii
        $s2 = "requestServer" ascii
        $s3 = "getFiles" ascii
        $s4 = "APP_POOL_CONFIG" wide
        $s5 = "<virtualDirectory" wide
        $s6 = "stringinstr" ascii
        $s7 = "504f5354" wide
        $s8 = "XValidate" ascii
        $s9 = "XEReverseShell" ascii
        $s10 = "XERsvData" ascii

    condition:
        6 of them
}


rule trojan_golang_pantegana : Commodity
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects PANTEGANA, a Golang backdoor used by a range of threat actors due to its public availability."
        date = "2022-03-30"
        hash1 = "8297c99391aae918f154077c61ea94a99c7a339166e7981d9912b7fdc2e0d4f0"
        reference = "https://github.com/elleven11/pantegana"
        reference2 = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 1

    strings:
        $s1 = "RunFingerprinter" ascii
        $s2 = "SendSysInfo" ascii
        $s3 = "ExecAndGetOutput" ascii
        $s4 = "RequestCommand" ascii
        $s5 = "bindataRead" ascii
        $s6 = "RunClient" ascii
        
        $magic = "github.com/elleven11/pantegana" ascii

    condition:
        5 of ($s*) or 
        $magic
}

rule trojan_win_backwash_cpp : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "CPP loader for the Backwash malware."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        date = "2021-11-17"
        hash1 = "0cf93de64aa4dba6cec99aa5989fc9c5049bc46ca5f3cb327b49d62f3646a852"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "cor1dbg.dll" wide
        $s2 = "XEReverseShell.exe" wide
        $s3 = "XOJUMAN=" wide
        
    condition:
        2 of them
}
rule trojan_win_backwash_iis : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "Variant of the BACKWASH malware family with IIS worm functionality."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        hash = "98e39573a3d355d7fdf3439d9418fdbf4e42c2e03051b5313d5c84f3df485627"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $a1 = "GetShell" ascii 
        $a2 = "smallShell" ascii 
        $a3 = "createSmallShell" ascii 
        $a4 = "getSites" ascii 
        $a5 = "getFiles " ascii 

        $b1 = "action=saveshell&domain=" ascii wide
        $b2 = "&shell=backsession.aspx" ascii wide
        
    condition:
        all of ($a*) or 
        any of ($b*)
}
rule trojan_win_cobaltstrike : Commodity
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-05-25"
        description = "The CobaltStrike malware family."
        reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
        hash = "b041efb8ba2a88a3d172f480efa098d72eef13e42af6aa5fb838e6ccab500a7c"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "%s (admin)" fullword
        $s2 = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}
        $s3 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
        $s4 = "%s as %s\\%s: %d" fullword
        $s5 = "%s&%s=%s" fullword
        $s6 = "rijndael" fullword
        $s7 = "(null)"

    condition:
        all of them
}
rule trojan_win_iis_shellsave : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects an AutoIT backdoor designed to run on IIS servers and to install a webshell. This rule will only work against memory samples."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        date = "2021-11-17"
        hash1 = "21683e02e11c166d0cf616ff9a1a4405598db7f4adfc87b205082ae94f83c742"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "getdownloadshell" ascii
        $s2 = "deleteisme" ascii 
        $s3 = "sitepapplication" ascii 
        $s4 = "getapplicationpool" ascii

    condition:
        all of them
}
import "pe"
rule trojan_win_pngexe : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "Detects PNGEXE, a simple reverse shell loader."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        hash = "72f7d4d3b9d2e406fa781176bd93e8deee0fb1598b67587e1928455b66b73911"
        hash2 = "4d913ecb91bf32fd828d2153342f5462ae6b84c1a5f256107efc88747f7ba16c"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $a1 = "amd64.png" ascii
        $a2 = "x86.png" ascii
        
    condition:
    	uint16(0) == 0x5A4D and 
        (
        	(
                any of ($a*) and 
                filesize > 30KB and 
                filesize < 200KB
            ) or   
          pe.imphash() == "ca41f83b03cf3bb51082dbd72e3ba1ba" or 
          pe.imphash() == "e93abc400902e72707edef1f717805f0" or 
          pe.imphash() == "83a5d4aa20a8aca2a9aa6fc2a0aa30b0"
         )
}

rule trojan_win_xe_backwash : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "The BACKWASH malware family, which acts as a reverse shell on the victim machine."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        hash = "815d262d38a26d5695606d03d5a1a49b9c00915ead1d8a2c04eb47846100e93f"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $pdb1 = "x:\\MultiOS_ReverseShell-master\\Multi-OS_ReverseShell\\obj\\Release\\XEReverseShell.pdb"
        $pdb2 = "\\Release\\XEReverseShell.pdb"

        $a1 = "RunServer" ascii
        $a2 = "writeShell" ascii
        $a3 = "GetIP" ascii

        $b1 = "xequit" wide
        $b2 = "setshell" wide

    condition:
        any of ($pdb*) or
        (
            (
                all of ($a*) or 
                all of ($b*)
            ) and     
            filesize < 40KB 
        )
}

rule webshell_aspx_reGeorgTunnel : Webshell Commodity
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "variation on reGeorgtunnel"
        hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
        reference2 = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"

    strings:
        $s1 = "System.Net.Sockets"
        $s2 = "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"
        $t1 = ".Split('|')"
        $t2 = "Request.Headers.Get"
        $t3 = ".Substring("
        $t4 = "new Socket("
        $t5 = "IPAddress ip;"

    condition:
        all of ($s*) or
        all of ($t*)
}
rule webshell_aspx_simpleseesharp : Webshell Unclassified
{

    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "A simple ASPX Webshell that allows an attacker to write further files to disk."
        reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
        hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $header = "<%@ Page Language=\"C#\" %>"
        $body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"

    condition:
        $header at 0 and
        $body and
        filesize < 1KB
}
rule webshell_aspx_sportsball : Webshell
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "The SPORTSBALL webshell allows attackers to upload files or execute commands on the system."
        reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
        hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
        $uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE=" 

        $var1 = "Result.InnerText = string.Empty;"
        $var2 = "newcook.Expires = DateTime.Now.AddDays("
        $var3 = "System.Diagnostics.Process process = new System.Diagnostics.Process()"
        $var4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
        $var5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
        $var6 = "<input type=\"submit\" value=\"Upload\" />" 

    condition:
        any of ($uniq*) or
        all of ($var*)
}
rule webshell_java_behinder_shellservice : Webshells Commodity
{
    meta:
        author = "threatintel@volexity.com"
        description = "Looks for artifacts generated (generally seen in .class files) related to the Behinder framework."
        date = "2022-03-18"
        hash1 = "9a9882f9082a506ed0fc4ddaedd50570c5762deadcaf789ac81ecdbb8cf6eff2"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        reference = "https://github.com/MountCloud/BehinderClientSource/blob/master/src/main/java/net/rebeyond/behinder/core/ShellService.java"
        reference2 = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        memory_suitable = 1

    strings:
        $s1 = "CONNECT" ascii fullword
        $s2 = "DISCONNECT" ascii fullword
        $s3 = "socket_" ascii fullword
        $s4 = "targetIP" ascii fullword
        $s5 = "targetPort" ascii fullword
        $s6 = "socketHash" ascii fullword
        $s7 = "extraData" ascii fullword

    condition:
        all of them
}
rule webshell_java_realcmd : Commodity Webshells
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the RealCMD webshell, one of the payloads for BEHINDER."
        date = "2022-06-01"
        hash1 = "a9a30455d6f3a0a8cd0274ae954aa41674b6fd52877fafc84a9cb833fd8858f6"
        reference = "https://github.com/Freakboy/Behinder/blob/master/src/main/java/vip/youwe/sheller/payload/java/RealCMD.java"
        reference2 = "https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        
    strings:
        $fn1 = "runCmd" wide ascii fullword
        $fn2 = "RealCMD" ascii wide fullword
        $fn3 = "buildJson" ascii wide fullword
        $fn4 = "Encrypt" ascii wide fullword

        $s1 = "AES/ECB/PKCS5Padding" ascii wide
        $s2 = "python -c 'import pty; pty.spawn" ascii wide
        $s3 = "status" ascii wide
        $s4 = "success" ascii wide
        $s5 = "sun.jnu.encoding" ascii wide
        $s6 = "java.util.Base64" ascii wide

    condition:
        all of ($fn*) or
        all of ($s*)
}
rule webshell_php_icescorpion : Commodity Webshell
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the IceScorpion webshell."
        date = "2022-01-17"
        hash1 = "5af4788d1a61009361b37e8db65deecbfea595ef99c3cf920d33d9165b794972"
        reference = "https://www.codenong.com/cs106064226/"
        reference2 = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 0

    strings:
        $s1 = "[$i+1&15];"
        $s2 = "openssl_decrypt"

    condition:
        all of them and 
        filesize < 10KB
}
rule webshell_php_str_replace_create_func : Webshells General
{
    meta:
        author = "threatintel@volexity.com"
        description = "Looks for obfuscated PHP shells where create_function() is obfuscated using str_replace and then called using no arguments."
        reference = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        date = "2022-04-04"
        hash1 = "c713d13af95f2fe823d219d1061ec83835bf0281240fba189f212e7da0d94937"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 0

    strings:
        $php = "<?php"
        // $P=str_replace(
        $s = "=str_replace(" ascii
        // call it as a function
        // $S=$P('',$a);
        $anon_func = "(''," ascii
        
    condition:
        filesize < 100KB and 
        $php at 0 and
        for any i in (1..#s):
            (
                for any j in (1..#anon_func):
                    (
					    uint16be(@s[i]-2) == uint16be(@anon_func[j]-2)
					)
            )
}
rule web_js_xeskimmer : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects JScript code using in skimming credit card details."
        date = "2021-11-17"
        hash1 = "92f9593cfa0a28951cae36755d54de63631377f1b954a4cb0474fa0b6193c537"
        reference1 = "https://blog.malwarebytes.com/threat-analysis/2020/07/credit-card-skimmer-targets-asp-net-sites/"
        reference2 = "https://github.com/MBThreatIntel/skimmers/blob/master/null_gif_skimmer.js"
        reference3 = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = ".match(/^([3456]\\d{14,15})$/g" ascii
        $s2 = "^(p(wd|ass(code|wd|word)))" ascii
        
        $b1 = "c('686569676874')" ascii
        $b2 = "c('7769647468')" ascii

        $c1 = "('696D67')" ascii
        $c2 = "('737263')" ascii

        $magic = "d=c.charCodeAt(b),a+=d.toString(16);" 
        
    condition:
        all of ($s*) or 
        all of ($b*) or 
        all of ($c*) or 
        $magic
}


/*
	yara-rule-havex-netscan.yar
		This searches for "~tracedscn.yls" or 
		port activity indicative of the 
		W32.Havex.Netscan malware module.
		NOTE: 5 ports are scanned by W32.Havex.Netscan; only 44818 was 
		chosen due to its high port number and hex rule limiting the 
		chance for a false positive! 
	Val A. Red, 20151206
*/

rule W32HavexNetscan
{
	meta:
		description = "Havex.Netscan search based on temp file & ports"
		in_the_wild = true
		reference = "https://github.com/vred/yara-rule-havex-netscan/blob/master/havex-netscan.yar"
	strings:
		$file = "~tracedscn.yls" wide nocase 
		//$p1 = { 0A F1 2? } 	// Rslinx 44818 only selected 
	condition:
		($file)// and ($p1)
}rule cs_hexlified_stager_sc
{
meta:
reference = "https://medium.com/walmartglobaltech/cobaltstrike-uuid-stager-ca7e82f7bb64"
strings:
$a1 = "d2648b52308b" nocase
condition:
all of them
}


rule counterPHPredirectBHEK
{
	meta:
		author = "adnan.shukor@gmail.com"
		description = "Detection rule to detect compromised page injected with invisible counter.php redirector"
		ref = "http://blog.xanda.org/2013/04/05/detecting-counter-php-the-blackhole-redirector"
		cve = "NA"
		version = "1"
		impact = 4
		hide = false
	strings:
		$counterPHP = /\<iframe\ src\=\"https?\:\/\/[a-zA-Z0-9\-\.]{4,260}\/counter\.php\"\ style\=\"visibility\:\ hidden\;\ position\:\ absolute\;\ left\:\ 0px\;\ top\:\ 0px\"\ width\=\"10\"\ height\=\"10\"\/\>$/
	condition:
		all of them
}

rule iframeRedKit
{
	meta:
		author = "adnan.shukor@gmail.com"
		description = "Detection rule to detect compromised page injected with invisible iframe of Redkit redirector"
		ref = "http://blog.xanda.org/2013/02/15/redkit-redirector-injected-into-legitimate-javascript-code/"
		cve = "NA"
		version = "1.2"
		impact = 4
		hide = false
	strings:
		$iRedKit_1 = /name\=['"]?Twitter['"]?/
		$iRedKit_2 = /scrolling\=['"]?auto['"]?/
		$iRedKit_3 = /frameborder\=['"]?no['"]?/
		$iRedKit_4 = /align\=['"]?center['"]?/
		$iRedKit_5 = /height\=['"]?2['"]?/
		$iRedKit_6 = /width\=['"]?2['"]?/
		$iRedKit_7 = /src\=['"]?http:\/\/[\w\.\-]{4,}\/(([a-z]{4}\.html?(\?[hij]=\d{7})?)|([a-z]{4,}\.php\?[a-z]{4,}\=[a-f0-9]{16}))['"]?/
	condition:
		all of them
}


rule jjEncode
{
   meta:
      description = "jjencode detection"
      ref = "http://blog.xanda.org/2015/06/10/yara-rule-for-jjencode/"
      author = "adnan.shukor@gmail.com"
      date = "10-June-2015"
      version = "1"
      impact = 3
      hide = false
   strings:
      $jjencode = /(\$|[\S]+)=~\[\]\;(\$|[\S]+)\=\{[\_]{3}\:[\+]{2}(\$|[\S]+)\,[\$]{4}\:\(\!\[\]\+["]{2}\)[\S]+/ fullword 
   condition:
      $jjencode
}

rule MS12_052
{
        meta:
                author = "Adnan Mohd Shukor" 
                author_email = "adnan.shukor @ G!"
                ref = "MS12-052"
                ref_url = "http://seclists.org/bugtraq/2012/Sep/29"
                cve = "CVE-"
                version = "1"
                impact = 4
                hide = false
        strings:
                $ms12052_1 = /mailto\:.{2000,}/ nocase fullword
                $ms12052_2 = /\.getElements?By/ nocase
                $ms12052_3 = /\.removeChild\(/ nocase
                //$ms12052_4 = /document\..*?= ?null/ nocase *greedy and ungreedy quantifiers can't be mixed in a regular expression*
        condition:
                $ms12052_1 and $ms12052_2 and ($ms12052_3 /*or $ms12052_4*/)
}
rule Yarochkin
{
	meta:
		author = "XecScan API 2.0 beta"
		date = "2013-0706 02:26:40"
		description ="scan.xecure-lab.com"
		hash0 = "68d3bf4e11a65a6ba8170c3b77cc49cb"
		Reference = "https://media.blackhat.com/us-13/US-13-Yarochkin-In-Depth-Analysis-of-Escalated-APT-Attacks-Slides.pdf"

	strings:
		$string0 = "blog.yam.com"
		$string1 = "http://blog.yam.com/minzhu0906/article/54726977"
		$string2 = "BLOG.YAM.COM"
		
	condition:
		any of them

}rule office_macro
{
    meta:
        description = "M$ Office document containing a macro"
        author = "Xavier Mertens"
        reference = "https://blog.rootshell.be/2015/01/08/searching-for-microsoft-office-files-containing-macro/"
        thread_level = 1
        in_the_wild = true
    strings:
        $a = {d0 cf 11 e0}
        $b = {00 41 74 74 72 69 62 75 74 00}
    condition:
        $a at 0 and $b
}
rule Worm_VBS_Uaper_B
{
meta:
    description = "Example rule from blog"
    author = "Xavier Mertens"
    reference = "https://blog.rootshell.be/2012/06/20/cuckoomx-automating-email-attachments-scanning-with-cuckoo/"
strings:
  $a0 = { 466f72204f353d3120546f204f332e41646472657373456e74726965732e436f756e74 }
  $a1 = { 536574204f363d4f332e41646472657373456e7472696573284f3529 }
  $a2 = { 4966204f353d31205468656e }
  $a3 = { 4f342e4243433d4f362e41646472657373 }
  $a4 = { 456c7365 }
  $a5 = { 4f342e4243433d4f342e424343202620223b20222026204f362e41646472657373 }

condition:
  $a0 and $a1 and $a2 and $a3 and $a4 and $a5
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Android_Malware : iBanking
{
	meta:
		author = "Xylitol xylitol@malwareint.com"
		date = "2014-02-14"
		description = "Match first two bytes, files and string present in iBanking"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3166"
		
	strings:
		// Generic android
		$pk = {50 4B}
		$file1 = "AndroidManifest.xml"
		// iBanking related
		$file2 = "res/drawable-xxhdpi/ok_btn.jpg"
		$string1 = "bot_id"
		$string2 = "type_password2"
	condition:
		($pk at 0 and 2 of ($file*) and ($string1 or $string2))
}
rule Windows_Malware : Zeus_1134
    {
            meta:
                    author = "Xylitol xylitol@malwareint.com"
                    date = "2014-03-03"
                    description = "Match first two bytes, protocol and string present in Zeus 1.1.3.4"
                    reference = "http://www.xylibox.com/2014/03/zeus-1134.html"
                    yaraexchange = "do what the fuck you want"
            strings:
                    $mz = {4D 5A}
                    $protocol1 = "X_ID: "
                    $protocol2 = "X_OS: "
                    $protocol3 = "X_BV: "
                    $stringR1 = "InitializeSecurityDescriptor"
                    $stringR2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)"
            condition:
                    ($mz at 0 and all of ($protocol*) and ($stringR1 or $stringR2))
    }rule CobianRAT { 
meta: 
  	description = "Yara Rule for Cobian RAT in Aggah Wayback campaign" 
  	author = "Yoroi Malware Zlab" 
    reference = "https://yoroi.company/research/the-wayback-campaign-a-large-scale-operation-hiding-in-plain-sight/"
  	last_updated = "2021_06_18" 
  	tlp = "white" 
  	category = "informational" 

strings: 
$s1="bWFzdGVy" wide
$s2="Ydmzipw~" wide 

$a1={11 8E B7 16 FE 01 5F 2C 46 1B 8D 1D} 
$a2={07 17 D6 0B 07 1A 30 20 14 0C 07 B5 1F 64 28 33} 

condition: 
   uint16(0) == 0x5A4D and any of ($s*) and 1 of ($a*)
} 
rule CVE_2012_0158_1 {
  meta:
    author = "cabrel@zerklabs.com"
    description = "ListView OCX Exploit"
    url = "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0158"

    file_1 = "Statement ID 4657-345-347-0332.doc"
    file_1_seen = "2013-05-09"
    file_1_sha256 = "807a355c641eb6e1de81757c31d711df1cd01f5858814091d8655ca1e6bdd538"

    file_2 = "BOA statement id 454-33-2463.doc"
    file_2_seen = "2013-05-13"
    file_2_sha256 = "9c9627490fcae513ca0461737c981a7bd4a2a18d50d4aef5ba66d780141f1a27"

  strings:
    $a = { 64 30 63 66 31 31 65 30 61 31 62 31 31 61 65 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 33 65 30 30 30 33 30 30 66 65 66 66 30 39 30 30 30 36 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 31 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 30 30 30 66 65 66 66 66 66 66 66 30 30 30 30 30 30 30 30 66 65 66 66 66 66 66 66 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 }
    $b = { 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 }
    $c = { 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 }
    $d = { 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 }
    $e = { 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 64 66 66 66 66 66 66 66 65 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 }
    $f = { 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 }
    $g = { 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 }
    $h = { 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 }
    $i = { 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 35 32 30 30 36 66 30 30 36 66 30 30 37 34 30 30 32 30 30 30 34 35 30 30 36 65 30 30 37 34 30 30 37 32 30 30 37 39 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 36 30 30 30 35 30 30 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 30 63 36 61 64 39 38 38 39 32 66 31 64 34 31 31 61 36 35 66 30 30 34 30 39 36 33 32 35 31 65 35 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 37 30 63 39 }
    $j = { 61 38 63 34 30 30 34 63 63 65 30 31 66 65 66 66 66 66 66 66 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 }
    $k = { 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 }
    $l = { 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 }
    $m = { 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 30 35 30 30 30 30 30 30 30 30 30 30 30 30 7D 7B 5C 6F 62 6A 65 63 74 5C 6F 62 6A 6F 63 78 7B 7B 5C 2A 5C 6F 62 6A 64 61 74 61 31 }

  condition:
    all of them
}

rule CVE_2012_0158_2 {
  meta:
    author = "cabrel@zerklabs.com"
    description = "RTF Stack Buffer Overflow Vulnerability"
    url = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0158"

    file_1 = "VAT Returns Repot 583387756.doc"
    file_1_seen = "2013-05-16"
    file_1_sha256 = "c6bdbe23857c0ca054d9fbc07f53ee0187b5ab6e86fea66091171e5b4268cb25"

  strings:
    $a = {30 31 30 35 30 30 30 30}
    $b = {35 30 36 31 36 33 36 62 36 31 36 37 36 35 30 30}
    $c = {31 36 37 37 30 33 30 30}
    $d = {63 63 37 35 30 33 30 30 33 30 33 30 36 34 36 34 33 30 33 30 36 34 36 34 39 62 39 62}
    $e = {32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62 32 62}
  condition:
    3 of ($a, $b, $c, $d, $e)
}

rule CVE_2012_0158_3 {
  meta:
    author = "cabrel@zerklabs.com"
    description = "RTF Stack Buffer Overflow Vulnerability"
    url = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0158"

    file_1_seen = "2013-05-16"
    file_1_sha256 = "60523591fe426f01a22584eab6844f7537220b786e7305296dc6bf52b7101326"

    file_2_seen = "2013-05-16"
    file_2_sha256 = "ccb738c0ee27704dc8738483cbb99de01160ab6a99277254c446bd46c781a708"

  strings:
    $a = "Marc Klenotic" wide

    $b = "JoeSoft"
    $c = "RSA1"
    $d = "S4Ra"
    $e = "CryptoAPI Private Key" wide
    $f = "Export Flag" wide

  condition:
    $a or ($b and $c and $d and $e and $f)
}
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