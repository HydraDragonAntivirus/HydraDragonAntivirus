

rule android_meterpreter
{
    meta:
        author="73mp74710n"
        comment="Metasploit Android Meterpreter Payload"
        
    strings:
	$checkPK = "META-INF/PK"
	$checkHp = "[Hp^"
	$checkSdeEncode = /;.Sk/
	$stopEval = "eval"
	$stopBase64 = "base64_decode"
	
    condition:
	any of ($check*) or any of ($stop*)
}

global rule isExecutable
{
	meta:
		author="73mp74710n"
		description="Yara rule to check for unobfuscated rat created with njrat"
	strings: 
		$MZ = { 4D 5A 90 00 }
		$PE = { 50 45 00 00 }
	condition:
		$MZ at 0 and $PE
	
}

/*

rule njRat  
{
	
	strings:
		$firewallDelete = "firewall delete allowed " wide
		$firewallAdded = "firewall add" wide

		/*ftw, ping ??*/
	/*	$ping = "ping" wide 

		/*regular expressoin to match an ip address*/
	/*	$regularExp = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide
		
	condition:
		 any of ($firewall*) or $ping or $regularExp 
		
}

*/rule snake
{
meta:
author = "artemon security"
md5 = "40aa66d9600d82e6c814b5307c137be5"
reference = "http://artemonsecurity.com/uroburos.pdf"
strings:
$ModuleStart = { 00 4D 6F 64 75 6C 65 53 74 61 72 74 00 }
$ModuleStop = { 00 4D 6F 64 75 6C 65 53 74 6F 70 00}
$firefox = "firefox.exe"
condition:
all of them
}
rule snake_packed
{
meta:
author = "artemon security"
md5 = "f4f192004df1a4723cb9a8b4a9eb2fbf"
reference = "http://artemonsecurity.com/uroburos.pdf"
strings:
/*
25 FF FF FE FF and eax, 0FFFEFFFFh
0F 22 C0 mov cr0, eax
C0 E8 ?? ?? 00 00 call sub_????
*/
$cr0 = { 25 FF FF FE FF 0F 22 C0 E8 ?? ?? 00 00}
condition:
any of them
}
rule lambda_malware
{
    meta:
        description = "Detects AWS Lambda Malware"
        author = "cdoman@cadosecurity.com"
        reference = "https://www.cadosecurity.com/cado-discovers-denonia-the-first-malware-specifically-targeting-lambda/"
        license = "Apache License 2.0"
        date = "2022-04-03"
        hash1 = "739fe13697bc55870ceb35003c4ee01a335f9c1f6549acb6472c5c3078417eed"
        hash2 = "a31ae5b7968056d8d99b1b720a66a9a1aeee3637b97050d95d96ef3a265cbbca"
    strings:
        $a = "github.com/likexian/doh-go/provider/"
        $b = "Mozilla/5.0 (compatible; Ezooms/1.0; help@moz.com)"
        $c = "username:password pair for mining server"
    condition:
        filesize < 30000KB and all of them
}
rule Linux_Wiper_AWFULSHRED {
    meta:
        description = "Detects AWFULSHRED wiper used against Ukrainian ICS"
        reference = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
        author = "mmuir@cadosecurity.com"
        date = "2022-04-12"
        license = "Apache License 2.0"
        hash = "bcdf0bd8142a4828c61e775686c9892d89893ed0f5093bdc70bde3e48d04ab99"
    strings:
        $isBash = "/bin/bash" ascii

	$a1 = "declare -r" ascii
	$a2 = "bash_history" ascii
	$a3 = "bs=1k if=/dev/urandom of=" ascii
	$a4 = "systemd" ascii
	$a5 = "apache http ssh" ascii
	$a6 = "shred" ascii

	$var1 = "iwljzfkg" ascii
	$var2 = "yrkdrrue" ascii
	$var3 = "agzerlyf" ascii
	$var4 = "rggygzny" ascii
	$var5 = "zubzgnvp" ascii
    condition:
        $isBash and 3 of ($a*) and 4 of ($var*)
}
rule Linux_Wiper_SOLOSHRED {
    meta:
        description = "Detects SOLOSHRED wiper used against Ukrainian ICS"
        reference = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
        author = "mmuir@cadosecurity.com"
        date = "2022-04-12"
        license = "Apache License 2.0"
        hash = "87ca2b130a8ec91d0c9c0366b419a0fce3cb6a935523d900918e634564b88028"
    strings:
        $a = "printenv | grep -i \"ora\"" ascii
        $b = "shred" ascii
	$c = "--no-preserve-root" ascii
        $d = "/dev/dsk" ascii
	$e = "$(ls /)" ascii
    condition:
        all of them
}
rule Linux_Worm_ORCSHRED {
    meta:
    description = "Detects ORCSHRED worm used in attacks on Ukrainian ICS"
    reference = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
	author = "mmuir@cadosecurity.com"
	date = "2022-04-12"
	license = "Apache License 2.0"
	hash = "43d07f28b7b699f43abd4f695596c15a90d772bfbd6029c8ee7bc5859c2b0861"
    strings:
    $a = "is_owner" ascii
	$b = "Start most security mode!" ascii
	$c = "check_solaris" ascii
	$d = "wsol.sh" ascii
	$e = "wobf.sh" ascii
	$f = "disown" ascii
	$g = "/var/log/tasks" ascii
    condition:
        4 of them
}
rule Powershell_Downloader_POWERGAP {
    meta:
        description = "Detects POWERGAP downloader used against Ukrainian ICS"
        reference = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
        author = "mmuir@cadosecurity.com"
        date = "2022-04-12"
        license = "Apache License 2.0"
    strings:
        $a = "Start-work" ascii
        $b = "$GpoGuid" ascii
        $c = "$SourceFile" ascii
        $d = "$DestinationFile" ascii
        $e = "$appName" ascii
	$f = "LDAP://ROOTDSE" ascii
	$g = "GPT.INI" ascii
	$h = "Get-WmiObject" ascii
    condition:
        5 of them
}
rule Whispergate_Stage_1 {
    meta:
      description = "Detects first stage payload from WhisperGate"
      author = "mmuir@cadosecurity.com"
      date = "2022-01-17"
      license = "Apache License 2.0"
      hash = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
      report = "https://github.com/cado-security/DFIR_Resources_Whispergate"
    strings:
      $a = { 31 41 56 4E 4D 36 38 67 6A 36 50 47 50 46 63 4A 75 66 74 4B 41 54 61 34 57 4C 6E 7A 67 38 66 70 66 76 }
      $b = { 38 42 45 44 43 34 31 31 30 31 32 41 33 33 42 41 33 34 46 34 39 31 33 30 44 30 46 31 38 36 39 39 33 43 36 41 33 32 44 41 44 38 39 37 36 46 36 41 35 44 38 32 43 31 45 44 32 33 30 35 34 43 30 35 37 45 43 45 44 35 34 39 36 46 36 35 }
      $c = { 24 31 30 6B 20 76 69 61 20 62 69 74 63 6F 69 6E 20 77 61 6C 6C 65 74 }
      $d = { 74 6F 78 20 49 44 }
    condition:
      uint16(0) == 0x5A4D and all of them
}
rule Whispergate_Stage_2 {
    meta:
      description = "Detects second stage payload from WhisperGate"
      author = "mmuir@cadosecurity.com"
      date = "2022-01-17"
      license = "Apache License 2.0"
      hash = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"
      report = "https://github.com/cado-security/DFIR_Resources_Whispergate"
    strings:
      $a = { 6D 5F 49 6E 74 65 72 63 65 70 74 6F 72 }
      $b = { 6D 5F 62 31 36 65 37 33 65 30 64 61 61 63 34 62 34 33 62 36 35 36 36 39 30 31 62 35 34 32 34 63 35 33 }
      $c = { 6D 5F 34 33 37 37 33 32 63 65 65 35 66 35 34 64 37 64 38 34 61 64 64 37 62 64 33 30 39 37 64 33 63 61 }
      $d = { 6D 5F 30 64 62 39 37 30 38 63 66 36 34 39 34 30 38 32 39 66 39 61 66 38 37 65 64 65 65 64 66 36 30 65 }
      $e = { 6D 5F 65 31 34 33 33 31 36 38 32 30 62 31 34 64 30 33 38 38 61 37 32 37 34 34 33 38 65 63 30 37 38 64 }
      $f = { 6D 5F 66 33 31 30 39 30 63 37 31 35 64 65 34 62 30 62 61 62 64 33 31 61 36 33 34 31 31 30 34 36 63 38 }
      $g = { 6D 5F 36 31 31 64 31 61 62 63 33 32 66 63 34 66 64 38 61 33 34 65 30 34 34 66 39 37 33 34 34 31 64 61 }
      $h = { 6D 5F 37 37 34 62 39 32 31 30 64 39 38 31 34 32 65 62 62 34 34 31 33 35 35 39 64 61 61 65 35 61 34 34 }
    condition:
      uint16(0) == 0x5A4D and all of them
}rule Wiper_Ukr_Feb_2022 {
    meta:
      description = "Detects Wiper seen in Ukraine 23rd Feb 2022"
      author = "cadosecurity.com"
      date = "2022-02-23"
      license = "Apache License 2.0"
      hash = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
      ref1 = "https://twitter.com/threatintel/status/1496578746014437376"
      ref2 = "https://twitter.com/ESETresearch/status/1496581903205511181"
      report = "https://github.com/cado-security/wiper_feb_2022"
    strings:
        $ = "Hermetica Digital Ltd" wide ascii
        $ = "DRV_XP_X64" wide ascii
        $ = "Windows\\System32\\winevt\\Logs" wide ascii
        $ = "EPMNTDRV\\%u" wide ascii
    condition:
      uint16(0) == 0x5A4D and all of them
}rule ROKRAT_loader : TAU DPRK APT

{

meta:

    author = "CarbonBlack Threat Research" //JMyers

    date = "2018-Jan-11"

    description = "Designed to catch loader observed used with ROKRAT malware"

    rule_version = 1

	yara_version = "3.7.0"

    TLP = "White"

	exemplar_hashes = "e1546323dc746ed2f7a5c973dcecc79b014b68bdd8a6230239283b4f775f4bbd"

strings:

	$n1 = "wscript.exe"

	$n2 = "cmd.exe"

	$s1 = "CreateProcess"

	$s2 = "VirtualAlloc"

	$s3 = "WriteProcessMemory"

	$s4 = "CreateRemoteThread"

	$s5 = "LoadResource"

	$s6 = "FindResource"

	$b1 = {33 C9 33 C0 E8 00 00 00 00 5E} //Clear Register, call+5, pop ESI

	$b2 = /\xB9.{3}\x00\x81\xE9?.{3}\x00/ //subtraction for encoded data offset

    //the above regex could slow down scanning

	$b3 = {03 F1 83 C6 02} //Fix up position

	$b4 = {3E 8A 06 34 90 46} //XOR decode Key

	$b5 = {3E 30 06 46 49 83 F9 00 75 F6} //XOR routine and jmp to code

	//push api hash values plain text

	$hpt_1 = {68 EC 97 03 0C} //api name hash value – Global Alloc

	$hpt_2 = {68 54 CA AF 91} //api name hash value – Virtual Alloc

	$hpt_3 = {68 8E 4E 0E EC} //api name hash value – Load Library

	$hpt_4 = {68 AA FC 0D 7C} //api name hash value – GetProc Addr

	$hpt_5 = {68 1B C6 46 79} //api name hash value – Virtual Protect

	$hpt_6 = {68 F6 22 B9 7C} //api name hash value – Global Free

	//push api hash values encoded XOR 0x13

	$henc_1 = {7B FF 84 10 1F} //api name hash value – Global Alloc

	$henc_2 = {7B 47 D9 BC 82} //api name hash value – Virtual Alloc

	$henc_3 = {7B 9D 5D 1D EC} //api name hash value – Load Library

	$henc_4 = {7B B9 EF 1E 6F} //api name hash value – GetProc Addr

	$henc_5 = {7B 08 D5 55 6A} //api name hash value – Virtual Protect

	$henc_6 = {7B E5 31 AA 6F} //api name hash value – Global Free

condition:

	(1 of ($n*) and 4 of ($s*) and 4 of ($b*)) or all of ($hpt*) or all of ($henc*)

}


rule ROKRAT_payload : TAU DPRK APT

{

meta:

    author = "CarbonBlack Threat Research" //JMyers

    date = "2018-Jan-11"

    description = "Designed to catch loader observed used with ROKRAT malware"

    rule_version = 1

	yara_version = "3.7.0"

    TLP = "White"

	exemplar_hashes = "e200517ab9482e787a59e60accc8552bd0c844687cd0cf8ec4238ed2fc2fa573"

strings:

	$s1 = "api.box.com/oauth2/token" wide

	$s2 = "upload.box.com/api/2.0/files/content" wide

	$s3 = "api.pcloud.com/uploadfile?path=%s&filename=%s&nopartial=1" wide

	$s4 = "cloud-api.yandex.net/v1/disk/resources/download?path=%s" wide

	$s5 = "SbieDll.dll"

	$s6 = "dbghelp.dll"

	$s7 = "api_log.dll"

	$s8 = "dir_watch.dll"

	$s9 = "def_%s.jpg" wide

	$s10 = "pho_%s_%d.jpg" wide

	$s11 = "login=%s&password=%s&login_submit=Authorizing" wide

	$s12 = "gdiplus.dll"

	$s13 = "Set-Cookie:\\b*{.+?}\\n" wide

	$s14 = "charset={[A-Za-z0-9\\-_]+}" wide

condition:

	12 of ($s*)

}

rule Word_Emotet_Dropper_2017Aug : TAU Word Emotet VBA

{

meta:

author = "Carbon Black TAU"

date = "2017-August-22"

description = "Emotet Word Document Dropper utilizing embedded Comments and Custom Properties Fields"

reference = "https://www.carbonblack.com/2017/08/28/threat-analysis-word-documents-embedded-macros-leveraging-emotet-trojan/"

yara_version = "3.5.0"

exemplar_hashes = "20ca01986dd741cb475dd0312a424cebb53f1201067938269f2e746fb90d7c2e, c7cab605153ac4718af23d87c506e46b8f62ee2bc7e7a3e6140210c0aeb83d48, 3ca148e6d17868544170351c7e0dbef38e58de9435a2f33fe174c83ea9a5a7f5"

strings:

$signature = {D0 CF 11 E0}

$base = /JAB7\w{100,}={0,2}/

$s1 = "BuiltInDocumentProperties"

$s2 = "CustomDocumentProperties"

$s3 = "Run"

$s4 = "VBA"

$s6 = "Comments"

$s7 = "autoopen"

$s8 = "Module1"

$s9 = "Picture 1" wide

$s10 = "JFIF"

condition:

$signature at 0 and

$base in (0x8200..0x9000) and

8 of ($s*)

}

import "pe"

rule bit9_ms15_093_plugx_dll_payload : TLPWHITE
{
    meta:
         author = "rnolen@bit9.com"
        date = "8.26.2015"
        description = "Find a specific plugx variant DLL payload"
        hash1 = "20d88b0fa34d3d79629cb602f08a1145008a75215fe2c91a3b3171287adc4c3d"
    strings:
        $datfile = "nvdisps_user.dat"
        $dllfile = "nvdisps.dll"
        $mutex	= "nvdisps_event"
    condition:
        3 of ($datfile,$dllfile,$mutex) and pe.exports("ShadowPlay")
}


rule bit9_ms15_093_plugx_dropper : TLPWHITE
{
    meta:
        author = "rnolen@bit9.com"
        date = "8.26.2015"
        description = "Find a specific plugx variant dropper"
        hash1 = "61900fb9841a4d6d14e990163ea575694e684beaf912f50989b0013a9634196f"
        hash2 = "71b201a5a7dfdbe91c0a7783f845b71d066c62014b944f488de5aec6272f907c"
        hash3 = "56ec1ccab98c1ed67a0095b7ec8e6b17b12da3e00d357274fa37ec63ec724c07"
        hash4 = "c437465db42268332543fbf6fd6a560ca010f19e0fd56562fb83fb704824b371"
    strings:
        $datfile = "nvdisps_user.dat"
        $dllfile = "nvdisps.dll"
        $rundll32 = "Rundll32.exe"
        $winhlp32 = "\\winhlp32.exe"
        $shellout = "ShadowPlay 84"
    condition:
        5 of ($datfile,$dllfile,$rundll32,$winhlp32,$shellout)
}


rule PNG_dropper:RU TR APT

{

meta:

      author = "CarbonBlack Threat Research"

      date = "2017-June-11"

      description = "Dropper tool that extracts payload from PNG resources"
      
      reference = "https://www.carbonblack.com/2017/08/18/threat-analysis-carbon-black-threat-research-dissects-png-dropper/"

      yara_version = "3.5.0"

      exemplar_hashes = "3a5918c69b6ee801ab8bfc4fc872ac32cc96a47b53c3525723cc27f150e0bfa3, 69389f0d35d003ec3c9506243fd264afefe099d99fcc0e7d977007a12290a290, eeb7784b77d86627bac32e4db20da382cb4643ff8eb86ab1abaebaa56a650158 "

strings:

	$s1 = "GdipGetImageWidth"

	$s2 = "GdipGetImageHeight"

	$s3 = "GdipCreateBitmapFromStream"

	$s4 = "GdipCreateBitmapFromStreamICM"

	$s5 = "GdipBitmapLockBits"

	$s6 = "GdipBitmapUnlockBits"

	$s7 = "LockResource"

	$s8 = "LoadResource"

	$s9 = "ExpandEnvironmentStringsW"

	$s10 = "SetFileTime"

	$s11 = "memcmp"

	$s12 = "strlen"

	$s13 = "memcpy"

	$s14 = "memchr"

	$s15 = "memmove"

	$s16 = "ZwQueryValueKey"

	$s17 = "ZwQueryInformationProcess"

	$s18 = "FindNextFile"

	$s19 = "GetModuleHandle"

	$s20 = "VirtualFree"

	$PNG1 = {89 50 4E 47 [8] 49 48 44 52} //PNG Header

	$bin32_bit1 = {50 68 07 10 06 00 6A 07 8?} //BitmapLockBits_x86

	$bin64_bit1 = {41 B? 07 10 06 00} //BitmapLockBits_x64

	$bin64_bit2 = {41 B? 07 00 00 00}//BitmapLockBits_x64

	$bin32_virt1 = {6A 40 68 00 10 00 00 50 53} //VirtualAlloc_x86

	$bin64_virt1 = {40 41 B? 00 10 00 00}//VirtualAlloc_x64

   

condition:

    uint16(0) == 0x5A4D and // MZ header check

    filesize < 6MB and

    18 of ($s*) and

    (#PNG1 > 7) and

//checks for multiple PNG headers

       ((#bin32_bit1 > 1 and $bin32_virt1) or

//More than 1 of $bin32_bit and $bi32_virt1

       (for 1 of ($bin64_bit*) : (# > 2) and $bin64_virt1))

//1 of $bin64_bit - present more that 2 times and $bin64_Virt1

}
rule APT28_SkinnyBoy_Dropper: RUSSIAN THREAT ACTOR {
meta:
author = "Cluster25"
hash1 = "12331809c3e03d84498f428a37a28cf6cbb1dafe98c36463593ad12898c588c9"
report = "https://21649046.fs1.hubspotusercontent-na1.net/hubfs/21649046/2021-05_FancyBear.pdf"
strings:
$ = "cmd /c DEL " ascii
$ = " \"" ascii
$ = {8a 08 40 84 c9 75 f9}
$ = {0f b7 84 0d fc fe ff ff 66 31 84 0d fc fd ff ff}
condition:
(uint16(0) == 0x5A4D and all of them)
}import "pe"
rule APT28_SkinnyBoy_Implanter: RUSSIAN THREAT ACTOR {
meta:
author= "Cluster25"
date= "2021-05-24"
hash= "ae0bc3358fef0ca2a103e694aa556f55a3fed4e98ba57d16f5ae7ad4ad583698"
report = "https://21649046.fs1.hubspotusercontent-na1.net/hubfs/21649046/2021-05_FancyBear.pdf"
strings:
$enc_string = {F3 0F 7E 05 ?? ?? ?? ?? 6? [5] 6A ?? 66 [6] 66 [7] F3 0F 7E 05 ?? ?? ?? ?? 8D
85 [4] 6A ?? 50 66 [7] E8}
$heap_ops = {8B [1-5] 03 ?? 5? 5? 6A 08 FF [1-6] FF ?? ?? ?? ?? ?? [0-6] 8B ?? [0-6] 8?}
$xor_cycle = { 8A 8C ?? ?? ?? ?? ?? 30 8C ?? ?? ?? ?? ?? 42 3B D0 72 }
condition:
uint16(0) == 0x5a4d and pe.is_dll() and filesize < 100KB and $xor_cycle and $heap_ops and
$enc_string
}rule APT28_SkinnyBoy_Launcher: RUSSIAN THREAT ACTOR {
meta:
author = "Cluster25"
hash1 ="2a652721243f29e82bdf57b565208c59937bbb6af4ab51e7b6ba7ed270ea6bce"
report = "https://21649046.fs1.hubspotusercontent-na1.net/hubfs/21649046/2021-05_FancyBear.pdf"
strings:
$sha = {F4 EB 56 52 AF 4B 48 EE 08 FF 9D 44 89 4B D5 66 24 61 2A 15 1D 58 14 F9 6D 97
13 2C 6D 07 6F 86}
$l1 = "CryptGetHashParam" ascii
$l2 = "CryptCreateHash" ascii
$l3 = "FindNextFile" ascii
$l4 = "PathAddBackslashW" ascii
$l5 = "PathRemoveFileSpecW" ascii
$h1 = {50 6A 00 6A 00 68 0C 80 00 00 FF ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A 00
56 ?? ?? ?? ?? 50 FF ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ??}
$h2 = {8B 01 3B 02 75 10 83 C1 04 83 C2 04 83 EE 04 73 EF}
condition:
uint16(0) == 0x5a4d and filesize < 100KB and ($sha or (all of ($l*) and all of ($h*)))
}rule APT29_HTMLSmuggling_ZIP_82733_00001 {
meta:
author = "Cluster25"
description = "Rule to detect the EnvyScout HTML smuggling with ZIP payload used in the APT29/Nobelium APT29 chain"
date = "2022-05-12"
hash = "d5c84cbd7dc70e71f3eb24434a58b2f149d0c39faa7e4157552b60c7dbb53d11"
report = "https://blog.cluster25.duskrise.com/2022/05/13/cozy-smuggled-into-the-box"
strings:
$s1 = "new Blob("
$s2 = "new Uint8Array("
$s3 = "application/octet-stream"
$t1 = "saveAs("
$t2 = "download("
$r1 = { 66 6F 72 28 76 61 72 20 69 20 3D 20 30 78 30 3B 20 69 20 3C 20 64 5B 27 6C 65 6E 67 74 68 27 5D 3B 20 69 2B 2B 29 20 7B 0A 20 20 20 20 64 5B 69 5D 20 3D 20 64 5B 69 5D }
condition: (filesize > 500KB and all of ($s*) and ($t1 or $t2) and $r1)
}import "pe"
rule APT29_Loader_87221_00001 {
    meta:
        author = "Cluster25"
        tlp = "white"
        description = "Detects DLL loader variants used in Nobelium kill-chain"
        hash1 = "6fc54151607a82d5f4fae661ef0b7b0767d325f5935ed6139f8932bc27309202"
        hash2 = "23a09b74498aea166470ea2b569d42fd661c440f3f3014636879bd012600ed68"
        report = "https://blog.cluster25.duskrise.com/2022/05/13/cozy-smuggled-into-the-box"
    strings:
        $s1 = "%s\\blank.pdf" fullword ascii
        $s2 = "%s\\AcroSup" fullword ascii
        $s3 = "vcruntime140.dll" fullword ascii
        $s4 = "ME3.99.5UUUUUUUUUUU" fullword ascii
        $c1 = "Rock" fullword ascii
        $c2 = ".mp3" fullword ascii
        $c3 = "%s.backup" fullword ascii
        $sequence1 = { C7 45 ?? 0B 00 10 00 48 8B CF FF 15 ?? ?? ?? 00 85 C0 74 ?? 48 8D 55 ?? 48 89 75 ?? 48 8B CF FF 15 ?? ?? ?? 00 85 C0 74 ?? 48 8B CF FF 15 ?? ?? ?? 00 } // Thread contect change
        $sequence2 = { 0F B6 0B 4C 8D 05 ?? ?? ?? 00 89 4C 24 ?? 4D 8B CD 49 8B CD BA 04 01 00 00 E8 ?? ?? ?? ?? 48 8D 5B 01 48 83 EF 01 75 ?? } // encoding cycle
        $sequence3 = { 4C 8D 8C 24 ?? 00 00 00 8B 53 ?? 44 8D 40 ?? 48 03 CD 44 89 A4 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 8B 43 ?? 44 8B 43 ?? 4A 8D 14 38 48 8D 0C 28 E8 ?? ?? 00 00 8B 4B ?? 4C 8D 8C 24 ?? 00 00 00 8B 53 ?? 48 03 CD 44 8B 84 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 } //DLL Unhook
        $sequence4 = { 42 0F B6 8C 32 ?? ?? ?? 00 48 83 C2 03 88 0F 48 8D 7F 01 48 83 FA 2D 7C E7 } // get domain name string
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB
            and pe.imports("kernel32.dll", "SetThreadContext") and pe.imports("kernel32.dll", "ResumeThread") and pe.imports("kernel32.dll", "K32GetModuleFileNameExA")
            and 3 of ($s*)
            and all of ($c*)
            and 3 of ($sequence*)
}rule GhostWriter_MicroBackdoor_72632_00001 {
meta:
author = "Cluster25"
hash1 = "559d8e8f2c60478d1c057b46ec6be912fae7df38e89553804cc566cac46e8e91"
tlp = "white"
report = "https://blog.cluster25.duskrise.com/2022/03/08/ghostwriter-unc1151-adopts-microbackdoor-variants-in-cyber-operations-against-targets-in-ukraine"
strings:
$ = "cmd.exe /C \"%s%s\"" fullword wide
$ = "client.dll" fullword ascii
$ = "ERROR: Unknown command" fullword ascii
$ = " *** ERROR: Timeout occured" fullword ascii
$ = "%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword ascii
$ = "MIIDazCCAlOgAwIBAgIUWOftflCclQXpmWMnL1ewj2F5Y1AwDQYJKoZIhvcNAQEL" fullword ascii
condition: (uint16(0) == 0x5a4d and all of them)
}rule GhostWriter_MicroLoader_72632_00001 {
meta:
author = "Cluster25"
hash1 = "e97f1d6ec1aa3f7c7973d57074d1d623833f0e9b1c1e53f81af92c057a1fdd72"
tlp = "white"
report = "https://blog.cluster25.duskrise.com/2022/03/08/ghostwriter-unc1151-adopts-microbackdoor-variants-in-cyber-operations-against-targets-in-ukraine"
strings:
$ = "ajf09aj2.dll" fullword wide
$ = "regsvcser" fullword ascii
$ = "X l.dlT" fullword ascii
$ = "rtGso9w|4" fullword ascii
$ = "ajlj}m${<" fullword ascii
condition: (uint16(0) == 0x5a4d and all of them)
}import "pe"
rule sidewinder_apt_rtf_cve_2017_0199{
meta:
author = "Cluster25"
date = "2021-09-09"
hash1 = "282367417cdc711fbad33eb6988c172c61a9a57d9f926addaefabc36cac3c004"
hash2 = "6d021166bdde0eab22fd4a9f398fdd8ccf8b977ff33a77c518f8d16e56d3eeee"
report = "https://21649046.fs1.hubspotusercontent-na1.net/hubfs/21649046/a_rattlesnake_in_the_navy.pdf"
strings:
$head = "{\\rtf1" ascii
$obj = "objdata 0105000002000000" ascii
$expl = "6D007300680074006D006C000000FFD7E8130000006E756E48544D4C4170706C69636174696F6E" ascii
$s1 = "416374697665584F626A656374" ascii nocase
$s2 = "5176524d384b4e4734504332565a55753765497764426f72686974366761416259796d356c4563306a4453576e585431334a7173467870484f666b7a4c392b2f3d" ascii nocase
$s3 = "62203e3e2031362026203235352c2062203e3e20382026203235352c2062202620323535" ascii nocase
condition:
$head at 0 and $obj and $expl and 2 of ($s*)
}rule UNC1222_HermeticWiper_23433_10001 {
meta:
date = "2022-02-23"
description = "Detects HermeticWiper variants by internal strings"
author = "Cluster25"
tlp = "white"
hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
hash2 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
report = "https://blog.cluster25.duskrise.com/2022/02/24/ukraine-analysis-of-the-new-disk-wiping-malware"
strings:
$ = "tdrv.pdb" fullword ascii
$ = "\\\\.\\EPMNTDRV\\%u" fullword wide
$ = "PhysicalDrive%u" fullword wide
$ = "Hermetica Digital Ltd"
condition:
(uint16(0) == 0x5a4d and all of them)
}import "pe"
rule UNC1222_HermeticWiper_23433_10002 {
meta:
date = "2022-02-23"
description = "Detects HermeticWiper variants by internal strings"
hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
hash2 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
tlp = "white"
report = "https://blog.cluster25.duskrise.com/2022/02/24/ukraine-analysis-of-the-new-disk-wiping-malware"
strings:
$p1 = "$INDEX_ALLOCATION" wide
$p2 = "$I30" wide
$p3 = "$DATA" wide
$p4 = "$logfile" wide
$p5 = "$bitmap" wide
$s1 = "PhysicalDrive%u" wide
$s2 = "EPMNTDRV" wide
$s3 = "SYSVOL" wide
$s4 = "SYSTEM\\CurrentControlSet\\Control\\CrashControl" wide
$s5 = "CrashDumpEnabled" wide
$s6 = "NTFS" ascii
$s7 = "FAT" ascii
$s8 = "OpenSCManager" ascii
$s9 = "SeBackupPrivilege" wide
$s10 = "SeLoadDriverPrivilege" wide
$s11 = "RCDATA" wide
// LookupPrivilegeValueW routine
$r1 = { 85 35 2C 50 40 00 C7 84 ?? ?? ?? ?? 77 00 6E 00 C7 84 ?? ?? ?? ?? 50 00 72 00 8D 43 04 50 8D 44 24 44 50 6A 00 FF D6 8D 43 10 50 68 A8 55 40 00 6A 00 FF D6 6A 00 6A 00 6A 00 53 C7 03 02 00 00 00 6A 00 }
// AdjustTokenPrivileges routine
$r2 = { C7 43 0C 02 00 00 00 C7 43 18 02 00 00 00 FF 74 24 24 FF 15 28 50 40 00 FF D7 85 C0 75 0F }
// OpenSCManagerW (DatabaseName: "ServicesActive") routine
$r3 = { 68 ?? 3f 00 0f 00 68 ?? 80 55 44 00 33 f6 56 ff 15 24 50 40 00 89 44 24 10 85 C0 75 06 }
// OpenServiceW (ServiceName: "vss") routine
$r4 = { 68 ?? 58 40 00 50 FF 15 20 50 40 00 8B D8 85 DB 75 0C }
// ChangeServiceConfigW routine
$r5 = { 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 6A FF 6A 04 6A 10 53 FF 15 14 50 40 00 85 C0 75 04 }
// CreateThread/CreateEventW and InitializeShutdownW routine
$r6 = { 8B 35 ?? ?? ?? ?? 8D 44 ?? ?? 6A 00 6A 00 50 68 ?? ?? 40 00 6A 00 6A 00 89 7C ?? ?? FF D6 6A 00 6A 00 6A 01 6A 00 89 44 ?? ?? FF 15 ?? ?? ?? ?? 6A 00 6A 00 89 44 ?? ?? 8D 44 ?? ?? 50 68 D0 34 40 00 6A 00 6A 00 FF D6 8B 3D D4 ?? ?? ?? 6B D8 85 DB 74 0A }
condition:
uint16(0)==0x5a4d and pe.imports("lz32.dll") and filesize < 200KB and (2 of ($p*) and (all of ($s*) or (6 of ($s*) and any of ($r*)) or 4 of ($r*)))
}import "pe"

rule APT28_HospitalityMalware_document {
 meta:
 description = "Yara Rule for APT28_Hospitality_Malware document identification"
 author = "CSE CybSec Enterprise - Z-Lab"
 last_updated = "2017-10-02"
 tlp = "white"
 reference = "http://csecybsec.com/download/zlab/APT28_Hospitality_Malware_report.pdf"
 category = "informational"

 strings:

 /* this string identifies the malicious payload */
 $a = {75 52 B9 ED 1B D6 83 0F DB 24 CA 87 4F 5F 25 36 BF 66 BA}

 /* this string identifies the document */
 $b = {EC 3B 6D 74 5B C5 95 F3 9E 24 5B FE 4A 64 C7 09 CE 07 C9 58 4E 62 3B}

 condition:
 all of them and filesize > 75KB and filesize < 82KB
}

rule APT28_HospitalityMalware_mvtband_file {
 meta:
 description = "Yara Rule for mvtband.dll malware"
 author = "CSE CybSec Enterprise - Z-Lab"
 last_updated = "2017-10-02"
 tlp = "white"
 reference = "http://csecybsec.com/download/zlab/APT28_Hospitality_Malware_report.pdf"
 category = "informational"

 strings:
 $a = "DGMNOEP"
 $b = {C7 45 94 0A 25 73 30 8D 45 94} // two significant instructions

 condition:
 all of them and pe.sections[2].raw_data_size == 0
}
rule BlackShades {
    meta:
        rule_group = "implant"
        implant = "BlackShades"
        
        description = "BlackShades implant"
        id = "CSE_900000"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = "Brian Wallace (@botnet_hunter)"
        creation_date = "2016-03-23T15:26:52.062158Z"
        date = "2014/04"
        family = "blackshades"
        last_saved_by = "malware_dev"
        ref = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.BlackShades.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
    strings:
        $string1 = "bal_server"
        $string2 = "txtChat"
        $string3 = "UDPFlood"
    
    condition:
        all of them
    
}

rule Punisher {
    meta:
        rule_group = "implant"
        implant = "Punisher"
        
        description = "Punisher implant"
        id = "CSE_900002"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.079754Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/Punisher"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.Punisher.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
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

rule gh0st {
    meta:
        rule_group = "implant"
        implant = "gh0st"
        
        description = "gh0st implant"
        id = "CSE_900003"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        creation_date = "2016-03-23T15:26:52.087951Z"
        last_saved_by = "malware_dev"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.Gh0st.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
    strings:
        // File 11401249a0e499a3cd2dc147d9600ff8.exe @ 0x00460E80 (2015-11-18)
        $Match_00460e80 = { 8b 44 24 04 56 8b 70 1c 8b 48 10 8b 56 14 3b d1 76 02 8b d1 85 d2 74 58 8b 76 10 8b ca 53 8b d9 57 8b 78 0c c1 e9 02 f3 a5 8b cb 83 e1 03 f3 a4 8b 78 0c 8b 48 1c 03 fa 89 78 0c 8b 71 10 03 f2 89 71 10 8b 58 14 8b 78 10 8b 48 1c 03 da 2b fa 89 58 14 89 78 10 8b 71 14 5f 2b f2 5b 89 71 14 8b 40 1c 8b 48 14 85 c9 75 06 8b 48 08 89 48 10 5e c3 }
    
    condition:
        all of them
    
}

rule Xtreme {
    meta:
        rule_group = "implant"
        implant = "Xtreme"
        
        description = "Xtreme implant"
        id = "CSE_900004"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.095338Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/Xtreme"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.Xtreme.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
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

rule Bozok {
    meta:
        rule_group = "implant"
        implant = "Bozok"
        
        description = "Bozok implant"
        id = "CSE_900005"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.101921Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/Bozok"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.Bozok.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
    strings:
        $a = "getVer" nocase
        $b = "StartVNC" nocase
        $c = "SendCamList" nocase
        $d = "untPlugin" nocase
        $e = "gethostbyname" nocase
    
    condition:
        all of them
    
}

rule CyberGate {
    meta:
        rule_group = "implant"
        implant = "CyberGate"
        
        description = "CyberGate implant"
        id = "CSE_900006"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.107496Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/CyberGate"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.CyberGate.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
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

rule NanoCore {
    meta:
        rule_group = "implant"
        implant = "NanoCore"
        
        description = "NanoCore implant"
        id = "CSE_900007"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.114711Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/NanoCore"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.NanoCore.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
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

rule xRAT {
    meta:
        rule_group = "implant"
        implant = "xRAT"
        
        description = "xRAT implant"
        id = "CSE_900008"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.120133Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/xRat"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.xRat.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
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

rule VirusRat {
    meta:
        rule_group = "implant"
        implant = "VirusRat"
        
        description = "VirusRat implant"
        id = "CSE_900009"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.125583Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/VirusRat"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.VirusRat.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
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

rule LuxNet {
    meta:
        rule_group = "implant"
        implant = "LuxNet"
        
        description = "LuxNet implant"
        id = "CSE_900010"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.131170Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/LuxNet"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.LuxNet.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
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

rule njRat {
    meta:
        rule_group = "implant"
        implant = "njRat"
        
        description = "njRat implant"
        id = "CSE_900011"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.138482Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/njRat"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.njRat.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
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

rule Pandora {
    meta:
        rule_group = "implant"
        implant = "Pandora"
        
        description = "Pandora implant"
        id = "CSE_900012"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.144083Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/Pandora"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.Pandora.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
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

rule njrat: rat {
    meta:
        rule_group = "implant"
        implant = "njrat"
        
        description = "tested against NjRat versions 0.3.6 - 0.7d"
        id = "CSE_900013"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de>"
        creation_date = "2016-03-23T15:26:52.150257Z"
        date = "2015-11-18"
        last_saved_by = "malware_dev"
        sample = "unpacked: 2b96518a66d251fedb39264e668f588c (0.7d)"
        al_configdumper = "external.geekweek.batchNjRat.getConfig"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
        type = "info"
        updated = "2015-11-18"
        version = "1"
    
    strings:
        $cnc_traffic_0 = {7C 00 27 00 7C 00 27 00 7C} // looks like: |'|'|
        $rights_0 = "netsh firewall add allowedprogram \"" wide
        $rights_1 = "netsh firewall delete allowedprogram \"" wide
    
    condition:
        (all of ($cnc_traffic_*)) and (all of ($rights_*))
    
}

rule darkcomet51: rat {
    meta:
        rule_group = "implant"
        implant = "darkcomet51"
        
        description = "DarkComet RAT version 5.1"
        id = "CSE_900015"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = "CCIRC"
        creation_date = "2016-03-23T15:26:52.162005Z"
        date = "2015-11-16"
        last_saved_by = "malware_dev"
        al_configparser = "DarkComet51"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
    strings:
        $config = "D57ABA5857F0AFF67584605E90BE4665C9814BEEC7E"
    
    condition:
        any of them
    
}

rule PoisonIvy {
    meta:
        rule_group = "implant"
        implant = "PoisonIvy"
        
        description = "PoisonIvy implant"
        id = "CSE_900016"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.166521Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/PoisonIvy"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.PoisonIvy.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
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

rule DarkComet {
    meta:
        rule_group = "implant"
        implant = "DarkComet"
        
        description = "DarkComet implant"
        id = "CSE_900001"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = " Kevin Breen <kevin@techanarchy.net>"
        creation_date = "2016-03-23T15:26:52.071996Z"
        date = "2014/04"
        filetype = "exe"
        last_saved_by = "malware_dev"
        maltype = "Remote Access Trojan"
        ref = "http://malwareconfig.com/stats/DarkComet"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.DarkComet.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
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
        (all of ($a*) or all of ($b*)) and not darkcomet51
    
}

rule darkcomet_rc4 {
    meta:
        rule_group = "implant"
        implant = "darkcomet_rc4"
        
        description = "darkcomet_rc4 implant"
        id = "CSE_900014"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        creation_date = "2016-03-23T15:26:52.155838Z"
        last_saved_by = "malware_dev"
        al_configdumper = "al_services.alsvc_configdecoder.ext.RATDecoders.DarkComet.run"
        al_configparser = "GenericParser"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
    strings:
        // File 175e27f2e47674e51cb20d9daa8a30c4 @ 0x468438 (2015-11-16)
        $darkcomet_rc4 = { 55 8B EC 81 C4 E0 FB FF FF 53 56 57 33 DB 89 9D E0 FB FF FF 89 5D F4 89 5D F0 89 4D EC 89 55 F8 89 45 FC 8B 45 FC E8 ?? ?? ?? ?? 8B 45 F8 E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 F8 85 C0 74 05 83 E8 04 8B 00 85 C0 0F 84 3E 02 00 00 8B 45 FC 85 C0 74 05 83 E8 04 8B 00 85 C0 0F 84 2A 02 00 00 8D 95 E0 FB FF FF 8B 45 FC E8 ?? ?? ?? ?? 8B 95 E0 FB FF FF 8D 45 FC E8 ?? ?? ?? ?? 8B 55 F8 8B C2 85 C0 74 05 83 E8 04 8B 00 3D 00 01 00 00 7E 34 68 00 01 00 00 8D 45 F4 B9 01 00 00 00 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 8D 45 F8 E8 ?? ?? ?? ?? 8B D0 8B 45 F4 B9 00 01 00 00 E8 ?? ?? ?? ?? EB 42 8B DA 85 DB 74 05 83 EB 04 8B 1B 53 8D 45 F4 B9 01 00 00 00 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 8B 5D F8 85 DB 74 05 83 EB 04 8B 1B 8D 45 F8 E8 ?? ?? ?? ?? 8B D0 8B 45 F4 8B CB E8 ?? ?? ?? ?? 33 F6 8D 85 E4 FB FF FF 89 30 46 83 C0 04 81 FE 00 01 00 00 75 F2 33 DB 33 F6 8D 8D E4 FB FF FF 8B 7D F8 85 FF 74 05 83 EF 04 8B 3F 8B C6 99 F7 FF 8B 45 F4 0F B6 04 10 03 19 03 C3 25 FF 00 00 80 79 07 48 0D 00 FF FF FF 40 8B D8 0F B6 01 88 45 EB 8B 84 9D E4 FB FF FF 89 01 0F B6 45 EB 89 84 9D E4 FB FF FF 46 83 C1 04 81 FE 00 01 00 00 75 AE 33 DB 33 FF 8B 75 FC 85 F6 74 05 83 EE 04 8B 36 56 8D 45 F0 B9 01 00 00 00 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 8B 75 FC 85 F6 74 05 83 EE 04 8B 36 8D 45 FC E8 ?? ?? ?? ?? 8B D0 8B 45 F0 8B CE E8 ?? ?? ?? ?? 8B 45 FC 85 C0 74 05 83 E8 04 8B 00 48 85 C0 0F 8C 82 00 00 00 40 89 45 E4 33 F6 43 81 E3 FF 00 00 80 79 08 4B 81 CB 00 FF FF FF 43 03 BC 9D E4 FB FF FF 81 E7 FF 00 00 80 79 08 4F 81 CF 00 FF FF FF 47 0F B6 84 9D E4 FB FF FF 88 45 EB 8B 84 BD E4 FB FF FF 89 84 9D E4 FB FF FF 0F B6 45 EB 89 84 BD E4 FB FF FF 8B 84 9D E4 FB FF FF 03 84 BD E4 FB FF FF 25 FF 00 00 80 79 07 48 0D 00 FF FF FF 40 0F B6 84 85 E4 FB FF FF 8B 55 F0 30 04 32 46 FF 4D E4 75 84 8B 45 FC 85 C0 74 05 83 E8 04 8B 00 8B 55 EC 92 E8 ?? ?? ?? ?? 8B 5D FC 85 DB 74 05 83 EB 04 8B 1B 8B 45 EC E8 ?? ?? ?? ?? 8B 55 F0 8B CB E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 E0 FB FF FF E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? B9 02 00 00 00 E8 ?? ?? ?? ?? 8D 45 F8 BA 02 00 00 00 E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB CD 5F 5E 5B 8B E5 5D C3 }
    
    condition:
        $darkcomet_rc4 and not darkcomet51
    
}
/*
https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
*/

import "pe"

rule CS_default_exe_beacon_stager {
meta:
description = "Remote CS beacon execution as a service - spoolsv.exe"
author = "TheDFIRReport"
date = "2021-07-13"
hash1 = "f3dfe25f02838a45eba8a683807f7d5790ccc32186d470a5959096d009cc78a2"
strings:
$s1 = "windir" fullword ascii
$s2 = "rundll32.exe" fullword ascii
$s3 = "VirtualQuery failed for %d bytes at address %p" fullword ascii
$s4 = "msvcrt.dll" fullword wide
condition:
uint16(0) == 0x5a4d and filesize < 800KB and (pe.imphash() == "93f7b1a7b8b61bde6ac74d26f1f52e8d" and
3 of them ) or ( all of them )
}

rule tdr615_exe { 
meta: 
description = "Cobalt Strike on beachhead: tdr615.exe" 
author = "TheDFIRReport" 
reference = "https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/" 
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
import "pe"

rule CS_DLL {
meta:
description = "62.dll"
author = "TheDFIRReport"
reference = "https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/"
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
( pe.imphash() == "1b1b73382580c4be6fa24e8297e1849d" or ( 1 of ($x*) or 4 of them ) )
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

rule CS_encrypted_beacon_x86 {
meta:
author = "Etienne Maynier tek@randhome.io"
strings:
$s1 = { fc e8 ?? 00 00 00 }
$s2 = { 8b [1-3] 83 c? 04 [0-1] 8b [1-2] 31 }
condition:
$s1 at 0 and $s2 in (0..200) and filesize < 300000
}

rule CS_encrypted_beacon_x86_64 {
meta:
author = "Etienne Maynier tek@randhome.io"
strings:
$s1 = { fc 48 83 e4 f0 eb 33 5d 8b 45 00 48 83 c5 04 8b }
condition:
$s1 at 0 and filesize < 300000
}

rule CS_beacon {
meta:
author = "Etienne Maynier tek@randhome.io"

strings:
$s1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
$s2 = "%s as %s\\%s: %d" ascii
$s3 = "Started service %s on %s" ascii
$s4 = "beacon.dll" ascii
$s5 = "beacon.x64.dll" ascii
$s6 = "ReflectiveLoader" ascii
$s7 = { 2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f }
$s8 = { 69 68 69 68 69 6b ?? ?? 69 6b 69 68 }
$s9 = "%s (admin)" ascii
$s10 = "Updater.dll" ascii
$s11 = "LibTomMath" ascii
$s12 = "Content-Type: application/octet-stream" ascii

condition:
6 of them and filesize < 300000
}
/*
YARA Rule Set
Author: The DFIR Report
Date: 2022-04-24
Identifier: Quantum Case 12647
Reference: https://thedfirreport.com/2022/04/25/quantum-ransomware/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule docs_invoice_173 {
meta:
description = "IcedID - file docs_invoice_173.iso"
author = "The DFIR Report"
reference = "https://thedfirreport.com"
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
reference = "https://thedfirreport.com"
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
reference = "https://thedfirreport.com"
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
reference = "https://thedfirreport.com"
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
reference = "https://thedfirreport.com"
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
