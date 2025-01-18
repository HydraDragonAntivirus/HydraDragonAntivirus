rule shellshock_generic

{
meta:
author="Adam Burt"
strings:
$starter = "() { "
$alt1 = "(a)=>"
$alt2 = ":; } ;"
$att1 = "HOLD Flooding"
$att2 = "JUNK Flooding"
$att4 = "PONG!"
$att5 = "/bin/busybox"
$att6 = "SCANNER"
condition:
( $starter and any of ($alt*) ) or ( all of ($att*) )
}
rule BackOffPOS_1_56_LAST
{
meta:
	description = "BackoffPOS 1.56 LAST process injection code detection"
	in_the_wild = true

strings:
$a = {E8 00 00 00 00 5D 81 ED 05 00 00 00 31 C9 64 8B 71 30 8B 76 0C 8B 76 1C 8B 5E 08 8B 7E 20 8B 36 66 39 4F 18 75 F2 8D BD E3 05 00 00 89 FE B9 0E 00 00 00 AD E8 15 02 00 00 AB E2 F7 8D 85 D0 03 00 00 50 6A 00 6A 00 FF 95 EB 05 00 00 8D 85 99 03 00 00 50 FF 95 FF 05 00 00 85 C0 0F 84 D5 01 00 00 8D 9D A5 03 00 00 53 50 FF 95 FB 05 00 00 85 C0 0F 84 BF 01 00 00 89 85 DF 05 00 00 8D BD DD 03 00 00 6A 00 6A 1A 57 6A 00 FF 95 DF 05 00 00 89 FE E8 A7 01 00 00 01 C7 B9 09 00 00 00 8D B5 82 03 00 00 F3 A4 8D BD DC 04 00 00 6A 00 6A 1A 57 6A 00 FF 95 DF 05 00 00 89 FE E8 7E 01 00 00 01 C7 B9 0E 00 00 00 8D B5 8B 03 00 00 F3 A4 8D 85 72 03 00 00 50 6A 00 68 01 00 1F 00 FF 95 03 06 00 00 85 C0 74 14 50 FF 95 E3 05 00 00 68 E0 93 04 00 FF 95 0B 06 00 00 EB D4 8D 85 DD 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 50 FF 95 E7 05 00 00 83 F8 FF 0F 84 03 01 00 00 89 C3 6A 00 50 FF 95 F7 05 00 00 83 F8 FF 0F 84 E8 00 00 00 89 C7 6A 04 68 00 30 00 00 50 6A 00 FF 95 0F 06 00 00 85 C0 0F 84 CE 00 00 00 89 C6 8D 85 DB 05 00 00 6A 00 50 57 56 53 FF 95 07 06 00 00 85 C0 0F 84 B2 00 00 00 53 FF 95 E3 05 00 00 8D 85 6A 03 00 00 50 57 56 E8 28 01 00 00 8D 85 DC 04 00 00 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 50 FF 95 E7 05 00 00 83 F8 FF 74 29 89 C3 8D 85 DB 05 00 00 6A 00 50 57 56 53 FF 95 17 06 00 00 53 FF 95 E3 05 00 00 68 00 80 00 00 6A 00 56 FF 95 13 06 00 00 8D 85 99 03 00 00 50 FF 95 FF 05 00 00 8D 9D BD 03 00 00 53 50 FF 95 FB 05 00 00 8D 9D CB 03 00 00 8D BD DC 04 00 00 6A 00 6A 00 6A 00 57 53 6A 00 FF D0 68 E0 93 04 00 FF 95 0B 06 00 00 8D BD DC 04 00 00 57 FF 95 F3 05 00 00 E9 B0 FE FF FF 53 FF 95 E3 05 00 00 68 E0 93 04 00 FF 95 0B 06 00 00 E9 99 FE FF FF 6A 00 FF 95 EF 05 00 00 53 31 C0 8A 1C 06 84 DB 74 03 40 EB F6 5B C3 55 89 E5 83 EC 0C 60 89 5D FC 89 45 F8 03 5B 3C 8B 5B 78 03 5D FC 8B 7B 20 03 7D FC 31 F6 8D 14 B7 8B 12 03 55 FC 31 C0 C1 C0 07 32 02 42 80 3A 00 75 F5 3B 45 F8 74 06 46 3B 73 18 72 E0 8B 53 24 03 55 FC 0F B7 14 72 8B 43 1C 03 45 FC 8B 04 90 03 45 FC 89 45 F4 61 8B 45 F4 C9 C3 55 89 E5 57 56 53 81 EC 04 01 00 00 31 C0 88 84 28 F4 FE FF FF 40 3D 00 01 00 00 75 F1 8D 8D F4 FE FF FF 8D 7D F4 31 D2 31 DB 8A 01 88 85 F2 FE FF FF 8B 75 10 02 04 32 01 C3 0F B6 DB 8A 84 2B F4 FE FF FF 88 01 8A 85 F2 FE FF FF 88 84 2B F4 FE FF FF 8D 42 01 BE 08 00 00 00 99 F7 FE 41 39 F9 75 C7 31 C9 31 D2 31 C0 EB 42 42 81 E2 FF 00 00 00 0F B6 BC 2A F4 FE FF FF 01 F9 0F B6 C9 0F B6 B4 29 F4 FE FF FF 89 F3 88 9C 2A F4 FE FF FF 89 FB 88 9C 29 F4 FE FF FF 8D 1C 37 0F B6 DB 8A 9C 2B F4 FE FF FF 8B 75 08 30 1C 30 40 3B 45 0C 7C B9 81 C4 04 01 00 00 5B 5E 5F 5D C2 0C 00 }
$b = {50 61 73 73 77 6F 72 64 }
$c = {6E 73 6B 61 6C }
$d = {77 69 6E 73 65 72 76 73 2E 65 78 65 }
$e = {73 68 65 6C 6C 33 32 2E 64 6C 6C 00 53 48 47 65 74 53 70 65 63 69 61 6C 46 6F 6C 64 65 72 50 61 74 68 41 00 53 68 65 6C 6C 45 78 65 63 75 74 65 41 }

condition:

all of them

}

rule BackOffPOS_1_55_DEC
{
meta:
	description = "BackoffPOS 1.56 LAST process injection code detection"
	in_the_wild = true

strings:
$a = "dec"
$b = "1.55"
$d = "Update"
$e = "Terminate"
$f = "Upload KeyLogs"
$g = "[Enter]"

condition:

all of them

}

rule BackOffPOS_GENERIC
{
meta:
	description = "BackoffPOS generic catcher for known strings"
	in_the_wild = true

strings:
$a = "Update"
$b = "Terminate"
$d = "Uninstall"
$e = "Download"
$f = "Run"
$g = "Upload"
$h = "KeyLogs"
$i = "Password"
$j = "USERNAME"
$k = "[Enter]"
$l = "Log"

condition:

all of them

}
rule Dexter
{
meta:
	description = "Dexter malware memory injection detection"
	in_the_wild = true

strings:
$a = "Resilience"
$b = "download-"
$c = "update-"
$d = "checkin:"
$e = "uninstall"
$f = "CurrentVersion\\Run"
$g = "response="
$h = "gateway.php"
$i = "iexplore.exe"

condition:

all of them

}
import "pe"

rule metasploit_payload_msfpayload
{
	meta:
		description = "This rule detects generic metasploit callback payloads generated with msfpayload"
		Author = "Adam Burt (adam_burt@symantec.com)"
	strings:
		$a1 = "asf"
		$a2 = "release"
		$a3 = "build"
		$a4 = "support"
		$a5 = "ab.pdb"
		$l1 = "WS2_32.dll"
		$l2 = "mswsock"
		$l3 = "ntdll.dll"
		$l4 = "KERNEL32.dll"
		$l5 = "shell32"
		$l6 = "malloc"
		$l7 = "fopen"
		$l8 = "fclose"
		$l9 = "fprintf"
		$l10 = "strncpy"
	condition:
		all of ($l*)
		and all of ($a*)

}


rule metasploit_service_starter
{
	meta:
		description = "This rule detects related metasploit service starters"
		author = "Adam Burt (adam_burt@symantec.com)"
	strings:
		$a1 = "StartServiceCtrlDispatcher"
		$a2 = "RegisterServiceCtrlHandle"
		$a3 = "CloseHandle"
		$a4 = "memset"
		$a5 = "rundll32.exe"
		$a6 = "msvcrt.dll"
	condition:
		pe.sections[3].name == ".bss"
		and pe.sections[3].virtual_size == 0x00000030
		and pe.sections[2].virtual_size == 0x0000001c
		and pe.sections[4].virtual_size == 0x00000224
		and all of them
}
rule trojan_poweliks_dropper
{
meta:
author = "Adam Burt (adam_burt@symantec.com)"
md5hash = "181dbed16bce32a7cfc15ecdd6e31918"
sha1hash = "b00a9e4e12f799a1918358d175f571439fc4b45c"

strings:
$s1 = "NameOfMutexObject"
$c1 = {2F 2E 6D 2C}
$c2 = {76 AB 0B A7}


condition:
$c1 at 0x104a0 or ($s1 and $c2 at 0x104a8)
}
rule InceptionDLL
{
    meta:
		author = "Blue Coat Systems, Inc"
		info = "Used by unknown APT actors: Inception"
		reference = "https://www.bluecoat.com/documents/download/638d602b-70f4-4644-aaad-b80e1426aad4/d5c87163-e068-440f-b89e-e40b2f8d2088"

    strings:
		$a = "dll.polymorphed.dll"
		$b = {83 7d 08 00 0f 84 cf 00 00 00 83 7d 0c 00 0f 84 
c5 00 00 00 83 7d 10 00 0f 84 bb 00 00 00 83 7d 14 08 
0f 82 b1 00 00 00 c7 45 fc 00 00 00 00 8b 45 10 89 45 
dc 68 00 00}
		$c = {FF 15 ?? ?? ?? ?? 8B 4D 08 8B 11 C7 42 14 00 00 
00 00 8B 45 08 8B 08 8B 55 14 89 51 18 8B 45 08 8B 08 
8B 55 0C 89 51 1C 8B 45 08 8B 08 8B 55 10 89 51 20 8B 
45 08 8B 08}
		$d = {68 10 27 00 00 FF 15 ?? ?? ?? ?? 83 7D CC 0A 0F 
8D 47 01 00 00 83 7D D0 00 0F 85 3D 01 00 00 6A 20 6A 
00 8D 4D D4 51 E8 ?? ?? ?? ?? 83 C4 0C 8B 55 08 89 55 
E8 C7 45 D8}  
		$e = {55 8B EC 8B 45 08 8B 88 AC 23 03 00 51 8B 55 0C 
52 8B 45 0C 8B 48 04 FF D1 83 C4 08 8B 55 08 8B 82 14 
BB 03 00 50 8B 4D 0C 51 8B 55 0C 8B 42 04}

    condition:
		any of them
}

rule InceptionAndroid {
    meta:
		author = "Blue Coat Systems, Inc"
		info = "Used by unknown APT actors: Inception"
		reference = "https://www.bluecoat.com/documents/download/638d602b-70f4-4644-aaad-b80e1426aad4/d5c87163-e068-440f-b89e-e40b2f8d2088"

    strings:
		$a1 = "BLOGS AVAILABLE="
		$a2 = "blog-index"
		$a3 = "Cant create dex="
        
    condition:
		all of them
}

rule InceptionBlackberry {
    meta:
		author = "Blue Coat Systems, Inc"
		info = "Used by unknown APT actors: Inception"
		reference = "https://www.bluecoat.com/documents/download/638d602b-70f4-4644-aaad-b80e1426aad4/d5c87163-e068-440f-b89e-e40b2f8d2088"

    strings:
		$a1 = "POSTALCODE:"
		$a2 = "SecurityCategory:"
		$a3 = "amount of free flash:"
		$a4 = "$071|'1'|:"
		$b1 = "God_Save_The_Queen"
		$b2 = "UrlBlog"
        
    condition:
		all of ($a*) or all of ($b*)
}

rule InceptionIOS {
    meta:
		author = "Blue Coat Systems, Inc"
		info = "Used by unknown APT actors: Inception"
		reference = "https://www.bluecoat.com/documents/download/638d602b-70f4-4644-aaad-b80e1426aad4/d5c87163-e068-440f-b89e-e40b2f8d2088"

    strings:
		$a1 = "Developer/iOS/JohnClerk/"
		$b1 = "SkypeUpdate"
		$b2 = "/Syscat/"
		$b3 = "WhatsAppUpdate"

    condition:
		$a1 and any of ($b*)
}

rule InceptionMips {
    meta:
		author = "Blue Coat Systems, Inc"
		info = "Used by unknown APT actors: Inception"
		reference = "https://www.bluecoat.com/documents/download/638d602b-70f4-4644-aaad-b80e1426aad4/d5c87163-e068-440f-b89e-e40b2f8d2088"

    strings:
		$a = "start_sockat" ascii wide
		$b = "start_sockss" ascii wide
		$c = "13CStatusServer" ascii wide

    condition:
all of them
}

rule InceptionRTF {
    meta:
		author = "Blue Coat Systems, Inc"
		info = "Used by unknown APT actors: Inception"
		reference = "https://www.bluecoat.com/documents/download/638d602b-70f4-4644-aaad-b80e1426aad4/d5c87163-e068-440f-b89e-e40b2f8d2088"

    strings:
		$a = "))PT@T"
		$b = "XMLVERSION \"3.1.11.5604.5606"
		$c = "objclass Word.Document.12}\\objw9355"
    
    condition:
		all of them
}

rule InceptionVBS {

    meta:
		author = "Blue Coat Systems, Inc"
		info = "Used by unknown APT actors: Inception"
        reference = "https://www.bluecoat.com/documents/download/638d602b-70f4-4644-aaad-b80e1426aad4/d5c87163-e068-440f-b89e-e40b2f8d2088"

    
    strings:
		$a = "c = Crypt(c,k)"
		$b = "fso.BuildPath( WshShell.ExpandEnvironmentStrings(a), nn)"
        
    condition:
		all of them
}rule banswift :banswift {
meta:
description = "Yara rule to detect samples that share wiping function with banswift"
threat_level = 10
reference = "https://www.blueliv.com/research/recap-of-cyber-attacks-targeting-swift/"
strings:
$snippet1 = {88 44 24 0D B9 FF 03 00 00 33 C0 8D 7C 24 2D C6 44 24 2C 5F 33 DB F3 AB 66 AB 53 68 80 00 00 00 6A 03 53 AA 8B 84 24 40 10 00 00 53 68 00 00 00 40 50 C6 44 24 2A FF 88 5C 24 2B C6 44 24 2C 7E C6 44 24 2D E7}
/*
88 44 24 0D mov [esp+102Ch+var_101F], al
B9 FF 03 00 00 movecx, 3FFh
33 C0 xoreax, eax
8D 7C 24 2D lea edi, [esp+102Ch+var_FFF]
C6 44 24 2C 5F mov [esp+102Ch+var_1000], 5Fh
33 DB xorebx, ebx
F3 AB rep stosd
66 AB stosw
53 push ebx ; _DWORD
68 80 00 00 00 push 80h ; _DWORD
6A 03 push 3 ; _DWORD
53 push ebx ; _DWORD
AA stosb
8B 84 24 40 10 00 00 moveax, [esp+103Ch+arg_0]
53 push ebx ; _DWORD
68 00 00 00 40 push 40000000h ; _DWORD
50 push eax ; _DWORD
C6 44 24 2A FF mov [esp+1048h+var_101E], 0FFh
88 5C 24 2B mov [esp+1048h+var_101D], bl
C6 44 24 2C 7E mov [esp+1048h+var_101C], 7Eh
C6 44 24 2D E7 mov [esp+1048h+var_101B], 0E7h
*/
$snippet2 = {25 FF 00 00 00 B9 00 04 00 00 8A D0 8D 7C 24 30 8A F2 8B C2 C1 E0 10 66 8B C2 F3 AB}
/*
25 FF 00 00 00 and eax, 0FFh
B9 00 04 00 00 movecx, 400h
8A D0 mov dl, al
8D 7C 24 30 lea edi, [esp+30h]
8A F2 mov dh, dl
8B C2 moveax, edx
C1 E0 10 shleax, 10h
66 8B C2 mov ax, dx
F3 AB rep stosd
*/
condition:
all of ($snippet*)
}rule banswift0 :banswift0 {
meta:
description = "Yara rule to detect samples that share wiping function with banswift"
reference = "https://www.blueliv.com/research/recap-of-cyber-attacks-targeting-swift/"
threat_level = 10

strings:
$snippet1 = {88 44 24 0D B9 FF 03 00 00 33 C0 8D 7C 24 2D C6 44 24 2C 5F 33 DB F3 AB 66 AB 53 68 80 00 00 00 6A 03 53 AA 8B 84 24 40 10 00 00 53 68 00 00 00 40 50 C6 44 24 2A FF 88 5C 24 2B C6 44 24 2C 7E C6 44 24 2D E7}
$snippet2 = {25 FF 00 00 00 B9 00 04 00 00 8A D0 8D 7C 24 30 8A F2 8B C2 C1 E0 10 66 8B C2 F3 AB}
condition:
all of ($snippet*)
}
rule petya_eternalblue : petya_eternalblue {
    meta:
        author      = "blueliv"
        description =  "Based on spreading petya version: 2017-06-28"
        reference = "https://blueliv.com/petya-ransomware-cyber-attack-is-spreading-across-the-globe-part-2/"
    strings:
        /* Some commands executed by the Petya variant */
       $cmd01 = "schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%0" wide
       $cmd02 = "shutdown.exe /r /f" wide
       $cmd03 = "%s \\\\%s -accepteula -s" wide
       $cmd04 = "process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\%s\\\" #1" wide
       /* Strings of encrypted files */
       $str01 = "they have been encrypted. Perhaps you are busy looking" wide
        /* MBR/VBR payload */
        $mbr01 = {00 00 00 55 aa e9 ?? ??}
    condition:
        all of them
}
rule wannacry_static_ransom : wannacry_static_ransom {

meta:

description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$mutex01 = "Global\\MsWinZonesCacheCounterMutexA" ascii

$lang01 = "m_bulgarian.wnr" ascii

$lang02 = "m_vietnamese.wnry" ascii

$startarg01 = "StartTask" ascii

$startarg02 = "TaskStart" ascii

$startarg03 = "StartSchedule" ascii

$wcry01 = "WanaCrypt0r" ascii wide

$wcry02 = "WANACRY" ascii

$wcry03 = "WANNACRY" ascii

$wcry04 = "WNCRYT" ascii wide

$forig01 = ".wnry\x00" ascii

$fvar01 = ".wry\x00" ascii

condition:

($mutex01 or any of ($lang*)) and ( $forig01 or all of ($fvar*) ) and any of ($wcry*) and any of ($startarg*)

}

rule wannacry_memory_ransom : wannacry_memory_ransom {

meta:

description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants in memory"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$s01 = "%08X.eky"

$s02 = "%08X.pky"

$s03 = "%08X.res"

$s04 = "%08X.dky"

$s05 = "@WanaDecryptor@.exe"

condition:

all of them

}

rule worm_ms17_010 : worm_ms17_010 {

meta:

description = "Detects Worm used during 2017-May-12th WannaCry campaign, which is based on ETERNALBLUE"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$s01 = "__TREEID__PLACEHOLDER__" ascii

$s02 = "__USERID__PLACEHOLDER__@" ascii

$s03 = "SMB3"

$s05 = "SMBu"

$s06 = "SMBs"

$s07 = "SMBr"

$s08 = "%s -m security" ascii

$s09 = "%d.%d.%d.%d"

$payloadwin2000_2195 =

"\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00"

$payload2000_50 =

"\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00"

condition:

all of them

}
rule APT34_PDB_path
{
  meta:
    author = "Booz Allen Hamilton"
    reference = "https://www.boozallen.com/s/insight/blog/dark-labs-discovers-apt34-malware-variants.html"
    malware = "exerunner"
    actor = "APT34"
  strings:
    $exeruner_string_1 = "C:\\Users\\aaa\\documents\\visual studio 2015\\Projects\\exeruner\\exeruner\\obj\\Debug\\exeruner.pdb"
    $exeruner_string_2 = "C:\\Users\\aaa\\Desktop\\test\\exeruner\\exeruner\\obj\\Debug\\exeruner_new.pdb"

  condition:
    $exeruner_string_1 or $exeruner_string_2
}
rule DoublePulsarXor_Petya
{
 meta:
   description = "Rule to hit on the XORed DoublePulsar shellcode"
   author = "Patrick Jones"
   company = "Booz Allen Hamilton"
   reference1 ="https://www.boozallen.com/s/insight/publication/the-petya-ransomware-outbreak.html"
   reference2 = "https://www.boozallen.com/content/dam/boozallen_site/sig/pdf/white-paper/rollup-of-booz-allen-petya-research.pdf"
   date = "2017-06-28"
   hash = "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"
   hash = "64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1"
 strings:
   $DoublePulsarXor_Petya = { FD 0C 8C 5C B8 C4 24 C5 CC CC CC 0E E8 CC 24 6B CC CC CC 0F 24 CD CC CC CC 27 5C 97 75 BA CD CC CC C3 FE }
 condition:
   $DoublePulsarXor_Petya
}

rule DoublePulsarDllInjection_Petya
{
 meta:
  description = "Rule to hit on the XORed DoublePulsar DLL injection shellcode"
  author = "Patrick Jones"
  company = "Booz Allen Hamilton"
  reference1 ="https://www.boozallen.com/s/insight/publication/the-petya-ransomware-outbreak.html"
  reference2 = "https://www.boozallen.com/content/dam/boozallen_site/sig/pdf/white-paper/rollup-of-booz-allen-petya-research.pdf"
  date = "2017-06-28"
  hash = "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"
  hash = "64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1"
 strings:
   $DoublePulsarDllInjection_Petya = { 45 20 8D 93 8D 92 8D 91 8D 90 92 93 91 97 0F 9F 9E 9D 99 84 45 29 84 4D 20 CC CD CC CC 9B 84 45 03 84 45 14 84 45 49 CC 33 33 33 24 77 CC CC CC 84 45 49 C4 33 33 33 24 84 CD CC CC 84 45 49 DC 33 33 33 84 47 49 CC 33 33 33 84 47 41 }
 condition:
   $DoublePulsarDllInjection_Petya
} 
rule PolishBankRAT_srservice_xorloop {
meta:
	author = "Booz Allen Hamilton Dark Labs"
	description = "Finds the custom xor decode loop for <PolishBankRAT-srservice>"
    reference = "https://blog.cyber4sight.com/2017/02/technical-analysis-watering-hole-attacks-against-financial-institutions/"
strings:
	$loop = { 48 8B CD E8 60 FF FF FF 48 FF C3 32 44 1E FF 48 FF CF 88 43 FF }
condition:
	(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $loop
}

rule PolishBankRAT_fdsvc_xor_loop {
meta:
	author = "Booz Allen Hamilton Dark Labs"
	description = "Finds the custom xor decode loop for <PolishBankRAT-fdsvc>"
    reference = "https://blog.cyber4sight.com/2017/02/technical-analysis-watering-hole-attacks-against-financial-institutions/"
strings:
	$loop = {0F B6 42 FF 48 8D 52 FF 30 42 01 FF CF 75 F1}
condition:
	(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $loop
}

rule PolishBankRAT_fdsvc_decode2 {
meta:
	author = "Booz Allen Hamilton Dark Labs"
	description = "Find a constant used as part of a payload decoding function in PolishBankRAT-fdsvc"
    reference = "https://blog.cyber4sight.com/2017/02/technical-analysis-watering-hole-attacks-against-financial-institutions/"
strings:
	$part1 = {A6 EB 96}
	$part2 = {61 B2 E2 EF}
	$part3 = {0D CB E8 C4}
	$part4 = {5A F1 66 9C}
	$part5 = {A4 80 CD 9A}
	$part6 = {F1 2F 46 25}
	$part7 = {2F DB 16 26}
	$part8 = {4B C4 3F 3C}
	$str1 = "This program cannot be run in DOS mode"
condition:
	(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule decoded_PolishBankRAT_fdsvc_strings {
meta:
	author = "Booz Allen Hamilton Dark Labs"
	description = "Finds hard coded strings in PolishBankRAT-fdsvc"
    reference = "https://blog.cyber4sight.com/2017/02/technical-analysis-watering-hole-attacks-against-financial-institutions/"
strings:
	$str1 = "ssylka" wide ascii
	$str2 = "ustanavlivat" wide ascii
	$str3 = "poluchit" wide ascii
	$str4 = "pereslat" wide ascii
	$str5 = "derzhat" wide ascii
	$str6 = "vykhodit" wide ascii
	$str7 = "Nachalo" wide ascii
condition:
	(uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and 4 of ($str*)
}rule chinapic_zip

{

    meta:
        description = "Find zip archives of pony panels that have china.jpg"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "china.jpg"
        $txt2 = "config.php"
        $txt3 = "setup.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}
rule PotentiallyCompromisedCert

{
    meta:
        description = "Search for PE files using cert issued to DEMUZA "
        author = "Brian Carter"
        last_modified = "July 21, 2017"
        sample = "7ef8f5e0ca92a0f3a5bd8cdc52236564"
        TLP = "WHITE"

    strings:
        $magic = { 50 4b 03 04 (14 | 0a) 00 }

        $txt1 = "demuza@yandex.ru" nocase
        $txt2 = "https://secure.comodo.net/CPS0C" nocase
        $txt3 = "COMODO CA Limited1"

    condition:
       $magic at 0 and all of ($txt*)
}
rule INJECTOR_PANEL_SQLITE

{
    meta:
        description = "Find sqlite dbs used with tables inject panel"
        author = "Brian Carter"
        last_modified = "August 14, 2017"

    strings:
        $magic = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 }
        $txt1 = "CREATE TABLE Settings"
        $txt2 = "CREATE TABLE Jabber"
        $txt3 = "CREATE TABLE Users"
        $txt4 = "CREATE TABLE Log"
        $txt5 = "CREATE TABLE Fakes"
        $txt6 = "CREATE TABLE ATS_links"

    condition:
        $magic at 0 and all of ($txt*)

}
rule DROPPER_9002 : APT8

{
    meta:
        description = "Strings associated with 9002_DROPPER APT8"
        description = "Used for retrohunt.  Don't expect to see new samples."
        author = "Brian Carter"
        last_modified = "September 22 2015"

    strings:
        $magic = { 50 4b 03 04 (14 | 0a) 00 }

        $txt1 = "PhotoShow.class"
        $txt2 = "update.rar"
        $txt3 = "META-INF/MANIFEST.MF"
        $txt4 = "Desert.jpg"
        $txt5 = "Hydrangeas.jpg"

    condition:
       $magic at 0 and all of ($txt*)
}
rule PDF_EMBEDDED_DOCM

{
    meta:
        description = "Find pdf files that have an embedded docm with openaction"
        author = "Brian Carter"
        last_modified = "May 11, 2017"

    strings:
        $magic = { 25 50 44 46 2d }

        $txt1 = "EmbeddedFile"
        $txt2 = "docm)"
        $txt3 = "JavaScript" nocase

    condition:
        $magic at 0 and all of ($txt*)

}
rule diamondfox_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "gate.php"
        $txt2 = "install.php"
        $txt3 = "post.php"
        $txt4 = "plugins"
        $txt5 = "statistics.php"
        $magic = { 50 4b 03 04 }
        $not1 = "joomla" nocase
        
    condition:
        $magic at 0 and all of ($txt*) and not any of ($not*)
        
}

rule keybase_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "clipboard.php"
        $txt2 = "config.php"
        $txt3 = "create.php"
        $txt4 = "login.php"
        $txt5 = "screenshots.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule zeus_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "April 19, 2017"
        
    strings:
        $txt1 = "cp.php"
        $txt2 = "gate.php"
        $txt3 = "botnet_bots.php"
        $txt4 = "botnet_scripts.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule atmos_zip

{

    meta:
        description = "Find zip archives of panels"
        author = "Brian Carter"
        last_modified = "April 27, 2017"
        
    strings:
        $txt1 = "cp.php"
        $txt2 = "gate.php"
        $txt3 = "api.php"
        $txt4 = "file.php"
        $txt5 = "ts.php"
        $txt6 = "index.php"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}

rule new_pony_panel

{

    meta:
        description = "New Pony Zips"
        
    strings:
        $txt1 = "includes/design/images/"
        $txt2 = "includes/design/style.css"
        $txt3 = "admin.php"
        $txt4 = "includes/design/images/user.png"
        $txt5 = "includes/design/images/main_bg.gif"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}
rule config_php

{
    meta:
        description = "Find config.php files that have details for the db"
        author = "Brian Carter"
        last_modified = "March 31, 2017"
        
    strings:
        $txt1 = "$mysql_host ="
        $txt2 = "$mysql_user ="
        $txt3 = "mysql_pass ="
        $txt4 = "mysql_database ="
        $txt5 = "global_filter_list"
        $txt6 = "white-list"
        $php1 = "<?php"
        
    condition:
        $php1 at 0 and all of ($txt*)
        
}
rule tables_inject

{

    meta:
        description = "Find zip archives of tables inject panel"
        author = "Brian Carter"
        last_modified = "August 14, 2017"
        
    strings:
        $txt1 = "tinymce"
        $txt2 = "cunion.js"
        $txt3 = "tables.php"
        $txt4 = "sounds/1.mp3"
        $txt5 = "storage/db.sqlite"
        $magic = { 50 4b 03 04 }
        
    condition:
        $magic at 0 and all of ($txt*)
        
}rule BabukRansomware {
	meta:
	  	description = "YARA rule for Babuk Ransomware"
		reference = "http://chuongdong.com/reverse%20engineering/2021/01/03/BabukRansomware/"
		author = "@cPeterr"
		date = "2021-01-03"
		rule_version = "v1"
		malware_type = "ransomware"
		tlp = "white"
	strings:
		$lanstr1 = "-lanfirst"
		$lanstr2 = "-lansecond"
		$lanstr3 = "-nolan"
		$str1 = "BABUK LOCKER"
		$str2 = ".__NIST_K571__" wide
		$str3 = "How To Restore Your Files.txt" wide
		$str4 = "ecdh_pub_k.bin" wide
	condition:
		all of ($str*) and all of ($lanstr*)
}
rule BabukRansomwareV3 {
    meta:
        description = "YARA rule for Babuk Ransomware v3"
        reference = "http://chuongdong.com/reverse%20engineering/2021/01/16/BabukRansomware-v3/"
        author = "@cPeterr"
        date = "2021-01-16"
        rule_version = "v3"
        malware_type = "ransomware"
        tlp = "white"
    strings:
        $lanstr1 = "-lanfirst"
        $lanstr2 = "-nolan"
        $lanstr3 = "shares"
        $str1 = "BABUK LOCKER"
        $str2 = "babukq4e2p4wu4iq.onion"
        $str3 = "How To Restore Your Files.txt" wide
        $str4 = "babuk_v3"
        $str5 = ".babyk" wide
    condition:
        all of ($str*) and all of ($lanstr*)
}
rule ContiV2 {
	meta:
	  	description = "YARA rule for Conti Ransomware v2"
		reference = "http://chuongdong.com/reverse%20engineering/2020/12/15/ContiRansomware/"
		author = "@cPeterr"
    		date = "2020-12-15"
    		rule_version = "v2"
    		malware_type = "ransomware"
    		malware_family = "Ransom:W32/Conti"
		tlp = "white"
	strings:
		$str1 = "polzarutu1982@protonmail.com"
		$str2 = "http://m232fdxbfmbrcehbrj5iayknxnggf6niqfj6x4iedrgtab4qupzjlaid.onion"
    		$str3 = "expand 32-byte k"
		$string_decryption = { 8a 07 8d 7f 01 0f b6 c0 b9 ?? 00 00 00 2b c8 6b c1 ?? 99 f7 fe 8d 42 7f 99 f7 fe 88 57 ff }
    		$compare_size = { ?? ?? 00 00 50 00 }
	condition:
		all of ($str*) and $string_decryption and $compare_size
}
rule DarksideRansomware1_8_6_2 {
  meta:
    description = "YARA rule for Darkside v1.8.6.2"
    reference = "http://chuongdong.com/reverse%20engineering/2021/05/06/DarksideRansomware/"
    author = "@cPeterr"
    tlp = "white"
  strings:
    $hash_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    $gen_key_buff = {89 54 0E 0C 89 44 0E 08 89 5C 0E 04 89 3C 0E 81 EA 10 10 10 10 2D 10 10 10 10 81 EB  10 10 10 10 81 EF 10 10 10 10 83 E9 10 79 D5}
    $dyn_api_resolve = {FF 76 FC 56 E8 91 FE FF FF 56 E8 ?? 69 00 00 8B D8 FF 76 FC 56 E8 85 FB FF FF 8B 46 FC 8D 34 06 B9 23 00 00 00 E8 5E 02 00 00 AD}
    $get_config_len = {81 3C 18 DE AD BE EF 75 02 EB 03 40 EB F2}
    $RSA_1024_add_big_num = {8B 06 8B 5E 04 8B 4E  08 8B 56 0C 11 07 11 5F 04 11 4F 08 11 57 0C}
    $CRC32_checksum = {FF 75 0C FF 75 08 68 EF BE AD DE FF 15 ?? ?? ?? 00 FF 75 0C FF 75 08 50 FF 15 ?? ?? ?? 00 31 07 FF 75 0C FF 75 08 50 FF 15 ?? ?? ?? 00 }
  condition:
    all of them
}
rule MountLocker5_0 {
	meta:
		description = "YARA rule for MountLocker v5.0"
		reference = "http://chuongdong.com/reverse%20engineering/2021/05/23/MountLockerRansomware/"
		author = "@cPeterr"
		tlp = "white"
	strings:
		$worm_str = "========== WORM ==========" wide
		$ransom_note_str = ".ReadManual.%0.8X" wide
		$version_str = "5.0" wide
		$chacha_str = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>"
		$chacha_const = "expand 32-byte k"
		$lock_str = "[OK] locker.file > time=%0.3f size=%0.3f KB speed=%" wide
		$bat_str = "attrib -s -r -h %1"
		$IDirectorySearch_RIID = { EC A8 9B 10 F0 92 D0 11 A7 90 00 C0 4F D8 D5 A8 }
	condition:
		uint16(0) == 0x5a4d and all of them
}
rule regretlocker {
	meta:
		description = "YARA rule for RegretLocker"
		reference = "http://chuongdong.com/reverse%20engineering/2020/11/17/RegretLocker/"
		author = "@cPeterr"
		tlp = "white"
	strings:
		$str1 = "tor-lib.dll"
		$str2 = "http://regretzjibibtcgb.onion/input"
		$str3 = ".mouse"
		$cmd1 = "taskkill /F /IM \\"
		$cmd2 = "wmic SHADOWCOPY DELETE"
		$cmd3 = "wbadmin DELETE SYSTEMSTATEBACKUP"
		$cmd4 = "bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures"
		$cmd5 = "bcdedit.exe / set{ default } recoveryenabled No"
		$func1 = "open_virtual_drive()"
		$func2 = "smb_scanner()"
		$checklarge = { 81 fe 00 00 40 06 }
	condition:
		all of ($str*) and any of ($cmd*) and any of ($func*) and $checklarge
}
import "pe"

rule apt_RU_turla_comlook
{
	meta:
		date="20/01/22"
		Author = "ClearSky Cybersecurity"
		TLP = "WHITE"
	
	strings:

		$a1 = "\x00Server switched.\x00" 
		$a2 = "\x00Message handling error!\x00" 
		$a3 = "\x00Incorrect username in IMAP request.\x00"
		$a4 = "\x00Incorrect password in IMAP request.\x00"
		$a5 = "atexit failed to register curl_global_cleanup.\x00"
		$a6 = "curl FetchMessagePart failed."
		$a7 = "curl PerformQuery failed."
		$a8 = "curl SendResult failed."
		$a9 = "Cannot copy data for sending buffer."
		$a10 = "Initialization of libcurl has failed."
		$a11 = "COULDN'T OPEN PIPES TO RECEIVE EXECUTION RESULT\x00"
		$a12 = "OPERATION PERFORMED SUCCESSFULLY WITHOUT WAITING FOR RESULT\x00"
		$a13 = "OPERATION PERFORMED SUCCESSFULLY WITH NULL RESULT.\x00"
		$a14 = "COMMAND IS EMPTY.\x00"
		$a15 = "Antispam Marisuite for The Bat!"
		$a16 = "\x00CMD_EXECUTION_PIPE_OPEN_ERROR\x00"
		$a17 = "\x00CONFIG_LAST_COMMAND_DATE_REG_WRITE_ERROR\x00"
		$a18 = "\x00IMAP_MAILSERVER_FORMAT_INCORRECT\x00"
		$a19 = "\x00GET_UIDS_TO_CHECK_PARSING_ERROR\x00"
		
		$b1 = "\x00SEARCH UID \x00"
		$b2 = "\x00 +FLAGS \\Deleted\x00"
		$b3 = "\x00UID SEARCH SENTSINCE \x00"
		$b4 = "Software\\RIT\\The Bat!\x00" wide 

	condition:
		filesize < 10MB and uint16(0) == 0x5A4D and
		(
			pe.imphash() == "ee4ac9f3c15a225a117392a01b78686e" or
			2 of ($a*) or
			3 of ($b*) or
			(
				pe.imports("TBP_Intialize") and
				any of ($a*)
			)
		)
}
 rule gholee

    {

    meta:

    author = "www.clearskysec.com"

    date = "2014/08"

    maltype = "Remote Access Trojan"

    filetype = "dll"

    reference = "http://www.clearskysec.com/gholee-a-protective-edge-themed-spear-phishing-campaign/"


    strings:

    $a = "sandbox_avg10_vc9_SP1_2011"

    $b = "gholee"

    condition:

    all of them

    }import "pe"


rule apt_c16_win_memory_pcclient : Memory APT 
{
  meta:
    author = "@dragonthreatlab"
    md5 = "ec532bbe9d0882d403473102e9724557"
    description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
    date        = "2015/01/11" 
    reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
  strings:
    $str1 = "Kill You" ascii
    $str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
    $str3 = "%4.2f  KB" ascii
    $encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}  
  condition:
    all of them
}

rule apt_c16_win_disk_pcclient : Disk
{
  meta:
    author = "@dragonthreatlab"
    md5 = "55f84d88d84c221437cd23cdbc541d2e"
    description = "Encoded version of pcclient found on disk"
    date        = "2015/01/11" 
    reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
  strings:
    $header = {51 5C 96 06 03 06 06 06 0A 06 06 06 FF FF 06 06 BE 06 06 06 06 06 06 06 46 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 EE 06 06 06 10 1F BC 10 06 BA 0D D1 25 BE 05 52 D1 25 5A 6E 6D 73 26 76 74 6F 67 74 65 71 26 63 65 70 70 6F 7A 26 64 69 26 74 79 70 26 6D 70 26 4A 4F 53 26 71 6F 6A 69 30 11 11 0C 2A 06 06 06 06 06 06 06 73 43 96 1B 37 24 00 4E 37 24 00 4E 37 24 00 4E BA 40 F6 4E 39 24 00 4E 5E 41 FA 4E 33 24 00 4E 5E 41 FC 4E 39 24 00 4E 37 24 FF 4E 0D 24 00 4E FA 31 A3 4E 40 24 00 4E DF 41 F9 4E 36 24 00 4E F6 2A FE 4E 38 24 00 4E DF 41 FC 4E 38 24 00 4E 54 6D 63 6E 37 24 00 4E 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 56 49 06 06 52 05 09 06 5D 87 8C 5A 06 06 06 06 06 06 06 06 E6 06 10 25 0B 05 08 06 06 1C 06 06 06 1A 06 06 06 06 06 06 E5 27 06 06 06 16 06 06 06 36 06 06 06 06 06 16 06 16 06 06 06 04 06 06 0A 06 06 06 06 06 06 06 0A 06 06 06 06 06 06 06 06 76 06 06 06 0A 06 06 06 06 06 06 04 06 06 06 06 06 16 06 06 16 06 06}
  condition:
    $header at 0
}

rule apt_c16_win32_dropper : Dropper
{
  meta:
    author = "@dragonthreatlab"
    md5 = "ad17eff26994df824be36db246c8fb6a"
    description = "APT malware used to drop PcClient RAT"
    date        = "2015/01/11" 
    reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
  strings:
    $mz = {4D 5A}
    $str1 = "clbcaiq.dll" ascii
    $str2 = "profapi_104" ascii
    $str3 = "/ShowWU" ascii
    $str4 = "Software\\Microsoft\\Windows\\CurrentVersion\\" ascii
    $str5 = {8A 08 2A CA 32 CA 88 08 40 4E 75 F4 5E}
  condition:
    $mz at 0 and all of ($str*)
}

rule apt_c16_win_swisyn : Memory
{
  meta:
    author = "@dragonthreatlab"
    md5 = "a6a18c846e5179259eba9de238f67e41"
    description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
    date        = "2015/01/11" 
    reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
  strings:
    $mz = {4D 5A}
    $str1 = "/ShowWU" ascii
    $str2 = "IsWow64Process"
    $str3 = "regsvr32 "
    $str4 = {8A 11 2A 55 FC 8B 45 08 88 10 8B 4D 08 8A 11 32 55 FC 8B 45 08 88 10}
  condition:
    $mz at 0 and all of ($str*)
}

rule apt_c16_win_wateringhole 
{
  meta:
    author = "@dragonthreatlab"
    description = "Detects code from APT wateringhole"
    date        = "2015/01/11" 
    reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
  strings:
    $str1 = "function runmumaa()"
    $str2 = "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String("
    $str3 = "function MoSaklgEs7(k)"
  condition:
    any of ($str*)
}

rule apt_c16_win64_dropper : Dropper
{
    meta:
        author      = "@dragonthreatlab"
        date        = "2015/01/11" 
        description = "APT malware used to drop PcClient RAT"
        reference   = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

    strings:
        $mz = { 4D 5A }
        $str1 = "clbcaiq.dll" ascii
        $str2 = "profapi_104" ascii
        $str3 = "\\Microsoft\\wuauclt\\wuauclt.dat" ascii
        $str4 = { 0F B6 0A 48 FF C2 80 E9 03 80 F1 03 49 FF C8 88 4A FF 75 EC }

    condition:
        $mz at 0 and all of ($str*)
}import "pe"

rule Contains_ah_encoded_PE_file
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect an &H encoded executable"
		method = "&Hxx is the hexadecimal notation for a byte in VBA"
		reference = "https://blog.didierstevens.com/2014/12/23/oledump-extracting-embedded-exe-from-doc/"
		hash = "6a574342b3e4e44ae624f7606bd60efa"
		date = "2016-04-23"

	strings:
		$MZ = "&H4d&H5a" nocase // DOS header signature in e_magic
		$DOS = "&H21&H54&H68&H69&H73&H20&H70&H72&H6f&H67&H72&H61&H6d&H20&H63&H61&H6e&H6e&H6f&H74&H20&H62&H65&H20&H72&H75&H6e&H20&H69&H6e&H20&H44&H4f&H53&H20&H6d&H6f&H64&H65&H2e" nocase // !This program cannot be run in DOS mode. (DOS stub)
		$PE = "&H50&H45&H00&H00" nocase // PE signature at start of PE header (NtHeader)

	condition:
		$MZ and $DOS and $PE
}

rule Contains_ASCII_Hex_encoded_PE_file
{
    meta:
        author = "Martin Willing (https://evild3ad.com)"
        description = "Detect an ASCII Hex encoded executable"
		reference = "https://blogs.mcafee.com/mcafee-labs/w97m-downloader-serving-vawtrak/"
		hash = "e56a57acf528b8cd340ae039519d5150"
		date = "2016-03-28"
		
    strings:
		$MZ = "4D5A" nocase // DOS header signature in e_magic
		$DOS = "21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6f64652E" nocase // !This program cannot be run in DOS mode. (DOS stub)
		$PE = "50450000" nocase // PE signature at start of PE header (NtHeader)
		
    condition:
		$MZ and $DOS and $PE

}

rule Contains_hidden_PE_File_inside_a_sequence_of_numbers
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect a hidden PE file inside a sequence of numbers (comma separated)"
		reference = "http://blog.didierstevens.com/2016/01/07/blackenergy-xls-dropper/"
		reference = "http://www.welivesecurity.com/2016/01/04/blackenergy-trojan-strikes-again-attacks-ukrainian-electric-power-industry/"
		date = "2016-01-09"
		filetype = "decompressed VBA macro code"
		
	strings:
		$a = "= Array(" // Array of bytes
		$b = "77, 90," // MZ
		$c = "33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46," // !This program cannot be run in DOS mode.
	
	condition:
	 	all of them
}

rule Contains_UserForm_Object_1
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect UserForm object in MS Office document. Attackers use UserForm objects to obfuscate their scripts and malicious code."
		alert = "May used to store a URL as a property of a userform"
		reference = "https://isc.sans.edu/forums/diary/Tip+Quick+Analysis+of+Office+Maldoc/20751/"
		reference = "http://blog.didierstevens.com/2016/03/11/update-oledump-py-version-0-0-23/"
		hash = "4e0c55054c4f7c32aece5cfbbea02846"
		date = "2016-03-11"
		filetype = "Office documents"
		
	strings:
		
		$a = "Microsoft Forms 2.0" // Forms
		$b = "http"
	
	condition:
	 	all of them
}

rule Contains_UserForm_Object_2
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect UserForm object in MS Office document. Attackers use UserForm objects to obfuscate their scripts and malicious code."
		alert = "May used to store malicious code in a UserForm object embedded in a form object"
		reference = "https://msdn.microsoft.com/en-us/library/office/gg264663.aspx"
		hash = "3c013125ffe34b81e39f92b59ca26b6c"
		date = "2016-03-11"
		filetype = "Office documents"
		
	strings:
		
		$a = "Microsoft Forms 2.0" // Forms
		$b = "UserForm1" // UserForm
	
	condition:
	 	all of them
}

rule Contains_UserForm_Object_3
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect UserForm object in MS Office document. Attackers use UserForm objects to obfuscate their scripts and malicious code."
		alert = "May used to store malicious code in a TextBox1 object embedded in a form object"
		reference = "https://blogs.mcafee.com/mcafee-labs/macro-malware-associated-dridex-finds-new-ways-hide/"
		hash = "13d4e6f0f7dc15ba17df91954de0b01d"
		date = "2016-03-11"
		filetype = "Office documents"
		
	strings:
		
		$a = "Microsoft Forms 2.0" // Forms
		$b = "UserForm1" // UserForm
		$c = "TextBox1" // Control
	
	condition:
	 	all of them
}
rule Contains_VBA_macro_code
{
	meta:
		author = "evild3ad"
		description = "Detect a MS Office document with embedded VBA macro code"
		date = "2016-01-09"
		filetype = "Office documents"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"

		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F } // Attribute VB_

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"

	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}
rule MIME_MSO_ActiveMime_base64
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect MIME MSO Base64 encoded ActiveMime file"
		date = "2016-02-28"
		filetype = "Office documents"
		
	strings:
		$mime = "MIME-Version:"
		$base64 = "Content-Transfer-Encoding: base64"
		$mso = "Content-Type: application/x-mso"
		//$activemime = /Q(\x0D\x0A|)W(\x0D\x0A|)N(\x0D\x0A|)0(\x0D\x0A|)a(\x0D\x0A|)X(\x0D\x0A|)Z(\x0D\x0A|)l(\x0D\x0A|)T(\x0D\x0A|)W/
	
	condition:
		$mime at 0 and $base64 and $mso //and $activemime
}

rule cve_2014_6352

{
meta:
  author = "Forcepoint"
  reference = "https://blogs.forcepoint.com/security-labs/ebola-spreads-cyber-attacks-too"
strings:

        $rootentry = {52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 16 00 05 00 ff ff ff ff ff ff ff ff 01 00 00 00}

        $ole10native = {4F 00 ( 4C | 6C ) 00 ( 45 | 65 ) 00 31 00 30 00 4E 00 61 00 74 00 69 00 76 00 65 00 00}

        $c = "This program cannot be run in DOS mode"

condition:

     ($rootentry or $ole10native) and $c

}
rule ws_f0xy_downloader {
  meta:
    description = "f0xy malware downloader"
    author = "Nick Griffin (Websense)"
    reference = "https://blogs.forcepoint.com/security-labs/new-f0xy-malware-intelligent-employs-cunning-stealth-trickery"

  strings:
    $mz="MZ"
    $string1="bitsadmin /transfer"
    $string2="del rm.bat"
    $string3="av_list="
  
  condition:
    ($mz at 0) and (all of ($string*))
}
rule crime_win_zbot_memory_dev_ws
{
    meta:
        description = "ZBot & variants - configuration _unpack routine detection"
        author = "Nick Griffin (Websense)"
        yaraexchange = "No distribution without author's consent"
        reference = "https://blogs.forcepoint.com/security-labs/crimeware-based-targeted-attacks-citadel-case-part-iii"
        date = "2014-04"
        filetype = "memory"
        md5 = "4d175203db0f269f9d86d2677ac859cf"
        sha1 = "4b422b48be4beaa44557c452f0920aa1ee0b16cb"
     
    strings:
        $hex_string = {85 C0 7? ?? 8A 4C 30 FF 30 0C 30 48 7?}
        $bkrebs = "Coded by BRIAN KREBS for personal use only. I love my job & wife."
     
    condition:
        $hex_string or $bkrebs
} 
rule Ponmocup : plugins
{
              meta:
                            description = "Ponmocup plugin detection (memory)"
                            author = "Danny Heppener, Fox-IT"
              strings:
                            $1100 = {4D 5A 90 [29] 4C 04}
                            $1201 = {4D 5A 90 [29] B1 04}
                            $1300 = {4D 5A 90 [29] 14 05}
                            $1350 = {4D 5A 90 [29] 46 05}
                            $1400 = {4D 5A 90 [29] 78 05}
                            $1402 = {4D 5A 90 [29] 7A 05}
                            $1403 = {4D 5A 90 [29] 7B 05}
                            $1404 = {4D 5A 90 [29] 7C 05}
                            $1405 = {4D 5A 90 [29] 7D 05}
                            $1406 = {4D 5A 90 [29] 7E 05}
                            $1500 = {4D 5A 90 [29] DC 05}
                            $1501 = {4D 5A 90 [29] DD 05}
                            $1502 = {4D 5A 90 [29] DE 05}
                            $1505 = {4D 5A 90 [29] E1 05}
                            $1506 = {4D 5A 90 [29] E2 05}
                            $1507 = {4D 5A 90 [29] E3 05}
                            $1508 = {4D 5A 90 [29] E4 05}
                            $1509 = {4D 5A 90 [29] E5 05}
                            $1510 = {4D 5A 90 [29] E6 05}
                            $1511 = {4D 5A 90 [29] E7 05}
                            $1512 = {4D 5A 90 [29] E8 05}
                            $1600 = {4D 5A 90 [29] 40 06}
                            $1601 = {4D 5A 90 [29] 41 06}
                            $1700 = {4D 5A 90 [29] A4 06}
                            $1800 = {4D 5A 90 [29] 08 07}
                            $1801 = {4D 5A 90 [29] 09 07}
                            $1802 = {4D 5A 90 [29] 0A 07}
                            $1803 = {4D 5A 90 [29] 0B 07}
                            $2001 = {4D 5A 90 [29] D1 07}
                            $2002 = {4D 5A 90 [29] D2 07}
                            $2003 = {4D 5A 90 [29] D3 07}
                            $2004 = {4D 5A 90 [29] D4 07}
                            $2500 = {4D 5A 90 [29] C4 09}
                            $2501 = {4D 5A 90 [29] C5 09}
                            $2550 = {4D 5A 90 [29] F6 09}
                            $2600 = {4D 5A 90 [29] 28 0A}
                            $2610 = {4D 5A 90 [29] 32 0A}
                            $2700 = {4D 5A 90 [29] 8C 0A}
                            $2701 = {4D 5A 90 [29] 8D 0A}
                            $2750 = {4D 5A 90 [29] BE 0A}
                            $2760 = {4D 5A 90 [29] C8 0A}
                            $2810 = {4D 5A 90 [29] FA 0A}

              condition:
                            any of them
}rule shimrat
{
 meta:
  description = "Detects ShimRat and the ShimRat loader"
  author = "Yonathan Klijnsma (yonathan.klijnsma@fox-it.com)"
  date = "20/11/2015"
  
 strings:
  $dll = ".dll"
  $dat = ".dat"
  $headersig = "QWERTYUIOPLKJHG"
  $datasig = "MNBVCXZLKJHGFDS"
  $datamarker1 = "Data$$00"
  $datamarker2 = "Data$$01%c%sData"
  $cmdlineformat = "ping localhost -n 9 /c %s > nul"
  $demoproject_keyword1 = "Demo"
  $demoproject_keyword2 = "Win32App"
  $comspec = "COMSPEC"
  $shim_func1 = "ShimMain"
  $shim_func2 = "NotifyShims"
  $shim_func3 = "GetHookAPIs"


 condition:
  ($dll and $dat and $headersig and $datasig) or ($datamarker1 and $datamarker2) or ($cmdlineformat and $demoproject_keyword1 and $demoproject_keyword2 and $comspec) or ($dll and $dat and $shim_func1 and $shim_func2 and $shim_func3)
}rule shimratreporter
{
 meta:
  description = "Detects ShimRatReporter"
  author = "Yonathan Klijnsma (yonathan.klijnsma@fox-it.com)"
  date = "20/11/2015"

 strings:
  $IpInfo = "IP-INFO"
  $NetworkInfo = "Network-INFO"
  $OsInfo = "OS-INFO"
  $ProcessInfo = "Process-INFO"
  $BrowserInfo = "Browser-INFO"
  $QueryUserInfo = "QueryUser-INFO"
  $UsersInfo = "Users-INFO"
  $SoftwareInfo = "Software-INFO"
  $AddressFormat = "%02X-%02X-%02X-%02X-%02X-%02X"
  $proxy_str = "(from environment) = %s"

  $netuserfun = "NetUserEnum"
  $networkparams = "GetNetworkParams"

 condition:
  all of them
}import "pe"

rule albaniiutas_dropper_exe
{
  meta:
    author = "Dmitry Kupin"
    company = "Group-IB"
    family = "albaniiutas.dropper"
    description = "Suspected Albaniiutas dropper"
    reference = "https://blog.group-ib.com/task"
    sample = "2a3c8dabdee7393094d72ce26ccbce34bff924a1be801f745d184a33119eeda4" // csrss.exe dropped from 83b619f65...
    sample = "71750c58eee35107db1a8e4d583f3b1a918dbffbd42a6c870b100a98fd0342e0" // csrss.exe dropped from 690bf6b83...
    sample = "83b619f65d49afbb76c849c3f5315dbcb4d2c7f4ddf89ac93c26977e85105f32" // dropper_stage_0 with decoy
    sample = "690bf6b83cecbf0ac5c5f4939a9283f194b1a8815a62531a000f3020fee2ec42" // dropper_stage_0 with decoy
    severity = 9
    date = "2021-07-06"

  strings:
    $eventname = /[0-9A-F]{8}-[0-9A-F]{4}-4551-8F84-08E738AEC[0-9A-F]{3}/ fullword ascii wide
    $rc4_key = { 00 4C 21 51 40 57 23 45 24 52 25 54 5E 59 26 55 2A 41 7C 7D 74 7E 6B 00 } // L!Q@W#E$R%T^Y&U*A|}t~k
    $aes256_str_seed = { 00 65 34 65 35 32 37 36 63 30 30 30 30 31 66 66 35 00 } // e4e5276c00001ff5
    $s0 = "Release Entery Error" fullword ascii
    $s1 = "FileVJCr error" fullword ascii
    $s2 = "wchWSMhostr error" fullword ascii
    $s3 = "zlib err0r" fullword ascii
    $s4 = "De err0r" fullword ascii
    $s5 = "CreateFileW_CH error!" fullword ascii
    $s6 = "GetConfigOffset error!" fullword ascii

  condition:
    5 of them or
    (
     pe.imphash() == "222e118fa8c0eafeef102e49953507b9" or
     pe.imphash() == "7210d5941678578c0a31adb5c361254d" or
     pe.imphash() == "41e9907a6c468b4118e968a01461a45b"
    )
}
rule albaniiutas_rat_dll
{
  meta:
    author = "Dmitry Kupin"
    company = "Group-IB"
    family = "albaniiutas.rat"
    description = "Suspected Albaniiutas RAT (fileless)"
    reference = "https://blog.group-ib.com/task"
    sample = "fd43fa2e70bcc3b602363667560494229287bf4716638477889ae3f816efc705" // dumped
    severity = 9
    date = "2021-07-06"

  strings:
    $rc4_key = { 00 4C 21 51 40 57 23 45 24 52 25 54 5E 59 26 55 2A 41 7C 7D 74 7E 6B 00 } // L!Q@W#E$R%T^Y&U*A|}t~k
    $aes256_str_seed = { 00 30 33 30 34 32 37 36 63 66 34 66 33 31 33 34 35 00 } // 0304276cf4f31345
    $s0 = "http://%s/%s/%s/" fullword ascii
    $s1 = "%s%04d/%s" fullword ascii
    $s2 = "GetRemoteFileData error!" fullword ascii
    $s3 = "ReadInjectFile error!" fullword ascii
    $s4 = "%02d%02d" fullword ascii
    $s5 = "ReadInject succeed!" fullword ascii
    $s6 = "/index.htm" fullword ascii
    $s7 = "commandstr" fullword ascii
    $s8 = "ClientX.dll" fullword ascii
    $s9 = "GetPluginObject" fullword ascii
    $s10 = "D4444 0k!" fullword ascii
    $s11 = "D5555 E00r!" fullword ascii
    $s12 = "U4444 0k!" fullword ascii
    $s13 = "U5555 E00r!" fullword ascii

  condition:
    5 of them
}
rule CorkowDLL
{
meta:
	description = "Rule to detect the Corkow DLL files"
    reference = "www.group-ib.ru/brochures/Group-IB-Corkow-Report-EN.pdf"
strings:
	$mz = { 4d 5a }
	$binary1 = {60 [0-8] 9C [0-8] BB ?? ?? ?? ?? [0-8] 81 EB ?? ?? ?? ?? [0-8] E8 ?? 00 00 00 [0-8] 58 [0-8] 2B C3}
	$binary2 = {(FF 75 ?? | 53) FF 75 10 FF 75 0C FF 75 08 E8 ?? ?? ?? ?? [3-9] C9 C2 0C 00}
	$export1 = "Control_RunDLL"
	$export2 = "ServiceMain"
	$export3 = "DllGetClassObject"
condition:
	($mz at 0) and ($binary1 and $binary2) and any of ($export*)
}import "pe"

rule webdavo_rat
{
  meta:
    author = "Dmitry Kupin"
    company = "Group-IB"
    family = "webdavo.rat"
    description = "Suspected Webdav-O RAT (YaDisk)"
    reference = "https://blog.group-ib.com/task"
    sample = "7874c9ab2828bc3bf920e8cdee027e745ff059237c61b7276bbba5311147ebb6" // x86
    sample = "849e6ed87188de6dc9f2ef37e7c446806057677c6e05a367abbd649784abdf77" // x64
    severity = 9
    date = "2021-06-10"

  strings:
    $rc4_key_0 = { 8A 4F 01 47 34 C9 75 F8 2B C8 C1 E9 D2 F3 A5 8B }
    $rc4_key_1 = { C3 02 03 04 05 DD EE 08 09 10 11 12 1F D2 15 16 }
    $s0 = "y_dll.dll" fullword ascii
    $s1 = "test3.txt" fullword ascii
    $s2 = "DELETE" fullword wide
    $s3 = "PROPFIND" fullword wide

  condition:
    (any of ($rc4_key*) or 3 of ($s*)) or
    (
     pe.imphash() == "43021febc8494d66a8bc60d0fa953473" or
     pe.imphash() == "68320a454321f215a3b6fcd7d585626b"
    )
}
rule compiled_autoit {
	strings:
		$str1 = "This is a compiled AutoIt script. AV researchers please email avsupport@autoitscript.com for support."

	condition:
		all of them
}

rule MSFTConnectionManagerPhonebook {
	strings:
		$cmpbk1 = "cmpbk32.dll"
		$cmpbk2 = "PhoneBookEnumNumbersWithRegionsZero"
		$cmpbk3 = "PhoneBookLoad"
		$cmpbk4 = "PhoneBookUnload"
		$cmpbk5 = "PhoneBookGetCurrentCountryId"
		$cmpbk6 = "PhoneBookGetCountryNameA"
		$cmpbk7 = "PhoneBookFreeFilter"
		$cmpbk8 = "PhoneBookCopyFilter"
		$cmpbk9 = "PhoneBookMatchFilter"
		$cmpbk10 = "PhoneBookGetCountryId"
		$cmpbk11 = "PhoneBookGetPhoneDescA"
		$cmpbk12 = "PhoneBookHasPhoneType"
		$cmpbk13 = "PhoneBookGetRegionNameA"
		$cmpbk14 = "PhoneBookEnumRegions"
		$cmpbk15 = "PhoneBookParseInfoA"
		$cmpbk16 = "PhoneBookGetPhoneDUNA"
		$cmpbk17 = "PhoneBookGetPhoneDispA"
		$cmpbk18 = "PhoneBookGetPhoneCanonicalA"
		$cmpbk19 = "PhoneBookGetPhoneType"
		$cmpbk20 = "PhoneBookEnumNumbers"
		$cmpbk21 = "PhoneBookMergeChanges"
		$cmpbk22 = "PhoneBookGetPhoneNonCanonicalA"

	condition:
		12 of them
}
rule delphi_wlan {
	strings:
		$dll = "wlanapi.dll"

		$api2 = "WlanOpenHandle"
		$api3 = "WlanCloseHandle"
		$api4 = "WlanEnumInterfaces"
		$api5 = "WlanQueryInterface"
		$api6 = "WlanGetAvailableNetworkList"

		$options1 = "80211_OPEN"
		$options2 = "80211_SHARED_KEY"
		$options3 = "WPA_PSK"
		$options4 = "WPA_NONE"
		$options5 = "RSNA"
		$options6 = "RSNA_PSK"
		$options7 = "IHV_START"
		$options8 = "IHV_END"
		$options9 = "WEP104"
		$options10 = "WPA_USE_GROUP OR RSN_USE_GROUP"
		$options11 = "IHV_START"
		$options12 = "IHV_END"
		$options13 = "WEP40"

	condition:
		$dll and 3 of ($api*) and 6 of ($options*)
}


rule ejects_cdrom {
	strings:
		$cddoor1 = "mciSendString"
		$cddoor2 = "set cdaudio door open"
		$cddoor3 = "set cdaudio door closed"

	condition:
		2 of them
}

rule lowers_security {
	strings:
		$actions1 = "EnableLUA"
		$actions2 = "AntiVirusDisableNotify"
		$actions3 = "DisableNotifications"
		$actions4 = "UpdatesDisableNotify"

	condition:
		2 of them
}



rule reads_clipboard {
	strings:
		$clipboard1 = "CloseClipboard"
		$clipboard2 = "EmptyClipboard"
		$clipboard3 = "EnumClipboardFormats"
		$clipboard4 = "GetClipboardData"
		$clipboard5 = "IsClipboardFormatAvailable"
		$clipboard6 = "OpenClipboard"
		$clipboard7 = "RefreshClipboard"
		$clipboard8 = "RegisterClipboardFormat"
		$clipboard9 = "SendYourClipboard"
		$clipboard10 = "SetClipboardData"

	condition:
		5 of them
}

rule pcre {
	strings:
		$pcre1 = "this version of PCRE is not compiled with PCRE_UTF8 support"
		$pcre2 = "this version of PCRE is not compiled with PCRE_UCP support"
		$pcre3 = "alpha"
		$pcre4 = "lower"
		$pcre5 = "upper"
		$pcre6 = "alnum"
		$pcre7 = "ascii"
		$pcre8 = "blank"
		$pcre9 = "cntrl"
		$pcre10 = "digit"
		$pcre11 = "graph"
		$pcre12 = "print"
		$pcre13 = "punct"
		$pcre14 = "space"
		$pcre15 = "word"
		$pcre16 = "xdigit"
		$pcre17 = "at end of pattern"
		$pcre18 = "numbers out of order in {} quantifier"
		$pcre19 = "number too big in {} quantifier"
		$pcre20 = "missing terminating ] for character class"
		$pcre21 = "invalid escape sequence in character class"
		$pcre22 = "range out of order in character class"
		$pcre23 = "nothing to repeat"
		$pcre24 = "operand of unlimited repeat could match the empty string"
		$pcre25 = "internal error: unexpected repeat"
		$pcre26 = "unrecognized character after (? or (?-"
		$pcre27 = "POSIX named classes are supported only within a class"
		$pcre28 = "missing )"
		$pcre29 = "reference to non-existent subpattern"
		$pcre30 = "erroffset passed as NULL"
		$pcre31 = "unknown option bit(s) set"
		$pcre32 = "missing ) after comment"
		$pcre33 = "parentheses nested too deeply"
		$pcre34 = "regular expression is too large"
		$pcre35 = "failed to get memory"
		$pcre36 = "unmatched parentheses"
		$pcre37 = "internal error: code overflow"
		$pcre38 = "unrecognized character after (?<"
		$pcre39 = "lookbehind assertion is not fixed length"
		$pcre40 = "malformed number or name after (?("
		$pcre41 = "conditional group contains more than two branches"
		$pcre42 = "assertion expected after (?("
		$pcre43 = "(?R or (?[+-]digits must be followed by )"
		$pcre44 = "unknown POSIX class name"
		$pcre45 = "POSIX collating elements are not supported"
		$pcre46 = "this version of PCRE is not compiled with PCRE_UTF8 support"
		$pcre47 = "spare error"
		$pcre48 = "character value in x{...} sequence is too large"
		$pcre49 = "invalid condition (?(0)"
		$pcre50 = "number after (?C is > 255"
		$pcre51 = "closing ) for (?C expected"
		$pcre52 = "recursive call could loop indefinitely"
		$pcre53 = "unrecognized character after (?P"
		$pcre54 = "syntax error in subpattern name (missing terminator)"
		$pcre55 = "two named subpatterns have the same name"
		$pcre56 = "invalid UTF-8 string"
		$pcre57 = "subpattern name is too long (maximum 32 characters)"
		$pcre58 = "too many named subpatterns (maximum 10000)"
		$pcre59 = "repeated subpattern is too long"
		$pcre60 = "octal value is greater than 377 (not in UTF-8 mode)"
		$pcre61 = "internal error: overran compiling workspace"
		$pcre62 = "internal error: previously-checked referenced subpattern not found"
		$pcre63 = "DEFINE group contains more than one branch"
		$pcre64 = "repeating a DEFINE group is not allowed"
		$pcre65 = "inconsistent NEWLINE options"
		$pcre66 = "different names for subpatterns of the same number are not allowed"
		$pcre67 = "subpattern name expected"
		$pcre68 = "a numbered reference must not be zero"

	condition:
		30 of them
}rule doc_efax_buran {
	meta:
		author = "Alex Holland (@cryptogramfan)"
        reference = "https://threatresearch.ext.hp.com/buran-ransomware-targets-german-organisations-through-malicious-spam-campaign/"
		date = "2019-10-10"
		sample_1 = "7DD46D28AAEC9F5B6C5F7C907BA73EA012CDE5B5DC2A45CDA80F28F7D630F1B0"
		sample_2 = "856D0C14850BE7D45FA6EE58425881E5F7702FBFBAD987122BB4FF59C72507E2"
		sample_3 = "33C8E805D8D8A37A93D681268ACCA252314FF02CF9488B6B2F7A27DD07A1E33A"
		
	strings:
		$vba = "vbaProject.bin" ascii nocase
		$image = "image1.jpeg" ascii nocase
		$padding_xml = /[a-zA-Z0-9]{5,40}\d{10}\.xml/ ascii
		
	condition:
		all of them and filesize < 800KB
}
rule js_downloader_gootloader : downloader
{
  meta:
    description = "JavaScript downloader known to deliver Gootkit or REvil ransomware"
    reference = "https://github.com/hpthreatresearch/tools/blob/main/gootloader/js_downloader_gootloader.yar"
    author = "HP Threat Research @HPSecurity"
    filetype = "JavaScript"
    maltype = "Downloader"
    date = "2021-02-22"

  strings:
    $a = "function"
    $b1 = "while"
    $b2 = "if"
    $b3 = "else"
    $b4 = "return"
    $c = "charAt"
    $d = "substr"
    $e1 = "\".+"
    $e2 = "\\=\\\""
    $e3 = " r,"
    $e4 = "+;\\\""
    $f = /(\w+\[\w+\]\s+=\s+\w+\[\w+\[\w+\]\];)/

  condition:
    #a > 8 and #a > (#b4 + 3) and all of ($b*) and ($c or $d) and any of ($e*) and $f and filesize < 8000
}
rule js_RATDispenser : downloader
{
  meta:
    description = "JavaScript downloader resp. dropper delivering various RATs"
    reference = "https://threatresearch.ext.hp.com/javascript-malware-dispensing-rats-into-the-wild/"
    author = "HP Threat Research @HPSecurity"
    filetype = "JavaScript"
    maltype = "Downloader"
    date = "2021-05-27" 

  strings:
    $a = /{(\d)}/

    $c1 = "/{(\\d+)}/g"
    $c2 = "eval"
    $c3 = "prototype"

    $d1 = "\\x61\\x64\\x6F\\x64\\x62\\x2E"
    $d2 = "\\x43\\x68\\x61\\x72\\x53\\x65\\x74"
    $d3 = "\\x54\\x79\\x70\\x65"

    $e1 = "adodb."
    $e2 = "CharSet"
    $e3 = "Type"

    $f1 = "arguments"
    $f2 = "this.replace"

  condition:
    #a > 50 and all of ($c*) and (any of ($d*) or any of ($e*)) and all of ($f*) and filesize < 2MB
}
rule trickbot_maldoc_embedded_dll_september_2020 {
    meta:
        author = "HP-Bromium Threat Research"
        reference = "https://threatresearch.ext.hp.com/detecting-a-stealthy-trickbot-campaign/"
        date = "2020-10-03"
        sharing = "TLP:WHITE"

    strings:
        $magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $s1 = "EncryptedPackage" wide
        $s2 = "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}" wide
        $s3 = { FF FF FF FF FF FF FF FF FF FF ( 90 90 | 10 10 | E2 E2 | 17 17 ) FF FF FF FF FF FF FF FF FF FF }

    condition:
        $magic at 0 and
        all of ($s*) and
        (filesize > 500KB and filesize < 1000KB)
}
rule win_l0rdix {
	meta:
		author = "Alex Holland (Bromium Labs)"
        reference = "https://threatresearch.ext.hp.com/an-analysis-of-l0rdix-rat-panel-and-builder/"
		date = "2019-07-19"
		sample_1 = "18C6AAF76985404A276466D73A89AC5B1652F8E9659473F5D6D656CA2705B0D3"
		sample_2 = "C2A4D706D713937F47951D4E6E975754C137159DC2C30715D03331FC515AE4E8"
		
	strings:
		$ua = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0" wide // Firefox 53 on Windows 10
		$sig = "L0rdix" wide ascii
		$sched_task = "ApplicationUpdateCallback" wide
		$exe = "syscall.exe" wide
		$cnc_url_1 = "connect.php?" wide
		$cnc_url_2 = "show.php" wide 
		$browser_1 = "\\Kometa\\User Data\\Default\\Cookies" wide 
		$browser_2 = "\\Orbitum\\User Data\\Default\\Cookies" wide
		$browser_3 = "\\Amigo\\User\\User Data\\Default\\Cookies" wide
		$coin_regex_1 = "[13][a-km-zA-HJ-NP-Z1-9]{25,34}" wide // Bitcoin
		$coin_regex_2 = "0x[a-fA-F0-9]{40}" wide // Ethereum
		$coin_regex_3 = "L[a-zA-Z0-9]{26,33}" wide // Litecoin
		
	condition:
		uint16(0) == 0x5A4D and (any of ($ua,$sig,$sched_task,$exe)) and (any of ($cnc_url_*)) and (any of ($browser_*)) and (any of ($coin_regex_*))
}
rule win_ostap_jse {
	meta:
		author = "Alex Holland @cryptogramfan (Bromium Labs)"
        reference = "https://threatresearch.ext.hp.com/deobfuscating-ostap-trickbots-javascript-downloader/"
		date = "2019-08-29"
		sample_1 = "F3E03E40F00EA10592F20D83E3C5E922A1CE6EA36FC326511C38F45B9C9B6586"
		sample_2 = "38E2B6F06C2375A955BEA0337F087625B4E6E49F6E4246B50ECB567158B3717B"
		
	strings:
		$comment = { 2A 2A 2F 3B } // Matches on **/;
		$array_0 = /\w{5,8}\[\d+\]=\d{1,3};/
		$array_1 = /\w{5,8}\[\d+\]=\d{1,3};/
				
	condition:
		((($comment at 0) and (#array_0 > 100) and (#array_1 > 100)) or
		((#array_0 > 100) and (#array_1 > 100))) and
		(filesize > 500KB and filesize < 1500KB)
}
rule xll_custom_builder
{
  meta:
    description = "XLL Custom Builder"
    reference = "https://threatresearch.ext.hp.com/how-attackers-use-xll-malware-to-infect-systems/"
    author = "patrick.schlapfer@hp.com"
    date = "2022-01-07"

  strings:
    $str1 = "xlAutoOpen"
    $str2 = "test"
    $op1 = { 4D 6B C9 00 }
    $op2 = { 4D 31 0E }
    $op3 = { 49 83 C6 08 }
    $op4 = { 49 39 C6 }

  condition:
    uint16(0) == 0x5A4D and all of ($str*) and all of ($op*) and filesize < 10KB
}
rule nspps_RC4_Key {
    meta:
        author = "IronNet Threat Research"
        date = "20200320"
        version = "1.0.0"
        description = "RC4 Key used in nspps RAT"
        reference = "SHA1:3bbb58a2803c27bb5de47ac33c6f13a9b8a5fd79"
        report = "https://www.ironnet.com/blog/malware-analysis-nspps-a-go-rat-backdoor"
    strings:
        $s1 = { 37 36 34 31 35 33 34 34 36 62 36 31 }
    condition:
        all of them
}
rule nspss_executable_strings {

    meta:
        author = "IronNet Threat Research"
        date = "20200320"
        version = "1.0.0"
        description = "ASCII strings seen in nspps RAT"
        reference = "SHA1:3bbb58a2803c27bb5de47ac33c6f13a9b8a5fd79"
        report = "https://www.ironnet.com/blog/malware-analysis-nspps-a-go-rat-backdoor"
strings:
        $s00 = "%s.lock" wide ascii
        $s01 = ", pass " wide ascii
        $s02 = ", user " wide ascii
        $s03 = "/getT" wide ascii
        $s04 = "/tmp/." wide ascii
        $s05 = "/var/tmp/." wide ascii
        $s06 = "Get task error" wide ascii
        $s07 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36" wide ascii
        $s08 = "SKL=" wide ascii
        $s09 = "Targets for task %d is empty" wide ascii
        $s10 = "Targets getted, type cidr, size %d" wide ascii
        $s11 = "Targets getted, type ip, size %d" wide ascii
        $s12 = "Targets getted, type url, size %d" wide ascii
        $s13 = "Task %d, executed in %s" wide ascii
        $s14 = "Task %d, new targets setted, size %d" wide ascii
        $s15 = "Task %d, processed %d/%d, left %d, thread %d, pps %d" wide ascii
        $s16 = "Try to get targets for %d, offset %d" wide ascii
        $s17 = "UpdateCommand: downloaded to %s" wide ascii
        $s18 = "User-Agent:" wide ascii
        $s19 = "curl" wide ascii
        $s20 = "doTask with type %s"
        $s21 = "exec_out" wide ascii
        $s22 = "firewire.sh" wide ascii
        $s23 = "get md5 of file error" wide ascii
        $s24 = "invalid md5, actual %s, expected %s, url %s" wide ascii
        $s25 = "libpcap-dev" wide ascii
        $s26 = "masscan chmod output %s" wide ascii
        $s27 = "sendSocks %s" wide ascii
        $s28 = "socks port = " wide ascii
        $s29 = "startCmd %s, pid %d" wide ascii
        $s30 = "try to send %d results for task %d"
        $s31 = "versionAndHash is empty" wide ascii
        $s32 = "wget" wide ascii
        $s33 = "Client sent AUTH, but no password is set" wide ascii
condition:
        24 of them
}
rule BLOWFISH_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for Blowfish constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { D1310BA6 }
		$c1 = { A60B31D1 }	
		$c2 = { 98DFB5AC }
		$c3 = { ACB5DF98 }
		$c4 = { 2FFD72DB }
		$c5 = { DB72FD2F }
		$c6 = { D01ADFB7 }
		$c7 = { B7DF1AD0 }
		$c8 = { 4B7A70E9 }
		$c9 = { E9707A4B }
		$c10 = { F64C261C }
		$c11 = { 1C264CF6 }
	condition:
                6 of them
}rule MD5_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for MD5 constants"
                date = "2014-01"
                version = "0.2"
        strings:
		// Init constants
		$c0 = { 67452301 }
		$c1 = { efcdab89 }
		$c2 = { 98badcfe }
		$c3 = { 10325476 }
		$c4 = { 01234567 }
		$c5 = { 89ABCDEF }
		$c6 = { FEDCBA98 }
		$c7 = { 76543210 }	
		// Round 2
		$c8 = { F4D50d87 }
		$c9 = { 78A46AD7 }
	condition:
                5 of them
}rule RC6_Constants {
        meta:
                author = "chort (@chort0)"
                description = "Look for RC6 magic constants in binary"
                reference = "https://twitter.com/mikko/status/417620511397400576"
                reference2 = "https://twitter.com/dyngnosis/status/418105168517804033"
                date = "2013-12"
                version = "0.2"
        strings:
                $c1 = { B7E15163 }
                $c2 = { 9E3779B9 }
                $c3 = { 6351E1B7 }
                $c4 = { B979379E }
        condition:
                2 of them
}rule RIPEMD160_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for RIPEMD-160 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
	condition:
		5 of them
}rule SHA1_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for SHA1 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
	condition:
                5 of them
}
rule SHA256_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for SHA224/SHA256 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 428a2f98 }
		$c1 = { 982F8A42 }
		$c2 = { 71374491 }
		$c3 = { 91443771 }
		$c4 = { B5C0FBCF }
		$c5 = { CFFBC0B5 }
		$c6 = { E9B5DBA5 }
		$c7 = { A5DBB5E9 }
		// Exclude
		$e0 = { D728AE22 }
		$e1 = { 22AE28D7 }
	condition:
                4 of ($c0,$c1,$c2,$c3,$c4,$c5,$c6,$c7) and not ($e0 or $e1)
}rule SHA512_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for SHA384/SHA512 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 428a2f98 }
		$c1 = { 982F8A42 }
		$c2 = { 71374491 }
		$c3 = { 91443771 }
		$c4 = { B5C0FBCF }
		$c5 = { CFFBC0B5 }
		$c6 = { E9B5DBA5 }
		$c7 = { A5DBB5E9 }
		$c8 = { D728AE22 }
		$c9 = { 22AE28D7 }
	condition:
		5 of them
}rule WHIRLPOOL_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for WhirlPool constants"
                date = "2014-02"
                version = "0.1"
        strings:
                $c0 = { 18186018c07830d8 }
                $c1 = { d83078c018601818 }
                $c2 = { 23238c2305af4626 }
                $c3 = { 2646af05238c2323 }
        condition:
                2 of them
}


/*Magic Number rules
This rule set defines a list of file signature to help identify files
https://github.com/pveutin/YaraRules/blob/master/filesig.yar
*/


//Documents

rule office_magic_bytes
{
  strings:
    $magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
  condition:
    $magic
}

rule chm_file
{
  strings:
    $magic = { 49 54 53 46 03 00 00 00  60 00 00 00 01 00 00 00 }
  condition:
    $magic
}

rule excel_document
{
  strings:
    $rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $workbook = "Workbook" wide nocase
    $msexcel = "Microsoft Excel" nocase
  condition:
    all of them
}

rule word_document
{
  strings:
    $rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $worddoc = "WordDocument" wide
    $msworddoc = "MSWordDoc" nocase
  condition:
    $rootentry and ($worddoc or $msworddoc)
}

rule powerpoint_document
{
  strings:
    $pptdoc = "PowerPoint Document" wide nocase
    $rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  condition:
    all of them
}

rule pdf_document
{
  strings:
    $a = "%PDF-"
  condition:
    $a at 0
}


//Programs

rule mz_executable // from YARA user's manual
{
  condition:
  // MZ signature at offset 0 and ...
  uint16(0) == 0x5A4D and
  // ... PE signature at offset stored in MZ header at 0x3C
  uint32(uint32(0x3C)) == 0x00004550
}

//Archives
rule zip_file
{
  strings:
    $magic = { 50 4b 03 04 }
    $magic2 = { 50 4b 05 06 }
    $magic3 = { 50 4b 07 08 }
  condition:
    ($magic at 0) or ($magic2 at 0) or ($magic3 at 0)
}

rule sevenzip_file
{
  strings:
    $magic = { 37 7A BC AF 27 1C }
  condition:
    $magic at 0
}

rule rar_file
{
  strings:
    $rar = { 52 61 72 21 1A 07 00 }
    $rar5 = { 52 61 72 21 1A 07 01 00 }
  condition:
    ($rar at 0) or ($rar5 at 0)
}

//Pictures
rule gif_file
{
  strings:
    $gif89a = { 47 49 46 38 39 61 }
    $gif87a = { 47 49 46 38 37 61 }
  condition:
    ( $gif89a at 0 ) or ( $gif87a at 0 )
}

rule png_file
{
  strings :
    $magic = { 89 50 4E 47 0D 0A 1A 0A }
  condition:
    $magic at 0
}

rule bmp_file
{
  strings:
    $magic = "BM"
  condition:
    $magic at 0
}

rule jpeg_file
{
  strings:
    $jpeg = { FF D8 FF E0 }
    $jpeg1 = { FF D8 FF E1 }
  condition:
    ($jpeg at 0) or ($jpeg1 at 0)
}import "pe"

rule Elise_lstudio_variant_B_resource

{

meta:

description = "Elise lightserver variant."

author = "PwC Cyber Threat Operations :: @michael_yip"

version = "1.0"

created = "2015-12-16"

exemplar_md5 = "c205fc5ab1c722bbe66a4cb6aff41190"

 reference = "http://pwc.blogs.com/cyber_security_updates/2015/12/elise-security-through-obesity.html"

condition:

uint16(0) == 0x5A4D and for any i in (0..pe.number_of_resources - 1) : (pe.resources[i].type_string == "A\x00S\x00D\x00A\x00S\x00D\x00A\x00S\x00D\x00A\x00S\x00D\x00S\x00A\x00D\x00")

}
rule Lightserver_variant_B : Red_Salamander

{

      meta:

            description = "Elise lightserver variant."

            author = "PwC Cyber Threat Operations :: @michael_yip"

            version = "1.0"

            created = "2015-12-16"

            exemplar_md5 = "c205fc5ab1c722bbe66a4cb6aff41190"

            reference = "http://pwc.blogs.com/cyber_security_updates/2015/12/elise-security-through-obesity.html"


      strings:

            $json = /\{\"r\":\"[0-9]{12}\",\"l\":\"[0-9]{12}\",\"u\":\"[0-9]{7}\",\"m\":\"[0-9]{12}\"\}/

            $mutant1 = "Global\\{7BDACDEE-8BF6-4664-B946-D00FCFF1FFBA}"

            $mutant2 = "{5947BACD-63BF-4e73-95D7-0C8A98AB95F2}"

            $serv1 = "Server1=%s"

            $serv2 = "Server2=%s"

            $serv3 = "Server3=%s"

      condition:

            uint16(0) == 0x5A4D and ($json or $mutant1 or $mutant2 or all of ($serv*))

}
 rule MSSUP : AST

{

meta:

       author="PwC Cyber Threat Operations"

       date="2014-09-11"

       hash="8083ee212588a05d72561eebe83c57bb"
       
       reference = "http://pwc.blogs.com/cyber_security_updates/2014/09/malware-microevolution.html"

 strings:

       $debug1="d:\\Programming\\CSharp\\BlackBerry\\BlackBerry\\obj\\Debug\\MSSUP.pdb" nocase

       $debug2="D:\\Programming\\CSharp\\BlackBerry\\UploadDownload\\bin\\x86\\Debug\\UploadDownload.pdb" nocase

       $debug3="Unexpected error has been occurred in {0}, the process must restart for some reason, if it's first time you see this message restart the {0}, if problem was standing contacts the support team ."

       $fileheader1="MSSUP" ascii wide

       $fileheader2="1.0.0.0" ascii wide

       $fileheader3="2014" ascii wide

       $configload1="sqlite3.dll"

       $configload2="URLExtractRegex"

       $configload3="HTTPHeaderName"

       $configload4="HTTPHeaderType"

       $configload5="MsupPath"

 

condition:

       (all of ($fileheader*) or 3 of ($configload*)) and filesize < 200KB or any of ($debug*)

}

rule OrcaRAT
  {
  meta:  
         author = "PwC Cyber Threat Operations   :: @tlansec"
         distribution = "TLP WHITE"
         sha1 =   "253a704acd7952677c70e0c2d787791b8359efe2c92a5e77acea028393a85613"
  strings:

       $MZ="MZ"

       $apptype1="application/x-ms-application"

       $apptype2="application/x-ms-xbap"

       $apptype3="application/vnd.ms-xpsdocument"

       $apptype4="application/xaml+xml"

       $apptype5="application/x-shockwave-flash"

       $apptype6="image/pjpeg"

       $err1="Set return time error =   %d!"

       $err2="Set return time   success!"

       $err3="Quit success!"

 

condition:

       $MZ at 0 and filesize < 500KB and   (all of ($apptype*) and 1 of ($err*))
  }rule smbWormTool

 {

 meta:

 author = "PwC Cyber Threat Operations"

 description = "SMB Worm Tool"

 version = "1.0"

 created = "2014-12-30"

 osint_ref =

 "http://totalhash.com/analysis/db6cae5734e433b195d8fc3252cbe58469e42bf3"

 exemplar_md5 = "61bf45be644e03bebd4fbf33c1c14be2"

 reference = "http://pwc.blogs.com/cyber_security_updates/2015/01/destructive-malware.html"

 strings:

 $STR1 = "%s\\Admin$\\%s.exe" wide ascii nocase

 $STR2 ="NetScheduleJobAdd" wide ascii nocase

 $STR3 = "SetServiceStatus failed, error code" wide   ascii nocase

 $STR4 = "LoadLibrary( NTDLL.DLL ) Error" wide ascii   nocase

 $STR5 = "NTLMSSP" wide ascii nocase

 condition:

 all of them

 }
rule Tendrit_2014 : OnePHP

{

meta:

       author = "PwC Cyber Threat Operations   :: @tlansec"

       date="2014-12"

       ref="[http://pwc.blogs.com/cyber_security_updates/2014/12/festive-spearphishing-merry-christmas-from-an-apt-actor.html]"

       hash = "7b83a7cc1afae7d8b09483e36bc8dfbb"

strings:

       $url1="favicon"

       $url2="policyref"

       $url3="css.ashx"

       $url4="gsh.js"

       $url5="direct"



       $error1="Open HOST_URL error"

       $error2="UEDone"

       $error3="InternetOpen error"

       $error4="Create process fail"

       $error5="cmdshell closed"

       $error6="invalid command"

       $error7="mget over&bingle"

       $error8="mget over&fail"

 condition:

       (all of ($url*) or all of ($error*)) and filesize < 300KB

}
/*

    root9B Yara Rules for SHELLTEA + POSLURP MALWARE blog entry

    https://www.root9b.com/newsroom/shelltea-poslurp-malware

*/

rule PoSlurpFile : PoSlurp

{

    meta:

       copyright = "root9b, LLC"

       authors = "Matt Weeks, Dax Morrow"

       description = "ShellTea + PoSlurp PoS Malware on Disk PoSlurp executable"

       reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

       version = "1.0"

       last_modified = "2017-06-27"

strings:

       $hex1 = { 81 C2 FF 5C F3 22 52 56 E8 } // outer layer custom function resolver

condition:

       uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and $hex1

}

rule inRegPowerSniff : PowerSniff

{

meta:

       copyright = "root9b, LLC"

       authors = "Matt Weeks, Dax Morrow"

       description = "ShellTea + PoSlurp PoS Malware in Registry PowerSniff"

		reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

		version = "1.0"

       last_modified = "2017-06-27"

strings:

       $hex1 = { 41 2B CF 81 38 BE BA AD AB 48 8B D0 75 09 81 78 04 0D F0 AD 8B } //shellcode blob in registry

condition:

$hex1

}

rule inRegShellTea : ShellTea {

meta:

       copyright = "root9b, LLC"

   authors = "Matt Weeks, Dax Morrow"

       description = "ShellTea + PoSlurp PoS Malware in Registry ShellTea"

reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

version = "1.0"

       last_modified = "2017-06-27"

strings:

       $hex1 = { 48 83 EC 28 E8 F7 03 00 00 [1015] 48 89 5C 24 18 48 89 4C 24 08 55 56 57 41 54 41 } // Binary registry value with variable content for ShellTea config

condition:

$hex1

}

rule inMemPowerSniff : PowerSniff {

meta:

       copyright = "root9b, LLC"

       authors = "Matt Weeks, Dax Morrow"

       description = "ShellTea + PoSlurp in Memory PowerSniff"

       reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

version = "1.0"

       last_modified = "2017-06-27"

strings:

       $wide_string = "/%s?user=%08x%08x%08x%08x&id=%u&ver=%u&os=%lu&os2=%lu&host=%u&k=%lu&type=%u" wide //PowerSniff URL Pattern

       $wide_string2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT %u.%u%s)" wide // PowerSniff URL Pattern

condition:

all of them

}

rule inMemShellTea : ShellTea {

meta:

       copyright = "root9b, LLC"

       authors = "Matt Weeks, Dax Morrow"

       description = "ShellTea + PoSlurp PoS Malware in Memory ShellTea"

		reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

		version = "1.0"

       last_modified = "2017-06-27"

strings:

       $hex1 = { B9 1D C7 12 45 E8 } // opcodes for function hash

		$hex2 = { B9 52 7E 10 E1 E8 } // opcodes for function hash
	
		$hex3 = { B9 CC 11 67 D6 E8 } // opcodes for function hash

condition:

all of them

}

rule inMemPoSlurp : PoSlurp {

meta:

       copyright = "root9b, LLC"

       authors = "Matt Weeks, Dax Morrow"

       description = "ShellTea + PoSlurp PoS Malware in Memory PoSlurp"

reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

version = "1.0"

        last_modified = "2017-06-27"

       strings:

          $hex1 = { C6 45 ED 65 C6 45 EE 72 C6 45 EF 6E C6 45 F0 65 } // Kernel32 obfuscated

          $hex2 = { E8 EE FD FF FF 68 88 13 00 00 FF D6 8D 44 24 18 50 FF D7 8D 44 24 10 50 8D 44 24 1C 50 FF D3 8B 44 24 10 2B 05 80 50 40 00 8B 4C 24 14 1B 0D 84 50 40 00 6A 00 68 80 96 98 00 51 50 E8 B7 05 00 00 6A 3C 33 D2 59 F7 F1 3B 05 2C 40 40 00 72 B0 } // opcodes f rom top-level scan memory basic block

       condition:

         all of them

} 
