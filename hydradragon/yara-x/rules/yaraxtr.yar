import "pe"
import "hash"
import "elf"
import "console"
import "dotnet"
import "macho"
import "math"
import "time"


// YARA rule set for detecting potential malicious TTPs in a file sample
// Author: Phil Stokes, SentinelLabs
// Date: 29 August, 2023
// Ref: https://s1.ai/BigBins-macOS

rule Stealer {
 	strings:
       		$a = "dump-generic-passwords"
		$b = "keychain-db"
       		$A = "dump-generic-passwords" base64
		$B = "keychain-db" base64
   	condition:
 		any of them
}

rule System_Discovery {
        meta:
	        mitre = "T1082 System Information Discovery"
 	strings:
       		$a = "sw_vers" 
		$b = "spctl" 
		$c = "test-devid-status"
		$d = "csrutil"
		$e = "df -m / |"
		$f = "__kCFSystemVersionProductNameKey"
		$g = "__kCFSystemVersionProductVersionKey"
       		$A = "sw_vers" base64
		$B = "spctl" base64
		$C = "test-devid-status" base64
		$D = "csrutil" base64
		$E = "df -m / |" base64
		$F = "__kCFSystemVersionProductNameKey" base64
		$G = "__kCFSystemVersionProductVersionKey" base64
   	condition:
 		any of them
}

rule Password_Spoofing {
 	strings:
       		$a = "with hidden answer"
       		$A = "with hidden answer" base64
   	condition:
 		any of them
}

rule Hidden_Process_Deception {
 	meta:
		mitre = ""
 	strings:
       		$a = "/.com.apple."
		$a1 = "/.google."
		$a2 = ".plist"
		$l1 = "/LaunchAgents/"
		$l2 = "/LaunchDaemons/"
       		$A = "/.com.apple." base64
		$A1 = "/.google." base64
		$A2 = ".plist" base64
		$L1 = "/LaunchAgents/" base64  
		$L2 = "/LaunchDaemons/" base64
   	condition:
 	  (2 of ($a*) or 2 of ($A*)) and (1 of ($l*) or 1 of ($L*))
}

rule System_Network_Discovery {
 	meta:
		mitre = "T1016 System Network Configuration Discovery"
 	strings:
       		$a = "checkip.dyndns.org"
		$n = "/usr/sbin/networksetup"
		$n1 = "listnetworkserviceorder"
		$N = "/usr/sbin/networksetup"  base64
		$N1 = "listnetworkserviceorder" base64
   	condition:
 		any of them
}

rule Adversary_in_the_Middle {
 	meta:
		mitre = "T1557 Adversary in the Middle"
 	strings:
       		$a = "mitmproxy"
       		$A = "mitmproxy" base64
   	condition:
 		any of them
}

private rule Macho
{
    meta:
        description = "private rule to match Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca

}

private rule PE
{
    meta:
        description = "private rule to match PE binaries"

    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x4550
}

rule XProtect_MACOS_644e18d
{
    meta:
        description = "MACOS.644e18d"
    strings:
        $a = { 63 6f 6e 6e 65 63 74 54 6f 50 72 6f 78 79 4d 61 6e 61 67 65 72 }
        $b = { 63 6f 6e 6e 65 63 74 54 6f 44 65 73 74 69 6e 61 74 69 6f 6e }
        $c = { 68 65 61 72 74 62 65 61 74 53 65 6e 64 65 72 }
        $d = { 63 6f 6e 6e 65 63 74 54 6f 43 6e 63 }
        $e = { 70 72 6f 78 69 74 2e 63 6f 6d 2f 70 65 65 72 }
    condition:
        Macho and 2 of them
}

rule XProtect_MACOS_6e6bed7
{
    meta:
        description = "MACOS.6e6bed7"
    strings:
        $a = { 77 65 62 56 69 65 77 3a 64 65 63 69 64 65 50 6f 6c 69 63 79 46 6f 72 4e 61 76 69 67 61 74 69 6f 6e 41 63 74 69 6f 6e 3a 64 65 63 69 73 69 6f 6e 48 61 6e 64 6c 65 72 3a }
        $b = { 4e 53 54 61 73 6b }
        $c = { 5f 70 63 6c 6f 73 65 00 5f 70 6f 70 65 6e }
        $d1 = { ( 19 | 17 ) 6d 1b ( d1 | 51 ) }
        $d2 = { 44 8d b4 08 25 f9 ff ff }
        $d3 = { 89 16 40 38 e9 03 29 2a }
        $d4 = { 41 8a 14 0e f6 d2 88 14 08 }
        $d5 = { 5a 07 00 91 88 03 13 4a }
    condition:
        Macho and $a and ( $b or $c ) and ( 1 of ( $d* ) ) and filesize < 500KB
}

rule XProtect_MACOS_cbb1424
{
    meta:
        description = "MACOS.cbb1424"
    strings:
        $a = {
			48 63 85 ?? ?? ?? ??
			8B 84 85 ?? ?? ?? ??
			88 85 ?? ?? ?? ??
			8A 85 ?? ?? ?? ??
			48 63 8D ?? ?? ?? ??
			88 84 0D ?? ?? ?? ??
			8B 85 ?? ?? ?? ??
			83 C0 01
			89 85 ?? ?? ?? ??
		}
        $b = {
			66 ( 41 0f | 0F ) ( 6F | 6f 44 ) ( 04 | 05 ) 0?
			66 0F 38 00 C1
			( 66 41 0F 7E 45 ?? | 66 0F 7e 03 )
			( 48 | 49 ) 83 C? 10
			( 48 | 49 ) 83 C? 04
			( 4? 81 F? | 48 3D ??) [3-4]
			75 ??
		}
    condition:
        Macho and any of them
}

rule XProtect_MACOS_1afcb8b
{
    meta:
        description = "MACOS.1afcb8b"
    strings:
        $a = { 77 65 62 76 69 65 77 2e 4e 65 77 }
        $b = { 65 6e 63 6f 64 69 6e 67 2f 62 61 73 65 36 34 2e 28 2a 45 6e 63 6f 64 69 6e 67 29 2e 44 65 63 6f 64 65 53 74 72 69 6e 67 }
        $c = { (45 | 46) 0f b6 ( 2c | 24 ) ( 02 | 22 ) 45 31 ( ea | e1 ) }
    condition:
        Macho and all of them
}

rule XProtect_MACOS_e71e847
{
    meta:
        description = "MACOS.e71e847"
    strings:
        $a = { 73 70 6d 44 6f 6d 61 69 6e }
        $b = { 65 78 74 49 64 50 61 72 61 6d }
        $c = { 69 64 50 61 72 61 6d }
        $d = { 6c 6f 67 67 69 6e 67 55 72 6c }
        $e = { 73 72 63 68 50 72 6f 78 79 55 52 4c }
        $f = { 67 65 74 4c 6f 67 67 69 6e 67 55 72 6c }
        $g = { 53 61 66 61 72 69 45 78 74 65 6e 73 69 6f 6e 56 69 65 77 43 6f 6e 74 72 6f 6c 6c 65 72 }
        $h = { 70 6f 70 6f 76 65 72 56 69 65 77 43 6f 6e 74 72 6f 6c 6c 65 72 }
    condition:
        Macho and filesize < 500KB and all of them
}

rule XProtect_MACOS_1940318
{
    meta:
        description = "MACOS.1940318"
    strings:
        $a = { 42 30 4C 30 FF 8D 51 29 81 F9 D5 00 00 00 41 0F 4F D4 42 30 14 30 8D 4A 29 81 FA D5 00 00 00 41 0F 4F CC 48 83 C0 02 48 3D 01 74 05 00 75 }
    condition:
        Macho and filesize < 600KB and $a
}

rule XProtect_MACOS_275ff12
{
    meta:
        description = "MACOS.275ff12"
    strings:
        $a = { 69 00 6f 00 72 00 65 00 67 00 20 00 2d 00 72 00 64 00 31 00 20 00 2d 00 63 00 20 00 49 00 4f 00 50 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 45 00 78 00 70 00 65 00 72 00 74 00 44 00 65 00 76 00 69 00 63 00 65 00 20 00 7c 00 20 00 61 00 77 00 6b 00 20 00 27 00 2f 00 49 00 4f 00 50 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 55 00 55 00 49 00 44 00 2f 00 20 00 7b 00 20 00 73 00 70 00 6c 00 69 00 74 00 28 00 24 00 30 00 2c 00 20 00 6c 00 69 00 6e 00 65 00 2c 00 20 00 22 00 5c 00 22 00 22 00 29 00 3b 00 20 00 70 00 72 00 69 00 6e 00 74 00 66 00 28 00 22 00 25 00 73 00 22 00 2c 00 20 00 6c 00 69 00 6e 00 65 00 5b 00 34 00 5d 00 29 00 3b 00 20 00 7d 00 27 00 }
        $b = { 5f 6b 66 75 6e 3a 23 6d 61 69 6e 28 29 }
    condition:
        Macho and all of them
}

rule XProtect_MACOS_7c241b4
{
    meta:
        description = "MACOS.7c241b4"

    strings:
        $a1 = { 5f 54 72 61 6e 73 66 6f 72 6d 50 72 6f 63 65 73 73 54 79 70 65 }
        $a2 = { 5f 69 6e 66 6c 61 74 65 49 6e 69 74 }
        $b1 = { 90 4? 63 c? 48 8? 0d ?? ?? 00 00 32 14 08 4c 39 fb }
        $b2 = { 49 63 c6 48 8d 0d ?? ?? 00 00 44 32 3c 08 90 48 8b 85 78 ff ff ff 48 3b 45 80 }
        $b3 = { ff cb [0-2] 48 63 c3 48 8b (15 | 0d) ?? ?? 00 (00 | 00 44) 32 ?? ?? 48 8b ?5 [1-4] 48 3b ?5 }
        
    condition:
        Macho and any of ( $a* ) and any of ( $b* )
}

rule XProtect_MACOS_54d6414
{
    meta:
        description = "MACOS.54d6414"
    strings:
        $a = { 23 21 }

        $b1 = { 6d 6b 74 65 6d 70 }
        $b2 = { 74 61 69 6c 20 2d 63 20 22}
        $b3 = { 66 75 6e 7a 69 70 20 2d 22}
        $b4 = { 63 68 6d 6f 64 20 2b 78 }
        $b5 = { 6e 6f 68 75 70 }

        $c1 = { 50 4b 03 04 }

    condition:
        filesize < 100KB and $a at 0 and (all of ($b*)) and $c1
}

rule XProtect_MACOS_2b50ea5
{
    meta:
        description = "MACOS.2b50ea5"
    strings:
        $string_1 = { 43 61 6e 6e 6f 74 20 72 65 6d 6f 76 65 20 6f 6c 64 20 66 69 6c 65 }
        $string_2 = { 2f 62 69 6e 2f 62 61 73 68 }
        $string_3 = { 56 65 72 73 69 6f 6e 20 64 65 63 6f 64 65 64 }
        $string_4 = { 76 65 72 73 69 6f 6e 49 73 4f 4b }
        $string_5 = { 73 6f 72 74 65 65 64 43 69 74 79 4c 69 73 74 }
        $string_6 = { 5f 75 70 64 61 74 65 50 61 74 68 }

    condition:
        Macho and filesize < 1MB and all of them
}

rule XProtect_MACOS_f5d33c9
{
    meta:
        description = "MACOS.f5d33c9"
    strings:
        $a1 = { 23 21 }

        $b1 = { 6d 6b 74 65 6d 70 20 2d 74 }
        $b2 = { 74 61 69 6c [1-2] 2d 63 }
        $b3 = { 24 30 [1-3] 7c [1-3] 66 75 6e 7a 69 70 [1-3] 2d [5-9] [1-3] 3e [1-3] 24 }
        $b4 = { 63 68 6d 6f 64 [1-3] 2b 78 }
        $b5 = { 6b 69 6c 6c 61 6c 6c [1-3] 54 65 72 6d 69 6e 61 6c }
        $b6 = { 50 4b 03 04 14 }
    condition:
        filesize < 100KB and $a1 at 0 and all of ($b*)
}
rule XProtect_MACOS_11eaac1
{
    meta:
        description = "MACOS.11eaac1"
    strings:
        $a1 = { 23 21 }

        $b1 = { 74 61 69 6c 20 2b }
        $b2 = { 66 75 6e 7a 69 70 20 2d }
        $b3 = { 6d 6b 74 65 6d 70 20 2d 64 20 2d 74 20 78 }
        $b4 = { 63 68 6d 6f 64 20 2d 52 [0-1] 20 37 35 35 }
        $b5 = { 6b 69 6c 6c 61 6c 6c 20 [0-3] 54 65 72 6d 69 6e 61 6c }
        $b6 = { 6e 6f 68 75 70 20 24 54 4d 50 44 49 52 2f 2a 2e 61 70 70 2f 43 6f 6e 74 65 6e 74 73 2f 4d 61 63 4f 53 2f }

        $c1 = { 50 4b 03 04 0a }

    condition:
        filesize < 500KB and $a1 at 0 and 4 of ($b*) and $c1
}

rule XProtect_MACOS_0e32a32
{
    meta:
        description = "MACOS.0e32a32"

    strings:
        $a = { 23 21 }

        $b1 = { ?? 3d 22 ?? 22 3b ?? 3d 22 ?? 22 3b ?? 3d 22 ?? 22 3b ?? 3d 22 ?? 22 3b ?? 3d 22 ?? 22 3b }
        $b2 = { 6d 6b 74 65 6d 70 20 2d 64 20 2f 74 6d 70 }
        $b3 = { 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d 20 24 7b ?? 7d 24 7b ?? 7d 24 7b ?? 7d }
        $b4 = { 6e 6f 68 75 70 20 2f 62 69 6e 2f 62 61 73 68 20 2d 63 20 22 65 76 61 6c }

        $c1 = { 27 5c 2e 28 63 6f 6d 6d 61 6e 64 29 24 27 }
        $c2 = { 55 32 46 73 64 47 56 6b 58 31 }
        $c3 = { 6b 69 6c 6c 61 6c 6c 20 54 65 72 6d 69 6e 61 6c }

    condition:
        filesize < 10KB and $a at 0 and (all of ($b*) or all of ($c*))
}

rule XProtect_MACOS_2afe6bd
{
    meta:
        description = "MACOS.2afe6bd"
    strings:

        $a1 = { bf 0a [0-3] e8 ?? ?? ?? ?? 48 ?? 6d 6d 6d 6d 6d 6d 6d 6d 48 89 08 [0-4] 66 c7 ?? ?? ?? [0-1] ?? c7 ?? ?? }
        $a2 = { BF 09 00 00 00 E8 ?? ?? 00 00 48 B9 53 53 53 53 53 53 53 53 48 89 08 C6 ?? ?? ?? C6 00 ?? ?? 40 ?? }
        $b1 = { e8 ed 8d d2 e8 ed ad f2 e8 ed cd f2 e8 ed ed f2 08 20 00 a9 08 e0 00 f8 c8 0d 80 52 08 34 00 39 }
        $b2 = { A8 AD 8D D2 A8 AD AD F2 A8 AD CD F2 A8 AD ED F2 08 00 00 F9 ?? ?? 80 52 }

        $c1 = { 48 8D ?? ?? 23 00 00 48 ?? ?? FE FF FF FF E8 ?? ?? 00 00 48 89 ?? ?? ?? 48 85 C0 0F ?? ?? 01 00 00 48 8D ?? ?? ?? 00 00 48 ?? ?? FE FF FF FF E8 ?? ?? 00 00 48 89 ?? ?? ?? 48 85 ?? 0F 84 ?? ?? 00 00 48 8D ?? ?? ?? 00 00 48 8D ?? ?? ?? 00 00 E8 ?? ?? 00 00 48 85 C0 0F ?? ?? ?? 00 00 48 ?? ?? 48 89 ?? ?? ?? 31 F6 BA 02 00 00 00 E8 ?? 02 00 00 48 8B ?? ?? ?? E8 ?? 02 00 00 31 FF 48 89 ?? ?? ?? }

        $c2 = { E1 10 01 10 1F 20 03 D5 20 00 80 92 B7 00 00 94 E0 1B 00 F9 00 0E 00 B4 A1 10 01 70 1F 20 03 D5 20 00 80 92 B1 00 00 94 60 ?? 00 ?? F4 03 00 AA 40 10 01 30 1F 20 03 D5 81 11 01 50 1F 20 03 D5 B0 00 00 94 80 0C 00 B4 F7 03 00 AA F4 17 00 F9 01 00 80 D2 42 00 80 52 B3 00 00 94 E0 03 17 AA B4 00 00 94 E0 03 F8 B7 F4 03 00 AA E0 03 17 AA }


        $d1 = { 5f 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 45 78 65 63 75 74 65 57 69 74 68 50 72 69 76 69 6c 65 67 65 73 }
        $d2 = { 5f 43 46 42 75 6e 64 6c 65 47 65 74 56 65 72 73 69 6f 6e 4e 75 6d 62 65 72 }

        $e1 = { 5f 67 65 74 5f 69 6e 73 74 61 6c 6c 65 72 5f 6e 73 73 74 72 5f 63 6f 6e 73 74 }
        $e2 = { 5f 67 65 74 5f 69 6e 73 74 61 6c 6c 65 72 5f 63 73 74 72 5f 63 6f 6e 73 74 }
        $e3 = { 5f 67 65 74 5f 61 75 74 68 5f 72 65 66 }
        $e4 = { 5f 72 75 6e 5f 61 73 5f 72 6f 6f 74 }

        $f1 = { 5f 43 46 42 75 6e 64 6c 65 47 65 74 56 65 72 73 69 6f 6e 4e 75 6d 62 65 72 00 90 00 72 ?? 01 15 40 5f 43 46 53 74 72 69 6e 67 47 65 74 43 53 74 72 69 6e 67 50 74 72 }
        

    condition:
        Macho and filesize < 1MB and ( (all of ($e*)) or ((all of ($a*) or all of ($b*) or all of ($c*)) and (all of ($d*))) and all of ($f*) )
}

rule XProtect_MACOS_4d60c89
{
    meta:
        description = "MACOS.4d60c89"
    strings:

        $a1 = { 23 21 }

        $b1 = { 5f 70 6b 67 5f 69 6e 73 74 61 6c 6c 5f }

        $b2 = { 70 75 62 6c 69 73 68 65 72 5f 69 64 }

        $b3 = { 70 61 67 65 5f 69 64 }

        $b4 = { 50 41 47 45 5f 49 44 }

        $b5 = { 70 72 6f 64 75 63 74 56 65 72 73 69 6f 6e }

        $b6 = { 63 6f 6d 2e 61 70 70 6c 65 2e 6d 65 74 61 64 61 74 61 3a 6b 4d 44 49 74 65 6d 57 68 65 72 65 46 72 6f 6d 73 }

        $b7 = { 5c 22 65 76 65 6e 74 5c 22 3a 20 5c 22 73 75 63 63 65 73 73 5c 22 }

        $b8 = { 5c 22 65 76 65 6e 74 5c 22 3a 20 5c 22 73 74 61 72 74 5c 22 }

        $c1 = { 73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 53 50 48 61 72 64 77 61 72 65 44 61 74 61 54 79 70 65 20 7c 20 61 77 6b }

        $c2 = { 6c 61 75 6e 63 68 63 74 6c 20 6c 6f 61 64 20 2d 77 }

        $c3 = { 69 6f 72 65 67 20 2d 61 64 32 20 2d 63 20 49 4f 50 6c 61 74 66 6f 72 6d 45 78 70 65 72 74 44 65 76 69 63 65 }

        $c4 = { 73 77 5f 76 65 72 73 20 2d 70 72 6f 64 75 63 74 }

        $c5 = { 64 65 66 61 75 6c 74 73 20 77 72 69 74 65 20 22 24 70 6c 69 73 74 4c 41 22 }

        $c6 = { 73 75 64 6f 20 63 75 72 6c }

        $c7 = { 6f 73 76 65 72 73 69 6f 6e }

        $c8 = { 57 68 65 72 65 46 72 6f 6d }

        $c9 =  { 77 68 65 72 65 46 72 6f 6d }

        $c10 =  { 53 74 61 72 74 49 6e 74 65 72 76 61 6c }

        $c11 = { 52 75 6e 41 74 4c 6f 61 64 }

    condition:
        filesize < 10KB and $a1 at 0 and 4 of ($b*) and (6 of ($c*))
}

rule XProtect_MACOS_74416b0
{
    meta:
        description = "MACOS.74416b0"

    strings:
        $a1  = { 4d 41 43 48 49 4e 45 49 44 3d 22 24 28 69 6f 72 65 67 20 2d 61 64 32 20 2d 63 20 49 4f 50 6c 61 74 66 6f 72 6d 45 78 70 65 72 74 44 65 76 69 63 65 20 7c 20 78 6d 6c 6c 69 6e 74 20 2d 2d 78 70 61 74 68 20 27 2f 2f 6b 65 79 5b 2e 3d 22 49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 22 5d 2f 66 6f 6c 6c 6f 77 69 6e 67 2d 73 69 62 6c 69 6e 67 3a 3a 2a 5b 31 5d 2f 74 65 78 74 28 29 27 20 2d 29 22 3b 43 4f 4e 54 45 4e 54 3d 24 28 63 75 72 6c 20 2d 2d 63 6f 6e 6e 65 63 74 2d 74 69 6d 65 6f 75 74 20 39 30 }

        $a2 = { 65 76 61 6c 20 22 24 43 4f 4e 54 45 4e 54 22 }

        $a3 = { 5f 73 79 73 74 65 6d }


        $b1 = { 49 89 C7 48 BF 2F 75 73 72 2F 73 62 69 48 BE 6E 2F 63 68 6F 77 6E EF }

        $b2 = { 49 89 C6 48 BF 2F 62 69 6E 2F 63 68 6D 48 BE 6F 64 00 00 00 00 00 EA }

        $b3 = { 28 69 6f 72 65 67 20 2d 61 64 32 20 2d 63 20 49 4f 50 6c 61 74 66 6f 72 6d 45 78 70 65 72 74 44 65 76 69 63 65 20 7c 20 78 6d 6c 6c 69 6e 74 20 2d 2d 78 70 61 74 68 20 27 2f 2f 6b 65 79 5b 2e 3d 22 49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 22 5d 2f 66 6f 6c 6c 6f 77 69 6e 67 2d 73 69 62 6c 69 6e 67 3a 3a 2a 5b 31 5d }

        $b4 = { 28 73 77 5f 76 65 72 73 20 2d 70 72 6f 64 75 63 74 4e 61 6d 65 29 00 00 00 00 00 00 00 00 00 00 28 73 77 5f 76 65 72 73 20 2d 70 72 6f 64 75 63 74 56 65 72 73 69 6f 6e 29 }

        $b5 = { 48 B9 6F 73 5F 76 65 72 73 69 }

        $b6 = { 48 B8 6E 6F 74 5F 6C 61 75 6E 48 89 05 6E A2 00 00 48 B8 63 68 65 64 00 00 00 EC }

    condition:
        filesize < 100KB and Macho and ((all of ($a*)) or (all of ($b*)))
}

rule XProtect_MACOS_e16be2c
{
    meta:
        description = "MACOS.e16be2c"
    strings:
        $a = { 80 7d ?? 00 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 0f 45 c1 ( e9 | eb ) ?? ?? ?? ?? }
        $b = { 53 61 66 61 72 69 45 78 74 65 6e 73 69 6f 6e 48 61 6e 64 6c 65 72 }
        $c = { 73 79 73 63 74 6c }
        $d = { 49 4f 53 65 72 76 69 63 65 47 65 74 4d 61 74 63 68 69 6e 67 53 65 72 76 69 63 65 }
    condition:
        filesize < 500KB and Macho and all of them
}

rule XProtect_MACOS_1373c52
{
    meta:
        description = "MACOS.1373c52"
    strings:
        $a = { 48 8d b5 58 ff ff ff e8 ?? ?? ?? ?? 49 89 c4 66 0f 6f 05 09 3e 00 00 f3 0f 7f 40 10 4c 8d 68 20 44 88 78 20 48 8d 58 21 48 8b 7d c8 e8 ?? ?? ?? ?? 4c 89 ef 48 89 de 4c 8d 6d 90 e8 ?? ?? ?? ?? 4c 89 e7 e8 ?? ?? ?? ?? 48 8b 5d 80 48 ff c3 70 ?? }
    condition:
        filesize < 200KB and Macho and $a
}

rule XProtect_MACOS_6e7d4c2
{
    meta:
        description = "MACOS.6e7d4c2"
    strings:
        $a1 = { 73 65 74 44 69 73 74 72 69 62 75 74 65 72 }
        $a2 = { 73 65 74 44 65 76 69 63 65 49 44 }
        $a3 = { 73 65 74 43 68 61 6e 6e 65 6c 49 44 }
        $a4 = { 73 65 74 49 70 41 64 64 72 65 73 73 }
        $a5 = { 73 65 74 42 61 72 63 6f 64 65 49 44 }
        $a6 = { 73 65 74 43 48 }
        $a7 = { 73 65 74 46 46 }
        $a8 = { 73 65 74 53 61 66 61 72 69 45 58 }
        $b1 = { 49 4e 43 68 72 6f 6d 65 41 6e 64 46 46 53 65 74 74 65 72 }
        $b2 = { 49 4e 41 70 53 65 74 74 65 72 }
        $b3 = { 49 4e 49 6e 73 74 61 6c 6c 65 72 46 6c 6f 77 }
        $c = { 48 8b 85 f0 fe ff ff 48 89 c7 ff ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 bd c0 fe ff ff 48 89 cf 48 89 c2 ff ?? ?? ?? ?? ?? 48 89 c7 e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8b 8d c0 fe ff ff 48 89 cf 48 89 c2 48 89 85 b8 fe ff ff ff ?? ?? ?? ?? ?? 48 8b 85 b8 fe ff ff 48 89 c7 ff ?? ?? ?? ?? ?? 45 31 c0 44 89 c6 48 8d 45 e0 48 89 c7 e8 ?? ?? ?? ?? 48 81 c4 50 01 00 00 5d c3 }
    condition:
        Macho and filesize < 1MB and ( ( all of ( $a* ) and all of ( $b* ) ) or $c )
}

rule XProtect_MACOS_1f26189
{
    meta:
        description = "MACOS.1f26189"
    strings:
        $a1 = { 70 72 6F 63 65 73 73 49 6E 66 6F 00 6F 70 65 72 61 74 69 6E 67 53 79 73 74 65 6D 56 65 72 73 69 6F 6E 00 }
        $a2 = { 49 4F 45 74 68 65 72 6E 65 74 49 6E 74 65 72 66 61 63 65 00 49 4F 50 72 69 6D 61 72 79 49 6E 74 65 72 66 61 63 65 00 49 4F 50 72 6F 70 65 72 74 79 4D 61 74 63 68 00 49 4F 53 65 72 76 69 63 65 00 49 4F 4D 41 43 41 64 64 72 65 73 73 00 49 4F 50 6C 61 74 66 6F 72 6D 53 65 72 69 61 6C 4E 75 6D 62 65 72 00 49 4F 50 6C 61 74 66 6F 72 6D 55 55 49 44 00 }

        $b1 = { 0F 28 ?? ?? ?? ?? 00 0F 29 ?? ?? ?? ?? 00 48 8D ?? ?? ?? ?? 00 [0-20] 48 ?? ?? ?? ?? ?? 00 C7 05 5B B1 05 00 B0 ED F8 F0 [0-20] C6 ?? ?? ?? ?? 00 ?? 48 8D ?? ?? ?? ?? 00 48 ?? ?? ?? DA FE FF E8 ?? ?? ?? 00 48 8D ?? ?? ?? ?? 00 }

        $b2 = { C7 45 ?? ?? 00 00 00 83 7D ?? ?? 7C ?? 48 63 45 ?? F2 48 0F ?? 04 ?? F2 0F 51 C0 F2 0F 2C C0 48 63 4D ?? 88 84 0B ?? 00 00 00 8B 45 ?? 83 C0 ?? 89 45 ?? EB ?? EB ?? }

    condition:
        filesize < 1MB and Macho and all of ($a*) and any of ($b*)
}


rule XProtect_MACOS_8f20223
{
    meta:
        description = "MACOS.8f20223"
    strings:
        $a = { 48 83 c? 77 (0f | 70) ?? }
        $b = { 5f 43 47 44 69 73 70 6c 61 79 4d 6f 76 65 43 75 72 73 6f 72 54 6f 50 6f 69 6e 74 }
    condition:
        filesize < 500KB and Macho and all of them
}

rule XProtect_MACOS_1c119be
{
    meta:
        description = "MACOS.1c119be"
    strings:
        $a = { 70 72 65 70 61 72 65 5f 73 65 61 72 63 68 }
        $b = { 65 78 65 63 75 74 65 5f 73 65 61 72 63 68 }
        $c = { 67 65 74 51 75 65 72 79 50 61 72 74 }
        $d = { 53 65 61 72 63 68 50 72 65 66 69 78 65 73 }
        $e = { 49 67 6e 6f 72 65 44 6f 6d 61 69 6e 73 }
        $f = { 53 65 61 72 63 68 65 73 43 6c 6f 75 64 }
        $g = { 53 65 61 72 63 68 65 73 4e 65 74 77 6f 72 6b }
        $h = { 48 ?? 71 75 65 72 79 00 00 00 }
        $i = { 48 ?? 72 65 73 65 74 20 53 65 }
        $j = { 48 ?? 74 74 69 6e 67 73 00 }
    condition:
        filesize < 100KB and Macho and 3 of them
}

rule XProtect_MACOS_449a7ed
{
    meta:
        description = "MACOS.449a7ed"
    strings:
        $a1 = { 63 6c 6f 73 65 64 69 72 00 5f 6d 65 6d 63 68 72 00 5f 6d 65 6d 63 6d 70 00 5f 6d 65 6d 63 70 79 00 5f 6d 65 6d 73 65 74 00 5f 6f 70 65 6e 64 69 72 24 49 4e 4f 44 45 36 34 00 5f 72 61 6e 64 00 5f 72 65 61 64 64 69 72 24 49 4e 4f 44 45 36 34 00 5f 73 72 61 6e 64 00 5f 73 74 61 74 24 49 4e 4f 44 45 36 34 00 5f 73 74 72 63 70 79 00 5f 73 74 72 6c 65 6e 00 5f 73 79 73 74 65 6d 00 5f 74 69 6d 65 00 5f 76 73 6e 70 72 69 6e 74 66 00 64 79 6c 64 5f }
        $a2 = { 48 89 7D F0 48 C7 45 F8 ?? 00 00 00 E8 3B 2D 00 00 B9 ?? 00 00 00 48 98 31 D2 48 F7 F1 48 8D ?? ?? 30 00 00 0F BE 04 ?? 48 83 C4 ?? }
        $a3 = { 48 89 ?? 48 89 ?? E8 45 ?? 00 00 48 8D 45 ?? 48 8D ?? F0 FE FF FF 48 89 48 ?? 48 8D 4D ?? 48 89 48 ?? C7 40 04 ?? 00 00 00 C7 00 ?? 00 00 00 48 8D ?? ?? E8 7C ?? 00 00 49 89 C4 48 63 5D BC 4C 89 FF E8 9D ?? 00 00 48 8D ?? ?? 4C 89 ?? 48 89 ?? 48 89 ?? E8 0F ?? 00 00 89 45 ?? }
    condition:
        filesize < 500KB and Macho and all of them
}

rule XProtect_MACOS_e3548bb
{
    meta:
        description = "MACOS.e3548bb"

    strings:
        $a1 = { 5f 49 4f 53 65 72 76 69 63 65 4d 61 74 63 68 69 6e 67 }
        $a2 = { 5f 49 4f 53 65 72 76 69 63 65 47 65 74 4d 61 74 63 68 69 6e 67 53 65 72 76 69 63 65 }
        $a3 = { 5f 49 4f 52 65 67 69 73 74 72 79 45 6e 74 72 79 43 72 65 61 74 65 43 46 50 72 6f 70 65 72 74 79 }

        $a4 = { 48 89 ?? ?? 48 89 ?? 4C 89 ?? 48 8D ?? ?? ?? 00 00 41 FF ?? 48 89 ?? E8 37 ?? 00 00 48 89 ?? ?? 48 89 ?? ?? }
        $a5 = { 44 89 7C ?? ?? C1 E3 ?? C1 E5 ?? 0F B7 ?? 09 D9 41 0F B6 ?? 09 ?? 89 54 ?? ?? 48 8D 74 ?? ?? BF ?? 00 00 00 FF ?? }

    condition:
        filesize < 500KB and Macho and all of them
}

rule XProtect_MACOS_71915a8
{
    meta:
        description = "MACOS.71915a8"
    strings:
        $shebang = "#!"
        $a = "zsh"
        $b = "\\U00000"
        $c = "${"
        $d = "rev)"

    condition:
        filesize < 10KB and $shebang at 0 and $a and #b > 15 and #c > 100 and $d
}

rule XProtect_MACOS_260ae81
{
    meta:
        description = "MACOS.260ae81"
    strings:
        $s1 = { 4D 65 64 69 61 52 65 6D 6F 74 65 2E 61 70 70 }
        $s2 = { 57 61 74 63 68 43 61 74 2E 61 70 70 }
        $s3 = { 73 77 5F 76 65 72 73 20 2D 70 72 6F 64 75 63 74 4E 61 6D 65 }
        $s4 = { 73 77 5F 76 65 72 73 20 2D 70 72 6F 64 75 63 74 56 65 72 73 69 6F 6E }
        $s5 = { 73 77 5F 76 65 72 73 20 2D 62 75 69 6C 64 56 65 72 73 69 6F 6E }
        $s6 = { 77 68 6F 61 6D 69 }
        $s7 = { 70 73 20 2D 65 20 2D 6F 20 63 6F 6D 6D 61 6E 64 }
        $s8 = { 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 5F 31 33 5F 36 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 36 30 35 2E 31 2E 31 35 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 56 65 72 73 69 6F 6E 2F 31 32 2E 30 2E 32 20 53 61 66 61 72 69 2F 36 30 35 2E 31 2E 31 35 }
    condition:
        Macho and filesize < 500KB and all of them
}

rule XProtect_MACOS_580a1bc
{
    meta:
        description = "MACOS.580a1bc"
    strings:
        $s1 = { 73 77 5F 76 65 72 73 20 2D 70 72 6F 64 75 63 74 4E 61 6D 65 }
        $s2 = { 73 77 5F 76 65 72 73 20 2D 70 72 6F 64 75 63 74 56 65 72 73 69 6F 6E }
        $s3 = { 73 77 5F 76 65 72 73 20 2D 62 75 69 6C 64 56 65 72 73 69 6F 6E }
        $s4 = { 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 5F 31 33 5F 36 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 36 30 35 2E 31 2E 31 35 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 56 65 72 73 69 6F 6E 2F 31 32 2E 30 2E 32 20 53 61 66 61 72 69 2F 36 30 35 2E 31 2E 31 35 }
        $s5 = { 63 6F 6D 2E 61 70 70 6C 65 2E 77 61 74 63 68 63 61 74 2E 70 6C 69 73 74 }
    condition:
        Macho and filesize < 500KB and all of them
}

rule XProtect_MACOS_6cb9746
{
    meta:
        description = "MACOS.6cb9746"
    strings:
        $a = { 8b 45 bc 48 8b 4d a0 48 63 55 9c 33 04 91 89 04 91 8b 7d bc be 01 00 00 00 e8 ?? ?? ?? ?? 89 45 bc 8b 45 9c 83 c0 01 89 45 9c e9 ?? ?? ?? ?? }
        $b = { 48 0f bf 85 ce fe ff ff 0f b6 8c 05 f0 fe ff ff 48 0f bf 85 ce fe ff ff 0f b6 84 05 f0 fe ff ff 0f b6 95 db fe ff ff 89 95 bc fe ff ff 99 8b b5 bc fe ff ff f7 fe 01 d1 89 c8 99 b9 ?? ?? ?? ?? f7 f9 40 88 d7 4c 0f bf 85 ce fe ff ff 42 88 bc 05 f0 fe ff ff 0f b6 85 db fe ff ff 0f bf 8d ce fe ff ff 01 c1 66 89 ca 66 89 95 ce fe ff ff e9 ?? ?? ?? ?? }
    condition:
        Macho and all of them
}

rule XProtect_MACOS_b17a97e
{
    meta:
        description = "MACOS.b17a97e"
    strings:
        $s1 = { 89 C1 C1 E9 07 48 69 C9 11 08 04 02 48 C1 E9 20 69 C9 80 3F 00 00 F7 D9 }
    condition:
        Macho and filesize < 100KB and all of them
}


rule XProtect_MACOS_2b3d4cb
{
    meta:
        description = "MACOS.2b3d4cb"
    strings:
        $s1 = { 43 6F 6E 6E 4D 6F 64 65 6C }
        $s2 = { 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 5F 31 32 5F 36 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 36 36 2E 30 2E 33 33 35 39 2E 31 33 39 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
        $s3 = { 31 72 65 70 6C 79 46 69 6E 69 73 68 65 64 28 29 }
        $s4 = { 32 66 69 6E 69 73 68 65 64 28 29 }
    condition:
        Macho and filesize < 100KB and all of them
}

rule XProtect_MACOS_8340d93
{
    meta:
        description = "MACOS.8340d93"
    strings:
        $s1 = { 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 5F 31 34 5F 33 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 36 30 35 2E 31 2E 31 35 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 56 65 72 73 69 6F 6E 2F 31 32 2E 30 2E 32 20 53 61 66 61 72 69 2F 36 30 35 2E 31 2E 31 35 }
        $s2 = { 5F 42 61 73 65 36 34 45 6E 63 6F 64 65 }
        $s3 = { 5F 43 75 72 6C 53 65 6E 64 52 65 63 76 }
        $s4 = { 5F 44 6F 77 6E 41 63 74 }
        $s5 = { 5F 47 65 6E 65 72 61 74 65 46 69 6C 65 4E 61 6D 65 }
        $s6 = { 5F 47 65 74 49 6E 66 6F 4C 69 6E 65 }
        $s7 = { 5F 47 65 74 49 6E 74 65 72 6E 61 6C 49 50 }
        $s8 = { 5F 47 65 74 55 73 65 72 4E 61 6D 65 }
        $s9 = { 5F 47 65 74 5F 53 57 5F 56 45 52 }
        $s10 = { 5F 53 69 6E 53 6C 65 65 70 }
        $s11 = { 5F 53 69 6E 5A 65 72 6F 4D 65 6D 6F 72 79 }
    condition:
        Macho and filesize < 100KB and all of them
}

rule XProtect_MACOS_f4a3a92
{
    meta:
        description = "MACOS.f4a3a92"
    strings:
        $s1 = { 6A 47 7A 41 63 4E 36 6B 34 56 73 54 52 6E 39 }
        $s2 = { 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 37 32 2E 30 2E 33 36 32 36 2E 31 32 31 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
    condition:
        Macho and filesize < 100KB and all of them
}

rule XProtect_MACOS_8d038b3
{
    meta:
        description = "MACOS.8d038b3"
    strings:
        $s1 = { 5F 69 73 5F 73 69 65 72 72 61 }
        $s2 = { 5F 66 69 6E 64 5F 6D 61 63 68 6F }
        $s3 = { 5F 66 69 6E 64 5F 65 70 63 }
        $s4 = { 5F 72 65 73 6F 6C 76 65 5F 73 79 6D 62 6F 6C }
        $s5 = { 5F 6D 65 6D 6F 72 79 5F 65 78 65 63 32 }
        $s6 = { 5F 6D 65 6D 6F 72 79 5F 65 78 65 63 }
        $s7 = { 5F 6C 6F 61 64 5F 66 72 6F 6D 5F 6D 65 6D 6F 72 79 }
    condition:
        Macho and filesize < 100KB and all of them
}

rule XProtect_MACOS_c723519
{
    meta:
        description = "MACOS.c723519"
    strings:
        $s1 = { 5F 6D 5F 43 6F 6E 66 69 67 }
        $s2 = { 5F 5F 5A 39 53 65 74 43 6F 6E 66 69 67 76 }
        $s3 = { 5F 5F 5A 31 30 4C 6F 61 64 43 6F 6E 66 69 67 76 }
        $s4 = { 5F 5F 5A 31 30 53 61 76 65 43 6F 6E 66 69 67 76 }
        $s5 = { 5F 5F 5A 31 33 4D 65 73 73 61 67 65 54 68 72 65 61 64 76 }
    condition:
        Macho and filesize < 100KB and all of them
}

rule XProtect_MACOS_bd64115
{
    meta:
        description = "MACOS.bd64115"
    strings:
        $s1 = { 68 74 74 70 73 3A 2F 2F 63 6F 69 6E 67 6F 74 72 61 64 65 2E 63 6F 6D 2F 75 70 64 61 74 65 5F 63 6F 69 6E 67 6F 74 72 61 64 65 2E 70 68 70 }
        $s2 = { 76 65 72 3D 25 64 26 74 69 6D 65 73 74 61 6D 70 3D 25 6C 64 }
        $s3 = { 43 6F 69 6E 47 6F 54 72 61 64 65 20 31 2E 30 20 28 43 68 65 63 6B 20 55 70 64 61 74 65 20 4F 73 78 29 }
        $s4 = { 2F 70 72 69 76 61 74 65 2F 74 6D 70 2F 75 70 64 61 74 65 63 6F 69 6E 67 6F 74 72 61 64 65 }
        $s5 = { 6B 75 70 61 79 5F 75 70 64 61 74 65 72 5F 6D 61 63 5F 6E 65 77 2D 35 35 35 35 34 39 34 34 39 34 36 35 31 63 37 36 32 65 32 35 33 37 65 31 62 32 66 31 32 64 30 31 64 33 63 34 33 37 63 37 }
    condition:
        Macho and filesize < 100KB and all of them
}

rule XProtect_MACOS_8032420
{
    meta:
        description = "MACOS.8032420"
    strings:
        $a1 = { 0f 28 ?? ?? ?? ?? ?? 0f 28 ?? ?? ?? ?? ?? 0f 57 c8 0f 29 ?? ?? ?? ?? ?? 0f 57 05 e3 13 07 00 0f 29 ?? ?? ?? ?? ?? 80 35 ?? ?? ?? 00 ?? 80 35 ?? ?? ?? 00 ?? 80 35 ?? ?? ?? 00 ?? 80 35 ?? ?? ?? 00 ?? 80 35 ?? ?? ?? 00 ?? }
        $a2 = { 48 8d [5] 80 34 08 ?? 48 ff c0 48 ?? ?? ?? 75 ?? 48 8d [5] 48 89 df 4c 89 fe ff }
        $a3 = { b8 02 00 00 00 48 ?? ?? ?? ?? ?? ?? 48 c7 c2 ff ff ff ff 80 ?? ?? ?? 48 ff c8 48 39 d0 75 ?? }
        $a4 = { 48 c7 c2 ff ff ff ff 80 ?? ?? ?? 48 ff c8 48 39 d0 75 ?? 48 ?? ?? ?? ?? ?? ?? 48 89 df }
        $a5 = { 50 58 90 90 90 90 50 58 90 90 90 8a (4c | 8c ) c7 [1-4] 80 ?? ?? 88 (4c | 8c) 07 [1-4] 50 58 90 90 50 58 90 90 48 ff c8 48 ?? ?? ?? 75 ?? }
        $a7 = { 50 58 90 50 58 80 f? ?? 88 ( 4c | 5c | 6c | 7c ) ?? ?? 50 58 50 58 }
        $b = { 0f 57 c0 f2 48 0f 2a 44 c1 [1-4] f2 0f 51 c0 [0-8] f2 0f 2c d0 88 ?? 08 [1-4] 48 ff c8 48 ?? ?? ?? 75 ?? }
        $c = { 8a ?4 c1 ?? [0-3] fe ca 88 ?4 08 ?? [0-3] 48 ff c8 48 ?? ?? ?? 75 ?? }
        $d = { 31 C0 48 8D 0D ?? ?? ?? 00 0F 57 C0 F2 48 0F 2A ?? C1 ?? [0-10] F2 0F 51 C0 F2 0F 2C D0 88 ?? 08 ?? [0-10] 48 FF C8 48 83 F8 ?? 75 ?? [0-20] ?? 89 F7 }
        $e = { 5f 73 79 73 74 65 6d }
        $f = { 5f 6d 65 6d 63 70 79 }
        $g = { 8b 42 fc 34 ?? 88 02 8b 42 fc fe c0 34 ?? 88 42 01 8b 42 fc 04 02 34 ?? 88 42 02 8b 42 fc 04 03 34 ?? 88 42 03 8b 42 fc 04 04 34 ?? 88 42 04 8b 42 fc 04 05 34 ?? 88 42 05 8b 42 fc 04 06 34 ?? 88 42 06 8b 42 fc 04 07 34 ?? 88 42 07 8b 42 fc 04 08 34 ?? }

    condition:
        Macho and filesize < 4MB and (any of ( $a* ) or #g > 50 or $b or $c ) or ( #d > 1 and #e > 1 and #f > 1 )
}


rule XProtect_MACOS_e4644f7
{
    meta:
        description = "MACOS.e4644f7"

    strings:
        $a1 = { 5f 73 79 73 74 65 6d  }
        $a2 = { 62 61 73 65 36 34 20 2d 2d 64 65 63 6f 64 65 20 }

        $b1 = { E8 ?? ?? 00 00  31 FF 48 89 C6 E8 ?? ?? 00 00 }

        $b3 = { 48 8B ?? ?? ?? 00 00 48 8D ?? ?? ?? 00 00 }

        $b4 = { 48 89 ?? E8 ?? 00 00 00 48 8B ?? D0 }

    condition:
        Macho and all of them
}


rule XProtect_MACOS_3ea93d1
{
    meta:
        description = "MACOS.3ea93d1"

    strings:
        $a1 = { 5f 63 68 6d 6f 64 }
        $a2 = { 5f 5f 5f 65 72 72 6f 72 }

        $b1 = { BE FF 01 00 00 48 ?? ?? E8 ?? 2B 00 00 E8 ?? ?? 00 00 83 38 02 75 ?? 81 ?? CF FA ED FE }
        $b2 = { BA 00 10 00 00 31 C9 48 BF 00 00 00 00 01 00 00 00 48 ?? ?? D0 E8 ?? ?? FF FF 4C 8B 75 }

        $c1 = { 30 ?? ?? 83 C0 ?? 3D FE 00 00 00 0F 4F C1 48 FF C7 48 39 FE 75 EA }
        $c2 = { 80 ?? ?? ?? 48 FF C0 48 39 C6 75 ?? 8B ?? ?? ?? 00 00 83 ?? ?? }
        $c3 = { BE 19 00 00 00 BA 72 6F 6D 4D E8 ?? FE FF FF }

    condition:
        Macho and filesize < 1MB and all of ($a*) and all of ($b*) and any of ($c*)
}

rule XProtect_MACOS_c592675
{
    meta:
        description = "MACOS.c592675"
    strings:
        $a = { 4c 75 6d 62 65 72 6a 61 63 6b }
        $b = { 69 61 6d 72 6f 6f 74 }
        $c = { 53 68 45 78 65 63 75 74 6f 72 }
    condition:
		Macho and 2 of them
}

rule XProtect_MACOS_489e70f
{
    meta:
        description = "MACOS.489e70f"
    strings:
        $a1 = { 66 89 45 d2 48 ?? ?? ?? ?? ?? ?? ba 01 00 00 00 4? 89 ?e 41 ff d? 66 89 45 d4 48 ?? ?? ?? ?? ?? ?? ba 02 00 00 00 4? 89 ?e 41 ff d? 66 89 45 d6 }
        $a2 = { 44 89 e0 b9 ab aa aa aa 48 0f af c1 48 c1 e8 22 01 c0 49 89 dd 8d 1c 40 }
        $a3 = { 44 89 e1 29 d9 4c 89 ?? 83 e1 fe 66 33 44 0d d2 48 8b ?? }
        $a4 = { 66 89 4d ?? 0f be cb 66 89 4d ?? 0f be c0 66 89 45 ?? 48 }
    condition:
        Macho and filesize < 200KB and any of them
}

rule XProtect_MACOS_8283b86
{
    meta:
        description = "MACOS.8283b86"
    strings:
        $a = { 67 65 74 61 64 76 61 6e 63 65 64 6d 61 63 }
    	$b = { 74 72 61 63 6b 57 65 62 4f 66 66 65 72 73 56 69 65 77 }
    	$c = { 67 65 74 4f 66 66 65 72 50 61 72 73 65 64 43 6f 75 6e 74 }
    	$d = { 77 76 47 65 74 50 68 6f 6e 65 52 65 6e 64 6f 6d }
    	$e = { 48 8B 3D ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 89 ?? ?? 48 8D ?? ?? ?? ?? ?? 48 8D ?? ?? ?? ?? ?? 4C 8D ?? ?? ?? ?? ?? 4C 8D ?? ?? ?? ?? ?? 4C 8B ?? ?? ?? ?? ?? 31 C0 41 FF D7 49 89 C4 48 8B ?? ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 41 FF D7 48 8B 35 ?? ?? ?? ?? 48 89 C7 41 FF D7 48 ?? ?? ?? 4C 8B 35 ?? ?? ?? ?? 48 89 DF 4C 89 F6 41 FF D7 49 89 C5 4C 89 ?? ?? 4C 89 E7 4C 89 F6 41 FF D7 45 85 ED 0F 84 A1 00 00 00 48 8B ?? ?? ?? ?? ?? 48 89 ?? ?? 48 8B ?? ?? ?? ?? ?? 48 89 4D C0 44 89 E9 48 89 4D C8 45 31 ED 45 31 FF 48 89 5D A8 [-] 48 89 DF 4C 8B 75 B8 4C 89 F6 4C 89 EA 4C 8B ?? ?? ?? ?? ?? 41 FF D4 89 C3 44 89 FA 48 8B 7D A0 4C 89 F6 41 FF D4 0F B7 C0 C1 E8 04 31 D8 }
    condition:
    	Macho and filesize < 3000000 and all of them
}

rule XProtect_MACOS_b264ff6
{
    meta:
        description = "MACOS.b264ff6"
    strings:
        $a1 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 44 89 ( e8 | e9 | e0 ) 48 ?? ?? ?? 45 31 (ed | e4) 45 31 (f6 | ff) }
        $a2 = { 48 ?? ?? ?? 8b ?? ?? 89 ca 48 ?? ?? ?? ?? ?? ?? 48 89 c7 e8 ?? ?? ?? ?? 0f b7 c8 48 ?? ?? ?? 44 ?? ?? ?? 44 89 c6 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 d7 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 d6 48 ?? ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 0f b7 c8 c1 f9 04 44 ?? ?? ?? ?? ?? ?? 41 31 c8 66 44 89 c0 66 89 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 0f b7 ?? ?? 4c ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4c 89 ce b0 00 e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 d7 48 89 c2 e8 ?? ?? ?? ?? 8b ?? ?? 83 c1 01 89 ?? ?? 3b ?? ?? 0f 83 ?? ?? ?? ?? }
        $a3 = { 48 ?? ?? ?? 8b ?? ?? 89 ca 48 ?? ?? ?? ?? ?? ?? 48 89 c7 ff ?? ?? ?? ?? ?? 0f b7 c8 48 ?? ?? ?? 44 ?? ?? ?? 44 89 c6 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 d7 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 d6 48 ?? ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 0f b7 c8 c1 f9 04 44 ?? ?? ?? ?? ?? ?? 41 31 c8 66 44 89 c0 66 89 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 0f b7 ?? ?? 4c ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4c 89 ce b0 00 ff ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 d7 48 89 c2 ff ?? ?? ?? ?? ?? 8b ?? ?? 83 c1 01 89 ?? ?? 3b ?? ?? 0f 83 ?? ?? ?? ?? }
        $a4 = { e8 ?? ?? ?? ?? 48 ?? ?? ?? e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 cf 48 ?? ?? ?? 48 89 d6 48 ?? ?? ?? ff ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 c7 ff ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 c7 48 89 ca ff ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 89 d7 48 89 ca 48 89 c1 b0 00 ff ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 89 cf 48 89 c2 ff ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 c7 ff ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 89 c7 48 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? 48 ?? ?? ?? e8 ?? ?? ?? ?? }
        $b1 = { 75 73 65 72 45 6e 74 65 72 65 64 46 69 6c 65 6e 61 6d 65 }
        $b2 = { 64 69 64 43 61 6e 63 65 6c 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 43 68 61 6c 6c 65 6e 67 65 }
        $b3 = { 65 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 }
        $b4 = { 2f 75 73 72 2f 73 62 69 6e 2f 73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 }
        $c = { 00 25 40 25 40 25 40 25 40 00 25 63 00 }
    condition:
		Macho and filesize < 3000000 and (1 of ($a*)) and (1 of ($b*)) and $c
}

rule XProtect_MACOS_f3edc61
{
    meta:
        description = "MACOS.f3edc61"
    strings:
        $a = { 6f 70 65 6e 50 68 6f 74 6f 73 4e 61 67 }
		$b = { 73 69 6c 65 6e 74 6c 79 46 69 72 65 55 72 6c }
		$c = { 54 72 61 63 6b 4f 66 66 65 72 73 }
		$d = { 48 8D 05 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 89 D7 48 89 C2 48 89 8D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 89 CF 48 89 C2 FF 15 ?? ?? ?? ?? 41 B8 10 00 00 00 31 F6 41 B9 40 00 00 00 44 89 CA 48 89 85 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 C1 48 89 CF 48 89 85 ?? ?? ?? ?? 4C 89 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 89 C1 48 89 CF 48 8B 95 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 4C 8B 85 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 83 F8 00 48 89 85 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? }
    condition:
		Macho and filesize < 1000000 and all of them
}

rule XProtect_MACOS_60a3d68
{
    meta:
        description = "MACOS.60a3d68"
    strings:
        $a = { 23 21 }
        $b1 = { 6f 70 65 6e 73 73 6c [1-3] 65 6e 63 }
        $b2 = { 2d 61 65 73 2d 32 35 36 2d 63 62 63 }
        $c1 = { 24 4f 24 50 24 45 24 4e 24 53 24 53 24 4c 20 24 45 24 4e 24 43 }
        $c2 = { 2d 24 41 24 45 24 53 2d 32 35 36 2d 63 62 63 }
        $d1 = { 24 7b 4f 7d 24 7b 50 7d 24 7b 45 7d 24 7b 4e 7d 24 7b 53 7d 24 7b 53 7d 24 7b 4c 7d 20 24 7b 45 7d 24 7b 4e 7d 24 7b 43 7d }
        $d2 = { 2d 24 7b 41 7d 24 7b 45 7d 24 7b 53 7d 2d 32 35 36 2d 63 62 63 }
        $e1 = { 2d 62 61 73 65 36 34 }
        $e2 = { 2d 61 }
        $e3 = { 2d 62 24 7b 41 7d 24 7b 53 7d 24 7b 45 7d 36 34 }
        $f = { 2d 64 }
        $g1 = { 2d 69 6e }
        $g2 = { 2d 6e 6f 73 61 6c 74 }
        $g3 = { 2d 73 61 6c 74 }
        $g4 = { 2d 6b }
        $g5 = { 2d 6f 75 74 }
        $g6 = { 2d 70 61 73 73 }
        $g7 = { 2d 50 24 41 24 53 24 53 }
        $g8 = { 2d 24 7b 50 7d 24 7b 41 7d 24 7b 53 7d 24 7b 53 7d }
        $h1 = { 64 64 20 69 66 3d 2f 64 65 76 2f 75 72 61 6e 64 6f 6d 20 62 73 3d 24 28 6a 6f 74 20 2d 72 20 31 20 35 20 31 35 29 }
        $h2 = { 62 61 73 65 36 34 20 7c 20 74 72 20 2d 64 63 20 27 61 2d 7a 41 2d 5a 30 2d 39 27 }
        $h3 = { 3c 65 6e 63 29 22 }
        $h4 = { 52 65 73 6f 75 72 63 65 73 2f 65 6e 63 29 22 }
        $h5 = { 73 68 65 6c 6c 5f 65 78 65 63 }
        $h6 = { 65 76 61 6c }
        $h7 ={ 63 68 6d 6f 64 20 2b 78 20 }
        $h8 = { 73 75 62 70 72 6f 63 65 73 73 2e 50 6f 70 65 6e }
    condition:
        $a at 0 and filesize < 5KB and (all of ($b*) or all of ($c*) or  all of ($d*)) and any of ($e*) and $f and any of ($g*) and any of ($h*)
}

rule XProtect_MACOS_5af1486
{
    meta:
        description = "MACOS.5af1486"
    strings:
        $a1 = { 00 70 72 6f 6d 70 74 00 69 63 6f 6e 00 }
        $a2 = { 00 64 61 74 61 31 00 70 6c 69 73 74 00 }
        $b1 = { 55 48 89 e5 48 83 ec 50 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? b9 ?? ?? ?? ?? 89 ca 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 89 c7 48 ?? ?? ?? e8 ?? ?? ?? ?? c7 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 8b ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 c7 48 ?? ?? ?? e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 0f 85 ?? ?? ?? ?? 48 ?? ?? ?? 48 83 c4 50 5d c3 e8 ?? ?? ?? ?? }

    condition:
        Macho and (filesize < 2MB) and all of them
}

rule XProtect_MACOS_03b5cbe
{
    meta:
        description = "MACOS.03b5cbe"
    strings:
		$a = { 48 ?? ?? ?? ?? ?? ?? 31 c0 e8 ?? ?? ?? ?? 49 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 41 ff d6 49 ?? ?? ?? 49 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? b9 01 00 00 00 41 ff d6 49 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 41 ff d6 84 c0 74 ?? }
		$b = { 73 74 61 74 75 73 2e 70 6c 69 73 74 }
		$c = { 74 72 69 67 67 65 72 }

	condition:
		Macho and (filesize < 100KB) and all of them
}

rule XProtect_MACOS_ce3281e
{
    meta:
        description = "MACOS.ce3281e"
    strings:
        $a = { 4c ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 c7 e8 ?? ?? ?? ?? 49 89 c5 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4c ?? ?? ?? ?? ?? ?? 31 c0 4c 89 f7 4c 89 e9 41 ff d4 48 89 c7 e8 ?? ?? ?? ?? 48 89 c3 4c ?? ?? ?? ?? ?? ?? 4c 89 ef 41 ff d6 4c ?? ?? ?? ?? ?? ?? 31 c0 4c 89 ff 48 89 de e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 41 ff d4 48 ?? ?? ?? ?? ?? ?? 48 89 c7 48 ?? ?? ?? 48 89 da 41 ff d4 49 89 c5 48 ?? ?? ?? ?? ?? ?? 4c 89 ef 41 ff d4 48 89 c7 e8 ?? ?? ?? ?? 48 89 c3 31 c0 4c 89 ff 48 89 de e8 ?? ?? ?? ?? 48 89 df 41 ff d6 4d 85 ed 74 ?? }
        $b = { 50 61 74 68 20 74 6f 20 70 72 65 66 3a 20 25 40 }
        $c = { 73 65 61 72 63 68 76 }
        $d = { 66 6f 72 6d 3d 41 50 4d 43 53 31 }
        $e = { 2f 4c 69 62 72 61 72 79 2f 50 72 65 66 65 72 65 6e 63 65 73 2f 70 72 65 66 2e 70 6c 69 73 74 }
        $f = { 66 72 3d 61 61 70 6c 77 }

    condition:
        Macho and (filesize < 100KB) and all of them
}

rule XProtect_MACOS_9bdf6ec
{
    meta:
        description = "MACOS.9bdf6ec"
    strings:
        $a1 = { 48 8b 3d ?? ?? ?? ?? e8 ?? ?? ?? ?? 49 89 c4 48 89 df e8 ?? ?? ?? ?? 48 89 cb 48 89 c7 48 89 d6 48 89 da e8 ?? ?? ?? ?? 49 89 c6 48 89 df e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? be 18 00 00 00 ba 07 00 00 00 48 8d 3d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 c3 4c 89 6b 10 48 8d 05 ?? ?? ?? ?? 48 89 45 b0 48 89 5d b8 48 8b 05 ?? ?? ?? ?? 48 89 45 90 c7 45 98 00 00 00 42 c7 45 9c 00 00 00 00 0f 28 45 80 0f 11 45 a0 48 8d 7d 90 e8 ?? ?? ?? ?? 49 89 c7 4c 89 ef e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 48 8b 35 ?? ?? ?? ?? 4c 89 e7 4c 89 f2 4c 89 f9 e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 4c 89 f7 e8 ?? ?? ?? ?? 48 8b 3d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 35 ?? ?? ?? ?? 48 89 c7 f3 0f 7e 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 55 c8 a8 01 }
        $a2 = { e8 ?? ?? ?? ?? 41 80 e7 01 44 88 78 10 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 89 4b 20 48 89 43 28 48 ?? ?? ?? ?? ?? ?? 48 89 03 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 66 48 0f 6e c0 48 ?? ?? ?? ?? ?? ?? 66 48 0f 6e c8 66 0f 6c c8 f3 0f 7f 4b 10 48 89 df e8 ?? ?? ?? ?? 49 89 c7 48 ?? ?? ?? e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 4c 89 e2 4c 89 f9 e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 4c 89 e7 e8 ?? ?? ?? ?? 4c 89 f7 4c 89 ee e8 ?? ?? ?? ?? }
        $a3 = { 48 89 c3 4c 8b 7d b8 4c 89 ef e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4c 89 e7 4c 89 f2 48 89 d9 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 4c 89 f7 e8 ?? ?? ?? ?? }
        $a4 = { 49 8B ?? 00 4C 89 ?? E8 37 ?? 00 00 48 8D ?? ?? ?? 00 00 48 39 C3 74 ?? 48 8D ?? ?? ?? 00 00 48 BE 00 00 00 00 00 00 00 80 48 09 ?? 48 BF 30 00 00 00 00 00 00 D0 FF 55 ?? EB ?? 48 8D ?? ?? ?? 00 00 48 BE 00 00 00 00 00 00 00 80 48 09 ?? 48 BF 30 00 00 00 00 00 00 D0 E8 6F ?? 00 00 }
        $a5 = {48 8B ?? ?? ?? 00 00 4C 8D ?? ?? FF FF FF 31 F6 48 89 DF E8 ?? ?? 00 00 49 89 C6 49 89 D5 48 89 DF 4C 89 E6 41 FF ?? ?? 4C 89 E8 48 C1 ?? ?? 48 3D ?? 00 00 00 0F 87 ?? ?? 00 00 4C 89 E8 48 C1 ?? ?? 3C ?? 0F 84 ?? 00 00 00 3C ?? 74 ?? 3C ?? 0F 84 ?? 00 00 00 4C 89 E8 48 C1 ?? ?? 0F B6 ?? 48 85 DB 75 ?? E9 ?? 00 00 00 49 8B ?? ?? 49 2B ?? ?? 0F 80 ?? ?? 00 00 }
        $b1 = { 73 68 6f 77 50 72 65 66 65 72 65 6e 63 65 73 46 6f 72 45 78 74 65 6e 73 69 6f 6e 57 69 74 68 49 64 65 6e 74 69 66 69 65 72 3a 63 6f 6d 70 6c 65 74 69 6f 6e 48 61 6e 64 6c 65 72 3a }
        $b2 = { 67 65 74 53 74 61 74 65 4f 66 53 61 66 61 72 69 45 78 74 65 6e 73 69 6f 6e 57 69 74 68 49 64 65 6e 74 69 66 69 65 72 3a 63 6f 6d 70 6c 65 74 69 6f 6e 48 61 6e 64 6c 65 72 3a }
        $c1 = { 6d 61 63 62 75 69 6c 64 65 72 5f 62 75 69 6c 64 73 }
        $c2 = { 4c 6f 63 61 6c 53 61 66 61 72 69 41 70 70 45 78 74 }
        $c3 = { 73 65 61 72 63 68 48 69 73 74 6f 72 79 }
        $c4 = { 6d 61 74 63 68 44 61 74 61 54 69 6d 65 72 }
        $c5 = { 6f 70 65 6e 50 72 65 66 }
        $c6 = { 67 65 74 53 79 73 74 65 6d 55 55 49 44 }
        $c7 = { 70 72 6f 63 65 73 73 49 6e 66 6f }
        $c8 = { 61 72 67 75 6d 65 6e 74 73 }
        $c9 = { 5f 49 4f 53 65 72 76 69 63 65 4d 61 74 63 68 69 6e 67 }
        $c10 = { 48 BF 49 4F 50 6C 61 74 66 6F 48 BE 72 6D 55 55 49 44 00 EE }

    condition:
        Macho and (filesize < 200KB) and (1 of ($a*)) and (all of ($b*)) and (2 of ($c*))
}

rule XProtect_MACOS_e79dc35
{
    meta:
        description = "MACOS.e79dc35"
    strings:
        $a = { 73 65 61 72 63 68 [2-12] 2e 61 6b 61 6d 61 69 68 64 2e 6e 65 74 2f }
        $b1 = { 49 be 79 73 00 00 00 00 00 ea 49 ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 d8 e8 ?? ?? ?? ?? be 02 00 00 00 4c 89 e7 e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 49 81 c6 f5 00 00 00 48 89 df 4c 89 ee 4c 89 f2 e8 ?? ?? ?? ?? 49 89 dd e8 ?? ?? ?? ?? 49 89 c7 41 ?? ?? ?? ?? 4c 89 e3 49 c7 c4 ff ff ff ff 49 d3 e4 49 f7 d4 4d 21 e7 4c 89 f8 48 c1 e8 06 48 ?? ?? ?? ?? 4c 0f a3 f8 0f 83 ?? ?? ?? ?? }
        $b2 = { 4c 89 ef e8 ?? ?? ?? ?? 48 ?? 61 62 70 2d 64 61 74 61 48 be 00 00 00 00 00 00 00 e8 e8 ?? ?? ?? ?? 49 89 c4 48 ?? ?? ?? ?? ?? ?? 48 85 ff 75 ?? }
        $b3 = { 49 89 c6 48 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 49 89 c7 4c 8b 6d b8 4c 89 ef e8 ?? ?? ?? ?? 48 8b bd 20 ff ff ff 4c 89 ee e8 ?? ?? ?? ?? 49 89 c4 48 ?? ?? ?? ?? ?? ?? 4c 89 ff 48 89 c2 48 89 d9 e8 ?? ?? ?? ?? 48 89 c3 4c 89 ef e8 ?? ?? ?? ?? 4c 89 e7 e8 ?? ?? ?? ?? 48 85 db 0f 84 ?? ?? ?? ?? }
        $b4 = { 48 8d b5 a0 fd ff ff 48 89 c7 e8 ?? ?? ?? ?? 4c 89 fa 48 89 55 a8 49 89 c7 0f 28 ?? ?? ?? ?? ?? 41 0f 11 47 10 48 ?? ?? ?? ?? ?? ?? 66 48 0f 6e c0 b8 02 00 00 00 66 48 0f 6e c8 66 0f 6c c1 66 0f 7f 4d c0 }
        $b5 = { 49 ff c7 31 d2 4c 89 f8 48 f7 75 c0 48 8b 5d c8 48 3b 53 10 0f 82 ?? ?? ?? ?? }
        $c1 = { 6c 61 73 74 48 65 61 72 74 62 65 61 74 }
        $c2 = { 73 65 73 73 69 6f 6e 47 75 69 64 }
        $c3 = { 65 78 74 65 6e 73 69 6f 6e 49 64 }
        $c4 = { 75 73 65 72 47 75 69 64 }
        $c5 = { 41 70 70 45 78 74 48 65 61 72 74 62 65 61 74 }
        $c6 = { 69 73 4e 65 77 53 65 61 72 63 68 }
        $c7 = { 73 65 6e 64 48 65 61 72 74 62 65 61 74 }
        $c8 = { 53 61 66 61 72 69 45 78 74 65 6e 73 69 6f 6e 48 61 6e 64 6c 65 72 }
        $c9 = { 6d 65 73 73 61 67 65 52 65 63 65 69 76 65 64 }
        $d1 = { 48 89 CA 48 83 E2 FC 48 8D 5A ?? 48 89 DF 48 C1 EF ?? 48 FF C7 89 FE 83 E6 ?? 48 83 FB 0C 73 18 66 0F EF C0 31 FF 66 0F EF C9 48 85 F6 }
        $e1 = { 5f 49 4f 53 65 72 76 69 63 65 47 65 74 4d 61 74 63 68 69 6e 67 53 65 72 76 69 63 65 }
        $e2 = { 5f 49 4f 53 65 72 76 69 63 65 4d 61 74 63 68 69 6e 67 }
        $e3 = { 53 46 53 61 66 61 72 69 50 61 67 65 50 72 6f 70 65 72 74 69 65 73 }
        $f1 = { 48 B8 53 55 50 45 52 53 54 52 48 89 85 ?? FE FF FF 48 B8 49 4E 47 44 55 44 45 EF }
        $f2 = { 49 FF C7 31 D2 4C 89 F8 48 F7 [2-5] 48 3B 53 10 }
        $f3 = { 48 BF 49 4F 50 6C 61 74 66 6F 48 BE 72 6D 55 55 49 44 00 EE }
        $f4 = { 48 89 55 C8 0F B6 44 13 20 4C 8B B5 50 FF FF FF 48 8B 8D 58 FF FF FF 48 89 CA 48 C1 EA 3E 80 FA 01 74 2D }
        $f5 = { 48 B8 59 57 30 54 64 53 54 52 }

    condition:
        Macho and (filesize < 2MB) and ((($a or any of ($b*)) and (2 of ($c*))) or (any of ($d*) and (all of ($e*))) or ((all of ($e*)) and 4 of ($f*))) and #c8 > 10
}

rule XProtect_MACOS_BUNDLORE
{
    meta:
        description = "MACOS.BUNDLORE"
    strings:
        $a1 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4c 89 ff 41 ff d5 48 ?? ?? ?? c6 03 00 48 ?? ?? ?? ?? ?? ?? 4c 89 f6 41 ff d5 48 ?? ?? ?? ?? ?? ?? 48 89 c7 48 89 da 41 ff d5 48 89 c3 48 ?? ?? ?? ?? ?? ?? 4c 89 ff 48 89 da 41 ff d5 48 ?? ?? ?? ?? ?? ?? 4c 89 ff 41 ff d5 84 c0 74 ?? }
        $a2 = { 83 7e f8 00 78 ?? 4c 89 e7 e8 ?? ?? ?? ?? 49 8b 34 24 48 8b 45 c8 42 80 3c 3e 5c 75 ?? 4d 8d 6f 01 4c 3b 6e e8 73 ?? 83 7e f8 00 78 ?? 4c 89 }
        $b1 = { 63 6f 6d 2e 6d 6d 2d 69 6e 73 74 61 6c 6c 2d 6d 61 63 6f 73 2e 77 77 77 }
        $b2 = { 26 66 75 6e 6e 65 6c 3d }
        $b3 = { 4d 4d 5f 50 41 53 53 57 44 }
    condition:
		Macho and (any of ($a*)) or (all of ($b*))
}

rule XProtect_MACOS_0e62876
{
    meta:
        description = "MACOS.0e62876"
	strings:
  	    $a = { 57 65 62 74 6f 6f 6c 73 43 6f 6e 66 69 67 }
        $b = { 53 74 61 72 74 69 6e 67 20 70 72 6f 74 65 63 74 6f 72 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e }
        $c = { 6a 73 46 72 6f 6d 41 70 70 6c 65 45 76 65 6e 74 73 45 6e 61 62 6c 65 64 }
        $d = { 65 6e 61 62 6c 65 4a 73 46 72 6f 6d 41 70 70 6c 65 45 76 65 6e 74 73 }
        $e = { 43 6c 69 63 6b 47 65 6e 65 72 61 74 6f 72 }
        $f = { 73 6f 75 74 65 72 }
    condition:
        Macho and 3 of them
}

rule XProtect_MACOS_de444f2
{
    meta:
        description = "MACOS.de444f2"
    strings:
        $a1 = { (48 | 49) 63 ?? 41 32 ?? ?? (88 8D ?? ?? ?? ?? 48 | 48) ?? ?? 74 ?? 88 ?? 48 ?? ?? ?? eb ?? }
        $a2 = { 48 8b [2-5] 48 89 ?? 48 f7 d? 48 01 c? 44 88 ?? ?? 48 8b [2-5] 48 89 c? 48 f7 d? 48 03 [2-5] ( 44 88 | 88 0c ) [1-2] 4? 83 f? ?? }
        $a3 = { b1 ?? 41 be 01 00 00 00 4c 8d bd 7f ff ff ff 44 89 eb eb ?? }
        $a4 = { 41 ff c? 90 49 63 c? 48 ?? ?? ?? ?? ?? ?? ( 44 32 34 0a 48 39 d8 74 ?? | 32 0c 02 88 8d 7f ff ff ff 48 8b 45 88 48 3b 45 90 74 ?? ) }
        $a5 = { 90 0f 57 c0 4c 8d 65 80 41 0f 29 04 24 49 c7 44 24 }
        $a6 = { ff cb 90 48 63 c3 48 ?? ?? ?? ?? ?? ?? 32 0c 02 48 8b 85 78 ff ff ff 48 3b 45 80 74 ?? }
        $a7 = { 45 85 ?? 41 8d 4? ff b? ?? ?? ?? ?? 0f 4e c? 4? 8a ?? ?? b0 4? ff c? 4? 89 c6 }
        $a8 = { 44 8a 74 05 b0 48 ff c0 48 89 85 ( a0 fa | 38 f4 ) ff ff }
        $a9 = { 46 8a ?4 ?? b0 49 63 c5 48 ?? ?? ?? ?? ?? ?? 8a 04 08 88 85 ?8 f5 ff ff 4? 89 ?d ?8 fa ff ff 4? 89 ?d ?0 fa ff ff 48 83 a5 ?8 fa ff ff 00 4? 89 ?f 6a ?? 5e e8 ?? ?? ?? ?? 44 32 ?? ?8 f5 ff ff 44 88 ?5 ?0 f5 ff ff 48 8d bd ?? fa ff ff 48 8d b5 ?0 f5 ff ff e8 ?? ?? ?? ?? 4? 8? ?? 4? 8d ?5 }
        $a10 = { 90 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 48 89 df 48 8d b5 08 f6 ff ff e8 ?? ?? ?? ?? 48 8b 85 b0 fa ff ff 0f b6 78 10 e8 ?? ?? ?? ?? 90 48 89 df e8 ?? ?? ?? ?? 49 ff c? }
        $a11 = { 83 c2 fc 85 d2 6a ?? 58 0f 4e d0 4c 89 ef 48 89 de 6a ff 59 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 4c 89 ef e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff 48 8d b5 98 f5 ff ff e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff e8 ?? ?? ?? ?? 49 ff c6 }
        $a12 = { 0F 57 C0 0F 29 45 B0 48 C7 45 ?? 00 00 00 00 41 BD ?? 00 00 00 41 B6 ?? 31 DB BF ?? 00 00 00 31 C0 41 BF ?? 00 00 00 EB ??45 85 FF 41 8D ?? ?? 41 0F 4E CD 44 0F B6 ?? ?? ?? ?? FF FF 48 8B 45 ?? 48 8B ?? ?? 48 FF C7 41 89 CF 90 90 49 63 CF 46 32 ?? ?? }
        $a13 = { 48 63 c3 48 ?? ?? ?? ?? ?? ?? 8a 04 08 42 32 44 2d b0 88 85 70 ff ff ff [2-6] f? 4c 89 e6 e8 ?? ?? ?? ?? 85 db 8d 43 ff 89 c3 ?? [0-4] 0f 4e d? 4c 89 ff 89 de e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 49 ff c5 }
        $a14 = { 85 db 41 0f 4e dc 42 8a 4c 2d b0 49 ff c5 }
        $a15 = { 49 63 c7 48 ?? ?? ?? ?? ?? ?? 8a 04 08 32 44 1d b0 88 85 70 ff ff ff 4c 89 f7 4c 89 ee e8 ?? ?? ?? ?? 45 85 ff 41 8d 47 ff 41 0f 4e c4 48 ff c3 41 89 c7 }
        $b1 = { 41 64 6d 69 6e 20 53 75 63 63 65 73 73 3a 20 25 40 }
        $b2 = { 45 72 72 6f 72 3a 20 25 40 }
        $b3 = { 40 40 41 70 70 50 61 74 68 40 40 2f 43 6f 6e 74 65 6e 74 73 2f 4d 61 63 4f 53 }
        $b4 = { 72 75 6e 41 70 70 }
    condition:
        Macho and filesize < 15MB and (any of ($a*)) and (any of ($b*))
}

rule XProtect_MACOS_b70290c
{
    meta:
        description = "MACOS.b70290c"
    strings:
        $a1 = { (48 | 49) 63 ?? 41 32 ?? ?? (88 8D ?? ?? ?? ?? 48 | 48) ?? ?? 74 ?? 88 ?? 48 ?? ?? ?? eb ?? }
        $a2 = { 48 8b [2-5] 48 89 ?? 48 f7 d? 48 01 c? 44 88 ?? ?? 48 8b [2-5] 48 89 c? 48 f7 d? 48 03 [2-5] ( 44 88 | 88 0c ) [1-2] 4? 83 f? ?? }
        $a3 = { b1 ?? 41 be 01 00 00 00 4c 8d bd 7f ff ff ff 44 89 eb eb ?? }
        $a4 = { 41 ff c? 90 49 63 c? 48 ?? ?? ?? ?? ?? ?? ( 44 32 34 0a 48 39 d8 74 ?? | 32 0c 02 88 8d 7f ff ff ff 48 8b 45 88 48 3b 45 90 74 ?? ) }
        $a5 = { 90 0f 57 c0 4c 8d 65 80 41 0f 29 04 24 49 c7 44 24 }
        $a6 = { ff cb 90 48 63 c3 48 ?? ?? ?? ?? ?? ?? 32 0c 02 48 8b 85 78 ff ff ff 48 3b 45 80 74 ?? }
        $a7 = { 45 85 ?? 41 8d 4? ff b? ?? ?? ?? ?? 0f 4e c? 4? 8a ?? ?? b0 4? ff c? 4? 89 c6 }
        $a8 = { 44 8a 74 05 b0 48 ff c0 48 89 85 ( a0 fa | 38 f4 ) ff ff }
        $a9 = { 46 8a ?4 ?? b0 49 63 c5 48 ?? ?? ?? ?? ?? ?? 8a 04 08 88 85 ?8 f5 ff ff 4? 89 ?d ?8 fa ff ff 4? 89 ?d ?0 fa ff ff 48 83 a5 ?8 fa ff ff 00 4? 89 ?f 6a ?? 5e e8 ?? ?? ?? ?? 44 32 ?? ?8 f5 ff ff 44 88 ?5 ?0 f5 ff ff 48 8d bd ?? fa ff ff 48 8d b5 ?0 f5 ff ff e8 ?? ?? ?? ?? 4? 8? ?? 4? 8d ?5 }
        $a10 = { 90 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 48 89 df 48 8d b5 08 f6 ff ff e8 ?? ?? ?? ?? 48 8b 85 b0 fa ff ff 0f b6 78 10 e8 ?? ?? ?? ?? 90 48 89 df e8 ?? ?? ?? ?? 49 ff c? }
        $a11 = { 83 c2 fc 85 d2 6a ?? 58 0f 4e d0 4c 89 ef 48 89 de 6a ff 59 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 4c 89 ef e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff 48 8d b5 98 f5 ff ff e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff e8 ?? ?? ?? ?? 49 ff c6 }
        $a12 = { 0F 57 C0 0F 29 45 B0 48 C7 45 ?? 00 00 00 00 41 BD ?? 00 00 00 41 B6 ?? 31 DB BF ?? 00 00 00 31 C0 41 BF ?? 00 00 00 EB ??45 85 FF 41 8D ?? ?? 41 0F 4E CD 44 0F B6 ?? ?? ?? ?? FF FF 48 8B 45 ?? 48 8B ?? ?? 48 FF C7 41 89 CF 90 90 49 63 CF 46 32 ?? ?? }
        $a13 = { 48 63 c3 48 ?? ?? ?? ?? ?? ?? 8a 04 08 42 32 44 2d b0 88 85 70 ff ff ff [2-6] f? 4c 89 e6 e8 ?? ?? ?? ?? 85 db 8d 43 ff 89 c3 ?? [0-4] 0f 4e d? 4c 89 ff 89 de e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 49 ff c5 }
        $a14 = { 85 db 41 0f 4e dc 42 8a 4c 2d b0 49 ff c5 }
        $a15 = { 49 63 c7 48 ?? ?? ?? ?? ?? ?? 8a 04 08 32 44 1d b0 88 85 70 ff ff ff 4c 89 f7 4c 89 ee e8 ?? ?? ?? ?? 45 85 ff 41 8d 47 ff 41 0f 4e c4 48 ff c3 41 89 c7 }
        $b1 = { 57 65 62 56 69 65 77 }
        $b2 = { 4a 53 45 78 70 6f 72 74 }
    condition:
        Macho and filesize < 15MB and (any of ($a*)) and (any of ($b*))
}

rule XProtect_MACOS_22d71e9
{
    meta:
        description = "MACOS.22d71e9"
    strings:
        $a1 = { (48 | 49) 63 ?? 41 32 ?? ?? (88 8D ?? ?? ?? ?? 48 | 48) ?? ?? 74 ?? 88 ?? 48 ?? ?? ?? eb ?? }
        $a2 = { 48 8b [2-5] 48 89 ?? 48 f7 d? 48 01 c? 44 88 ?? ?? 48 8b [2-5] 48 89 c? 48 f7 d? 48 03 [2-5] ( 44 88 | 88 0c ) [1-2] 4? 83 f? ?? }
        $a3 = { b1 ?? 41 be 01 00 00 00 4c 8d bd 7f ff ff ff 44 89 eb eb ?? }
        $a4 = { 41 ff c? 90 49 63 c? 48 ?? ?? ?? ?? ?? ?? ( 44 32 34 0a 48 39 d8 74 ?? | 32 0c 02 88 8d 7f ff ff ff 48 8b 45 88 48 3b 45 90 74 ?? ) }
        $a5 = { 90 0f 57 c0 4c 8d 65 80 41 0f 29 04 24 49 c7 44 24 }
        $a6 = { ff cb 90 48 63 c3 48 ?? ?? ?? ?? ?? ?? 32 0c 02 48 8b 85 78 ff ff ff 48 3b 45 80 74 ?? }
        $a7 = { 45 85 ?? 41 8d 4? ff b? ?? ?? ?? ?? 0f 4e c? 4? 8a ?? ?? b0 4? ff c? 4? 89 c6 }
        $a8 = { 44 8a 74 05 b0 48 ff c0 48 89 85 ( a0 fa | 38 f4 ) ff ff }
        $a9 = { 46 8a ?4 ?? b0 49 63 c5 48 ?? ?? ?? ?? ?? ?? 8a 04 08 88 85 ?8 f5 ff ff 4? 89 ?d ?8 fa ff ff 4? 89 ?d ?0 fa ff ff 48 83 a5 ?8 fa ff ff 00 4? 89 ?f 6a ?? 5e e8 ?? ?? ?? ?? 44 32 ?? ?8 f5 ff ff 44 88 ?5 ?0 f5 ff ff 48 8d bd ?? fa ff ff 48 8d b5 ?0 f5 ff ff e8 ?? ?? ?? ?? 4? 8? ?? 4? 8d ?5 }
        $a10 = { 90 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 48 89 df 48 8d b5 08 f6 ff ff e8 ?? ?? ?? ?? 48 8b 85 b0 fa ff ff 0f b6 78 10 e8 ?? ?? ?? ?? 90 48 89 df e8 ?? ?? ?? ?? 49 ff c? }
        $a11 = { 83 c2 fc 85 d2 6a ?? 58 0f 4e d0 4c 89 ef 48 89 de 6a ff 59 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 4c 89 ef e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff 48 8d b5 98 f5 ff ff e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff e8 ?? ?? ?? ?? 49 ff c6 }
        $a12 = { 0F 57 C0 0F 29 45 B0 48 C7 45 ?? 00 00 00 00 41 BD ?? 00 00 00 41 B6 ?? 31 DB BF ?? 00 00 00 31 C0 41 BF ?? 00 00 00 EB ??45 85 FF 41 8D ?? ?? 41 0F 4E CD 44 0F B6 ?? ?? ?? ?? FF FF 48 8B 45 ?? 48 8B ?? ?? 48 FF C7 41 89 CF 90 90 49 63 CF 46 32 ?? ?? }
        $a13 = { 48 63 c3 48 ?? ?? ?? ?? ?? ?? 8a 04 08 42 32 44 2d b0 88 85 70 ff ff ff [2-6] f? 4c 89 e6 e8 ?? ?? ?? ?? 85 db 8d 43 ff 89 c3 ?? [0-4] 0f 4e d? 4c 89 ff 89 de e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 49 ff c5 }
        $a14 = { 85 db 41 0f 4e dc 42 8a 4c 2d b0 49 ff c5 }
        $a15 = { 49 63 c7 48 ?? ?? ?? ?? ?? ?? 8a 04 08 32 44 1d b0 88 85 70 ff ff ff 4c 89 f7 4c 89 ee e8 ?? ?? ?? ?? 45 85 ff 41 8d 47 ff 41 0f 4e c4 48 ff c3 41 89 c7 }
        $b1 = { 57 65 62 56 69 65 77 }
        $b2 = { 4a 53 45 78 70 6f 72 74 }
    condition:
        Macho and filesize < 15MB and (any of ($a*)) and (not any of ($b*))
}

rule XProtect_MACOS_6175e25
{
    meta:
        description = "MACOS.6175e25"
    strings:
        $a1 = { 00 25 40 25 40 25 40 25 40 00 25 63 00 }
        $a2 = { 64 65 6c 65 74 65 41 70 70 42 79 53 65 6c 66 }
        $a3 = { 65 6e 63 72 79 70 74 44 65 63 72 79 70 74 4f 70 65 72 61 74 69 6f 6e }
        $a4 = { 45 6e 63 6f 64 65 44 65 63 6f 64 65 4f 70 73 }
        $a5 = { 63 72 65 61 74 46 69 6c 65 4f 6e 54 65 6d 70 3a 73 63 72 70 4e 61 6d 65 3a }
    condition:
        Macho and all of ($a*) and filesize < 200KB
}

rule XProtect_MACOS_d1e06b8
{
    meta:
        description = "MACOS.d1e06b8"
    strings:
        $a1 =  { 2f 00 2f 00 2a 00 45 00 72 00 72 00 6f 00 72 00 43 00 6f 00 64 00 65 00 2a 00 5c 00 5c 00 }
        $a2 =  { 28 00 3c 00 5e 00 5e 00 5e 00 5e 00 3e 00 29 00 }
        $a3 =  { 74 72 61 63 6b 69 6e 67 58 4d 4c }
        $a4 =  { 41 00 6c 00 6c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 41 00 70 00 70 00 73 00 }
        $a5 =  { 6f 66 66 65 72 5f 70 61 72 61 6d 65 74 65 72 }
        $a6 =  { 6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 }

    condition:
        PE and all of ($a*) and filesize < 200KB
}

rule XProtect_OSX_28a9883
{
    meta:
        description = "OSX.28a9883"

    strings:

        $a1 = { 3A 6C 61 62 65 6C 3A 70 6C 69 73 74 50 61 74 68 3A }
        $a2 = { 3A 62 69 6E 3A 70 6C 69 73 74 3A }
        $a3 = { 21 40 23 24 7E 5E 26 2A 28 29 5B 5D 7B 7D 3A 3B 3C 3E 2C 2E 31 71 32 77 33 65 34 72 35 74 36 79 37 75 38 69 39 6F 30 70 41 5A 53 58 44 43 46 56 47 42 48 4E 4A 4D 4B 4C 51 57 45 52 54 59 55 49 }

    condition:
        Macho and all of ($a*)
}

rule XProtect_OSX_Bundlore_D
{
    meta:
        description = "OSX.Bundlore.D"

    strings:

        $a1 = { 20 00 65 00 63 00 68 00 6F 00 20 00 }
        $a2 = { 20 00 7C 00 20 00 6F 00 70 00 65 00 6E 00 73 00 73 00 6C 00 20 00 65 00 6E 00 63 00 20 00 2D 00 61 00 65 00 73 00 2D 00 32 00 35 00 36 00 2D 00 63 00 66 00 62 00 20 00 2D 00 70 00 61 00 73 00 73 00 20 00 70 00 61 00 73 00 73 00 3A }
        $a3 = { 00 2D 00 73 00 61 00 6C 00 74 00 20 00 2D 00 41 00 20 00 2D 00 61 00 20 00 2D 00 64 00 20 00 7C 00 20 00 62 00 61 00 73 00 68 00 20 00 2D 00 73 }
        $b1 = { 46 61 73 64 55 41 53 }

    condition:
        $b1 at 0 and all of ($a*) and filesize <= 3000
}

rule XProtect_OSX_Particle_Smasher_A
{
    meta:
        description = "OSX.ParticleSmasher.A"

    strings:
        $a1 = { 63 6F 75 6C 64 6E 27 74 20 6F 70 65 6E 20 74 68 65 20 64 62 00 }
        $a2 = { 25 40 2F 4F 50 45 52 41  2E 7A 69 70 00 }
        $a3 = { 25 40 2F 43 48 52 4F 4D 45 5F 25 40 2E 7A 69 70 00 }
        $a4 = { 25 40 2F 53 41 46 41 52 49 2E 7A 69 70 00 }
        $a5 = { 25 40 2F 46 49 52 45 46 4F 58 5F 25 40 2E 7A 69 70 00 }
        $a6 = { 63 70 20 25 40 2F 70 6C 61 63 65 73 2E 73 71 6C 69 74 65 20 25 40 2F 70 6C 61 63 65 73 2E 73 71 6C 69 74 65 2E 64 75 6D 70 00 }
        $a7 = { 63 70 20 25 40 2F 48 69 73 74 6F 72 79 20 25 40 2F 48 69 73 74 6F 72 79 2E 64 75 6D 70 00 }

    condition:
      Macho and filesize < 450000 and all of ($a*)
}

rule XProtect_OSX_HiddenLotus_A
{
    meta:
        description = "OSX.HiddenLotus.A"
    strings:
        $a1 = { 00 2F 00 25 6C 64 00 00 00 00 00 00 00 00 00 00 00 }
        $a2 = { 00 72 62 00 00 20 26 00 00 00 00 00 00 00 }
        $a3 = { 00 25 64 00 20 32 3E 26 31 00 72 00 0D 0A 00 00 }
        $a4 = { 00 25 30 32 78 00 00 00 00 00 00 00 }
        $a5 = { 00 3D 00 3B 00 00 00 }
    condition:
        Macho and all of ($a*) and filesize < 180000
}

rule XProtect_OSX_Mughthesec_B
{
    meta:
        description = "OSX.Mughthesec.B"
    strings:
        $a1 = { 42 75 6E 64 6C 65 4D 65 55 70 }
        $a2 = { 50 75 62 6C 69 73 68 65 72 4F 66 66 65 72 53 74 61 74 65 }
        $a3 = { 49 6E 73 74 61 6C 6C 50 72 6F 67 72 65 73 73 53 74 61 74 65 }
        $a4 = { 41 64 76 65 72 74 69 73 65 72 4F 66 66 65 72 53 74 61 74 65 }
        $b1 = { 42 65 72 54 61 67 67 65 64 44 61 74 61 }
        $b2 = { 42 45 52 50 72 69 6E 74 56 69 73 69 74 6F 72 }
    condition:
        Macho and filesize < 3000000 and all of them
}

rule XProtect_OSX_HMining_D
{
    meta:
        description = "OSX.HMining.D"
    strings:
        $a1 = { 72 ?? 75 ?? 6E ?? 41 ?? 6C ?? 6C ?? 41 ?? 70 ?? 70 }
        $a2 = { 66 ?? 69 ?? 72 ?? 65 ?? 46 ?? 6F ?? 78 ?? 53 ?? 65 ?? 74 ?? 4E ?? 74 ?? 53 ?? 70 }
        $a3 = { 53 ?? 61 ?? 66 ?? 61 ?? 72 ?? 69 ?? 2E ?? 61 ?? 70 ?? 70 }
        $a4 = { 63 ?? 6F ?? 6D ?? 2E ?? 61 ?? 70 ?? 70 ?? 6C ?? 65 ?? 2E ?? 53 ?? 61 ?? 66 ?? 61 ?? 72 ?? 69 }
        $a5 = { 63 ?? 6F ?? 6D ?? 2E ?? 61 ?? 70 ?? 70 ?? 6C ?? 65 ?? 2E ?? 71 ?? 75 ?? 61 ?? 72 ?? 61 ?? 6E ?? 74 ?? 69 ?? 6E ?? 65 }
    condition:
        Macho and filesize <= 2000000 and all of ($a*)
}

rule XProtect_AdLoad_B_2 : dropper
{
    meta:
        description = "OSX.AdLoad.B.2"

    strings:
        $a1 = {48 8B ?? ?? ?? ?? ?? 48 8D 5D B8 48 89 03 C7 43 08 00 00 00 C2 C7 43 0C 00 00 00 00 48 8D ?? ?? ?? ?? ?? 48 89 43 10 48 8D ?? ?? ?? ?? ?? 48 89 43 18 4C 89 F7 ?? ?? ?? ?? ?? ?? 48 89 43 20 4C 89 FF 48 89 DE ?? ?? ?? ?? ?? 4C 89 FF ?? ?? ?? 48 8B 7B 20 ?? ?? ??
48 83 C4 30}
        $b1 = {67 65 74 53 61 66 61 72 69 56 65 72 73 69 6F 6E}

    condition:
        Macho and filesize < 300000 and $a1 and $b1
}

rule XProtect_AdLoad_B_1
{
    meta:
        description = "OSX.AdLoad.B.1"

    strings:
        $a1 = {73 65 74 49 6E 73 74 61 6C 6C 46 69 6E 69 73 68 65 64 54 65 78 74}
        $a2 = {73 65 74 46 69 6E 69 73 68 54 69 63 6B 49 6D 61 67 65 56 69 65 77}
        $a3 = {4F 66 66 65 72 43 6F 6E 74 72 6F 6C 6C 65 72}
        $a4 = {26 4F 46 46 45 52 5F 49 44 3D 25 40}

    condition:
        Macho and filesize < 400000 and (all of ($a*))
}


rule OSX_ExtensionsInstaller_A
{
    meta:
        description = "OSX.ExtensionsInstaller.A"
    strings:
        $a1 = {72 65 6D 6F 76 65 58 61 74 74 72 54 6F}
        $a2 = {67 65 74 43 72 79 70 74 65 64 44 61 74 61 46 72 6F 6D 55 72 6C}
        $a3 = {67 65 74 42 65 73 74 4F 66 66 65 72 43 6F 6E 66 69 67 3A 61 63 63 65 70 74 65 64 4F 66 66 65 72 73}
        $b1 = {53 61 66 61 72 69 45 78 74 65 6E 73 69 6F 6E 49 6E 73 74 61 6C 6C 65 72}
        $b2 = {54 61 72 43 6F 6D 70 72 65 73 73 6F 72}
    condition:
        Macho and filesize < 2500000 and all of them
}

rule XProtect_MACOS_51f7dde
{
    meta:
        description = "MACOS.51f7dde"
    strings:

        $a = { 63 6F 6D 2E 72 65 66 6F 67 2E 76 69 65 77 65 72 }
        $b = { 53 6D 6F 6B 65 43 6F 6E 74 72 6F 6C 6C 65 72 }
        $c1 = { 75 70 64 61 74 65 53 6D 6F 6B 65 53 74 61 74 75 73 }
        $c2 = { 70 61 75 73 65 53 6D 6F 6B 65 3A }
        $c3 = { 72 65 73 75 6D 65 53 6D 6F 6B 65 3A }
        $c4 = { 73 74 6F 70 53 6D 6F 6B 65 3A }
    condition:
        Macho and filesize < 2MB and all of them
}

rule XProtect_MACOS_cb4abc2
{
    meta:
        description = "MACOS.cb4abc2"
    strings:
        $s1 = { 2F 4C 69 62 72 61 72 79 2F 4C 61 75 6E 63 68 41 67 65 6E 74 73 2F 63 6F 6D 2E 61 65 78 2D 6C 6F 6F 70 2E 61 67 65 6E 74 2E 70 6C 69 73 74 }
        $s2 = { 2F 4C 69 62 72 61 72 79 2F 4C 61 75 6E 63 68 44 61 65 6D 6F 6E 73 2F 63 6F 6D 2E 61 65 78 2D 6C 6F 6F 70 2E 61 67 65 6E 74 2E 70 6C 69 73 74 }
        $s3 = { 2F 70 72 6F 63 2F 25 64 2F 74 61 73 6B }
        $s4 = { 2F 70 72 6F 63 2F 25 64 2F 63 6D 64 6C 69 6E 65 }
        $s5 = { 2F 70 72 6F 63 2F 25 64 2F 73 74 61 74 75 73 }
        $s6 = { 63 5F 32 39 31 30 2E 63 6C 73 }
        $s7 = { 6B 5F 33 38 37 32 2E 63 6C 73 }
        $s8 = { 2F 4C 69 62 72 61 72 79 2F 43 61 63 68 65 73 2F 63 6F 6D 2E 61 70 70 6C 65 2E 61 70 70 73 74 6F 72 65 2E 64 62 }
        $s9 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 36 35 2E 30 2E 33 33 32 35 2E 31 38 31 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
    condition:
        Macho and filesize < 1MB and all of them
}

rule XProtect_MACOS_fa6a259
{
    meta:
        description = "MACOS.fa6a259"
    strings:
        $s1 = { 63 6F 6D 2E 54 69 6E 6B 61 4F 54 50 }
        $s2 = { 2E 63 6F 6D 2E 54 69 6E 6B 61 4F 54 50 }
        $s3 = { 20 7E 2F 4C 69 62 72 61 72 79 2F 2E 6D 69 6E 61 20 3E 20 2F 64 65 76 2F 6E 75 6C 6C 20 32 3E 26 31 20 26 26 20 63 68 6D 6F 64 20 2B 78 20 7E 2F 4C 69 62 72 61 72 79 2F 2E 6D 69 6E 61 20 3E 20 2F 64 65 76 2F 6E 75 6C 6C 20 32 3E 26 31 20 26 26 20 7E 2F 4C 69 62 72 61 72 79 2F 2E 6D 69 6E 61 20 3E 20 2F 64 65 76 2F 6E 75 6C 6C 20 32 3E 26 31 }
        $s4 = { 63 75 72 6C 20 2D 6B 20 2D 6F 20 7E 2F 4C 69 62 72 61 72 79 2F 2E 6D 69 6E 61 20 68 74 74 70 73 3A 2F 2F 6C 6F 6E 65 65 61 67 6C 65 72 65 63 6F 72 64 73 2E 63 6F 6D 2F 77 70 2D 63 6F 6E 74 65 6E 74 2F 75 70 6C 6F 61 64 73 2F 32 30 32 30 2F 30 31 2F 69 6D 61 67 65 73 2E 74 67 7A 2E 30 30 31 20 3E 20 2F 64 65 76 2F 6E 75 6C 6C 20 32 3E 26 31 20 26 26 20 63 68 6D 6F 64 20 2B 78 20 7E 2F 4C 69 62 72 61 72 79 2F 2E 6D 69 6E 61 20 3E 20 2F 64 65 76 2F 6E 75 6C 6C 20 32 3E 26 31 20 26 26 20 7E 2F 4C 69 62 72 61 72 79 2F 2E 6D 69 6E 61 20 3E 20 2F 64 65 76 2F 6E 75 6C 6C 20 32 3E 26 31 }
    condition:
        Macho and filesize < 1MB and ( ($s1 and $s3) or ($s2 and $s4) )
}

rule XProtect_MACOS_61ee022
{
    meta:
        description = "MACOS.61ee022"
    strings:
        $s1 = { 68 74 74 70 73 3A 2F 2F 61 70 69 2E 6B 72 61 6B 65 6E 2E 63 6F 6D 2F 30 2F 70 75 62 6C 69 63 2F 4F 48 4C 43 3F 70 61 69 72 3D }
        $s2 = { 68 74 74 70 73 3A 2F 2F 61 70 69 2E 68 75 6F 62 69 2E 70 72 6F 2F 6D 61 72 6B 65 74 2F 68 69 73 74 6F 72 79 2F 6B 6C 69 6E 65 3F 70 65 72 69 6F 64 3D }
        $s3 = { 68 74 74 70 73 3A 2F 2F 61 70 69 2E 62 69 6E 61 6E 63 65 2E 63 6F 6D 2F 61 70 69 2F 76 33 2F 6B 6C 69 6E 65 73 3F 69 6E 74 65 72 76 61 6C 3D }
        $s4 = { 68 74 74 70 73 3A 2F 2F 61 70 69 2E 6B 72 61 6B 65 6E 2E 63 6F 6D 2F 30 2F 70 75 62 6C 69 63 2F 54 69 63 6B 65 72 3F 70 61 69 72 3D }
        $s5 = { 68 74 74 70 73 3A 2F 2F 61 70 69 2E 68 75 6F 62 69 2E 70 72 6F 2F 6D 61 72 6B 65 74 2F 64 65 74 61 69 6C 3F 73 79 6D 62 6F 6C 3D }
        $s6 = { 68 74 74 70 73 3A 2F 2F 61 70 69 2E 62 69 6E 61 6E 63 65 2E 63 6F 6D 2F 61 70 69 2F 76 33 2F 74 69 63 6B 65 72 2F 32 34 68 72 3F 73 79 6D 62 6F 6C 3D }
        $s7 = { 2F 56 6F 6C 75 6D 65 73 2F 57 6F 72 6B 2F 57 6F 72 6B 2F 43 6F 64 69 6E 67 2F }
        $s8 = { 45 6D 61 69 6C 20 69 73 20 69 6E 76 61 6C 69 64 61 74 65 2E }
        $s9 = { 50 61 73 73 77 6F 72 64 20 69 73 20 69 6E 63 6F 72 72 65 63 74 2E }
        $s10 = { 50 6C 65 61 73 65 20 69 6E 70 75 74 20 63 6F 6E 66 69 72 6D 20 70 61 73 73 77 6F 72 64 2E }
        $s11 = { 50 6C 65 61 73 65 20 69 6E 70 75 74 20 70 61 73 73 77 6F 72 64 2E }
        $s12 = { 53 75 63 63 65 73 73 66 75 6C 6C 79 20 63 72 65 61 74 65 64 20 61 20 6E 65 77 20 61 63 63 6F 75 6E 74 2E }
        $s13 = { 54 68 69 73 20 61 63 63 6F 75 6E 74 20 61 6C 72 65 61 64 79 20 65 78 69 73 74 73 2E }
        $s14 = { 50 61 73 73 77 6F 72 64 20 69 73 20 77 72 6F 6E 67 2E }
        $s15 = { 55 73 65 72 20 64 6F 65 73 20 6E 6F 74 20 65 78 69 73 74 21 }
    condition:
        Macho and filesize < 500KB and all of them
}

rule XProtect_MACOS_bb90861
{
    meta:
        description = "MACOS.bb90861"
    strings:
        $s1 = { 25 73 2E 6C 63 6B }
        $s2 = { 53 48 45 4C 4C }
        $s3 = { 2F 62 69 6E 2F 7A 73 68 }
        $s4 = { 5F 52 55 4E 5F 54 41 47 5F 53 45 52 56 45 52 31 }
        $s5 = { 5F 52 55 4E 5F 54 41 47 5F 53 45 52 56 45 52 32 }
        $s6 = { 5F 52 55 4E 5F 54 41 47 5F 50 52 4F 58 59 }
        $s7 = { 5F 52 55 4E 5F 54 41 47 5F 50 52 4F 58 59 5F 55 53 45 52 }
        $s8 = { 5F 52 55 4E 5F 54 41 47 5F 50 52 4F 58 59 5F 50 57 44 }
        $s9 = { 5F 52 55 4E 5F 54 41 47 5F 46 4F 52 57 41 52 44 }
        $s10 = { 5F 52 55 4E 5F 54 41 47 5F 54 41 52 47 45 54 }
        $s11 = { 5F 52 55 4E 5F 54 41 47 5F 4C 49 53 54 45 4E }
        $s12 = { 5F 52 55 4E 5F 54 41 47 5F 55 49 44 }
        $s13 = { 5F 52 55 4E 5F 54 41 47 5F 54 49 4D 45 5F 43 4F 4E 4E }
        $s14 = { 5F 45 58 50 4C 4F 52 45 52 5F 46 49 4C 54 45 52 }
        $s15 = { 5F 45 58 50 4C 4F 52 45 52 5F 44 49 52 5F 53 45 4C 46 }
        $s16 = { 5F 45 58 50 4C 4F 52 45 52 5F 44 49 52 5F 50 41 52 45 4E 54 }
        $s17 = { 5F 45 58 50 4C 4F 52 45 52 5F 53 54 52 5F 54 59 50 45 }
        $s18 = { 5F 45 58 50 4C 4F 52 45 52 5F 46 49 4C 45 5F 44 45 4C 45 54 45 5F 54 59 50 45 }
        $s19 = { 5F 46 49 4C 45 54 49 4D 45 5F 53 54 52 5F 54 59 50 45 }
        $s20 = { 5F 43 4D 44 5F 54 45 53 54 }
        $s21 = { 5F 43 4D 44 5F 52 55 4E }
        $s22 = { 5F 54 49 4D 45 5F 46 4F 52 4D 41 54 }
        $s23 = { 5F 43 4D 44 5F 53 55 43 43 45 53 53 }
        $s24 = { 5F 43 4D 44 5F 46 41 49 4C 45 44 }
        $s25 = { 5F 50 52 4F 58 59 5F 43 4F 4E 4E 45 43 54 }
        $s26 = { 5F 50 52 4F 58 59 5F 48 54 54 50 }
        $s27 = { 5F 50 52 4F 58 59 5F 55 53 45 52 5F 41 47 45 4E 54 }
        $s28 = { 5F 50 52 4F 58 59 5F 4B 45 45 50 5F 43 4F 4E 4E 45 43 54 49 4F 4E }
        $s29 = { 5F 50 52 4F 58 59 5F 50 52 4F 47 4D 41 }
        $s30 = { 5F 50 52 4F 58 59 5F 4D 4F 44 45 5F 42 41 53 49 43 }
        $s31 = { 5F 50 52 4F 58 59 5F 4D 4F 44 45 5F 4E 54 4C 4D }
    condition:
        Macho and filesize < 500KB and all of them
}

rule XProtect_MACOS_2070d41
{
    meta:
        description = "MACOS.2070d41"
    strings:
        $a = { 46 61 73 64 55 41 53 }
        $b1 = { 00 63 00 75 00 72 00 6C 00 20 00 2D 00 2D 00 63 00 6F 00 6E 00 6E 00 65 00 63 00 74 00 2D 00 74 00 69 00 6D 00 65 00 6F 00 75 00 74 00 20 00 [2-4] 20 00 2D 00 6B 00 73 00 20 00 2D 00 64 00 20 }
        $b2 = { 00 63 00 75 00 72 00 6C 00 20 00 2D 00 6B 00 73 00 20 00 2D 00 2D 00 63 00 6F 00 6E 00 6E 00 65 00 63 00 74 00 2D 00 74 00 69 00 6D 00 65 00 6F 00 75 00 74 00 20 00 [2-4] 20 00 2D 00 64 00 20 }
        $c1 = { 00 2F 00 61 00 67 00 65 00 6E 00 74 00 2F 00 6C 00 6F 00 67 00 2E 00 70 00 68 00 70 }
        $c2 = { 00 2F 00 61 00 70 00 70 00 6C 00 65 00 2F 00 6C 00 6F 00 67 00 2E 00 70 00 68 00 70 }
        $d1 = { 00 58 00 2D 00 4D 00 6F 00 64 00 75 00 6C 00 65 00 3A 00 20 }
        $d2 = { 00 58 00 2D 00 55 00 73 00 65 00 72 00 3A 00 20 }
    condition:
        $a at 0 and filesize < 100KB and any of ($b*) and any of ($c*) and all of ($d*)
}

rule XProtect_MACOS_9e2bab9
{
    meta:
        description = "MACOS.9e2bab9"
    strings:
        $a = { 46 61 73 64 55 41 53 }
        $b1 = { 18 2E 73 79 73 6F 65 78 65 63 54 45 58 54 FF FF 80 }
        $b2 = { 6B 6F 63 6C 0A FF ?? 00 04 0A 63 6F 62 6A 0A FF ?? 00 18 2E 63 6F 72 65 63 6E 74 65 2A 2A 2A 2A }
        $b3 = { 2A 2A 2A 2A 03 FF ?? 00 64 0A FF ?? 00 04 0A 70 63 6E 74 0A FF ?? 00 04 0A 54 45 58 54 0A FF ?? 00 08 0B 6B 66 72 6D 49 44 }
        $c1 = { 00 A7 00 D3 00 D2 00 D8 00 C5 00 CD 00 D2 00 C9 00 D6 00 D7 }
        $c2 = { 00 C6 00 D9 00 CD 00 D0 00 C8 00 C3 00 DA 00 C9 00 D2 00 C8 00 D3 00 D6 }
        $c3 = { 00 C6 00 D9 00 CD 00 D0 00 C8 00 C3 00 DA 00 C9 00 D6 00 D7 00 CD 00 D3 00 D2 }
        $c4 = { 00 D3 00 D7 00 C5 00 C7 00 D3 00 D1 00 D4 00 CD 00 D0 00 C9 }
        $c5 = { 00 D3 00 D7 00 C5 00 D7 00 C7 00 D6 00 CD 00 D4 00 D8 }
    condition:
        $a at 0 and filesize < 100KB and all of ($b*) and any of ($c*)
}

rule XProtect_MACOS_889c9e6
{
    meta:
        description = "MACOS.889c9e6"
    strings:
        $a = { 23 21 2F 75 73 72 2F 62 69 6E 2F 65 6E 76 20 62 61 73 68 0A }
        $b1 = { 2F 43 6F 6E 74 65 6E 74 73 2F 4D 61 63 4F 53 2F 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 22 20 2D 2D 72 65 6D 6F 74 65 2D 64 65 62 75 67 67 69 6E 67 2D 70 6F 72 74 3D 31 39 32 33 34 }
        $b2 = { 2F 43 6F 6E 74 65 6E 74 73 2F 4D 61 63 4F 53 2F 42 72 61 76 65 20 42 72 6F 77 73 65 72 22 20 2D 2D 72 65 6D 6F 74 65 2D 64 65 62 75 67 67 69 6E 67 2D 70 6F 72 74 3D 31 39 33 38 34 }
        $b3 = { 2F 43 6F 6E 74 65 6E 74 73 2F 4D 61 63 4F 53 2F 4D 69 63 72 6F 73 6F 66 74 20 45 64 67 65 22 20 2D 2D 72 65 6D 6F 74 65 2D 64 65 62 75 67 67 69 6E 67 2D 70 6F 72 74 3D 31 39 32 36 34 }
        $b4 = { 2F 43 6F 6E 74 65 6E 74 73 2F 4D 61 63 4F 53 2F 66 69 72 65 66 6F 78 22 20 2D 2D 73 74 61 72 74 2D 64 65 62 75 67 67 65 72 2D 73 65 72 76 65 72 20 77 73 3A 31 39 32 34 30 }
        $b5 = { 2F 43 6F 6E 74 65 6E 74 73 2F 4D 61 63 4F 53 2F 4F 70 65 72 61 22 20 2D 2D 72 65 6D 6F 74 65 2D 64 65 62 75 67 67 69 6E 67 2D 70 6F 72 74 3D 31 39 32 33 38 }
        $b6 = { 2F 43 6F 6E 74 65 6E 74 73 2F 4D 61 63 4F 53 2F 33 36 30 43 68 72 6F 6D 65 22 20 2D 2D 72 65 6D 6F 74 65 2D 64 65 62 75 67 67 69 6E 67 2D 70 6F 72 74 3D 31 39 32 36 38 }
        $b7 = { 2F 43 6F 6E 74 65 6E 74 73 2F 4D 61 63 4F 53 2F 59 61 6E 64 65 78 22 20 2D 2D 72 65 6D 6F 74 65 2D 64 65 62 75 67 67 69 6E 67 2D 70 6F 72 74 3D 31 39 32 33 36 }
        $b8 = { 2F 43 6F 6E 74 65 6E 74 73 2F 4D 61 63 4F 53 2F 43 68 72 6F 6D 69 75 6D 22 20 2D 2D 72 65 6D 6F 74 65 2D 64 65 62 75 67 67 69 6E 67 2D 70 6F 72 74 3D 31 39 32 33 36 }
        $b9 = { 2F 4C 69 62 72 61 72 79 2F 43 6F 6E 74 61 69 6E 65 72 73 2F 53 61 66 61 72 69 2F 72 75 6E 2E 70 79 }
    condition:
        $a at 0 and any of ($b*) and filesize < 200
}

rule XProtect_MACOS_1db9cfa
{
    meta:
        description = "MACOS.1db9cfa"
    condition:
        Macho and filesize < 10MB and (
            hash.sha1(0, 22032) == "04b823a72f134918f64cd6bbac8251f95a42b052" or
            hash.sha1(0, 50704) == "082fa2d8b3841899f5fbe244f1a6ee6247a00c1c" or
            hash.sha1(0, 22032) == "102229386892fd0aa16ca349919cd9b20db30dc8" or
            hash.sha1(0, 50704) == "10f8a912c90317c1eeecce12fc8c1c1d7b5655ab" or
            hash.sha1(0, 22032) == "1f22744799d3d13e851cb1dedf4cbb1b28eda695" or
            hash.sha1(0, 50704) == "2217a4633fd8654972e980d436cb9c38d324dd29" or
            hash.sha1(0, 50704) == "234562f93adebf3db00578ff347cc14baf68a531" or
            hash.sha1(0, 50704) == "3e64273d156321b3503fd5738fd88c3820ab66d2" or
            hash.sha1(0, 50704) == "4b8d96e88c9057314bd68e1101f055b8a84f8edf" or
            hash.sha1(0, 50704) == "562b30388e335ffd3658fc5dedcba6a0f5ff0aad" or
            hash.sha1(0, 22032) == "60c7b8e84f5103f4597199f30bffcb79e4271d37" or
            hash.sha1(0, 50704) == "6110eaa6053fbd77171f52147ef0a863f8bd7328" or
            hash.sha1(0, 13780) == "684e8a068d2af353930bf7007cc502488374b984" or
            hash.sha1(0, 50704) == "6a9ed3bda52b6d1e0f2c3fb8d644f8434203d6ee" or
            hash.sha1(0, 50704) == "6bf52006ce9e6dc23e26e2a2151edc12cd726966" or
            hash.sha1(0, 17936) == "6e683382cefa20d9ec6133f4558ab18e8d5daa1f" or
            hash.sha1(0, 50704) == "75c39a6b0a66c33badbbd07bb096631936c076e7" or
            hash.sha1(0, 50704) == "8b4207ac1c227f98119c0b719cc5896d606ee362" or
            hash.sha1(0, 22032) == "8dc7a8c88896758d139366fa054ff9ad848270a0" or
            hash.sha1(0, 50704) == "a603a6c65156c3fb932f8671da03c0c77db5408f" or
            hash.sha1(0, 22032) == "ac269f677a14406d1e4a9ef4f0fa3cc272e370d2" or
            hash.sha1(0, 50704) == "b4ffa58582cc3e8ef2525667b73df98667bd0266" or
            hash.sha1(0, 50704) == "d1900adb4983a979155b9b2bc4042784baf24963" or
            hash.sha1(0, 50704) == "e7076183c90d4937ff6c95ad4aa24af14a3162be" or
            hash.sha1(0, 50704) == "f13c3959ccdbb8850dadc39d97fe36c31d96b7f1" or
            hash.sha1(0, 50704) == "f53da2ae651f2806cbf5723fecc1455364e8ff35" or
            hash.sha1(0, 50704) == "fe7e7bce3032cd05fe19067f28cee24ef8adcc32" or
            hash.sha1(0, 50704) == "5a7d2fcb0ca59364cb764a698af08921dc05681f" or
            hash.sha1(0, 50704) == "ff2a1f98d1aefcb0e9d67b8b8bc5703b20dbcc39" or
            hash.sha1(0, 50704) == "1aba53a2a364e782c5e18fffba067b19d634204c" or
            hash.sha1(0, 50704) == "6581957d1a7cde24a375bfa73e11bae17d1ef779" or
            hash.sha1(0, 50704) == "daaad99d3162d037b9b4a610c87867d0cfa7fa8f" or
            hash.sha1(0, 50704) == "9327e28f0bbdb215c0a0d050acad16ac74470d84" or
            hash.sha1(0, 50704) == "31ac2f1783a9dd807e8478304471cebcaa5a8818" or
            (hash.sha1(12480, 3383) == "004f76d87aa8a54b3f8e7a81c05907c435fe0e1a" and hash.sha1(32944, 10899) == "19f6ff8f2e5373c6ceea6c5ce3a5ca508b215e54") or
            (hash.sha1(12480, 3383) == "a84321e906733c899446e9f8f7c033d9839c9041" and hash.sha1(32944, 3213)  == "4712921d105a4874c2371542bbbf1b64fa3216eb") or
            (hash.sha1(12480, 3383) == "12622a1009c200ba049a66931efdfeed4776f6d4" and hash.sha1(32944, 12539) == "9b93e47be24e03e33926e2f0456eed1b4b1dd971") or
            (hash.sha1(12496, 3367) == "5f9d750a6da1d886edc6c9a5dfabe0623997046e" and hash.sha1(32944, 3138)  == "500c2199792632959ed04dc8b0a9799dac353519") or
            (hash.sha1(12480, 3383) == "f7ac34703d0ab6c02a0197b1b9347ec6ffa4a968" and hash.sha1(32944, 11631) == "b7ca72ad28280f4778efa49da6346f01de7e82c7") or
            (hash.sha1(12480, 3383) == "e53163e5f4524a1d078bad5de96c8f656e37abce" and hash.sha1(32944, 2731)  == "8950d8649618253e55b60afaf36e33604a0c9139") or
            (hash.sha1(12480, 3383) == "5cd351e839c033869add29a91494c2fb75c6c5b8" and hash.sha1(32944, 12985) == "ffc27549dc1e020de294a7559cd5ab6f880f237c") or
            (hash.sha1(12480, 3383) == "7894b20f73a8e7473e01ebe655cfe209dd8d69b6" and hash.sha1(32944, 3332)  == "7073d411e84c2d59537df8d7e60d7fff7ee6f38c") or
            (hash.sha1(12496, 3367) == "863fea54f1f228a2e2f20a9e1c616ce64932bef5" and hash.sha1(32944, 12131) == "b2156d6d36c88d2e606f10d9baf2718fc6c0ecb8") or
            (hash.sha1(12480, 3383) == "69dc7106e4a79703984f2fabb87e4b6ae0207dc3" and hash.sha1(32944, 9685)  == "66ffd2cb4aa2e6a1baf194b94d84ff4b2971facf") or
            (hash.sha1(12480, 3383) == "9f20e6eac2f59ba91be98698faeafe244adfed19" and hash.sha1(32944, 11922) == "267bd25181d8e5dd496c818ace38e460f5fc1786") or
            (hash.sha1(12624, 3230) == "45923099d3f99bd94f9a5c58e24f9ca77d92ca3f" and hash.sha1(32944, 10719) == "5a6fc07dfa47009d756ad5169a17376351eeeb66") or
            (hash.sha1(12640, 3214) == "fe768b3234600e95541a9c7348e13afb845c3257" and hash.sha1(32944, 12314) == "ef70d0b3058349817eeaac627cb8747d4922511b")
        )
}

rule XProtect_MACOS_6eaea4b
{
    meta:
        description = "MACOS.6eaea4b"
    condition:
        Macho and filesize < 10MB and (
            hash.sha1(0, 454544) == "8bda23d6fe3c5f61bbe035b3b3955c128fe5fd0c" or 
            hash.sha1(0, 478384) == "eff0e86a0c1fdb31442b3b27ae275265144b22ec" or 
            hash.sha1(0, 888976) == "3bddee4293c423dcf791872e214c364b89df558b" or 
            hash.sha1(0, 465728) == "ab859e350bca96ed8ab4d3ee87ecbdaad42cbf76" or 
            hash.sha1(0, 462816) == "175a12023d4de5d0b2cb484fa6b22f4a579c59b0" or 
            hash.sha1(0, 465536) == "c91343995496fc20c853d177411338cfe954994f" or 
            hash.sha1(0, 465536) == "231b970b66af08780b6fbaf07367d1c8d73d7f8e" or 
            hash.sha1(0, 888976) == "674493bd15f6df947d6a32d42ffd800197a05a9a" or 
            hash.sha1(0, 482496) == "7034b366281882f3839089dbc99dde1c409db2d1" or 
            hash.sha1(0, 482416) == "f2a6ca3b9ebcfab66eda50621dbf1bb1e52d3e07" or 
            hash.sha1(0, 465936) == "f058b8f68f2e306ca00f3c43b485536ec9efa13a" or 
            hash.sha1(0, 482608) == "cadcf5a2618893e06477dde8162a651c0b971ad7" or 
            hash.sha1(0, 922656) == "b6cd41a0b199a131572e9185805a523a4af285b5" or
            (hash.sha1(23728, 267226) == "e15f33dc0ab40e560b25a2548fa76f98c46d7a64" and hash.sha1(492920, 235168) == "5134edfe096a6ff12f803cfd4c1ec54927846e33") or
            (hash.sha1(21520, 269322) == "920c2ba31e95917aa2aa5e0b9f60c62034e913b0" and hash.sha1(490900, 237060) == "0bd8de35f2a5924eda4655a8b358805560cd7da5") or
            (hash.sha1(45744, 277834) == "1812f9c0cc91ac3f1b21549ba3345bd388687be8" and hash.sha1(522084, 238540) == "a7634e3dcd5541fa5f7358c81b91bbf9086ab7f9") or
            (hash.sha1(45440, 278122) == "572efd9090128cb2ba7cf03a1ef95852b8803d61" and hash.sha1(521784, 238816) == "a229148416fa671c5ee1aa546c5ffef3c8695acc") or
            (hash.sha1(45456, 278106) == "01677a4751a36b7c2e85350a0325450d06ddf94b" and hash.sha1(521784, 238816) == "a1bf16e40febb8fae0d61462fb098b3885b48d05") or
            (hash.sha1(36704, 270282) == "02f12d6efddb9915ef5e48dc8672e8c49eaf695d" and hash.sha1(508868, 235172) == "0cdb4314624dd23045bf48ecb7e736d4ab452b14") or
            (hash.sha1(53088, 270282) == "02f12d6efddb9915ef5e48dc8672e8c49eaf695d" and hash.sha1(525252, 235172) == "0cdb4314624dd23045bf48ecb7e736d4ab452b14") or
            hash.sha1(0, 478384) == "dd7e5f9407f670a8ee04ba4b326c70c409db4871" or
            hash.sha1(0, 474224) == "166f3d5be9cde70c3bf0a22fbb8365d13d81ca34" or
            hash.sha1(0, 450256) == "e6beeb6b32a140904a648fca9dab614d73dcd94c" or 
            hash.sha1(0, 474224) == "09b03db91357d5a067439d101e81c163f4eba4b0" or 
            hash.sha1(0, 888864) == "e386145673963ebfedc99665868106ec00e23607" or 
            hash.sha1(0, 922480) == "bd13d22095d377938c50088e59fa3079143cb0f2" or
            (hash.sha1(26160, 264618) == "25cb0ea0b706034409c7439ada832e141a9099cf" and hash.sha1(495056, 232672) == "bdc7c63c90390e7d737c04f37fe068b1d4398931") or
            (hash.sha1(24704, 266058) == "e522e55f91c3fe14079fa142b0ffd41a929657c9" and hash.sha1(493628, 234068) == "aaa386881e9f0c210e8c300667c4631b9a32b365") or
            (hash.sha1(47920, 275578) == "e29a36bf609f5c1700c91261574bf83757f5d6cc" and hash.sha1(524636, 235708) == "f87ee1e0488fbf3c64ab9cc40bfcef5745357afc") or
            (hash.sha1(47616, 275866) == "e2dbe92730b3e06937d5270b21abd8151ba3a504" and hash.sha1(524348, 235988) == "d43f3b412debf84206efc2732a65926681b94e24") or
            (hash.sha1(47632, 275850) == "5fb180aefdfa3a3c7163bd37fac7b8eb193e5286" and hash.sha1(524352, 235984) == "0a59d04c27ca3761e71330bcaf3c79e77fe665f3") or
            (hash.sha1(22208, 268314) == "757f1e6b691c2e91f5b9fcebacf35edfcc9ce315" and hash.sha1(493612, 233732) == "639f0af300aed26656ac217ce28565f8eaed8d35") or
            (hash.sha1(22208, 268314) == "757f1e6b691c2e91f5b9fcebacf35edfcc9ce315" and hash.sha1(493612, 233732) == "639f0af300aed26656ac217ce28565f8eaed8d35") or
            hash.sha1(0, 454448) == "e4b84e22214062b57a3f3a81fba5d4ddd163b0bb" or 
            hash.sha1(0, 474144) == "5c448f6272d63a57c0e7965d09bd93e23a15ee86" or 
            hash.sha1(0, 888864) == "a15f39ce5007e25e742d071d15c8e38658165e5a" or 
            hash.sha1(0, 922384) == "cbf08fae71fcd46cc852fad7502685466c40e168" or
            (hash.sha1(25584, 264906) == "38ae77158e1ce3079a36303bf45d46246befc753" and hash.sha1(494844, 232940) == "dddb9c37fa39a49c7e17f77ea8176fe0a29e23a2") or
            (hash.sha1(24128, 266330) == "da85d3675bbd891f6e7d0269173243adaa1300ff" and hash.sha1(493444, 234284) == "d0fa0e947ab4d51278bc3c2be092918345dc9fc5") or
            (hash.sha1(46928, 276282) == "51b695a80c74a0d30d4c614a8ecc605457bb7adc" and hash.sha1(524176, 236216) == "05806c64f585306b25a75ccdb071375ed1c74098") or
            (hash.sha1(46624, 276570) == "326e55ae93aeced73be9bf830a574a4ea551b231" and hash.sha1(523872, 236496) == "55efadfed76814a75f11ed255da7ebdf90248a1d") or
            (hash.sha1(46656, 276554) == "77b726c10e6d381456704be730c76b5963ff9625" and hash.sha1(523876, 236492) == "4420fede63ed01fd9fd20428d8738b105e8c6e41") or
            (hash.sha1(37392, 269162) == "77756fb4720bc7ea364a947df659495a473ff15d" and hash.sha1(509160, 234424) == "dfdab2704a010782a4b0dfd180569c0aa245c866") or
            (hash.sha1(53776, 269162) == "77756fb4720bc7ea364a947df659495a473ff15d" and hash.sha1(525544, 234424) == "dfdab2704a010782a4b0dfd180569c0aa245c866") or
            hash.sha1(0, 450112) == "21b63689d192a7d1309d98afa35d42f695098d7a" or 
            hash.sha1(0, 474048) == "509dba18a168fdeecf990704741e14cb17b2a31e" or 
            hash.sha1(0, 888656) == "3a1665f1b92f1aae4eb44753f5134b3a0ec0a35f" or 
            hash.sha1(0, 444752) == "4a86f9cd51d9682a67bdd9921542806b9c32eef0" or 
            hash.sha1(0, 465232) == "5bb4e5bf7bab49945878993ca0faa70f83b732df" or 
            hash.sha1(0, 465888) == "5266f907da5c8fc78971e848fe89927acce2ba92" or 
            hash.sha1(0, 465792) == "d6a65d5bb692f5d82f0b1b688e660f1baf857538" or 
            hash.sha1(0, 922448) == "65e62ef1bd1ae50730974cafee5d8b22b97fa7aa" or 
            hash.sha1(0, 922448) == "a012a408a9a7108d71d771cb701725fa1894d539" or 
            hash.sha1(0, 922448) == "23d05530ee621b5f0410c5eac8840c7cf1e512e9" or
            hash.sha1(0, 922448) == "2a62d6bcac7b0c5e75f561458e934ec45c77699c" or
            (hash.sha1(25248, 264250) == "2d7ec4dcaad429421f2e61e62bbff0ca7cede95a" and hash.sha1(494424, 232080) == "ca15aa3cc18977d93bfc0f751305baaeadd02abc") or
            (hash.sha1(24160, 265098) == "457869b75082919b9d44e3f9b3097bc1e2b76c0a" and hash.sha1(493392, 232872) == "6664a7a1399377447c6f4459e71a44aa0e30391e") or
            (hash.sha1(45472, 276730) == "f32c2cdad1f8deb30cb235d2d196fb0d8b569dc2" and hash.sha1(521912, 237008) == "97a3e72e5426f7dcd4f40fc759336b0cf7073c10") or
            (hash.sha1(45168, 277018) == "cafd8549f9a623c538d5c5b7799449c4121866bf" and hash.sha1(521608, 237288) == "e743db22d055f765d9948e0e66f934b67b7774f9") or
            (hash.sha1(45152, 277034) == "81d3729c09971fce700a10e01284610a17003c5b" and hash.sha1(521588, 237308) == "be6313f77dc0de79a8d9e3d718f23cc5f8a7907b") or
            (hash.sha1(36384, 269130) == "37bd3a555e23ee2f2792e78b79d30e6a1c0b2f1e" and hash.sha1(507920, 234144) == "fccc75ca700171c8d3fbc1add4b5f972ba0688d0") or
            (hash.sha1(52768, 269130) == "37bd3a555e23ee2f2792e78b79d30e6a1c0b2f1e" and hash.sha1(524304, 234144) == "fccc75ca700171c8d3fbc1add4b5f972ba0688d0") or
            hash.sha1(0, 955424) == "8d2f1644320ba4f90b2cd23eeca51843168f59b8" or 
            hash.sha1(0, 955424) == "263b243df32be6d9d9878c459d2fc6491342d547" or
            (hash.sha1(52928, 269834) == "5e9380abd57f0f143b119695cba20cf4d98117bd" and hash.sha1(522040, 237840) == "78b2101b6fad4712a6df7905e7d51bbd5208bb48") or
            (hash.sha1(51600, 271146) == "d334ecef808a49eb3841c1cdadc6bf1c9d2a6d2b" and hash.sha1(520692, 239156) == "0e0a6f18ddfb9620f9547ab6d4f5fe8fe29d6c1a") or
            (hash.sha1(43104, 279610) == "5c1d1d356040ff714838ddb516620fbca71d0b45" and hash.sha1(519864, 239880) == "71c1b3143e3896dca48a674bd2155e6f450c5d61") or
            (hash.sha1(42800, 279898) == "4e8afb74fe55b941c8e8eceeb77d8d4bee8e7a4c" and hash.sha1(519560, 240160) == "4b700681cb0a1a62831cdd3f4b5e79205ff11aa5") or
            (hash.sha1(42800, 279898) == "627c3801155a14f4b985bf8e8549d9baf16c7da2" and hash.sha1(519564, 240156) == "3742d2860894378a745a8998013e42fcbeda44bf") or
            (hash.sha1(33968, 272138) == "3b1254e5401eab70fcba51413a325347a5628ec2" and hash.sha1(506532, 236628) == "492e728422320a33d819b1133c7968b29bf17447") or
            (hash.sha1(50352, 272138) == "3b1254e5401eab70fcba51413a325347a5628ec2" and hash.sha1(522916, 236628) == "492e728422320a33d819b1133c7968b29bf17447") or
            hash.sha1(0, 450256) == "373d5b73e02899bda6091936efdd768821ba3dd2" or 
            hash.sha1(0, 474224) == "8d0f391449c0e479c189c10da873d047c2327d5f" or 
            hash.sha1(0, 888864) == "4db9cd9b165c3d820ab4f456df551e8f03c7a797" or 
            hash.sha1(0, 465728) == "163a01132cd6c038c8692d4ba5f50681181c74ce" or 
            hash.sha1(0, 465760) == "68387bf302163de4dcdcc9a7b1bb53d50ecc7256" or 
            hash.sha1(0, 905696) == "b05c39e48ac7959545028d20acd41010ae5726f4" or 
            hash.sha1(0, 922384) == "2a6d37160f21ec13aa6c692a3ca3374db3d35e96" or
            (hash.sha1(27440, 263226) == "f4ab841ecd1d48e3085ae92b0b1ca8604e85ce83" and hash.sha1(496240, 231608) == "66be42c88520537be247d29f3b117323612dcdfc") or
            (hash.sha1(25936, 264682) == "2bb4155dad4a0c6c8eec33e3ae5fd7bfc40d71f6" and hash.sha1(494820, 232972) == "5ec40ea1630d3f919171cf4a1fb64abf83bf9f5a") or
            (hash.sha1(49008, 274346) == "ffe4482ab09ad6915bf594aa5b856bdd4e45e1bd" and hash.sha1(525904, 234536) == "b9f835adcc3332ffd4a041397550fbdaa36bfdbb") or
            (hash.sha1(48704, 274634) == "2357331346f7bdab42efe34077d4f2cbf0aeeb47" and hash.sha1(525600, 234816) == "395d3290248c761e506f70d2e1517df586f0f4b2") or
            (hash.sha1(48736, 274618) == "7b06f11ef35e3303ce0a24a0873e61c24f1a1f44" and hash.sha1(525604, 234812) == "b96a33dfe6f7df8e5af7b3b602750891d19f951e") or
            (hash.sha1(23056, 267290) == "dd3b3211c25317d28f9a3ae3f400fe019b4fff4c" and hash.sha1(494756, 232636) == "0cf7e3b710028528974fbddf7791745568866535") or
            (hash.sha1(23056, 267290) == "dd3b3211c25317d28f9a3ae3f400fe019b4fff4c" and hash.sha1(494756, 232636) == "0cf7e3b710028528974fbddf7791745568866535") or
            hash.sha1(0, 454448) == "0d1cbf5473fab9156922de90a09b7a2e64aef328" or 
            hash.sha1(0, 474160) == "501bdd880699749ae3a7a6e9c2230f903200fcab" or 
            hash.sha1(0, 888864) == "976a71300d0c76bdf505e4a70be5e173471d683d" or 
            hash.sha1(0, 922368) == "1396fdbff38b787d14b1135dcdfc367658669637" or
            (hash.sha1(22288, 267866) == "3af51e49dd4401abc6a7a5834b14a448ccce7427" and hash.sha1(491096, 236000) == "6aade93d0c0b34b96525f6ca30ec8de4caa62bce") or
            (hash.sha1(53536, 269354) == "8628b9d4fa183c6d3b216a2b4c86ea4dd638bcf6" and hash.sha1(522536, 237272) == "5b1e151c1e216f952bdadf156e3ca14d4568cdc1") or
            (hash.sha1(43552, 279306) == "c855d3e10958b6af42db92a3e361d1b27bb94c2d" and hash.sha1(520852, 238836) == "a896bbdbbca929b2e17919171725a2041452a9ec") or
            (hash.sha1(43248, 279594) == "be15c2de5a35c24947fd625873d1748d64bfc1fb" and hash.sha1(520548, 239116) == "1d4da70c86c505e8117a2197a8c0ddae6f4ced72") or
            (hash.sha1(43248, 279594) == "2673f90a96a4e00dbc2b873a9da32bcc0dbd84be" and hash.sha1(520552, 239112) == "7521b7b36a9276b87ffda4cd1e4be95ec4fdaa27") or
            (hash.sha1(34416, 271818) == "7dc98e2010a865259407dd987601a4816f06a7e8" and hash.sha1(506396, 236660) == "4f17547c6c83d106cea576825fe838bbf07c69d1") or
            (hash.sha1(50800, 271818) == "7dc98e2010a865259407dd987601a4816f06a7e8" and hash.sha1(522780, 236660) == "4f17547c6c83d106cea576825fe838bbf07c69d1") or
            hash.sha1(0, 450256) == "533972a1736426bc23a715eb662e6374c6ea400a" or 
            hash.sha1(0, 474224) == "db31ba474d8f75437872f5caf275c1dd2609ee89" or 
            hash.sha1(0, 888864) == "eccacfd1946df9b74c8515aa5b54eab01c7582cb" or 
            hash.sha1(0, 469936) == "7377d0f081d93eb47ec5e6893e51291895622d91" or 
            hash.sha1(0, 922688) == "e4b6c56faa97493dc0f0f7c4fc2196096ef66513" or
            (hash.sha1(25008, 264890) == "befbd5b2ce01539a857d9332bbba88bae2ac65a1" and hash.sha1(493260, 233572) == "7bb48f16db086713c52b723e0d60495eb813aee2") or
            (hash.sha1(23632, 266250) == "450ec6c3f8109bf48bfa35ec8161a257765c17ae" and hash.sha1(491924, 234876) == "38584bebb3271d4a334adea2c6fdcc638c1df55f") or
            (hash.sha1(47728, 274922) == "78b279ef031f5aae76a5376922bff5915eaeefb5" and hash.sha1(523088, 236360) == "8eba37d5f875f52c0bc935531cb0bb3f6793c81f") or
            (hash.sha1(47424, 275210) == "4281ce5084d7f669374146b405def7872234aaed" and hash.sha1(522788, 236636) == "d45a917cbf21c272e7c8e6dd2148e32392d4939d") or
            (hash.sha1(47424, 275210) == "91145c92e2e85d6ed5dd33f6e0c32f84d2f76d02" and hash.sha1(522788, 236636) == "763b985cbc7bb60934e848ca6375cf8dda59f47a") or
            (hash.sha1(37296, 268714) == "cecfc085a9108edd47052e5a57e64670b59962eb" and hash.sha1(509452, 233364) == "ed630344a18228c94d6a7b5434757b42f8a7046e") or
            (hash.sha1(53680, 268714) == "cecfc085a9108edd47052e5a57e64670b59962eb" and hash.sha1(525836, 233364) == "ed630344a18228c94d6a7b5434757b42f8a7046e") or
            hash.sha1(0, 465600) == "d019a86482f03a0012d82a4455212ad36c9c09eb" or
            hash.sha1(0, 466240) == "30b7f694684af729619f30567be5443f849a3399" or
            hash.sha1(0, 465616) == "26565b29cfdd7de87da708ed45f4ab4799bdbb28" or
            hash.sha1(0, 466224) == "de662a98ff4cdfeca3eb95e746d9c253b73ee846" or
            hash.sha1(0, 448304) == "509aea0eb79253ced67a045738f1b9c6c84271ad" or
            hash.sha1(0, 466272) == "2c1142a9d938e415f23dd40205909686a3c69c51" or
            hash.sha1(0, 465600) == "acd00ea03ea2d9a2b43e8b076ee29b71255246b1" or
            hash.sha1(0, 466304) == "4ff733254fd4ef6e0df07bcb5215f391437f3592" or
            hash.sha1(0, 466224) == "926cc0c45610e286edccfe8104a95a096bfbaab2" or
            hash.sha1(0, 465328) == "c4e43c7d6e8aeb39654906a1b8445402b04db355" or
            hash.sha1(0, 465328) == "8a4994c138a24960818db2eec5c702acf25b0750" or
            hash.sha1(0, 465328) == "fe026ba19524c71dbf70923bde8ca065f5f8e186" or
            hash.sha1(0, 465616) == "a898e15d701e50f0c869abf62fab5cfe7854fa70" or
            hash.sha1(0, 466240) == "572b4e472e25da27b64b29d40e0bf5f85448bcff" or
            hash.sha1(0, 465776) == "74d8f5f5e904637d5b3383291d2d169643dda302" or
            hash.sha1(0, 465328) == "df3896ea9f02ed8b4b1e8e13588766fb16b8aab0" or
            hash.sha1(0, 465328) == "4a0359acfa8454454f8775ebc235f5bbd47b4d6c" or
            hash.sha1(0, 465616) == "49916762bab2816fcd93fb553d5231d320ed1b51" or
            (hash.sha1(22416, 268442) == "9c87e5a1281614714986c2fc0e934dbe6b57a746" and hash.sha1(491736, 236240) == "3aab2900d91e10f16a8c699d7f2f49e6ccf83827") or
            (hash.sha1(54272, 269322) == "c2db6347040d8d76c85d28fa04e79024e17fc1bd" and hash.sha1(523648, 237064) == "02f286233bbc98aa840ab6b70dbf4f66d462111d") or
            (hash.sha1(45744, 277818) == "551275307722b5ef579f5e7da5c9b59e2433f4c9" and hash.sha1(522048, 238560) == "fd16c95286f5f9d1ff87dc93f0417d4a3c35986a") or
            (hash.sha1(45440, 278106) == "9ed6803200759a489e1a645ecb68cfbed2ebd166" and hash.sha1(521748, 238836) == "fc033effb80619af879cacae80ca2010b4662a1e") or
            (hash.sha1(45456, 278090) == "1e725c6e13618a08164d9614402d9efa9d8c0e59" and hash.sha1(521748, 238836) == "1c432482778154334802e5d25b496690497485f0") or
            (hash.sha1(36672, 270266) == "26cf2ce4510cac9f319eaab76b6a7f1425df0c79" and hash.sha1(508820, 235172) == "fbc9bf6bea034248ec8b96bb049af6c70837dbb7") or
            (hash.sha1(53056, 270266) == "26cf2ce4510cac9f319eaab76b6a7f1425df0c79" and hash.sha1(525204, 235172) == "fbc9bf6bea034248ec8b96bb049af6c70837dbb7")
        )
}

rule XProtect_MACOS_7f5b902
{
    meta:
        description = "MACOS.7f5b902"
    strings:
        $a1 = { 2f 71 75 65 72 79 2f 74 6f 3f 71 69 3d 31 26 63 61 74 65 67 6f 72 79 3d 77 65 62 26 61 70 70 5f 69 64 3d }
        $a2 = { 2f 69 6e 73 74 61 6c 6c 2f 61 67 65 6e 74 5f 75 70 64 61 74 65 3f 73 65 73 73 69 6f 6e 5f 69 64 3d }
        $a3 = { 2f 6d 6f 6e 65 74 69 7a 65 3f 73 65 73 73 69 6f 6e 5f 69 64 3d }
        $a4 = { 2f 69 6e 73 74 61 6c 6c 3f 73 65 73 73 69 6f 6e 5f 69 64 3d }
        $a5 = { 2f 69 6e 73 74 61 6c 6c 2f 66 69 72 73 74 5f 74 69 6d 65 3f 73 65 73 73 69 6f 6e 5f 69 64 3d }
        $a6 = { 2f 74 61 73 6b 2d 66 6f 72 3f 65 6d 69 64 3d }
        $b1 = { 26 65 78 74 3d 31 26 7a 3d 35 26 71 75 65 72 79 3d 6d 79 51 75 65 72 79 }
        $b2 = { 63 6f 6d 2e 61 70 70 6c 65 2e 71 75 61 72 61 6e 74 69 6e 65 }
        $b3 = { 67 65 74 20 76 65 72 73 69 6f 6e 20 6f 66 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 22 53 61 66 61 72 69 22 }
        $b4 = { 26 26 69 73 5f 73 65 74 5f 73 70 5f 61 70 70 72 6f 76 65 64 3d }
        $b5 = { 26 69 73 5f 69 6e 73 74 61 6c 6c 5f 61 63 63 65 70 74 65 64 3d }
        $b6 = { 41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 71 75 69 74 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 3f }
        $b7 = { 51 75 69 74 69 6e 67 20 77 69 6c 6c 20 63 61 6e 63 65 6c 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e }
    condition:
        Macho and ( 1 of ( $a* ) ) and ( 3 of ( $b* ) ) and filesize < 400KB
}

rule XProtect_MACOS_a291b70
{
    meta:
        description = "MACOS.a291b70"
    strings:
        $a1 = { 2f 69 6e 73 74 61 6c 6c 2f 61 67 65 6e 74 5f 75 70 64 61 74 65 3f 65 6d 69 64 3d }
        $a2 = { 2f 6d 6f 6e 65 74 69 7a 65 3f 73 65 73 73 69 6f 6e 5f 69 64 3d }
        $a3 = { 2f 69 6e 73 74 61 6c 6c 3f 73 65 73 73 69 6f 6e 5f 69 64 3d }
        $a4 = { 2f 69 6e 73 74 61 6c 6c 2f 66 69 72 73 74 5f 74 69 6d 65 3f 73 65 73 73 69 6f 6e 5f 69 64 3d }
        $a5 = { 25 40 3f 65 6d 69 64 3d 25 40 26 61 70 70 49 64 3d 25 40 }
        $b1 = { 63 6f 6d 2e 61 70 70 6c 65 2e 71 75 61 72 61 6e 74 69 6e 65 }
        $b2 = { 67 65 74 20 76 65 72 73 69 6f 6e 20 6f 66 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 22 53 61 66 61 72 69 22 }
        $b3 = { 26 69 73 5f 73 65 74 5f 73 70 5f 61 70 70 72 6f 76 65 64 3d }
        $b4 = { 26 69 73 5f 69 6e 73 74 61 6c 6c 5f 61 63 63 65 70 74 65 64 3d }
        $b5 = { 26 73 61 66 61 72 69 5f 73 70 5f 73 65 74 3d }
        $b6 = { 41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 71 75 69 74 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 3f }
        $b7 = { 51 75 69 74 69 6e 67 20 77 69 6c 6c 20 63 61 6e 63 65 6c 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e }
        $b8 = { 69 6f 72 65 67 20 2d 6c 20 7c 20 67 72 65 70 20 2d 65 20 4d 61 6e 75 66 61 63 74 75 72 65 72 20 2d 65 20 5c 27 56 65 6e 64 6f 72 20 4e 61 6d 65 5c 27 }
        $b9 = { 73 65 61 72 63 68 20 69 73 20 64 65 73 69 67 6e 65 64 20 74 6f 20 70 72 6f 76 69 64 65 20 79 6f 75 20 74 68 65 20 62 65 73 74 20 73 65 61 72 63 68 20 65 78 70 65 72 69 65 6e 63 65 }
        $b10 = { 73 65 61 72 63 68 20 72 65 73 75 6c 74 73 20 61 6e 64 20 72 65 63 6f 6d 6d 61 6e 64 61 74 69 6f 6e 73 20 69 6e 20 72 65 61 6c 20 74 69 6d 65 2c 20 65 6e 6a 6f 79 }
    condition:
        Macho and ( 2 of ( $a* ) ) and ( 4 of ( $b* ) ) and filesize < 500KB
}

rule XProtect_MACOS_30445d1
{
    meta:
        description = "MACOS.30445d1"
    strings:
        $a1 = { 23 21 2f 62 69 6e 2f 73 68 }
        $a2 = { 23 21 2f 62 69 6e 2f 62 61 73 68 }
        $b = { 68 69 6e 74 3d 22 24 28 6c 73 20 7c 20 67 72 65 70 20 2d 76 20 27 31 2e 70 6e 67 5c 7c 32 2e 69 63 6e 73 5c 7c 63 6f 6e 76 65 72 74 65 72 2e 74 6f 6f 6c 5c 7c 73 63 72 69 70 74 2d 65 6e 63 27 29 22 }
        $c = { 63 6d 64 3d 22 24 28 6f 70 65 6e 73 73 6c 20 65 6e 63 20 2d 64 20 2d 61 65 73 2d 32 35 36 2d 63 62 63 20 2d 41 20 2d 62 61 73 65 36 34 20 2d 6b 20 24 68 69 6e 74 20 2d 69 6e 20 73 63 72 69 70 74 2d 65 6e 63 20 7c 20 73 68 20 2d 29 22 }
    condition:
        any of ( $a* ) and $b and $c and filesize < 5MB
}

rule XProtect_MACOS_d4735e3
{
    meta:
        description = "MACOS.d4735e3"
    strings:
        $a1 = { 8B B2 C4 67 56 5C 63 42 8E F0 CF C5 F4 8D 87 AE 58 0C 5B A4 14 }
        $a2 = { D2 5A C9 65 FE D7 69 C7 A7 3B F9 5E 6A 35 9B 20 20 65 77 E5 14 }

        $b1 = { 41 0f b6 55 ?? 49 8d 3c 1f 31 c0 4c 89 e6 e8 ?? ?? ?? ?? 49 ff c5 48 83 c3 ?? 48 83 fb ?? 75 ?? }
        $b2 = { 49 89 f5 49 89 fe bf ?? ?? ?? ?? }
        $b3 = { 25 30 32 78 00 }

        $c = { 0f b6 33 31 c6 40 88 31 48 ff c3 48 ff c1 ff ca 75 ?? }

        $d = {
            31 ff e8 ?? ?? ?? ?? 89 c7 e8 ?? ?? ?? ?? e8 ??
            ?? ?? ?? 48 63 c8 48 69 c9 ?? ?? ?? ?? 48 89 ca
            48 c1 ea ?? 48 c1 f9 ?? 01 d1 c1 e1 ?? 8d 0c c9
            f7 d9 8d 7c 08 ?? e8 ?? ?? ?? ??
        }

        $e1 = { 30 48 37 42 53 35 34 71 42 66 75 47 37 61 6c 6d 71 66 76 55 37 63 6e 32 35 31 42 6c 6b 4e 43 5a 68 55 70 62 6b 61 6f 30 78 67 71 57 6c 57 77 46 4c 44 42 58 68 37 68 68 44 70 49 47 6b 6b 35 76 6f 42 4d 72 44 33 43 52 33 70 42 44 4b 75 43 70 48 36 4b 6e 6b 49 73 33 37 7a 4d 57 31 47 58 68 39 62 42 32 75 65 57 48 53 71 77 3d }
        $e2 = { 75 70 41 63 75 6b 43 31 71 68 50 72 45 45 39 4d 78 6f 42 45 76 37 6d 4d 6d 37 50 59 54 73 61 50 6f 70 6f 55 2b 73 41 49 68 4d 50 74 70 52 4a 55 63 35 57 41 6d 47 4a 38 6a 6c 71 76 6a 7a 63 7a 6f 4e 44 39 32 77 64 71 57 30 33 53 30 65 64 63 6b 33 49 41 50 59 3d 3d }
        $e3 = { 4d 31 61 79 42 61 69 39 76 38 72 50 46 41 77 58 74 48 46 59 2f 76 41 54 2b 70 4c 31 64 44 68 62 39 35 36 74 6a 44 63 4e 4d 37 41 3d }
        $e4 = { 4d 6c 6b 48 56 64 52 62 4f 6b 72 61 39 73 2b 47 36 35 4d 41 6f 4c 67 61 33 34 30 74 33 2b 7a 6a 2f 75 38 4c 50 66 50 33 68 69 67 3d }
        $e5 = { 31 53 69 62 34 48 66 50 75 52 51 6a 70 78 49 70 45 43 6e 78 78 54 50 69 75 33 46 58 4f 46 41 48 4d 78 2f 2b 39 4d 45 56 76 39 4d 2b 68 31 6e 67 56 37 54 35 57 55 50 33 62 30 7a 73 67 30 51 64 }

        $f = { 49 4a 4b 4c 4d 4e 4f 50 67 68 69 6a 6b 6c 6d 6e 41 42 43 44 45 46 47 48 51 52 53 54 55 56 57 58 34 35 36 37 38 39 2b 2f 6f 70 71 72 73 74 75 76 59 5a 61 62 63 64 65 66 77 78 79 7a 30 31 32 33 }
    condition:
        Macho and filesize < 200KB and 1 of ( $a* ) and 1 of ( $b* ) and $c and $d and 2 of ( $e* ) and $f
}

rule XProtect_MACOS_b5bd028
{
    meta:
        description = "MACOS.b5bd028"

    strings:
        $a = { 23 21 2f 62 69 6e 2f 62 61 73 68 }
        $b1 = { 2f 70 61 72 61 6d 73 4a 73 6f 6e 2e 6a 73 6f 6e }
        $b2 = { 2f 2e 52 65 73 6f 75 72 63 65 73 }

    condition:
        $a at 0 and all of ($b*) and filesize < 1KB
}

rule XProtect_MACOS_d98ded3
{
    meta:
        description = "MACOS.d98ded3"

    strings:
        $a1 = { 50 58 ( 90 90 | 90 90 90 | 90 90 90 90 | 90 90 90 90 90 ) 50 58 ( 90 90 | 90 90 90 | 90 90 90 90 | 90 90 90 90 90 ) }
        $a2 = { 50 50 58 ( 90 90 | 90 90 90 | 90 90 90 90 | 90 90 90 90 90 ) 58 ( 90 90 | 90 90 90 | 90 90 90 90 | 90 90 90 90 90 ) }
        $a3 = { 50 50 50 58 ( 90 90 | 90 90 90 | 90 90 90 90 | 90 90 90 90 90 ) 58 ( 90 90 | 90 90 90 | 90 90 90 90 | 90 90 90 90 90 ) 58 ( 90 90 | 90 90 90 | 90 90 90 90 | 90 90 90 90 90 ) }
        $b1 = { 5f 43 46 55 55 49 44 43 72 65 61 74 65 }
        $b2 = { 5f 43 46 55 55 49 44 43 72 65 61 74 65 53 74 72 69 6e 67 }
        $c1 = { 5f 73 79 73 74 65 6d }
        $c2 = { 6c 61 75 6e 63 68 65 64 54 61 73 6b 57 69 74 68 4c 61 75 6e 63 68 50 61 74 68 3a 61 72 67 75 6d 65 6e 74 73 3a }

    condition:
        Macho and any of ($a*) and all of ($b*) and any of ($c*) and filesize < 5MB
}

rule XProtect_MACOS_9a3e9ed
{
    meta:
        description = "MACOS.9a3e9ed"

    strings:
        $a1 = { 55 48 89 e5 [0 - 2] 83 ff 7? 77 3? 89 f8 48 8d 0d ?? 2? 00 00 48 63 04 81 48 01 c8 ff e0 bf 09 00 00 00 e8 ?d 7? 00 00 [30 - 40] 31 (db | c0) }
        $a2 = { f4 4f be a9 fd 7b 01 a9 fd 43 00 91 1f dc 01 71 08 ?? ?? 54 [0 - 30] 20 01 80 52 }
        $a3 = { 5F 67 65 74 5F 75 70 64 61 74 65 72 5F 63 73 74 72 5F 63 6F 6E 73 74 }
        $b1 = { 7b 73 65 61 72 63 68 54 48 }
        $b2 = { 2e 6d 79 63 6f 75 70 6f 48 }
        $b3 = { 6e 73 6d 61 72 74 73 6d 48 }
        $b4 = { 70 72 75 64 65 6e 73 65 48 }
        $b5 = { 5f 53 4d 4a 6f 62 53 75 62 6d 69 74 }
        $b6 = { 5f 6b 53 4d 44 6f 6d 61 69 6e 53 79 73 74 65 6d 4c 61 75 6e 63 68 64 }
        $b7 = { 49 4f 50 6c 61 74 66 6f 72 6d 53 65 72 69 61 6c 4e 75 6d 62 65 72 }
        $b8 = { 79 6f 75 67 6f 74 75 70 64 61 74 65 64 }
        $b9 = { 2d 6d 65 74 68 6f 64 3d 72 75 6e }
        $b10 = { 72 65 74 72 69 65 76 65 4D 61 63 68 69 6E 65 49 64 }
        $b11 = { 72 75 6E 41 70 70 6C 65 53 63 72 69 70 74 }
        $b12 = { 6D 6F 64 69 66 79 55 73 65 72 44 65 66 61 75 6C 74 73 }
     
    condition:
        Macho and filesize < 500KB and ((2 of ($a*)) or (5 of ($b*)))
}

rule XProtect_MACOS_22f03bb
{
    meta:
        description = "MACOS.22f03bb"
    strings:
 		$a1 = { 63 72 79 70 74 6F 5F 32 20 6C 6F 61 64 }
 		$a2 = { 68 6F 6F 6B 43 6F 6D 6D 6F 6E }
 		$a3 = { 6D 79 4F 43 4C 6F 67 3A }
 		$a4 = { 72 75 6E 53 68 65 6C 6C 57 69 74 68 43 6F 6D 6D 61 6E 64 3A 63 6F 6D 70 6C 65 74 65 42 6C 6F 63 6B }

     condition:
         Macho and (all of ($a*)) and filesize < 2MB
}

rule XProtect_MACOS_e150543
{
    meta:
        description = "MACOS.e150543"

    strings:
        $a1 = { 53 68 65 6c 6c 56 69 65 77 }
        $a2 = { 6f 6b 45 76 74 }
        $a3 = { 63 6c 6f 73 65 45 76 74 }
        $a4 = { 63 61 6e 63 65 6c 45 76 74 }
        $a5 = { 72 75 6e 4d 6f 64 61 6c 3a }
        $a6 = { 4f 70 74 3a }
        $a7 = { 63 72 61 62 73 3a }
        $a8 = { 54 6d 70 3a }

    condition:
        Macho and 3 of them and filesize < 200KB
}

rule XProtect_MACOS_efb903b
{
    meta:
        description = "MACOS.efb903b"
    strings:
        $a = { 5f 64 69 73 70 61 74 63 68 5f 61 73 79 6e 63 }

        $b1 = { 43 44 44 53 4d 61 63 42 61 73 65 49 6e 66 6f }
        $b2 = {
            68 74 74 70 3a 2f 2f 63
            67 69 31 2e 61 70 6e 69
            63 2e 6e 65 74 2f 63 67
            69 2d 62 69 6e 2f 6d 79
            2d 69 70 2e 70 68 70
        }

        $c = { 25 40 2f 4d 47 44 2f }

        $d1 = {
            44 72 69 76 65 43 72 65 
            64 73
        }
        $d2 = {
            67 65 74 44 72 69 76 65
            54 6f 4d 65 6d 6f 72 79
        }
        $d3 = {
            63 68 65 63 6b 44 72 69
            76 65 43 6d 64 46 69 6c
            65 4c 69 73 74
        }

    condition:
        Macho and filesize < 2MB and
        all of ($a*) and
        (any of ($b*) or all of ($c*)) and
        2 of ($d*)
}

rule XProtect_MACOS_da36796
{
    meta:
        description = "MACOS.da36796"
    strings:
        $ = { 4d 65 74 61 49 6e 73 74 61 6c 6c 65 72 }
        $ = { 53 69 6c 65 6e 74 49 6e 73 74 61 6c 6c 65 72 57 69 6e 64 6f 77 }
        $ = { 69 6e 73 74 61 6c 6c 65 72 2e 70 6c 69 73 74 }
        $ = { 6d 65 74 61 64 61 74 61 55 52 4c }
        $ = { 72 65 70 6f 72 74 55 52 4c }
    condition:
        Macho and all of them and filesize < 1MB
}

rule XProtect_MACOS_KEYSTEAL_A
{
    meta:
        description = "MACOS.KEYSTEAL.A"
    strings:
        $ = { 64 61 74 61 3A 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 2D 61 70 70 6C 65 2D 61 73 70 65 6E 2D 6D 6F 62 69 6C 65 70 72 6F 76 69 73 69 6F 6E 3B 62 61 73 65 36 34 2C 25 40 }
        $ = { 00 6E 65 77 64 65 76 00 6E 65 77 69 64 00 67 6F 67 6F 67 6F 00 }
        $ = { 7B 22 64 61 74 61 22 3A 22 25 40 22 7D }
    condition:
        Macho and all of them and filesize < 1MB
}

rule XProtect_HONKBOX_A
{
    meta:
        description = "MACOS.HONKBOX.A"
    strings:
        $ = { 65 34 70 70 67 7a 75 65 71 6a 69 61 6d 33 71 76 68 7a 66 66 77 72 61 61 6b 76 63 67 7a 72 6a 70 35 64 7a 6c 33 78 7a 76 32 34 77 36 71 35 72 6a 72 37 6b 71 2e 62 33 32 2e 69 32 70 }
        $ = { 69 67 6e 6b 62 70 66 71 75 68 62 36 36 68 67 37 34 64 74 6b 69 71 69 65 74 79 6d 6d 68 63 33 78 77 63 66 77 70 73 70 62 37 36 62 34 77 64 61 64 76 32 63 71 2e 62 33 32 2e 69 32 70 }
        $ = { 70 61 6b 6e 68 33 69 66 6b 33 6d 6a 32 67 71 35 77 36 67 62 66 7a 78 77 61 32 6e 64 36 71 6c 65 6b 6c 77 33 37 72 6c 7a 6f 63 71 69 70 71 37 71 34 6c 63 61 2e 62 33 32 2e 69 32 70 }
        $ = { 68 67 68 73 66 6b 72 61 74 35 64 64 37 69 6b 71 7a 6b 33 64 33 68 35 6a 61 74 74 6a 78 6c 72 75 36 7a 6d 78 7a 78 64 37 79 33 77 69 62 36 67 6f 6f 64 6d 71 2e 62 33 32 2e 69 32 70 }
        $ = { 6a 69 61 73 69 6c 33 61 37 6b 63 78 69 74 75 34 73 77 6c 69 78 62 6e 79 74 36 77 62 62 6d 36 35 6b 71 6b 6e 71 6b 6e 6e 76 6b 6a 32 79 76 6a 37 6c 6c 69 71 2e 62 33 32 2e 69 32 70 }
    condition:
        Macho and any of them and filesize < 200MB
}

rule XProtect_HONKBOX_B
{
    meta:
        description = "MACOS.HONKBOX.B"
    strings:
        $ = { 42 41 53 45 36 34 42 4c 4f 42 3d 22 58 51 41 41 67 41 44 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f }
        $ = { 42 41 53 45 36 34 42 4c 4f 42 20 7c 20 62 61 73 65 36 34 20 2d 6f 20 22 }
        $ = { 52 41 4e 44 4f 4d 20 25 20 31 30 30 30 }
    condition:
        Macho and all of them and filesize < 100MB
}

rule XProtect_HONKBOX_C
{
    meta:
        description = "MACOS.HONKBOX.C"
    strings:
        $ = { 50 4c 44 3d 22 58 51 41 41 67 41 44 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f }
        $ = { 65 63 68 6f 20 24 50 4c 44 20 7c 20 62 61 73 65 36 34 20 2d 64 20 3e 20 22 }
        $ = { 52 41 4e 44 4f 4d 20 25 20 31 30 30 30 }
    condition:
        Macho and all of them and filesize < 5MB
}

rule XProtect_MACOS_16e6816
{
    meta:
        description = "MACOS.16e6816"

    strings:
        $ = { 45 78 74 72 61 63 74 53 61 66 65 53 74 6f 72 61 67 65 50 61 73 73 77 6f 72 64 }
        $ = { 44 65 63 72 79 70 74 4b 65 79 63 68 61 69 6e }
        $ = { 44 75 6d 70 4b 65 79 43 68 61 69 6e }
        $ = { 55 70 6c 6f 61 64 4b 65 79 63 68 61 69 6e }
        $ = { 5a 69 70 46 6f 6c 64 65 72 }
        $ = { 47 65 74 53 65 65 64 73 }
        $ = { 43 55 52 52 45 4e 54 43 68 61 6e 44 69 72 43 6f 69 6e 6f 6d 69 43 6f 6e 76 65 72 74 43 6f 6f 6b 69 65 73 43 72 65 61 74 65 64 43 79 70 72 69 6f 74 }
        $ = { 45 76 69 63 74 4e 53 }

    condition:
        Macho and 6 of them and filesize < 30MB
}

rule XProtect_MACOS_6319b53 {
    meta:
        description = "MACOS.6319b53"
    strings:
        $a = { 5f 75 75 69 64 5f 67 65 6e 65 72 61 74 65 5f 72 61 6e 64 6f 6d }
        $b = { 5f 75 75 69 64 5f 75 6e 70 61 72 73 65 }
        $c = { 5f 73 79 73 63 74 6c }
        $d = { 5f 73 79 73 6c 6f 67 }
        $e = { 5f 67 65 74 67 72 67 69 64 }
        $f = { 5f 67 65 74 70 77 75 69 64 }
        $g = { 5f 53 65 63 54 72 61 6e 73 66 6f 72 6d 45 78 65 63 75 74 65 }
        $h = { 5f 49 4f 53 65 72 76 69 63 65 4d 61 74 63 68 69 6e 67 }
        $i = { 5f 49 4f 53 65 72 76 69 63 65 47 65 74 4d 61 74 63 68 69 6e 67 53 65 72 76 69 63 65}
        $j = { 42 65 72 54 61 67 67 65 64 }
        $k = { 62 65 72 43 6f 6e 74 65 6e 74 }
        $l = { 62 65 72 4c 65 6e 67 74 68 42 79 74 65 73 }
        $m = { 49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 }
        $n = { 49 4f 50 6c 61 74 66 6f 72 6d 53 65 72 69 61 6c 4e 75 6d 62 65 72 }

    condition:
        Macho and all of them and filesize < 4MB
}

rule XProtect_MACOS_SOMA_A
{
    meta:
        description = "MACOS.SOMA.A"

    strings:
        $ = { 47 72 61 62 46 69 72 65 66 6f 78 }
        $ = { 46 69 6c 65 47 72 61 62 62 65 72 }
        $ = { 47 72 61 62 43 68 72 6f 6d ( 65 | 69 75 6d ) }
        $ = { 2f 73 65 6e 64 6c 6f 67 }
        $ = { 42 75 69 6c 64 49 44 }

    condition:
        Macho and all of them and filesize < 200MB
}

rule XProtect_MACOS_SOMA_C
{
    meta:
        description = "MACOS.SOMA.C"

    strings:
        $ = { 53 50 ( 48 61 72 64 | 53 6F 66 74 ) 77 61 72 65 44 61 74 61 54 79 70 65 }
        $ = { 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 }
        $ = { 6b 65 79 63 68 61 69 6e 2d 64 62 }
        $ = { 6f 73 61 73 63 72 69 70 74 }
        $ = { 61 75 74 68 6f 6e 6c 79 }

    condition:
        Macho and all of them and filesize < 2MB
}

rule XProtect_MACOS_SOMA_D
{
    meta:
        description = "MACOS.SOMA.D"

    strings:
        $a01 = { 43 6f 6f 6b 69 65 73 2e 62 69 6e 61 72 79 63 6f 6f 6b 69 65 73 }
        $a02 = { 57 65 62 20 44 61 74 61 }
        $a03 = { 4c 6f 67 69 6e 20 44 61 74 61 }
        $a04 = { 63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65 }
        $a05 = { 66 6f 72 6d 68 69 73 74 6f 72 79 2e 73 71 6c 69 74 65 }
        $a06 = { 6b 65 79 34 2e 64 62 }
        $a07 = { 6c 6f 67 69 6e 73 2e 6a 73 6f 6e }
        $a08 = { 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 }
        $a09 = { 61 75 74 68 6f 6e 6c 79 }
        $a10 = { 6f 73 61 73 63 72 69 70 74 }
        $a11 = { 73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 }
        $a12 = { 53 50 53 6f 66 74 77 61 72 65 44 61 74 61 54 79 70 65 }
        $a13 = { 53 50 48 61 72 64 77 61 72 65 44 61 74 61 54 79 70 65 }
        $a14 = { 53 50 44 69 73 70 6c 61 79 73 44 61 74 61 54 79 70 65 }
        $b1 = { (6f|4f) (6f|4f) (6b|4b) (6a|4a) (6c|4c) (62|42) (6b|4b) (69|49) (69|49) (6a|4a) (69|49) (6e|4e) (68|48) (70|50) (6d|4d) (6e|4e) (6a|4a) (66|46) (66|46) (63|43) (6f|4f) (66|46) (6a|4a) (6f|4f) (6e|4e) (62|42) (66|46) (62|42) (67|47) (61|41) (6f|4f) (63|43) }
        $b1_64 = { 62 32 39 72 61 6d 78 69 61 32 6c 70 61 6d 6c 75 61 48 42 74 62 6d 70 6d 5a 6d 4e 76 5a 6d 70 76 62 6d 4a 6d 59 6d 64 68 62 32 4d 3d }
        $b2 = { (63|43) (67|47) (65|45) (65|45) (6f|4f) (64|44) (70|50) (66|46) (61|41) (67|47) (6a|4a) (63|43) (65|45) (65|45) (66|46) (69|49) (65|45) (66|46) (6c|4c) (6d|4d) (64|44) (66|46) (70|50) (68|48) (70|50) (6c|4c) (6b|4b) (65|45) (6e|4e) (6c|4c) (66|46) (6b|4b) }
        $b2_64 = { 59 32 64 6c 5a 57 39 6b 63 47 5a 68 5a 32 70 6a 5a 57 56 6d 61 57 56 6d 62 47 31 6b 5a 6e 42 6f 63 47 78 72 5a 57 35 73 5a 6d 73 3d }
        $b3 = { (68|48) (6e|4e) (68|48) (6f|4f) (62|42) (6a|4a) (6d|4d) (63|43) (69|49) (62|42) (63|43) (68|48) (6e|4e) (6d|4d) (67|47) (6c|4c) (66|46) (62|42) (6c|4c) (64|44) (62|42) (66|46) (61|41) (62|42) (63|43) (67|47) (61|41) (6b|4b) (6e|4e) (6c|4c) (6b|4b) (6a|4a) }
        $b3_64 = { 61 47 35 6f 62 32 4a 71 62 57 4e 70 59 6d 4e 6f 62 6d 31 6e 62 47 5a 69 62 47 52 69 5a 6d 46 69 59 32 64 68 61 32 35 73 61 32 6f 3d }
        $b4 = { (62|42) (63|43) (6f|4f) (70|50) (67|47) (63|43) (68|48) (68|48) (6f|4f) (6a|4a) (6d|4d) (67|47) (67|47) (6d|4d) (66|46) (66|46) (69|49) (6c|4c) (70|50) (6c|4c) (6d|4d) (62|42) (64|44) (69|49) (63|43) (67|47) (61|41) (69|49) (68|48) (6c|4c) (6b|4b) (70|50) }
        $b4_64 = { 59 6d 4e 76 63 47 64 6a 61 47 68 76 61 6d 31 6e 5a 32 31 6d 5a 6d 6c 73 63 47 78 74 59 6d 52 70 59 32 64 68 61 57 68 73 61 33 41 3d }
        $b5 = { (68|48) (6d|4d) (65|45) (6f|4f) (62|42) (6e|4e) (66|46) (6e|4e) (66|46) (63|43) (6d|4d) (64|44) (6b|4b) (64|44) (63|43) (6d|4d) (6c|4c) (62|42) (6c|4c) (67|47) (61|41) (67|47) (6d|4d) (66|46) (70|50) (66|46) (62|42) (6f|4f) (69|49) (65|45) (61|41) (66|46) }
        $b5_64 = { 61 47 31 6c 62 32 4a 75 5a 6d 35 6d 59 32 31 6b 61 32 52 6a 62 57 78 69 62 47 64 68 5a 32 31 6d 63 47 5a 69 62 32 6c 6c 59 57 59 3d }
        $b6 = { (6e|4e) (6b|4b) (62|42) (69|49) (68|48) (66|46) (62|42) (65|45) (6f|4f) (67|47) (61|41) (65|45) (61|41) (6f|4f) (65|45) (68|48) (6c|4c) (65|45) (66|46) (6e|4e) (6b|4b) (6f|4f) (64|44) (62|42) (65|45) (66|46) (67|47) (70|50) (67|47) (6b|4b) (6e|4e) (6e|4e) }
        $b6_64 = { 62 6d 74 69 61 57 68 6d 59 6d 56 76 5a 32 46 6c 59 57 39 6c 61 47 78 6c 5a 6d 35 72 62 32 52 69 5a 57 5a 6e 63 47 64 72 62 6d 34 3d }

    condition:
        Macho and 3 of ($a*) and 3 of ($b*) and filesize < 200MB
}

rule XProtect_MACOS_SOMA_E
{
    meta:
        description = "MACOS.SOMA.E"

    strings:
        $a   = { 50 4f 53 54 20 2f 70 32 70 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 00 }
        $a00 = { 50 4e 51 57 24 2a 76 35 }
        $a01 = { 51 4d 50 50 25 29 77 3a }
        $a02 = { 52 4c 57 51 26 28 78 3b }
        $a03 = { 53 4b 56 52 27 27 79 38 }
        $a04 = { 54 4a 55 53 28 26 7a 39 }
        $a05 = { 55 49 54 5c 29 25 7b 3e }
        $a06 = { 56 48 5b 5d 2a 24 7c 3f }
        $a07 = { 57 47 5a 5e 2b 23 7d 3c }
        $a08 = { 58 46 59 5f 2c 22 7e 3d }
        $a09 = { 59 45 58 58 2d 21 7f 22 }
        $a0a = { 5a 44 5f 59 2e 20 60 23 }
        $a0b = { 5b 43 5e 5a 2f 3f 61 20 }
        $a0c = { 5c 42 5d 5b 30 3e 62 21 }
        $a0d = { 5d 41 5c 44 31 3d 63 26 }
        $a0e = { 5e 40 43 45 32 3c 64 27 }
        $a0f = { 5f 5f 42 46 33 3b 65 24 }
        $a10 = { 40 5e 41 47 34 3a 66 25 }
        $a11 = { 41 5d 40 40 35 39 67 2a }
        $a12 = { 42 5c 47 41 36 38 68 2b }
        $a13 = { 43 5b 46 42 37 37 69 28 }
        $a14 = { 44 5a 45 43 38 36 6a 29 }
        $a15 = { 45 59 44 4c 39 35 6b 2e }
        $a16 = { 46 58 4b 4d 3a 34 6c 2f }
        $a17 = { 47 57 4a 4e 3b 33 6d 2c }
        $a18 = { 48 56 49 4f 3c 32 6e 2d }
        $a19 = { 49 55 48 48 3d 31 6f 12 }
        $a1a = { 4a 54 4f 49 3e 30 50 13 }
        $a1b = { 4b 53 4e 4a 3f 0f 51 10 }
        $a1c = { 4c 52 4d 4b 00 0e 52 11 }
        $a1d = { 4d 51 4c 74 01 0d 53 16 }
        $a1e = { 4e 50 73 75 02 0c 54 17 }
        $a1f = { 4f 6f 72 76 03 0b 55 14 }
        $a20 = { 70 6e 71 77 04 0a 56 15 }
        $a21 = { 71 6d 70 70 05 09 57 1a }
        $a22 = { 72 6c 77 71 06 08 58 1b }
        $a23 = { 73 6b 76 72 07 07 59 18 }
        $a24 = { 74 6a 75 73 08 06 5a 19 }
        $a25 = { 75 69 74 7c 09 05 5b 1e }
        $a26 = { 76 68 7b 7d 0a 04 5c 1f }
        $a27 = { 77 67 7a 7e 0b 03 5d 1c }
        $a28 = { 78 66 79 7f 0c 02 5e 1d }
        $a29 = { 79 65 78 78 0d 01 5f 02 }
        $a2a = { 7a 64 7f 79 0e 00 40 03 }
        $a2b = { 7b 63 7e 7a 0f 1f 41 00 }
        $a2c = { 7c 62 7d 7b 10 1e 42 01 }
        $a2d = { 7d 61 7c 64 11 1d 43 06 }
        $a2e = { 7e 60 63 65 12 1c 44 07 }
        $a2f = { 7f 7f 62 66 13 1b 45 04 }
        $a30 = { 60 7e 61 67 14 1a 46 05 }
        $a31 = { 61 7d 60 60 15 19 47 0a }
        $a32 = { 62 7c 67 61 16 18 48 0b }
        $a33 = { 63 7b 66 62 17 17 49 08 }
        $a34 = { 64 7a 65 63 18 16 4a 09 }
        $a35 = { 65 79 64 6c 19 15 4b 0e }
        $a36 = { 66 78 6b 6d 1a 14 4c 0f }
        $a37 = { 67 77 6a 6e 1b 13 4d 0c }
        $a38 = { 68 76 69 6f 1c 12 4e 0d }
        $a39 = { 69 75 68 68 1d 11 4f 72 }
        $a3a = { 6a 74 6f 69 1e 10 30 73 }
        $a3b = { 6b 73 6e 6a 1f 6f 31 70 }
        $a3c = { 6c 72 6d 6b 60 6e 32 71 }
        $a3d = { 6d 71 6c 14 61 6d 33 76 }
        $a3e = { 6e 70 13 15 62 6c 34 77 }
        $a3f = { 6f 0f 12 16 63 6b 35 74 }
        $a40 = { 10 0e 11 17 64 6a 36 75 }
        $a41 = { 11 0d 10 10 65 69 37 7a }
        $a42 = { 12 0c 17 11 66 68 38 7b }
        $a43 = { 13 0b 16 12 67 67 39 78 }
        $a44 = { 14 0a 15 13 68 66 3a 79 }
        $a45 = { 15 09 14 1c 69 65 3b 7e }
        $a46 = { 16 08 1b 1d 6a 64 3c 7f }
        $a47 = { 17 07 1a 1e 6b 63 3d 7c }
        $a48 = { 18 06 19 1f 6c 62 3e 7d }
        $a49 = { 19 05 18 18 6d 61 3f 62 }
        $a4a = { 1a 04 1f 19 6e 60 20 63 }
        $a4b = { 1b 03 1e 1a 6f 7f 21 60 }
        $a4c = { 1c 02 1d 1b 70 7e 22 61 }
        $a4d = { 1d 01 1c 04 71 7d 23 66 }
        $a4e = { 1e 00 03 05 72 7c 24 67 }
        $a4f = { 1f 1f 02 06 73 7b 25 64 }
        $a50 = { 00 1e 01 07 74 7a 26 65 }
        $a51 = { 01 1d 00 00 75 79 27 6a }
        $a52 = { 02 1c 07 01 76 78 28 6b }
        $a53 = { 03 1b 06 02 77 77 29 68 }
        $a54 = { 04 1a 05 03 78 76 2a 69 }
        $a55 = { 05 19 04 0c 79 75 2b 6e }
        $a56 = { 06 18 0b 0d 7a 74 2c 6f }
        $a57 = { 07 17 0a 0e 7b 73 2d 6c }
        $a58 = { 08 16 09 0f 7c 72 2e 6d }
        $a59 = { 09 15 08 08 7d 71 2f 52 }
        $a5a = { 0a 14 0f 09 7e 70 10 53 }
        $a5b = { 0b 13 0e 0a 7f 4f 11 50 }
        $a5c = { 0c 12 0d 0b 40 4e 12 51 }
        $a5d = { 0d 11 0c 34 41 4d 13 56 }
        $a5e = { 0e 10 33 35 42 4c 14 57 }
        $a5f = { 0f 2f 32 36 43 4b 15 54 }
        $a60 = { 30 2e 31 37 44 4a 16 55 }
        $a61 = { 31 2d 30 30 45 49 17 5a }
        $a62 = { 32 2c 37 31 46 48 18 5b }
        $a63 = { 33 2b 36 32 47 47 19 58 }
        $a64 = { 34 2a 35 33 48 46 1a 59 }
        $a65 = { 35 29 34 3c 49 45 1b 5e }
        $a66 = { 36 28 3b 3d 4a 44 1c 5f }
        $a67 = { 37 27 3a 3e 4b 43 1d 5c }
        $a68 = { 38 26 39 3f 4c 42 1e 5d }
        $a69 = { 39 25 38 38 4d 41 1f 42 }
        $a6a = { 3a 24 3f 39 4e 40 00 43 }
        $a6b = { 3b 23 3e 3a 4f 5f 01 40 }
        $a6c = { 3c 22 3d 3b 50 5e 02 41 }
        $a6d = { 3d 21 3c 24 51 5d 03 46 }
        $a6e = { 3e 20 23 25 52 5c 04 47 }
        $a6f = { 3f 3f 22 26 53 5b 05 44 }
        $a70 = { 20 3e 21 27 54 5a 06 45 }
        $a71 = { 21 3d 20 20 55 59 07 4a }
        $a72 = { 22 3c 27 21 56 58 08 4b }
        $a73 = { 23 3b 26 22 57 57 09 48 }
        $a74 = { 24 3a 25 23 58 56 0a 49 }
        $a75 = { 25 39 24 2c 59 55 0b 4e }
        $a76 = { 26 38 2b 2d 5a 54 0c 4f }
        $a77 = { 27 37 2a 2e 5b 53 0d 4c }
        $a78 = { 28 36 29 2f 5c 52 0e 4d }
        $a79 = { 29 35 28 28 5d 51 0f b2 }
        $a7a = { 2a 34 2f 29 5e 50 f0 b3 }
        $a7b = { 2b 33 2e 2a 5f af f1 b0 }
        $a7c = { 2c 32 2d 2b a0 ae f2 b1 }
        $a7d = { 2d 31 2c d4 a1 ad f3 b6 }
        $a7e = { 2e 30 d3 d5 a2 ac f4 b7 }
        $a7f = { 2f cf d2 d6 a3 ab f5 b4 }
        $a80 = { d0 ce d1 d7 a4 aa f6 b5 }
        $a81 = { d1 cd d0 d0 a5 a9 f7 ba }
        $a82 = { d2 cc d7 d1 a6 a8 f8 bb }
        $a83 = { d3 cb d6 d2 a7 a7 f9 b8 }
        $a84 = { d4 ca d5 d3 a8 a6 fa b9 }
        $a85 = { d5 c9 d4 dc a9 a5 fb be }
        $a86 = { d6 c8 db dd aa a4 fc bf }
        $a87 = { d7 c7 da de ab a3 fd bc }
        $a88 = { d8 c6 d9 df ac a2 fe bd }
        $a89 = { d9 c5 d8 d8 ad a1 ff a2 }
        $a8a = { da c4 df d9 ae a0 e0 a3 }
        $a8b = { db c3 de da af bf e1 a0 }
        $a8c = { dc c2 dd db b0 be e2 a1 }
        $a8d = { dd c1 dc c4 b1 bd e3 a6 }
        $a8e = { de c0 c3 c5 b2 bc e4 a7 }
        $a8f = { df df c2 c6 b3 bb e5 a4 }
        $a90 = { c0 de c1 c7 b4 ba e6 a5 }
        $a91 = { c1 dd c0 c0 b5 b9 e7 aa }
        $a92 = { c2 dc c7 c1 b6 b8 e8 ab }
        $a93 = { c3 db c6 c2 b7 b7 e9 a8 }
        $a94 = { c4 da c5 c3 b8 b6 ea a9 }
        $a95 = { c5 d9 c4 cc b9 b5 eb ae }
        $a96 = { c6 d8 cb cd ba b4 ec af }
        $a97 = { c7 d7 ca ce bb b3 ed ac }
        $a98 = { c8 d6 c9 cf bc b2 ee ad }
        $a99 = { c9 d5 c8 c8 bd b1 ef 92 }
        $a9a = { ca d4 cf c9 be b0 d0 93 }
        $a9b = { cb d3 ce ca bf 8f d1 90 }
        $a9c = { cc d2 cd cb 80 8e d2 91 }
        $a9d = { cd d1 cc f4 81 8d d3 96 }
        $a9e = { ce d0 f3 f5 82 8c d4 97 }
        $a9f = { cf ef f2 f6 83 8b d5 94 }
        $aa0 = { f0 ee f1 f7 84 8a d6 95 }
        $aa1 = { f1 ed f0 f0 85 89 d7 9a }
        $aa2 = { f2 ec f7 f1 86 88 d8 9b }
        $aa3 = { f3 eb f6 f2 87 87 d9 98 }
        $aa4 = { f4 ea f5 f3 88 86 da 99 }
        $aa5 = { f5 e9 f4 fc 89 85 db 9e }
        $aa6 = { f6 e8 fb fd 8a 84 dc 9f }
        $aa7 = { f7 e7 fa fe 8b 83 dd 9c }
        $aa8 = { f8 e6 f9 ff 8c 82 de 9d }
        $aa9 = { f9 e5 f8 f8 8d 81 df 82 }
        $aaa = { fa e4 ff f9 8e 80 c0 83 }
        $aab = { fb e3 fe fa 8f 9f c1 80 }
        $aac = { fc e2 fd fb 90 9e c2 81 }
        $aad = { fd e1 fc e4 91 9d c3 86 }
        $aae = { fe e0 e3 e5 92 9c c4 87 }
        $aaf = { ff ff e2 e6 93 9b c5 84 }
        $ab0 = { e0 fe e1 e7 94 9a c6 85 }
        $ab1 = { e1 fd e0 e0 95 99 c7 8a }
        $ab2 = { e2 fc e7 e1 96 98 c8 8b }
        $ab3 = { e3 fb e6 e2 97 97 c9 88 }
        $ab4 = { e4 fa e5 e3 98 96 ca 89 }
        $ab5 = { e5 f9 e4 ec 99 95 cb 8e }
        $ab6 = { e6 f8 eb ed 9a 94 cc 8f }
        $ab7 = { e7 f7 ea ee 9b 93 cd 8c }
        $ab8 = { e8 f6 e9 ef 9c 92 ce 8d }
        $ab9 = { e9 f5 e8 e8 9d 91 cf f2 }
        $aba = { ea f4 ef e9 9e 90 b0 f3 }
        $abb = { eb f3 ee ea 9f ef b1 f0 }
        $abc = { ec f2 ed eb e0 ee b2 f1 }
        $abd = { ed f1 ec 94 e1 ed b3 f6 }
        $abe = { ee f0 93 95 e2 ec b4 f7 }
        $abf = { ef 8f 92 96 e3 eb b5 f4 }
        $ac0 = { 90 8e 91 97 e4 ea b6 f5 }
        $ac1 = { 91 8d 90 90 e5 e9 b7 fa }
        $ac2 = { 92 8c 97 91 e6 e8 b8 fb }
        $ac3 = { 93 8b 96 92 e7 e7 b9 f8 }
        $ac4 = { 94 8a 95 93 e8 e6 ba f9 }
        $ac5 = { 95 89 94 9c e9 e5 bb fe }
        $ac6 = { 96 88 9b 9d ea e4 bc ff }
        $ac7 = { 97 87 9a 9e eb e3 bd fc }
        $ac8 = { 98 86 99 9f ec e2 be fd }
        $ac9 = { 99 85 98 98 ed e1 bf e2 }
        $aca = { 9a 84 9f 99 ee e0 a0 e3 }
        $acb = { 9b 83 9e 9a ef ff a1 e0 }
        $acc = { 9c 82 9d 9b f0 fe a2 e1 }
        $acd = { 9d 81 9c 84 f1 fd a3 e6 }
        $ace = { 9e 80 83 85 f2 fc a4 e7 }
        $acf = { 9f 9f 82 86 f3 fb a5 e4 }
        $ad0 = { 80 9e 81 87 f4 fa a6 e5 }
        $ad1 = { 81 9d 80 80 f5 f9 a7 ea }
        $ad2 = { 82 9c 87 81 f6 f8 a8 eb }
        $ad3 = { 83 9b 86 82 f7 f7 a9 e8 }
        $ad4 = { 84 9a 85 83 f8 f6 aa e9 }
        $ad5 = { 85 99 84 8c f9 f5 ab ee }
        $ad6 = { 86 98 8b 8d fa f4 ac ef }
        $ad7 = { 87 97 8a 8e fb f3 ad ec }
        $ad8 = { 88 96 89 8f fc f2 ae ed }
        $ad9 = { 89 95 88 88 fd f1 af d2 }
        $ada = { 8a 94 8f 89 fe f0 90 d3 }
        $adb = { 8b 93 8e 8a ff cf 91 d0 }
        $adc = { 8c 92 8d 8b c0 ce 92 d1 }
        $add = { 8d 91 8c b4 c1 cd 93 d6 }
        $ade = { 8e 90 b3 b5 c2 cc 94 d7 }
        $adf = { 8f af b2 b6 c3 cb 95 d4 }
        $ae0 = { b0 ae b1 b7 c4 ca 96 d5 }
        $ae1 = { b1 ad b0 b0 c5 c9 97 da }
        $ae2 = { b2 ac b7 b1 c6 c8 98 db }
        $ae3 = { b3 ab b6 b2 c7 c7 99 d8 }
        $ae4 = { b4 aa b5 b3 c8 c6 9a d9 }
        $ae5 = { b5 a9 b4 bc c9 c5 9b de }
        $ae6 = { b6 a8 bb bd ca c4 9c df }
        $ae7 = { b7 a7 ba be cb c3 9d dc }
        $ae8 = { b8 a6 b9 bf cc c2 9e dd }
        $ae9 = { b9 a5 b8 b8 cd c1 9f c2 }
        $aea = { ba a4 bf b9 ce c0 80 c3 }
        $aeb = { bb a3 be ba cf df 81 c0 }
        $aec = { bc a2 bd bb d0 de 82 c1 }
        $aed = { bd a1 bc a4 d1 dd 83 c6 }
        $aee = { be a0 a3 a5 d2 dc 84 c7 }
        $aef = { bf bf a2 a6 d3 db 85 c4 }
        $af0 = { a0 be a1 a7 d4 da 86 c5 }
        $af1 = { a1 bd a0 a0 d5 d9 87 ca }
        $af2 = { a2 bc a7 a1 d6 d8 88 cb }
        $af3 = { a3 bb a6 a2 d7 d7 89 c8 }
        $af4 = { a4 ba a5 a3 d8 d6 8a c9 }
        $af5 = { a5 b9 a4 ac d9 d5 8b ce }
        $af6 = { a6 b8 ab ad da d4 8c cf }
        $af7 = { a7 b7 aa ae db d3 8d cc }
        $af8 = { a8 b6 a9 af dc d2 8e cd }
        $af9 = { a9 b5 a8 a8 dd d1 8f 32 }
        $afa = { aa b4 af a9 de d0 70 33 }
        $afb = { ab b3 ae aa df 2f 71 30 }
        $afc = { ac b2 ad ab 20 2e 72 31 }
        $afd = { ad b1 ac 54 21 2d 73 36 }
        $afe = { ae b0 53 55 22 2c 74 37 }
        $aff = { af 4f 52 56 23 2b 75 34 }

        $b   = { 73 65 63 75 72 69 74 79 20 32 3e 26 31 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 66 69 6e 64 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 20 2d 67 61 20 27 43 68 72 6f 6d 65 27 20 7c 20 61 77 6b 20 27 7b 70 72 69 6e 74 20 24 32 7d 27 }
        $b00 = { 2e 45 51 5c 57 71 69 75 }
        $b01 = { 2f 46 50 5b 56 72 68 7a }
        $b02 = { 2c 47 57 5a 55 73 67 7b }
        $b03 = { 2d 40 56 59 54 7c 66 78 }
        $b04 = { 2a 41 55 58 5b 7d 65 79 }
        $b05 = { 2b 42 54 57 5a 7e 64 7e }
        $b06 = { 28 43 5b 56 59 7f 63 7f }
        $b07 = { 29 4c 5a 55 58 78 62 7c }
        $b08 = { 26 4d 59 54 5f 79 61 7d }
        $b09 = { 27 4e 58 53 5e 7a 60 62 }
        $b0a = { 24 4f 5f 52 5d 7b 7f 63 }
        $b0b = { 25 48 5e 51 5c 64 7e 60 }
        $b0c = { 22 49 5d 50 43 65 7d 61 }
        $b0d = { 23 4a 5c 4f 42 66 7c 66 }
        $b0e = { 20 4b 43 4e 41 67 7b 67 }
        $b0f = { 21 54 42 4d 40 60 7a 64 }
        $b10 = { 3e 55 41 4c 47 61 79 65 }
        $b11 = { 3f 56 40 4b 46 62 78 6a }
        $b12 = { 3c 57 47 4a 45 63 77 6b }
        $b13 = { 3d 50 46 49 44 6c 76 68 }
        $b14 = { 3a 51 45 48 4b 6d 75 69 }
        $b15 = { 3b 52 44 47 4a 6e 74 6e }
        $b16 = { 38 53 4b 46 49 6f 73 6f }
        $b17 = { 39 5c 4a 45 48 68 72 6c }
        $b18 = { 36 5d 49 44 4f 69 71 6d }
        $b19 = { 37 5e 48 43 4e 6a 70 52 }
        $b1a = { 34 5f 4f 42 4d 6b 4f 53 }
        $b1b = { 35 58 4e 41 4c 54 4e 50 }
        $b1c = { 32 59 4d 40 73 55 4d 51 }
        $b1d = { 33 5a 4c 7f 72 56 4c 56 }
        $b1e = { 30 5b 73 7e 71 57 4b 57 }
        $b1f = { 31 64 72 7d 70 50 4a 54 }
        $b20 = { 0e 65 71 7c 77 51 49 55 }
        $b21 = { 0f 66 70 7b 76 52 48 5a }
        $b22 = { 0c 67 77 7a 75 53 47 5b }
        $b23 = { 0d 60 76 79 74 5c 46 58 }
        $b24 = { 0a 61 75 78 7b 5d 45 59 }
        $b25 = { 0b 62 74 77 7a 5e 44 5e }
        $b26 = { 08 63 7b 76 79 5f 43 5f }
        $b27 = { 09 6c 7a 75 78 58 42 5c }
        $b28 = { 06 6d 79 74 7f 59 41 5d }
        $b29 = { 07 6e 78 73 7e 5a 40 42 }
        $b2a = { 04 6f 7f 72 7d 5b 5f 43 }
        $b2b = { 05 68 7e 71 7c 44 5e 40 }
        $b2c = { 02 69 7d 70 63 45 5d 41 }
        $b2d = { 03 6a 7c 6f 62 46 5c 46 }
        $b2e = { 00 6b 63 6e 61 47 5b 47 }
        $b2f = { 01 74 62 6d 60 40 5a 44 }
        $b30 = { 1e 75 61 6c 67 41 59 45 }
        $b31 = { 1f 76 60 6b 66 42 58 4a }
        $b32 = { 1c 77 67 6a 65 43 57 4b }
        $b33 = { 1d 70 66 69 64 4c 56 48 }
        $b34 = { 1a 71 65 68 6b 4d 55 49 }
        $b35 = { 1b 72 64 67 6a 4e 54 4e }
        $b36 = { 18 73 6b 66 69 4f 53 4f }
        $b37 = { 19 7c 6a 65 68 48 52 4c }
        $b38 = { 16 7d 69 64 6f 49 51 4d }
        $b39 = { 17 7e 68 63 6e 4a 50 32 }
        $b3a = { 14 7f 6f 62 6d 4b 2f 33 }
        $b3b = { 15 78 6e 61 6c 34 2e 30 }
        $b3c = { 12 79 6d 60 13 35 2d 31 }
        $b3d = { 13 7a 6c 1f 12 36 2c 36 }
        $b3e = { 10 7b 13 1e 11 37 2b 37 }
        $b3f = { 11 04 12 1d 10 30 2a 34 }
        $b40 = { 6e 05 11 1c 17 31 29 35 }
        $b41 = { 6f 06 10 1b 16 32 28 3a }
        $b42 = { 6c 07 17 1a 15 33 27 3b }
        $b43 = { 6d 00 16 19 14 3c 26 38 }
        $b44 = { 6a 01 15 18 1b 3d 25 39 }
        $b45 = { 6b 02 14 17 1a 3e 24 3e }
        $b46 = { 68 03 1b 16 19 3f 23 3f }
        $b47 = { 69 0c 1a 15 18 38 22 3c }
        $b48 = { 66 0d 19 14 1f 39 21 3d }
        $b49 = { 67 0e 18 13 1e 3a 20 22 }
        $b4a = { 64 0f 1f 12 1d 3b 3f 23 }
        $b4b = { 65 08 1e 11 1c 24 3e 20 }
        $b4c = { 62 09 1d 10 03 25 3d 21 }
        $b4d = { 63 0a 1c 0f 02 26 3c 26 }
        $b4e = { 60 0b 03 0e 01 27 3b 27 }
        $b4f = { 61 14 02 0d 00 20 3a 24 }
        $b50 = { 7e 15 01 0c 07 21 39 25 }
        $b51 = { 7f 16 00 0b 06 22 38 2a }
        $b52 = { 7c 17 07 0a 05 23 37 2b }
        $b53 = { 7d 10 06 09 04 2c 36 28 }
        $b54 = { 7a 11 05 08 0b 2d 35 29 }
        $b55 = { 7b 12 04 07 0a 2e 34 2e }
        $b56 = { 78 13 0b 06 09 2f 33 2f }
        $b57 = { 79 1c 0a 05 08 28 32 2c }
        $b58 = { 76 1d 09 04 0f 29 31 2d }
        $b59 = { 77 1e 08 03 0e 2a 30 12 }
        $b5a = { 74 1f 0f 02 0d 2b 0f 13 }
        $b5b = { 75 18 0e 01 0c 14 0e 10 }
        $b5c = { 72 19 0d 00 33 15 0d 11 }
        $b5d = { 73 1a 0c 3f 32 16 0c 16 }
        $b5e = { 70 1b 33 3e 31 17 0b 17 }
        $b5f = { 71 24 32 3d 30 10 0a 14 }
        $b60 = { 4e 25 31 3c 37 11 09 15 }
        $b61 = { 4f 26 30 3b 36 12 08 1a }
        $b62 = { 4c 27 37 3a 35 13 07 1b }
        $b63 = { 4d 20 36 39 34 1c 06 18 }
        $b64 = { 4a 21 35 38 3b 1d 05 19 }
        $b65 = { 4b 22 34 37 3a 1e 04 1e }
        $b66 = { 48 23 3b 36 39 1f 03 1f }
        $b67 = { 49 2c 3a 35 38 18 02 1c }
        $b68 = { 46 2d 39 34 3f 19 01 1d }
        $b69 = { 47 2e 38 33 3e 1a 00 02 }
        $b6a = { 44 2f 3f 32 3d 1b 1f 03 }
        $b6b = { 45 28 3e 31 3c 04 1e 00 }
        $b6c = { 42 29 3d 30 23 05 1d 01 }
        $b6d = { 43 2a 3c 2f 22 06 1c 06 }
        $b6e = { 40 2b 23 2e 21 07 1b 07 }
        $b6f = { 41 34 22 2d 20 00 1a 04 }
        $b70 = { 5e 35 21 2c 27 01 19 05 }
        $b71 = { 5f 36 20 2b 26 02 18 0a }
        $b72 = { 5c 37 27 2a 25 03 17 0b }
        $b73 = { 5d 30 26 29 24 0c 16 08 }
        $b74 = { 5a 31 25 28 2b 0d 15 09 }
        $b75 = { 5b 32 24 27 2a 0e 14 0e }
        $b76 = { 58 33 2b 26 29 0f 13 0f }
        $b77 = { 59 3c 2a 25 28 08 12 0c }
        $b78 = { 56 3d 29 24 2f 09 11 0d }
        $b79 = { 57 3e 28 23 2e 0a 10 f2 }
        $b7a = { 54 3f 2f 22 2d 0b ef f3 }
        $b7b = { 55 38 2e 21 2c f4 ee f0 }
        $b7c = { 52 39 2d 20 d3 f5 ed f1 }
        $b7d = { 53 3a 2c df d2 f6 ec f6 }
        $b7e = { 50 3b d3 de d1 f7 eb f7 }
        $b7f = { 51 c4 d2 dd d0 f0 ea f4 }
        $b80 = { ae c5 d1 dc d7 f1 e9 f5 }
        $b81 = { af c6 d0 db d6 f2 e8 fa }
        $b82 = { ac c7 d7 da d5 f3 e7 fb }
        $b83 = { ad c0 d6 d9 d4 fc e6 f8 }
        $b84 = { aa c1 d5 d8 db fd e5 f9 }
        $b85 = { ab c2 d4 d7 da fe e4 fe }
        $b86 = { a8 c3 db d6 d9 ff e3 ff }
        $b87 = { a9 cc da d5 d8 f8 e2 fc }
        $b88 = { a6 cd d9 d4 df f9 e1 fd }
        $b89 = { a7 ce d8 d3 de fa e0 e2 }
        $b8a = { a4 cf df d2 dd fb ff e3 }
        $b8b = { a5 c8 de d1 dc e4 fe e0 }
        $b8c = { a2 c9 dd d0 c3 e5 fd e1 }
        $b8d = { a3 ca dc cf c2 e6 fc e6 }
        $b8e = { a0 cb c3 ce c1 e7 fb e7 }
        $b8f = { a1 d4 c2 cd c0 e0 fa e4 }
        $b90 = { be d5 c1 cc c7 e1 f9 e5 }
        $b91 = { bf d6 c0 cb c6 e2 f8 ea }
        $b92 = { bc d7 c7 ca c5 e3 f7 eb }
        $b93 = { bd d0 c6 c9 c4 ec f6 e8 }
        $b94 = { ba d1 c5 c8 cb ed f5 e9 }
        $b95 = { bb d2 c4 c7 ca ee f4 ee }
        $b96 = { b8 d3 cb c6 c9 ef f3 ef }
        $b97 = { b9 dc ca c5 c8 e8 f2 ec }
        $b98 = { b6 dd c9 c4 cf e9 f1 ed }
        $b99 = { b7 de c8 c3 ce ea f0 d2 }
        $b9a = { b4 df cf c2 cd eb cf d3 }
        $b9b = { b5 d8 ce c1 cc d4 ce d0 }
        $b9c = { b2 d9 cd c0 f3 d5 cd d1 }
        $b9d = { b3 da cc ff f2 d6 cc d6 }
        $b9e = { b0 db f3 fe f1 d7 cb d7 }
        $b9f = { b1 e4 f2 fd f0 d0 ca d4 }
        $ba0 = { 8e e5 f1 fc f7 d1 c9 d5 }
        $ba1 = { 8f e6 f0 fb f6 d2 c8 da }
        $ba2 = { 8c e7 f7 fa f5 d3 c7 db }
        $ba3 = { 8d e0 f6 f9 f4 dc c6 d8 }
        $ba4 = { 8a e1 f5 f8 fb dd c5 d9 }
        $ba5 = { 8b e2 f4 f7 fa de c4 de }
        $ba6 = { 88 e3 fb f6 f9 df c3 df }
        $ba7 = { 89 ec fa f5 f8 d8 c2 dc }
        $ba8 = { 86 ed f9 f4 ff d9 c1 dd }
        $ba9 = { 87 ee f8 f3 fe da c0 c2 }
        $baa = { 84 ef ff f2 fd db df c3 }
        $bab = { 85 e8 fe f1 fc c4 de c0 }
        $bac = { 82 e9 fd f0 e3 c5 dd c1 }
        $bad = { 83 ea fc ef e2 c6 dc c6 }
        $bae = { 80 eb e3 ee e1 c7 db c7 }
        $baf = { 81 f4 e2 ed e0 c0 da c4 }
        $bb0 = { 9e f5 e1 ec e7 c1 d9 c5 }
        $bb1 = { 9f f6 e0 eb e6 c2 d8 ca }
        $bb2 = { 9c f7 e7 ea e5 c3 d7 cb }
        $bb3 = { 9d f0 e6 e9 e4 cc d6 c8 }
        $bb4 = { 9a f1 e5 e8 eb cd d5 c9 }
        $bb5 = { 9b f2 e4 e7 ea ce d4 ce }
        $bb6 = { 98 f3 eb e6 e9 cf d3 cf }
        $bb7 = { 99 fc ea e5 e8 c8 d2 cc }
        $bb8 = { 96 fd e9 e4 ef c9 d1 cd }
        $bb9 = { 97 fe e8 e3 ee ca d0 b2 }
        $bba = { 94 ff ef e2 ed cb af b3 }
        $bbb = { 95 f8 ee e1 ec b4 ae b0 }
        $bbc = { 92 f9 ed e0 93 b5 ad b1 }
        $bbd = { 93 fa ec 9f 92 b6 ac b6 }
        $bbe = { 90 fb 93 9e 91 b7 ab b7 }
        $bbf = { 91 84 92 9d 90 b0 aa b4 }
        $bc0 = { ee 85 91 9c 97 b1 a9 b5 }
        $bc1 = { ef 86 90 9b 96 b2 a8 ba }
        $bc2 = { ec 87 97 9a 95 b3 a7 bb }
        $bc3 = { ed 80 96 99 94 bc a6 b8 }
        $bc4 = { ea 81 95 98 9b bd a5 b9 }
        $bc5 = { eb 82 94 97 9a be a4 be }
        $bc6 = { e8 83 9b 96 99 bf a3 bf }
        $bc7 = { e9 8c 9a 95 98 b8 a2 bc }
        $bc8 = { e6 8d 99 94 9f b9 a1 bd }
        $bc9 = { e7 8e 98 93 9e ba a0 a2 }
        $bca = { e4 8f 9f 92 9d bb bf a3 }
        $bcb = { e5 88 9e 91 9c a4 be a0 }
        $bcc = { e2 89 9d 90 83 a5 bd a1 }
        $bcd = { e3 8a 9c 8f 82 a6 bc a6 }
        $bce = { e0 8b 83 8e 81 a7 bb a7 }
        $bcf = { e1 94 82 8d 80 a0 ba a4 }
        $bd0 = { fe 95 81 8c 87 a1 b9 a5 }
        $bd1 = { ff 96 80 8b 86 a2 b8 aa }
        $bd2 = { fc 97 87 8a 85 a3 b7 ab }
        $bd3 = { fd 90 86 89 84 ac b6 a8 }
        $bd4 = { fa 91 85 88 8b ad b5 a9 }
        $bd5 = { fb 92 84 87 8a ae b4 ae }
        $bd6 = { f8 93 8b 86 89 af b3 af }
        $bd7 = { f9 9c 8a 85 88 a8 b2 ac }
        $bd8 = { f6 9d 89 84 8f a9 b1 ad }
        $bd9 = { f7 9e 88 83 8e aa b0 92 }
        $bda = { f4 9f 8f 82 8d ab 8f 93 }
        $bdb = { f5 98 8e 81 8c 94 8e 90 }
        $bdc = { f2 99 8d 80 b3 95 8d 91 }
        $bdd = { f3 9a 8c bf b2 96 8c 96 }
        $bde = { f0 9b b3 be b1 97 8b 97 }
        $bdf = { f1 a4 b2 bd b0 90 8a 94 }
        $be0 = { ce a5 b1 bc b7 91 89 95 }
        $be1 = { cf a6 b0 bb b6 92 88 9a }
        $be2 = { cc a7 b7 ba b5 93 87 9b }
        $be3 = { cd a0 b6 b9 b4 9c 86 98 }
        $be4 = { ca a1 b5 b8 bb 9d 85 99 }
        $be5 = { cb a2 b4 b7 ba 9e 84 9e }
        $be6 = { c8 a3 bb b6 b9 9f 83 9f }
        $be7 = { c9 ac ba b5 b8 98 82 9c }
        $be8 = { c6 ad b9 b4 bf 99 81 9d }
        $be9 = { c7 ae b8 b3 be 9a 80 82 }
        $bea = { c4 af bf b2 bd 9b 9f 83 }
        $beb = { c5 a8 be b1 bc 84 9e 80 }
        $bec = { c2 a9 bd b0 a3 85 9d 81 }
        $bed = { c3 aa bc af a2 86 9c 86 }
        $bee = { c0 ab a3 ae a1 87 9b 87 }
        $bef = { c1 b4 a2 ad a0 80 9a 84 }
        $bf0 = { de b5 a1 ac a7 81 99 85 }
        $bf1 = { df b6 a0 ab a6 82 98 8a }
        $bf2 = { dc b7 a7 aa a5 83 97 8b }
        $bf3 = { dd b0 a6 a9 a4 8c 96 88 }
        $bf4 = { da b1 a5 a8 ab 8d 95 89 }
        $bf5 = { db b2 a4 a7 aa 8e 94 8e }
        $bf6 = { d8 b3 ab a6 a9 8f 93 8f }
        $bf7 = { d9 bc aa a5 a8 88 92 8c }
        $bf8 = { d6 bd a9 a4 af 89 91 8d }
        $bf9 = { d7 be a8 a3 ae 8a 90 72 }
        $bfa = { d4 bf af a2 ad 8b 6f 73 }
        $bfb = { d5 b8 ae a1 ac 74 6e 70 }
        $bfc = { d2 b9 ad a0 53 75 6d 71 }
        $bfd = { d3 ba ac 5f 52 76 6c 76 }
        $bfe = { d0 bb 53 5e 51 77 6b 77 }
        $bff = { d1 44 52 5d 50 70 6a 74 }

        $adrop = { 74 65 6c 6c [1-30] 61 70 70 [1-30] 54 65 72 6d 69 6e 61 6c [1-30] 74 6f [1-30] 63 6c 6f 73 65 [1-30] 66 69 72 73 74 [1-30] 77 69 6e 64 6f 77 }
        $bdrop = { 55 53 45 52 00 2f 55 73 65 72 73 2f 00 2f 65 78 65 00 63 68 6d 6f 64 20 2b 78 20 00 72 6d 20 00 }

    condition:
        Macho and any of ($a*) and any of ($b*) and filesize < 4MB
}

rule XProtect_MACOS_SOMA_F
{
    meta:
        description = "MACOS.SOMA.F"

    strings:
        $a = {
            73 79 73 74 65 6d 5f [40-60]
            41 70 70 6c 65 20 56 [240-280]
            64 73 63 6c 20 2f 4c [0-10]
            2f 70 61 73 73 77 6f [30-60]
            2f 6c 6f 67 69 6e 2d
        }

        $b01 = { 72 78 72 75 64 6c 5e 71 73 6e 67 68 6d 64 73 }
        $b02 = { 71 7b 71 76 67 6f 5d 72 70 6d 64 6b 6e 67 70 }
        $b03 = { 70 7a 70 77 66 6e 5c 73 71 6c 65 6a 6f 66 71 }
        $b04 = { 77 7d 77 70 61 69 5b 74 76 6b 62 6d 68 61 76 }
        $b05 = { 76 7c 76 71 60 68 5a 75 77 6a 63 6c 69 60 77 }
        $b06 = { 75 7f 75 72 63 6b 59 76 74 69 60 6f 6a 63 74 }
        $b07 = { 74 7e 74 73 62 6a 58 77 75 68 61 6e 6b 62 75 }
        $b08 = { 7b 71 7b 7c 6d 65 57 78 7a 67 6e 61 64 6d 7a }
        $b09 = { 7a 70 7a 7d 6c 64 56 79 7b 66 6f 60 65 6c 7b }
        $b0a = { 79 73 79 7e 6f 67 55 7a 78 65 6c 63 66 6f 78 }
        $b0b = { 78 72 78 7f 6e 66 54 7b 79 64 6d 62 67 6e 79 }
        $b0c = { 7f 75 7f 78 69 61 53 7c 7e 63 6a 65 60 69 7e }
        $b0d = { 7e 74 7e 79 68 60 52 7d 7f 62 6b 64 61 68 7f }
        $b0e = { 7d 77 7d 7a 6b 63 51 7e 7c 61 68 67 62 6b 7c }
        $b0f = { 7c 76 7c 7b 6a 62 50 7f 7d 60 69 66 63 6a 7d }
        $b10 = { 63 69 63 64 75 7d 4f 60 62 7f 76 79 7c 75 62 }
        $b11 = { 62 68 62 65 74 7c 4e 61 63 7e 77 78 7d 74 63 }
        $b12 = { 61 6b 61 66 77 7f 4d 62 60 7d 74 7b 7e 77 60 }
        $b13 = { 60 6a 60 67 76 7e 4c 63 61 7c 75 7a 7f 76 61 }
        $b14 = { 67 6d 67 60 71 79 4b 64 66 7b 72 7d 78 71 66 }
        $b15 = { 66 6c 66 61 70 78 4a 65 67 7a 73 7c 79 70 67 }
        $b16 = { 65 6f 65 62 73 7b 49 66 64 79 70 7f 7a 73 64 }
        $b17 = { 64 6e 64 63 72 7a 48 67 65 78 71 7e 7b 72 65 }
        $b18 = { 6b 61 6b 6c 7d 75 47 68 6a 77 7e 71 74 7d 6a }
        $b19 = { 6a 60 6a 6d 7c 74 46 69 6b 76 7f 70 75 7c 6b }
        $b1a = { 69 63 69 6e 7f 77 45 6a 68 75 7c 73 76 7f 68 }
        $b1b = { 68 62 68 6f 7e 76 44 6b 69 74 7d 72 77 7e 69 }
        $b1c = { 6f 65 6f 68 79 71 43 6c 6e 73 7a 75 70 79 6e }
        $b1d = { 6e 64 6e 69 78 70 42 6d 6f 72 7b 74 71 78 6f }
        $b1e = { 6d 67 6d 6a 7b 73 41 6e 6c 71 78 77 72 7b 6c }
        $b1f = { 6c 66 6c 6b 7a 72 40 6f 6d 70 79 76 73 7a 6d }
        $b20 = { 53 59 53 54 45 4d 7f 50 52 4f 46 49 4c 45 52 }
        $b21 = { 52 58 52 55 44 4c 7e 51 53 4e 47 48 4d 44 53 }
        $b22 = { 51 5b 51 56 47 4f 7d 52 50 4d 44 4b 4e 47 50 }
        $b23 = { 50 5a 50 57 46 4e 7c 53 51 4c 45 4a 4f 46 51 }
        $b24 = { 57 5d 57 50 41 49 7b 54 56 4b 42 4d 48 41 56 }
        $b25 = { 56 5c 56 51 40 48 7a 55 57 4a 43 4c 49 40 57 }
        $b26 = { 55 5f 55 52 43 4b 79 56 54 49 40 4f 4a 43 54 }
        $b27 = { 54 5e 54 53 42 4a 78 57 55 48 41 4e 4b 42 55 }
        $b28 = { 5b 51 5b 5c 4d 45 77 58 5a 47 4e 41 44 4d 5a }
        $b29 = { 5a 50 5a 5d 4c 44 76 59 5b 46 4f 40 45 4c 5b }
        $b2a = { 59 53 59 5e 4f 47 75 5a 58 45 4c 43 46 4f 58 }
        $b2b = { 58 52 58 5f 4e 46 74 5b 59 44 4d 42 47 4e 59 }
        $b2c = { 5f 55 5f 58 49 41 73 5c 5e 43 4a 45 40 49 5e }
        $b2d = { 5e 54 5e 59 48 40 72 5d 5f 42 4b 44 41 48 5f }
        $b2e = { 5d 57 5d 5a 4b 43 71 5e 5c 41 48 47 42 4b 5c }
        $b2f = { 5c 56 5c 5b 4a 42 70 5f 5d 40 49 46 43 4a 5d }
        $b30 = { 43 49 43 44 55 5d 6f 40 42 5f 56 59 5c 55 42 }
        $b31 = { 42 48 42 45 54 5c 6e 41 43 5e 57 58 5d 54 43 }
        $b32 = { 41 4b 41 46 57 5f 6d 42 40 5d 54 5b 5e 57 40 }
        $b33 = { 40 4a 40 47 56 5e 6c 43 41 5c 55 5a 5f 56 41 }
        $b34 = { 47 4d 47 40 51 59 6b 44 46 5b 52 5d 58 51 46 }
        $b35 = { 46 4c 46 41 50 58 6a 45 47 5a 53 5c 59 50 47 }
        $b36 = { 45 4f 45 42 53 5b 69 46 44 59 50 5f 5a 53 44 }
        $b37 = { 44 4e 44 43 52 5a 68 47 45 58 51 5e 5b 52 45 }
        $b38 = { 4b 41 4b 4c 5d 55 67 48 4a 57 5e 51 54 5d 4a }
        $b39 = { 4a 40 4a 4d 5c 54 66 49 4b 56 5f 50 55 5c 4b }
        $b3a = { 49 43 49 4e 5f 57 65 4a 48 55 5c 53 56 5f 48 }
        $b3b = { 48 42 48 4f 5e 56 64 4b 49 54 5d 52 57 5e 49 }
        $b3c = { 4f 45 4f 48 59 51 63 4c 4e 53 5a 55 50 59 4e }
        $b3d = { 4e 44 4e 49 58 50 62 4d 4f 52 5b 54 51 58 4f }
        $b3e = { 4d 47 4d 4a 5b 53 61 4e 4c 51 58 57 52 5b 4c }
        $b3f = { 4c 46 4c 4b 5a 52 60 4f 4d 50 59 56 53 5a 4d }
        $b40 = { 33 39 33 34 25 2d 1f 30 32 2f 26 29 2c 25 32 }
        $b41 = { 32 38 32 35 24 2c 1e 31 33 2e 27 28 2d 24 33 }
        $b42 = { 31 3b 31 36 27 2f 1d 32 30 2d 24 2b 2e 27 30 }
        $b43 = { 30 3a 30 37 26 2e 1c 33 31 2c 25 2a 2f 26 31 }
        $b44 = { 37 3d 37 30 21 29 1b 34 36 2b 22 2d 28 21 36 }
        $b45 = { 36 3c 36 31 20 28 1a 35 37 2a 23 2c 29 20 37 }
        $b46 = { 35 3f 35 32 23 2b 19 36 34 29 20 2f 2a 23 34 }
        $b47 = { 34 3e 34 33 22 2a 18 37 35 28 21 2e 2b 22 35 }
        $b48 = { 3b 31 3b 3c 2d 25 17 38 3a 27 2e 21 24 2d 3a }
        $b49 = { 3a 30 3a 3d 2c 24 16 39 3b 26 2f 20 25 2c 3b }
        $b4a = { 39 33 39 3e 2f 27 15 3a 38 25 2c 23 26 2f 38 }
        $b4b = { 38 32 38 3f 2e 26 14 3b 39 24 2d 22 27 2e 39 }
        $b4c = { 3f 35 3f 38 29 21 13 3c 3e 23 2a 25 20 29 3e }
        $b4d = { 3e 34 3e 39 28 20 12 3d 3f 22 2b 24 21 28 3f }
        $b4e = { 3d 37 3d 3a 2b 23 11 3e 3c 21 28 27 22 2b 3c }
        $b4f = { 3c 36 3c 3b 2a 22 10 3f 3d 20 29 26 23 2a 3d }
        $b50 = { 23 29 23 24 35 3d 0f 20 22 3f 36 39 3c 35 22 }
        $b51 = { 22 28 22 25 34 3c 0e 21 23 3e 37 38 3d 34 23 }
        $b52 = { 21 2b 21 26 37 3f 0d 22 20 3d 34 3b 3e 37 20 }
        $b53 = { 20 2a 20 27 36 3e 0c 23 21 3c 35 3a 3f 36 21 }
        $b54 = { 27 2d 27 20 31 39 0b 24 26 3b 32 3d 38 31 26 }
        $b55 = { 26 2c 26 21 30 38 0a 25 27 3a 33 3c 39 30 27 }
        $b56 = { 25 2f 25 22 33 3b 09 26 24 39 30 3f 3a 33 24 }
        $b57 = { 24 2e 24 23 32 3a 08 27 25 38 31 3e 3b 32 25 }
        $b58 = { 2b 21 2b 2c 3d 35 07 28 2a 37 3e 31 34 3d 2a }
        $b59 = { 2a 20 2a 2d 3c 34 06 29 2b 36 3f 30 35 3c 2b }
        $b5a = { 29 23 29 2e 3f 37 05 2a 28 35 3c 33 36 3f 28 }
        $b5b = { 28 22 28 2f 3e 36 04 2b 29 34 3d 32 37 3e 29 }
        $b5c = { 2f 25 2f 28 39 31 03 2c 2e 33 3a 35 30 39 2e }
        $b5d = { 2e 24 2e 29 38 30 02 2d 2f 32 3b 34 31 38 2f }
        $b5e = { 2d 27 2d 2a 3b 33 01 2e 2c 31 38 37 32 3b 2c }
        $b5f = { 2c 26 2c 2b 3a 32 00 2f 2d 30 39 36 33 3a 2d }
        $b60 = { 13 19 13 14 05 0d 3f 10 12 0f 06 09 0c 05 12 }
        $b61 = { 12 18 12 15 04 0c 3e 11 13 0e 07 08 0d 04 13 }
        $b62 = { 11 1b 11 16 07 0f 3d 12 10 0d 04 0b 0e 07 10 }
        $b63 = { 10 1a 10 17 06 0e 3c 13 11 0c 05 0a 0f 06 11 }
        $b64 = { 17 1d 17 10 01 09 3b 14 16 0b 02 0d 08 01 16 }
        $b65 = { 16 1c 16 11 00 08 3a 15 17 0a 03 0c 09 00 17 }
        $b66 = { 15 1f 15 12 03 0b 39 16 14 09 00 0f 0a 03 14 }
        $b67 = { 14 1e 14 13 02 0a 38 17 15 08 01 0e 0b 02 15 }
        $b68 = { 1b 11 1b 1c 0d 05 37 18 1a 07 0e 01 04 0d 1a }
        $b69 = { 1a 10 1a 1d 0c 04 36 19 1b 06 0f 00 05 0c 1b }
        $b6a = { 19 13 19 1e 0f 07 35 1a 18 05 0c 03 06 0f 18 }
        $b6b = { 18 12 18 1f 0e 06 34 1b 19 04 0d 02 07 0e 19 }
        $b6c = { 1f 15 1f 18 09 01 33 1c 1e 03 0a 05 00 09 1e }
        $b6d = { 1e 14 1e 19 08 00 32 1d 1f 02 0b 04 01 08 1f }
        $b6e = { 1d 17 1d 1a 0b 03 31 1e 1c 01 08 07 02 0b 1c }
        $b6f = { 1c 16 1c 1b 0a 02 30 1f 1d 00 09 06 03 0a 1d }
        $b70 = { 03 09 03 04 15 1d 2f 00 02 1f 16 19 1c 15 02 }
        $b71 = { 02 08 02 05 14 1c 2e 01 03 1e 17 18 1d 14 03 }
        $b72 = { 01 0b 01 06 17 1f 2d 02 00 1d 14 1b 1e 17 00 }
        $b73 = { 00 0a 00 07 16 1e 2c 03 01 1c 15 1a 1f 16 01 }
        $b74 = { 07 0d 07 00 11 19 2b 04 06 1b 12 1d 18 11 06 }
        $b75 = { 06 0c 06 01 10 18 2a 05 07 1a 13 1c 19 10 07 }
        $b76 = { 05 0f 05 02 13 1b 29 06 04 19 10 1f 1a 13 04 }
        $b77 = { 04 0e 04 03 12 1a 28 07 05 18 11 1e 1b 12 05 }
        $b78 = { 0b 01 0b 0c 1d 15 27 08 0a 17 1e 11 14 1d 0a }
        $b79 = { 0a 00 0a 0d 1c 14 26 09 0b 16 1f 10 15 1c 0b }
        $b7a = { 09 03 09 0e 1f 17 25 0a 08 15 1c 13 16 1f 08 }
        $b7b = { 08 02 08 0f 1e 16 24 0b 09 14 1d 12 17 1e 09 }
        $b7c = { 0f 05 0f 08 19 11 23 0c 0e 13 1a 15 10 19 0e }
        $b7d = { 0e 04 0e 09 18 10 22 0d 0f 12 1b 14 11 18 0f }
        $b7e = { 0d 07 0d 0a 1b 13 21 0e 0c 11 18 17 12 1b 0c }
        $b7f = { 0c 06 0c 0b 1a 12 20 0f 0d 10 19 16 13 1a 0d }
        $b80 = { f3 f9 f3 f4 e5 ed df f0 f2 ef e6 e9 ec e5 f2 }
        $b81 = { f2 f8 f2 f5 e4 ec de f1 f3 ee e7 e8 ed e4 f3 }
        $b82 = { f1 fb f1 f6 e7 ef dd f2 f0 ed e4 eb ee e7 f0 }
        $b83 = { f0 fa f0 f7 e6 ee dc f3 f1 ec e5 ea ef e6 f1 }
        $b84 = { f7 fd f7 f0 e1 e9 db f4 f6 eb e2 ed e8 e1 f6 }
        $b85 = { f6 fc f6 f1 e0 e8 da f5 f7 ea e3 ec e9 e0 f7 }
        $b86 = { f5 ff f5 f2 e3 eb d9 f6 f4 e9 e0 ef ea e3 f4 }
        $b87 = { f4 fe f4 f3 e2 ea d8 f7 f5 e8 e1 ee eb e2 f5 }
        $b88 = { fb f1 fb fc ed e5 d7 f8 fa e7 ee e1 e4 ed fa }
        $b89 = { fa f0 fa fd ec e4 d6 f9 fb e6 ef e0 e5 ec fb }
        $b8a = { f9 f3 f9 fe ef e7 d5 fa f8 e5 ec e3 e6 ef f8 }
        $b8b = { f8 f2 f8 ff ee e6 d4 fb f9 e4 ed e2 e7 ee f9 }
        $b8c = { ff f5 ff f8 e9 e1 d3 fc fe e3 ea e5 e0 e9 fe }
        $b8d = { fe f4 fe f9 e8 e0 d2 fd ff e2 eb e4 e1 e8 ff }
        $b8e = { fd f7 fd fa eb e3 d1 fe fc e1 e8 e7 e2 eb fc }
        $b8f = { fc f6 fc fb ea e2 d0 ff fd e0 e9 e6 e3 ea fd }
        $b90 = { e3 e9 e3 e4 f5 fd cf e0 e2 ff f6 f9 fc f5 e2 }
        $b91 = { e2 e8 e2 e5 f4 fc ce e1 e3 fe f7 f8 fd f4 e3 }
        $b92 = { e1 eb e1 e6 f7 ff cd e2 e0 fd f4 fb fe f7 e0 }
        $b93 = { e0 ea e0 e7 f6 fe cc e3 e1 fc f5 fa ff f6 e1 }
        $b94 = { e7 ed e7 e0 f1 f9 cb e4 e6 fb f2 fd f8 f1 e6 }
        $b95 = { e6 ec e6 e1 f0 f8 ca e5 e7 fa f3 fc f9 f0 e7 }
        $b96 = { e5 ef e5 e2 f3 fb c9 e6 e4 f9 f0 ff fa f3 e4 }
        $b97 = { e4 ee e4 e3 f2 fa c8 e7 e5 f8 f1 fe fb f2 e5 }
        $b98 = { eb e1 eb ec fd f5 c7 e8 ea f7 fe f1 f4 fd ea }
        $b99 = { ea e0 ea ed fc f4 c6 e9 eb f6 ff f0 f5 fc eb }
        $b9a = { e9 e3 e9 ee ff f7 c5 ea e8 f5 fc f3 f6 ff e8 }
        $b9b = { e8 e2 e8 ef fe f6 c4 eb e9 f4 fd f2 f7 fe e9 }
        $b9c = { ef e5 ef e8 f9 f1 c3 ec ee f3 fa f5 f0 f9 ee }
        $b9d = { ee e4 ee e9 f8 f0 c2 ed ef f2 fb f4 f1 f8 ef }
        $b9e = { ed e7 ed ea fb f3 c1 ee ec f1 f8 f7 f2 fb ec }
        $b9f = { ec e6 ec eb fa f2 c0 ef ed f0 f9 f6 f3 fa ed }
        $ba0 = { d3 d9 d3 d4 c5 cd ff d0 d2 cf c6 c9 cc c5 d2 }
        $ba1 = { d2 d8 d2 d5 c4 cc fe d1 d3 ce c7 c8 cd c4 d3 }
        $ba2 = { d1 db d1 d6 c7 cf fd d2 d0 cd c4 cb ce c7 d0 }
        $ba3 = { d0 da d0 d7 c6 ce fc d3 d1 cc c5 ca cf c6 d1 }
        $ba4 = { d7 dd d7 d0 c1 c9 fb d4 d6 cb c2 cd c8 c1 d6 }
        $ba5 = { d6 dc d6 d1 c0 c8 fa d5 d7 ca c3 cc c9 c0 d7 }
        $ba6 = { d5 df d5 d2 c3 cb f9 d6 d4 c9 c0 cf ca c3 d4 }
        $ba7 = { d4 de d4 d3 c2 ca f8 d7 d5 c8 c1 ce cb c2 d5 }
        $ba8 = { db d1 db dc cd c5 f7 d8 da c7 ce c1 c4 cd da }
        $ba9 = { da d0 da dd cc c4 f6 d9 db c6 cf c0 c5 cc db }
        $baa = { d9 d3 d9 de cf c7 f5 da d8 c5 cc c3 c6 cf d8 }
        $bab = { d8 d2 d8 df ce c6 f4 db d9 c4 cd c2 c7 ce d9 }
        $bac = { df d5 df d8 c9 c1 f3 dc de c3 ca c5 c0 c9 de }
        $bad = { de d4 de d9 c8 c0 f2 dd df c2 cb c4 c1 c8 df }
        $bae = { dd d7 dd da cb c3 f1 de dc c1 c8 c7 c2 cb dc }
        $baf = { dc d6 dc db ca c2 f0 df dd c0 c9 c6 c3 ca dd }
        $bb0 = { c3 c9 c3 c4 d5 dd ef c0 c2 df d6 d9 dc d5 c2 }
        $bb1 = { c2 c8 c2 c5 d4 dc ee c1 c3 de d7 d8 dd d4 c3 }
        $bb2 = { c1 cb c1 c6 d7 df ed c2 c0 dd d4 db de d7 c0 }
        $bb3 = { c0 ca c0 c7 d6 de ec c3 c1 dc d5 da df d6 c1 }
        $bb4 = { c7 cd c7 c0 d1 d9 eb c4 c6 db d2 dd d8 d1 c6 }
        $bb5 = { c6 cc c6 c1 d0 d8 ea c5 c7 da d3 dc d9 d0 c7 }
        $bb6 = { c5 cf c5 c2 d3 db e9 c6 c4 d9 d0 df da d3 c4 }
        $bb7 = { c4 ce c4 c3 d2 da e8 c7 c5 d8 d1 de db d2 c5 }
        $bb8 = { cb c1 cb cc dd d5 e7 c8 ca d7 de d1 d4 dd ca }
        $bb9 = { ca c0 ca cd dc d4 e6 c9 cb d6 df d0 d5 dc cb }
        $bba = { c9 c3 c9 ce df d7 e5 ca c8 d5 dc d3 d6 df c8 }
        $bbb = { c8 c2 c8 cf de d6 e4 cb c9 d4 dd d2 d7 de c9 }
        $bbc = { cf c5 cf c8 d9 d1 e3 cc ce d3 da d5 d0 d9 ce }
        $bbd = { ce c4 ce c9 d8 d0 e2 cd cf d2 db d4 d1 d8 cf }
        $bbe = { cd c7 cd ca db d3 e1 ce cc d1 d8 d7 d2 db cc }
        $bbf = { cc c6 cc cb da d2 e0 cf cd d0 d9 d6 d3 da cd }
        $bc0 = { b3 b9 b3 b4 a5 ad 9f b0 b2 af a6 a9 ac a5 b2 }
        $bc1 = { b2 b8 b2 b5 a4 ac 9e b1 b3 ae a7 a8 ad a4 b3 }
        $bc2 = { b1 bb b1 b6 a7 af 9d b2 b0 ad a4 ab ae a7 b0 }
        $bc3 = { b0 ba b0 b7 a6 ae 9c b3 b1 ac a5 aa af a6 b1 }
        $bc4 = { b7 bd b7 b0 a1 a9 9b b4 b6 ab a2 ad a8 a1 b6 }
        $bc5 = { b6 bc b6 b1 a0 a8 9a b5 b7 aa a3 ac a9 a0 b7 }
        $bc6 = { b5 bf b5 b2 a3 ab 99 b6 b4 a9 a0 af aa a3 b4 }
        $bc7 = { b4 be b4 b3 a2 aa 98 b7 b5 a8 a1 ae ab a2 b5 }
        $bc8 = { bb b1 bb bc ad a5 97 b8 ba a7 ae a1 a4 ad ba }
        $bc9 = { ba b0 ba bd ac a4 96 b9 bb a6 af a0 a5 ac bb }
        $bca = { b9 b3 b9 be af a7 95 ba b8 a5 ac a3 a6 af b8 }
        $bcb = { b8 b2 b8 bf ae a6 94 bb b9 a4 ad a2 a7 ae b9 }
        $bcc = { bf b5 bf b8 a9 a1 93 bc be a3 aa a5 a0 a9 be }
        $bcd = { be b4 be b9 a8 a0 92 bd bf a2 ab a4 a1 a8 bf }
        $bce = { bd b7 bd ba ab a3 91 be bc a1 a8 a7 a2 ab bc }
        $bcf = { bc b6 bc bb aa a2 90 bf bd a0 a9 a6 a3 aa bd }
        $bd0 = { a3 a9 a3 a4 b5 bd 8f a0 a2 bf b6 b9 bc b5 a2 }
        $bd1 = { a2 a8 a2 a5 b4 bc 8e a1 a3 be b7 b8 bd b4 a3 }
        $bd2 = { a1 ab a1 a6 b7 bf 8d a2 a0 bd b4 bb be b7 a0 }
        $bd3 = { a0 aa a0 a7 b6 be 8c a3 a1 bc b5 ba bf b6 a1 }
        $bd4 = { a7 ad a7 a0 b1 b9 8b a4 a6 bb b2 bd b8 b1 a6 }
        $bd5 = { a6 ac a6 a1 b0 b8 8a a5 a7 ba b3 bc b9 b0 a7 }
        $bd6 = { a5 af a5 a2 b3 bb 89 a6 a4 b9 b0 bf ba b3 a4 }
        $bd7 = { a4 ae a4 a3 b2 ba 88 a7 a5 b8 b1 be bb b2 a5 }
        $bd8 = { ab a1 ab ac bd b5 87 a8 aa b7 be b1 b4 bd aa }
        $bd9 = { aa a0 aa ad bc b4 86 a9 ab b6 bf b0 b5 bc ab }
        $bda = { a9 a3 a9 ae bf b7 85 aa a8 b5 bc b3 b6 bf a8 }
        $bdb = { a8 a2 a8 af be b6 84 ab a9 b4 bd b2 b7 be a9 }
        $bdc = { af a5 af a8 b9 b1 83 ac ae b3 ba b5 b0 b9 ae }
        $bdd = { ae a4 ae a9 b8 b0 82 ad af b2 bb b4 b1 b8 af }
        $bde = { ad a7 ad aa bb b3 81 ae ac b1 b8 b7 b2 bb ac }
        $bdf = { ac a6 ac ab ba b2 80 af ad b0 b9 b6 b3 ba ad }
        $be0 = { 93 99 93 94 85 8d bf 90 92 8f 86 89 8c 85 92 }
        $be1 = { 92 98 92 95 84 8c be 91 93 8e 87 88 8d 84 93 }
        $be2 = { 91 9b 91 96 87 8f bd 92 90 8d 84 8b 8e 87 90 }
        $be3 = { 90 9a 90 97 86 8e bc 93 91 8c 85 8a 8f 86 91 }
        $be4 = { 97 9d 97 90 81 89 bb 94 96 8b 82 8d 88 81 96 }
        $be5 = { 96 9c 96 91 80 88 ba 95 97 8a 83 8c 89 80 97 }
        $be6 = { 95 9f 95 92 83 8b b9 96 94 89 80 8f 8a 83 94 }
        $be7 = { 94 9e 94 93 82 8a b8 97 95 88 81 8e 8b 82 95 }
        $be8 = { 9b 91 9b 9c 8d 85 b7 98 9a 87 8e 81 84 8d 9a }
        $be9 = { 9a 90 9a 9d 8c 84 b6 99 9b 86 8f 80 85 8c 9b }
        $bea = { 99 93 99 9e 8f 87 b5 9a 98 85 8c 83 86 8f 98 }
        $beb = { 98 92 98 9f 8e 86 b4 9b 99 84 8d 82 87 8e 99 }
        $bec = { 9f 95 9f 98 89 81 b3 9c 9e 83 8a 85 80 89 9e }
        $bed = { 9e 94 9e 99 88 80 b2 9d 9f 82 8b 84 81 88 9f }
        $bee = { 9d 97 9d 9a 8b 83 b1 9e 9c 81 88 87 82 8b 9c }
        $bef = { 9c 96 9c 9b 8a 82 b0 9f 9d 80 89 86 83 8a 9d }
        $bf0 = { 83 89 83 84 95 9d af 80 82 9f 96 99 9c 95 82 }
        $bf1 = { 82 88 82 85 94 9c ae 81 83 9e 97 98 9d 94 83 }
        $bf2 = { 81 8b 81 86 97 9f ad 82 80 9d 94 9b 9e 97 80 }
        $bf3 = { 80 8a 80 87 96 9e ac 83 81 9c 95 9a 9f 96 81 }
        $bf4 = { 87 8d 87 80 91 99 ab 84 86 9b 92 9d 98 91 86 }
        $bf5 = { 86 8c 86 81 90 98 aa 85 87 9a 93 9c 99 90 87 }
        $bf6 = { 85 8f 85 82 93 9b a9 86 84 99 90 9f 9a 93 84 }
        $bf7 = { 84 8e 84 83 92 9a a8 87 85 98 91 9e 9b 92 85 }
        $bf8 = { 8b 81 8b 8c 9d 95 a7 88 8a 97 9e 91 94 9d 8a }
        $bf9 = { 8a 80 8a 8d 9c 94 a6 89 8b 96 9f 90 95 9c 8b }
        $bfa = { 89 83 89 8e 9f 97 a5 8a 88 95 9c 93 96 9f 88 }
        $bfb = { 88 82 88 8f 9e 96 a4 8b 89 94 9d 92 97 9e 89 }
        $bfc = { 8f 85 8f 88 99 91 a3 8c 8e 93 9a 95 90 99 8e }
        $bfd = { 8e 84 8e 89 98 90 a2 8d 8f 92 9b 94 91 98 8f }
        $bfe = { 8d 87 8d 8a 9b 93 a1 8e 8c 91 98 97 92 9b 8c }
        $bff = { 8c 86 8c 8b 9a 92 a0 8f 8d 90 99 96 93 9a 8d }

        $c00 = { 6f 73 61 73 63 72 69 70 74 }
        $c01 = { 6e 72 60 72 62 73 68 71 75 }
        $c02 = { 6d 71 63 71 61 70 6b 72 76 }
        $c03 = { 6c 70 62 70 60 71 6a 73 77 }
        $c04 = { 6b 77 65 77 67 76 6d 74 70 }
        $c05 = { 6a 76 64 76 66 77 6c 75 71 }
        $c06 = { 69 75 67 75 65 74 6f 76 72 }
        $c07 = { 68 74 66 74 64 75 6e 77 73 }
        $c08 = { 67 7b 69 7b 6b 7a 61 78 7c }
        $c09 = { 66 7a 68 7a 6a 7b 60 79 7d }
        $c0a = { 65 79 6b 79 69 78 63 7a 7e }
        $c0b = { 64 78 6a 78 68 79 62 7b 7f }
        $c0c = { 63 7f 6d 7f 6f 7e 65 7c 78 }
        $c0d = { 62 7e 6c 7e 6e 7f 64 7d 79 }
        $c0e = { 61 7d 6f 7d 6d 7c 67 7e 7a }
        $c0f = { 60 7c 6e 7c 6c 7d 66 7f 7b }
        $c10 = { 7f 63 71 63 73 62 79 60 64 }
        $c11 = { 7e 62 70 62 72 63 78 61 65 }
        $c12 = { 7d 61 73 61 71 60 7b 62 66 }
        $c13 = { 7c 60 72 60 70 61 7a 63 67 }
        $c14 = { 7b 67 75 67 77 66 7d 64 60 }
        $c15 = { 7a 66 74 66 76 67 7c 65 61 }
        $c16 = { 79 65 77 65 75 64 7f 66 62 }
        $c17 = { 78 64 76 64 74 65 7e 67 63 }
        $c18 = { 77 6b 79 6b 7b 6a 71 68 6c }
        $c19 = { 76 6a 78 6a 7a 6b 70 69 6d }
        $c1a = { 75 69 7b 69 79 68 73 6a 6e }
        $c1b = { 74 68 7a 68 78 69 72 6b 6f }
        $c1c = { 73 6f 7d 6f 7f 6e 75 6c 68 }
        $c1d = { 72 6e 7c 6e 7e 6f 74 6d 69 }
        $c1e = { 71 6d 7f 6d 7d 6c 77 6e 6a }
        $c1f = { 70 6c 7e 6c 7c 6d 76 6f 6b }
        $c20 = { 4f 53 41 53 43 52 49 50 54 }
        $c21 = { 4e 52 40 52 42 53 48 51 55 }
        $c22 = { 4d 51 43 51 41 50 4b 52 56 }
        $c23 = { 4c 50 42 50 40 51 4a 53 57 }
        $c24 = { 4b 57 45 57 47 56 4d 54 50 }
        $c25 = { 4a 56 44 56 46 57 4c 55 51 }
        $c26 = { 49 55 47 55 45 54 4f 56 52 }
        $c27 = { 48 54 46 54 44 55 4e 57 53 }
        $c28 = { 47 5b 49 5b 4b 5a 41 58 5c }
        $c29 = { 46 5a 48 5a 4a 5b 40 59 5d }
        $c2a = { 45 59 4b 59 49 58 43 5a 5e }
        $c2b = { 44 58 4a 58 48 59 42 5b 5f }
        $c2c = { 43 5f 4d 5f 4f 5e 45 5c 58 }
        $c2d = { 42 5e 4c 5e 4e 5f 44 5d 59 }
        $c2e = { 41 5d 4f 5d 4d 5c 47 5e 5a }
        $c2f = { 40 5c 4e 5c 4c 5d 46 5f 5b }
        $c30 = { 5f 43 51 43 53 42 59 40 44 }
        $c31 = { 5e 42 50 42 52 43 58 41 45 }
        $c32 = { 5d 41 53 41 51 40 5b 42 46 }
        $c33 = { 5c 40 52 40 50 41 5a 43 47 }
        $c34 = { 5b 47 55 47 57 46 5d 44 40 }
        $c35 = { 5a 46 54 46 56 47 5c 45 41 }
        $c36 = { 59 45 57 45 55 44 5f 46 42 }
        $c37 = { 58 44 56 44 54 45 5e 47 43 }
        $c38 = { 57 4b 59 4b 5b 4a 51 48 4c }
        $c39 = { 56 4a 58 4a 5a 4b 50 49 4d }
        $c3a = { 55 49 5b 49 59 48 53 4a 4e }
        $c3b = { 54 48 5a 48 58 49 52 4b 4f }
        $c3c = { 53 4f 5d 4f 5f 4e 55 4c 48 }
        $c3d = { 52 4e 5c 4e 5e 4f 54 4d 49 }
        $c3e = { 51 4d 5f 4d 5d 4c 57 4e 4a }
        $c3f = { 50 4c 5e 4c 5c 4d 56 4f 4b }
        $c40 = { 2f 33 21 33 23 32 29 30 34 }
        $c41 = { 2e 32 20 32 22 33 28 31 35 }
        $c42 = { 2d 31 23 31 21 30 2b 32 36 }
        $c43 = { 2c 30 22 30 20 31 2a 33 37 }
        $c44 = { 2b 37 25 37 27 36 2d 34 30 }
        $c45 = { 2a 36 24 36 26 37 2c 35 31 }
        $c46 = { 29 35 27 35 25 34 2f 36 32 }
        $c47 = { 28 34 26 34 24 35 2e 37 33 }
        $c48 = { 27 3b 29 3b 2b 3a 21 38 3c }
        $c49 = { 26 3a 28 3a 2a 3b 20 39 3d }
        $c4a = { 25 39 2b 39 29 38 23 3a 3e }
        $c4b = { 24 38 2a 38 28 39 22 3b 3f }
        $c4c = { 23 3f 2d 3f 2f 3e 25 3c 38 }
        $c4d = { 22 3e 2c 3e 2e 3f 24 3d 39 }
        $c4e = { 21 3d 2f 3d 2d 3c 27 3e 3a }
        $c4f = { 20 3c 2e 3c 2c 3d 26 3f 3b }
        $c50 = { 3f 23 31 23 33 22 39 20 24 }
        $c51 = { 3e 22 30 22 32 23 38 21 25 }
        $c52 = { 3d 21 33 21 31 20 3b 22 26 }
        $c53 = { 3c 20 32 20 30 21 3a 23 27 }
        $c54 = { 3b 27 35 27 37 26 3d 24 20 }
        $c55 = { 3a 26 34 26 36 27 3c 25 21 }
        $c56 = { 39 25 37 25 35 24 3f 26 22 }
        $c57 = { 38 24 36 24 34 25 3e 27 23 }
        $c58 = { 37 2b 39 2b 3b 2a 31 28 2c }
        $c59 = { 36 2a 38 2a 3a 2b 30 29 2d }
        $c5a = { 35 29 3b 29 39 28 33 2a 2e }
        $c5b = { 34 28 3a 28 38 29 32 2b 2f }
        $c5c = { 33 2f 3d 2f 3f 2e 35 2c 28 }
        $c5d = { 32 2e 3c 2e 3e 2f 34 2d 29 }
        $c5e = { 31 2d 3f 2d 3d 2c 37 2e 2a }
        $c5f = { 30 2c 3e 2c 3c 2d 36 2f 2b }
        $c60 = { 0f 13 01 13 03 12 09 10 14 }
        $c61 = { 0e 12 00 12 02 13 08 11 15 }
        $c62 = { 0d 11 03 11 01 10 0b 12 16 }
        $c63 = { 0c 10 02 10 00 11 0a 13 17 }
        $c64 = { 0b 17 05 17 07 16 0d 14 10 }
        $c65 = { 0a 16 04 16 06 17 0c 15 11 }
        $c66 = { 09 15 07 15 05 14 0f 16 12 }
        $c67 = { 08 14 06 14 04 15 0e 17 13 }
        $c68 = { 07 1b 09 1b 0b 1a 01 18 1c }
        $c69 = { 06 1a 08 1a 0a 1b 00 19 1d }
        $c6a = { 05 19 0b 19 09 18 03 1a 1e }
        $c6b = { 04 18 0a 18 08 19 02 1b 1f }
        $c6c = { 03 1f 0d 1f 0f 1e 05 1c 18 }
        $c6d = { 02 1e 0c 1e 0e 1f 04 1d 19 }
        $c6e = { 01 1d 0f 1d 0d 1c 07 1e 1a }
        $c6f = { 00 1c 0e 1c 0c 1d 06 1f 1b }
        $c70 = { 1f 03 11 03 13 02 19 00 04 }
        $c71 = { 1e 02 10 02 12 03 18 01 05 }
        $c72 = { 1d 01 13 01 11 00 1b 02 06 }
        $c73 = { 1c 00 12 00 10 01 1a 03 07 }
        $c74 = { 1b 07 15 07 17 06 1d 04 00 }
        $c75 = { 1a 06 14 06 16 07 1c 05 01 }
        $c76 = { 19 05 17 05 15 04 1f 06 02 }
        $c77 = { 18 04 16 04 14 05 1e 07 03 }
        $c78 = { 17 0b 19 0b 1b 0a 11 08 0c }
        $c79 = { 16 0a 18 0a 1a 0b 10 09 0d }
        $c7a = { 15 09 1b 09 19 08 13 0a 0e }
        $c7b = { 14 08 1a 08 18 09 12 0b 0f }
        $c7c = { 13 0f 1d 0f 1f 0e 15 0c 08 }
        $c7d = { 12 0e 1c 0e 1e 0f 14 0d 09 }
        $c7e = { 11 0d 1f 0d 1d 0c 17 0e 0a }
        $c7f = { 10 0c 1e 0c 1c 0d 16 0f 0b }
        $c80 = { ef f3 e1 f3 e3 f2 e9 f0 f4 }
        $c81 = { ee f2 e0 f2 e2 f3 e8 f1 f5 }
        $c82 = { ed f1 e3 f1 e1 f0 eb f2 f6 }
        $c83 = { ec f0 e2 f0 e0 f1 ea f3 f7 }
        $c84 = { eb f7 e5 f7 e7 f6 ed f4 f0 }
        $c85 = { ea f6 e4 f6 e6 f7 ec f5 f1 }
        $c86 = { e9 f5 e7 f5 e5 f4 ef f6 f2 }
        $c87 = { e8 f4 e6 f4 e4 f5 ee f7 f3 }
        $c88 = { e7 fb e9 fb eb fa e1 f8 fc }
        $c89 = { e6 fa e8 fa ea fb e0 f9 fd }
        $c8a = { e5 f9 eb f9 e9 f8 e3 fa fe }
        $c8b = { e4 f8 ea f8 e8 f9 e2 fb ff }
        $c8c = { e3 ff ed ff ef fe e5 fc f8 }
        $c8d = { e2 fe ec fe ee ff e4 fd f9 }
        $c8e = { e1 fd ef fd ed fc e7 fe fa }
        $c8f = { e0 fc ee fc ec fd e6 ff fb }
        $c90 = { ff e3 f1 e3 f3 e2 f9 e0 e4 }
        $c91 = { fe e2 f0 e2 f2 e3 f8 e1 e5 }
        $c92 = { fd e1 f3 e1 f1 e0 fb e2 e6 }
        $c93 = { fc e0 f2 e0 f0 e1 fa e3 e7 }
        $c94 = { fb e7 f5 e7 f7 e6 fd e4 e0 }
        $c95 = { fa e6 f4 e6 f6 e7 fc e5 e1 }
        $c96 = { f9 e5 f7 e5 f5 e4 ff e6 e2 }
        $c97 = { f8 e4 f6 e4 f4 e5 fe e7 e3 }
        $c98 = { f7 eb f9 eb fb ea f1 e8 ec }
        $c99 = { f6 ea f8 ea fa eb f0 e9 ed }
        $c9a = { f5 e9 fb e9 f9 e8 f3 ea ee }
        $c9b = { f4 e8 fa e8 f8 e9 f2 eb ef }
        $c9c = { f3 ef fd ef ff ee f5 ec e8 }
        $c9d = { f2 ee fc ee fe ef f4 ed e9 }
        $c9e = { f1 ed ff ed fd ec f7 ee ea }
        $c9f = { f0 ec fe ec fc ed f6 ef eb }
        $ca0 = { cf d3 c1 d3 c3 d2 c9 d0 d4 }
        $ca1 = { ce d2 c0 d2 c2 d3 c8 d1 d5 }
        $ca2 = { cd d1 c3 d1 c1 d0 cb d2 d6 }
        $ca3 = { cc d0 c2 d0 c0 d1 ca d3 d7 }
        $ca4 = { cb d7 c5 d7 c7 d6 cd d4 d0 }
        $ca5 = { ca d6 c4 d6 c6 d7 cc d5 d1 }
        $ca6 = { c9 d5 c7 d5 c5 d4 cf d6 d2 }
        $ca7 = { c8 d4 c6 d4 c4 d5 ce d7 d3 }
        $ca8 = { c7 db c9 db cb da c1 d8 dc }
        $ca9 = { c6 da c8 da ca db c0 d9 dd }
        $caa = { c5 d9 cb d9 c9 d8 c3 da de }
        $cab = { c4 d8 ca d8 c8 d9 c2 db df }
        $cac = { c3 df cd df cf de c5 dc d8 }
        $cad = { c2 de cc de ce df c4 dd d9 }
        $cae = { c1 dd cf dd cd dc c7 de da }
        $caf = { c0 dc ce dc cc dd c6 df db }
        $cb0 = { df c3 d1 c3 d3 c2 d9 c0 c4 }
        $cb1 = { de c2 d0 c2 d2 c3 d8 c1 c5 }
        $cb2 = { dd c1 d3 c1 d1 c0 db c2 c6 }
        $cb3 = { dc c0 d2 c0 d0 c1 da c3 c7 }
        $cb4 = { db c7 d5 c7 d7 c6 dd c4 c0 }
        $cb5 = { da c6 d4 c6 d6 c7 dc c5 c1 }
        $cb6 = { d9 c5 d7 c5 d5 c4 df c6 c2 }
        $cb7 = { d8 c4 d6 c4 d4 c5 de c7 c3 }
        $cb8 = { d7 cb d9 cb db ca d1 c8 cc }
        $cb9 = { d6 ca d8 ca da cb d0 c9 cd }
        $cba = { d5 c9 db c9 d9 c8 d3 ca ce }
        $cbb = { d4 c8 da c8 d8 c9 d2 cb cf }
        $cbc = { d3 cf dd cf df ce d5 cc c8 }
        $cbd = { d2 ce dc ce de cf d4 cd c9 }
        $cbe = { d1 cd df cd dd cc d7 ce ca }
        $cbf = { d0 cc de cc dc cd d6 cf cb }
        $cc0 = { af b3 a1 b3 a3 b2 a9 b0 b4 }
        $cc1 = { ae b2 a0 b2 a2 b3 a8 b1 b5 }
        $cc2 = { ad b1 a3 b1 a1 b0 ab b2 b6 }
        $cc3 = { ac b0 a2 b0 a0 b1 aa b3 b7 }
        $cc4 = { ab b7 a5 b7 a7 b6 ad b4 b0 }
        $cc5 = { aa b6 a4 b6 a6 b7 ac b5 b1 }
        $cc6 = { a9 b5 a7 b5 a5 b4 af b6 b2 }
        $cc7 = { a8 b4 a6 b4 a4 b5 ae b7 b3 }
        $cc8 = { a7 bb a9 bb ab ba a1 b8 bc }
        $cc9 = { a6 ba a8 ba aa bb a0 b9 bd }
        $cca = { a5 b9 ab b9 a9 b8 a3 ba be }
        $ccb = { a4 b8 aa b8 a8 b9 a2 bb bf }
        $ccc = { a3 bf ad bf af be a5 bc b8 }
        $ccd = { a2 be ac be ae bf a4 bd b9 }
        $cce = { a1 bd af bd ad bc a7 be ba }
        $ccf = { a0 bc ae bc ac bd a6 bf bb }
        $cd0 = { bf a3 b1 a3 b3 a2 b9 a0 a4 }
        $cd1 = { be a2 b0 a2 b2 a3 b8 a1 a5 }
        $cd2 = { bd a1 b3 a1 b1 a0 bb a2 a6 }
        $cd3 = { bc a0 b2 a0 b0 a1 ba a3 a7 }
        $cd4 = { bb a7 b5 a7 b7 a6 bd a4 a0 }
        $cd5 = { ba a6 b4 a6 b6 a7 bc a5 a1 }
        $cd6 = { b9 a5 b7 a5 b5 a4 bf a6 a2 }
        $cd7 = { b8 a4 b6 a4 b4 a5 be a7 a3 }
        $cd8 = { b7 ab b9 ab bb aa b1 a8 ac }
        $cd9 = { b6 aa b8 aa ba ab b0 a9 ad }
        $cda = { b5 a9 bb a9 b9 a8 b3 aa ae }
        $cdb = { b4 a8 ba a8 b8 a9 b2 ab af }
        $cdc = { b3 af bd af bf ae b5 ac a8 }
        $cdd = { b2 ae bc ae be af b4 ad a9 }
        $cde = { b1 ad bf ad bd ac b7 ae aa }
        $cdf = { b0 ac be ac bc ad b6 af ab }
        $ce0 = { 8f 93 81 93 83 92 89 90 94 }
        $ce1 = { 8e 92 80 92 82 93 88 91 95 }
        $ce2 = { 8d 91 83 91 81 90 8b 92 96 }
        $ce3 = { 8c 90 82 90 80 91 8a 93 97 }
        $ce4 = { 8b 97 85 97 87 96 8d 94 90 }
        $ce5 = { 8a 96 84 96 86 97 8c 95 91 }
        $ce6 = { 89 95 87 95 85 94 8f 96 92 }
        $ce7 = { 88 94 86 94 84 95 8e 97 93 }
        $ce8 = { 87 9b 89 9b 8b 9a 81 98 9c }
        $ce9 = { 86 9a 88 9a 8a 9b 80 99 9d }
        $cea = { 85 99 8b 99 89 98 83 9a 9e }
        $ceb = { 84 98 8a 98 88 99 82 9b 9f }
        $cec = { 83 9f 8d 9f 8f 9e 85 9c 98 }
        $ced = { 82 9e 8c 9e 8e 9f 84 9d 99 }
        $cee = { 81 9d 8f 9d 8d 9c 87 9e 9a }
        $cef = { 80 9c 8e 9c 8c 9d 86 9f 9b }
        $cf0 = { 9f 83 91 83 93 82 99 80 84 }
        $cf1 = { 9e 82 90 82 92 83 98 81 85 }
        $cf2 = { 9d 81 93 81 91 80 9b 82 86 }
        $cf3 = { 9c 80 92 80 90 81 9a 83 87 }
        $cf4 = { 9b 87 95 87 97 86 9d 84 80 }
        $cf5 = { 9a 86 94 86 96 87 9c 85 81 }
        $cf6 = { 99 85 97 85 95 84 9f 86 82 }
        $cf7 = { 98 84 96 84 94 85 9e 87 83 }
        $cf8 = { 97 8b 99 8b 9b 8a 91 88 8c }
        $cf9 = { 96 8a 98 8a 9a 8b 90 89 8d }
        $cfa = { 95 89 9b 89 99 88 93 8a 8e }
        $cfb = { 94 88 9a 88 98 89 92 8b 8f }
        $cfc = { 93 8f 9d 8f 9f 8e 95 8c 88 }
        $cfd = { 92 8e 9c 8e 9e 8f 94 8d 89 }
        $cfe = { 91 8d 9f 8d 9d 8c 97 8e 8a }
        $cff = { 90 8c 9e 8c 9c 8d 96 8f 8b }

    condition:
        Macho and (any of ($a*) or (any of ($b*) and any of ($c*))) and filesize < 2MB
}

rule XProtect_MACOS_CHERRYPIE_A
{
    meta:
        description = "MACOS.CHERRYPIE.A"
    
    strings:
        $ = { 66 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 73 74 64 69 6e 20 70 69 70 65 3a 20 25 76 }
        $ = { 63 6f 6d 6d 61 6e 64 20 66 69 6e 69 73 68 65 64 20 77 69 74 68 20 65 72 72 6f 72 3a 20 25 76 }
        $ = { 2e 44 69 73 61 6c 6c 6f 77 45 6d 70 74 79 }
        $ = { 2e 48 69 64 65 54 65 78 74 }
        $ = { 2e 4e 6f 43 61 6e 63 65 6c }

    condition:
        Macho and all of them and filesize < 40MB    
}

rule XProtect_MACOS_ADLOAD_WSS {
    meta:
        description = "MACOS.ADLOAD.WSS"
    strings:
        $a = { 6d 5f 63 75 72 73 6f 72 20 2d 20 6d 5f 73 74 61 72 74 20 3e 3d 20 32 }
        $b = { 66 69 6c 6c 5f 6c 69 6e 65 5f 62 75 66 66 65 72 }
        $c = { 42 65 72 54 61 67 67 65 64 }
        $d = { 6d 69 73 73 69 6e 67 20 6f 72 20 77 72 6f 6e 67 20 6c 6f 77 20 73 75 72 72 6f 67 61 74 65 }

    condition:
        Macho and all of them and filesize < 14MB
}

rule XProtect_MACOS_BUNDLORE_E
{
    meta:
        description = "MACOS.BUNDLORE.E"

    strings:
        $ = { 6d 6d 50 61 73 73 77 64 53 75 63 63 65 73 73 }
        $ = { 69 64 20 2d 75 6e 20 35 30 31 }
        $ = { 69 73 5f 72 6f 6f 74 3d 24 7b 69 73 52 6f 6f 74 7d }
        $ = { 63 6c 69 65 6e 74 2e 6d 6d 2d 62 71 2e 68 6f 73 74 }
        $ = { 70 65 72 69 6f 64 69 6b 61 6c 2e 63 6f 6d }

    condition:
        4 of them
}

rule XProtect_BUNDLORE_resource_fork
{
    meta:
        description = "MACOS.BUNDLORE.SCRIPT"
    strings:
        $shebang = "#!"
        $resource_fork = "$0/..namedfork/rsrc" fullword
        $tail = "tail -c" fullword
    condition:
        $shebang at 0 and
        all of them
}

rule XProtect_MACOS_BUNDLORE_Symbols
{
    meta:
        description = "MACOS.BUNDLORE"
    strings:
        $tbt_check_if_mm_search_exists = "__tbt_checkIfmmSearchExists:"
        $tbt_check_if_file_exisrs_at_application_support = "__tbt_checkIfFileExitsAtApplicationsSupport:"
    condition:
        Macho and any of them
}

rule XProtect_MULTI_SNOWCAR
{
    meta:
        description = "MULTI.SNOWCAR"
    strings:
        $command_test = { 05 6c 18 00 09 00 1f 00 18 00 4c 00 }
        $command_run = { 04 ab d9 00 de 00 c5 00 8b 00 }
        $command_port_scan = { 0a 60 10 00 0f 00 12 00 14 00 3f 00 13 00 03 00 01 00 0e 00 40 00 }
        $command_ping_scan = { 0a 75 05 00 1c 00 1b 00 12 00 2a 00 06 00 16 00 14 00 1b 00 55 00 }
    condition:
        2 of them
}

rule XProtect_MACOS_SHEEPSWAP_OBFCOMMON
{
    meta:
        description = "MACOS.SHEEPSWAP.OBFCOMMON"

    strings:
        $a1 = { 60 10 10 10 80 01 10 40 10 10 10 10 10 10 10 10 }
        $a2 = { 48 8D 7D C8 48 89 CE 48 89 C2 E8 78 13 00 00 0F }
        $a3 = { 47 8A 27 26 33 33 FC A0 74 BC AF EB 41 AD 86 C9 }
        $a4 = { 10 48 85 C1 0F 84 7F 01 00 00 48 FF C8 48 21 C2 }
        $b = { 53 61 66 61 72 69 45 78 74 65 6e 73 69 6f 6e 48 61 6e 64 6c 65 72 }
    
    condition:
        Macho and 2 of ($a*) and $b
}

rule XProtect_MACOS_2fc5997
{
    meta:
        description = "MACOS.2fc5997"
    strings:
		$a0 = { 23 21 2f 62 69 6e 2f (62 61 73 68 | 73 68) }
        $b0 = { 63 75 72 6c 20 2d 73 20 2d 4c 20 2d 6f 20 22 2f 76 61 72 2f 74 6d 70 2f [3-15] 2e 74 67 7a 22 }
        $b1 = { 68 74 74 70 3a 2f 2f [12-20] 2f 73 74 61 74 69 63 2f 73 33 2f 65 78 65 63 36 36 32 35 2f [3-15] 2e 74 67 7a }
        $b2 = { 6d 6b 64 69 72 20 2d 70 20 2f 76 61 72 2f 74 6d 70 }
        $b3 = { 74 61 72 20 2d 78 7a 66 20 22 2f 76 61 72 2f 74 6d 70 2f [3-15] 2e 74 67 7a 22 20 2d 43 20 22 2f 76 61 72 2f 74 6d 70 2f [3-15] 2f 22 }
        $b4 = { 66 75 6e 63 5f [1-12] (28 | 20 26) }
        $b5 = { 73 6c 65 65 70 20 3? 3? 3? }
    condition:
        $a0 at 0 and filesize < 50KB and 4 of ($b*)
}

rule XProtect_MACOS_a6d7810
{
    meta:
		description = "MACOS.a6d7810"

    strings:
        $a0 = { 40 5f 49 4f 53 65 72 76 69 63 65 4d 61 74 63 68 69 6e 67 }
        $a1 = { 40 5f 49 4f 52 65 67 69 73 74 72 79 45 6e 74 72 79 43 72 65 61 74 65 43 46 50 72 6f 70 65 72 74 79 }
        
     	$b0 = { 
			00 8b d5 df 3d d3 8f 3e
			30 d6 55 26 39 a7 e6 fe 
			16 ea 5f 66 14 c2 72 b3 
			0d f6 1c c9 01 a5 6b 68 
			96 c2 9f 45 4e 7d 62 2b 
			e8 72 dd ea 99 cf 96 66 
			7c 54 1f 88 c7 1c e6 d3 
			9d 67 d3 11 c7 e0 5d 44 
			5e f2 4b b7 f0 07 d7 64 
			cf b4 1b 2d 53 22 88 d9 
			3c 16 8a 1a 
		}
        $b1 = { 
			70 72 6f 63 65 73 73 49
			6e 66 6f 00 61 72 67 75 
			6d 65 6e 74 73 00 66 69 
			72 73 74 4f 62 6a 65 63 
			74 00 6c 61 73 74 50 61 
			74 68 43 6f 6d 70 6f 6e 
			65 6e 74 00 65 6e 76 69 
			72 6f 6e 6d 65 6e 74 00 
			70 72 6f 63 65 73 73 49 
			64 65 6e 74 69 66 69 65 
			72 00 6e 75 6d 62 65 72 
			57 69 74 68 49 6e 74 3a 
			00 68 6f 73 74 4e 61 6d 
			65 00 67 6c 6f 62 61 6c 
			6c 79 55 6e 69 71 75 65 
			53 74 72 69 6e 67 00 73 
			74 72 69 6e 67 57 69 74 
			68 46 6f 72 6d 61 74 3a 
		}
        
    condition:
        Macho and filesize < 2MB and all of ($a*) and 1 of ($b*)
}

rule XProtect_macos_snowdock_crypt {
    meta:
        description = "MACOS.SNOWDOCK"
    strings:
        $key_1 = {1d82b8c76c847ff654295b7201390269}
        $iv_1 = {99ed52008eced6de1dba5b72513039ae}
    condition:
        any of them
}

rule XProtect_MACOS_PIRRIT_GEN {
    meta:
        description = "MACOS.PIRRIT.GEN"
    
    strings:
        $ = {
            37 A6 17 43 F9 86 21 ED 98 A3 94 C4 44 D7 68 25
            ED 03 48 7E 7B 23 24 AA 80 47 B7 84 54 19 1B A7
            C9 C1 DC BA F2 64 AC 99 88 74 CC 47 86 D6 C9 AC
            80 0D EB 6A 4D B0 97 BF 4E 63 65 F3 F7 C7 C9 8D
            3C 22 E6 40 4C 05 AD 7F AC B2 58 6F C6 E9 66 C0
            04 D7 D1 D1 6B 02 4F 58 05 FF 7C B4 7C 7A 85 DA
            BD 8B 48 89 2C A7 B8 D0 30 AA 2E 4D D5 C1 16 2C
            E2 0D 59 62 DE D2 CB 0E F9 2D 91 B0 11 52 3E 36
            97 E2 AE
        }
        
        $ = {
            5F 76 08 37 D9 EC 03 49 64 C3 DD 15 3F DC 39 C9
            F2 BC E0 68 9D 20 8B 6F 41 ED 00 C2 34 9D 85 61
            53 6E 06 D0 A4 F7 D1 38 7E 9F 05 4B E9 BC F3 F6
            54 B6 7C 77 60 83 D0 C1 7F E5 94 91 26 89 8E 77
            66 F1 45 CD 83 44 97 C4 A3 AD 0F 4C AB 27 98 A7
            F4 37 79 D0 90 97 56 F7 81 6E 68 1D
        }
            
        $ = {
            52 41 52 41 52 41 52 41 52 41 52 41 52 41 52 41
            52 41 52 41 52 41 52 41 52 41 52 41 52 41 52 41
            52 41 52 41 52 41 52 41 52 41 52 41 52 41 52 41
            52 41 52 41 60 2D 41 52 44 53 44 58 43 53 42 70
        }
        
        $ = {
            4F 6F 1D E4 55 F8 00 36 BA A4 50 87 D2 DA 8B 0C
            1E 8C 56 90 AD 7A 9B C4 0B AF B2 9C 51 AE 75 71
            93 31 72 D0 4F 91 39 4D BA 76 CC 3A 37 06 33 1C
            F9 A0 0E 71 FD EB 21 94 A4 7E C0 B2 B2 3F B4 5F
        }
            
        $ = {
            54 42 52 41 52 41 52 41 52 41 52 41 52 41 52 41
            52 41 52 41 52 41 52 41 52 41 52 41 52 41 52 41
            52 41 52 41 52 41 52 42 52 42 60
        }
        
        $ = { 52 42 53 43 53 43 53 43 53 43 53 43 52 42 52 42 53 43 52 42 52 42 52 42 52 42 52 42 70 }
        
    condition:
        Macho and 2 of them
}

rule XProtect_MACOS_ADLOAD_FMT {
    meta:
        description = "MACOS.ADLOAD.FMT"
    strings:
        $ = "_Tt%cSs%zu%.*s%s"
        $ = "_Tt%c%zu%.*s%zu%.*s%s"
        $ = {20 0a 0d 09 0c 0b}
    condition:
        Macho and all of them
}

rule XProtect_MACOS_SHEEPSWAP_ALLBIDCOMMON
{
    meta:
        description = "MACOS.SHEEPSWAP.ALLBIDCOMMON"

    strings:
        $s_1 = { 67 65 74 53 74 61 74 65 4f 66 53 61 66 61 72 69 45 78 74 65 6e 73 69 6f 6e 57 69 74 68 49 64 65 6e 74 69 66 69 65 72 3a 63 6f 6d 70 6c 65 74 69 6f 6e 48 61 6e 64 6c 65 72 3a }
        $s_2 = { 73 68 6f 77 50 72 65 66 65 72 65 6e 63 65 73 46 6f 72 45 78 74 65 6e 73 69 6f 6e 57 69 74 68 49 64 65 6e 74 69 66 69 65 72 3a 63 6f 6d 70 6c 65 74 69 6f 6e 48 61 6e 64 6c 65 72 3a }
        $s_3 = { 5f 73 77 69 66 74 }
        $c_1 = { 00 11 22 30 60 29 30 80 01 53 42 54 43 70 10 54 43 70 10 53 42 53 42 53 42 58 44 70 30 60 15 41 }
        $c_2 = { 41 52 41 52 41 52 41 52 41 52 41 52 42 52 42 60 23 43 70 30 53 44 70 10 70 10 60 0F 44 70 08 70 }

     condition:
         Macho and all of ($s_*) and #s_3 > 84 and any of ($c_*) and filesize < 1500KB
}

rule XProtect_MACOS_PIRRIT_A {
    meta:
        description = "MACOS.PIRRIT.A"

    strings:
        $ = {7B505576505F}
        $ = {405f494f536572766963654d61746368696e67}
        $ = {5544524770305341524152415241524152416045495242524370}
        $ = {405f494f5265676973747279456e747279437265617465434650726f7065727479}
        $ = {00654B39B42ECAF00FD402B66D691086D24FE7CF288C1D780CC3226FA7140A1011436E8ADEC866C7C4ABC1492CEAD175887366FDE50BD2678B95C9BD41965EAA92E1CAF0}

    condition:
        Macho and all of them
}

rule XProtect_MACOS_PIRRIT_BR {
	meta:
        description = "MACOS.PIRRIT.BR"

    strings:
        $ = {FF684E080000E90CFDFFFF685C080000E902FDFFFF6869080000E9F8FCFFFF6876080000E9EEFCFFFF6885080000E9E4FCFFFF6895080000E9DAFCFFFF68A908}
        $ = {405F63686D6F6400900072F80411405F636C6F736500900072800511405F636F6E6673747200900072880511405F646C6F70656E00900072900511405F646C73796D00900072980511405F6578697400900072A00511405F6672656500900072A80511405F676574656E7600900072B00511405F676574657569}
        $ = {FF68C8080000E9BCFCFFFF68D7080000E9B2FCFFFF68E6080000E9A8FCFFFF68F7080000E99EFCFFFF6807090000E994FCFFFF6816090000E98AFCFFFF6825090000E980FCFFFF6834090000E976FCFFFF6844090000E96CFCFFFF6853090000E962FCFFFF6862090000E958FCFFFF6871090000E94EFCFFFF6880090000E944FCFFFF6898090000E93AFCFFFF68A7090000E930FCFFFF68B4090000E926FCFFFF68D1090000E91CFCFFFF68E6090000E912FCFFFF}

    condition:
        Macho and 2 of them
}

rule XProtect_MACOS_DOLITTLE_HJK {
    meta:
        description = "MACOS.DOLITTLE.HJK"

    strings:
        $a01 = { 4e 53 41 70 70 6c 65 53 63 72 69 70 74 }
        $a02 = { 69 6e 69 74 57 69 74 68 53 6f 75 72 63 65 }
        $b01 = { 4e 53 52 65 67 75 6c 61 72 45 78 70 72 65 73 73 69 6f 6e }
        $b02 = { 72 61 6e 67 65 4f 66 46 69 72 73 74 4d 61 74 63 68 49 6e 53 74 72 69 6e 67 }
        $c01 = { 55 52 4c 57 69 74 68 53 74 72 69 6e 67 }
        $c02 = { 69 6e 69 74 57 69 74 68 55 52 4c }
        $c03 = { 73 65 74 48 54 54 50 4d 65 74 68 6f 64 }
        $d01 = { 55 54 46 38 53 74 72 69 6e 67 }
        $d02 = { 73 74 72 69 6e 67 57 69 74 68 46 6f 72 6d 61 74 }
        $d03 = { 63 6f 6d 70 6f 6e 65 6e 74 73 53 65 70 61 72 61 74 65 64 42 79 53 74 72 69 6e 67 }
        $d04 = { 6f 62 6a 65 63 74 41 74 49 6e 64 65 78 65 64 53 75 62 73 63 72 69 70 74 }
        $d05 = { 69 6e 74 56 61 6c 75 65 }
        $d06 = { 61 70 70 65 6e 64 46 6f 72 6d 61 74 }
        $e01 = { 55 52 4c 46 6f 72 41 70 70 6c 69 63 61 74 69 6f 6e 57 69 74 68 42 75 6e 64 6c 65 49 64 65 6e 74 69 66 69 65 72 }
        $e02 = { 55 52 4c 46 6f 72 41 70 70 6c 69 63 61 74 69 6f 6e 54 6f 4f 70 65 6e 55 52 4c }
        $e03 = { 62 75 6e 64 6c 65 57 69 74 68 55 52 4c }
        $f01 = { 73 65 74 4c 61 75 6e 63 68 50 61 74 68 }
        $f02 = { 73 65 74 41 72 67 75 6d 65 6e 74 73 }
        $f03 = { 70 69 70 65 }
        $f04 = { 73 65 74 53 74 61 6e 64 61 72 64 4f 75 74 70 75 74 }
        $f05 = { 6c 61 75 6e 63 68 }
        $f06 = { 66 69 6c 65 48 61 6e 64 6c 65 46 6f 72 52 65 61 64 69 6e 67 }
        $f07 = { 72 65 61 64 44 61 74 61 54 6f 45 6e 64 4f 66 46 69 6c 65 }
        $f08 = { 77 61 69 74 55 6e 74 69 6c 45 78 69 74 }
        $h01 = { 73 65 74 54 69 74 6c 65 56 69 73 69 62 69 6c 69 74 79 }
        $h02 = { 73 65 74 54 69 74 6c 65 62 61 72 41 70 70 65 61 72 73 54 72 61 6e 73 70 61 72 65 6e 74 }
        $h03 = { 63 6f 6e 74 65 6e 74 52 65 63 74 46 6f 72 46 72 61 6d 65 52 65 63 74 }
        $h04 = { 65 66 66 65 63 74 69 76 65 41 70 70 65 61 72 61 6e 63 65 }
        $h05 = { 73 65 74 42 61 63 6b 67 72 6f 75 6e 64 43 6f 6c 6f 72 }
        $h06 = { 69 6e 69 74 57 69 74 68 46 72 61 6d 65 }
        $h07 = { 73 65 74 42 75 74 74 6f 6e 54 79 70 65 }
        $h08 = { 73 65 74 42 65 7a 65 6c 53 74 79 6c 65 }
        $g = { 73 65 74 49 67 6e 6f 72 65 73 4d 6f 75 73 65 45 76 65 6e 74 73 }
        $i = { 2f 75 73 72 2f 6c 69 62 2f 6c 69 62 6f 62 6a 63 2e 41 2e 64 79 6c 69 62 }
        $j = { 2f 53 79 73 74 65 6d 2f 4c 69 62 72 61 72 79 2f 46 72 61 6d 65 77 6f 72 6b 73 2f }

    condition:
        Macho and 100KB < filesize and filesize < 1MB
        and all of ($a*)
        and all of ($b*)
        and 2 of ($c*)
        and 5 of ($d*)
        and 2 of ($e*)
        and 6 of ($f*)
        and $g
        and 6 of ($h*)
        and $i
        and (
            (not (uint32be(0) == 0xcafebabe and uint32(4) < 0x14000000) and #j <= 8)
            or ((uint32be(0) == 0xcafebabe and uint32(4) < 0x14000000) and #j <= 16)
        )
}

rule XProtect_MACOS_SHEEPSWAP_OBF_C
{
    meta:
        description = "MACOS.SHEEPSWAP.OBF.C"

    strings:
        $a1 = {51 7a 52 4a 5a 6e 77}
        $a2 = {61 70 72 6f 54 45 58 54}
        $a3 = {4e 6a 49 35 46 6e 4a}
        $a4 = {52 30 5a 42 62 58 59}
        $a5 = {75 70 78 54 45 58 54}
        $a6 = {52 30 46 4e 62 58 30}

        $b1 = {
            75 ?? 8b 1e 48 83 ee fc
            11 db 8a 16 73 ?? 83 e8
            03 72 ?? c1 e0 08 0f b6
            d2 09 d0 48 ff c6 83 ??
            ?? 0f 84 ?? ?? ?? ?? 48
            63 e8 8d 41 01 41 ff d3
        }

    condition:
        Macho and (any of ($a*) and $b1) and for any of ($a*) : ($ at 0xb0) and filesize > 30KB and filesize < 100KB
}

rule XProtect_MACOS_CRAPYRATOR_A1
{
    meta:
        description = "MACOS.CRAPYRATOR.A1"

    strings:
        $ = { 46 61 69 6c 65 64 21 00 4e 6f 74 68 69 6e 67 20 74 6f 20 64 6f 21 00 53 75 63 63 65 73 73 21 00 74 6f 6f 6c 00 }
        $ = { 2d 5b 45 6c 65 76 61 74 65 20 72 75 6e 3a 5d }

    condition:
        Macho and all of them and filesize < 1MB
}

rule XProtect_MACOS_CRAPYRATOR_A2
{
    meta:
        description = "MACOS.CRAPYRATOR.A2"

    strings:
        $ = { 6c 61 73 74 45 78 65 63 75 74 65 64 53 63 72 69 70 74 48 61 73 68 }
        $ = { dc 22 b6 f8 2e 21 ab 13 c0 b4 59 c8 10 af 39 60 }

    condition:
        Macho and all of them and filesize < 1MB
}

rule XProtect_MACOS_REALSTAR {
    meta:
        description = "MACOS.REALSTAR"
    strings:
        $a = {2e 2e 75 74 69 6c 73}
        $b = {2e 2e 62 72 6f 77 73 65 72 73}
        $c = {70 72 6f 67 72 61 6d 6d 65 73}
        $d = {2e 2e 64 61 74 61 5f 73 74 65 61 6c 65 72 73 2e 2e}
        $e = {46 69 72 65 46 6f 78 4b 65 79 53 74 65 61 6c 65 72}
        $f = {43 68 72 6f 6d 65 4b 65 79 53 74 65 61 6c 65 72}
        $g = {43 68 72 6f 6d 65 44 61 74 61 53 74 65 61 6c 65 72}
        $h = {75 74 69 6c 73 3a 3a 67 65 74 5f 73 74 72 65 61 6d 5f 66 69 6c 65}
        $i = {75 74 69 6c 73 3a 3a 67 65 74 5f 6f 73 5f 69 6e 66 6f}
        $j = {75 74 69 6c 73 3a 3a 6d 61 6b 65 5f 73 63 72 65 65 6e}
        $k = {75 74 69 6c 73 3a 3a 67 65 74 5f 63 68 65 63 6b 5f 62 72 6f 77 73 65 72}
        $l = {75 74 69 6c 73 3a 3a 67 65 74 5f 6b 63 5f 6b 65 79 73}
    condition:
        Macho and 3 of them
}

rule XProtect_MACOS_FRISKYHORSE_COMMON {
    meta:
        description = "MACOS.FRISKYHORSE.COMMON"

    strings:
        $a = {4C89F74C89FE4C89E2E860FEFFFF4189C6B8FFFFFFFF45392F0F8E0101000083BDCCF7FFFF000F8EF400000031C0488985B8F7FFFF488985C0F7FFFFBF00080000}
        $b = {0000418B0424412B0783F81D776BB8000800004C8DBDC0F7FFFF4889D9C6010048FFC148FFC875F58BBDCCF7FFFFBA000800004889DEE8}
        $c = {AD7FACB2586FC6E966C004D7D1D16B024F5805FF7CB47C7A85DABD8B48892CA7AD7FACB2586FC6E966C004D7D1D16B024F5805FF7CB47C7A85DABD8B48892CA7}
        $d = {2F62696E2F626173680062617368002D6300657865636C002825732920323E2631002F}
        $e = {FEFFFF4189C6B8FFFFFFFF45392F0F8E0101000083BDCCF7FFFF000F8EF400000031C0488985B8F7FFFF488985C0F7FFFFBF00080000E8}
        $f = {00004585F674134885C0740E31C9C604080048FFC14839CB75F45B415E5DC3554889E5}
        $g = {C0F7FFFF4889D9C6010048FFC148FFC875F58BBDCCF7FFFFBA000800004889DEE8}

    condition:
        Macho and 4 of them
}

rule XProtect_MACOS_ADLOAD_SEARCH_DAEMON_B_COMMON {
    meta:
        description = "MACOS.ADLOAD.SEARCHDAEMONB.COMMON"

    strings:
        $string_1 = {3A40BA7F03C03B16996C038E3C088A6C03D53C2CF27603A13E16FB6B03EF3E08EC6B03B63F25C57503FB4016DD6B03C94108CE6B0390422C987403B04330A16B03E34308B46A039F4508AF6A03A74547C078039346168F6903E14608806903A8472CB47003ED4819F16803BE4908E26803874A1FA06F03BF4B19D36803904C08C46803D74C25DA6D039C4E16B56803EA4E08A66803B14F25}
        $string_2 = {5B0AB5950303AB5C0AB3950303BC5D088BDA0203815E13EBE20203AC5E35DFF30203C9601ED3E20203E7600CBEE20203AB610AB9E20203E36215E1FA0203F86281020000F9640AED930303BB650AEB930303CC660886DA0203916713AEE20203BC6735A3F30203D9692196E20203FA690CFEE10203BE}
        $string_3 = {5B0BFD860103EB5B08C1820103A25C0CFD860103BF5C0CBB7803CB5C0C996403D75C1DF96303F45C0FE66303BF5D12936603F45F0FCB7E03AC600FE16305BB6016C56305FB610CA86C05A6620CC06303B7620CBB6303C8620CFA82}
        $string_4 = {03EC3A08894B03B13B13D54B03E73B35A84F03A93E13B24B03C83E14964B03EB3E13ED4A03A83F08E54A05B83F088E4B05DB3F07964D058C450AE84F03994508FF4C03A1450AEB4C03CD4518B54C}

    condition:
        Macho and all of them and filesize < 2MB
}

rule XProtect_MACOS_ADLOAD_SEARCH_DAEMON_C_COMMON {
    meta:
        description = "MACOS.ADLOAD.SEARCHDAEMONC.COMMON"

    strings:
        $string_1 = {0FB55700D3340F9C57008C350FA15A00B23560C05A00D1360FA15A00F736B102C05A00BE4339915400FE430CB45000B04432FB5300E9440CAF50009B4532E55300D4450CAA5000864632815300BF460CA55000F14632D25200AA470CA05000DC4732DA5000E3480F945000E449188F5000FC499D030000994D0C8A5000A74D0C855000B54D0C805000C34D0CFB4F00D14D0CF64F00DF4D0CF14F00ED4D0CEC4F00FB4D0CE74F00894E0CE24F00974E0CDD4F00A54E1A975500C14E1A925500DD4E1A8D5500F94E1A885500954F1A835500B44F1FD84F00B35508BD5501CC550CED5501D85508E55501E055980800}
        $string_2 = {0A0CE7B10103BB0A16C8B10103FD0A1AA9B10103970B0CF6AF0103930C47A9B20103B40D1AC4AF0103CE0D0C91AE0103B00E13E9B10103CE0E0CF9AD0103DA0E13E1AD0103AE129D01DBB80103FE14FD01F0B10103}
        $string_3 = {2F00FA211AB42F0094220C842E00A022C1090000E12B09E02D00EF2B09DB2D00FD2B09D62D008B2C09D12D00992C09CC2D00A72C09C72D00B52C09C22D00C02C09BD2D00CB2C17B13000E42C17923000FD2C09EA2D}
        $string_4 = {4640DC4C00C2460F0000D146088A4C00D946230000FC4613854C008F4713DF4B00F2479B02DC4C009C4A2B9A4C00CC4A43DC4C00944B1FDA4B00B84B0CE34C00}
        $string_5 = {2100E5080BAA1C00980908A11C00E80916CD2000870B0B981C00BA0B088F1C008A0C1ADE1F00AD0D0B861C00E00D08FD1B00B00E1AEF1E00FD0F08F41B00AD100BEB1B008011EA04A12300A5160EF21A00971713BF}
        $string_6 = {A94D0CF14F00B74D0CEC4F00C54D0CE74F00D34D0CE24F00E14D0CDD4F00EF4D0CD84F00FD4D0CD34F008B4E0CCE4F00994E0CC94F00A74E0CC44F00B54E1AA85500D14E1AA35500ED4E1A9E5500894F1A995500A54F1AF35400875508915501BC550CDD5501C85508D55501D055980800}
        $string_7 = {00FF9B6D015D2513F30A034D1AC50A03670CFB0803C9020FB80B03B10408A70803FA0543830B03EE0613B80B0384070CAC080390078901000099080CA70803A508E403}
        $string_8 = {B81313943C00CB131AB73B0084161AA13B009E160CC83900C4171AC93600DE170C983500C0180EB63900C41E1AFB3400DE1E0CCA3300C01F0EB63900CE1FBC02}
        $string_9 = {3D009E2B970F0000B53A09AA3D00C33A09A83D00D13A09A63D00DC3A09A43D00E73A09A23D00F23A09A03D00FD3A099E3D00883B099C3D00933B099A3D009E3B09983D00A93B09963D00B43B09943D00BF3B09923D00CA3B09903D00D53B17B83D00EE3B17B63D00873C17B43D00A03C17B23D00B93C17B03D00D23C}
    
    condition:
        Macho and 4 of them and filesize < 4MB
}

rule macos_sourpigeon {
	meta:
		description = "MACOS.SOURPIGEON"
	strings:
		$a01 = { 53 77 65 65 74 49 52 43 41 70 70 }
		$a02 = { 52 6F 6F 6D 4C 69 73 74 56 69 65 77 4D 6F 64 65 6C }
		$a03 = { 43 68 61 74 56 4D }
		$b01 = { 5F 72 6F 6F 6D 5F 69 64 }
		$b02 = { 64 65 73 43 6F 6E 66 69 67 }
		$b03 = { 64 65 73 43 6F 6E 74 65 6E 74 }
		$b04 = { 64 69 72 6C 69 73 74 }
		$b05 = { 69 73 44 6F 77 6E 6C 6F 61 64 69 6E 67 }
		$b06 = { 73 65 72 5F 64 6F 6D 61 69 6E }
		$c01 = { 43 6F 6E 6E 65 63 74 69 6F 6E 20 69 73 20 46 61 69 6C 65 64 }
		$c02 = { 54 68 69 73 20 72 65 71 75 65 73 74 20 69 73 20 72 65 66 75 73 65 64 20 62 65 63 61 75 73 65 20 6F 66 20 79 6F 75 72 20 49 50 20 61 64 64 72 65 73 73 20 6F 72 20 73 79 73 74 65 6D 20 76 65 72 73 69 6F 6E 2E }
		$d01 = { 77 77 77 2E 73 61 66 65 5F 6D 65 65 74 69 6E 67 2E 6E 65 74 }
		$e01 = { 2F 56 6F 6C 75 6D 65 73 2F 53 61 66 65 4D 65 65 74 69 6E 67 2F 2E 6C 69 73 74 2E 69 6E 66 6F }
		$e02 = { 2F 55 73 65 72 73 2F 53 68 61 72 65 64 2F 43 6F 72 65 53 69 6D 75 6C 61 74 6F 72 58 44 }
		$e03 = { 2F 55 73 65 72 73 2F 53 68 61 72 65 64 2F 2E 50 6F 64 63 61 73 74 73 55 70 64 61 74 65 53 53 48 4B 65 79 }
	condition:
		Macho and 100KB < filesize and filesize < 6MB and all of ($a*) and (4 of ($b*) or all of ($c*) or any of ($d*) or any of ($e*))
}

rule XProtect_MACOS_SHEEPSWAP_OBF_E_COMMON 
{
    meta:
        description = "MACOS.SHEEPSWAP.OBFE.COMMON"

    strings:
        $s1 = {0710A55DB5903F26D241B4F6D0AC63D873FF33D0A660768FDF52EBA0438610FB705F0BA8474D69B3401BB04187B8458751F6C16465F5436CC036D2348C96E26E638B453B3393E9DAC837}
        $s2 = {663A330876B80E62E39853DA15D3636F15A02543D814A35DA82BB7B02F5968C31127B829578114CDB4C02D7344CF35BC76E1A7CD3B7464D462B48B058276566F6DD13742D182A698}
        $s3 = {0256E2CC48EFD806A64E53D4A715A15108696EFD06729021B028E91F43A1587BDF27206230C17B7236812DCAA8C1087CE44EED0613353E7B8FDA66A66C9F073066726B884F3B}
        $s4 = {B08B037FB8D9A73A53D048D63603E9E7EBC4285BD6ECE1865D84415DC356402C5098AAC360416B4289A490380495086CDBACE0E11539670EA0A0C8A84C12B3FDCDDAB08EC230}
        $s5 = {B4E378A7E94230E86447C889109BC8168425D07FEC601FED32307D4E6F77F7D8778ED8B044E5E06D311D41C548CC3755E8764141886F287923F04522FB0C21E3}
    
    condition:
        Macho and all of them and filesize < 400KB
}

rule macos_adload_launcher
{
    meta:
        description = "MACOS.ADLOAD"

    strings:
        $code = { (48 | 49) 63 ?? 41 32 ?? ?? (88 8D ?? ?? ?? ?? 48 | 48) ?? ?? 74 ?? 88 ?? 48 ?? ?? ?? eb ?? }
        $code2 = { 48 8b [2-5] 48 89 ?? 48 f7 d? 48 01 c? 44 88 ?? ?? 48 8b [2-5] 48 89 c? 48 f7 d? 48 03 [2-5] ( 44 88 | 88 0c ) [1-2] 4? 83 f? ?? }
        $code3 = { b1 ?? 41 be 01 00 00 00 4c 8d bd 7f ff ff ff 44 89 eb eb ?? }
        $code4 = { 41 ff c? 90 49 63 c? 48 ?? ?? ?? ?? ?? ?? ( 44 32 34 0a 48 39 d8 74 ?? | 32 0c 02 88 8d 7f ff ff ff 48 8b 45 88 48 3b 45 90 74 ?? ) }
        $code5 = { 90 0f 57 c0 4c 8d 65 80 41 0f 29 04 24 49 c7 44 24 }
        $code6 = { ff cb 90 48 63 c3 48 ?? ?? ?? ?? ?? ?? 32 0c 02 48 8b 85 78 ff ff ff 48 3b 45 80 74 ?? }
        $code7 = { 45 85 ?? 41 8d 4? ff b? ?? ?? ?? ?? 0f 4e c? 4? 8a ?? ?? b0 4? ff c? 4? 89 c6 }
        $code8 = { 44 8a 74 05 b0 48 ff c0 48 89 85 ( a0 fa | 38 f4 ) ff ff }
        $code9 = { 46 8a ?4 ?? b0 49 63 c5 48 ?? ?? ?? ?? ?? ?? 8a 04 08 88 85 ?8 f5 ff ff 4? 89 ?d ?8 fa ff ff 4? 89 ?d ?0 fa ff ff 48 83 a5 ?8 fa ff ff 00 4? 89 ?f 6a ?? 5e e8 ?? ?? ?? ?? 44 32 ?? ?8 f5 ff ff 44 88 ?5 ?0 f5 ff ff 48 8d bd ?? fa ff ff 48 8d b5 ?0 f5 ff ff e8 ?? ?? ?? ?? 4? 8? ?? 4? 8d ?5 }
        $code10 = { 90 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 48 89 df 48 8d b5 08 f6 ff ff e8 ?? ?? ?? ?? 48 8b 85 b0 fa ff ff 0f b6 78 10 e8 ?? ?? ?? ?? 90 48 89 df e8 ?? ?? ?? ?? 49 ff c? }
        $code11 = { 83 c2 fc 85 d2 6a ?? 58 0f 4e d0 4c 89 ef 48 89 de 6a ff 59 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 4c 89 ef e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff 48 8d b5 98 f5 ff ff e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff e8 ?? ?? ?? ?? 49 ff c6 }
        $code12 = { 0F 57 C0 0F 29 45 B0 48 C7 45 ?? 00 00 00 00 41 BD ?? 00 00 00 41 B6 ?? 31 DB BF ?? 00 00 00 31 C0 41 BF ?? 00 00 00 EB ??45 85 FF 41 8D ?? ?? 41 0F 4E CD 44 0F B6 ?? ?? ?? ?? FF FF 48 8B 45 ?? 48 8B ?? ?? 48 FF C7 41 89 CF 90 90 49 63 CF 46 32 ?? ?? }
        $code13 = { 48 63 c3 48 ?? ?? ?? ?? ?? ?? 8a 04 08 42 32 44 2d b0 88 85 70 ff ff ff [2-6] f? 4c 89 e6 e8 ?? ?? ?? ?? 85 db 8d 43 ff 89 c3 ?? [0-4] 0f 4e d? 4c 89 ff 89 de e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 49 ff c5 }
        $code14 = { 85 db 41 0f 4e dc 42 8a 4c 2d b0 49 ff c5 }
        $code15 = { 49 63 c7 48 ?? ?? ?? ?? ?? ?? 8a 04 08 32 44 1d b0 88 85 70 ff ff ff 4c 89 f7 4c 89 ee e8 ?? ?? ?? ?? 45 85 ff 41 8d 47 ff 41 0f 4e c4 48 ff c3 41 89 c7 }
        $stringA = "Admin Success: %@"
        $stringB = "Error: %@"
        $stringC = "@@AppPath@@/Contents/MacOS"
        $stringD = "runApp"

    condition:
        Macho and filesize < 15MB and (any of ($code*)) and (any of ($string*))
}

rule macos_adload_main
{
  meta:
    description = "MACOS.ADLOAD"
  strings:
    $code = { (48 | 49) 63 ?? 41 32 ?? ?? (88 8D ?? ?? ?? ?? 48 | 48) ?? ?? 74 ?? 88 ?? 48 ?? ?? ?? eb ?? }
    $code2 = { 48 8b [2-5] 48 89 ?? 48 f7 d? 48 01 c? 44 88 ?? ?? 48 8b [2-5] 48 89 c? 48 f7 d? 48 03 [2-5] ( 44 88 | 88 0c ) [1-2] 4? 83 f? ?? }
    $code3 = { b1 ?? 41 be 01 00 00 00 4c 8d bd 7f ff ff ff 44 89 eb eb ?? }
    $code4 = { 41 ff c? 90 49 63 c? 48 ?? ?? ?? ?? ?? ?? ( 44 32 34 0a 48 39 d8 74 ?? | 32 0c 02 88 8d 7f ff ff ff 48 8b 45 88 48 3b 45 90 74 ?? ) }
    $code5 = { 90 0f 57 c0 4c 8d 65 80 41 0f 29 04 24 49 c7 44 24 }
    $code6 = { ff cb 90 48 63 c3 48 ?? ?? ?? ?? ?? ?? 32 0c 02 48 8b 85 78 ff ff ff 48 3b 45 80 74 ?? }
    $code7 = { 45 85 ?? 41 8d 4? ff b? ?? ?? ?? ?? 0f 4e c? 4? 8a ?? ?? b0 4? ff c? 4? 89 c6 }
    $code8 = { 44 8a 74 05 b0 48 ff c0 48 89 85 ( a0 fa | 38 f4 ) ff ff }
    $code9 = { 46 8a ?4 ?? b0 49 63 c5 48 ?? ?? ?? ?? ?? ?? 8a 04 08 88 85 ?8 f5 ff ff 4? 89 ?d ?8 fa ff ff 4? 89 ?d ?0 fa ff ff 48 83 a5 ?8 fa ff ff 00 4? 89 ?f 6a ?? 5e e8 ?? ?? ?? ?? 44 32 ?? ?8 f5 ff ff 44 88 ?5 ?0 f5 ff ff 48 8d bd ?? fa ff ff 48 8d b5 ?0 f5 ff ff e8 ?? ?? ?? ?? 4? 8? ?? 4? 8d ?5 }
    $code10 = { 90 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 48 89 df 48 8d b5 08 f6 ff ff e8 ?? ?? ?? ?? 48 8b 85 b0 fa ff ff 0f b6 78 10 e8 ?? ?? ?? ?? 90 48 89 df e8 ?? ?? ?? ?? 49 ff c? }
    $code11 = { 83 c2 fc 85 d2 6a ?? 58 0f 4e d0 4c 89 ef 48 89 de 6a ff 59 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 4c 89 ef e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff 48 8d b5 98 f5 ff ff e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff e8 ?? ?? ?? ?? 49 ff c6 }
    $code12 = { 0F 57 C0 0F 29 45 B0 48 C7 45 ?? 00 00 00 00 41 BD ?? 00 00 00 41 B6 ?? 31 DB BF ?? 00 00 00 31 C0 41 BF ?? 00 00 00 EB ??45 85 FF 41 8D ?? ?? 41 0F 4E CD 44 0F B6 ?? ?? ?? ?? FF FF 48 8B 45 ?? 48 8B ?? ?? 48 FF C7 41 89 CF 90 90 49 63 CF 46 32 ?? ?? }
    $code13 = { 48 63 c3 48 ?? ?? ?? ?? ?? ?? 8a 04 08 42 32 44 2d b0 88 85 70 ff ff ff [2-6] f? 4c 89 e6 e8 ?? ?? ?? ?? 85 db 8d 43 ff 89 c3 ?? [0-4] 0f 4e d? 4c 89 ff 89 de e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 49 ff c5 }
    $code14 = { 85 db 41 0f 4e dc 42 8a 4c 2d b0 49 ff c5 }
    $code15 = { 49 63 c7 48 ?? ?? ?? ?? ?? ?? 8a 04 08 32 44 1d b0 88 85 70 ff ff ff 4c 89 f7 4c 89 ee e8 ?? ?? ?? ?? 45 85 ff 41 8d 47 ff 41 0f 4e c4 48 ff c3 41 89 c7 }
    $stringA = "WebView"
    $stringB = "JSExport"
    $stringC = "_TransformProcessType"

  condition:
    Macho and filesize < 15MB and (any of ($code*)) and (any of ($string*))
}

rule macos_adload_agent
{
  meta:
    description = "MACOS.ADLOAD"
  strings:
    $code = { (48 | 49) 63 ?? 41 32 ?? ?? (88 8D ?? ?? ?? ?? 48 | 48) ?? ?? 74 ?? 88 ?? 48 ?? ?? ?? eb ?? }
    $code2 = { 48 8b [2-5] 48 89 ?? 48 f7 d? 48 01 c? 44 88 ?? ?? 48 8b [2-5] 48 89 c? 48 f7 d? 48 03 [2-5] ( 44 88 | 88 0c ) [1-2] 4? 83 f? ?? }
    $code3 = { b1 ?? 41 be 01 00 00 00 4c 8d bd 7f ff ff ff 44 89 eb eb ?? }
    $code4 = { 41 ff c? 90 49 63 c? 48 ?? ?? ?? ?? ?? ?? ( 44 32 34 0a 48 39 d8 74 ?? | 32 0c 02 88 8d 7f ff ff ff 48 8b 45 88 48 3b 45 90 74 ?? ) }
    $code5 = { 90 0f 57 c0 4c 8d 65 80 41 0f 29 04 24 49 c7 44 24 }
    $code6 = { ff cb 90 48 63 c3 48 ?? ?? ?? ?? ?? ?? 32 0c 02 48 8b 85 78 ff ff ff 48 3b 45 80 74 ?? }
    $code7 = { 45 85 ?? 41 8d 4? ff b? ?? ?? ?? ?? 0f 4e c? 4? 8a ?? ?? b0 4? ff c? 4? 89 c6 }
    $code8 = { 44 8a 74 05 b0 48 ff c0 48 89 85 ( a0 fa | 38 f4 ) ff ff }
    $code9 = { 46 8a ?4 ?? b0 49 63 c5 48 ?? ?? ?? ?? ?? ?? 8a 04 08 88 85 ?8 f5 ff ff 4? 89 ?d ?8 fa ff ff 4? 89 ?d ?0 fa ff ff 48 83 a5 ?8 fa ff ff 00 4? 89 ?f 6a ?? 5e e8 ?? ?? ?? ?? 44 32 ?? ?8 f5 ff ff 44 88 ?5 ?0 f5 ff ff 48 8d bd ?? fa ff ff 48 8d b5 ?0 f5 ff ff e8 ?? ?? ?? ?? 4? 8? ?? 4? 8d ?5 }
    $code10 = { 90 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 48 89 df 48 8d b5 08 f6 ff ff e8 ?? ?? ?? ?? 48 8b 85 b0 fa ff ff 0f b6 78 10 e8 ?? ?? ?? ?? 90 48 89 df e8 ?? ?? ?? ?? 49 ff c? }
    $code11 = { 83 c2 fc 85 d2 6a ?? 58 0f 4e d0 4c 89 ef 48 89 de 6a ff 59 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 4c 89 ef e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff 48 8d b5 98 f5 ff ff e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff e8 ?? ?? ?? ?? 49 ff c6 }
    $code12 = { 0F 57 C0 0F 29 45 B0 48 C7 45 ?? 00 00 00 00 41 BD ?? 00 00 00 41 B6 ?? 31 DB BF ?? 00 00 00 31 C0 41 BF ?? 00 00 00 EB ??45 85 FF 41 8D ?? ?? 41 0F 4E CD 44 0F B6 ?? ?? ?? ?? FF FF 48 8B 45 ?? 48 8B ?? ?? 48 FF C7 41 89 CF 90 90 49 63 CF 46 32 ?? ?? }
    $code13 = { 48 63 c3 48 ?? ?? ?? ?? ?? ?? 8a 04 08 42 32 44 2d b0 88 85 70 ff ff ff [2-6] f? 4c 89 e6 e8 ?? ?? ?? ?? 85 db 8d 43 ff 89 c3 ?? [0-4] 0f 4e d? 4c 89 ff 89 de e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 49 ff c5 }
    $code14 = { 85 db 41 0f 4e dc 42 8a 4c 2d b0 49 ff c5 }
    $code15 = { 49 63 c7 48 ?? ?? ?? ?? ?? ?? 8a 04 08 32 44 1d b0 88 85 70 ff ff ff 4c 89 f7 4c 89 ee e8 ?? ?? ?? ?? 45 85 ff 41 8d 47 ff 41 0f 4e c4 48 ff c3 41 89 c7 }
    $stringA = "WebView"
    $stringB = "JSExport"

  condition:
    Macho and filesize < 15MB and (any of ($code*)) and #stringA == 0 and #stringB == 0
}

rule macos_smolgolf_adload_dropper
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $varName = "main.DownloadURL"
        $libraryName = "github.com/denisbrodbeck/machineid.ID"
        $execCommand = "os/exec.Command"

    condition:
        Macho and all of them
}

rule macos_smolgolf_adload_dropper_mrt
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $string_1 = "net.isDomainName"
        $string_2 = "net.absDomainName"
        $string_3 = "_ioctl"
        $string_4 = "_getnameinfo"
        $string_5 = "_getaddrinfo"
        $string_6 = "_getattrlist"
        $string_7 = "net.equalASCIIName"
        $string_8 = "github.com/denisbrodbeck/machineid"
        $string_9 = "ioreglstatmkdirmonthpanic"
        $string_10 = "runtime.panicSliceB"
        $string_11 = "_getnameinfo"
        $string_12 = "cpuid"
        $string_13 = "url.UserPassword"
        $string_14 = "127.0.0.1:53"
        $string_15 = "syscall.Getsockname"
        $string_16 = "main.DownloadURL"
        $string_17 = "/etc/hosts"
        $string_18 = "/Library/LaunchDaemons/%s.plist"
        $string_19 = "/tmp0x%x"
    condition:
        Macho and filesize < 10MB and all of them
}

rule macos_gardna_agent
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $logString = "error executing commands"
        $binPathA = "/bin/cat"
        $binPathB = "/bin/bash"
        $swift5 = "__swift5_typeref"

    condition:
        filesize < 100KB and Macho and all of them
}

rule macos_gardna_agent_b
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $code = { 48 8d b5 58 ff ff ff e8 ?? ?? ?? ?? 49 89 c4 66 0f 6f 05 09 3e 00 00 f3 0f 7f 40 10 4c 8d 68 20 44 88 78 20 48 8d 58 21 48 8b 7d c8 e8 ?? ?? ?? ?? 4c 89 ef 48 89 de 4c 8d 6d 90 e8 ?? ?? ?? ?? 4c 89 e7 e8 ?? ?? ?? ?? 48 8b 5d 80 48 ff c3 70 ?? }

    condition:
        filesize < 200KB and Macho and $code
}

rule macos_magicplant_dropper
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $code = { 48 8d ?? ?? f? ff ff e8 ?? ?? ?? ?? eb ?? 48 8d ?? ?? f? ff ff e8 ?? ?? ?? ?? eb ?? 48 ?? ?? ?? ?? ?? ?? 48 89 85 b0 fe ff ff 48 8d bd b0 fe ff ff be 02 00 00 00 e8 ?? ?? ?? ?? eb ?? }

    condition:
        Macho and $code
}

rule macos_magicplant_dropper_function : adware
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $decode_routine = { 55 48 89 E5 41 57 41 56 53 48 83 EC 48 49 89 FE 48 8B 05 ?? ?? ?? ?? 48 8B 00 48 89 45 E0 48 8D 05 ?? ?? ?? ?? 48 89 45 A8 4C 8B 7D A8 48 C7 45 B0 00 00 00 00 48 8B 45 B0 48 83 F8 12 73 40 48 8B 75 B0 4C 89 FF E8 ?? ?? ?? ?? 0F B6 18 4C 89 FF 48 83 C7 12 48 8B 75 B0 E8 ?? ?? ?? ?? 0F B6 00 29 C3 88 5D BF 8A 45 BF 48 8B 4D B0 88 44 0D C0 48 8B 45 B0 48 83 C0 01 48 89 45 B0 EB B6 48 8D 75 C0 48 89 F2 48 83 C2 11 4C 89 F7 E8 ?? ?? ?? ?? 48 8B 45 E0 48 8B 0D ?? ?? ?? ?? 48 8B 09 48 29 C1 75 02 EB 05 E8 ?? ?? ?? ?? 48 83 C4 48 5B 41 5E 41 5F 5D C3 }

    condition:
        Macho and $decode_routine and filesize < 250KB
}

rule macos_magicplant_dropper_obfuscated_function : adware
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $function = {
            A8 01 75 02 EB 21 C6 03
            01 48 8D 7D D8 BE 01 00
            00 00 ?? ?? ?? ?? ?? 48
            8B 45 D8 48 89 43 08 48
            89 DF ?? ?? ?? ?? ?? 48
            89 DF ?? ?? ?? ?? ?? A8
            01 75 02 EB 4E 48 8B 5B
            08 48 8B 75 D0 4C 8D 75
            80 4C 89 F7 ?? ?? ?? ??
            ?? 48 89 DF 4C 89 F6 ??
            ?? ?? ?? ?? [0-2] 48 89
            C3 [0-2] 48 8D 7D 80 ??
            ?? ?? ?? ??
        }
    condition:
        Macho and filesize < 250KB and $function
}

rule macos_adload_python_dropper
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $shebang = "#!"

        $iokit_1 = "IOKit"
        $iokit_2 = "IOServiceGetMatchingService"
        $iokit_3 = "IOServiceMatching"
        $iokit_4 = "IORegistryEntryCreateCFProperty"
        $iokit_5 = "IOPlatformExpertDevice"

        $method_1 = "rmtree"
        $method_2 = "load_source"
        $method_3 = "encryptText"
        $method_4 = "decryptText"
        $method_5 = "encryptList"
        $method_6 = "decryptList"
        $method_7 = "check_call"
        $method_8 = "endswith"
        $method_9 = "mac_ver"

        $string_1 = "chmod"
        $string_2 = "/dev/null"
        $string_3 = "key"
        $string_4 = "commands"
        $string_5 = "uuid"
        $string_6 = "machineID"
        $string_7 = "open"
        $string_8 = "sessionID"
        $string_9 = "appName"
        $string_10 = "curl"
        $string_11 = "/tmp"
        $string_12 = "unzip"
        $string_13 = "/Volumes"
        $string_14 = "--args"

    condition:
        $shebang at 0 and (4 of ($iokit_*)) and (7 of ($method_*)) and (10 of ($string_*))
}

rule macos_biter_dropper : adware
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $import1 = "\x00_chmod\x00"
        $import2 = "\x00___error\x00"


        $constant_bytes1 = { BE FF 01 00 00 48 ?? ?? E8 ?? 2B 00 00 E8 ?? ?? 00 00 83 38 02 75 ?? 81 ?? CF FA ED FE }

        $constant_bytes2 = { BA 00 10 00 00 31 C9 48 BF 00 00 00 00 01 00 00 00 48 ?? ?? D0 E8 ?? ?? FF FF 4C 8B 75 }



        $variable_bytes1 = { 30 ?? ?? 83 C0 ?? 3D FE 00 00 00 0F 4F C1 48 FF C7 48 39 FE 75 EA }

        $variable_bytes2 = { 80 ?? ?? ?? 48 FF C0 48 39 C6 75 ?? 8B ?? ?? ?? 00 00 83 ?? ?? }


        $variable_bytes3 = { BE 19 00 00 00 BA 72 6F 6D 4D E8 ?? FE FF FF }

    condition:
        Macho and filesize < 1MB and all of ($import*) and all of ($constant_bytes*) and any of ($variable_bytes*)
}


rule    macos_biter_second_stage : adware
{
    meta:
        description = "MACOS.ADLOAD"
    strings:


        $import_1 = "_IORegistryEntryFromPath"
        $import_2 = "_kIOMasterPortDefault"
        $import_3 = "_DASessionCreate"
        $import_4 = "_DADiskCreateFromVolumePath"
        $import_5 = "_time"
        $import_6 = "_gethostuuid"
        $import_7 = "_getxattr"
        $import_8 = "_iconv"


        $string_1 = "failed malloc"
        $string_2 = ".cloudfront.net/"
        $string_3 = "s3.amazonaws.com/"
        $string_4 = "/Contents/MacOS/* && open -a \""
        $string_5 = "\" \"/Volumes/Player\""
        $string_6 = "An error occurred"
        $string_7 = "please close and try again"
        $string_8 = "cloudfront.net/sd/?c=yWRybQ==&u="
        $string_9 = "&s=$session_guid&o="
        $string_10 = "com.apple.metadata:kMDItemWhereFroms"
        $string_11 = "chmod 77"
        $string_12 = "/tmp/ins"

    condition:
        Macho and filesize < 500KB and 6 of ($import*) and 9 of ($string*)
}


rule macos_biter_b_dropper : adware
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $import_1 = "\x00_getsectiondata\x00"
        $import_2 = "\x00_pthread_getspecific\x00"
        $import_3 = "\x00_pthread_key_create\x00"
        $import_4 = "\x00_sigaction\x00"

        $bytes1 = { 48 89 ?? ?? BA ?? 00 00 00 B8 ?? 00 00 00 EB ?? 66 0F 1F ?? 00 00 00 00 00 48 83 C0 ?? 89 CA 48 ?? ?? ?? ?? 00 74 ?? 42 30 54 ?? ?? 83 C2 ?? }

    condition:
        Macho and filesize < 1MB and all of ($import*) and all of ($bytes*)
}


rule macos_biter_b_dropper_xprotect
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $a1 = { 70 74 68 72 65 61 64 5f 6b 65 79 5f 63 72 65 61 74 65 00 90 00 72 f8 01 15 40 5f 70 74 68 72 65 61 64 5f 6f 6e 63 65 00 90 00 72 80 02 15 40 5f 70 74 68 72 65 61 64 5f 73 65 74 73 70 65 63 69 66 69 63 00 90 00 72 88 02 15 40 5f 73 69 67 61 63 74 69 6f 6e 00 90 00 72 90 02 15 40 5f 73 69 67 6c 6f 6e 67 6a 6d 70 00 90 00 72 98 02 15 40 5f 73 69 67 73 65 74 6a 6d 70 }
        $a2 = { 3c 6b 65 79 3e 63 6f 6d 2e 61 70 70 6c 65 2e 73 65 63 75 72 69 74 79 2e 63 73 2e 61 6c 6c 6f 77 2d 75 6e 73 69 67 6e 65 64 2d 65 78 65 63 75 74 61 62 6c 65 2d 6d 65 6d 6f 72 79 3c 2f 6b 65 79 3e }
        $a3 = { 5f 73 69 67 6e 61 6c 5f 68 61 6e 64 6c 65 72 }
        $a4 = { 5f 74 72 79 5f 63 61 74 63 68 5f 69 6e 69 74 }
        $a5 = { BA ?? 00 00 00 B8 01 00 00 00 EB ?? 66 0F 1F 84 00 ?? ?? 00 00 48 83 C0 02 89 CA 48 3D ?? ?? ?? ?? 74 ?? 42 30 54 30 ?? 83 C2 ?? 31 C9 BE 00 00 00 00 81 FA FE 00 00 00 7F ?? 89 D6 42 30 34 30 83 C6 ?? 81 FE FE 00 00 00 7F ?? 89 F1 EB ?? }

    condition:
        Macho and filesize < 500KB and all of them
}

rule macos_adload_downloader_dec2020_strings
{
    meta:
        description = "MACOS.ADLOAD"

    strings:

        $method1 = "_TtC9Installer14ViewController"
        $method2 = "_TtC9Installer11AppDelegate"

        $import1 = "swift_getExistentialTypeMetadata"
        $import2 = "swift_getTypeContextDescriptor"
        $import3 = "swift_getObjCClassMetadata"
        $import4 = "objc_addLoadImageFunc"

    condition:

        Macho and filesize > 350KB and filesize < 3MB and all of them
}

rule macos_adload_d {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $string_1 = "@_inflateInit2_\x00"
        $string_2 = { 312E322E313100776200726200722B6200696E746567657200737472696E670064617461007265616C00646174650066616C736500747275650061727261790064696374006B657900706C6973740062706C6973743030 }
        $string_3 = "_uuid_unparse\x00"
        $string_4 = "_IOServiceGetMatchingService\x00"
        $string_5 = "regex_error"
        $string_6 = "IOMACAddress"
        $string_7 = "IOPlatformSerialNumber"
        $string_8 = "IOEthernetInterface"
        $string_9 = "BerTagged"

    condition:
        Macho and filesize < 20MB and 8 of them
}

rule macos_adload_e {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $string_1 = "\x00_uuid_generate_random\x00"
        $string_2 = "\x00_system\x00"
        $string_3 = "\x00_syslog\x00"
        $string_4 = "\x00_SecKeyGenerateSymmetric\x00"
        $string_5 = "application/x-www-form-urlencoded"
        $string_6 = "berContents"
        $string_7 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $string_8 = "BerTaggedData"
        $string_9 = "getSystemVer"
    condition:
        Macho and filesize < 500KB and all of them
}

rule macos_adload_f {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $string_1 = "main.copyFile"
        $string_2 = "main.createPlist"
        $string_3 = "syscall.Recvmsg"
        $string_4 = "syscall.SendmsgN"
        $string_5 = "_sysctl"
        $string_6 = "_ioctl"
        $string_7 = "_execve"
        $string_8 = "_getuid"
        $string_9 = "_recvmsg"
        $string_10 = "_sendmsg"
        $string_11 = "_getgrgid_r"
        $string_12 = "_getgrnam_r"
        $string_13 = "_getpwnam_r"
        $string_14 = "_getpwuid_r"
        $string_15 = "can't scan type: chrome-extension_corrupt"
        $string_16 = "ExtensionInstallForcelist"
        $string_17 = "cfprefsd"
        $string_18 = "killallpanic"
    condition:
        Macho and filesize < 5MB and all of them
}

rule macos_adload_search_daemon {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $string_1 = "_uuid_generate_random"
        $string_2 = "_uuid_unparse"
        $string_3 = "_sysctl"
        $string_4 = "_syslog"
        $string_5 = "_getxattr"
        $string_6 = "_getgrgid"
        $string_7 = "_getpwuid"
        $string_8 = "_SecTransformExecute"
        $string_9 = "_IOServiceMatching"
        $string_10 = "_IOServiceGetMatchingServices"
        $string_11 = "BerTagged"
        $string_12 = "berContent"
        $string_13 = "berLengthBytes"
        $string_14 = "IOPlatformUUID"
        $string_15 = "IOEthernetInterface"
        $string_16 = "IOPlatformSerialNumber"
    condition:
        Macho and filesize < 2MB and all of them
}

rule macos_adload_wwxf_objc
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $a1 = "ShellView"
        $a2 = "okEvt"
        $a3 = "closeEvt"
        $a4 = "cancelEvt"
        $a5 = "runModal:"
        $a6 = "Opt:"
        $a7 = "crabs:"
        $a8 = "Tmp:"
    condition:
        Macho and 3 of them and filesize < 200KB
}

rule macos_adload_c_dropper : adware
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $shebang = "#!"
        $string_1 = "mktemp -d /tmp"
        $string_2 = "head -n 1 | rev)"
        $string_3 = "U2FsdGVkX1"
        $string_4 = "-256-cbc"
        $string_5 = "killall Terminal "

    condition:
        $shebang at 0 and all of ($string_*)
}

rule macos_adload_shell_script_obfuscation
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $shebang = "#!/bin/bash"

        $defs = /([A-Z]{1}\=\"[a-z]{1}\"\;){5,}/

        $subs = /(\$\{[A-Z]{1}\}){5,}/

    condition:
        $shebang at 0 and filesize < 100KB and all of them

}

rule macos_adload_fantacticmarch : dropper
{
    meta:
        description = "MACOS.ADLOAD"
    strings:

        $kotlin_1 = "_krefs:kotlin"
        $kotlin_2 = "_kfun:kotlinx"

        $method_1 = "getVolumeInfo"
        $method_2 = "createProcess"
        $method_3 = "runCommand"
        $method_4 = "getDirectories"
        $method_5 = "writeBinary"
        $method_6 = "makeFileExecutable"

        $import_1 = "_gethostuuid"
        $import_2 = "_chmod"

        $strings_1 = "bash"
        $strings_2 = "volumes"
        $strings_3 = "executablePath"

    condition:
        Macho and filesize < 50000000 and all of ($kotlin*) and 4 of ($method*) and all of ($import*) and all of ($strings*)
}

rule macos_adload_d_xor_obfuscation
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $symbol1 = "_TransformProcessType"
            $symbol2 = "_inflateInit"

            $code1 = { 90 4? 63 c? 48 8? 0d ?? ?? 00 00 32 14 08 4c 39 fb }
            $code2 = { 49 63 c6 48 8d 0d ?? ?? 00 00 44 32 3c 08 90 48 8b 85 78 ff ff ff 48 3b 45 80 }
            $code3 = { ff cb [0-2] 48 63 c3 48 8b (15 | 0d) ?? ?? 00 (00 | 00 44) 32 ?? ?? 48 8b ?5 [1-4] 48 3b ?5 }

    condition:
        Macho and all of ($symbol*) and any of ($code*)
}

rule macos_adload_daemon_obfuscation
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $symbolA = "_CFHTTPMessageCreateRequest"
        $symbolB = "_CFHTTPMessageSetHeaderFieldValue"
        $symbolE = "basic_string"

        $codeA = { 8a 44 19 ff 8b 0c 19 44 01 e9 28 c8 88 45 d7 48 8b 4d a8 48 3b 4d b0 }

        $codeB = { 8a 51 ff
                   8a 18
                   88 59 ff
                   88 10
                   48 ff c8
                   48 39 c1
                   48 8d 49 01
                   72 ea }

    condition:
        Macho and (#codeA + #codeB) > 70 and all of ($symbol*)
}

rule macos_adload_nautilus_dropper
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $shebang = "#!"

        $string_1 = "mktemp -t"
        $string_2 = {74 61 69 6c [1-2] 2d 63}
        $string_3 = { 24 30 [1-3] 7c [1-3] 66 75 6e 7a 69 70 [1-3] 2d [5-9] [1-3] 3e [1-3] 24 }
        $string_4 = { 63 68 6d 6f 64 [1-3] 2b 78 }
        $string_5 = { 6b 69 6c 6c 61 6c 6c [1-3] 54 65 72 6d 69 6e 61 6c }

        $string_6 = { 50 4b 03 04 14 }

    condition:
        filesize < 100KB and $shebang at 0 and all of ($string*)
}

rule macos_adload_nautilus_dropper_xprotect
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $a1 = { 23 21 }

        $b1 = { 6d 6b 74 65 6d 70 20 2d 74 }
        $b2 = { 74 61 69 6c [1-2] 2d 63 }
        $b3 = { 24 30 [1-3] 7c [1-3] 66 75 6e 7a 69 70 [1-3] 2d [5-9] [1-3] 3e [1-3] 24 }
        $b4 = { 63 68 6d 6f 64 [1-3] 2b 78 }
        $b5 = { 6b 69 6c 6c 61 6c 6c [1-3] 54 65 72 6d 69 6e 61 6c }
        $b6 = { 50 4b 03 04 14 }

    condition:
        filesize < 100KB and $a1 at 0 and all of ($b*)
}

rule macos_adload_nautilus_installer: adware
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $decode_routine = { 55 48 89 E5 41 57 41 56 53 48 83 EC 48 49 89 FE 48 8B 05 ?? ?? ?? ?? 48 8B 00 48 89 45 E0 48 8D 05 ?? ?? ?? ?? 48 89 45 A8 4C 8B 7D A8 48 C7 45 B0 00 00 00 00 48 8B 45 B0 48 83 F8 12 73 40 48 8B 75 B0 4C 89 FF E8 ?? ?? ?? ?? 0F B6 18 4C 89 FF 48 83 C7 12 48 8B 75 B0 E8 ?? ?? ?? ?? 0F B6 00 29 C3 88 5D BF 8A 45 BF 48 8B 4D B0 88 44 0D C0 48 8B 45 B0 48 83 C0 01 48 89 45 B0 EB B6 48 8D 75 C0 48 89 F2 48 83 C2 11 4C 89 F7 E8 ?? ?? ?? ?? 48 8B 45 E0 48 8B 0D ?? ?? ?? ?? 48 8B 09 48 29 C1 75 02 EB 05 E8 ?? ?? ?? ?? 48 83 C4 48 5B 41 5E 41 5F 5D C3 }

    condition:
        Macho and $decode_routine and filesize < 250KB
}

rule macos_adload_nautilus_obfuscated_function : adware
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $function1 = { A8 01 75 02 EB 21 C6 03 01 48 8D 7D D8 BE 01 00 00 00 ?? ?? ?? ?? ?? 48 8B 45 D8 48 89 43 08 48 89 DF ?? ?? ?? ?? ?? 48 89 DF ?? ?? ?? ?? ?? A8 01 75 02 EB 4E 48 8B 5B 08 48 8B 75 D0 4C 8D 75 80 4C 89 F7 ?? ?? ?? ?? ?? 48 89 DF 4C 89 F6 ?? ?? ?? ?? ?? EB 00 48 89 C3 48 8D 7D 80 ?? ?? ?? ?? ?? }

    condition:
        Macho and filesize < 250KB and $function1
}


rule macos_adload_nautilus_xprotect
{
    meta:
        description = "MACOS.ADLOAD"
    strings:

        $import_v1_1 = { 5f 67 65 74 78 61 74 74 72 }

        $import_v1_2 = { 5f 73 79 73 74 65 6d }

        $import_v1_3 = { 5f 75 75 69 64 5f 67 65 6e 65 72 61 74 65 5f 72 61 6e 64 6f 6d }

        $import_v2_1 = { 5f 54 72 61 6e 73 66 6f 72 6d 50 72 6f 63 65 73 73 54 79 70 65 }

        $import_v2_2 = { 5f 61 63 63 65 73 73 00 5f 63 68 6d 6f 64 00 5f 64 6c 63 6c 6f 73 65 00 5f 64 6c 6f 70 65 6e 00 5f 64 6c 73 79 6d 00 5f 66 63 6c 6f 73 65 00 5f 66 65 6f 66 00 5f 66 66 6c 75 73 68 00 5f 66 67 65 74 73 00 5f 66 6f 70 65 6e 00 5f 66 72 65 61 64 00 5f 66 72 65 65 00 5f 66 73 65 65 6b 00 5f 66 73 65 65 6b 6f 00 5f 66 74 65 6c 6c 6f 00 5f 66 77 72 69 74 65 00 5f 6b 43 46 41 6c 6c 6f 63 61 74 6f 72 }

        $string_1 = { A8 01 75 02 EB 21 C6 03 01 48 8D 7D D8 BE 01 00 00 00 ?? ?? ?? ?? ?? 48 8B 45 D8 48 89 43 08 48 89 DF ?? ?? ?? ?? ?? 48 89 DF ?? ?? ?? ?? ?? A8 01 75 02 EB 4E 48 8B 5B 08 48 8B 75 D0 4C 8D 75 80 4C 89 F7 ?? ?? ?? ?? ?? 48 89 DF 4C 89 F6 ?? ?? ?? ?? ?? EB 00 48 89 C3 48 8D 7D 80 ?? ?? ?? ?? ??  }

    condition:
        Macho and filesize < 250KB and (all of ($import_v1*) or all of ($import_v2*)) and $string_1
}


rule macos_adload_dropper_custom_upx
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $custom_upx_1 = "rgbTEXT"
        $custom_upx_2 = "!bgr"
    condition:
        Macho and filesize < 500KB and $custom_upx_1 in (0..1024) and $custom_upx_2 in (0..1024)
}

rule macos_adload_dropper_custom_upx_unpacked
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $string_1 = "s3.amazonaws.com"
        $string_2 = "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
        $string_3 = "select LSQuarantineAgentBundleIdentifier, LSQuarantineDataURLString from LSQuarantineEvent"


        $import_1 = "_$s10Foundation3URLV15fileURLWithPath"

        $bytes_1 = { 48 B8 2F 62 69 6E 2F 62 61 73 48 ?? ?? 20 }

        $bytes_2 = { 48 BE 63 68 6D 6F 64 20 37 37 48 ?? 37 20 22 00 00 00 00 ?? }

        $bytes_3 = { 48 BF 2F 62 69 6E 2F 62 61 73 48 ?? 68 00 00 00 00 00 00 ?? }

    condition:
        Macho and filesize < 500KB and all of them
}

rule macos_adload_macho_deobfuscation_code
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $code = {
            42 30 4C 30 FF
            8D 51 29
            81 F9 D5 00 00 00
            41 0F 4F D4
            42 30 14 30
            8D 4A 29
            81 FA D5 00 00 00
            41 0F 4F CC
            48 83 C0 02
            48 3D 01 74 05 00
            75
        }

    condition:
        Macho and filesize < 600KB and $code
}

rule macos_adload_swift_dropper_strings
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $stringA = "_old_sa"
        $stringB = "_env_key"

        $objective_c = "@_objc_retain"

        $libz = "/libz.1.dylib"

    condition:
        Macho and filesize < 600KB and all of them

}

rule macos_adload_kotlin_agent
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $ioreg_cmd = "ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformUUID/ { split($0, line, \"\\\"\"); printf(\"%s\", line[4]); }'" wide
        $kotlin = "_kfun:#main()"

    condition:
        Macho and all of them
}

rule macos_adload_gardna_c
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $bash = "/bin/bash"
        $cat = "/bin/cat"
        $swift = "_swift"
        $guardian = "guardian"

    condition:
        Macho and filesize < 100KB and all of them
}

rule macos_airplay_app
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $pathA = "com.activitymoniter.agent.plist"
        $pathB = "Library/Application Support/.amoniter"
        $cmdA = "sleep 5; rm -rf \"%@\""
        $cmdB = "/usr/bin/unzip"
        $cmdC = "/bin/sh"

    condition:
        Macho and filesize < 100KB and 1 of ($path*) and 2 of ($cmd*)
}

rule macos_toydrop_a {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $webView = "webView:decidePolicyForNavigationAction:decisionHandler:"
        $nstask = "NSTask"
        $process = "_pclose\x00_popen"
        $codeA = { ( 19 | 17 ) 6d 1b ( d1 | 51 ) }
        $codeB = { 44 8d b4 08 25 f9 ff ff }
        $codeD = { 89 16 40 38 e9 03 29 2a }
        $codeE = { 41 8a 14 0e f6 d2 88 14 08 }
        $codeF = { 5a 07 00 91 88 03 13 4a }
    condition:
        Macho and #webView > 1 and ($nstask or $process) and (1 of ($code*)) and filesize < 500KB
}

rule macos_toydrop_b {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $webview = "webview.New"
        $base64 = "encoding/base64.(*Encoding).DecodeString"
        $code = { (45 | 46) 0f b6 ( 2c | 24 ) ( 02 | 22 ) 45 31 ( ea | e1 ) }

    condition:
        Macho and all of them
}

rule macos_toydrop_a_obfuscation_code
{
    meta:
        description = "MACOS.ADLOAD"
    strings:

        $codeA = {
            48 63 85 ?? ?? ?? ??
            8B 84 85 ?? ?? ?? ??
            88 85 ?? ?? ?? ??
            8A 85 ?? ?? ?? ??
            48 63 8D ?? ?? ?? ??
            88 84 0D ?? ?? ?? ??
            8B 85 ?? ?? ?? ??
            83 C0 01
            89 85 ?? ?? ?? ??
        }

        $codeB = {
            66 ( 41 0f | 0F ) ( 6F | 6f 44 ) ( 04 | 05 ) 0?
            66 0F 38 00 C1
            ( 66 41 0F 7E 45 ?? | 66 0F 7e 03 )
            ( 48 | 49 ) 83 C? 10
            ( 48 | 49 ) 83 C? 04
            ( 4? 81 F? | 48 3D ??) [3-4]
            75 ??
        }

    condition:
        Macho and any of them
}

rule macos_toydrop_a_agent_strings
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $stringA = "_GoKnuckles"
        $stringB = "_HearthI"
        $stringC = "_getNLS"
        $stringD = "_rrStr"

    condition:
        Macho and (2 of them)
}

rule macos_adload_dropper_cpp_function
{
    meta:
        description = "MACOS.ADLOAD"
    strings:

        $code = {
                e8 c0 fe 00 00 48 85 c0
                74 23 48 89 c3 48 89 c7
                4c 89 fe 4c 89 e2 e8 b0
                fe 00 00 85 c0 74 16 48
                ff c3 4c 89 f2 48 29 da
                4c 39 e2 7d c5
            }

    condition:
        Macho and $code
}

rule macos_smolgolf_adload_dropper_B
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $str1 = "_os/exec.init.0.func1"
        $str2 = "_net/http.http2h1ServerKeepAlivesDisabled"
        $str3 = "compareSearchAddrTo"
        $str4 = "obfuscatedTicketAge"
        $str5 = "(*ReqProxyConds).Do.func1"
        $str6 = "copyOrWarn"

    condition:
        Macho and all of them and filesize <7MB
}

rule macos_toydrop_pkg_null_padded_trailer : dropper
{
    meta:
        description = "MACOS.ADLOAD"
    condition:
        100KB < filesize and filesize < 3MB
        and uint32be(0) == 0x78617221
        and uint32be(filesize-4) < filesize - 32 - 16 - 50
        and uint32be(filesize-4) > 0x30000
        and for all i in (1..32): (uint8(uint32be(filesize-4)-i) == 0x00)
        and for all i in (0..5): (uint16(uint32be(filesize-4)+ 32 + 16 + i*2) != 0x0000)
}

rule macos_adload_mitmproxy_goproxy : adware
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $mod_goproxy_func1 = "sendNoIntercept"
        $mod_goproxy_func2 = "generateCertificate"
        $main_func1 = "loadConfigFromArgs"
        $main_func2 = "sendPageVisit"
        $listen_port = ":8080"
        $str_goproxy_func1 = "ReqHostMatches"
        $str1 = "//search.yahoo/etc/protocols127"
        $str2 = "Repeat searchReset"
        $str3 = "v + / @ P [ \t%T%d%v(\") )()\n*."

    condition:
        Macho and any of ($mod_goproxy_func*) and any of ($main_func*) and $listen_port and 2 of ($str*) and filesize < 10MB
}

rule macos_adload_mitmproxy_goproxy_b {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $listen_port = ":8080"
        $mod_goproxy_func1 = "sendNoIntercept"
        $mod_goproxy_func2 = "generateCertificate"
        $main_func1 = "loadConfigFromArgs"
        $proxy = "/goproxy/proxy.go"
        $regex_apple = "apple.*avx512f"
        $regex_icloud = "icloud.*if-matchif-range"
        $regex_allgall = "^.*$allgallp"
    condition:
        Macho and 4 of them
}

rule macos_adload_mitmproxy_goproxy_c {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $mitm_always = ".AlwaysMitm"
        $mitm_connect = ".MitmConnect"
        $mitm_cooldown = ".cleanCooldown"
        $mitm_sendNoIntercept = ".sendNoIntercept"

        $regex_apple = "apple.*avx512f"
        $regex_icloud = "icloud.*if-matchif-range"
        $regex_allgall = "^.*$allgallp"

        $config_json = "configuration.json"

        $comms_pv = "p/v"
        $comms_MCExt_GP = "MCExt_GP"
    condition:
        Macho and
        any of ($mitm_*) and
        any of ($regex_*) and
        ($config_json or any of ($comms_*))
}

rule macos_adload_mitmproxy_pyinstaller
{

    meta:
        description = "MACOS.ADLOAD"
    strings:
        $mitm = "mitmproxy"
        $str_pyz = "out00-PYZ.pyz"
        $str_MEI = "_MEIPASS"
        $str_pyi_tmpdir = "pyi-runtime-tmpdir"
        $str_partial1 = "gnoreEnvironmentFlag" fullword
        $str_partial2 = "ythonHome" fullword

    condition:
        Macho and all of them and #mitm > 150 and filesize < 20MB
}

rule macos_adload_search_daemon_qls
{

    meta:
        description = "MACOS.ADLOAD"
    strings:
        $obf_code = {
            b9 ?? ?? ?? ?? 49 89 4d
            28 49 89 45 50 49 89 45
            48 49 89 45 40 49 89 45
            38 49 89 45 30 49 89 4d
            58 49 89 85 80 00 00 00
            49 89 45 78 49 89 45 70
            49 89 45 68 49 89 45 60
            ba ?? ?? ?? ??
        }
        $s_unique = { 72 61 69 73 65 55 6e 69 6d 70 6c 65 6d 65 6e 74 65 64 }

    condition:
        Macho and filesize < 2MB and all of them
}

rule macos_adload_search_agent_qls_str
{

    meta:
        description = "MACOS.ADLOAD"
    strings:
        $str_1 = "HOME="
        $str_2 = "Dispaly=:0"
        $str_3 = "_putenv"
        $str_unique = "raiseUnimplemented"

    condition:
        Macho and filesize < 1MB and all of them
}

rule macos_adload_search_agent_qls
{

    meta:
        description = "MACOS.ADLOAD"
    strings:
        $obf_code = {
            b8 ?? ?? ?? ?? 49 89 45
            28 49 83 65 50 00 49 83
            65 48 00 49 83 65 40 00
            49 83 65 38 00 49 83 65
            30 00 49 89 45 58 49 83
            a5 80 00 00 00 00 49 83
            65 78 00 49 83 65 70 00
            49 83 65 68 00 49 83 65
            60 00 b9 ?? ?? ?? ??
        }
        $s_unique = { 72 61 69 73 65 55 6e 69 6d 70 6c 65 6d 65 6e 74 65 64 }

    condition:
        Macho and all of them and filesize < 500KB
}

rule macos_adload_search_qls_combo
{
    meta:
        description = "MACOS.ADLOAD"

    strings:
        $string_1 = "_uuid_generate_random"
        $string_2 = "_uuid_unparse"
        $string_3 = "_sysctl"
        $string_4 = "_syslog"
        $string_5 = "_getgrgid"
        $string_6 = "_getpwuid"
        $string_7 = "_SecTransformExecute"
        $string_8 = "_IOServiceMatching"
        $string_9 = "_IOServiceGetMatchingService"
        $string_10 = "BerTagged"
        $string_11 = "berContent"
        $string_12 = "berLengthBytes"
        $string_13 = "IOPlatformUUID"
        $string_14 = "IOPlatformSerialNumber"

    condition:
        Macho and filesize < 2MB and all of them
}

rule macos_adload_golang {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $func_main = "_main.main" // Is GoLang

        $target_bundle = "/Library/Application Support/Google/Chrome/"

        $prefs_plist_extension_force = "ExtensionInstallForcelist"
        $prefs_plist_extension_url = "https://clients2.google.com/service/update2/crx"

        $command_killall = "killall"
        $command_cfprefs = "cfprefs"

        /* From 25bffeab797bc8c7558525b3f11e6a8c51ad0c746acf5ae2e39edf5d20813406
        0119e1ec      "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1"
        0119e1ec      ".0.dtd\">\n"
        0119e1ec      "<plist version=\"1.0\">\n"
        0119e1ec      "\t<dict>\n"
        0119e1ec      "\t\t<key>ExtensionInstallForcelist</key>\n"
        0119e1ec      "\t\t<array>\n"
        0119e1ec      "\t\t\t<string>{{.ExtID}};https://clients2.google.com/service/update2/crx</string>\n"
        0119e1ec      "\t\t</array>\n"
        0119e1ec      "\t</dict>\n"
        0119e1ec      "</plist>\n", 0
        */
    condition:
        Macho and
        all of ($func_*) and
        all of ($command_*) and
        $target_bundle and
        all of ($prefs_plist_extension_*)
}

rule macos_adload_g_fragment {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $framgment_thing = "=?CLMNPS"
        $chrome_url = "https://clients2.google.com/service/update2/crx"
    condition:
        Macho and
        all of them
}

rule macos_adload_g_extension_plist {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $command = "ExtensionInstallForcelist"
        $chrome_url = "https://clients2.google.com/service/update2/crx"
        $prefs_plist_golang_pattern_dhelp = "{{.DHelp}}" fullword
        $prefs_plist_golang_pattern_extension_id = "{{.ExtID}}" fullword
        $prefs_plist_golang_pattern_chelp = "{{.CHelp}}" fullword
        $prefs_plist_golang_pattern_ehelp = "{{.EHelp}}"
    condition:
        Macho and
        $command and $chrome_url and any of ($prefs_plist_*)
}

rule macos_adload_g_bundle {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $func_main = "_main.main"
        $target_bundle = "/Library/Application Support/Google/Chrome/"
        $command_killall = "killall"
        $command_cfprefs = "cfprefs"
    condition:
        Macho and
        all of them
}

rule macos_adload_g_go_funcs {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $func_main = "_main.main" // Is GoLang
        $func_create_plist = "_main.createPlist" // This may not always be present
        $func_copy_file = "_main.copyFile" // This is not always present
    condition:
       Macho and
       all of them
}

rule macos_adload_g_chrome_constants {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $chrome_string_corrupt = "chrome-extension_corrupt"
        $chrome_string_local_storage = ".localstorageasync"
        $prefs_plist_extension_force = "ExtensionInstallForcelist"
    condition:
        Macho and
        all of them
}

rule macos_adload_calypso_obfuscation
{

    meta:
        description = "MACOS.ADLOAD"
    strings:
        $obf_code = {
            55 48 89 e5 41 57 41 56
            41 55 41 54 53 50 49 89
            ff 48 8b 17 4c 8b 67 08
            49 29 d4 4c 89 e0 48 ff
            c0 0f 88 ?? ?? ?? ?? 49
            8b 5f 10 48 29 d3 48 ??
            ?? ?? ?? ?? ?? ?? ?? ??
            48 39 cb 77 ?? 48 01 db
            48 39 c3 48 0f 42 d8 48
            85 db 75 ?? 31 db 45 31
            ed eb ?? 48 ?? ?? ?? ??
            ?? ?? ?? ?? ?? 48 89 df
            49 89 d6 49 89 f5 e8 ??
            ?? ?? ?? 4c 89 ee 4c 89
            f2 49 89 c5 4c 01 eb 8a
            06 4f 8d 74 25 01 41 88
            46 ff 4d 85 e4 7e ?? 4c
            89 ef 48 89 55 d0 48 8b
            75 d0 4c 89 e2 e8 ?? ??
            ?? ?? 48 8b 55 d0 4d 89
            2f 4d 89 77 08 49 89 5f
            10 48 85 d2 74 ?? 48 89
            d7 48 83 c4 08 5b 41 5c
            41 5d 41 5e 41 5f 5d e9
            ?? ?? ?? ?? 48 83 c4 08
            5b 41 5c 41 5d 41 5e 41
            5f 5d c3 4c 89 ff
        }
        $s_unique = { 56 49 44 54 45 58 5f 53 54 52 }

    condition:
        Macho and filesize < 5MB and all of them
}



rule macos_adload_websearchstride_strings
{
    meta:
        description = "MACOS.ADLOAD"

    strings:

        $str_1 = "m_cursor - m_start >= 2"
        $str_2 = "fill_line_buffer"
        $str_3 = "BerTagged"
        $str_4 = "missing or wrong low surrogate"

    condition:

        Macho and all of them and filesize < 14MB
}

rule macos_adload_websearchstride_xor
{
    meta:
        description = "MACOS.ADLOAD"

    strings:

        $xor = {

            32 0c 18 88 8d ?? f3 ff
            ff 48 8b ?5 ?8 ?? ?? ??
            ?? ?? ?? 88 08 48 ff 45
            b8 eb ?? 4c 89 ff 4c 89
            ?? [0-1] e8 ?? ?? ?? ??
            48 ?? ?? ?? 75 ??
        }

    condition:

       Macho and all of them
}

rule macos_adload_pdfcreator
{
    meta:
        description = "MACOS.ADLOAD"

    strings:
        $code = { 46 32 ?4 3? [0-1] 48 8b 45 80 48 8b 4d 88 48 89 ca 48 c1 ea 3e }
        $s = "initWithBase64EncodedString:options:"

    condition:
        Macho and all of them
}



rule macos_adload_common_data {
    meta:
        description = "MACOS.ADLOAD"
    strings:
            $ = { 34 0c be 0f 00 7b 08 b6 }
            $ = { 0f 00 b5 01 08 ae 0f 00 }
            $ = { 90 02 10 ac 0f 00 bb 02 }
            $ = { 32 e3 0f 00 fc 02 10 aa }
            $ = { 0f 00 a7 03 16 dc 0f 00 }
            $ = { c0 03 10 a8 0f 00 eb 03 }
            $ = { 08 a6 0f 00 f6 03 10 a4 }
            $ = { 0f 00 a1 04 08 90 0f 00 }
            $ = { fd 04 08 de 0f 00 88 05 }
            $ = { 10 8e 0f 00 b3 05 08 8c }
            $ = { 0f 00 fb 05 08 de 0f 00 }
            $ = { 86 06 10 ea 0e 00 b1 06 }
            $ = { 16 da 0f 00 ca 06 10 e5 }
            $ = { 0e 00 f5 06 37 c6 0f 00 }
            $ = { af 07 10 e3 0e 00 da 07 }
            $ = { 08 e1 0e 00 b6 08 08 de }
            $ = { 0f 00 c1 08 10 8a 0f 00 }
            $ = { ec 08 61 f9 0f 00 dc 09 }
            $ = { 10 88 0f 00 87 0a 08 86 }
            $ = { 0f 00 9e 0a 10 de 0f 00 }
            $ = { b1 0b 49 e5 0f 00 9d 0c }
            $ = { 0f ec 0e 00 aa 0e 05 c6 }
    condition:
        Macho and 3 of them
}

rule xprotect_macos_adload_common_data {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $common_data = {34 0c be 0f 00 7b 08 b6}
    condition:
        Macho and all of them
}

rule macos_adload_format_strings {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $format_1 = "_Tt%cSs%zu%.*s%s"
        $format_2 = "_Tt%c%zu%.*s%zu%.*s%s"

        $escapes = {20 0a 0d 09 0c 0b}

        $optional_path = ".app/Contents/MacOS/"
        $optional_zip_header = {504b03040a0000000000}
        $optional_deobfuscate_string_function = "DecompressString"
        $optional_lsgetapp = "LSGetApplicationForURL"
        $optional_uuid = "_uuid_generate_random"

    condition:
        Macho and
        all of ($format_*) and $escapes and
        any of ($optional_*) and
        filesize < 5MB
}

rule macos_adload_random_bytes {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $ = {240CA84A00F42505A64A00B2260CA54D00D72605A34D00EC260BA14A00F227059E4D008B290BC65000EA290BC85000B82A0C994D00E52A0CF44C00DC2D1AE84C00A42E0CC84C00DA2E0CAA4C00BF300C9E4C00F83013924C00C53108864C00863208FA4B00F032FF01914F00A5350EFC49009A361AD54B00B43613B74B00C73621994B008638168D4B00C3}
        $ = {3E46AC089C01AC0270C402C402D602D602D602447A465E3199020CBE0280026250EA063E8202CE0187014DA601060A1406484A0C20484A06464CBE04514D4C8606E2027F4C4D060A14484ABA013C4A20303020302A20303420303AA91C4D96048C01F801E002D802860192044CD001FE01334DD40220303C}
        $ = {220CB44A00FF241AAC4A00C7250C904A00FD250CF64900BE2725E04900962818DB4900DF280CE3470084290CE14700872A05DF4700C52A0CD64900EA2A05D14900FF2A0BDA4700852C05CC49009E2D0BC14F00FD2D0BC34F00CB2E0CC74900F82E0CC54900E1311AC34900A9320CC14900DF320CBF49}
        $ = {5400BD4405AC5600D6450BE55C00B5460BE75C0083470CA75600B0470C865600994A1AFE5500E14A0CE25500974B0CC85500E14C13C05500F44C27B45C009B4D249F5500BF4D249F5400E34D23855400864E23EB5300A94EB503D15300DE510F0000ED510CCC5300FB510CC753}
        $ = {5900C6210CF75800CD241AEF580095250CD35800CB250CB95800B02718B15800F9270CE454009E280CE25400A12905E05400DF290CA95800842A05A75800992A0BDB54009F2B05A25800B82C0BE15F00972D}
        $ = {4400B02F0CB84400A43118AF4400ED310CCF410098320CCD41009B3305CB4100E433059944008234059744009B340FC64100A535058D4400B7360FE84A009A370FEA4A00EC370C88440099380CE643}
        $ = {E13918844B00AA3A0CFA4900CF3A0CF84900D23B05F64900903C0CFF4A00B53C05FA4A00CA3C0BF14900D03D05F54A00E93E0BC25000C83F0BC4500096400CF0}
        $ = {3F0083070CB53B00B0070C943B00B70A1A8C3B00FF0A0CF03A00B50B0CD63A00A30D18CE3A00EC0D0CA43700910E0CA23700940F05A03700D20F0CC63A00F70F05C43A008C100B9B3700921105BF3A00AB120BAD3E008A130BAF3E00D8130CBA3A0085140C993A008017}
        $ = {240CF65600B5250CF45600F82618CA5600EB2718BF6000BB280CF75D00E02808F55D00D62908EC5D00972A08C76000B42A08C96000C82A0EEE5D00D12B13D16000EA2C13C06300D12D13C26300A72E0C996000DB2E0C9E60}
        $ = {310CD73700F7310CBD3700C2340BF84000F23411B8380083355E0000E1350CF43600EF350CEF3600FD350CEA36008B360CE5360099360CE03600A7360CDB3600B5360C}
        $ = {280C803700862905FE3600C4290CA83800E92905A63800FE290BF93600842B05A138009D2C0BD13B00FC2C0BD33B00CA2D0C9C3800F72D0CFB370080311AF337}
        $ = {4D4C8606E2027F4C4D060A14484ABA013C4A20303020302A20303420303AA91C4D96048C01F801E002D802860192044CD001FE01334DD40220303C42443C4244}
        $ = {6100E93D0BDB6700A33E0CF86100DF3E13DC6100F93E15BF6100E2410CB96A00F541088A5F008C4208ED5E00AB420AD35E00FE421892610083440C8D6100AD450BFB6600E7450C886100AA4613836100BD4615E46000A6490CCE5E00B94908AF5E00D04908925E00EF490AF85D00D54A0C9563009E4B08FE6400AE4B18CA6200B34C0CC56200DD4D0B9F6900974E0CC06200DA4E13A46200ED4E15876200D6510C896000E9}
        $ = {0000B35A0CF35D00C15A0CEE5D00CF5A0CE95D00DD5A0CE45D00EB5A0CDF5D00F95A0CDA5D00875B0CCE5E00955B0CD56B00A35B0CA76B00B15B0CD55D00BF5B0CCE5E00CD5B0CD05D00DB5B0CCB5D00EC5B0CA56A00FD5B05806700875C0C916600985C0C9B6600A95C0C966600BA5C05926500C45C059A6300CE5C0CC06200DF}
        $ = {842605B96A00B426058C6600E62625E76600902713E26600A32715C36600F7290CBB6A008A2A08C96500A12A08AC6500C02A0A926500932B13876600A62B15E86500FA2D0CB96A008D2E08D16300A42E08B46300C32E0A9A63009D2F05E76600C12F0FDA6400843013AE5F00B53031DA64}
        $ = {0574860924A40DEA02E0033C42B00236C4023C42C802607A30FA0138E40772F201D401D601800152C60DDA018A015AB0018604F602E602CA02C302797EBC039C01C2047E5A86018804DA022E36188A01}
        $ = {056A0B0D230BD22077103033DD11A701F00B2F12DE01F92CA20C58C904D504D703141222800ED60B9F14E70FDE063354103010300A0A0B323863B404D70300}
        $ = {3C32CA2DD72D8D6CDB925CD30659CA4905A5C1E06B452F8290CBCD812A6CD92812C3CE34974A70115818AC3F50EEE06184665759D2FB63CAE394C260D05FC8E556B2B4A31747250F1811F50EF161268DD487404AE72FD34FC87BD590CC18DDE7BB}
        $ = {3809A14000F4381380500087390C854000B63909904100843C3CDC4E00C03C16F44800D63C16D34800A13D0CCE4800C63E09954100E63E09B34100893F099A41009E3F09FB3F00A93F0CF63F00B73F0CF13F00C53F09EC3F00D03F0CEF4700DE3F0CE44100EA3F}
        $ = {B7DA17276B66812AB432E7D67540C63E8AF136A062BE92B438F74178B0EE444462E97AA564F90B86A6BFFBB4B97ACA9BD14F5C8F43E4CDD3C93C7D3B96803D9D2817DCE3E693EA5FB21DCAA63F84C8A78C83CE0B}
        $ = {B534271143F1E4CDEAE556DF49C37D646CDEFC777BE9B095635119DA76E2D379D86633D5B4B07A67E0B3907B89FB6AA16B06BBCF9A27DB864A8D9705A9CC308DE9A50A11CDC9902162C3177AA2}
        $ = {F9650E098C1BDFDBA3AFEE4CCAC2B147A7312E01831DAF7DC55C5DB757B3729D2267AB28828F9CBA7B7ED9599403A2BCDE5422D6BF901B147BCE68F961C0158238AB466A14}
        $ = {E5081DB0230387090CC4230398090CD82303B6091DEC2303D8090C802403E9090C942403870A1DA82403A90A0CBC2403BA0A0CD02403D80A1DE42403FA0A0CF824038B0B0C8C2503AB0B1DA02503CD0B0CB42503DE0B0CC82503FC0B1DDC25039E0C0CF02503AF0C0C842603CD0C1D982603EF0C0CAC2603800D0CC02603A00D1DD42603C20D0CE82603D30D0CFC2603E40D219027038A0E0CA427039B0E0CB82703AC0E21CC2703D20E0CE02703E30E0CF42703830F1D882803A50F0C9C2803B60F0CB02803C70F21C42803ED0F0CD82803FE0F0CEC2803A81029802903DB102194290381110CA8290392110CBC2903B2110FD02903C61121E42903EC110CF82903FD110C8C2A038E1213A02A03A61221B42A03CC120CC82A03DD120CDC2A03871329F02A03BA1321842B03E0130C982B03F1130CAC2B039B1429C02B03CE1421D42B03F4140CE82B0385150CFC2B0396150C902C03A7150CA42C03B8151AB82C03D71521CC2C03FD15EF01E02C03F1171AF42C03931F1DAC2103D33411F83403AD350CAF3603DC351AC33603F635C3}
        $ = {BF03B804D60205FC071FC80B03E608CB03E20B03B60C13AC0E03CE0C15BA0E03E80D16E20B03830E13E00E03870FAC03E20B03B81213AE1403D01215BC1403EA1316E20B03851413E21403891572E20B03801613A91603D0160FE20B03DF168401}
        $ = {8D1FF6FFFF9090486385B4F6FFFF89C2FFC28995B4F6FFFF488BB5B8F6FFFF31D248F7F6488DBD98F6FFFF4889D6E8}
        $ = {B30D05BA1C00B80D180000D00D05C91C00D50D110000E60D2FD81C00950E340000C90E05961D00CE0E140000E20E0AA81D00EC0E150000810F05961D00860F110000970F05961D009C0F0D0000A90F05C31D00AE0F140000C20F05D51D00C70F180000DF0F05E41D00E40F1F}
        $ = {306030501050201020201040203020105020203030201040203050403040D007B003D003708004D0078004C003D003C003B003D003B003C003C003E03AA003C0}
        $ = {A51405BD2000AA141B0000C51418CC2000DD142B0000881505AB20008D15140000A1150AF02000AB15150000C01505AB2000C5150D0000D215058B2100D71514}
        $ = {8E0B1B861B00A90B330000DC0B05BC1B00E10B0D0000EE0B05CE1B00F30B0D0000800C2EDD1B00AE0C140000C20C18EC1B00DA0C2E0000880D05991C008D0D0D}
        $ = {24E0028004B003203030A0042030401030203020201010205030306030501050201020201040203020105020203030201040203050403040D007B003D0037080}
        $ = {A20E01FE0408930D03BA055DA20E019E0608F00C03DA064AA20E01AB0708CD0C03E70749A20E01B70808AA0C0381095DA20E01E50908870C03AF0A5DA20E01930B08E4}
        $ = {C1E83E88C188CA80EA0148897DF8488975F0884DEF8855EE740EEB008A45EF2C028845ED7421EB5448B8FFFFFFFFFFFFFF3F488B4DF04821C14889CFE8254B0000488945}
        $ = {000089C148FFC90F90C248898D60FEFFFF88955FFEFFFF0F801808000031C089C1488B9560FEFFFF4829D1400F90C648FFC9400F90C74883F9004088B55EFEFFFF}
        $ = {6E0025020000000400C0A6010000000000009034E001502030A01C50302080016080016010F01E5030503050900160505020102080012020D0195060101080054020E0025010409001403020200000000000}
        $ = {0050220002802200008024000190240000302500017025000440320000903200011033000390350001F035000250370001B0370000C03800013039000219010301190B040100}
        $ = {800970900420508017C008A006F00FA03050505050205090016070F013800160A00120E005B00380066010E0017080025030503090015050800150A001106010602010504050405050504050505050501010101010301020203030106010306000}
        $ = {70404883C60F4883E6F04889E74829F74889FC488BB560FFFFFF4C8B46F84D8B48404983C10F4983E1F04989E24D29CA4C89D44989E34D29CB4C89DC4C895DE84889E34C29CB4889DC48895DE04C8B8D68}
        $ = {C1E83E88C188CA80EA0148897DF8488975F0884DEF8855EE740EEB008A45EF2C028845ED741DEB4248B8FFFFFFFFFFFFFF3F488B4DF04821C14889CFE8DD0A00}
        $ = {00000036ab000000d341000000db1b000000de33000000258d000000dc1c000000d227000000de4100000090d0ffffffe958000000d8570000007cbc000000cc1400000034bc0000004585000000bb03000000b327000000d7170000001b}
    condition:
        Macho and any of them
}

rule macos_adload_c2_constants {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $smc_header = "smc100"
        $escape_string = { 20 0a 0d 09 0c 0b 00 }
        $arrow = "-> "
        $m_parameter = "m="
    condition:
        Macho and (
            $smc_header and
            $escape_string and
            ($arrow or $m_parameter)
        )
}

rule macos_adload_search_daemon_b
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $string_1 = "fill_line_buffer"
        $string_2 = "setBerTagValue:"
        $string_3 = "m_cursor - m_start >= 2"
    condition:
        Macho and all of them and filesize < 2MB
}



rule macos_xprotect_adload_search_daemon_b_common
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $string_1 = {3A40BA7F03C03B16996C038E3C088A6C03D53C2CF27603A13E16FB6B03EF3E08EC6B03B63F25C57503FB4016DD6B03C94108CE6B0390422C987403B04330A16B03E34308B46A039F4508AF6A03A74547C078039346168F6903E14608806903A8472CB47003ED4819F16803BE4908E26803874A1FA06F03BF4B19D36803904C08C46803D74C25DA6D039C4E16B56803EA4E08A66803B14F25}
        $string_2 = {5B0AB5950303AB5C0AB3950303BC5D088BDA0203815E13EBE20203AC5E35DFF30203C9601ED3E20203E7600CBEE20203AB610AB9E20203E36215E1FA0203F86281020000F9640AED930303BB650AEB930303CC660886DA0203916713AEE20203BC6735A3F30203D9692196E20203FA690CFEE10203BE}
        $string_3 = {5B0BFD860103EB5B08C1820103A25C0CFD860103BF5C0CBB7803CB5C0C996403D75C1DF96303F45C0FE66303BF5D12936603F45F0FCB7E03AC600FE16305BB6016C56305FB610CA86C05A6620CC06303B7620CBB6303C8620CFA82}
        $string_4 = {03EC3A08894B03B13B13D54B03E73B35A84F03A93E13B24B03C83E14964B03EB3E13ED4A03A83F08E54A05B83F088E4B05DB3F07964D058C450AE84F03994508FF4C03A1450AEB4C03CD4518B54C}

    condition:
        Macho and all of them and filesize < 2MB
}

rule macos_adload_search_daemon_c
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $string_1 = "fill_line_buffer"
        $string_2 = "strequal"
        $string_3 = "m_cursor - m_start >= 2"
        $string_4 = "convert_buffer_utf"
        $string_5 = "kIOMasterPortDefault"
        $string_6 = "kMDItemWhereFroms"
    condition:
        Macho and all of them and filesize < 4MB
}

rule macos_xprotect_adload_search_daemon_c_common
{
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $string_1 = {0FB55700D3340F9C57008C350FA15A00B23560C05A00D1360FA15A00F736B102C05A00BE4339915400FE430CB45000B04432FB5300E9440CAF50009B4532E55300D4450CAA5000864632815300BF460CA55000F14632D25200AA470CA05000DC4732DA5000E3480F945000E449188F5000FC499D030000994D0C8A5000A74D0C855000B54D0C805000C34D0CFB4F00D14D0CF64F00DF4D0CF14F00ED4D0CEC4F00FB4D0CE74F00894E0CE24F00974E0CDD4F00A54E1A975500C14E1A925500DD4E1A8D5500F94E1A885500954F1A835500B44F1FD84F00B35508BD5501CC550CED5501D85508E55501E055980800}
        $string_2 = {0A0CE7B10103BB0A16C8B10103FD0A1AA9B10103970B0CF6AF0103930C47A9B20103B40D1AC4AF0103CE0D0C91AE0103B00E13E9B10103CE0E0CF9AD0103DA0E13E1AD0103AE129D01DBB80103FE14FD01F0B10103}
        $string_3 = {2F00FA211AB42F0094220C842E00A022C1090000E12B09E02D00EF2B09DB2D00FD2B09D62D008B2C09D12D00992C09CC2D00A72C09C72D00B52C09C22D00C02C09BD2D00CB2C17B13000E42C17923000FD2C09EA2D}
        $string_4 = {4640DC4C00C2460F0000D146088A4C00D946230000FC4613854C008F4713DF4B00F2479B02DC4C009C4A2B9A4C00CC4A43DC4C00944B1FDA4B00B84B0CE34C00}
        $string_5 = {2100E5080BAA1C00980908A11C00E80916CD2000870B0B981C00BA0B088F1C008A0C1ADE1F00AD0D0B861C00E00D08FD1B00B00E1AEF1E00FD0F08F41B00AD100BEB1B008011EA04A12300A5160EF21A00971713BF}
        $string_6 = {A94D0CF14F00B74D0CEC4F00C54D0CE74F00D34D0CE24F00E14D0CDD4F00EF4D0CD84F00FD4D0CD34F008B4E0CCE4F00994E0CC94F00A74E0CC44F00B54E1AA85500D14E1AA35500ED4E1A9E5500894F1A995500A54F1AF35400875508915501BC550CDD5501C85508D55501D055980800}
        $string_7 = {00FF9B6D015D2513F30A034D1AC50A03670CFB0803C9020FB80B03B10408A70803FA0543830B03EE0613B80B0384070CAC080390078901000099080CA70803A508E403}
        $string_8 = {B81313943C00CB131AB73B0084161AA13B009E160CC83900C4171AC93600DE170C983500C0180EB63900C41E1AFB3400DE1E0CCA3300C01F0EB63900CE1FBC02}
        $string_9 = {3D009E2B970F0000B53A09AA3D00C33A09A83D00D13A09A63D00DC3A09A43D00E73A09A23D00F23A09A03D00FD3A099E3D00883B099C3D00933B099A3D009E3B09983D00A93B09963D00B43B09943D00BF3B09923D00CA3B09903D00D53B17B83D00EE3B17B63D00873C17B43D00A03C17B23D00B93C17B03D00D23C}

    condition:
        Macho and 4 of them and filesize < 4MB
}

rule macos_adload_weird_plutil {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $weird_plutil = "================== PlUtil - runAppleScript error result: "
    condition:
        Macho and any of them
}

rule macos_adload_dylibs {
    meta:
        description = "MACOS.ADLOAD"
    strings:
        $dylib_pled = "@rpath/pled.dylib"
        $dylib_smsf = "@rpath/smsf.dylib"
        $dylib_asu = "@rpath/asu.dylib"
    condition:
        Macho and any of them
}

rule XProtect_MACOS_44db411
{
    meta:

        description = "MACOS.44db411"
        gk_first_launch_only = true
        match_type = 2

    strings:

        $a1 = { 2F 55 73 65 72 73 2F 25 40 2F 4C 69 62 72 61 72 79 2F 41 70 70 6C 69 63 61 74 69 6F 6E 20 53 75 70 70 6F 72 74 2F 53 6D 61 72 74 20 4D 61 63 20 43 61 72 65 2F 6C 69 63 65 6E 73 65 69 6E 66 6F 2E 70 6C 69 73 74 }
        $b1 = { 69 73 45 78 70 69 72 65 64 4C 69 63 65 6E 73 65 }
        $b2 = { 69 73 56 61 6C 69 64 4C 69 63 65 6E 73 65 }
        $b3 = { 69 73 4D 6F 72 65 4C 69 63 65 6E 73 65 }
        $b4 = { 69 73 4B 65 79 73 49 6E 63 6F 72 72 65 63 74 }
        $b5 = { 64 61 79 73 52 65 6D 61 69 6E 69 6E 67 }
        $c1 = { 63 6F 6D 2E 74 75 6E 65 75 70 6D 79 6D 61 63 }

    condition:

        Macho and
        filesize < 8MB and
        all of them

}

/**
This rule is use to match apk virus
**/

rule MAL_NET_LimeCrypter_RunPE_Jan24
{
	meta:
		description = "Detects LimeCrypter RunPE module. LimeCrypter is an open source .NET based crypter and loader commonly used by threat actors"
		author = "Jonathan Peters"
		date = "2024-01-16"
		reference = "https://github.com/NYAN-x-CAT/Lime-Crypter/tree/master"
		hash = "bcc8c679acfc3aabf22ebdb2349b1fabd351a89fd23a716d85154049d352dd12"
		score = 80
	strings:
		$op1 = { 1F 1A 58 1F 1A 58 28 }
		$op2 = { 20 B3 00 00 00 8D ?? 00 00 01 13 ?? 11 ?? 16 20 02 00 01 00 }
		$op3 = { 11 0? 11 0? 20 00 30 00 00 1F 40 28 ?? 00 00 06 }
		$op4 = { 6E 20 FF 7F 00 00 6A FE 02 }

		$s1 = "RawSecurityDescriptor" ascii
		$s2 = "CommonAce" ascii
	condition:
		uint16(0) == 0x5a4d and
		all of ($s*) and
		2 of ($op*)
}
rule MAL_NET_NixImports_Loader_Jan24 {
	meta:
		description = "Detects open-source NixImports .NET malware loader. A stealthy loader using dynamic import resolving to evade static detection"
		author = "Jonathan Peters"
		date = "2024-01-12"
		reference = "https://github.com/dr4k0nia/NixImports/tree/master"
		hash = "dd3f22871879b0bc4990c96d1de957848c7ed0714635bb036c73d8a989fb0b39"
		score = 80
	strings:
		$op1 = { 1F 0A 64 06 1F 11 62 60 } // Hash algorithm
		$op2 = { 03 20 4D 5A 90 00 94 4B 2A } // Magic
		$op3 = { 20 DE 7A 1F F3 20 F7 1B 18 BC } // Hardcoded function hashes
		$op4 = { 20 CE 1F BE 70 20 DF 1F 3E F8 14 } // Hardcoded function hashes

		$sa1 = "OffsetToStringData" ascii
		$sa2 = "GetRuntimeMethods" ascii
		$sa3 = "netstandard" ascii
	condition:
		uint16(0) == 0x5a4d and
		all of ($sa*) and
		2 of ($op*)
}
rule Eazfuscator_String_Encryption : suspicious
{
	meta:
		name = "Eazfuscator"
		category = "obfuscation"
		description = "Eazfuscator.NET string encryption"
		author = "Jonathan Peters"
		created = "2024-01-01"
		reliability = 90
		tlp = "TLP:white"
		sample = "3a9ee09ed965e3aee677043ba42c7fdbece0150ef9d1382c518b4b96bbd0e442"
	strings:
		$sa1 = "StackFrame" ascii
		$sa2 = "StackTrace" ascii
		$sa3 = "Enter" ascii
		$sa4 = "Exit" ascii

		$op1 = { 11 ?? 18 91 11 ?? 1? 91 1F 10 62 60 11 ?? 1? 91 1E 62 60 11 ?? 17 91 1F 18 62 60 }
		$op2 = { D1 28 ?? 00 00 0A 0? 1F 10 63 D1 }
		$op3 = { 1F 10 63 D1 28 [3] 0A }
		$op4 = { 7B ?? 00 00 04 16 91 02 7B ?? 00 00 04 17 91 1E 62 60 02 7B ?? 00 00 04 18 91 1F 10 62 60 02 7B ?? 00 00 04 19 91 1F 18 62 60 }
	condition:
		uint16(0) == 0x5a4d and
		all of ($sa*) and
		(
			2 of ($op*) or
			#op1 == 2
		)
}

rule Eazfuscator_Code_Virtualization : suspicious
{
	meta:
		name = "Eazfuscator"
		category = "obfuscation"
		description = "Eazfuscator.NET code virtualization"
		author = "Jonathan Peters"
		created = "2024-01-01"
		reliability = 90
		tlp = "TLP:white"
		sample = "53d5c2574c7f70b7aa69243916acf6e43fe4258fbd015660032784e150b3b4fa"
	strings:
		$sa1 = "BinaryReader" ascii
		$sa2 = "GetManifestResourceStream" ascii
		$sa3 = "get_HasElementType" ascii

		$op1 = { 28 [2] 00 06 28 [2] 00 06 72 [2] 00 70 ?? 1? 2D 0? 26 26 26 26 2B }
		$op2 = { 7E [3] 04 2D 3D D0 [3] 02 28 [3] 0A 6F [3] 0A 72 [3] 70 6F [3] 0A 20 80 00 00 00 8D ?? 00 00 01 25 D0 [3] 04 28 [3] 0A 28 [3] 06 28 [3] 06 80 [3] 04 7E [3] 04 2A } // VM Stream Init
		$op3 = { 02 20 [4] 1F 09 73 [4] 7D [3] 04 }
	condition:
		uint16(0) == 0x5a4d and
		all of ($sa*) and
		2 of ($op*)
}

rule ConfuserEx_Naming_Pattern : suspicious
{
	meta:
		name = "ConfuserEx"
		category = "obfuscation"
		description = "ConfuserEx Renaming Pattern"
		author = "Jonathan Peters"
		created = "2024-01-03"
		reliability = 90
	strings:
		$s1 = "mscoree.dll" ascii
		$s2 = "mscorlib" ascii 
		$s3 = "System.Private.Corlib" ascii
		$s4 = "#Strings" ascii
		$s5 = { 5F 43 6F 72 [3] 4D 61 69 6E }

		$name_pattern = { E2 ( 80 8? | 81 AA ) E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 80 AE}
	condition:
		uint16(0) == 0x5a4d
		and 2 of ($s*)
		and #name_pattern > 5
}

rule ConfuserEx_Packer : suspicious
{
	meta:
		name = "ConfuserEx"
		category = "obfuscation"
		description = "ConfuserEx Packer"
		author = "Jonathan Peters"
		created = "2024-01-09"
		reliability = 90
	strings:
		$s1 = "GCHandle" ascii
		$s2 = "GCHandleType" ascii

		$op1 = { 5A 20 89 C0 3F 14 6A 5E [8-20] 5A 20 FB 56 4D 44 6A 5E 6D 9E }
		$op2 = { 20 61 FF 6F 00 13 ?? 06 13 ?? 16 13 [10-20] 20 1F 3F 5E 00 5A }
		$op3 = { 16 91 7E [3] 04 17 91 1E 62 60 7E [3] 04 18 91 1F 10 62 60 7E [3] 04 19 91 1F 18 62 }
	condition:
		uint16(0) == 0x5a4d and
		all of ($s*) and
		2 of ($op*)
}



rule Reactor_Indicators : suspicious
{
	meta:
		name = ".NET Reactor"
		category = "obfuscation"
		description = "Ezriz .NET Reactor obfuscator"
		author = "Jonathan Peters"
		created = "2024-01-09"
		reliability = 90
	strings:
		$ = { 33 7B 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 7D 00 }
		$ = { 3C 50 72 69 76 61 74 65 49 6D 70 6C 65 6D 65 6E 74 61 74 69 6F 6E 44 65 74 61 69 6C 73 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
		$ = { 3C 4D 6F 64 75 6C 65 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
	condition:
      uint16(0) == 0x5a4d
		and 2 of them
}
rule SUSP_OBF_NET_ConfuserEx_Name_Pattern_Jan24 {
	meta:
		description = "Detects Naming Pattern used by ConfuserEx. ConfuserEx is a widely used open source obfuscator often found in malware"
		author = "Jonathan Peters"
		date = "2024-01-03"
		reference = "https://github.com/yck1509/ConfuserEx/tree/master"
		hash = "2f67f590cabb9c79257d27b578d8bf9d1a278afa96b205ad2b4704e7b9a87ca7"
		score = 60
	strings:
		$s1 = "mscoree.dll" ascii
		$s2 = "mscorlib" ascii 
		$s3 = "System.Private.Corlib" ascii
		$s4 = "#Strings" ascii
		$s5 = { 5F 43 6F 72 [3] 4D 61 69 6E }

		$name_pattern = { E2 ( 80 8? | 81 AA ) E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 80 AE}
	condition:
		uint16(0) == 0x5a4d
		and 2 of ($s*)
		and #name_pattern > 5
}

rule SUSP_OBF_NET_ConfuserEx_Packer_Jan24 {
	meta:
		description = "Detects binaries packed with ConfuserEx compression packer. This feature compresses and encrypts the actual image into a stub that unpacks and loads the original image on runtime."
		author = "Jonathan Peters"
		date = "2024-01-09"
		reference = "https://github.com/yck1509/ConfuserEx/tree/master"
		hash = "2570bd4c3f564a61d6b3d589126e0940af27715e1e8d95de7863579fbe25f86f"
		score = 70
	strings:
		$s1 = "GCHandle" ascii
		$s2 = "GCHandleType" ascii

		$op1 = { 5A 20 89 C0 3F 14 6A 5E [8-20] 5A 20 FB 56 4D 44 6A 5E 6D 9E }
		$op2 = { 20 61 FF 6F 00 13 ?? 06 13 ?? 16 13 [10-20] 20 1F 3F 5E 00 5A}
		$op3 = { 16 91 7E [3] 04 17 91 1E 62 60 7E [3] 04 18 91 1F 10 62 60 7E [3] 04 19 91 1F 18 62 }
	condition:
		uint16(0) == 0x5a4d
		and all of ($s*)
		and 2 of ($op*)
}
rule SUSP_OBF_NET_Eazfuscator_String_Encryption_Jan24
{
	meta:
		description = "Detects .NET images obfuscated with Eazfuscator string encryption. Eazfuscator is a widely used commercial obfuscation solution used by both legitimate software and malware."
		author = "Jonathan Peters"
		date = "2024-01-01"
		reference = "https://www.gapotchenko.com/eazfuscator.net"
		hash = "3a9ee09ed965e3aee677043ba42c7fdbece0150ef9d1382c518b4b96bbd0e442"
		score = 60
	strings:
		$sa1 = "StackFrame" ascii
		$sa2 = "StackTrace" ascii
		$sa3 = "Enter" ascii
		$sa4 = "Exit" ascii

		$op1 = { 11 ?? 18 91 11 ?? 1? 91 1F 10 62 60 11 ?? 1? 91 1E 62 60 11 ?? 17 91 1F 18 62 60 }
		$op2 = { D1 28 ?? 00 00 0A 0? 1F 10 63 D1 }
		$op3 = { 1F 10 63 D1 28 [3] 0A }
		$op4 = { 7B ?? 00 00 04 16 91 02 7B ?? 00 00 04 17 91 1E 62 60 02 7B ?? 00 00 04 18 91 1F 10 62 60 02 7B ?? 00 00 04 19 91 1F 18 62 60 } // (int)this.\u0003[0] | ((int)this.\u0003[1] << 8) | ((int)this.\u0003[2] << 0x10) | ((int)this.\u0003[3] << 0x18);
	condition:
		uint16(0) == 0x5a4d 
		and all of ($sa*) 
		and (
			2 of ($op*) 
			or
			#op1 == 2
		)
}

rule SUSP_OBF_NET_Eazfuscator_Virtualization_Jan24
{
	meta:
		description = "Detects .NET images obfuscated with Eazfuscator virtualization protection. Eazfuscator is a widely used commercial obfuscation solution used by both legitimate software and malware."
		author = "Jonathan Peters"
		date = "2024-01-02"
		reference = "https://www.gapotchenko.com/eazfuscator.net"
		hash = "53d5c2574c7f70b7aa69243916acf6e43fe4258fbd015660032784e150b3b4fa"
		score = 60
	strings:
		$sa1 = "BinaryReader" ascii
		$sa2 = "GetManifestResourceStream" ascii
		$sa3 = "get_HasElementType" ascii

		$op1 = { 28 [2] 00 06 28 [2] 00 06 72 [2] 00 70 ?? 1? 2D 0? 26 26 26 26 2B }
		$op2 = { 7E [3] 04 2D 3D D0 [3] 02 28 [3] 0A 6F [3] 0A 72 [3] 70 6F [3] 0A 20 80 00 00 00 8D ?? 00 00 01 25 D0 [3] 04 28 [3] 0A 28 [3] 06 28 [3] 06 80 [3] 04 7E [3] 04 2A } // VM Stream Init
		$op3 = { 02 20 [4] 1F 09 73 [4] 7D [3] 04 }
	condition:
		uint16(0) == 0x5a4d 
		and all of ($sa*)
		and 2 of ($op*)
}

rule SUSP_OBF_NET_Reactor_Native_Stub_Jan24 {
	meta:
		description = "Detects native packer stub for version 4.5-4.7 of .NET Reactor. A pirated copy of version 4.5 of this commercial obfuscation solution is used by various malware families like BlackBit, RedLine, AgentTesla etc."
		author = "Jonathan Peters"
		date = "2024-01-05"
		reference = "https://notes.netbytesec.com/2023/08/understand-ransomware-ttps-blackbit.html"
		hash = "6e8a7adf680bede7b8429a18815c232004057607fdfbf0f4b0fb1deba71c5df7"
		score = 70
	strings:
		$op = {C6 44 24 18 E0 C6 44 24 19 3B C6 44 24 1A 8D C6 44 24 1B 2A C6 44 24 1C A2 C6 44 24 1D 2A C6 44 24 1E 2A C6 44 24 1F 41 C6 44 24 20 D3 C6 44 24 21 20 C6 44 24 22 64 C6 44 24 23 06 C6 44 24 24 8A C6 44 24 25 F7 C6 44 24 26 3D C6 44 24 27 9D C6 44 24 28 D9 C6 44 24 29 EE C6 44 24 2A 15 C6 44 24 2B 68 C6 44 24 2C F4 C6 44 24 2D 76 C6 44 24 2E B9 C6 44 24 2F 34 C6 44 24 30 BF C6 44 24 31 1E C6 44 24 32 E7 C6 44 24 33 78 C6 44 24 34 98 C6 44 24 35 E9 C6 44 24 36 6F C6 44 24 37 B4}
	condition:
		for any i in (0..pe.number_of_resources-1) : (pe.resources[i].name_string == "_\x00_\x00")
		and $op
}

rule SUSP_OBF_NET_Reactor_Indicators_Jan24
{
	meta:
		description = "Detects indicators of .NET Reactors managed obfuscation. Reactor is a commercial obfuscation solution, pirated versions are often abused by threat actors."
		author = "Jonathan Peters"
		date = "2024-01-09"
		reference = "https://www.eziriz.com/dotnet_reactor.htm"
		hash = "be842a9de19cfbf42ea5a94e3143d58390a1abd1e72ebfec5deeb8107dddf038"
		score = 65
	strings:
		$ = { 33 7B 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 7D 00 }
		$ = { 3C 50 72 69 76 61 74 65 49 6D 70 6C 65 6D 65 6E 74 61 74 69 6F 6E 44 65 74 61 69 6C 73 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
		$ = { 3C 4D 6F 64 75 6C 65 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
	condition:
      uint16(0) == 0x5a4d
		and 2 of them
}

rule SUSP_NET_Shellcode_Loader_Indicators_Jan24 {
   meta:
      description = "Detects indicators of shellcode loaders in .NET binaries"
      author = "Jonathan Peters"
      date = "2024-01-11"
      reference = "https://github.com/Workingdaturah/Payload-Generator/tree/main"
      hash = "c48752a5b07b58596564f13301276dd5b700bd648a04af2e27d3f78512a06408"
      score = 65
   strings:
      $sa1 = "VirtualProtect" ascii
      $sa2 = "VirtualAlloc" ascii
      $sa3 = "WriteProcessMemory" ascii
      $sa4 = "CreateRemoteThread" ascii
      $sa5 = "CreateThread" ascii
      $sa6 = "WaitForSingleObject" ascii

      $x = "__StaticArrayInitTypeSize=" ascii
   condition:
      uint16(0) == 0x5a4d and
      3 of ($sa*) and
      #x == 1
}
rule SUSP_Direct_Syscall_Shellcode_Invocation_Jan24 {
	meta:
		description = "Detects direct syscall evasion technqiue using NtProtectVirtualMemory to invoke shellcode"
		author = "Jonathan Peters"
		date = "2024-01-14"
		reference = "https://unprotect.it/technique/evasion-using-direct-syscalls/"
		hash = "f7cd214e7460c539d6f8d02b6650098e3983862ff658b76ea02c33f5a45fc836"
		score = 65
	strings:
		$ = { B8 40 00 00 00 67 4C 8D 08 49 89 CA 48 C7 C0 50 00 00 00 0F 05 [4-8] 4C 8D 3D 02 00 00 00 FF E0 }
	condition:
		all of them and
		filesize < 2MB
}
rule SUSP_OBF_PyArmor_Jan24
{
	meta:
		description = "Detects PyArmor python code obfuscation. PyArmor is used by various threat actors like BatLoader"
		author = "Jonathan Peters"
		date = "2024-01-16"
		reference = "https://www.trendmicro.com/en_us/research/23/h/batloader-campaigns-use-pyarmor-pro-for-evasion.html"
		hash = "2727a418f31e8c0841f8c3e79455067798a1c11c2b83b5c74d2de4fb3476b654"
		score = 65
	strings:
		$ = "__pyarmor__" ascii
		$ = "pyarmor_runtime" ascii
		$ = "pyarmor(__" ascii
		$ = { 50 79 61 72 6D 6F 72 20 [5] 20 28 70 72 6F 29 }
		$ = { 5F 5F 61 72 6D 6F 72 5F ( 65 78 69 74 | 77 72 61 70 | 65 6E 74 65 72 ) 5F 5F }
	condition:
		2 of them
}

rule SUSP_RLO_Exe_Extension_Spoofing_Jan24 {
   meta:
      description = "Detects Right-To-Left (RLO) Unicode (U+202E) extension spoofing for .exe files"
      author = "Jonathan Peters"
      date = "2024-01-14"
      reference = "https://unprotect.it/technique/right-to-left-override-rlo-extension-spoofing/"
      hash = "cae0ab10f7c1afd7941aff767a9b59901270e3de4d44167e932dae0991515487"
      score = 70
   strings:
      $ = { E2 80 AE 76 73 63 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // csv
      $ = { E2 80 AE 66 64 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // pdf
      $ = { E2 80 AE 78 73 6C 78 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // xlsx
      $ = { E2 80 AE 78 63 6F 64 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // docx
      $ = { E2 80 AE 70 69 7A ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // zip
      $ = { E2 80 AE 67 6E 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // png
      $ = { E2 80 AE 67 65 70 6A ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // jpeg
      $ = { E2 80 AE 67 70 6A ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // jpg
      $ = { E2 80 AE 6E 6C 73 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) } // sln

      $ = { E2 80 AE 74 78 74 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 66 64 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 78 74 70 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 74 64 6f ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 63 74 65 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 66 69 67 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 70 6d 62 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 66 66 69 74 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 67 76 73 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 34 70 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 69 76 61 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 76 6f 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 76 6d 77 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 76 6c 66 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 76 6b 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 33 70 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 76 61 77 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 63 61 61 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 63 61 6c 66 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 67 67 6f ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 61 6d 77 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 72 61 72 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 7a 37 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 7a 67 72 61 74 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6f 73 69 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6c 6d 74 68 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6c 6d 65 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6d 74 68 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 66 74 72 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6d 68 63 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 61 74 68 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6b 6e 6c ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 73 6c 78 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 63 6f 64 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
      $ = { E2 80 AE 6d 63 6f 64 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
   condition:
      1 of them
}

rule Obfuscar
{
    meta:
        author = "kevoreilly"
        description = "Obfuscar xor routime"
        // cape_type = "AgentTesla Payload"
        // https://github.com/obfuscar/obfuscar/blob/65e9ced171e0f2a92d2c64c479c3a1ec3624802a/Obfuscar/Obfuscator.cs#L1693
    strings:
        $decode = {06 91 06 61 20 [4] 61 D2 9C 06 17 58 0A 06 7E [4] 8E 69 FE 04 2D ?? 2A}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PyinstallerWiper
{
    meta:
        description = "Detects indicators of the PyinstallerWiper malware variant that downloads files to system directories, corrupts user files, and disables recovery"
        author = "Emirhan Ucan"
        reference = "https://github.com/HydraDragonAntivirus/HydraDragonIOC/tree/main/PyinstallerWiper"
        hash = "3227a61794ae08b789eea4d1dcc190c67ce47ea94d78a41cba867b7aaeebe4a7"
        date = "2025-02-10"

    strings:
        // File paths created by the malware
        $sys_path     = "c:\\Windows\\System32\\drivers\\sjs.sys"
        $inf_path     = "c:\\Windows\\inf\\sjs.inf"
        // Download URL for the payload
        $download_url = "https://download1640.mediafire.com/0cg81k7i3oog0Vrbdvt4z8Dm6cr_cYgIEn6I2oJdtsv-N_wutfpSfI4z9KrH_cLItET4oZQ6fIi8Feybi8udAp58vKj2ivjUNebKCSktSQxdnFgodWEDHYVdGqVc8cLsiSZPCZPB8BWlqxdub01nZnvJSnWIoj1sxQMJ4FIB554fCPA/pk3gvqwu9nc3fs4/notepad.exe"
        // Registry and command-line strings used to disable system recovery and defenses
        $disable_defender = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender\" /v DisableAntiSpyware"
        $vssadmin         = "vssadmin delete shadows /all /quiet"
        $reg_del          = "reg delete \"HKLM\\SOFTWARE\" /f"
        // UI strings that indicate malicious intent
        $greeting         = "Helo :-)"
        $final_msg        = "Count your days."
        // Taskkill commands for critical processes
        $tk_svchost       = "taskkill /f /im svchost.exe"
        $tk_csrss         = "taskkill /f /im csrss.exe"
        // Marker used after corrupting files
        $mlbo_ext         = ".mlbo"

    condition:
        2 of ($sys_path, $inf_path, $download_url, $disable_defender, $vssadmin, $reg_del, $greeting, $final_msg, $tk_svchost, $tk_csrss, $mlbo_ext)
}

rule HackTool_Python_Pyramid_Generic {
    meta:
        description = "Detects generic Pyramid-based Python hacktools using in-memory execution and encryption techniques"
        author = "Emirhan Ucan"
        date = "2024-01-14"
        version = "0.1"
        category = "malware/hacktool"
        reference = "https://www.reddit.com/r/computerviruses/comments/1i0wf7w/fake_youtube_parnership/"
        reference2 = "https://www.virusview.net/malware/HackTool/Python/Pyramid"
        hash_description = "Hashes of known Pyramid tool samples"
        hash1 = "a08b0637632f4eb6de1512bb44f9ba787aaab2e92b0fb1f707ac6b8c0a366ccf"
        hash2 = "33f404d7d5feed8819b0981e7315ac7b213edfaaaf6d1ecd185c23ef5d77ccc9"
    strings:
        $in_memory_exec = /exec\(.*\.decode\(.*utf-8.*\)\)/ nocase  // In-memory execution
        $chacha20_func = /def\s+yield_chacha20_xor_stream/ nocase  // ChaCha20 encryption function
        $encryption_wrapper = /def\s+encrypt_wrapper\(.*encryption.*\)/ nocase  // Encryption wrapper function
        $ssl_bypass = /ssl\.CERT_NONE/ nocase  // SSL certificate verification bypass
        $base64_encode = /base64\.b64encode\(.*\)/ nocase  // Base64 encoding for obfuscation
        $dynamic_import = /class\s+CFinder.*moduleRepo.*_meta_cache.*sys\.meta_path/ nocase  // Dynamic Python module import
        $pyramid_reference = /AUTO-GENERATED PYRAMID CONFIG/ nocase  // Pyramid-specific configuration
    condition:
        all of ($in_memory_exec, $chacha20_func, $encryption_wrapper, $ssl_bypass, $dynamic_import) or 
        ($pyramid_reference and $base64_encode and 3 of ($in_memory_exec, $chacha20_func, $encryption_wrapper, $ssl_bypass))
}

private rule file_pe_header {
    meta:
        description = "Finds PE file MZ header as uint16"
        last_modified = "2024-01-01"
        author = "@petermstewart"
        DaysofYara = "1/100"

    condition:
        uint16(0) == 0x5a4d
}

private rule file_elf_header {
    meta:
        description = "Matches ELF file \x7fELF header as uint32"
        last_modified = "2024-01-02"
        author = "@petermstewart"
        DaysofYara = "2/100"

    condition:
        uint32(0) == 0x464c457f
}

private rule file_macho_header {
    meta:
        description = "Matches Mach-O file headers as uint32"
        last_modified = "2024-01-03"
        author = "@petermstewart"
        DaysofYara = "3/100"

    condition:
        uint32(0) == 0xfeedface or  //MH_MAGIC
        uint32(0) == 0xcefaedfe or  //MH_CIGAM
        uint32(0) == 0xfeedfacf or  //MH_MAGIC_64
        uint32(0) == 0xcffaedfe or  //MH_CIGAM_64
        uint32(0) == 0xcafebabe or  //FAT_MAGIC
        uint32(0) == 0xbebafeca     //FAT_CIGAM
}

private rule file_pe_signed {
    meta:
        description = "Finds signed Windows executables"
        last_modified = "2024-01-04"
        author = "@petermstewart"
        DaysofYara = "4/100"
        
    condition:
        uint16(0) == 0x5a4d and
        pe.number_of_signatures >= 1
}

private rule file_zip {
    meta:
        description = "Finds files that look like ZIP archives"
        last_modified = "2024-02-12"
        author = "@petermstewart"
        DaysofYara = "43/100"
        ref = "https://en.wikipedia.org/wiki/ZIP_(file_format)"

    strings:
        $local_file_header = { 50 4b 03 04 }
        $central_directory_header = { 50 4b 01 02 }
        $end_of_central_directory = { 50 4b 05 06 }
        
    condition:
        $local_file_header at 0 and
        $central_directory_header and
        $end_of_central_directory
}

private rule file_zip_password_protected {
    meta:
        description = "Finds files that look like password-protected ZIP archives"
        last_modified = "2024-02-13"
        author = "@petermstewart"
        DaysofYara = "44/100"
        ref = "https://en.wikipedia.org/wiki/ZIP_(file_format)"
        ref = "https://twitter.com/tylabs/status/1366728540683599878"
        
    condition:
        file_zip and
        uint16(6) & 0x1 == 0x1 //Check the general purpose bit flag in the local file header
}

private rule file_msi {
    meta:
        description = "Finds Microsoft Installer (.msi) files"
        last_modified = "2024-03-02"
        author = "@petermstewart"
        DaysofYara = "62/100"

    strings:
        $magic = { d0 cf 11 e0 a1 b1 1a e1 }
        $clsid = { 84 10 0c 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
        
    condition:
        $magic at 0 and
        $clsid
}

private rule file_pdf_header {
    meta:
        description = "Finds Portable Document Format (.pdf) files"
        last_modified = "2024-03-06"
        author = "@petermstewart"
        DaysofYara = "66/100"
        ref = "https://en.wikipedia.org/wiki/PDF"

    condition:
        uint32(0) == 0x46445025
}

/*
These rules utilise regular expressions to match cryptocurrency wallet addresses and may cause performance issues.
Comment them out if this is a problem for you.
*/
rule TTP_contains_XMR_address {
    meta:
        description = "Matches regex for Monero wallet addresses."
        last_modified = "2024-01-10"
        author = "@petermstewart"
        DaysofYara = "10/100"

    strings:
        $r1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ fullword ascii wide

    condition:
        filesize < 5MB and
        $r1
}

rule MAL_Lemonduck_strings {
    meta:
        description = "Matches strings found in Lemonduck cryptominer samples."
        last_modified = "2024-01-31"
        author = "@petermstewart"
        DaysofYara = "31/100"
        sha256 = "a5de49d6b14b04ba854246e1945ea1cfc8a7e7e254d0974efaba6415922c756f"

    strings:
        $a1 = "stratum+tcp"
        $a2 = "stratum+ssl"
        $b1 = "\"donate-level\":"
        $b2 = "\"health-print-time\":"
        $b3 = "\"retry-pause\":"
        $b4 = "\"nicehash\":"
        $b5 = "\"coin\":"
        $b6 = "\"randomx\":"
        $b7 = "\"opencl\":"
        $b8 = "\"cuda\":"
        $b9 = "This is a test This is a test This is a test"

    condition:
        (file_pe_header or file_elf_header) and
        1 of ($a*) and
        8 of ($b*)
}

rule HUNT_Mimizatz_ascii_art {
    meta:
        description = "Matches ascii art Mimikatz logo."
        last_modified = "2024-03-05"
        author = "@petermstewart"
        DaysofYara = "65/100"
        sha256 = "912018ab3c6b16b39ee84f17745ff0c80a33cee241013ec35d0281e40c0658d9"

    strings:
        $a1 = ".#####." ascii wide
        $a2 = ".## ^ ##."  ascii wide
        $a3 = "## / \\ ##" ascii wide
        $a4 = "## \\ / ##" ascii wide
        $a5 = "'## v ##'" ascii wide
        $a6 = "'#####'" ascii wide

    condition:
        all of them
}

rule MAL_HuntersInternational_Win_strings {
    meta:
        description = "Matches strings found in Hunters International Windows ransomware samples."
        last_modified = "2024-03-30"
        author = "@petermstewart"
        DaysofYara = "90/100"
        sha256 = "c4d39db132b92514085fe269db90511484b7abe4620286f6b0a30aa475f64c3e"

    strings:
        $a1 = "windows_encrypt/src/main.rs"
        $a2 = "skipped, reserve dir"
        $a3 = "skipped, min size:"
        $a4 = "skipped, symlink:"
        $a5 = "skipped, reserved file:"
        $a6 = "skipped, reserved extension:"
        $a7 = "got, dir:"
        $a8 = "encrypting"

    condition:
        file_pe_header and
        all of them
}

rule MAL_FIN13_BLUEAGAVE_PowerShell {
    meta:
        description = "Matches code sample of BLUEAGAVE PowerShell webshell used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-01"
        author = "@petermstewart"
        DaysofYara = "92/100"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "$decode = [System.Web.HttpUtility]::UrlDecode($data.item('kmd'))" ascii wide
        $a2 = "$Out =  cmd.exe /c $decode 2>&1" ascii wide
        $a3 = "$url = 'http://*:" ascii wide

    condition:
        filesize < 5KB and
        all of them
}

rule MAL_FIN13_BLUEAGAVE_Perl {
    meta:
        description = "Matches strings found in BLUEAGAVE Perl webshell used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-02"
        author = "@petermstewart"
        DaysofYara = "93/100"
        ref = "https://www.netwitness.com/wp-content/uploads/FIN13-Elephant-Beetle-NetWitness.pdf"

    strings:
        $a1 = "'[cpuset]';" ascii wide
        $a2 = "$key == \"kmd\"" ascii wide
        $a3 = "SOMAXCONN,"
        $a4 = "(/\\s*(\\w+)\\s*([^\\s]+)\\s*HTTP\\/(\\d.\\d)/)" ascii wide
        $a5 = "s/^\\s+//; s/\\s+$//;" ascii wide

    condition:
        filesize < 5KB and
        all of them
}

rule MAL_FIN13_LATCHKEY {
    meta:
        description = "Matches strings found in LATCHKEY ps2exe loader used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-03"
        author = "@petermstewart"
        DaysofYara = "94/100"
        sha256 = "b23621caf5323e2207d8fbf5bee0a9bd9ce110af64b8f5579a80f2767564f917"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "Unhandeled exception in PS2EXE" wide
        $b1 = "function Out-Minidump" base64wide
        $b2 = "$MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)" base64wide
        $b3 = "Get-Process lsass | Out-Minidump" base64wide

    condition:
        filesize < 50KB and
        file_pe_header and
        all of them
}

rule MAL_FIN13_PORTHOLE {
    meta:
        description = "Matches strings found in PORTHOLE Java network scanner used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-04"
        author = "@petermstewart"
        DaysofYara = "95/100"
        sha256 = "84ac021af9675763af11c955f294db98aeeb08afeacd17e71fb33d8d185feed5"
        sha256 = "61257b4ef15e20aa9407592e25a513ffde7aba2f323c2a47afbc3e588fc5fcaf"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "IpExtender.class"
        $a2 = "PortScanner.class"
        $a3 = "ObserverNotifier.class"

    condition:
        filesize < 20KB and
        file_zip and
        all of them
}

rule MAL_FIN13_CLOSEWATCH {
    meta:
        description = "Matches strings found in CLOSEWATCH JSP webshell and scanner used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-05"
        author = "@petermstewart"
        DaysofYara = "96/100"
        sha256 = "e9e25584475ebf08957886725ebc99a2b85af7a992b6c6ae352c94e8d9c79101"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "host=\"localhost\";"
        $a2 = "pport=16998;"
        $b1 = "request.getParameter(\"psh3\")"
        $b2 = "request.getParameter(\"psh\")"
        $b3 = "request.getParameter(\"psh2\")"
        $b4 = "request.getParameter(\"c\")"
        $c1 = "ja!, perra xD"

    condition:
        filesize < 20KB and
        6 of them
}

rule MAL_FIN13_NIGHTJAR {
    meta:
        description = "Matches strings found in NIGHTJAR file upload tool used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-06"
        author = "@petermstewart"
        DaysofYara = "97/100"
        sha256 = "5ece301c0e0295b511f4def643bf6c01129803bac52b032bb19d1e91c679cacb"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLConnection.class"
        $a2 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandler.class"
        $a3 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandlerFactory.class"
        $a4 = "FileTransferClient.class"

    condition:
        filesize < 15KB and
        file_zip and
        all of them
}

rule MAL_FIN13_SIXPACK {
    meta:
        description = "Matches strings found in SIXPACK ASPX webshell/tunneler used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-07"
        author = "@petermstewart"
        DaysofYara = "98/100"
        sha256 = "a3676562571f48c269027a069ecb08ee08973b7017f4965fa36a8fa34a18134e"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "Sending a packs..."
        $a2 = "Sending a pack..."
        $b1 = "nvc[\"host\"]"
        $b2 = "nvc[\"port\"]"
        $b3 = "nvc[\"timeout\"]"

    condition:
        filesize < 15KB and
        1 of ($a*) and
        all of ($b*)
}

rule MAL_FIN13_SWEARJAR {
    meta:
        description = "Matches strings found in SWEARJAR cross-platform backdoor used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-08"
        author = "@petermstewart"
        DaysofYara = "99/100"
        sha256 = "e76e0a692be03fdc5b12483b7e1bd6abd46ad88167cd6b6a88f6185ed58c8841"
        sha256 = "2f23224937ac723f58e4036eaf1ee766b95ebcbe5b6a27633b5c0efcd314ce36"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLConnection.class"
        $a2 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandler.class"
        $a3 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandlerFactory.class"
        $a4 = "bankcard.class"

    condition:
        filesize < 20KB and
        file_zip and
        all of them
}

rule MAL_FIN13_MAILSLOT {
    meta:
        description = "Matches strings found in MAILSLOT SMTP/POP C2 used by FIN13 (AKA: ElephantBeetle, SQUAB SPIDER)"
        last_modified = "2024-04-09"
        author = "@petermstewart"
        DaysofYara = "100/100"
        sha256 = "5e59b103bccf5cad21dde116c71e4261f26c2f02ed1af35c0a17218b4423a638"
        ref = "https://www.mandiant.com/resources/blog/fin13-cybercriminal-mexico"

    strings:
        $a1 = "%ws%\\uhost.exe" wide
        $a2 = "reg add %ws /v Uhost /t REG_SZ /d \"%ws\" /f" wide
        $a3 = "netsh advfirewall firewall add rule name=\"Uhost\"" wide
        $a4 = "profile=domain,private,public protocol=any enable=yes DIR=Out program=\"%ws\" Action=Allow" wide
        $b1 = "name=\"smime.p7s\"%s"
        $b2 = "Content-Transfer-Encoding: base64%s"
        $b3 = "Content-Disposition: attachment;"
        $b4 = "Content-Type: %smime;"

    condition:
        file_pe_header and
        all of them
}

rule macho_cstring_entrophy
{
	meta:
		description = "Identify a mach-o binary with 'high' cstring entrophy."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.13"
		DaysofYARA = "44/100"

	condition:
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__cstring" and
				math.entropy(sect.offset, sect.size) >= 7 and
				console.log("__cstring entropy: ", math.entropy(sect.offset, sect.size))
			)
		)
}

rule macho_cfstring_entrophy
{
	meta:
		description = "Identify a mach-o binary with 'high' cfstring entrophy."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.13"
		DaysofYARA = "44/100"

	condition:
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__cfstring" and
				math.entropy(sect.offset, sect.size) >= 7 and
				console.log("__cfstring entropy: ", math.entropy(sect.offset, sect.size))
			)
		)
}

rule macho_ustring_entrophy
{
	meta:
		description = "Identify a mach-o binary with 'high' ustring entrophy."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.13"
		DaysofYARA = "44/100"

	condition:
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__ustring" and
				math.entropy(sect.offset, sect.size) >= 4.5 and
				console.log("__ustring entropy: ", math.entropy(sect.offset, sect.size))
			)
		)
}

rule macho_libframework_suspicious {
  meta:
    description = "Detects on LightSpy variant dylibs"
    author = "Jacob Latonis @jacoblatonis"
    date = "2024-04-25"

  condition:
    macho.has_dylib("/usr/lib/libsqlite3.dylib") and macho.has_dylib("/usr/local/lib/libframework.dylib")
}

rule macho_no_section_text
{
	meta:
		description = "Identify macho executable without a __text section."
		author = "@shellcromancer"
		version = "1.1"
		date = "2023.02.11"
		sample = "b117f042fe9bac7c7d39eab98891c2465ef45612f5355beea8d3c4ebd0665b45"
		sample = "e94781e3da02c7f1426fd23cbd0a375cceac8766fe79c8bc4d4458d6fe64697c"
		DaysofYARA = "42/100"
		DaysofYARA = "43/100"

	condition:
		macho.filetype == macho.MH_EXECUTE and
		not for any file in macho.file : (
			for any seg in file.segments : (
				seg.segname == "__TEXT" and
				for any sect in seg.sections : (
					sect.sectname == "__text"
				)
			)
		) and
		not for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			for any sect in seg.sections : (
				sect.sectname == "__text"
			)
		)
}


/*
https://github.com/kpwn/NULLGuard
> but I haven't yet encountered a non-malicious binary lacking PAGEZERO.
*/
rule macho_no_pagezero
{
	meta:
		description = "Identify macho executable without a __PAGEZERO segment."
		author = "@shellcromancer"
		version = "1.1"
		date = "2023.02.09"
		sample = "6ab836d19bc4b69dfe733beef295809e15ace232be0740bc326f58f9d31d8197" // FinSpy
		DaysofYARA = "40/100"
		DaysofYARA = "43/100"

	condition:
		macho.filetype == macho.MH_EXECUTE and
		not for any file in macho.file : (
			not for any seg in file.segments : (
				seg.segname == "__PAGEZERO"
			)
		) and
		not for any seg in macho.segments : (
			seg.segname == "__PAGEZERO"
		)
}

rule macho_has_restrict
{
	meta:
		description = "Identify macho executables with a __RESTRICT/__restrict section."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.08"
		reference = "https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/common/MachOFile.cpp#L1588-L1598"
		sample = "fa82c3ea06d0a6da0167632d31a9b04c0569f00b4c80f921f004ceb9b7e43a7c"
		DaysofYARA = "39/100"

	condition:
		// check for section in Universal/FAT binaries
		for all file in macho.file : (
			for any seg in file.segments : (
				seg.segname == "__RESTRICT" and
				for any sect in seg.sections : (
					sect.sectname == "__restrict"
				)
			)
		) or
		// check for section in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__RESTRICT" and
			for any sect in seg.sections : (
				sect.sectname == "__restrict"
			)
		)
}

rule macho_text_protected
{
	meta:
		description = "Identify macho executables with the __TEXT segment marked as protected."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.10"
		reference = "https://objective-see.org/blog/blog_0x0D.html"
		reference = "https://ntcore.com/?p=436"
		sample = "58e4e4853c6cfbb43afd49e5238046596ee5b78eca439c7d76bd95a34115a273"
		DaysofYARA = "41/100"

	condition:
		// check for segment protection in Universal/FAT binaries
		for any file in macho.file : (
			for any seg in file.segments : (
				seg.segname == "__TEXT" and
				seg.flags & macho.SG_PROTECTED_VERSION_1
			)
		) or
		// check for segment protection in single arch binaries
		for any seg in macho.segments : (
			seg.segname == "__TEXT" and
			seg.flags & macho.SG_PROTECTED_VERSION_1
		)
}
rule macos_bundle_qlgenerator
{
	meta:
		description = "Identify macOS QuickLook plugins - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.15"
		reference = "https://theevilbit.github.io/beyond/beyond_0012/"
		DaysofYARA = "46/100"

	strings:
		$factory = "QuickLookGeneratorPluginFactory"

	condition:
		$factory and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

rule macos_bundle_mdimporter
{
	meta:
		description = "Identify macOS Spotlight Importers - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.16"
		reference = "https://theevilbit.github.io/beyond/beyond_0011/"
		DaysofYARA = "47/100"

	strings:
		$factory = "MetadataImporterPluginFactory"

	condition:
		$factory and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

rule macos_bundle_saver
{
	meta:
		description = "Identify macOS Screen Savers - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.17"
		reference = "https://theevilbit.github.io/beyond/beyond_0016/"
		reference = "https://posts.specterops.io/saving-your-access-d562bf5bf90b"
		DaysofYARA = "48/100"

	strings:
		$init1 = "initWithFrame"
		$init2 = "configureSheet"
		$init3 = "hasConfigureSheet"
		$init4 = "startAnimation"

	condition:
		3 of them and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

rule macos_bundle_colorpicker
{
	meta:
		description = "Identify macOS Color Picker's - a macOS persistence vector."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.02.18"
		reference = "https://theevilbit.github.io/beyond/beyond_0017/"
		DaysofYARA = "49/100"

	strings:
		$init1 = "NSColorPicker"
		$init2 = "NSColorPickingCustom"

	condition:
		all of them and
		(
			macho.filetype == macho.MH_BUNDLE or
			for any file in macho.file : (
				file.filetype == macho.MH_BUNDLE
			)
		)
}

rule finspy0 : cdshide android
{

	meta:
		description = "Detect Gamma/FinFisher FinSpy for Android #GovWare"
		date = "2020/01/07"
		author = "Thorsten Schröder - ths @ ccc.de (https://twitter.com/__ths__)"
		reference1 = "https://github.com/devio/FinSpy-Tools"
		reference2 = "https://github.com/Linuzifer/FinSpy-Dokumentation"
		reference3 = "https://www.ccc.de/de/updates/2019/finspy"
		sample = "c2ce202e6e08c41e8f7a0b15e7d0781704e17f8ed52d1b2ad7212ac29926436e"

	strings:
		$re = /\x50\x4B\x01\x02[\x00-\xff]{32}[A-Za-z0-9+\/]{6}/

	condition:
		$re and (#re > 50)
}
