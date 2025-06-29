/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
    // VS 8.0+
        // Binary tricks
        // Random strings
        // MAC addresses
// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule Check_unhandledExceptionFiler_iat {

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "it's checked if UnhandledExceptionFilter is imported"
		Date = "20/04/2015"
		Reference = "http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide#UnhandledExceptionFilter"

	condition:
		pe.imports("kernel32.dll","UnhandledExceptionFilter")
}
*/
// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule check_RaiseException_iat {

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "it's checked if RaiseException is imported"
		Date = "20/04/2015"
		Reference = "http://waleedassar.blogspot.com.es/2012/11/ollydbg-raiseexception-bug.html"

	condition:
		pe.imports("kernel32.dll","RaiseException")
}
*/
		// Drivers
		// SYSTEM\ControlSet001\Services
		// Processes
/*
	Rules that are included in several other files.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        /*
    	$gif1 = /\w+\.gif/
    	*/
/*
rule APT1_payloads
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $pay1 = "rusinfo.exe" wide ascii
        $pay2 = "cmd.exe" wide ascii
        $pay3 = "AdobeUpdater.exe" wide ascii
        $pay4 = "buildout.exe" wide ascii
        $pay5 = "DefWatch.exe" wide ascii
        $pay6 = "d.exe" wide ascii
        $pay7 = "em.exe" wide ascii
        $pay8 = "IMSCMig.exe" wide ascii
        $pay9 = "localfile.exe" wide ascii
        $pay10 = "md.exe" wide ascii
        $pay11 = "mdm.exe" wide ascii
        $pay12 = "mimikatz.exe" wide ascii
        $pay13 = "msdev.exe" wide ascii
        $pay14 = "ntoskrnl.exe" wide ascii
        $pay15 = "p.exe" wide ascii
        $pay16 = "otepad.exe" wide ascii
        $pay17 = "reg.exe" wide ascii
        $pay18 = "regsvr.exe" wide ascii
        $pay19 = "runinfo.exe" wide ascii
        $pay20 = "AdobeUpdate.exe" wide ascii
        $pay21 = "inetinfo.exe" wide ascii
        $pay22 = "svehost.exe" wide ascii
        $pay23 = "update.exe" wide ascii
        $pay24 = "NTLMHash.exe" wide ascii
        $pay25 = "wpnpinst.exe" wide ascii
        $pay26 = "WSDbg.exe" wide ascii
        $pay27 = "xcmd.exe" wide ascii
        $pay28 = "adobeup.exe" wide ascii
        $pay29 = "0830.bin" wide ascii
        $pay30 = "1001.bin" wide ascii
        $pay31 = "a.bin" wide ascii
        $pay32 = "ISUN32.EXE" wide ascii
        $pay33 = "AcroRD32.EXE" wide ascii
        $pay34 = "INETINFO.EXE" wide ascii

    condition:
        1 of them
}
*/
/* US CERT Rule */
/* Cylance Rule */
			/*
				"%s" /C "%s > "%s\tmp.txt" 2>&1 "     
			*/
	    /*
	      56                push    esi
	      B8 A7 C6 67 4E    mov     eax, 4E67C6A7h
	      83 C1 02          add     ecx, 2
	      BA 04 00 00 00    mov     edx, 4
	      57                push    edi
	      90                nop
	    */
	    // JSHash implementation (Justin Sobel's hash algorithm)
	    /*
	      0F B6 1C 03       movzx   ebx, byte ptr [ebx+eax]
	      8B 55 08          mov     edx, [ebp+arg_0]
	      30 1C 17          xor     [edi+edx], bl
	      47                inc     edi
	      3B 7D 0C          cmp     edi, [ebp+arg_4]
	      72 A4             jb      short loc_10003F31
	    */
	    // Encode loop, used to "encrypt" data before DNS request
	    /*
	      68 88 13 00 00    push    5000 # Also seen 3000, included below
	      FF D6             call    esi ; Sleep
	      4F                dec     edi
	      75 F6             jnz     short loc_10001554
	    */
	    // Sleep loop
	    // Generic strings
	    // Appears to be from copy/paste code
	    /*
	      6A 02             push    2               ; dwCreationDisposition
	      6A 00             push    0               ; lpSecurityAttributes
	      6A 00             push    0               ; dwShareMode
	      68 00 00 00 C0    push    0C0000000h      ; dwDesiredAccess
	      50                push    eax             ; lpFileName
	      FF 15 44 F0 00 10 call    ds:CreateFileA
	    */
	    // Arguments for CreateFileA
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-29
   Identifier: GRIZZLY STEPPE
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // this is in the encrypted code - shares with 9002 variant
        //$ = "POST http://%ls:%d/%x HTTP/1.1"
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // start code block
        // decryption from other variant with multiple start threads
        // also triggers on surtr $ = "mydll.dll\x00DoWork"
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
    /* generated with https://github.com/Xen0ph0n/YaraGenerator */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-02-19
	Identifier: BlackEnergy Malware
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
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
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
        /* XORed "/dev/null strdup() setuid(geteuid())" */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-08
	Identifier: Cheshire Cat
	Version: 0.1 
*/
/* Rule Set ----------------------------------------------------------------- */
/* Generic Rules ----------------------------------------------------------- */
/* Gen1 is more exact than Gen2 - until now I had no FPs with Gen2 */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-30
	Identifier: Codoso
	Comment: Reduced signature set for LOKI integration
*/
/* Rule Set ----------------------------------------------------------------- */
/* Super Rules ------------------------------------------------------------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
/* APTAnthemDeepPanda  */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    Yara Rule Set
    Author: Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud
    Date: 2015-12-09
   Reference = http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family
    Identifier: Derusbi Dez 2015
*/
/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-12-15
    Identifier: Derusbi Dez 2015
*/
      /* Op Code */
      /*
      test    ecx, ecx
      jz      short loc_590170
      xor     [esi], eax
      add     [esi], ebx
      add     esi, 4
      dec     ecx
      jmp     short loc_590162
      */
  //the above regex could slow down scanning
	//push api hash values plain text
	//push api hash values encoded XOR 0x13
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-10
	Identifier: Dubnium
*/
/* Rule Set ----------------------------------------------------------------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
/* Action Loader Samples --------------------------------------------------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-02
	Identifier: Emissary Malware
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-08
   Identifier: Equation Group hack tools leaked by ShadowBrokers

   Notice: Avoiding false positives is difficult with almost no antivirus
   coverage during the rule testing phase. Please report back false positives
   via https://github.com/Neo23x0/signature-base/issues
*/
/* Rule Set ----------------------------------------------------------------- */
/* Super Rules ------------------------------------------------------------- */
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-09
   Identifier: Equation Group hack tools leaked by ShadowBrokers
*/
/* Rule Set ----------------------------------------------------------------- */
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-15
   Identifier: Equation Group Toolset - Windows Folder
   Reference: https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation
*/
/* Rule Set ----------------------------------------------------------------- */
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-15
   Identifier: Equation Group Tools - Resource Folder
   Reference: https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation
*/
/* Rule Set ----------------------------------------------------------------- */
      /* Recommendation - verify the opcodes on Binarly : http://www.binar.ly */
      /* Test each of them in the search field & reduce length until it generates matches */
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-17
   Identifier: Equation Group Tool Output
   Reference: Internal Research
*/
/* Rule Set ----------------------------------------------------------------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/* Equation APT ------------------------------------------------------------ */
/* Equation Group - Kaspersky ---------------------------------------------- */
/* Rule generated from the mentioned keywords */
/* EquationDrug Update 11.03.2015 - http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/ */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-08-15
	Identifier: EQGRP
*/
/* Rule Set ----------------------------------------------------------------- */
/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-08-16
    Identifier: EQGRP
*/
/* Rule Set ----------------------------------------------------------------- */
        /* $c2 = { 7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 02 00 03 00 01 00 00 }  too many fps */
/* Super Rules ------------------------------------------------------------- */
/* Extras */
        /*
            mov     esi, [ecx+edx*4-4]
            sub     esi, 61C88647h
            mov     [ecx+edx*4], esi
            inc     edx
            cmp     edx, 2Bh
        */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/* FIVE EYES ------------------------------------------------------------------------------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        /* RC4 encryption password */
        /* Other strings */
        /* Op Code */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-08
   Identifier: ShadowBroker Screenshot Rules
*/
/* Rule Set ----------------------------------------------------------------- */
/*
Set of rules for Grasshopper APT.
Infected DLL hashes of Stolen Goods 2.1.
Ref: https://wikileaks.org/vault7/document/StolenGoods-2_1-UserGuide/StolenGoods-2_1-UserGuide.pdf

Author: Jaume Martin
Date: 07-04-2017
*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-25
   Identifier: Greenbug Malware
*/
/* Rule Set ----------------------------------------------------------------- */
/*
   Yara Rule Set
   Author: US CERT
   Date: 2017-02-10
   Identifier: US CERT Report on Grizzly Steppe - APT28/APT29
*/
/* Rule Set ----------------------------------------------------------------- */
/* TOO MANY FALSE POSITIVES

rule IMPLANT_1_v6 {
   meta:
      description = "Downrage Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $XORopcodes_eax = { 35 (22 07 15 0e|56 d7 a7 0a) }
      $XORopcodes_others = { 81 (F1|F2|F3|F4|F5|F6|F7) (22 07 15 0E|56 D7 A7 0A) }
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025) and any of them
}

*/
/* Some false positives - replaced with alternative rule (see below)

rule IMPLANT_4_v3 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $a1 = "Adobe Flash Player Installer" wide nocase
      $a3 = "regedt32.exe" wide nocase
      $a4 = "WindowsSysUtility" wide nocase
      $a6 = "USB MDM Driver" wide nocase
      $b1 = {00 05 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 05 00 88 15 28 0A 01 00 05 00 88 15 28 0A 3F 00 00 00
         00 00 00 00 04 00 04 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 5C 04 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 1C 02 00 00 01 00 30 00 30
         00 31 00 35 00 30 00 34 00 62 00 30 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 46
         00 0F 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 55 00 53 00 42 00 20
         00 4D 00 44 00 4D 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 00 00
         00 00 3C 00 0E 00 01 00 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73
         00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00
         30 00 30 00 2E 00 35 00 35 00 31 00 32 00 00 00 4A 00 13 00 01 00 4C
         00 65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00
         68 00 74 00 00 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74
         00 20 00 28 00 43 00 29 00 20 00 32 00 30 00 31 00 33 00 00 00 00 00
         3E 00 0B 00 01 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46
         00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 75 00 73 00 62 00
         6D 00 64 00 6D 00 2E 00 73 00 79 00 73 00 00 00 00 00 66 00 23 00 01
         00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00
         00 00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20
         00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 20 00 4F 00 70 00 65 00
         72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65
         00 6D 00 00 00 00 00 40 00 0E 00 01 00 50 00 72 00 6F 00 64 00 75 00
         63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 35 00 2E
         00 31 00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00 32 00
         00 00 1C 02 00 00 01 00 30 00 34 00 30 00 39 00 30 00 34 00 62 00 30
         00 00 00 4C 00 16 00 01 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00
         4E 00 61 00 6D 00 65 00 00 00 00 00 4D 00 69 00 63 00 72 00 6F 00 73
         00 6F 00 66 00 74 00 20 00 43 00 6F 00 72 00 70 00 6F 00 72 00 61 00
         74 00 69 00 6F 00 6E 00 00 00 46 00 0F 00 01 00 46 00 69 00 6C 00 65
         00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6F 00 6E 00
         00 00 00 00 55 00 53 00 42 00 20 00 4D 00 44 00 4D 00 20 00 44 00 72
         00 69 00 76 00 65 00 72 00 00 00 00 00 3C 00 0E 00 01 00 46 00 69 00
         6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 35
         00 2E 00 31 00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00
         32 00 00 00 4A 00 13 00 01 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F
         00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 43 00 6F 00 70 00
         79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 32
         00 30 00 31 00 33 00 00 00 00 00 3E 00 0B 00 01 00 4F 00 72 00 69 00
         67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D
         00 65 00 00 00 75 00 73 00 62 00 6D 00 64 00 6D 00 2E 00 73 00 79 00
         73 00 00 00 00 00 66 00 23 00 01 00 50 00 72 00 6F 00 64 00 75 00 63
         00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 4D 00 69 00 63 00 72 00
         6F 00 73 00 6F 00 66 00 74 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77
         00 73 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00
         20 00 53 00 79 00 73 00 74 00 65 00 6D 00 00 00 00 00 40 00 0E 00 01
         00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00
         69 00 6F 00 6E 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00 30 00 30
         00 2E 00 35 00 35 00 31 00 32 00 00 00 48 00 00 00 01 00 56 00 61 00
         72 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 00 00 28
         00 08 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00 74 00 69 00
         6F 00 6E 00 00 00 00 00 15 00 B0 04 09 04 B0 04}
      $b2 = {34 03 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 03 00 03 00 04 00 02 00 03 00 03 00 04 00 02 00 3F 00 00 00
         00 00 00 00 04 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 94 02 00 00 00 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 70 02 00 00 00 00 30 00 34
         00 30 00 39 00 30 00 34 00 65 00 34 00 00 00 4A 00 15 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 53 00 6F 00 6C 00 69 00 64 00 20 00 53 00 74 00 61 00 74 00 65 00
         20 00 4E 00 65 00 74 00 77 00 6F 00 72 00 6B 00 73 00 00 00 00 00 62
         00 1D 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 41 00 64 00 6F 00 62
         00 65 00 20 00 46 00 6C 00 61 00 73 00 68 00 20 00 50 00 6C 00 61 00
         79 00 65 00 72 00 20 00 49 00 6E 00 73 00 74 00 61 00 6C 00 6C 00 65
         00 72 00 00 00 00 00 30 00 08 00 01 00 46 00 69 00 6C 00 65 00 56 00
         65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 33 00 2E 00 33 00 2E
         00 32 00 2E 00 34 00 00 00 32 00 09 00 01 00 49 00 6E 00 74 00 65 00
         72 00 6E 00 61 00 6C 00 4E 00 61 00 6D 00 65 00 00 00 68 00 6F 00 73
         00 74 00 2E 00 65 00 78 00 65 00 00 00 00 00 76 00 29 00 01 00 4C 00
         65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68
         00 74 00 00 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00
         20 00 28 00 43 00 29 00 20 00 41 00 64 00 6F 00 62 00 65 00 20 00 53
         00 79 00 73 00 74 00 65 00 6D 00 73 00 20 00 49 00 6E 00 63 00 6F 00
         72 00 70 00 6F 00 72 00 61 00 74 00 65 00 64 00 00 00 00 00 3A 00 09
         00 01 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00
         6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 68 00 6F 00 73 00 74 00 2E
         00 65 00 78 00 65 00 00 00 00 00 5A 00 1D 00 01 00 50 00 72 00 6F 00
         64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 41 00 64
         00 6F 00 62 00 65 00 20 00 46 00 6C 00 61 00 73 00 68 00 20 00 50 00
         6C 00 61 00 79 00 65 00 72 00 20 00 49 00 6E 00 73 00 74 00 61 00 6C
         00 6C 00 65 00 72 00 00 00 00 00 34 00 08 00 01 00 50 00 72 00 6F 00
         64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00
         00 33 00 2E 00 33 00 2E 00 32 00 2E 00 34 00 00 00 44 00 00 00 00 00
         56 00 61 00 72 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00
         00 00 00 24 00 04 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00
         74 00 69 00 6F 00 6E 00 00 00 00 00 09 04 E4 04 46 45 32 58}
      $b3 = {C8 02 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 05 00 88 15 28 0A 01 00 05 00 88 15 28 0A 17 00 00 00
         00 00 00 00 04 00 04 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 28 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 04 02 00 00 01 00 30 00 34
         00 30 00 39 00 30 00 34 00 65 00 34 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 48
         00 10 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 49 00 44 00 45 00 20
         00 50 00 6F 00 72 00 74 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00
         00 00 62 00 21 00 01 00 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73
         00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00
         30 00 30 00 2E 00 35 00 35 00 31 00 32 00 20 00 28 00 78 00 70 00 73
         00 70 00 2E 00 30 00 38 00 30 00 34 00 31 00 33 00 2D 00 30 00 38 00
         35 00 32 00 29 00 00 00 00 00 4A 00 13 00 01 00 4C 00 65 00 67 00 61
         00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00
         43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43
         00 29 00 20 00 32 00 30 00 30 00 39 00 00 00 00 00 66 00 23 00 01 00
         50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00
         00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00
         57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 20 00 4F 00 70 00 65 00 72
         00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00
         6D 00 00 00 00 00 40 00 0E 00 01 00 50 00 72 00 6F 00 64 00 75 00 63
         00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 35 00 2E 00
         31 00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00 32 00 00
         00 44 00 00 00 01 00 56 00 61 00 72 00 46 00 69 00 6C 00 65 00 49 00
         6E 00 66 00 6F 00 00 00 00 00 24 00 04 00 00 00 54 00 72 00 61 00 6E
         00 73 00 6C 00 61 00 74 00 69 00 6F 00 6E 00 00 00 00 00 09 04 E4 04 }
      $b4 = {9C 03 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 06 00 01 40 B0 1D 01 00 06 00 01 40 B0 1D 3F 00 00 00
         00 00 00 00 04 00 04 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 FA 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 D6 02 00 00 01 00 30 00 34
         00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 58
         00 18 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 52 00 65 00 67 00 69
         00 73 00 74 00 72 00 79 00 20 00 45 00 64 00 69 00 74 00 6F 00 72 00
         20 00 55 00 74 00 69 00 6C 00 69 00 74 00 79 00 00 00 6C 00 26 00 01
         00 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00
         00 00 00 00 36 00 2E 00 31 00 2E 00 37 00 36 00 30 00 30 00 2E 00 31
         00 36 00 33 00 38 00 35 00 20 00 28 00 77 00 69 00 6E 00 37 00 5F 00
         72 00 74 00 6D 00 2E 00 30 00 39 00 30 00 37 00 31 00 33 00 2D 00 31
         00 32 00 35 00 35 00 29 00 00 00 3A 00 0D 00 01 00 49 00 6E 00 74 00
         65 00 72 00 6E 00 61 00 6C 00 4E 00 61 00 6D 00 65 00 00 00 72 00 65
         00 67 00 65 00 64 00 74 00 33 00 32 00 2E 00 65 00 78 00 65 00 00 00
         00 00 80 00 2E 00 01 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
         00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 A9 00 20 00 4D 00 69 00
         63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00 6F 00 72 00 70
         00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 2E 00 20 00 41 00 6C 00
         6C 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73
         00 65 00 72 00 76 00 65 00 64 00 2E 00 00 00 42 00 0D 00 01 00 4F 00
         72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E
         00 61 00 6D 00 65 00 00 00 72 00 65 00 67 00 65 00 64 00 74 00 33 00
         32 00 2E 00 65 00 78 00 65 00 00 00 00 00 6A 00 25 00 01 00 50 00 72
         00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00
         4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 AE 00 20 00 57
         00 69 00 6E 00 64 00 6F 00 77 00 73 00 AE 00 20 00 4F 00 70 00 65 00
         72 00 61 00 74 00 69 00 6E 00 67 00 20 00 53 00 79 00 73 00 74 00 65
         00 6D 00 00 00 00 00 42 00 0F 00 01 00 50 00 72 00 6F 00 64 00 75 00
         63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 36 00 2E
         00 31 00 2E 00 37 00 36 00 30 00 30 00 2E 00 31 00 36 00 33 00 38 00
         35 00 00 00 00 00 44 00 00 00 01 00 56 00 61 00 72 00 46 00 69 00 6C
         00 65 00 49 00 6E 00 66 00 6F 00 00 00 00 00 24 00 04 00 00 00 54 00
         72 00 61 00 6E 00 73 00 6C 00 61 00 74 00 69 00 6F 00 6E 00 00 00 00
         00 09 04 B0 04}
      $b5 = {78 03 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 00 00 05 00 6A 44 B1 1D 00 00 05 00 6A 44 B1 1D 3F 00 00 00
         00 00 00 00 04 00 04 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 D6 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 B2 02 00 00 01 00 30 00 34
         00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 4C 00 16 00 01 00 43 00
         6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00
         00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00
         6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 4E
         00 13 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00
         69 00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 57 00 69 00 6E 00 64
         00 6F 00 77 00 73 00 AE 00 53 00 79 00 73 00 55 00 74 00 69 00 6C 00
         69 00 74 00 79 00 00 00 00 00 72 00 29 00 01 00 46 00 69 00 6C 00 65
         00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00
         30 00 2E 00 37 00 36 00 30 00 31 00 2E 00 31 00 37 00 35 00 31 00 34
         00 20 00 28 00 77 00 69 00 6E 00 37 00 73 00 70 00 31 00 5F 00 72 00
         74 00 6D 00 2E 00 31 00 30 00 31 00 31 00 31 00 39 00 2D 00 31 00 38
         00 35 00 30 00 29 00 00 00 00 00 30 00 08 00 01 00 49 00 6E 00 74 00
         65 00 72 00 6E 00 61 00 6C 00 4E 00 61 00 6D 00 65 00 00 00 6D 00 73
         00 69 00 65 00 78 00 65 00 63 00 00 00 80 00 2E 00 01 00 4C 00 65 00
         67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74
         00 00 00 A9 00 20 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00
         74 00 20 00 43 00 6F 00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F
         00 6E 00 2E 00 20 00 41 00 6C 00 6C 00 20 00 72 00 69 00 67 00 68 00
         74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2E
         00 00 00 40 00 0C 00 01 00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00
         6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6D 00 73
         00 69 00 65 00 78 00 65 00 63 00 2E 00 65 00 78 00 65 00 00 00 58 00
         1C 00 01 00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D
         00 65 00 00 00 00 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 53 00
         79 00 73 00 55 00 74 00 69 00 6C 00 69 00 74 00 79 00 20 00 2D 00 20
         00 55 00 6E 00 69 00 63 00 6F 00 64 00 65 00 00 00 42 00 0F 00 01 00
         50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69
         00 6F 00 6E 00 00 00 35 00 2E 00 30 00 2E 00 37 00 36 00 30 00 31 00
         2E 00 31 00 37 00 35 00 31 00 34 00 00 00 00 00 44 00 00 00 01 00 56
         00 61 00 72 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00
         00 00 24 00 04 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00 74
         00 69 00 6F 00 6E 00 00 00 00 00 09 04 B0 04}
      $b6 = {D4 02 34 00 00 00 56 00 53 00 5F 00 56 00 45 00 52 00 53 00 49 00
         4F 00 4E 00 5F 00 49 00 4E 00 46 00 4F 00 00 00 00 00 BD 04 EF FE 00
         00 01 00 01 00 05 00 88 15 28 0A 01 00 05 00 88 15 28 0A 17 00 00 00
         00 00 00 00 04 00 04 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         00 34 02 00 00 01 00 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00
         00 65 00 49 00 6E 00 66 00 6F 00 00 00 10 02 00 00 01 00 30 00 34 00
         30 00 39 00 30 00 34 00 65 00 34 00 00 00 4C 00 16 00 01 00 43 00 6F
         00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00 00
         4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 20 00 43 00 6F
         00 72 00 70 00 6F 00 72 00 61 00 74 00 69 00 6F 00 6E 00 00 00 4E 00
         13 00 01 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63 00 72 00 69
         00 70 00 74 00 69 00 6F 00 6E 00 00 00 00 00 53 00 65 00 72 00 69 00
         61 00 6C 00 20 00 50 00 6F 00 72 00 74 00 20 00 44 00 72 00 69 00 76
         00 65 00 72 00 00 00 00 00 62 00 21 00 01 00 46 00 69 00 6C 00 65 00
         56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00 31
         00 2E 00 32 00 36 00 30 00 30 00 2E 00 35 00 35 00 31 00 32 00 20 00
         28 00 78 00 70 00 73 00 70 00 2E 00 30 00 38 00 30 00 34 00 31 00 33
         00 2D 00 30 00 38 00 35 00 32 00 29 00 00 00 00 00 4A 00 13 00 01 00
         4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70 00 79 00 72 00 69 00 67
         00 68 00 74 00 00 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00
         74 00 20 00 28 00 43 00 29 00 20 00 32 00 30 00 30 00 34 00 00 00 00
         00 6A 00 25 00 01 00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00
         61 00 6D 00 65 00 00 00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
         00 66 00 74 00 AE 00 20 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00
         AE 00 20 00 4F 00 70 00 65 00 72 00 61 00 74 00 69 00 6E 00 67 00 20
         00 53 00 79 00 73 00 74 00 65 00 6D 00 00 00 00 00 40 00 0E 00 01 00
         50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69
         00 6F 00 6E 00 00 00 35 00 2E 00 31 00 2E 00 32 00 36 00 30 00 30 00
         2E 00 35 00 35 00 31 00 32 00 00 00 44 00 00 00 01 00 56 00 61 00 72
         00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 00 00 24 00
         04 00 00 00 54 00 72 00 61 00 6E 00 73 00 6C 00 61 00 74 00 69 00 6F
         00 6E 00 00 00 00 00 09 04 E4 04}
   condition:
      (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and
      (((any of ($a*)) and (uint32(uint32(0x3C)+8) == 0x00000000)) or
      (for any of ($b*): ($ in (uint32(uint32(0x3C)+248+(40*(uint16(uint32(0x3C)+6)-1)+20))..(uint32(uint32(0x3C)+248+(40*(uint16(uint32(0x3C)+6)-1)+20))+uint32(uint32(0x3C)+248+(40*(uint16(uint32(0x3C)+6)-1)+16)))))))
}

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-12
   Identifier: Grizzly Steppe Alternatives
*/
/* Alternative Rule Set ---------------------------------------------------- */
/* Alternative Rule Set ---------------------------------------------------- */
/* TOO MANY FALSE POSITIVES

rule IMPLANT_4_v6 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = "DispatchCommand" wide ascii
      $STR2 = "DispatchEvent" wide ascii
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

*/
/* Deactivated - Slowing down scanning

rule IMPLANT_4_v12 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $CMP1 = {81 ?? 4D 5A 00 00 }
      $SUB1 = {81 ?? 00 10 00 00}
      $CMP2 = {66 81 38 4D 5A}
      $SUB2 = {2D 00 10 00 00}
      $HAL = "HAL.dll"
      $OUT = {E6 64 E9 ?? ?? FF FF}
   condition:
   (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
   uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and ($CMP1 or $CMP2)
   and ($SUB1 or $SUB2) and $OUT and $HAL
}
*/
/* TOO MANY FALSE POSITIVES

rule IMPLANT_6_v7 {
   meta:
      description = "Sednit / EVILTOSS Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = "Init1"
      $OPT1 = "ServiceMain"
      $OPT2 = "netids" nocase wide ascii
      $OPT3 = "netui" nocase wide ascii
      $OPT4 = "svchost.exe" wide ascii
      $OPT5 = "network" nocase wide ascii
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and $STR1 and 2 of ($OPT*)
}

*/
/* TOO MANY FALSE POSITIVES

rule IMPLANT_8_v2 {
   meta:
      description = "HAMMERTOSS / HammerDuke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $DOTNET= "mscorlib" ascii
      $XOR = {61 20 AA 00 00 00 61}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}

*/
/* TOO MANY FALSE POSITIVES

rule IMPLANT_10_v1 {
   meta:
      description = "CozyDuke / CozyCar / CozyBear Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {33 ?? 83 F2 ?? 81 E2 FF 00 00 00}
      $STR2 = {0F BE 14 01 33 D0 ?? F2 [1-4] 81 E2 FF 00 00 00 66 89 [6] 40 83
         F8 ?? 72}
   condition:
      uint16(0) == 0x5A4D and ($STR1 or $STR2)
}

*/
/* Deactivated - Slowing down scanning

rule IMPLANT_11_v12 {
   meta:
      description = "Mini Duke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {63 74 00 00} // ct
      $STR2 = {72 6F 74 65} // rote
      $STR3 = {75 61 6C 50} // triV
      $STR4 = {56 69 72 74} // Plau
      $STR5 = { e8 00 00 00 00 }
      $STR6 = { 64 FF 35 00 00 00 00 }
      $STR7 = {D2 C0}
      $STR8 = /\x63\x74\x00\x00.{3,20}\x72\x6F\x74\x65.{3,20}\x75\x61\x6C\x50.{3,20}\x56\x69\x72\x74/
   condition:
      (uint16(0) == 0x5A4D) and #STR5 > 4 and all of them
}

rule IMPLANT_12_v1 {
   meta:
      description = "Cosmic Duke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $FUNC = {A1 [3-5] 33 C5 89 [2-3] 56 57 83 [4-6] 64}
   condition:
      (uint16(0) == 0x5A4D) and $FUNC
}

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
        // Cause false positives.
        //$log3 = /\- About to call init routine at %p/ wide ascii
        //$log4 = /\- Calling init routine at %p/ wide ascii
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
	// BIOS Extended Write
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-13
   Identifier: Industroyer
   Reference: https://goo.gl/x81cSy
*/
/* Rule Set ----------------------------------------------------------------- */
      /* Decompressed File */
      /* .dat\x00\x00Crash */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-09-16
    Identifier: Iron Panda
*/
/* Rule Set ----------------------------------------------------------------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-05-24
	Identifier: TidePool (Ke3chang)
*/
/* APTKe3chang */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
*
* This section of the rules are all specific to the new 2016
* KeyBoy sample targeting the Tibetan community. Other following
* sections capture file characteristics observed across multiple
* years of development.
*
*/
        //MZ header //PE signature //The malware family seems to share many exports //but this is the new kid on the block.
        //MZ header //PE signature
/*
*
* This section of the rules are all broader and will hit on
* older KeyBoy samples and other samples possibly part of a
* a larger development effort.
*
*/
        //MZ header //PE signature
        //These strings are in ASCII pre-2015 and UNICODE in 2016
        //2016 specific:
        //Pre-2016:
        //MZ header  //PE signature
        //These strings are ASCII pre-2015 and UNICODE in 2016
        //MZ header //PE signature
        //MZ header //PE signature //The malware family seems to share many exports //but this is the new kid on the block.
// Note: The use of the .Init section has been observed in nearly
// all samples with the exception of the 2013 VN dropper from the
// Rapid7 blog. The config data was stored in that sample's .data
// section.
        //MZ header //PE signature //Payloads are normally smaller but the new dropper we spotted //is a bit larger. //Observed virtual sizes of the .Init section vary but they've //always been 1024, 2048, or 4096 bytes.
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        /* Original Hash */
        /* Derived Samples */
/* Related - SFX files or packed files with typical malware content -------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // gettickcount value checking
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
	//keeping only ascii version of string ->
	//strings from ora ->
	//strings from tdn ->
	//%s\r%s\r%s\r%s\r ->
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/* Rule Set ----------------------------------------------------------------- */
      /* Base64 encode config */
      /* $global:myhost = */
      /* HOME="%public%\Libraries\" */
      /* Set wss = CreateObject("wScript.Shell") */
      /* $scriptdir = Split-Path -Parent -Path $ */
      /* \x0aSet wss = CreateObject("wScript.Shell") */
      /* whoami & hostname */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        /* Decode Function
        CODE:00406C71 8B 55 F4                  mov     edx, [ebp+var_C]
        CODE:00406C74 8A 54 1A FF               mov     dl, [edx+ebx-1]
        CODE:00406C78 8B 4D F8                  mov     ecx, [ebp+var_8]
        CODE:00406C7B C1 E9 08                  shr     ecx, 8
        CODE:00406C7E 32 D1                     xor     dl, cl
        CODE:00406C80 88 54 18 FF               mov     [eax+ebx-1], dl
        CODE:00406C84 8B 45 F4                  mov     eax, [ebp+var_C]
        CODE:00406C87 0F B6 44 18 FF            movzx   eax, byte ptr [eax+ebx-1]
        CODE:00406C8C 03 45 F8                  add     eax, [ebp+var_8]
        CODE:00406C8F 69 C0 D9 DB 00 00         imul    eax, 0DBD9h
        CODE:00406C95 05 3B DA 00 00            add     eax, 0DA3Bh
        CODE:00406C9A 89 45 F8                  mov     [ebp+var_8], eax
        CODE:00406C9D 43                        inc     ebx
        CODE:00406C9E 4E                        dec     esi
        CODE:00406C9F 75 C9                     jnz     short loc_406C6A
        */
        /* Decode Function
        8B 1A       mov     ebx, [edx]
        8A 1B       mov     bl, [ebx]
        80 EB 02    sub     bl, 2
        8B 74 24 08 mov     esi, [esp+14h+var_C]
        32 1E       xor     bl, [esi]
        8B 31       mov     esi, [ecx]
        88 1E       mov     [esi], bl
        8B 1A       mov     ebx, [edx]
        43          inc     ebx
        89 1A       mov     [edx], ebx
        8B 19       mov     ebx, [ecx]
        43          inc     ebx
        89 19       mov     [ecx], ebx
        48          dec     eax
        75 E2       jnz     short loc_40EAC6
        */
        /* String
        C7 45 FC 00 04 00 00          mov     [ebp+Memory], 400h
        C6 45 D8 50                   mov     [ebp+Str], 'P'
        C6 45 D9 72                   mov     [ebp+var_27], 'r'
        C6 45 DA 6F                   mov     [ebp+var_26], 'o'
        C6 45 DB 78                   mov     [ebp+var_25], 'x'
        C6 45 DC 79                   mov     [ebp+var_24], 'y'
        C6 45 DD 2D                   mov     [ebp+var_23], '-'
        C6 45 DE 41                   mov     [ebp+var_22], 'A'
        C6 45 DF 75                   mov     [ebp+var_21], 'u'
        C6 45 E0 74                   mov     [ebp+var_20], 't'
        C6 45 E1 68                   mov     [ebp+var_1F], 'h'
        C6 45 E2 65                   mov     [ebp+var_1E], 'e'
        C6 45 E3 6E                   mov     [ebp+var_1D], 'n'
        C6 45 E4 74                   mov     [ebp+var_1C], 't'
        C6 45 E5 69                   mov     [ebp+var_1B], 'i'
        C6 45 E6 63                   mov     [ebp+var_1A], 'c'
        C6 45 E7 61                   mov     [ebp+var_19], 'a'
        C6 45 E8 74                   mov     [ebp+var_18], 't'
        C6 45 E9 65                   mov     [ebp+var_17], 'e'
        C6 45 EA 3A                   mov     [ebp+var_16], ':'
        C6 45 EB 20                   mov     [ebp+var_15], ' '
        C6 45 EC 4E                   mov     [ebp+var_14], 'N'
        C6 45 ED 54                   mov     [ebp+var_13], 'T'
        C6 45 EE 4C                   mov     [ebp+var_12], 'L'
        C6 45 EF 4D                   mov     [ebp+var_11], 'M'
        C6 45 F0 20                   mov     [ebp+var_10], ' '
        */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
// Operation Potao yara rules
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
        // hash of CryptBinaryToStringA and CryptStringToBinaryA
        // old hash of CryptBinaryToStringA and CryptStringToBinaryA
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-09
	Identifier: Poseidon Group APT
*/
// Operation Groundbait yara rules
// For feedback or questions contact us at: github@eset.com
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
        // binary
        // encrypted
        // mutex
        // other
        // dll names
        // rbcon
        // files and logs
        // pdb strings
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // $x2 = "msupdate" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.01' */
    // This hash from VT retrohunt, original sample was a memory dump
    // MiniLZO release date
    // Indicates a file transfer
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
    Warning: Don't use this rule set without excluding the false positive hashes listed in the file falsepositive-hashes.txt from https://github.com/Neo23x0/Loki/blob/master/signatures/falsepositive-hashes.txt

*/
/* Update 27.11.14 */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
    Warning: Don't use this rule set without excluding the false positive hashes listed in the file falsepositive-hashes.txt from https://github.com/Neo23x0/Loki/blob/master/signatures/falsepositive-hashes.txt

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    Yara Rule Set
    Author: FLorian Roth
    Date: 2016-08-09
    Identifier: Project Sauron - my own ruleset
*/
/* Rule Set ----------------------------------------------------------------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // .text:10002069 66 83 F8 2C                       cmp     ax, ','
        // .text:1000206D 74 0C                             jz      short loc_1000207B
        // .text:1000206F 66 83 F8 3B                       cmp     ax, ';'
        // .text:10002073 74 06                             jz      short loc_1000207B
        // .text:10002075 66 83 F8 7C                       cmp     ax, '|'
        // .text:10002079 75 05                             jnz     short loc_10002080
        // .text:10001D83 83 F8 09                          cmp     eax, 9          ; switch 10 cases
        // .text:10001D86 0F 87 DB 00 00 00                 ja      loc_10001E67    ; jumptable 10001D8C default case
        // .text:10001D8C FF 24 85 55 1F 00+                jmp     ds:off_10001F55[eax*4] ; switch jump
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-13
	Identifier: Sofacy Fysbis
*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-14
	Identifier: Sofacy June 2016
*/
/* Rule Set ----------------------------------------------------------------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    Yara Rule Set
    Author: Kudelski Security (modified by Florian Roth)
    Reference: https://www.kudelskisecurity.com/sites/default/files/sphinx_moth_cfc_report.pdf
    Date: 2015-11-23
    Identifier: Sphinx Moth
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
         // 0x10001778 8b 45 08  mov     eax, dword ptr [ebp + 8]
         // 0x1000177b 35 dd 79 19 ae    xor     eax, 0xae1979dd
         // 0x10001780 33 c9     xor     ecx, ecx
         // 0x10001782 8b 55 08  mov     edx, dword ptr [ebp + 8]
         // 0x10001785 89 02     mov     dword ptr [edx], eax
         // 0x10001787 89 ?? ??  mov     dword ptr [edx + 4], ecx
         // 0x10002045 74 36     je      0x1000207d
         // 0x10002047 8b 7f 08  mov     edi, dword ptr [edi + 8]
         // 0x1000204a 83 ff 00  cmp     edi, 0
         // 0x1000204d 74 2e     je      0x1000207d
         // 0x1000204f 0f b7 1f  movzx   ebx, word ptr [edi]
         // 0x10002052 8b 7f 04  mov     edi, dword ptr [edi + 4]
         // 0x100020cf 74 70     je      0x10002141
         // 0x100020d1 81 78 05 8d 54 24 04      cmp     dword ptr [eax + 5], 0x424548d
         // 0x100020d8 75 1b     jne     0x100020f5
         // 0x100020da 81 78 08 04 cd ?? ??      cmp     dword ptr [eax + 8], 0xc22ecd04
        /* Opcodes by Binar.ly */
        // 0x10001778 8b 45 08  mov     eax, dword ptr [ebp + 8]
        // 0x1000177b 35 dd 79 19 ae    xor     eax, 0xae1979dd
        // 0x10001780 33 c9     xor     ecx, ecx
        // 0x10001782 8b 55 08  mov     edx, dword ptr [ebp + 8]
        // 0x10001785 89 02     mov     dword ptr [edx], eax
        // 0x10001787 89 ?? ??  mov     dword ptr [edx + 4], ecx
        // 0x10002045 74 36     je      0x1000207d
        // 0x10002047 8b 7f 08  mov     edi, dword ptr [edi + 8]
        // 0x1000204a 83 ff 00  cmp     edi, 0
        // 0x1000204d 74 2e     je      0x1000207d
        // 0x1000204f 0f b7 1f  movzx   ebx, word ptr [edi]
        // 0x10002052 8b 7f 04  mov     edi, dword ptr [edi + 4]
        // 0x100020cf 74 70     je      0x10002141
        // 0x100020d1 81 78 05 8d 54 24 04      cmp     dword ptr [eax + 5], 0x424548d
        // 0x100020d8 75 1b     jne     0x100020f5
        // 0x100020da 81 78 08 04 cd ?? ??      cmp     dword ptr [eax + 8], 0xc22ecd04
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
/* Super Rules ------------------------------------------------------------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-06
	Identifier: Threat Group 3390
*/
        /* $s1 = "pnipcn.dllUT" fullword ascii
        $s2 = "ssonsvr.exeUT" fullword ascii
        $s3 = "navlu.dllUT" fullword ascii
        $s4 = "@CONOUT$" fullword wide 
        $s5 = "VPDN_LU.exeUT" fullword ascii
        $s6 = "msi.dll.urlUT" fullword ascii
        $s7 = "setup.exeUT" fullword ascii 
        $s8 = "pnipcn.dll.urlUT" fullword ascii
        $s9 = "ldvpreg.exeUT" fullword ascii */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
  Yara Rule Set
  Author: Florian Roth
  Date: 2016-05-23
  Identifier: Swiss RUAG APT Case
  Reference: https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case 
*/
  /* MZ Header and malformed PE header > 0x0bad */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-09-24
	Identifier: Unit 78020 Malware
*/
        /* additional strings based on PDF report - not found in samples */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        //MZ header //PE signature //Just a few of these as they differ
        //MZ header //PE signature
        //MZ header //PE signature
        //MZ header  //PE signature
        //MZ header //PE signature
        //MZ header //PE signature
        //MZ header //PE signature
        //MZ header //PE signature
        //MZ header //PE signature
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        //read file... error..
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/* Super Rules ------------------------------------------------------------- */
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
    // code from offset: 0x46CBCD
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-10-10
	Identifier: Winnti Malware
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	This Yara Rule is to be considered as "experimental"
	It reperesents a first attempt to detect BeEF hook function in memory
	It still requires further refinement 

*/
/* experimental */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
        /*$s6 = "-noni" fullword ascii*/
        /*$s7 = "-noninteractive" fullword ascii*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
        // v1 strs
        // Athena-v1.8.3
        // v1 cmds
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // May only the challenge guide you
        // Check for the presence of MZ and kutuzov license identifier
        // TokenSpy identifiers
        // Hidden VNC identifiers
        // Browsers identifiers
        // Remove the above line if you want to trig also on memory dumps, etc...
    // May only the challenge guide you
        // Entry point identifier with CreateThread pointer in '??' 
        // End of main proc with sleep value in '??' and api call to sleep in '??'
        // API String identifier (ShellExecuteExW, SHELL32.dll, GetUserNameExW, Secur32.dll)
        // New Thread identifier
        // Remove the above line if you want to trig also on memory dumps, etc...
        // May only the challenge guide you
        // Check for the presence of MZ, kutuzov license identifier, and good hardware ID
        // Builder strings identifiers
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
        // May only the challenge guide you
/*
0xD:
.text:004022EC FF 15 20 70 40 00             CALL DWORD PTR DS:[407020]  ; cscwcng.CscCngDispense
.text:004022F2 F6 C4 80                      TEST AH,80
winpot:
.text:004019D4 FF 15 24 60 40 00             CALL DWORD PTR DS:[406024]  ; cscwcng.CscCngDispense
.text:004019DA F6 C4 80                      TEST AH,80
*/
/*
0xD...: 0040506E  25 31 5B 31 2D 34 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D: %1[1-4]VAL=%8[0-9]
winpot: 0040404D  25 31 5B 30 2D 39 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D: %1[0-9]VAL=%8[0-9]
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
                    // May only the challenge guide you
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // dec [ebp + procname], push eax, push edx, call get procaddress
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/* 
  github.com/dfirnotes/rules
  Version 0.0.0
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // May only the challenge guide you
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*

   Generic Cloaking

   Florian Roth
   BSK Consulting GmbH

	License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
	Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
   //md5=474429d9da170e733213940acc9a2b1c
   /*
   seg000:08130801 68 00 09 13 08                          push    offset dword_8130900
    seg000:08130806 83 3D 30 17 13 08 02                    cmp     ds:dword_8131730, 2
    seg000:0813080D 75 07                                   jnz     short loc_8130816
    seg000:0813080F 81 04 24 00 01 00 00                    add     dword ptr [esp], 100h
    seg000:08130816                         loc_8130816:                           
    seg000:08130816 50                                      push    eax
    seg000:08130817 E8 15 00 00 00                          call    sub_8130831
    seg000:0813081C E9 C8 F6 F5 FF                          jmp     near ptr 808FEE9h
   */
    // md5=2579aa65a28c32778790ec1c673abc49
    /*
    .rodata:08104D20 E8 00 00 00 00                          call    $+5
    .rodata:08104D25 87 1C 24                                xchg    ebx, [esp+4+var_4] ;
    .rodata:08104D28 83 EB 05                                sub     ebx, 5
    .rodata:08104D2B 8D 83 00 FD FF FF                       lea     eax, [ebx-300h]
    .rodata:08104D31 83 BB 10 CA 02 00 02                    cmp     dword ptr [ebx+2CA10h], 2
    .rodata:08104D38 75 05                                   jnz     short loc_8104D3F
    .rodata:08104D3A 05 00 01 00 00                          add     eax, 100h
    .rodata:08104D3F                         loc_8104D3F:                           
    .rodata:08104D3F 50                                      push    eax
    .rodata:08104D40 FF 74 24 10                             push    [esp+8+strsVector]
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/* Rule Set ----------------------------------------------------------------- */
/* Super Rules ------------------------------------------------------------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // mov al, 20h; sub al, bl; add [ebx+esi], al; push esi; inc ebx; call edi; cmp ebx, eax
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
		// Specific strings (may change)
		// Less specific strings
		// Generic
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
		// decryption loop
		//mov byte ptr [ebp - x] y, x: 0x10-0x1 y: 0-9,A-F
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-10-18
	Identifier: Fareit Oct 2015
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // standard string hiding
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2016-07-21
	Identifier: NBXC4L
	ref = http://pastebin.com/raw/FdrnPwae
*/
/* Rule Set ----------------------------------------------------------------- */
/* Super Rules ------------------------------------------------------------- */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/* Yara rule to detect Linux/Httpsd generic
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
    and  open to any user or organization, as long as you use it under this license.
*/
/* Yara rule to detect IcedID banking trojan generic 
   This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   and  open to any user or organization, as long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // 88h decrypt
        // stage 2
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // Load these function strings 4 characters at a time. These check the first two blocks:
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // jmp $+5; push 423h
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
		// Network protocol
		// Injects
		// UAC bypass
		// Network protocol
		// Crypted strings
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
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
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/* LENOVO Superfish -------------------------------------------------------- */
		//$s1 = "VisualDiscovery.exe" fullword wide
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
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
		//if its just one char a time
		// bit hacky but for when samples dont just simply mov 1 char at a time
		// internal names
		// dbx
		// other folders
		// embedded file names
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // Load these function strings 4 characters at a time. These check the first two blocks:
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
ref : https://github.com/gwillem/magento-malware-scanner/blob/master/rules/backend.yar
author : https://github.com/gwillem

*/
    /*
		)){eval (${ $njap58}['q9e5e25' ])
		) ) { eval ( ${$yed7 }['
    */
	/*
		eval(hnsqqh($llmkuhieq, $dbnlftqgr));?>
		eval(vW91692($v7U7N9K, $v5N9NGE));?>
    */
	/*
    // $GLOBALS['ywanc2']($GLOBALS['ggbdg61']
    */
	/*
    // $ooooo00oo0000oo0oo0oo00ooo0ooo0o0o0 = gethostbyname($_SERVER["SERVER_NAME"]);
    // if(!oo00o0OOo0o00O("fsockopen"))
    // strings: $ = "$ooooo00oo0000oo0"
    */
		/*
        // https://en.wikipedia.org/wiki/List_of_file_signatures
        // magic module is not standard compiled in on our platform
        // otherwise: condition: magic.mime_type() == /^image/
        // $jpg = { 4A 46 49 46 00 01 }
        */
    /* forces php execution of image files, dropped in an .htaccess file under media */
    /* { eval($cco37(${ $kasd1}[ 'n46b398' ] ) );} */
    /* $GLOBALS['y63581'] = "\x43 */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
ref : https://github.com/gwillem/magento-malware-scanner
author : https://github.com/gwillem

*/
    /* token=KjsS29Msl&host= */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
ref : https://github.com/gwillem/magento-malware-scanner/
author : https://github.com/gwillem

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
  Description: This rule keys on email headers that may have been sent from a malicious PHP script on a compromised webserver.
  Priority: 4
  Scope: Against Email
  Tags: None
  Author: P.Burbage
  Created in PhishMe's Triage on September 1, 2015 1:43 PM
*/
/*
  Description: Hits on ZIP attachments that contain *.js or *.jse - usually JS Dropper malware that has downloaded Kovter & Boaxee in the past.
  Priority: 5
  Scope: Against Attachment
  Tags: FileID
  Author: P.Burbage
  Created in PhishMe's Triage on September 1, 2015 1:43 PM
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/* Yara rule to detect Mirai Okiru generic 
   This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   and  open to any user or organization, as long as you use it under this license.
*/
		// noted some Okiru variant doesnt have below function, uncomment to seek specific x86 bins
    // $st07 = "iptables -F\n" fullword nocase wide ascii
/* Yara rule to detect Mirai Satori generic 
   This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   and  open to any user or organization, as long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
	//$s4 = "./start" wide
	//$s9 = "%cd%" wide
		/* Sample 1 */
		/* Sample 2 */
		/* Sample 3 */
		/* Certificate and Keywords */
		/* Executables */
		/* Libraries */
		/* Imports */
		/* Registry */
		/* Folders */
		/* False Positives */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // decryption
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // decryption loop in dropper
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
		//network strings
		//debugging strings
		//dll component exports
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // push vars then look for MZ
        // nops then look for PE\0\0
        // xor 0x58 dos stub
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // DOS stub signature                           PE signature
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
    	//$useragent1 = "Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)"
    	//$useragent2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/5.0)"
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // decrypt in intelnat.sys
        // decrypt in mswsocket.dll
        // loop in msupdate.dll
/* Yara rule to detect ELF Linux malware Rebirth Vulcan (Torlus next-gen) generic 
   This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   and  open to any user or organization, as long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // decryption loop
        // push then pop values
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
  Description: Rar file with a .js inside
  Author: iHeartMalware
  Priority: 5
  Scope: Against Attachment
  Tags: http://phishme.com/rockloader-new-upatre-like-downloader-pushed-dridex-downloads-malwares/
  Created in PhishMe Triage on April 7, 2016 3:41 PM
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // xor 0x30 decryption
        // hidden AutoConfigURL
        // hidden ProxyEnable
        // xor on rand value?
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // add edi, 14h; cmp edi, 50D0F8h
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // decryption
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
		//decrypt config
		//if Burn folder name is not in strings
		//mov char in _Fire
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
/* Description:
    Detects ELF or MachO tinyshell backdoor on static, dynamic binary form.
    It is commonly used as backdoor in Linux, FreeBSD or MacOSX operating systems.
    This rule by default is NOT designed to scan the CNC client side.
    Category: ELF or MachO, backdoor, hacktool, RAT, shell
   License:
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html)
    Version 1-20180211, author:unixfreaxjp
*/
    // can be added
    // can be added
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
 * DESCRIPTION: Yara rules to match the known binary components of the HatMan
 *              malware targeting Triconex safety controllers. Any matching
 *              components should hit using the "hatman" rule in addition to a
 *              more specific "hatman_*" rule.
 * AUTHOR:      DHS/NCCIC/ICS-CERT
 */
/* Private rules that are used at the end in the public rules. */
/* Actual public rules to match using the private rules. */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-10-13
	Identifier: Upatre Campaign October 2015
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // add eax, ecx; xor byte ptr [eax], ??h; inc ecx
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // character replacement
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // decryption loop
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        //  encryption
		// the wide strings are 16bit bigendian strings in memory. strings -e b memdump.file
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
// Point of Sale (POS) Malware and Tools used during POS compromises
	//$s2 = "cmd /c net start %s"
	//$s3 = "=== pid:"
	//$s4 = "GOTIT"
	//$s5 = ".memdump"
	//$s6 = "POSWDS"
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        //64A130000000      mov eax, dword ptr fs:[0x30]
        //8B400C        mov eax, dword ptr [eax + 0xc]
        //8B401C        mov eax, dword ptr [eax + 0x1c]
        //8B4008        mov eax, dword ptr [eax + 8]
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
    /*
      Regla para detectar el dropper de Ransom.CryptXXX con MD5 d01fd2bb8c6296d51be297978af8b3a1
    */
    /*
      Regla para detectar el codigo Ransom.CryptXXX fuera del dropper con MD5 ae06248ab3c02e1c2ca9d53b9a155199
    */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
//more info at reversecodes.wordpress.com
//More at reversecodes.wordpress.com
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-17
	Identifier: Locky
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
Four YARA rules to check for payloads on systems. Thanks to sinkholing, encyrption may not occur, BUT you may still have binaries lying around.
If you get a match for "WannaDecryptor" and not for Wanna_Sample, then you may have a variant!
 
Check out http://yara.readthedocs.io on how to write and add a rule as below and index your
rule by the sample hashes.  Add, share, rinse and repeat!
*/
/* Kaspersky Rule */
/* Cylance Rule */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-03-24
	Identifier: Petya Ransomware
*/
/* Rule Set ----------------------------------------------------------------- */
      //filetype="PE"
      // DRIVE USAGE
      // RANSOMNOTE
      // FUNCTIONALITY, APIS
      // COMMANDS
      //  -- Clearing event logs & USNJrnl
      // -- Scheduled task
      // -- Sysinternals/PsExec and WMIC
      // (uint16(0) == 0x5A4D)
        /* Some commands executed by the Petya variant */
       /* Strings of encrypted files */
        /* MBR/VBR payload */
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
		// Versions 2x
		// Versions 3x & 4x & 5x
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
		// Part of the encoded User-Agent = Mozilla
		// XOR to decode User-Agent after string stacking 0x10001630
		// XOR with 0x2E - 0x10002EF6
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-10-01
	Identifier: Indetectables RAT
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
    	// Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0;rv:11.0) like Gecko
	// Software\Microsoft\Windows\CurrentVersion\Run
       // xor		word ptr [ebp+eax*2+var_5C], 14h
	// inc		eax
	// cmp     	eax, 14h
       // Loop to decode a static string. It reveals the "1a53b0cp32e46g0qio9" static string sent in the beacon
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        // call; fstp st
        // hiding string
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/
		/* WIDE: ProductName 1433 */
		/* WIDE: ProductVersion 1,4,3,3 */
        //check for MZ Signature at offset 0
        //check for dubrute specific strings
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-15
	Identifier: Exe2hex
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
        //$keylogger1 = /\<%s UTC %s\|%d\|%s\>/ wide ascii
        //$keylogger2 = /1201[0-9A-F]{8}\.dat/ wide ascii
        //$keylogger1 = /\<%s UTC %s\|%d\|%s\>/ wide ascii
        //$keylogger2 = /1201[0-9A-F]{8}\.dat/ wide ascii
        //$skyperec3 = /(1411|1421|1431|1451)[0-9A-F]{8}\.dat/ wide ascii
        //$mouserec1 = /(m)sc183Q000\.dat/ wide ascii
        //$mouserec2 = /2201[0-9A-F]{8}\.dat/ wide ascii
        //$versions1 = /(f)inspyv2/ nocase
        //$versions2 = /(f)inspyv4/ nocase
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-05
	Identifier: Powerkatz
*/
/* 		Yara rule to detect ELF Linux process injector toolkit "mandibule" generic.
   		name: TOOLKIT_Mandibule.yar analyzed by unixfreaxjp. 
		result:
		TOOLKIT_Mandibule ./mandibule//mandibule-dynx86-stripped
		TOOLKIT_Mandibule ./mandibule//mandibule-dynx86-UNstripped
		TOOLKIT_Mandibule ./mandibule//mandibule-dun64-UNstripped
		TOOLKIT_Mandibule ./mandibule//mandibule-dyn64-stripped

   		This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   		and  open to any user or organization, as long as you use it under this license.
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
//    $errormsg = "The version of this file is not compatible with the version of Windows you're running." wide ascii
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*

   THOR APT Scanner - Hack Tool Extract
   This rulset is a subset of all hack tool rules included in our
   APT Scanner THOR - the full featured APT scanner.

   We will frequently update this file with new rules rated TLP:WHITE

   Florian Roth
   BSK Consulting GmbH
   Web: bsk-consulting.de

   revision: 20150510

   License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
	Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/

*/
/* WCE */
/* pwdump/fgdump */
/* Disclosed hack tool set */
/* Other dumper and custom hack tools */
/* Mimikatz */
        //check for MZ Signature at offset 0
        //check for wineggdrop specific strings
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
rule Win_Adware_Multiplug_3
{
strings:
	$a0 = { 00000000 }

	$a1 = { 00376232323730373536323663363937333638363537323232336132303232 }


condition:
	$a0 and $a1
}
*/
/*
rule Win_Trojan_Sality_1056
{
strings:
	$a0 = { ebea }

	$a1 = { 6a0168 }

	$a2 = { 6a0068 }

	$a3 = { 8b5508c6420402a1 }

	$a4 = { 5168 }

	$a5 = { 010083c40c }

	$a6 = { 51e8 }

	$a7 = { eb05 }

	$a8 = { 8b45c48b48 }

	$a9 = { 3b48 }

	$a10 = { 8945c4 }

	$a11 = { 08000000eb1c }

	$a12 = { 837dc8020f8d16010000 }

	$a13 = { 837dc800756d }

	$a14 = { 7312 }

	$a15 = { 8945c4 }

	$a16 = { 8b42 }

	$a17 = { 51e8 }

	$a18 = { 000083c40c8b15 }

	$a19 = { 8995 }

	$a20 = { 8945 }

	$a21 = { feffff030f85 }

	$a22 = { 8985 }

	$a23 = { feffff0074 }

	$a24 = { 83bd }

	$a25 = { feffff00751d }

	$a26 = { feffff }

	$a27 = { 83bd }

	$a28 = { c785 }

	$a29 = { feffff508b8d }

	$a30 = { 2b45 }

	$a31 = { ff15 }

	$a32 = { 00008b0d }

	$a33 = { 518b55fc52ff15 }

	$a34 = { ff15 }

	$a35 = { ff15 }

	$a36 = { ff15 }

	$a37 = { ff15 }

	$a38 = { 6a0bff15 }

	$a39 = { 837d }

	$a40 = { 0075 }

	$a41 = { 00008985 }

	$a42 = { ffff }

	$a43 = { ffff }

	$a44 = { ffff }

	$a45 = { 558bec }

	$a46 = { 52a1 }

	$a47 = { 518b15 }

	$a48 = { ff15 }

	$a49 = { 8b15 }

	$a50 = { ff15 }

	$a51 = { 8bf0e8 }

	$a52 = { 5e5dc3 }

	$a53 = { 744f }

	$a54 = { 833d }

	$a55 = { 7510 }

	$a56 = { 0000 }

	$a57 = { ffff00000000c785 }

	$a58 = { c645 }

	$a59 = { fbffff00000000c645 }

	$a60 = { fbffff }

	$a61 = { f3ab }

	$a62 = { ffff0000 }

	$a63 = { ffff3b }

	$a64 = { 7312 }

	$a65 = { 8b85 }

	$a66 = { ffff }

	$a67 = { 038d }

	$a68 = { 8b95 }

	$a69 = { c745 }

	$a70 = { ffff03 }

	$a71 = { ffff89 }

	$a72 = { c785 }

	$a73 = { ffffeb10 }

	$a74 = { 03c8898d }

	$a75 = { 8b95 }

	$a76 = { ffff8995 }

	$a77 = { 8b85 }

	$a78 = { ffff }

	$a79 = { 8b8d }

	$a80 = { ffff }

	$a81 = { c785 }

	$a82 = { 8b8d }

	$a83 = { c785 }

	$a84 = { ffff }

	$a85 = { ffff }

	$a86 = { ff15 }

	$a87 = { ff15 }

	$a88 = { ff15 }

	$a89 = { f4faffff }

	$a90 = { 83bd }

	$a91 = { 000052ff15 }

	$a92 = { 50ff15 }

	$a93 = { ffff83c4 }

	$a94 = { 50ff15 }

	$a95 = { 000000 }

	$a96 = { 148b }

	$a97 = { 1085 }

	$a98 = { 2c83 }

	$a99 = { 1483 }

	$a100 = { ff15 }

	$a101 = { fbffff8b }

	$a102 = { ff15 }

	$a103 = { ff15 }

	$a104 = { 1483 }

	$a105 = { 85c07418 }

	$a106 = { 08c6 }

	$a107 = { ff15 }

	$a108 = { 33c0 }

	$a109 = { 50a1 }

	$a110 = { 50ff15 }

	$a111 = { 508b0d }

	$a112 = { 51e8 }

	$a113 = { 6a01e8 }

	$a114 = { 6a00e8 }

	$a115 = { 5168 }

	$a116 = { ff15 }

	$a117 = { ff15 }

	$a118 = { 5f8be55dc3 }

	$a119 = { ff15 }

	$a120 = { ff15 }

	$a121 = { 85c0742c }

	$a122 = { 85c0750c }

	$a123 = { 50ff15 }

	$a124 = { eb14 }

	$a125 = { 8985c4fdffffff15 }

	$a126 = { 8be55dc3 }

	$a127 = { 558bec6aff68 }

	$a128 = { 837dec007533 }

	$a129 = { 33c0 }

	$a130 = { 5dc3 }

	$a131 = { 8be55dc3 }

	$a132 = { 5dc3 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9 and $a10 and $a11 and $a12 and $a13 and $a14 and $a15 and $a16 and $a17 and $a18 and $a19 and $a20 and $a21 and $a22 and $a23 and $a24 and $a25 and $a26 and $a27 and $a28 and $a29 and $a30 and $a31 and $a32 and $a33 and $a34 and $a35 and $a36 and $a37 and $a38 and $a39 and $a40 and $a41 and $a42 and $a43 and $a44 and $a45 and $a46 and $a47 and $a48 and $a49 and $a50 and $a51 and $a52 and $a53 and $a54 and $a55 and $a56 and $a57 and $a58 and $a59 and $a60 and $a61 and $a62 and $a63 and $a64 and $a65 and $a66 and $a67 and $a68 and $a69 and $a70 and $a71 and $a72 and $a73 and $a74 and $a75 and $a76 and $a77 and $a78 and $a79 and $a80 and $a81 and $a82 and $a83 and $a84 and $a85 and $a86 and $a87 and $a88 and $a89 and $a90 and $a91 and $a92 and $a93 and $a94 and $a95 and $a96 and $a97 and $a98 and $a99 and $a100 and $a101 and $a102 and $a103 and $a104 and $a105 and $a106 and $a107 and $a108 and $a109 and $a110 and $a111 and $a112 and $a113 and $a114 and $a115 and $a116 and $a117 and $a118 and $a119 and $a120 and $a121 and $a122 and $a123 and $a124 and $a125 and $a126 and $a127 and $a128 and $a129 and $a130 and $a131 and $a132
}
*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
/*
rule Big_Numbers0
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 20:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{20}/ fullword ascii
	condition:
		$c0
}

rule Big_Numbers1
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 32:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{32}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers2
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 48:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{48}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers3
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 64:sized"
		date = "2016-07"
	strings:
        	$c0 = /[0-9a-fA-F]{64}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers4
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 128:sized"
		date = "2016-08"
	strings:
        	$c0 = /[0-9a-fA-F]{128}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers5
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 256:sized"
		date = "2016-08"
	strings:
        	$c0 = /[0-9a-fA-F]{256}/ fullword wide ascii
	condition:
		$c0
}
*/
		// Init constants
		// Round 2
		//added by _pusher_ 2016-07 - last round
		//needs improvement
/* //gives many false positives sorry Storm Shadow
rule x509_public_key_infrastructure_cert
{	meta:
		desc = "X.509 PKI Certificate"
		ext = "crt"
	strings:
		$c0 = { 30 82 ?? ?? 30 82 ?? ?? }
	condition: 
		$c0
}

rule pkcs8_private_key_information_syntax_standard
{	meta:
		desc = "Found PKCS #8: Private-Key"
		ext = "key"
	strings: 
		$c0 = { 30 82 ?? ?? 02 01 00 }
	condition:
		$c0
}
*/
		//x64 rad
		//x64 rad
		//newer delphi
		//x64
		//x64 rad
		//x64 rad
		//x64 rad
		//x64
        /*

        7F454C4602010100000000000000000002003E0001000000101A4000000000004000000000000000608C0000000000000000000040003800080040001D001A000600000005000000400000000000000040004000000000004000400000000000C001000000000000C001000000000000080000000000000003000000040000000002000000000000000240000000000000024000000000001C000000000000001C0000000000000001000000000000000100000005000000000000000000000000004000000000000000400000000000E476000000000000E476000000000000000020000000000001000000060000000080000000000000008060000000000000806000000000003808000000000000800C00000000000000002000000000000200000006000000288000000000000028806000000000002880600000000000A001000000000000A001000000000000080000000000000004000000040000001C020000000000001C024000000000001C0240000000000020000000000000002000000000000000040000000000000050E57464040000009C6D0000000000009C6D4000000000009C6D400000000000DC01000000000000DC01000000000000040000000000000051E57464060000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000002F6C696236342F6C642D6C696E75782D7838362D36342E736F2E3200040000001000000001000000474E5500000000000200000006000000090000000000000002000000500000000100000006000000000000000200002000000000500000007DF85A5800000000000000000000000000000000000000000000000000000000150100001200000000000000000000004101000000000000820100001200000000000000000000002500000000000000A301000012000000000000000000000025000000000000005300000012000000000000000000000062000000000000006A0100001200000000000000000000001B0B0000000000007E0200001200000000000000000000008B00000000000000490200001200000000000000000000002500000000000000BD0100001200000000000000000000006C00000000000000590000001200000000000000000000008E00000000000000F4010000120000000000000000000000250000000000000088010000120000000000000000000000F200000000000000FA010000120000000000000000000000A9010000000000000100000020000000000000000000000000000000000000001000000020000000000000000000000000000000000000005002000012000000000000000000000025000000000000007C010000120000000000000000000000EE00000000000000D20000001200000000000000000000000800000000000000230100001200000000000000000000009700000000000000CD000000120000000000000000000000F100000000000000170200001200000000000000000000008000000000000000CE010000120000000000000000000000240200000000000066020000120000000000000000000000A501000000000000710100001200000000000000000000002500000000000000C301000012000000000000000000000028000000000000009B010000120000000000000000000000E700000000000000380100001200000000000000000000003300000000000000E80000001200000000000000000000002901000000000000870200001200000000000000000000008A010000000000003D000000120000000000000000000000340C000000000000EC01000012000000000000000000000043000000000000004B01000012000000000000000000000025000000000000001C0100001200000000000000000000002500000000000000DC010000120000000000000000000000AB0400000000000078020000120000000000000000000000080000000000000043020000120000000000000000000000B9010000000000008C0000001200000000000000000000000A000000000000003F01000012000000000000000000000025000000000000005F020000120000000000000000000000F000000000000000D5010000120000000000000000000000BC010000000000002F020000120000000000000000000000EC01000000000000900100001200000000000000000000002800000000000000840000001200000000000000000000008000000000000000080200001200000000000000000000002700000000000000560200001200000000000000000000007401000000000000BF0000001200000000000000000000002500000000000000160200001200000000000000000000004601000000000000FA00000012000000000000000000000087000000000000005E0000001200000000000000000000001100000000000000A801000012000000000000000000000044000000000000001C0200001200000000000000000000005A00000000000000040100001200000000000000000000002901000000000000C6000000120000000000000000000000DC0000000000000044010000120000000000000000000000F100000000000000D80000001200000000000000000000006C00000000000000A00000001200000000000000000000005200000000000000BC0100001200000000000000000000000602000000000000E5010000120000000000000000000000340000000000000034000000120000000000000000000000A1000000000000000D010000120000000000000000000000A6000000000000008C0200001200000000000000000000004B00000000000000F10000001200000000000000000000002A000000000000006F00000012000000000000000000000005000000000000005E010000120000000000000000000000310000000000000074000000120000000000000000000000FF000000000000005E02000012000000000000000000000007000000000000004C000000120000000000000000000000A1000000000000007701000012000000000000000000000025000000000000000F0200001200000000000000000000006301000000000000DE0000001200000000000000000000007B01000000000000300100001200000000000000000000007504000000000000D90000001200000000000000000000000E00000000000000250200001200000000000000000000001100000000000000100200001200000000000000000000008000000000000000990000001200000000000000000000008000000000000000AF000000120000000000000000000000C20000000000000039020000120000000000000000000000C0000000000000002A01000012000000000000000000000025000000000000008B0100001200000000000000000000001200000000000000B20100001200000000000000000000006501000000000000520100001200000020174000000000001300000000000000005F5F676D6F6E5F73746172745F5F005F4A765F5265676973746572436C6173736573006C6962707468726561642E736F2E30007265637666726F6D00707468726561645F6372656174650073656E64746F0070617573650077616974005F5F6572726E6F5F6C6F636174696F6E00666F726B00707468726561645F7369676D61736B00636F6E6E65637400707468726561645F73656C660061636365707400707468726561645F6465746163680066636E746C006C6962632E736F2E3600736F636B65740073747263707900657869740068746F6E73007372616E6400696E65745F61746F6E00676574707775696400636C6F736564697200696E65745F6E746F61006765746772676964007374726E637079006461656D6F6E006C697374656E0073656C656374006D6B646972007265616C6C6F6300676574706964006B696C6C00737472746F6B006C63686F776E00616C706861736F7274363400736967656D707479736574006D656D73657400726D6469720062696E6400667365656B0063686469720061736374696D6500676574736F636B6F7074006772616E74707400647570320073696761646473657400696E65745F616464720066636C6F736500736574736F636B6F7074006D616C6C6F6300737472636174007265616C706174680072656D6F7665006F70656E64697200696F63746C00676574686F737462796E616D65006578656376650066777269746500667265616400756E6C6F636B7074006C6F63616C74696D65007363616E64697236340072656164646972363400736C6565700073657473696400756E616D65006D656D6D6F766500666F70656E3634005F5F6C6962635F73746172745F6D61696E006E746F687300736E7072696E74660066726565005F5F7873746174363400474C4942435F322E322E3500474C4942435F322E3300000002000200020003000200020002000300030002000200020000000000020002000200020002000300020002000200020002000200020002000300020002000200040002000200030002000300020002000200030002000200020002000200030002000200020002000200020003000200020003000200020002000300020003000200030002000200020002000200020003000300030002000200020002000200000001000100240000001000000020000000751A690900000300960200000000000001000200B500000010000000000000001369690D00000400A202000010000000751A6909000002009602000000000000C881600000000000060000000D0000000000000000000000E88160000000000007000000010000000000000000000000F08160000000000007000000020000000000000000000000F881600000000000070000000300000000000000000000000082600000000000070000000400000000000000000000000882600000000000070000000500000000000000000000001082600000000000070000000600000000000000000000001882600000000000070000000700000000000000000000002082600000000000070000000800000000000000000000002882600000000000070000000900000000000000000000003082600000000000070000000A00000000000000000000003882600000000000070000000B00000000000000000000004082600000000000070000000C00000000000000000000004882600000000000070000000F00000000000000000000005082600000000000070000001000000000000000000000005882600000000000070000001100000000000000000000006082600000000000070000001200000000000000000000006882600000000000070000001300000000000000000000007082600000000000070000001400
        
        */
        /*

        7F454C4602010103000000000000000002003E000100000000044000000000004000000000000000888C0D000000000000000000400038000500400021001E0001000000050000000000000000000000000040000000000000004000000000007E750D00000000007E750D00000000000000200000000000010000000600000080750D000000000080756D000000000080756D0000000000F012000000000000B09000000000000000002000000000000400000004000000580100000000000058014000000000005801400000000000440000000000000044000000000000000400000000000000070000000400000080750D000000000080756D000000000080756D000000000028000000000000007000000000000000080000000000000051E5746406000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000040000001000000001000000474E550000000000020000000600000012000000040000001400000003000000474E550005E7FAD31BCC78E6781883BB297455DC9ECB371F0000000080766D00000000002500000000000000F07E46000000000088766D00000000002500000000000000506742000000000090766D00000000002500000000000000B0A442000000000098766D00000000002500000000000000903F490000000000A0766D00000000002500000000000000909A420000000000A8766D0000000000250000000000000070D5420000000000B0766D000000000025000000000000007074420000000000B8766D000000000025000000000000009085420000000000C0766D00000000002500000000000000108B460000000000C8766D00000000002500000000000000608B420000000000D0766D000000000025000000000000003044420000000000D8766D00000000002500000000000000503F490000000000E0766D00000000002500000000000000508B460000000000E8766D00000000002500000000000000D0424200000000004883EC08E833010000E8D2010000E83D6A0A004883C408C3FF2572732D006800000000E900000000FF256A732D006800000000E900000000FF2562732D006800000000E900000000FF255A732D006800000000E900000000FF2552732D006800000000E900000000FF254A732D006800000000E900000000FF2542732D006800000000E900000000FF253A732D006800000000E900000000FF2532732D006800000000E900000000FF252A732D006800000000E900000000FF2522732D006800000000E900000000FF251A732D006800000000E900000000FF2512732D006800000000E900000000FF250A732D006800000000E90000000000000000000000000000000000000000000000000000000031ED4989D15E4889E24883E4F0505449C7C08016410048C7C1C016410048C7C7532F4000E827090100F490904883EC08488B0529722D004885C07402FFD04883C408C390909090909090909090909090554889E5534883EC08803D20842D0000755FBBD0756D00488B051A842D004881EBC0756D0048C1FB034883EB014839D87324660F1F4400004883C001488905F5832D00FF14C5C0756D00488B05E7832D004839D872E2B8E0614A004885C0740ABF98334C00E8265D0A00C605BF832D00014883C4085BC9C30F1F84000000000055B8C0474A004885C04889E5740FBEA0886D00BF98334C00E8D3420A0048833DE3702D00007419B8000000004885C0740FBFD8756D00C9FFE00F1F8000000000C9C39090554889E5534881ECF820000089BD2CDFFFFF48C745C8000000008B45143D001000000F871B0200008B451489C2488D8DC0EFFFFF8B852CDFFFFF4889CE89C7E88F43000085C00F84FA0100008B451489C2488D85C0EFFFFF89D64889C7E8CA030000BA908B4A00488D85C0EFFFFF4889D64889C7E8D3450100488945C848837DC8000F84C1010000488D85C0EFFFFF488D9530DFFFFF4889D64889C7E83B21030085C00F857C010000488B8560DFFFFF488945E0C7451400000000488B45E0894524488B45E048C1F820894520488B451048890424488B45184889442408488B45204889442410E80D550000894510BE18000000488D7D10E82F030000488D4D108B852CDFFFFFBA180000004889CE89C7E80745000085C00F840A010000488D4D108B852CDFFFFFBA180000004889CE89C7E89C42000085C00F84EC000000BE18000000488D7D10E8DF0200008B5D10488B451048890424488B45184889442408488B45204889442410E88A54000039C30F85B70000008B452089C04889C248C1E2208B452489C0488D0402488945E8488B4DE8488B45C8BA000000004889CE4889C7E8D4620100488B45E8488945D8EB67488B55C8488D85C0DFFFFF4889D1BA00100000BE010000004889C7E86A4501008945D4837DD4007E568B55D4488D85C0DFFFFF89D64889C7E83D0200008B45D44863D0488D8DC0DFFFFF8B852CDFFFFF4889CE89C7E81144000085C074248B45D44898480145D8488B45D8483B45E07C8FEB1090EB0D90EB0A90EB0790EB0490EB0190488B45C84889C7E83B3D0100EB0790EB0490EB0190B8000000004881C4F82000005BC9C3554889E5534881ECF80100004889BD28FEFFFFE89B8000004889C7E8A37C0000C745E0FFFFFFFF488B8528FEFFFF8B40088945E4488B8528FEFFFF8B008945E8488B8528FEFFFF8B40048945EC8B4DEC8B45E8BA0A00000089CE89C7E85B3C00008945E0837DE0FF0F843E010000488D45C0BA18000000BE000000004889C7E8A7FBFFFFC745CC00000000C745C4860100008B45E48945C8488B45C048890424488B45C84889442408488B45D04889442410E8E95200008945C0488D45C0BE180000004889C7E808010000488D4DC08B45E0BA180000004889CE89C7E8E342000085C00F84C6000000488D8530FEFFFF4889C7E81B180300488D8530FEFFFFBE860100004889C7E8C7000000488D8D30FEFFFF8B45E0BA860100004889CE89C7E89F42000085C00F8485000000488D4DC08B45E0BA180000004889CE89C7E83740000085C0746E488D45C0BE180000004889C7E87B0000008B5DC0488B45C048890424488B45C84889442408488B45D04889442410E82652000039C3753A8B45CC83F80375338B45E0488B55C048891424488B55C84889542408488B55D0488954241089C7E8FDFBFFFFEB0D90EB0A90EB0790EB0490EB01908B45E089C7E860DE0000B8000000004881C4F80100005BC9C390554889E548897DE88975E4C745FC10000000488B45E8488945F0C745F800000000EB30488B45F00FB6088B45F889C2C1FA1FF77DFC89D048980FB68010776D0089CA31C2488B45F088108345F801488345F0018B45F83B45E47CC8488B45E8C9C3554889E548897DE88975E4488B45E8488945F0C745FC00000000EB1F488B45F00FB6100FB605456D2D0031C2488B45F088108345FC01488345F0018B45FC3B45E47CD9488B45E8C9C39090554889E5534881EC0841000089BD1CBFFFFF48C745B80000000048C745C00000000048C745C8000000008B451489C2488D8DB0EFFFFF8B851CBFFFFF4889CE89C7E8B53E000085C00F845B0300008B451489C2488D85B0EFFFFF89D64889C7E8F0FEFFFF488D85B0EFFFFF488D95B0DFFFFF4889D64889C7E8372E0100BA988B4A00488D8DB0DFFFFF488D85B0CFFFFFBE001000004889C7B800000000E892340100488D85B0CFFFFF4889C7E8F36802004883C0014889C7E8670A0200488945B848837DB8000F84E0020000488D95B0CFFFFF488B45B84889D64889C7E84AF8FFFF488D85B0DFFFFF488D5DB0B9D01F4300BA000000004889DE4889C7E8B21203008945D4837DD4000F8E8C020000C745D800000000E969010000488B45B08B55D84863D248C1E2034801D0488B00488D5813BADB8B4A00488D8DB0DFFFFF488D85B0BFFFFF4989D8BE001000004889C7B800000000E8D9330100488D85B0BFFFFF488D9520BFFFFF4889D64889C7E8901B030085C00F850401000048C745C020776D0048C745C820776D00488D8520BFFFFF4883C0584889C7E815E202004889C7E81DE00200488B8D50BFFFFF8B9538BFFFFF4189D04181E0FF0100008B9538BFFFFF89D781E700F00000488B55B08B5DD84863DB48C1E3034801DA488B12488D7213BAE88B4A00488D9DB0CFFFFF488944241848894C2410488B45C84889442408488B45C0488904244589C14189F84889F1BE001000004889DF

        */
        /*

        7F454C4602010103000000000000000002003E000100000000044000000000004000000000000000B0BA3A0000000000000000004000380005004000270024000100000005000000000000000000000000004000000000000000400000000000BAA40C0000000000BAA40C000000000000002000000000000100000006000000C0A40C0000000000C0A46C0000000000C0A46C000000000050130000000000008890000000000000000020000000000004000000040000005801000000000000580140000000000058014000000000002000000000000000200000000000000004000000000000000700000004000000C0A40C0000000000C0A46C0000000000C0A46C000000000028000000000000007800000000000000080000000000000051E5746406000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000040000001000000001000000474E550000000000020000000400000000000000C0A56C00000000002500000000000000E084420000000000C8A56C00000000002500000000000000D037420000000000D0A56C000000000025000000000000008073420000000000D8A56C0000000000250000000000000050DA420000000000E0A56C00000000002500000000000000F024480000000000E8A56C00000000002500000000000000A084420000000000F0A56C00000000002500000000000000F083430000000000F8A56C00000000002500000000000000305E42000000000000A66C00000000002500000000000000506F42000000000008A66C00000000002500000000000000109142000000000010A66C00000000002500000000000000707542000000000018A66C00000000002500000000000000B01442000000000020A66C00000000002500000000000000B02448000000000028A66C00000000002500000000000000509142000000000030A66C0000000000250000000000000050134200000000004883EC08E843010000E862020000E84D9409004883C408C3FF25C2A22C006800000000E900000000FF25BAA22C006800000000E900000000FF25B2A22C006800000000E900000000FF25AAA22C006800000000E900000000FF25A2A22C006800000000E900000000FF259AA22C006800000000E900000000FF2592A22C006800000000E900000000FF258AA22C006800000000E900000000FF2582A22C006800000000E900000000FF257AA22C006800000000E900000000FF2572A22C006800000000E900000000FF256AA22C006800000000E900000000FF2562A22C006800000000E900000000FF255AA22C006800000000E900000000FF2552A22C006800000000E90000000000000000000000000000000000000000000000000000000031ED4989D15E4889E24883E4F0505449C7C0C0BC400048C7C100BD400048C7C7D02E4000E8A7B20000F490904883EC08488B0569A12C004885C07402FFD04883C408C390909090909090909090909090B817B86C0055482D10B86C004883F80E4889E5761BB8000000004885C074115DBF10B86C00FFE0660F1F8400000000005DC366666666662E0F1F840000000000BE10B86C00554881EE10B86C0048C1FE034889E54889F048C1E83F4801C648D1FE7415B8000000004885C0740B5DBF10B86C00FFE00F1F005DC3660F1F440000803D69B32C00007573554889E553BB10A56C004881EB00A56C004883EC08488B0553B32C0048C1FB034883EB014839D87324660F1F4400004883C00148890535B32C00FF14C500A56C00488B0527B32C004839D872E2E825FFFFFFB8708E49004885C0740ABFB8904B00E831890900C605FAB22C00014883C4085B5DF3C3669055B8508B49004885C04889E5740FBE60B86C00BFB8904B00E8E3850900BF18A56C0048833F0075085DE912FFFFFF6690B8000000004885C074EEFFD0EBEA9090554889E5534881ECD820000089BD2CDFFFFF48C745E0000000008B45143D001000007605E9F50100008B451489C2488D8DC0EFFFFF8B852CDFFFFF4889CE89C7E8C941000085C07505E9D00100008B451489C2488D85C0EFFFFF89D64889C7E870030000488D85C0EFFFFFBE24A549004889C7E828320100488945E048837DE0007505E996010000488D9530DFFFFF488D85C0EFFFFF4889D64889C7E82FCD030085C07405E968010000488B8560DFFFFF488945D8C7451400000000488B45D8894524488B45D848C1F8208945204883EC08FF7520FF7518FF7510E8585200004883C420894510BE18000000488D7D10E8DF0200008B852CDFFFFFBA18000000488D751089C7E82843000085C07505E9FE0000008B852CDFFFFFBA18000000488D751089C7E8E440000085C07505E9DF000000BE18000000488D7D10E8930200008B5D104883EC08FF7520FF7518FF7510E8E25100004883C42039C37405E9AF0000008B452089C048C1E0204889C28B452489C04801D0488945D0488B4DD0488B45E0BA000000004889CE4889C7E8AD4A0100488B45D0488945E8EB6B488B55E0488D85C0DFFFFF4889D1BA00100000BE010000004889C7E8F33001008945CC837DCC007F02EB4A8B55CC488D85C0DFFFFF89D64889C7E8F80100008B45CC4863D0488D8DC0DFFFFF8B852CDFFFFF4889CE89C7E83A42000085C07502EB138B45CC4898480145E8488B45E8483B45D87C8B488B45E04889C7E842270100B800000000488B5DF8C9C3554889E5534881ECD80100004889BD28FEFFFFE8BF7F00004889C7E8677F0000C745ECFFFFFFFF488B8528FEFFFF8B40088945E8488B8528FEFFFF8B008945E4488B8528FEFFFF8B40048945E08B4DE08B45E4BA0A00000089CE89C7E8063B00008945EC837DECFF7505E927010000488D45C0BA18000000BE000000004889C7E85AFBFFFFC745CC00000000C745C4860100008B45E88945C84883EC08FF75D0FF75C8FF75C0E8645000004883C4208945C0488D45C0BE180000004889C7E8E8000000488D4DC08B45ECBA180000004889CE89C7E83141000085C07505E9B4000000488D8530FEFFFF4889C7E8F6BD0300488D8530FEFFFFBE860100004889C7E8A6000000488D8D30FEFFFF8B45ECBA860100004889CE89C7E8EC40000085C07502EB72488D4DC08B45ECBA180000004889CE89C7E8AB3E000085C07502EB56488D45C0BE180000004889C7E85A0000008B5DC04883EC08FF75D0FF75C8FF75C0E8A94F00004883C42039C37402EB268B45CC83F8037402EB1C8B45EC4883EC08FF75D0FF75C8FF75C089C7E846FCFFFF4883C420908B45EC89C7E8C79A0000B800000000488B5DF8C9C3554889E548897DE88975E4C745F010000000488B45E8488945F8C745F400000000EB2C488B45F80FB6088B45F499F77DF089D048980FB68050A66C0031C189CA488B45F888108345F401488345F8018B45F43B45E47CCC488B45E85DC3554889E548897DE88975E4488B45E8488945F8C745F400000000EB1F488B45F80FB6100FB605659C2C0031C2488B45F888108345F401488345F8018B45F43B45E47CD9488B45E85DC39090554889E5534881ECD840000089BD2CBFFFFF48C745E80000000048C745D80000000048C745D0000000008B451489C2488D8DC0EFFFFF8B852CBFFFFF4889CE89C7E84C3D000085C07505E9400300008B451489C2488D85C0EFFFFF89D64889C7E8F3FEFFFF488D95C0DFFFFF488D85C0EFFFFF4889D64889C7E896180100488D95C0DFFFFF488D85C0CFFFFF4889D1BA28A54900BE001000004889C7B800000000E86E1F0100488D85C0CFFFFF4889C7E83F3A02004883C0014889C7E863E80100488945E848837DE8007505E9BE020000488D95C0CFFFFF488B45E84889D64889C7E815F8FFFF488D75C0488D85C0DFFFFFB980C44300BA000000004889C7E830B703008945CC837DCC000F8E72020000C745E400000000E95A010000488B45C08B55E44863D248C1E2034801D0488B00488D4813488D95C0DFFFFF488D85C0BFFFFF4989C84889D1BA6BA54900BE001000004889C7B800000000E8B41E0100488D9530BFFFFF488D85C0BFFFFF4889D64889C7E8DBC7030085C00F85F200000048C745D860A66C0048C745D060A66C00488D8530BFFFFF4883C0584889C7E8C08C03004889C7E8988C03004989C0488B9560BFFFFF8B8548BFFFFF25FF01000089C78B8548BFFFFF2500F0000089C6488B45C08B4DE44863C948C1E1034801C8488B00488D4813488D85C0CFFFFF415052FF75D0FF75D84189F94189F0BA78A54900BE001000004889C7B800000000E8FF1D01004883C420488B45E84889C7E8CF3802004889C3488D85C0CFFFFF

        */
        /*

        7F454C4602010100000000000000000001003E000100000000000000000000000000000000000000A82803000000000000000000400000000000400031002E00040000001400000003000000474E5500089FECFBE5E7F9736AEBF52A0D3FF3394571C0BD000000000000000000000000554889E553E800000000FF1425000000004889C74889C34881E7FFFFFEFFFF1425000000004889D85BC9C30F1F440000554889E5E800000000FF142500000000C9C366666666662E0F1F840000000000554889E5E8000000004885FF74524C8B47184D85C0744965488B0425000000008B80A80400004889150000000048C7C20000000089C1C1F91FC1E91601C825FF03000029C848984C8904C500000000FF1500000000C9C3660F1F84000000000031C0C9C36666662E0F1F840000000000554889E5E8000000004889150000000048C7C200000000FF1500000000C9C390554889E5E8000000008B96C0000000488B8ED0000000488D14110FB642093C06400F94C73C11410F94C174144084FF750FB801000000C9C30F1F8400000000008B050000000039420C74253B421074204584C9742B8B86BC0000004801C10FB705000000006639017406663B410275C14889F741FFD0B802000000C9C30F1F004084FF74AC8B86BC0000004801C10FB7050000000066390175D0EBD40F1F4000554889E5534883EC08E80000000031D24889F331F6E800000000483D00F0FFFF772F4885DB7417488B5018488B5210488B52E8488B525848899AF800000031F64889C7E80000000031C04883C4085BC9C383C8FFEBF4662E0F1F840000000000554889E5415453E8000000004989F44889D331F631D2E800000000483D00F0FFFF7733488B501831F64889C7488B5210488B52E8488B5258488B8AF800000049890C2448899AF8000000E80000000031C05B415CC9C383C8FFEBF60F1F440000554889E5534883EC08E80000000031D24889F331F6E800000000483D00F0FFFF772F4885DB7417488B5018488B5210488B52E8488B525848899A0001000031F64889C7E80000000031C04883C4085BC9C383C8FFEBF4662E0F1F840000000000554889E5415453E8000000004989F44889D331F631D2E800000000483D00F0FFFF7733488B501831F64889C7488B5210488B52E8488B5258488B8A0001000049890C2448899A00010000E80000000031C05B415CC9C383C8FFEBF60F1F440000554889E5534883EC08E80000000031D24889F3BE00000100E800000000483D00F0FFFF77204885DB7408488B502048895A3031F64889C7E80000000031C04883C4085BC9C383C8FFEBF4660F1F440000554889E5415453E8000000004989F44889D3BE0000010031D2E800000000483D00F0FFFF7725488B502031F64889C7488B523049891424488B502048895A30E80000000031C05B415CC9C383C8FFEBF6554889E54157415641554154534883EC28E8000000004889F3488D75C84989FF4189D54889DFBA0A0000004989CC44894DB84D89C6E800000000488B1500000000448B4DB84881FA00000000488D4AF87517EB340F1F4000488B51084881FA00000000488D4AF8741F0FB752F84839D075E64883C42831C05B415C415D415E415FC9C30F1F4400004D89F04C89E14489EA4889DE4C89FFFF15000000004883C4285B415C415D415E415FC9C30F1F4000554889E54157415641554154534883EC38E80000000065488B04250000000048897DB848894DB04189D48B80A80400004889F3B90200000048C7C6000000004889DF4D89C54589CE89C2C1FA1FC1EA1601D025FF03000029D0F3A648984C8B3CC5000000000F84D5000000B90300000048C7C6000000004889DFF3A60F84BE00000031F64585E44889D848895DC8448965C47431418D5424FF31F6488D7C13010FB6084883C0014889CA48C1E10448C1EA044801CA4801F24839F8488D0C92488D344A75DB8975C0488D75C04C89FFE8000000004885C04889C10F84A1000000488B41104885C07446817854FFCB00F10F847A000000488B0500000000483D000000004C8D78F87517EB350F1F440000498B4708483D000000004C8D78F87420498B374889DFE80000000085C075E131C04883C4385B415C415D415E415FC9C34589F14D89E8488B4DB04489E24889DE488B7DB8FF15000000004883C4385B415C415D415E415FC9C30F1F8000000000817850852DB6950F8579FFFFFF31C0EBB0488D75C04C89FFE8000000004885C04889C1749A498B7F10488B87F8000000488B40084885C0748631D24889CE48894DA8FFD04885C0488B4DA80F841FFFFFFF31C0E969FFFFFF0F1F840000000000554889E5534883EC08E80000000089FA488B3D000000004881FF00000000488D5FF87425663957F8750CEB240F1F4000663950F8741A488B4308483D00000000488D58F84889C775E74883C4085BC9C3E8000000004889DFE8000000004883C4085BC9C36666662E0F1F840000000000554889E5534883EC08E80000000089FA488B3D000000004881FF00000000488D5FF87425663957F8750CEB240F1F4000663950F8741A488B4308483D00000000488D58F84889C775E74883C4085BC9C3E8000000004889DFE8000000004883C4085BC9C36666662E0F1F840000000000554889E5534883EC08E80000000089FA488B3D000000004881FF00000000488D5FF87425663957F8750CEB240F1F4000663950F8741A488B4308483D00000000488D58F84889C775E74883C4085BC9C3E8000000004889DFE8000000004883C4085BC9C36666662E0F1F840000000000554889E5534883EC08E80000000089FA488B3D000000004881FF00000000488D5FF87425663957F8750CEB240F1F4000663950F8741A488B4308483D00000000488D58F84889C775E74883C4085BC9C3E8000000004889DFE8000000004883C4085BC9C36666662E0F1F840000000000554889E5534883EC08E80000000089FA488B3D000000004881FF00000000488D5FF87425663957F8750CEB240F1F4000663950F8741A488B4308483D00000000488D58F84889C775E74883C4085BC9C3E8000000004889DFE8000000004883C4085BC9C36666662E0F1F840000000000554889E541554154534883EC08E8000000004C8B25000000004989FD4981FC00000000498D5C24F87518EB3D0F1F40004C8B63084981FC00000000498D5C24F87427488B334C89EFE80000000085C075DF4C89E7E800000000488B3BE8000000004889DFE8000000004883C4085B415C415DC9C36666662E0F1F840000000000554889E5534883EC08E800000000488B3500000000BAD000000089FBBF18000000E8000000004885C0741A668918488B1500000000488D780848C7C600000000E8000000004883C4085BC9C30F1F4000554889E5534883EC08E800000000488B3500000000BAD000000089FBBF18000000E8000000004885C0741A668918488B1500000000488D780848C7C600000000E8000000004883C4085BC9C30F1F4000554889E5534883EC08E800000000488B3500000000BAD000000089FBBF18000000E8000000004885C0741A668918488B1500000000488D780848C7C600000000E8000000004883C4085BC9C30F1F4000554889E5534883EC08E800000000488B3500000000BAD000000089FBBF18000000E8000000004885C0741A668918488B1500000000488D780848C7C600000000E8000000004883C4085BC9C30F1F4000554889E5

        */
        /*

        7F454C4602010100000000000000000001003E00010000000000000000000000000000000000000050740900000000000000000040000000000040002B002800040000001400000003000000474E55002B4D95854AA9AB65223C6152AD3BE5EC9B4BE8F9000000000000000000000000E80000000055488915000000004889E541544989F4534889FB488B3D00000000E8000000004C89E64889DF48C7C200000000FF1500000000488B3D0000000089C3E80000000089D85B415C5DC30F1F00E80000000055488915000000004889E541544989F4534889FB488B3D00000000E8000000004C89E64889DF48C7C200000000FF1500000000488B3D0000000089C3E80000000089D85B415C5DC30F1F00E800000000554889E5415541544989FC534889F34883EC18488B3D0000000065488B042528000000488945E031C0E8000000004889DE4C89E7FF1500000000488B3D000000004189C5E800000000488B0500000000483D00000000488D58F87518EB580F1F440000488B53084881FA00000000488D5AF874420FB713488D7DD448C7C60000000031C0E800000000498B1424498B442418488D75D4488DBC026AFFFFFFBA96000000E8000000004885C074B649816C241896000000488B4DE06548330C25280000004489E8750B4883C4185B415C415D5DC3E8000000000F1F00E800000000554889E5415541544989FC534889F34883EC18488B3D0000000065488B042528000000488945E031C0E8000000004889DE4C89E7FF1500000000488B3D000000004189C5E800000000488B0500000000483D00000000488D58F87518EB580F1F440000488B53084881FA00000000488D5AF874420FB713488D7DD448C7C60000000031C0E800000000498B1424498B442418488D75D4488DBC026AFFFFFFBA96000000E8000000004885C074B649816C241896000000488B4DE06548330C25280000004489E8750B4883C4185B415C415D5DC3E8000000000F1F00E800000000554889E5415541544989FC534889F34883EC18488B3D0000000065488B042528000000488945E031C0E8000000004889DE4C89E7FF1500000000488B3D000000004189C5E800000000488B0500000000483D00000000488D58F87518EB580F1F440000488B53084881FA00000000488D5AF874420FB713488D7DD448C7C60000000031C0E800000000498B1424498B442418488D75D4488DBC026AFFFFFFBA96000000E8000000004885C074B649816C241896000000488B4DE06548330C25280000004489E8750B4883C4185B415C415D5DC3E8000000000F1F00E800000000554889E5415541544989FC534889F34883EC18488B3D0000000065488B042528000000488945E031C0E8000000004889DE4C89E7FF1500000000488B3D000000004189C5E800000000488B0500000000483D00000000488D58F87518EB580F1F440000488B53084881FA00000000488D5AF874420FB713488D7DD448C7C60000000031C0E800000000498B1424498B442418488D75D4488DBC026AFFFFFFBA96000000E8000000004885C074B649816C241896000000488B4DE06548330C25280000004489E8750B4883C4185B415C415D5DC3E8000000000F1F00E800000000554889E541574589CF415641554189D54154534889F34883EC18488B050000000048897DD048894DC84C8945C0483D000000004C8D70F874424C63E2EB150F1F440000498B4608483D000000004C8D70F87428498B364C89E24889DFE80000000085C075DE4883C4185B415C415D415E415F5DC30F1F80000000004589F94C8B45C0488B4DC84489EA4889DE488B7DD0FF15000000004883C4185B415C415D415E415F5DC3660F1F440000E800000000554889E541574589CF41564D89C641554989CD41544189D4BA0A000000534889F3488D75C84883EC1848897DC04889DF65488B042528000000488945D031C0E800000000488B0D000000004881F900000000488D51F8742E0FB749F84839C17514EB600F1F840000000000410FB74AF84839C1744E4C8B52084981FA00000000498D52F875E54589F94D89F04C89E94489E24889DE488B7DC0FF1500000000488B7DD06548333C252800000075194883C4185B415C415D415E415F5DC3660F1F44000031C0EBD8E8000000000F1F440000662E0F1F840000000000E80000000055BF820000C04889E54881EC1002000065488B042528000000488945F831C0488DB5F4FDFFFFFF142500000000B9400000004889C6488DBDF8FDFFFFF348A5488DBDF8FDFFFF48C7C200000000BE00020000B103E8000000004885C0742248BA00000000

        */
        /*

		    7F454C460101010300000000000000000200030001000000E08104083400000088250C0000000000340020000500280021001E000100000000000000008004080080040840150C0040150C0005000000001000000100000040150C0040A5100840A51008800C0000904A0000060000000010000004000000D4000000D4800408D4800408440000004400000004000000040000000700000040150C0040A5100840A510081400000030000000040000000400000051E5746400000000000000000000000000000000000000000600000004000000040000001000000001000000474E550000000000020000000600000012000000040000001400000003000000474E550069FB3ADE8762FA5297236F6B2C6C085495C9AB35B8A510082A000000BCA510082A000000C0A510082A000000C4A510082A000000C8A510082A000000CCA510082A0000005589E55383EC04E8000000005B81C358240C008B93FCFFFFFF85D27405E8967EFBF7E811010000E8CC610900585BC9C3FF25B8A510086800000000E900000000FF25BCA510086800000000E900000000FF25C0A510086800000000E900000000FF25C4A510086800000000E900000000FF25C8A510086800000000E900000000FF25CCA510086800000000E900000000000000000000000031ED5E89E183E4F050545268B055060868F0550608515668054C0508E89FCA0100F490909090909090909090909090905589E5538D6424EC803DC0B11008007553BB68A51008A1C4B1100881EB60A51008C1FB0283EB0139D8731D908D74260083C001A3C4B11008FF148560A51008A1C4B1100839D872E8B8D0D60D0885C0740CC704243C7B0F08E863540900C605C0B11008018D6424145B5DC3908D74260055B8D0BC0D0889E58D6424E8E8000000005A81C21B230C0085C074208954240CC744240800000000C7442404C8B11008C704243C7B0F08E8143A0900A16CA5100885C07412B80000000085C07409C704246CA51008FFD0C9C39090905589E583EC288B45088845F4A1E0B1100885C07415A1E0B110080FB655F4881083C001A3E0B11008EB1BC7442408010000008D45F489442404C7042400000000E85FA30100C9C35589E583EC18EB158B45080FB6000FBEC083450801890424E89CFFFFFF8B45080FB60084C075E1C9C35589E583EC488B45080FB6008845F283450801807DF2000F841C030000807DF22574110FBE45F2890424E861FFFFFFE900030000C745E8000000008B45080FB6008845F283450801807DF2307516C745E8010000008B45080FB6008845F283450801EB1A807DF22D7514C745E8020000008B45080FB6008845F283450801C745E400000000EB288B55E489D0C1E00201D001C089C20FBE45F28D040283E8308945E48B45080FB6008845F283450801807DF22F7E06807DF2397ECC807DF26C7406807DF24C7511834DE8048B45080FB6008845F283450801807DF2000F845A0200000FB645F28845F3807DF3607E0A0FB645F383E8208845F30FBE45F383E84283F8160F87CB0000008B0485ECFD0D08FFE08B450C8D500489550C8B008945F4C745E000000000EB048345E0018B45E08B55F48D04020FB60084C075ECEB0CC7042420000000E845FEFFFF8B45E883E00285C075118B45E03B45E40F92C08345E00184C075D98B45F4890424E866FEFFFFEB0CC7042420000000E811FEFFFF8B45E03B45E40F92C08345E00184C075E3E99F0100008B450C8D500489550C8B000FBEC0890424E8E5FDFFFFE984010000C745D802000000EB2CC745D808000000EB23C745D80A000000EB1AC745D810000000EB110FBE45F2890424E8B0FDFFFFE94F0100008B45E883E00485C0740D8B450C8D500489550C8B00EB1E807DF344750D8B450C8D500489550C8B00EB0B8B450C8D500489550C8B008945EC807DF344750E8B45EC85C07907F75DEC834DE808C745DC000000008B45ECBA00000000F775D889D08845F38B45ECBA00000000F775D88945EC807DF3097E1B807DF2787507B827000000EB05B8070000000FB655F301D08845F38B45DC0FB655F383C230885405C88345DC01837DEC007406837DDC0F76A38B45E883E00885C0740C8B45DCC64405C82D8345DC018B45DC8945E08B45E883E00184C07407B830000000EB05B8200000008845F3EB0C0FBE45F3890424E8B8FCFFFF8B45E883E00285C075118B45E03B45E40F92C08345E00184C075D9836DDC018B45DC0FB64405C80FBEC0890424E886FCFFFF837DDC0075E3EB0CC7042420000000E872FCFFFF8B45E03B45E40F92C08345E00184C075E3E9D2FCFFFFE9CDFCFFFF90EB0190C9C35589E583EC288D450C8945F48B45F4894424048B4508890424E8A3FCFFFFC9C35589E583EC088B55088B45108855FC8845F8C9C35589E557565381EC1C5200008B55088B4510889504AEFFFF888500AEFFFFC7853CFFFFFF00000000C78540FFFFFF000000000FB68500AEFFFFC744240C00000000C7442408150000008B551489542404890424E85D450000898544FFFFFF0FB68500AEFFFFC744240C48FE0D08C7442408140000008B551489542404890424E831450000898548FFFFFF0FB68500AEFFFFC744240C00000000C7442408080000008B551489542404890424E80545000089854CFFFFFF0FB68500AEFFFFC744240C4CFE0D08C7442408160000008B551489542404890424E8D9440000898550FFFFFF0FB68500AEFFFFC744240C01000000C7442408180000008B551489542404890424E8F9440000898554FFFFFF0FB68500AEFFFFC744240C50000000C7442408070000008B551489542404890424E8CD4400006689855AFFFFFF8D852FD7FFFFBA0128000089542408C744240400000000890424E89FF9FFFF83BD4CFFFFFF000F84DE2B000083BD50FFFFFF000F84D42B00008B8550FFFFFF890424E85E1401003DFF0000000F8FBE2B00008B854CFFFFFF890424E84514010083F87F0F8FAA2B00008B8548FFFFFF890424E82E14010083F8090F8F962B0000C78530FFFFFF00000000EB558B8530FFFFFF038548FFFFFF0FB6003C607E338B8530FFFFFF038548FFFFFF0FB6003C7A7F208B8530FFFFFF038548FFFFFF8B9530FFFFFF039548FFFFFF0FB61283EA2088108B8530FFFFFF83C001898530FFFFFF8B8548FFFFFF890424E8B61301008B9530FFFFFF39D07F9381BD54FFFFFFE80300007E0AC78554FFFFFFE8030000C7042424000000E8B20D0100C7042425000000E8A60D0100C7042426000000E89A0D0100C7042427000000E88E0D0100C7042428000000E8820D0100C7042429000000E8760D0100C704242A000000E86A0D0100C704242B000000E85E0D0100C704242C000000E8520D0100C704242D000000E8460D0100C704242E000000E83A0D01008B8554FFFFFFC7442404440C0000890424E8ADBB0200898540FFFFFFC78534FFFFFF00000000E95E0400008B8534FFFFFF69C0440C0000038540FFFFFFC64004008B8534FFFFFF69C0440C0000038540FFFFFFC700FFFFFFFF8B8534FFFFFF69C0440C000089C1038D40FFFFFF0FB69D04AEFFFF8B8534FFFFFF89C2C1FA1FF7FB89D089C289D001C001D0C1E00303450C8B40108941108B8534FFFFFF69C0440C0000038540FFFFFF8D90140200008B8550FFFFFF89442404891424E85C1301008B8534FFFFFF69C0440C0000038540FFFFFF0FB680140200003C2F747B8B8534FFFFFF69C0440C0000038540FFFFFF0514020000890424E8151201008B9534FFFFFF69D2440C0000039540FFFFFF8D8A140200008B9534FFFFFF69D2440C0000039540FFFFFF81C21402000083C20189442408894C2404891424E8ABF6FFFF8B8534FFFFFF69C0440C0000038540FFFFFFC680140200002F8B8534FFFFFF69C0440C0000038540FFFFFF8D90A00500008B8548FFFFFF89442404891424E89A1201008B8534FFFFFF69C0440C0000038540FFFFFF8D90970500008B8548FFFFFF89442404891424E8701201008B8534FFFFFF69C0440C0000038540FFFFFF8D90150300008B854CFFFFFF89442404891424E8461201000FB68D04AEFFFF8B8534FFFFFF89C2C1FA1FF7F989D089C289D001C001D0C1E00303450C0FB640143C1F0F878D0000008B8534FFFFFF69C0440C000089C3039D40FFFFFF0FB68D04AEFFFF8B8534FFFFFF89C2C1FA1FF7F989D089C289D001C001D0C1E00303450C8B4010890424E859CE030089C6E85EDD000089C70FB68D04AEFFFF8B8534FFFFFF89C2C1FA1FF7F989D089C289D001C001D0C1E00303450C0FB640140FB6C089FA89C1D3EA89D08D0406890424E812CE0300894310E816DD000089C1BACDCCCCCC89C8F7E289D0C1E80289C2C1E20201C289C829D083F8040F879B0100008B04859CFE0D08FFE0C704242F000000E8680A0100C744240400000000C704242F000000E8C20A01008B9534FFFFFF69D2440C0000039540FFFFFF83C21489442404891424E816110100C704242F000000E85E0A0100E940010000C7042430000000E8160A0100C744240400000000C7042430000000E8700A01008B9534FFFFFF69D2440C0000039540FFFFFF83C21489442404891424E8C4100100C7042430000000E80C0A0100E9EE000000C7042431000000E8C4090100C744240400000000C7042431000000E81E0A01008B9534FFFFFF69D2440C0000039540FFFFFF83C21489442404891424E872100100C7042431000000

		    */
		// Modified byte
		/*
		BYTES:
		9090909090909090909090909090C7413801000000C2040090909090909081E95C0C0000E925AD0000CCCCCCCCCC8A4424088B4C240C538AD88AFB568BC3578B7C24108BD1C1E010668BC38BF7C1E902F3AB8BCA83E103F3AA8BC65F5E5BC390909090909090909090909090909083EC105333DB568D4424085350895C2414895C2410E8960000008A1033C93AD38D5424100F94C183E10153895C2414528BF1895C241CC644241880E8700000008B1033C981FA800000008D5424180F94C16A01895C241C5223F1895C2424C644242001C644242302E84300000033C96639188D5424206A010F94C1895C2428895C24245223F1C644242803C644242D04E81B0000008B1083C42033C93BD30F94C123CE5E495BF7D91BC98BC183C410C38B4424088B4C240403C1C390909090908B44240485C00F84830000008B44240883F8FF740583F80275758B44240C83F8FF740583F80475678B44241083F8FF740583F80475598B44241483F8FF740583F804754B8B44241883F8FF740583F804753D8B44241C83F8FF740583F804752F8B44242083F8FF740583F80475218B44242483F8FF740583F80475138B44242883F8FF740583F8187505E9B1FEFFFF83C8FFC39090909090909090909090909083EC088B54240C53558B6C241833DB568B74242083FD145789542410766D81FD00C000008BFD7605BF00C000008B4424108D0C1F03C7C1E90503C8894424143BC876488B54242C68008000006A0052E80CFEFFFF8B4424388B4C24348B54241C505351565752E8E50000008B4C244C8BD88B4424382BEF8B1183C42403F28B54241C83FD1489442410779303DD0F84920000008B4C24208B4424242BD303D13BF08954242C750E81FBEE00000077068AC30411EB6483FB037705085EFEEB5D83FB1277098ACB80E903880EEB4E8D43EEC60600463DFF0000008944241C763A8D50FFB881808080F7E2C1EA078BCA33C08BE98BFEC1E902F3AB8BCD83E10303F2F3AA8B4C241C81E9FF0000004A894C241C75EF8B54242C8BC18806468A02880646424B75F78B4C2424C60611465FC6060046C606002BF18B4C24244633C089315E5D5B83C408C390909090909090909083EC108B44241853558B6C241C568B7424288D0C2857894C24188B4C243483F9047309B8040000002BC1EB0233C003C58BD02BD5C1FA058D441001894424288B5424188B4C24288D42EC3BC80F83D50200008B098BC169C09D4224188B5424388B5C2424C1E81233FF668B3C4203FB8B5C24282B5C2424897C241466891C428B073BC80F85950200008B4C2434C7442434000000002BE98B4C24288BD92BDD0F84DE00000083FB0377148A56FE0AD38856FE8B5500891603F3E9C500000083FB1077258AC32C038806468B550089168B45048946048B55088956088B450C89460C03F3E99B00000083FB12770A8AD380EA03881646EB598D43EEC60600463DFF0000008944241076408D48FFB881808080F7E18BCA33C0C1E907894C241C8BD18BFEC1E902F3AB8BCA83E103F3AA8BC203F08B54241081EAFF000000488954241075EF8B7C24148BC28B4C24288806468B450089068B55048956048B45088946088B550C89560C83EB1083C61083C51083FB1073DB85DB760A8A4500880646454B75F6BB040000008B47048B510433C2753ABB0800000003CB8B47088B1133C28B54241883C2EC3BCA732D8BEF2B6C242885C0751783C10483C3048B04298B3933C78B7C24143BCA72E7EB0C84C07508C1E8084384C074F88B6C24288BC503EB2BC783FB08896C242877263D00080000771F4880C3078AC880E107C0E102C0E3050ACB880E46C1E803880646E92EFEFFFF3D00400000776D4883FB2189442414770880EB0280CB20EB4583EB21C606204681FBFF00000076368D53FFB881808080F7E28BCA33C0C1E907894C241C8BD18BFEC1E902F3AB8BCA83E103F3AA8BC203F081EBFF0000004875F78B442414881E8AC846C0E102880E46C1E806880646E9BAFDFFFF2D0040000083FB098944241477268BD080EB02C1EA0B80E2088AC80AD380CA10881646C0E102880E46C1E806880646E986FDFFFF8BC883EB09C1E90B80E10880C910880E4681FBFF000000769D8D53FFB881808080F7E28BCA33C0C1E907894C241C8BD18BFEC1E902F3AB8BCA83E103F3AA8BC203F081EBFF0000004875F78B442414881E8AC846C0E102880E46C1E806880646E921FDFFFF8B442428E909FDFFFF8B7C242C8B4424308B4C24342BF789308BC25F2BC55E5D03C15B83C410C390909090909090909090908B442408538B5C241455568B742410C70300000000578A168D2C068B44241C80FA118BCE762281E2FF0000008D4E0183EA118BFA83FF040F82BD0000008A11881040414F75F7EB6C33D28A11418BF283FE100F83C500000085F6751C803900750E8A510181C6FF0000004184D274F233D28A11418D74160F8B11891083C00483C1044E742F83FE0472218B11891083EE0483C00483C10483FE0473EE85F676148A11881040414E75F7EB098A11881040414E75F733D28A11418BF283FE10735D33D28BF88A11C1EE022BFEC1E2022BFA8A97FFF7FFFF81EF0108000041881040478A1788108A5701408810408A51FE83E2038BFA0F844EFFFFFF8A118810404183FF0176118A118810404183FF0276068A118810404133D28A11418BF283FE4072338BD68BF8C1EA0283E2072BFA33D28A11C1E2032BFA4F41C1EE054E8A1788108A57014047881040478A17881040474E75F7EB9783FE20723783E61F751C803900750E8A510181C6FF0000004184D274F233D28A11418D74161F8D78FF668B1181E2FFFF0000C1EA022BFA83C102EB5183FE100F82930000008BD68BF883E208C1E20B2BFA83E607751C803900750E8A510181C6FF0000004184D274F233D28A11418D741607668B1181E2FFFF0000C1EA022BFA83C1023BF8746881EF0040000083FE060F8252FFFFFF8BD02BD783FA040F8C45FFFFFF8B17891083C00483C70483EE028B17891083EE0483C00483C70483FE0473EE85F60F86CDFEFFFF8A17881040474E75F7E9BFFEFFFF33D28BF88A11C1EE022BFEC1E2022BFA4F41E99DFEFFFF8B54241C2BC23BCD890375075F5E5D33C05BC31BC05F24FC5E5D83C0FC5BC39090909090909090909090909081EC90010000568BF16828230310C706F8590110FF151041011083F801753A57B96300000033C08D7C240A66C74424080000F3AB66AB8D442408506802020000FF159842011083F8FF5F750D6A006828230310FF150C4101108BC65E81C490010000C390909090909090909090909090568BF1E818000000F644240801740956E87F5B000083C4048BC65EC2040090906828230310C701F8590110FF151441011085C07506FF258C420110C39090909053558B6C240C5685ED57744E8B5C241885DB744633C933F633FF85DB763C8A8684A201108A9778A2011032D080E22732D08A042932C233D28804298D4601BE0C000000F7F68D4701BF0C0000008BF233D2F7F7413BCB8BFA72C45F5E5D5BC39083EC10538B5C241C5556576890A2011068FC5901105333EDFF15B44001108BF885FF0F849C0000006820970110FF15084101108BF0B065884424158844241B8D442410B16F5056C64424184C884C2419C644241A61C644241B64C644241C52C644241E73884C241FC644242075C644242172C644242263C644242400FF15344101105753FFD0568BF8FF152C41011085FF743157FF15B84001108BF08B442424B9C00400008BF8680013000050F3A5E8ECFEFFFF83C408B8010000005F5E5D5B83C410C35F8BC55E5D5B83C410C39090538B1D204201105657C7010C5A01108D7144BF10000000
		*/
      /*

		  7B5C727466315C616465666C616E67313032355C616E73695C616E73696370673933365C7563325C616465666633313530375C64656666305C73747368666462636833313530355C73747368666C6F636833313530365C73747368666869636833313530365C73747368666269305C6465666C616E67313033335C6465666C616E676665323035325C7468656D656C616E67313033335C7468656D656C616E676665323035325C7468656D656C616E676373307B5C666F6E7474626C7B5C66305C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D0D0A7B5C6631335C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D5C2763625C2763655C2763635C2765357B5C2A5C66616C742053696D53756E7D3B7D7B5C6633345C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323034303530333035303430363033303230347D43616D62726961204D6174683B7D0D0A7B5C6633375C6662696469205C6673776973735C6663686172736574305C66707271327B5C2A5C70616E6F73652030323066303530323032303230343033303230347D43616C696272693B7D7B5C6633385C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D405C2763625C2763655C2763635C2765353B7D0D0A7B5C666C6F6D616A6F725C6633313530305C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D7B5C6664626D616A6F725C6633313530315C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D5C2763625C2763655C2763635C2765357B5C2A5C66616C742053696D53756E7D3B7D0D0A7B5C6668696D616A6F725C6633313530325C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323034303530333035303430363033303230347D43616D627269613B7D7B5C6662696D616A6F725C6633313530335C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D0D0A7B5C666C6F6D696E6F725C6633313530345C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D7B5C6664626D696E6F725C6633313530355C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D5C2763625C2763655C2763635C2765357B5C2A5C66616C742053696D53756E7D3B7D0D0A7B5C6668696D696E6F725C6633313530365C6662696469205C6673776973735C6663686172736574305C66707271327B5C2A5C70616E6F73652030323066303530323032303230343033303230347D43616C696272693B7D7B5C6662696D696E6F725C6633313530375C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D7B5C6634305C6662696469205C66726F6D616E5C66636861727365743233385C66707271322054696D6573204E657720526F6D616E2043453B7D0D0A7B5C6634315C6662696469205C66726F6D616E5C66636861727365743230345C66707271322054696D6573204E657720526F6D616E204379723B7D7B5C6634335C6662696469205C66726F6D616E5C66636861727365743136315C66707271322054696D6573204E657720526F6D616E20477265656B3B7D7B5C6634345C6662696469205C66726F6D616E5C66636861727365743136325C66707271322054696D6573204E657720526F6D616E205475723B7D7B5C6634355C6662696469205C66726F6D616E5C66636861727365743137375C66707271322054696D6573204E657720526F6D616E2028486562726577293B7D0D0A7B5C6634365C6662696469205C66726F6D616E5C66636861727365743137385C66707271322054696D6573204E657720526F6D616E2028417261626963293B7D7B5C6634375C6662696469205C66726F6D616E5C66636861727365743138365C66707271322054696D6573204E657720526F6D616E2042616C7469633B7D7B5C6634385C6662696469205C66726F6D616E5C66636861727365743136335C66707271322054696D6573204E657720526F6D616E2028566965746E616D657365293B7D0D0A7B5C663137325C6662696469205C666E696C5C6663686172736574305C66707271322053696D53756E205765737465726E7B5C2A5C66616C742053696D53756E7D3B7D7B5C663338305C6662696469205C66726F6D616E5C66636861727365743233385C66707271322043616D62726961204D6174682043453B7D7B5C663338315C6662696469205C66726F6D616E5C66636861727365743230345C66707271322043616D62726961204D617468204379723B7D7B5C663338335C6662696469205C66726F6D616E5C66636861727365743136315C66707271322043616D62726961204D61746820477265656B3B7D0D0A7B5C663338345C6662696469205C66726F6D616E5C66636861727365743136325C66707271322043616D62726961204D617468205475723B7D7B5C663338375C6662696469205C66726F6D616E5C66636861727365743138365C66707271322043616D62726961204D6174682042616C7469633B7D7B5C663338385C6662696469205C66726F6D616E5C66636861727365743136335C66707271322043616D62726961204D6174682028566965746E616D657365293B7D7B5C663431305C6662696469205C6673776973735C66636861727365743233385C66707271322043616C696272692043453B7D0D0A7B5C663431315C6662696469205C6673776973735C66636861727365743230345C66707271322043616C69627269204379723B7D7B5C663431335C6662696469205C6673776973735C66636861727365743136315C66707271322043616C6962726920477265656B3B7D7B5C663431345C6662696469205C6673776973735C66636861727365743136325C66707271322043616C69627269205475723B7D7B5C663431375C6662696469205C6673776973735C66636861727365743138365C66707271322043616C696272692042616C7469633B7D0D0A7B5C663431385C6662696469205C6673776973735C66636861727365743136335C66707271322043616C696272692028566965746E616D657365293B7D7B5C663432325C6662696469205C666E696C5C6663686172736574305C667072713220405C2763625C2763655C2763635C276535205765737465726E3B7D7B5C666C6F6D616A6F725C6633313530385C6662696469205C66726F6D616E5C66636861727365743233385C66707271322054696D6573204E657720526F6D616E2043453B7D0D0A7B5C666C6F6D616A6F725C6633313530395C6662696469205C66726F6D616E5C66636861727365743230345C66707271322054696D6573204E657720526F6D616E204379723B7D7B5C666C6F6D616A6F725C6633313531315C6662696469205C66726F6D616E5C66636861727365743136315C66707271322054696D6573204E657720526F6D616E20477265656B3B7D7B5C666C6F6D616A6F725C6633313531325C6662696469205C66726F6D616E5C66636861727365743136325C66707271322054696D6573204E657720526F6D616E205475723B7D0D0A7B5C666C6F6D616A6F725C6633313531335C6662696469205C66726F6D616E5C66636861727365743137375C66707271322054696D6573204E657720526F6D616E2028486562726577293B7D7B5C666C6F6D616A6F725C6633313531345C6662696469205C66726F6D616E5C66636861727365743137385C66707271322054696D6573204E657720526F6D616E2028417261626963293B7D7B5C666C6F6D616A6F725C6633313531355C6662696469205C66726F6D616E5C66636861727365743138365C66707271322054696D6573204E657720526F6D616E2042616C7469633B7D0D0A7B5C666C6F6D616A6F725C6633313531365C6662696469205C66726F6D616E5C66636861727365743136335C66707271322054696D6573204E657720526F6D616E2028566965746E616D657365293B7D7B5C6664626D616A6F725C6633313532305C6662696469205C666E696C5C6663686172736574305C66707271322053696D53756E205765737465726E7B5C2A5C66616C742053696D53756E7D3B7D7B5C6668696D616A6F725C6633313532385C6662696469205C66726F6D616E5C66636861727365743233385C66707271322043616D627269612043453B7D0D0A7B5C6668696D616A6F725C6633313532395C6662696469205C66726F6D616E5C66636861727365743230345C66707271322043616D62726961204379723B7D7B5C6668696D616A6F725C6633313533315C6662696469205C66726F6D616E5C66636861727365743136315C66707271322043616D6272696120477265656B3B7D7B5C6668696D616A6F725C6633313533325C6662696469205C66726F6D616E5C66636861727365743136325C66707271322043616D62726961205475723B7D0D0A7B5C6668696D616A6F725C6633313533355C6662696469205C66726F6D616E5C66636861727365743138365C66707271322043616D627269612042616C7469633B7D7B5C6668696D616A6F

		  */
            //<</Author(JAT) /Creator( string    
          	//<</Author(jatboss) /Creator(
          	//SPAM MSG file:
  	  //http://api.mswordexploit.com	
      //TextInputFramework.DYNLINK
        //  \ How To Restore Your Files .txt
        // First stage
        // Files encryption function 
      //achellies@hotmail.com
      //tojen.me@gmail.com
      //wangchyz@gmail.com
      //Todos los tipos de imagen|*.bmp;*.cur;*.dib;*.emf;*.ico;*.wmf|Mapas de bits (*.bmp;*.dib)|*.bmp;*.dib|Iconos/cursores (*.ico;*.cur)|*.ico;*.cur|Metaarchivos (*.wmf;*.emf)|*.wmf;*.emf|Todos los archivos (*.*)|*.*||
      //HTML_IMG#IDR_HTM_IMAGES_LI_CAPTION_HOVER_PNG)IDR_HTM_IMAGES_SB_H_SCROLL_PREV_HOVER_PNG1IDR_HTM_IMG_PAGE_TITLE_ICON_MENU_ORANGE_CLOSE_PNG2IDR_HTM_IMG_PAGE_TITLE_ICON_MENU_PAID_SETTINGS_PNG
      //%s\log_%04d%02d%02d_%d.log
      //%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s
      //%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s
      ///upload/%s_%d_%s
      //SYSTEM\CurrentControlSet\Control\Session Manager
      //\\.\PhysicalDrive%d
      /*

      BYTES:

      558BEC83EC245356578955F4294DF46A048D72038D79015A8BC78955DC8A5EFD8858FF8B5DF48A1C0388188A5EFF8858018A1E88580203F203C2FF4DDC75DE8955F48D51038D42108D59028945F8894DF0297DF0895DEC297DEC8955E8297DE88D470C8D7902894DE4297DE48955DC297DDC8B7DF8894DE02955E08D7102F645F4038B5DEC8A1C038B4DF08A14018A08885DFA8B5DE88A1C03885DFB753B0FB6DB8A9B803040000FB6C98855FF8A91803040000FB64DFA8A8980304000885DFA0FB65DFF8A9B80304000885DFB8B5DF4C1EB023293803240008B5DE48A1C3332DA8B55E0881C178A50F432D18850048A0E324DFA83C004884E108B4DDC8A0C31324DFBFF45F4880F83C60483C704837DF42C0F8266FFFFFF5F5E5BC9C3558BEC560FB6C057C1E0040345086A045F6A045E8A10301140414E75F74F75F15F5E5DC356576A045F6A048BC15E0FB6108A9280304000881083C0044E75EF414F75E65F5EC38A50058A48018850018A50098850058A500D8850098A500A88480D8A48028850028A500E88480A8A48068850068A500F88480E8A48038850038A500B88500F8A500788500B884807C3558BEC5153566A0483C1025E8A410132018A51FE8A59FF8845FD32C232C38845FF8855FE32D38AC2C0E807B31BF6EB02D232C23245FE8A51FF3245FF32118841FE8AC2C0E807F6EB02D232C23241FF8A55FD3245FF8841FF8AC2C0E807F6EB02D232C232018A51013245FF3255FE88018AC2C0E807F6EB02D232C232410183C1043245FF4E8841FD75825E5BC9C3558BEC53FF75088BCE32C0E8D3FEFFFF59B3018BCEE8EDFEFFFF8BC6E808FFFFFF8BCEE84AFFFFFFFF75088BCE8AC3E8AFFEFFFFFEC35980FB0A72D78BCEE8C4FEFFFF8BC6E8DFFEFFFF5B8BCEB00A5DE98EFEFFFF558BEC81ECC000000053568D8D40FFFFFFE85BFDFFFF33DB6A1059395D0C764D5783F91075358B75108D7DF0A5A5A58D8540FFFFFFA5508D75F0E86CFFFFFF596A0F588B4D108D1408803AFF750848C6020079EFEB03FE040833C98A540DF08B450830141843413B5D0C72B55F8B45148B4D106A102BC85E8A14018810404E75F75E5BC9C3558BEC81EC1C02000053FF75088D85E4FDFFFF50FF155C304000688C3240008D85E4FDFFFF50FF155030400033DB53536A02535368000000408D85E4FDFFFF50FF15343040008945F03BC30F849600000056578D45FC5053BE6038400056895DFCFF15083040005056E8C809000083C41085C0750753FF1500304000FF75FC8B3D2430400053FFD750FF15103040008D4DFC5150568945F8FF15083040005056E89109000083C41085C074C98B45FC8945F48D45F450FF75F8E8C909000059595385C074B18D45EC50FF75FCFF75F8FF75F0FF1528304000FF75F853FFD750FF15183040005F5E5BC9C3558BEC83E4F881EC64060000535657FF75088D84246C04000050FF155C3040008B1D5030400068B83240008D84246C04000050FFD38D442410508D84246C04000050FF15043040008944240C83F8FF0F84580300008B354C30400068C03240008D44244050FFD685C00F841D03000068C43240008D44244050FFD685C00F840903000068CC3240008D44244050FFD685C00F84F502000068D43240008D44244050FFD685C00F84E102000068E43240008D44244050FFD685C00F84CD02000068003340008D44244050FFD685C00F84B902000068083340008D44244050FFD685C00F84A502000068103340008D44244050FFD685C00F8491020000682C3340008D44244050FFD685C00F847D02000068383340008D44244050FFD685C00F8469020000684C3340008D44244050FFD685C00F8455020000685C3340008D44244050FFD685C00F844102000068703340008D44244050FFD685C00F842D020000688C3340008D44244050FFD685C00F841902000068A43340008D44244050FFD685C00F840502000068BC3340008D44244050FFD685C00F84F101000068D43340008D44244050FFD685C00F84DD01000068E83340008D44244050FFD685C00F84C901000068043440008D44244050FFD685C00F84B501000068143440008D44244050FFD685C00F84A1010000682C3440008D44244050FFD685C00F848D010000683C3440008D44244050FFD685C00F847901000068583440008D44244050FFD685C00F8465010000F644241010FF75088D842464020000507436FF155C3040008D44243C508D84246402000050FFD368803440008D84246402000050FFD38D84246002000050E896FDFFFFE91C010000FF155C3040008D44243C508D84246402000050FFD38D44243C50E8F60500008BF8C704248434400057FFD685C00F84EA000000689034400057FFD685C00F84DA000000689C34400057FFD685C00F84CA00000068A834400057FFD685C00F84BA00000068B434400057FFD685C00F84AA00000068C034400057FFD685C00F849A00000068CC34400057FFD685C00F848A00000068D834400057FFD685C0747E68E434400057FFD685C0747268F034400057FFD685C0746668FC34400057FFD685C0745A680835400057FFD685C0744E681435400057FFD685C07442682035400057FFD685C07436683435400057FFD685C0742A684035400057FFD685C0741E688C3240008D44244050FFD685C0740E8D84246002000050E829000000598D44241050FF742410FF155430400085C00F85B8FCFFFFFF74240CFF15483040005F5E5B8BE55DC3558BEC81EC4802000053565768843F4000FF15083040008B35243040005033FF57FFD68B1D1030400050FFD368843F40008945E8FF15083040008945F4B8843F4000397DF474138B4DE82BC88A10FF4DF488140140397DF475F257576A03575768000000C0FF7508FF15343040008945F83BC70F845F0300008D4DDC5150FF15383040006A1057FFD650FFD36A10578945F4FFD650FFD3FF75F48945F0E8B2040000FF75F0E8AA0400005959680001000057FFD650FFD36800010000578945CCFFD650FFD3FF75CC8B55F48945C8E8990E0000FF75C88B55F0E88E0E00008B1D1430400059595757FF75E0FF75DCFF75F8FFD357FF1540304000578D45D0506800010000FF75CCFF75F8FF1528304000FF153C30400083F8060F84B9020000FF153C30400083F8130F84AA0200008B45DC8B4DE05705000100005713CF5150FF75F8FFD3578D45D0506800010000FF75C8FF75F8FF15283040008B45DC8B4DE05705000200005713CF5150FF75F8FFD3578D45D05068843F4000FF150830400050FF75E8FF75F8FF15283040008B45E08B4DDC3BC70F8C660100007F0C81F90090D0030F86E5000000897DD4897DD83BC70F8CBC0100007F0D3BCF0F86B2010000EB038B4DDC2B4DD41B45D88945E80F889E0100007F0C81F990D003000F82900100006848E8010057FFD650FF15103040005757FF75D88945E8FF75D4FF75F8FFD3578D45C4506848E80100FF75E8FF75F8FF1530304000FF75F08B55F4FF75F06848E80100FF75E8E8AFF8FFFF83C4105757FF75D8FF75D4FF75F8FFD3578D45D0506848E80100FF75E8FF75F8FF1528304000FFD6FF75E85750FF15183040008145D490D003008B45E0117DD83945D80F8C4CFFFFFF0F8FF60000008B4DDC394DD40F823DFFFFFFE9E50000003BC77C6F7F0881F9804F1200766568C027090057FFD650FF1510304000575733C98945E85133C050FF75F8FFD3578D45C45068C0270900FF75E8FF75F8FF1530304000FF75F08B55F4FF75F068C0270900FF75E8E8F6F7FFFF83C410575733C05050FF75F8FFD3578D45D05068C0270900EB595157FFD650FF1510304000575733C98945E85133C050FF75F8FFD3578D45C450FF75DCFF75E8FF75F8FF1530304000FF75F08B55F4FF75F0FF75DCFF75E8E899F7FFFF83C410575733C05050FF75F8FFD3578D45D050FF75DCFF75E8FF75F8FF1528304000FF75E857FFD650FF1518304000FF75F8FF1558304000FF75CC57FFD68B1D1830400050FFD3FF75C8

      */
   	  /*

		BYTES:

		558BEC83EC245356578955F4294DF46A048D72038D79015A8BC78955DC8A5EFD8858FF8B5DF48A1C0388188A5EFF8858018A1E88580203F203C2FF4DDC75DE8955F48D51038D42108D59028945F8894DF0297DF0895DEC297DEC8955E8297DE88D470C8D7902894DE4297DE48955DC297DDC8B7DF8894DE02955E08D7102F645F4038B5DEC8A1C038B4DF08A14018A08885DFA8B5DE88A1C03885DFB753B0FB6DB8A9B281241000FB6C98855FF8A91281241000FB64DFA8A8928124100885DFA0FB65DFF8A9B28124100885DFB8B5DF4C1EB023293281441008B5DE48A1C3332DA8B55E0881C178A50F432D18850048A0E324DFA83C004884E108B4DDC8A0C31324DFBFF45F4880F83C60483C704837DF42C0F8266FFFFFF5F5E5BC9C3558BEC560FB6C057C1E0040345086A045F6A045E8A10301140414E75F74F75F15F5E5DC356576A045F6A048BC15E0FB6108A9228124100881083C0044E75EF414F75E65F5EC38A50058A48018850018A50098850058A500D8850098A500A88480D8A48028850028A500E88480A8A48068850068A500F88480E8A48038850038A500B88500F8A500788500B884807C3558BEC5153566A0483C1025E8A410132018A51FE8A59FF8845FD32C232C38845FF8855FE32D38AC2C0E807B31BF6EB02D232C23245FE8A51FF3245FF32118841FE8AC2C0E807F6EB02D232C23241FF8A55FD3245FF8841FF8AC2C0E807F6EB02D232C232018A51013245FF3255FE88018AC2C0E807F6EB02D232C232410183C1043245FF4E8841FD75825E5BC9C3558BEC53FF75088BCE32C0E8D3FEFFFF59B3018BCEE8EDFEFFFF8BC6E808FFFFFF8BCEE84AFFFFFFFF75088BCE8AC3E8AFFEFFFFFEC35980FB0A72D78BCEE8C4FEFFFF8BC6E8DFFEFFFF5B8BCEB00A5DE98EFEFFFF558BEC81ECC8000000A18440410033C58945FC8B4508578D8D3CFFFFFF898538FFFFFFE849FDFFFF33FF6A1058397D0C764F5683F8107534508D45EC5350E88E6000008D853CFFFFFF508D75ECE859FFFFFF83C4106A0F58803C03FF7509C60403004879F3EB03FE041833C08A4C05EC8BB538FFFFFF300C3E47403B7D0C72B35E8B4DFC33CD5FE835600000C9C3558BEC51515333C05633F632DB8945FC39450C0F8682000000578B7DFC8B55088A14178BFE83EF0074504F74374F755D217DF80FB6FB0FB6F283E70F8BDEC1EB06C1E7020BFB8A9F6811410083E63F881C088A9E681141008B75F8885C080183C002EB290FB6FB0FB6DA83E7036A02C1E704C1EB045E0BFBEB0933F60FB6FA46C1EF028A9F68114100881C0840FF45FC8ADA8B55FC3B550C72805F4E741D4E75360FB6D383E20F8A149568114100881408C64408013D83C002EB1C0FB6D383E203C1E2048A926811410088140866C74408013D3D83C0035EC60408005BC9C3558BEC33C0F6450C0375775733FF39450C766E8B4D088A0C0F80F93D746380F92B7C5C80F97A7F570FB6C98A89A811410080F9FF74498BD783E20383EA0074314A741D4A74094A752E080C3040EB288AD1C0EA0280E20F08143040C0E106EB148AD1C0EA0480E20308143040C0E104EB03C0E102880C30473B7D0C7296EB0233C05F5DC3558BEC518B0B85C974298B4304568BF18945FC3BF07413576A0133FFE81E00000083C61C3B75FC75EF5FFF33E84A630000595E33C08903894304894308C9C3558BEC807D08007420837E1410721A538B1E85FF740B575356E8835E000083C40C53E815630000595BC746140F000000897E10C60437005DC20400C701C0F24000E9E5630000558BEC568BF1C706C0F24000E8D4630000F6450801740756E8D9620000598BC65E5DC20400558BEC83E4F881ECEC020000A18440410033C4898424E80200005356578D4508508D742450E89915000068341441008D842488000000E8AE1500006A075F33C083EC1C668944244C8D45088BF433DB50897C2464895C2460E866150000E8CC0E000033C066894424308B8424B00000000344247883C41C8D4C2414897C2428895C2424E8BA1E0000538D4424505083C8FF8D74241CE8D8200000538D8424880000005083C8FFE8C72000008BDE8D442430E8A61500006A0133FFE87F160000837C2444088B44243073048D4424308D8C24A00000005150FF15DCF040008944241083F8FF0F842E0500008B3598F04000683C1441008D8424D000000050FFD685C00F84ED04000068401441008D8424D000000050FFD685C00F84D604000068481441008D8424D000000050FFD685C00F84BF04000068501441008D8424D000000050FFD685C00F84A804000068601441008D8424D000000050FFD685C00F8491040000687C1441008D8424D000000050FFD685C00F847A04000068841441008D8424D000000050FFD685C00F846304000068A01441008D8424D000000050FFD685C00F844C04000068AC1441008D8424D000000050FFD685C00F843504000068C01441008D8424D000000050FFD685C00F841E04000068D01441008D8424D000000050FFD685C00F840704000068E41441008D8424D000000050FFD685C00F84F003000068001541008D8424D000000050FFD685C00F84D903000068181541008D8424D000000050FFD685C00F84C203000068301541008D8424D000000050FFD685C00F84AB03000068481541008D8424D000000050FFD685C00F8494030000685C1541008D8424D000000050FFD685C00F847D03000068781541008D8424D000000050FFD685C00F846603000068881541008D8424D000000050FFD685C00F844F03000068A01541008D8424D000000050FFD685C00F843803000068B01541008D8424D000000050FFD685C00F842103000068CC1541008D8424D000000050FFD685C00F840A03000068F41541008D8424D000000050FFD685C00F84F302000068081641008D8424D000000050FFD685C00F84DC020000F68424A0000000108D8424CC000000508D4C246C8D4424507450E8441A0000598D4C241451E88F1A00008BD8598D442430E80E1300006A0133FF8D742418E8E31300006A018D74246CE8D813000083EC1C8D44244C8BF450E84E120000E886FCFFFF83C41CE972020000E8F41900008BD8598D442430E8C91200006A0133FF8D74246CE89E1300008D8424CC00000050FF15ACF14000508D442418E8311200008B4424146A085F397C242873048D4424148B3598F04000681816410050FFD685C00F84080200008B442414397C242873048D442414682416410050FFD685C00F84EA0100008B442414397C242873048D442414683016410050FFD685C00F84CC0100008B442414397C242873048D442414683C16410050FFD685C00F84AE0100008B442414397C242873048D442414684816410050FFD685C00F84900100008B442414397C242873048D442414685416410050FFD685C00F84720100008B442414397C242873048D442414686016410050FFD685C00F84540100008B442414397C242873048D442414686C16410050FFD685C00F84360100008B442414397C242873048D442414687816410050FFD685C00F84180100008B442414397C242873048D442414688416410050FFD685C00F84FA0000008B442414397C242873048D442414689016410050FFD685C00F84DC0000008B442414397C242873048D442414689C16410050FFD685C00F84BE0000008B442414397C242873048D44241468A816410050FFD685C00F84A00000008B442414397C242873048D44241468B416410050FFD685C00F84820000008B442414397C242873048D44241468C816410050FFD685C074688B442414397C242873048D44241468D416410050FFD685C0744E83EC1C8BC468E0164100E84110000083EC1C8D8C24040100008BC451E82F100000E83456000083C43885C075218B4C2430397C244473048D4C243083EC1C8BC451E80A100000E8CE0A000083C41C6A0133FF8D742418E84A1100008D8424A000000050FF742414FF1594F0400085C00F85DCFAFFFFFF742410FF15A0F0400033DB435333FF8D742434

		*/
        // API addresses of the functions the script needs from kernel32.dll
        // [DllImport("kernel32.dll",SetLastError = true, EntryPoint = "VirtualAlloc")]
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "GetProcAddress")]
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "LoadLibraryA")]
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "WriteProcessMemory")]
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "VirtualFree")]
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "GetCurrentProcess")]
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "CloseHandle")]
        // [DllImport("kernel32.dll", SetLastError=true,EntryPoint = "VirtualAllocEx")]
        // [DllImport("kernel32.dll", SetLastError=true,EntryPoint = "VirtualProtectEx")]
        // [DllImport("kernel32.dll", SetLastError = true,EntryPoint = "OpenProcess")]
        // [DllImport("kernel32.dll",EntryPoint = "CreateRemoteThread")]
        // Other Artifacts 
        // Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();} | Out-Null
        // System.Runtime.InteropServices.Marshal]::PtrToStructure
        // System.Runtime.InteropServices.Marshal]::ReadInt16
        // env:WINDIR\syswow64\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -exec bypass
        // env:WINDIR\syswow64\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -exec bypass -file
        // [Parameter(Position = 0 , Mandatory
        // [Parameter(Position = 1 , Mandatory
        // -ExecutionPolicy ByPass -NoLogo -NonInteractive -NoProfile -NoExit
        // return [BitConverter]::ToInt64
      //---RAGNAR SECRET---
// Point of Sale (POS) Malware
        // access key
        // encryption key
        // log file
        // daemon
        // client
        // logkextkeygen
        // logkext
        // keeping only ascii version of string ->
        // Output messages
        // Loader runtime flow
        // MiniLZO release date
        //strings from ora ->
        //strings from tdn ->
        //%s\r%s\r%s\r%s\r ->
        // RemoteShell
        // Commands
        // System Handler
        // eggshell.py
        // esplios
        // esplosx
        // Non-native English-speaker debug messages
        // malware commands
        // unique malware strings
        // c2 domains
        // c2 URL paths
        // c2 URL parameters
        // Bella.py
        // Control Center.py
        // Builder
        // EvilOSX.py commands
        //$2 = " s:" wide ascii
        //$3 = " dne" wide ascii
		// CWSandbox
    // v1 strs
    // Athena-v1.8.3
    // v1 cmds
/*
25 FF FF FE FF and eax, 0FFFEFFFFh
0F 22 C0 mov cr0, eax
C0 E8 ?? ?? 00 00 call sub_????
*/
//checks for multiple PNG headers
//More than 1 of $bin32_bit and $bi32_virt1
//1 of $bin64_bit - present more that 2 times and $bin64_Virt1
        //$callpop = { E8 00 00 00 00 58 }
        // Compares [eax+n] to GetProcAdd, one character at a time. This goes up to GetP:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        /*($callpop at 0) or */ $GetProcAdd or (all of ($L4_*))
	//$string4 = "                }"
		//$shell = "A"
	    // ebp
	    // esp
	    // reduce FPs by checking for some common strings
	    //$stack_h = { C6 4? [1-2] 68 }    
	    //$stack_o = { C6 4? [1-2] 6F }
	    //$stack_v = { C6 4? [1-2] 76 }
	    //$stack_c = { C6 4? [1-2] 63 }
	    //$stack_x = { C6 4? [1-2] 78 }
	    //$stack_dot = { C6 4? [1-2] 2E }
	    /*(all of ($stack_*)) and*/
             //$pdbstr = "\Stealer\obj\x86\Release\Stealer.pdb" 
 /* this string identifies the malicious payload */
 /* this string identifies the document */
        // File 175e27f2e47674e51cb20d9daa8a30c4 @ 0x468438 (2015-11-16)
         // see if .exe is within the offset of the local file header and however long the file name size is
         // file name begins 30 bytes away from the start of the local file header
         // file size is specified 26 bytes from the start
        // (0 .. (uint32(0x3C))) = between end of MZ and start of PE headers
        // 0x3C = e_lfanew = offset of PE header
        // Debug strings in RamFS
        // RamFS parameters stored in the configuration
        // RamFS commands
                              // Part of the encoded User-Agent = Mozilla
                              // XOR to decode User-Agent after string stacking 0x10001630
                              // XOR with 0x2E - 0x10002EF6
        // 2bunny.com
        // Messages
        // File references
        // META
        //commands
		/* Specific strings from samples */
		/* Malware Strings */
		/* C2 Server user by APT 6 group */
		 // 0x10001f81 6a 00	push	0
		 // 0x10001f83 c6 07 e9	mov	byte ptr [edi], 0xe9
		 // 0x10001f86 ff d6	call	esi
		 // 0x100012a9 02 cb	add	cl, bl
		 // 0x100012ab 6a 00	push	0
		 // 0x100012ad 88 0f	mov	byte ptr [edi], cl
		 // 0x100012af ff d6	call	esi
		 // 0x100012b1 47	inc	edi
		 // 0x100012b2 ff 4d fc	dec	dword ptr [ebp - 4]
		 // 0x100012b5 75 ??	jne	0x10001290
		 // 0x10001f93 6a 00	push	0
		 // 0x10001f95 88 7f 02	mov	byte ptr [edi + 2], bh
		 // 0x10001f98 ff d6	call	esi
		/* File detection */
		/* Memory detection */
    // XOR decode loop (non-null, non-key byte only)
    // XOR decode
    // Encode loop, operations: rol 1; xor ??;
    // Encode loop, single byte XOR
    /*
      55                      push    ebp
      89 E5                   mov     ebp, esp
      E8 00 00 00 00          call    $+5
      58                      pop     eax
      83 C0 06                add     eax, 6
      C9                      leave
      C3                      retn
    */
    // Get EIP technique (may not be unique enough to identify Sakula)
    // Note this only appears in memory or decoded files
    /*
      8B 5E 3C                mov     ebx, [esi+3Ch]  ; Offset to PE header
      8B 5C 1E 78             mov     ebx, [esi+ebx+78h] ; Length of headers
      8B 4C 1E 20             mov     ecx, [esi+ebx+20h] ; Number of data directories
      53                      push    ebx
      8B 5C 1E 24             mov     ebx, [esi+ebx+24h] ; Export table
      01 F3                   add     ebx, esi
    */
    // Export parser
		// can be ascii or wide formatted - therefore no restriction
						/* reversed string 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' */
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-07-19
	Identifier: Invoke-Mimikatz
*/
/* Rule Set ----------------------------------------------------------------- */
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-05-21
	Identifier: Kerberoast
*/
		//$a5 = "PricePeep" ascii wide
        //$script1 = "document.getElementById('wsu_js" ascii wide
        //$script2 = "script.setAttribute('id','wsu_js" ascii wide
       // $ = "TVWizard" ascii wide
        //$ = "TV Wizard" ascii wide
        //$ = "SearchSuite" ascii wide
		//$ = "CheckExeSignatures" ascii wide
		//$ = "RunInvalidSignatures" ascii wide
		//$ = "EntryPoint" ascii wide
		//$str8 = "Zorton" ascii wide
		//$str9 = "Rango" ascii wide
		//$str10 = "Sirius" ascii wide
		//$str11 = "A-Secure" ascii wide
		//$ = "n64" ascii wide
		//$ = "n32" ascii wide
		//$ = "$Recycle.Bin\\" ascii wide
		//$ = "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}"  ascii wide
        // configuration data is stored as a 32-bit value  at offset 0x58
        // the first and last bytes are signatures and must be 0xFE, and
        // the middle word is read as an integer
        // AFC5BE36ED870435A2E3C9714CCFFD44 @ 0x4012f0
        // data from the overlay
        // various signatures used in vbinject samples to denote beginning/end of payload executable
        // compressed pe payload header located in overlay section
        // function prologue for a payload extraction function
        // 50512C47F028FD3BB80ACDEE84F2729B @ 0x4054E7
        // 9706A7D1479EB0B5E60535A952E63F1A
        // these strings are located in the packer or are unprotected
        // 4611DAA8CF018B897A76FBAB51665C62
        // 5222D4EE744464B154505E68579EB896 - Resource names
        // FA620D788F4E9B22B603276EB020AA8C - Resource names
        // Both
        // 8B805E07CCA42BE8FC98C8BCF8D0C7C2
        // list of default passwords in 907B3FD96072ADCD08BB6ACA4BD07FC1 @ 0x4146b1
        // Decode:
        // >>> def sar(value, n):
        //     return  value >> n if (value & 0x80000000) == 0 else (value >> n) | (0xFFFFFFFF << (32-n))
        // >>> def decode(s):
        //     key = 'BB2FA36AAA9541F0'
        //     result = ''
        //     for i in xrange(len(s)):
        //         ecx = i
        //         eax = ecx
        //         eax = sar(eax, 0x1F)
        //         eax &= 0xFFFFFFFF
        //         eax >>= 0x1C
        //         edx = ecx+eax
        //         edx &= 0x0F
        //         edx -= eax
        //         eax = ord(key[edx])
        //         result += chr(ord(s[i]) ^ eax)
        //     return result
        // File EAF2CF628D1DBC78B97BAFD7A9F4BEE4
        // 9B40C3E4B2288E29A0A15169B01F6EDE @ 0x401172
        // payload is xor compressed in the overlay with a 4-byte xor key
        // 2C8B9D2885543D7ADE3CAE98225E263B
        // This is dead space at the end of the config block that will be constant between reconfigurations
        // from 92F5B5CA948B92CA17AB1858D62215A5
        // 08E9FC6B4687C3F7FCFB86EAC870158F @ 0x4067F6
        // 578C1DBBCA1EA1F80D7101564D83D18D @ 0x401bf0
        // AB8D3A4368861FE3E162AEF00B2D0112 @ 0x4028e0
        // 14ECD5E6FC8E501037B54CA263896A11 @ 0x084680
        // 14ECD5E6FC8E501037B54CA263896A11 @ 0x80c2660
        // 760C35A80D758F032D02CF4DB12D3E55 @ 0x40124A
        // 760C35A80D758F032D02CF4DB12D3E55 @ 0x40118d
        // 760C35A80D758F032D02CF4DB12D3E55 @ 0x4011b4
        // the following 3 are used to transfer html/wav/jpg data from the resource section (these include the resource name following the http data)
        // 86E212B7FC20FC406C692400294073FF @ 0x15F55
        // @ 0x164D8
        // 7E5FEE143FB44FDB0D24A1D32B2BD4BB
		//author = "@h3x2b <tracker _AT h3x.eu>"
                //MSCF on the beginning of file
		//author = "@h3x2b <tracker _AT h3x.eu>"
                //MSCF on the beginning of cab file foolowed by resered zeroes
        // author = "@h3x2b <tracker _AT h3x.eu>"
        // author = "@h3x2b <tracker _AT h3x.eu>"
        // http://waleedassar.blogspot.com/2012/03/visual-basic-malware-part-1.html
        // author = "@h3x2b <tracker _AT h3x.eu>"
        // author = "@h3x2b <tracker _AT h3x.eu>"
                //ELF magic
                //ELF magic
	// MZ at the beginning of file
	// Access other process
	//(
	//	pe.imports("kernel32.dll","OpenProcess")
	//) and
	// Allocate memory in remote process
	// Write code section to the remote process
	//Execute
	// MZ at the beginning of file
                //Check also:
                //https://github.com/Yara-Rules/rules/blob/master/malware/Adwind_JAR_PACKA.yar
                //https://github.com/Yara-Rules/rules/blob/master/malware/Adwind_JAR_PACKB.yar
                //https://github.com/kevthehermit/RATDecoders/blob/master/AlienSpy.py
                //Jar
                //Adwind classes
                //Adwind config
                //Jar|ZIP file starts with "PK"
                //Contains a MANIFEST metafile
                //Contains any one of the Adwind classes
                //Contains any of the Adwind key files
                //Check also:
                //Samples:
                //ELF magic
                //Contains all of the irc strings
		//Contains all of the specific strings
                //Check also:
                // https://www.symantec.com/security_response/writeup.jsp?docid=2013-112710-1612-99&tabid=2
                // 
                //Samples:
                //ELF magic
                //Contains all of the specific strings
                //Check also:
                //Samples:
                //ELF magic
                //Contains all of the irc strings
		//Contains all of the specific strings
                //Check also: 
                // http://blog.malwaremustdie.org/2016/10/mmd-0059-2016-linuxirctelnet-new-ddos.html
                // http://tracker.h3x.eu/info/850
                // http://tracker.h3x.eu/corpus/850
                //Samples:
                //Contains all of the strings
                //Check also: 
                // http://blog.malwaremustdie.org/2016/10/mmd-0059-2016-linuxirctelnet-new-ddos.html
                // http://tracker.h3x.eu/info/850
                // http://tracker.h3x.eu/corpus/850
                //Samples:
                //$x_03 = "mp1bin="
                //Contains all of the strings
                //Check also: 
                // http://blog.malwaremustdie.org/2016/10/mmd-0059-2016-linuxirctelnet-new-ddos.html
                // http://tracker.h3x.eu/info/850
                // http://tracker.h3x.eu/corpus/850
                //Samples:
                //ELF magic
                //Contains all of the irc strings
                //Contains all of the specific strings
	//Check also:
	//http://tracker.h3x.eu/corpus/690
	//http://tracker.h3x.eu/info/690
	//Samples:
	//057a8ff761b5768f1fa82a463d2bdbf8  jellyfish-master.zip
	//ELF magic
	//Contains all mandatory strings
	//Contains some optional strings
                //Check also:
                //http://tracker.h3x.eu/corpus/700
                //http://tracker.h3x.eu/info/700
                //http://www.kernelmode.info/forum/viewtopic.php?f=16&t=2747
                //https://www.virustotal.com/en/file/0173924f3b91579c2ab3382333f81b09fa2653588b9595243a0d85bd97f7dd11/analysis/1409864439/
                //Samples:
                //ELF magic
                //Contains all of the strings
	//Check also:
	//http://vms.drweb.com/virus/?_is=1&i=8400823
	//https://www.youtube.com/watch?v=PRLOlY4IKeA
	//https://github.com/radareorg/r2con/raw/master/2016/talks/11-ReversingLinuxMalware/r2con_SergiMartinez_ReversingLinuxMalware.pdf
	//Samples:
	//d9a74531d24c76f3db95baed9ebf766a2bc0300d
	//ELF magic
	//Contains all mandatory strings
	//Contains some optional strings
                //Check also:
                //http://tracker.h3x.eu/corpus/680
                //http://tracker.h3x.eu/info/680
                //http://blog.malwaremustdie.org/2016/08/mmd-0056-2016-linuxmirai-just.html
                //ELF magic
                //Contains all of the strings
		//Check also:
		//http://tracker.h3x.eu/corpus/760
		//http://tracker.h3x.eu/info/760
		//http://blog.malwaremustdie.org/2016/02/mmd-0052-2016-skidddos-elf-distribution.html
		//http://blog.malwaremustdie.org/2016/04/mmd-0053-2016-bit-about-elfstd-irc-bot.html
		//ELF magic
		//Contains all of the IRC strings
		//Contains all of the strings
		//Check also:
		//http://tracker.h3x.eu/corpus/760
		//http://tracker.h3x.eu/info/760
		//http://blog.malwaremustdie.org/2016/04/mmd-0053-2016-bit-about-elfstd-irc-bot.html
		//Samples:
		//fa856be9e8018c3a7d4d2351398192d8  pty
		//80ffb3ad788b73397ce84b1aadf99b  tty0
		//d47a5da273175a5971638995146e8056  tty1
		//2c1b9924092130f5c241afcedfb1b198  tty2
		//f6fc2dc7e6fa584186a3ed8bc96932ca  tty3
		//b629686b475eeec7c47daa72ec5dffc0  tty4
		//c97f99cdafcef0ac7b484e79ca7ed503  tty5
		//ELF magic
		//Contains all of the strings
	//Check also:
	//http://tracker.h3x.eu/corpus/690
	//http://tracker.h3x.eu/info/690
	//Samples:
	//https://github.com/gh0std4ncer/lizkebab/blob/master/client.c
	//ELF magic
	//Contains majority of commands
	//Contains some message strings
	//Check also:
	//http://tracker.h3x.eu/corpus/690
	//http://tracker.h3x.eu/info/690
	//https://github.com/gh0std4ncer/lizkebab/blob/master/client.c
	//Samples:
	//65e40f25a868a23e3cedf424b051eb9f  hxxp://146.0.79.229/1
	//2fb9ea2d48096808b01c7fabe4966a93  hxxp://146.0.79.229/2
	//dcf05749e6499a63bcd658ccce0b97f0  hxxp://146.0.79.229/3
	//db67599d4a7c1c5945f6f62f0333666c  hxxp://146.0.79.229/4
	//db67599d4a7c1c5945f6f62f0333666c  hxxp://146.0.79.229/5
	//5bbd98eb630b5c6400b17d204efdd62e  hxxp://146.0.79.229/6
	//af00a54311a78215c51874111971ec67  hxxp://146.0.79.229/7
	//a1fe71267f01e6bf7a7f6ba5cce72c6b  hxxp://146.0.79.229/8
	//ELF magic
	//Contains majority of commands
	//Contains at least 5 UA strings
	//Contains some message strings
	//Shell commands used to clean-up
	//Check also:
	//http://tracker.h3x.eu/corpus/690
	//http://tracker.h3x.eu/info/690
	//Samples:
	//https://github.com/gh0std4ncer/lizkebab/blob/master/client.c
	//ELF magic
	//Contains majority of commands
	//Contains some message strings
        // Check also:
        // https://wiki.egi.eu/w/images/c/ce/Report-venom.pdf
        //ELF magic
        //Contains all of the strings
		//MSComctlLib.ListViewCtrl.2 GUID={BDD1F04B-858B-11D1-B16A-00C0F0283628}
                // DOC/Composite file magic
                //GUID of URL Moniker =  79EAC9E0-BAF9-11CE-8C82-00AA004BA90B
		//IID_IMoniker is defined as 0000000f-0000-0000-C000-000000000046
                // too poor for detection
                // DOC/Composite file magic
    // Parsers will open files without the full 'rtf'
    // Marks of embedded
    // RTF format
    // OLE format
    // Mandatory header plus sign of embedding, then any of the others
	// MZ at the beginning of file
                //Check also:
                //https://insights.sei.cmu.edu/sei_blog/2012/11/writing-effective-yara-signatures-to-identify-malware.html
                //Contains all of the strings
        //DOC file magic
        //Check also:
        //https://community.hpe.com/t5/Security-Research/Feeling-even-Locky-er/ba-p/6834311
        //Check also:
        //https://community.hpe.com/t5/Security-Research/Feeling-even-Locky-er/ba-p/6834311
        //Check also:
        //https://community.hpe.com/t5/Security-Research/Feeling-even-Locky-er/ba-p/6834311
		//$file_name_1 = "msisvcd.dll"
		//$file_name_2 = "mstisvc.dll"
	 	//file_type contains "pe"
		//and file_name contains ( $file_name_* )
		//File starts with MZ
		//File starts with MZ
		//File starts with MZ
		// file_type contains "pedll"
		//and file_name contains "apphelp.dll"
         //file_type contains "MZ"
        // EMBEDDED FLASH OBJECT BIN HEADER   
        // OBJECT APPLICATION TYPE TITLE
        // disabled 2/13/18 due to false positive on 2a75ff1acdf9141bfb836343f94f4a73b8c64b226b0e2ae30a69e9aacc472cba
        // $title = "Adobe Flex" wide ascii   
        // PDB PATH    
        // LOADER STRINGS   
        // 1a3269253784f76e3480e4b3de312dfee878f99045ccfd2231acb5ba57d8ed0d.fws exploit specific multivar definition.
        // 53fa83d02cc60765a75abd0921f5084c03e0b7521a61c4260176e68b6a402834 exploit specific.
        // disabled 2/13/18 due to false positive on 2a75ff1acdf9141bfb836343f94f4a73b8c64b226b0e2ae30a69e9aacc472cba
        //(all of ($header*) and all of ($title*) and 3 of ($loader*))
        //    or
        /* match WEB on the first line of a file
           takes into account potential whitespace before or after case-insensitive "WEB" string
        */
        /* match any http or https URL within the file */
        /*
           match WEB on the first line of a file
           takes into account potential whitespace before or after case-insensitive "WEB" string
        */
        /* match any http or https URL using a direct IP address */
        /* file upload/download providers */
        /* URL shorteners */
        /*
           match WEB on the first line of a file
           takes into account potential whitespace before or after case-insensitive "WEB" string
        */
        /*
            generic URL to direct download a file containing a potentially malicious extension.
            File extensions were decided based upon common extensions seen in the wild
            The extension list can be expanded upon as new information comes available from matches
            on the Stage 1 or Stage 2 signatures
         */
        /*
            sample payloads:
                https://www.virustotal.com/#/file/76b70f1dfd64958fca7ab3e18fffe6d551474c2b25aaa9515181dec6ae112895/details
                download: https://github.com/InQuest/malware-samples/blob/master/2018-08-Hidden-Bee-Elements/11310b509f8bf86daa5577758e9d1eb5

                https://www.virustotal.com/#/file/c1a6df241239359731c671203925a8265cf82a0c8c20c94d57a6a1ed09dec289/details
                download: https://github.com/InQuest/malware-samples/blob/master/2018-08-Hidden-Bee-Elements/b3eb576e02849218867caefaa0412ccd

             $ yara Hidden_Bee_Elements.rule -wr ../malware-samples/2018-08-Hidden-Bee-Elements/
                 Hidden_Bee_Elements ../malware-samples/2018-08-Hidden-Bee-Elements//b3eb576e02849218867caefaa0412ccd
                 Hidden_Bee_Elements ../malware-samples/2018-08-Hidden-Bee-Elements//11310b509f8bf86daa5577758e9d1eb5

            IDA loader module creation write-up and source from @RolfRolles:
                http://www.msreverseengineering.com/blog/2018/9/2/weekend-project-a-custom-ida-loader-module-for-the-hidden-bee-malware-family
                https://github.com/RolfRolles/HiddenBeeLoader

            Binary file format struct from @hasherezade:
                typedef struct {
                    DWORD magic;

                    WORD dll_list;
                    WORD iat;
                    DWORD ep;
                    DWORD mod_size;

                    DWORD relocs_size;
                    DWORD relocs;
                } t_bee_hdr;
        */
        // case-insensitive base64 http:// or https:// URI prefix
        // algorithm behind this generation magic: http://www.erlang-factory.com/upload/presentations/225/ErlangFactorySFBay2010-RobKing.pdf
            // at least 3 known DLL imports in the first 128 bytes.
            // base64 encoded URLs.
        // we have three regexes here so that we catch all possible orderings but still meet the requirement of all three parts.
        /*$conf = {00 00 00 00 00 00 00 00 00 7E}*/
               /* $s3 = { 0A F1 2? }      //Rslinx*/
//hunting rule    
    // Reduce FPs on other DOCF documents by requiring Outlook specific properties
    // Could be improved by taking further items from MS-OXMSG specs.
    // TODO: Is there any requirement to signature RFC822 emails?
    // SWF class identifiers, as embedded in the document
    // Parsers will open files without the full 'rtf'
    // Marks of embedded data (reduce FPs)
    // RTF format
    // XML Office documents
    // OLE format
    // Mandatory header plus sign of embedding, then any of the others
    // Parsers will open files without the full 'rtf'
    // Marks of embedded data (reduce FPs)
    // RTF format
    // XML Office documents
    // OLE format
    // Mandatory header plus sign of embedding, then any of the others
    // "Package" as embedded in objdata stream
    /*
      59                      pop     ecx
      5B                      pop     ebx
      6A 69                   push    'i'
      68 70 2E 6D 73          push    'sm.p'
      68 73 65 74 75          push    'utes'
      54                      push    esp             ; Source
      FF 35 04 20 00 10       push    ds:lpFileName   ; Dest
      E8 29 1F 00 00          call    strcat
    */
    // String stacking for 'setup.msi'
    /*
      48                      dec     eax
      83 F8 00                cmp     eax, 0
      0F 84 B2 00 00 00       jz      loc_10001171
      8A 18                   mov     bl, [eax]
      80 F3 5C                xor     bl, 5Ch
      80 FB 00                cmp     bl, 0
    */
    // Generic toolmarks from the compiler
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
		// vvv---- this sig hits on a legit CRT function it seems. 
  	// vvv---- this sig hits on a legit CRT function it seems. 
	/*
		8A 0C 18  mov     cl, [eax+ebx]
		80 F1 63  xor     cl, 63h
		88 0C 18  mov     [eax+ebx], cl
		8B 4D 00  mov     ecx, [ebp+0]
		40        inc     eax
		3B C1     cmp     eax, ecx
		72 EF     jb      short loc_4010B4
	*/
	/*
		50                 push    eax             ; argp
		68 7E 66 04 80     push    8004667Eh       ; cmd
		8B 8D DC FE FF FF  mov     ecx, [ebp+skt]
		51                 push    ecx             ; s
		FF 15 58 31 41 00  call    ioctlsocket
		83 F8 FF           cmp     eax, 0FFFFFFFFh
		75 08              jnz     short loc_4043F0
	*/
	/*
		E8 C3 FE FF FF     call    generate64ByteRandomNumber
		68 C8 01 00 00     push    1C8h            ; dwLength
		68 D8 E8 40 00     push    offset g_Config ; pvBuffer
		A3 80 EA 40 00     mov     dword ptr g_Config.qwIdentifier, eax
		89 15 84 EA 40 00  mov     dword ptr g_Config.qwIdentifier+4, edx
		E8 F9 E9 FF FF     call    DNSCALCDecode
		83 C4 08           add     esp, 8
		8D 4C 24 08        lea     ecx, [esp+214h+var_20C]
		6A 00              push    0
		51                 push    ecx
		68 C8 01 00 00     push    1C8h
		68 D8 E8 40 00     push    offset g_Config
		56                 push    esi
		FF 15 74 E7 40 00  call    WriteFile_9
		56                 push    esi
		FF 15 6C E7 40 00  call    CloseHandle_9
	*/
	/*
		FF 15 DC 2D 41 00  call    ReadFile_0
		8B 44 24 20        mov     eax, [esp+25Ch+offsetInFile]
		8B 54 24 1C        mov     edx, [esp+25Ch+dwEmbedCnt]
		35 78 56 34 12     xor     eax, 12345678h
		55                 push    ebp
		55                 push    ebp
		81 F2 78 56 34 12  xor     edx, 12345678h
		50                 push    eax
		57                 push    edi
		89 54 24 2C        mov     [esp+26Ch+dwEmbedCnt], edx
		89 44 24 30        mov     [esp+26Ch+offsetInFile], eax
		FF 15 E0 2D 41 00  call    SetFilePointer_0
	*/
	/*
		69 C0 28 01 00 00  imul    eax, 128h
		50                 push    eax             ; size_t
		53                 push    ebx             ; int
		FF B5 AC FD FF FF  push    [ebp+configRecords]; void *
		E8 6E 08 00 00     call    _memset
		8B 85 A4 FC FF FF  mov     eax, [ebp+var_35C.dwRecordCnt]
		69 C0 28 01 00 00  imul    eax, 128h
		50                 push    eax             ; size_t
		8B 85 C4 FE FF FF  mov     eax, [ebp+hMem]
		05 08 01 00 00     add     eax, 108h
		50                 push    eax             ; void *
		FF B5 AC FD FF FF  push    [ebp+configRecords]; void *
		E8 0A 05 00 00     call    _memcpy
		83 C4 18           add     esp, 18h
		8B BD A4 FC FF FF  mov     edi, [ebp+var_35C.dwRecordCnt]
		69 FF 28 01 00 00  imul    edi, 128h
		81 C7 08 01 00 00  add     edi, 108h
	*/
	/*
		FF D6        call    esi ; rand
		8B F8        mov     edi, eax
		C1 E7 10     shl     edi, 10h
		FF D6        call    esi ; rand
		03 F8        add     edi, eax
		89 7C 24 20  mov     [esp+2A90h+var_2A70], edi
		FF D6        call    esi ; rand
		8B F8        mov     edi, eax
		C1 E7 10     shl     edi, 10h
		FF D6        call    esi ; rand
		03 F8        add     edi, eax
		89 7C 24 24  mov     [esp+2A90h+var_2A6C], edi
	*/
	/*
		6A 0A              push    0Ah             ; int
		8D 85 C4 E4 FF FF  lea     eax, [ebp+Source]
		68 10 02 00 00     push    210h            ; unsigned int
		50                 push    eax             ; void *
		E8 FA 60 00 00     call    ??_L@YGXPAXIHP6EX0@Z1@Z; `eh vector constructor iterator'(void *,uint,int,void (*)(void *),void (*)(void *))
	*/
		/*
		.text:10001850                 push    7530h           ; dwTimeout
		.text:10001855                 lea     eax, [esp+420h+a2]
		.text:10001859                 push    4               ; len
		.text:1000185B                 push    eax             ; a2
		.text:1000185C                 push    esi             ; s
		.text:1000185D                 mov     dword ptr [esp+42Ch+a2], 1000h
		.text:10001865                 call    CommSendWithTimeout
		.text:1000186A                 add     esp, 14h
		.text:1000186D                 cmp     eax, 0FFFFFFFFh
		.text:10001870                 jz      loc_10001915
		.text:10001876                 lea     ecx, [esp+418h+random]
		.text:1000187A                 push    ecx             ; a1
		.text:1000187B                 call    Generate16ByteRandomBuffer
		.text:10001880                 push    0               ; fEncrypt
		.text:10001882                 push    7530h           ; dwTimeout		
		*/
		/*
			68 00 28 00 00     push    2800h
			56                 push    esi
			E8 38 F7 FF FF     call    sub_401000
			// optionally there is a "add esp, 8" in some variants here
			8D 44 24 28        lea     eax, [esp+270h+NumberOfBytesWritten]
			6A 00              push    0               ; lpOverlapped
			50                 push    eax             ; lpNumberOfBytesWritten
			68 00 28 00 00     push    2800h           ; nNumberOfBytesToWrite
			56                 push    esi             ; lpBuffer
			53                 push    ebx             ; hFile
			FF 15 6C 80 40 00  call    ds:WriteFile
			81 ED 00 28 00 00  sub     ebp, 2800h
			81 C7 00 28 00 00  add     edi, 2800h
			81 C6 00 28 00 00  add     esi, 2800h
		*/
	/*
		// Service installation code
		FF 15 68 30 40 00  call    ds:wsprintfA
		83 C4 18           add     esp, 18h
		8D 85 FC FE FF FF  lea     eax, [ebp+var_104]
		56                 push    esi
		56                 push    esi
		56                 push    esi
		56                 push    esi
		56                 push    esi
		50                 push    eax
		6A 01              push    1
		// some variants have these two lines added
		5E                 pop     esi
		56                 push    esi

		6A 02              push    2
		68 20 01 00 00     push    120h
		68 FF 01 0F 00     push    0F01FFh
		FF 75 0C           push    [ebp+arg_4]
		FF 75 08           push    [ebp+arg_0]
		
		// some variants have the next line as a push {reg} or push {stack var}
		53                 push    ebx
		//or
		FF 75 FC           push    [ebp+var_4]

		FF 15 E4 49 40 00  call    CreateServiceA
	*/
		/*
		push    <variable>
		call    GetAsyncKeyState
		cmp     ax, 8001h
		jnz     short loc_4021EE
		push    <variable>             ; a1
		call    AddCharacterToKeyLogBuffer
		add     esp, 4
		
		this block of code is used multiple times in sequence so i'm looking for 5 consecutive blocks
		*/
	/*
		6A 2A                    push    2Ah
		C6 84 24 C4 00 00 00 D6  mov     [esp+70Ch+var_648], 0D6h
		C6 84 24 C5 00 00 00 E1  mov     [esp+70Ch+var_647], 0E1h
		C6 84 24 C6 00 00 00 BF  mov     [esp+70Ch+var_646], 0BFh
		C6 84 24 C7 00 00 00 C8  mov     [esp+70Ch+var_645], 0C8h
		C6 84 24 C8 00 00 00 C3  mov     [esp+70Ch+var_644], 0C3h
		C6 84 24 C9 00 00 00 BD  mov     [esp+70Ch+var_643], 0BDh
		88 9C 24 CA 00 00 00     mov     [esp+70Ch+var_642], bl
		FF 15 48 5B 40 00        call    GetAsyncKeyState
		66 3D 01 80              cmp     ax, 8001h
		75 20                    jnz     short loc_401696
		8D 94 24 00 01 00 00     lea     edx, [esp+708h+pszOutput]
		8D 84 24 C0 00 00 00     lea     eax, [esp+708h+var_648]
		52                       push    edx             ; pszOutput
		6A 07                    push    7               ; dwLength
		50                       push    eax             ; pszInput
		E8 A3 F9 FF FF           call    DNSCALCDecode
		50                       push    eax             ; a1
		E8 7D FB FF FF           call    AddEntryToKeylogDataBuffer
		83 C4 10                 add     esp, 10h
	*/
	/*
		6A 2A                          push    2Ah
		C7 85 74 FF FF FF D6 E1 BF C8  mov     dword ptr [ebp+var_8C], 0C8BFE1D6h
		66 C7 85 78 FF FF FF C3 BD     mov     [ebp+var_88], 0BDC3h
		88 9D 7A FF FF FF              mov     [ebp+var_86], bl
		FF 15 04 47 41 00              call    GetAsyncKeyState
		BA 01 80 FF FF                 mov     edx, 0FFFF8001h
		66 3B C2                       cmp     ax, dx
		75 1E                          jnz     short loc_4018B0
		8D 85 CC FE FF FF              lea     eax, [ebp+a3]
		50                             push    eax             ; a3
		8D 8D 74 FF FF FF              lea     ecx, [ebp+var_8C]
		6A 07                          push    7               ; dwLength
		51                             push    ecx             ; a1
		E8 89 F7 FF FF                 call    DNSCalcDecode
		50                             push    eax             ; a1
		E8 83 F9 FF FF                 call    RecordStringToLog
		83 C4 10                       add     esp, 10h
	*/
	/*
		33 C0              xor     eax, eax
		66 8B 02           mov     ax, [edx]
		8B E8              mov     ebp, eax
		81 E5 00 F0 FF FF  and     ebp, 0FFFFF000h
		81 FD 00 30 00 00  cmp     ebp, 3000h
		75 0D              jnz     short loc_4019FB
		8B 6C 24 18        mov     ebp, [esp+10h+arg_4]
		25 FF 0F 00 00     and     eax, 0FFFh
		03 C7              add     eax, edi
		01 28              add     [eax], ebp
	*/
	/*
		83 C4 34        add     esp, 34h
		83 FD 0A        cmp     ebp, 0Ah
		5D              pop     ebp
		5B              pop     ebx
		7E 12           jle     short loc_1000106F
		57              push    edi             ; Src
		C6 07 4D        mov     byte ptr [edi], 4Dh
		C6 47 01 5A     mov     byte ptr [edi+1], 5Ah
		E8 97 01 00 00  call    ManualImageLoad
	*/
	/*
		FF 76 74           push    dword ptr [esi+74h]
		59                 pop     ecx
		50                 push    eax
		8F 86 48 01 00 00  pop     dword ptr [esi+148h]
		85 C0              test    eax, eax
		51                 push    ecx
		8F 86 44 01 00 00  pop     dword ptr [esi+144h]
		75 3D              jnz     short loc_100035F3
		F6 46 56 01        test    byte ptr [esi+56h], 1
		74 0A              jz      short loc_100035C6
	*/
	/*
		48 8B 4B 70           mov     rcx, [rbx+70h]
		48 89 8B 60 01 00 00  mov     [rbx+160h], rcx
		48 89 83 68 01 00 00  mov     [rbx+168h], rax
		48 85 C0              test    rax, rax
		75 35                 jnz     short loc_180002372
		F6 43 56 01           test    byte ptr [rbx+56h], 1
		74 07                 jz      short loc_18000234A
	*/
	/*
		8B 69 FC           mov     ebp, [ecx-4]
		83 C1 10           add     ecx, 10h
		81 F5 6D 3A 71 58  xor     ebp, 58713A6Dh
		89 2A              mov     [edx], ebp
		33 ED              xor     ebp, ebp
		66 8B 69 F0        mov     bp, [ecx-10h]
		89 6A 04           mov     [edx+4], ebp
		83 C2 08           add     edx, 8
		4F                 dec     edi
		75 E3              jnz     short loc_4026CE
	*/
	/*
		66 81 BC 24 A0 00 00 00 BB 01  cmp     [esp+98h+arg_4], 1BBh
		74 21                          jz      short loc_401BD7
		FF 15 58 30 40 00              call    ds:rand
		99                             cdq
		B9 32 00 00 00                 mov     ecx, 32h
		F7 F9                          idiv    ecx
		8B DA                          mov     ebx, edx
		8D 54 24 5E                    lea     edx, [esp+98h+var_3A]
		53                             push    ebx             ; dwSize
		52                             push    edx             ; pvBuffer
		E8 3F FB FF FF                 call    GenerateRandomBuffer
		83 C4 08                       add     esp, 8
		83 C3 46                       add     ebx, 46h
	*/
	/*
		68 C4 94 41 00     push    offset a0_0_0_0 ; "0.0.0.0"
		56                 push    esi             ; wchar_t *
		E8 1C B4 00 00     call    _wcscpy
		83 C6 28           add     esi, 28h
		83 C4 08           add     esp, 8
		81 FE E8 CD 41 00  cmp     esi, offset unk_41CDE8
		7C E7              jl      short loc_4039DA
	*/
		// push    esi                              
		// mov     esi, [esp+4+a1]                  
		// test    esi, esi                         
		// jle     short loc_403FEB                 
		// push    edi                              
		// mov     edi, ds:Sleep                    
		// push    0EA60h          ; dwMilliseconds 
		// call    edi ; Sleep                      
		// dec     esi                              
		// jnz     short loc_403FE0                 
		// pop     edi                              
		// pop     esi                              
		// retn                                     
	/*
		E8 D9 FC FF FF  call    SendData
		83 C4 10        add     esp, 10h
		85 C0           test    eax, eax
		74 0A           jz      short loc_10003FE8
		B8 02 00 00 00  mov     eax, 2
		5E              pop     esi
		83 C4 18        add     esp, 18h
		C3              retn
		6A 78           push    78h             ; dwTimeout
		6A 01           push    1               ; fDecode
		8D 54 24 18     lea     edx, [esp+24h+recvData]
		6A 0C           push    0Ch             ; dwLength
		52              push    edx             ; pvBuffer
		56              push    esi             ; skt
		E8 57 FD FF FF  call    RecvData
		83 C4 14        add     esp, 14h
		85 C0           test    eax, eax
		74 0A           jz      short loc_1000400A
		B8 02 00 00 00  mov     eax, 2
	*/
	/*
		81 E3 FF FF 00 00  and     ebx, 0FFFFh
		8B EB              mov     ebp, ebx
		57                 push    edi
		C1 EE 10           shr     esi, 10h
		81 E5 FF FF 00 00  and     ebp, 0FFFFh
		8B FE              mov     edi, esi
		8B C5              mov     eax, ebp
		81 E7 FF FF 00 00  and     edi, 0FFFFh
		C1 E0 10           shl     eax, 10h
		6A 00              push    0               ; _DWORD
		0B C7              or      eax, edi
		6A 00              push    0               ; _DWORD
		50                 push    eax             ; _DWORD
		68 10 14 11 71     push    offset sub_71111410; _DWORD
		6A 00              push    0               ; _DWORD
		6A 00              push    0               ; _DWORD
		FF 15 5C 8E 12 71  call    CreateThread_0
		C1 E7 10           shl     edi, 10h
	*/
	/*
	source: 641808833ad34f2e5143001c8147d779dbfd2a80a80ce0cfc81474d422882adb
		25 00 20 00 00     and     eax, 2000h
		3D 00 20 00 00     cmp     eax, 2000h
		0F 94 C1           setz    cl
		81 E2 80 00 00 00  and     edx, 80h
		33 C0              xor     eax, eax
		80 FA 80           cmp     dl, 80h
		0F 94 C0           setz    al
		03 C8              add     ecx, eax
		33 D2              xor     edx, edx
		83 F9 01           cmp     ecx, 1
	*/
	/*
		E8 78 00 00 00  call    GenerateRandomBuffer
		33 C0           xor     eax, eax
		8A 4C 04 04     mov     cl, [esp+eax+24h+buffer]
		80 E9 22        sub     cl, 22h
		80 F1 AD        xor     cl, 0ADh
		88 4C 04 04     mov     [esp+eax+24h+buffer], cl
		40              inc     eax
		83 F8 10        cmp     eax, 10h
		7C EC           jl      short loc_1000117A
		6A 01           push    1               ; fEncode
		8D 54 24 08     lea     edx, [esp+28h+buffer]
		6A 10           push    10h             ; dwDataLength
		52              push    edx             ; pvData
		8B CB           mov     ecx, ebx        ; this
		E8 A2 00 00 00  call    CSocket__Send
	*/
	/*
		C7 44 24 08 01 00 00 00  mov     [esp+128h+argp], 1
		8B 8C 24 30 01 00 00     mov     ecx, dword ptr [esp+128h+wPort]
		C7 44 24 04 00 00 20 03  mov     dword ptr [esp+128h+optval], 3200000h
		51                       push    ecx             ; hostshort
		89 44 24 1C              mov     dword ptr [esp+12Ch+name.sin_addr.S_un], eax
		FF 15 8C 01 FF 7E        call    ds:htons
		6A 06                    push    6               ; protocol
		6A 01                    push    1               ; type
		6A 02                    push    2               ; af
		66 89 44 24 22           mov     [esp+134h+name.sin_port], ax
		66 C7 44 24 20 02 00     mov     [esp+134h+name.sin_family], 2
		FF 15 84 01 FF 7E        call    ds:socket								     <--- this could be a relative call in some variants
		83 F8 FF                 cmp     eax, 0FFFFFFFFh
		89 46 04                 mov     [esi+4], eax
		0F 84 AD 00 00 00        jz      loc_7EFE4C63
		57                       push    edi
		8B 3D 88 01 FF 7E        mov     edi, ds:setsockopt            <---- this line is missing when relative calls are used
		8D 54 24 08              lea     edx, [esp+12Ch+optval]
		6A 04                    push    4               ; optlen
		52                       push    edx             ; optval
		68 02 10 00 00           push    1002h           ; optname
		68 FF FF 00 00           push    0FFFFh          ; level
		50                       push    eax             ; s
		FF D7                    call    edi ; setsockopt								<--- this could be a relative call in some variants
		8B 4E 04                 mov     ecx, [esi+4]
		8D 44 24 08              lea     eax, [esp+12Ch+optval]
		6A 04                    push    4               ; optlen
		50                       push    eax             ; optval
		68 01 10 00 00           push    1001h           ; optname
		68 FF FF 00 00           push    0FFFFh          ; level
		51                       push    ecx             ; s
		FF D7                    call    edi ; setsockopt								<--- this could be a relative call in some variants
	*/
		//$connect = {C7 [3] 01 00 00 00 8B [6] C7 [3] 00 00 20 03 5? 89 [3] (FF 15 [4] | E8 [4]) 6A 06 6A 01 6A 02 66 [4] 66 [4] 02 00 (FF 15 [4] | E8 [4]) 83 F8 FF 89 [2] 0F 84 [4] [0-7] 8D [3] 6A 04 5? 68 02 10 00 00 68 FF FF 00 00 5? (FF D? | E8 [4]) 8B [2] 8D [3] 6A 04 5? 68 01 10 00 00 68 FF FF 00 00 5? (FF D? | E8 [4])}
	/*
		FF 15 70 80 01 10  call    ds:GetTickCount
		50                 push    eax             ; unsigned int
		E8 80 93 00 00     call    _srand
		83 C4 04           add     esp, 4
		E8 85 93 00 00     call    _rand
		C1 E0 10           shl     eax, 10h
		89 46 0C           mov     [esi+0Ch], eax
		E8 7A 93 00 00     call    _rand
		01 46 0C           add     [esi+0Ch], eax
		E8 72 93 00 00     call    _rand
		C1 E0 10           shl     eax, 10h
		89 46 08           mov     [esi+8], eax
		E8 67 93 00 00     call    _rand
		01 46 08           add     [esi+8], eax
	*/
	/*
		E8 D3 C7 00 00  call    rand
		44 8B ED        mov     r13d, ebp
		44 8B E0        mov     r12d, eax
		B8 1F 85 EB 51  mov     eax, 51EB851Fh
		48 8B FD        mov     rdi, rbp
		41 F7 EC        imul    r12d
		C1 FA 05        sar     edx, 5
		8B CA           mov     ecx, edx
		C1 E9 1F        shr     ecx, 1Fh
		03 D1           add     edx, ecx
		6B D2 64        imul    edx, 64h
		44 2B E2        sub     r12d, edx
		41 83 C4 3C     add     r12d, 3Ch
	*/
	/*
		FF 15 40 70 01 10     call    ds:GetDiskFreeSpaceExA
		85 C0                 test    eax, eax
		74 34                 jz      short loc_10005072
		8B 84 24 20 01 00 00  mov     eax, [esp+11Ch+arg_0]
		6A 00                 push    0
		99                    cdq
		68 00 00 10 00        push    100000h
		52                    push    edx
		50                    push    eax
		E8 4C 7C 00 00        call    __allmul
	*/
	/*
		FF 15 78 A2 00 10  call    GetTickCount_9
		66 8B C8           mov     cx, ax

		// the next op is a mov or a push/pop depending on the code version
		53                 push    ebx
		8F 45 F4           pop     dword ptr [ebp-0Ch]
		//or
		89 5D F4           mov     dword ptr [ebp+var_C], ebx
		
		
		66 81 F1 40 1C     xor     cx, 1C40h
		66 D1 E9           shr     cx, 1
		81 C1 E0 56 00 00  add     ecx, 56E0h
		0F B7 C9           movzx   ecx, cx
		0F B7 C0           movzx   eax, ax
		81 F1 30 32 00 00  xor     ecx, 3230h
		C1 E0 10           shl     eax, 10h
		0B C8              or      ecx, eax
	*/
	/*
		FF 15 D8 5B 00 10  call    GetTickCount_9
		0F B7 C0           movzx   eax, ax
		8B C8              mov     ecx, eax
		// skipped: 6A 01              push    1               ; fDecode
		C1 E9 34           shr     ecx, 34h         <--- this value could change
		81 F1 C0 F3 00 00  xor     ecx, 0F3C0h			<--- this value could change
		// skipped: 6A 04              push    4               ; dwLength
		C1 E0 10           shl     eax, 10h
		0B C8              or      ecx, eax
	*/
	/*
		B9 10 00 00 00     mov     ecx, 10h        ; ecx = 16
		8B 06              mov     eax, [esi]      ; eax = lastValue
		C1 EA 10           shr     edx, 10h        ; edx = val >> 16
		81 E2 FF 7F 00 00  and     edx, 7FFFh      ; edx = (val >> 16) & 0x7FFF
		03 C2              add     eax, edx        ; eax = ((val >> 16) & 0x7FFF) + lastValue
		8B D0              mov     edx, eax        ; edx = ((val >> 16) & 0x7FFF) + lastValue
		8B F8              mov     edi, eax        ; edi = ((val >> 16) & 0x7FFF) + lastValue
		83 E2 0F           and     edx, 0Fh        ; edx = (((val >> 16) & 0x7FFF) + lastValue) & 0xF
		2B CA              sub     ecx, edx        ; ecx = 16 - ((((val >> 16) & 0x7FFF) + lastValue)) & 0xF
		D3 EF              shr     edi, cl         ; edi = (((val >> 16) & 0x7FFF) + lastValue) >> ((16 - ((val >> 16) & 0x7FFF) + lastValue) & 0xF)
		8B CA              mov     ecx, edx        ; ecx = (((val >> 16) & 0x7FFF) + lastValue) & 0xF
		D3 E0              shl     eax, cl         ; eax = (((val >> 16) & 0x7FFF) + lastValue) << ((((val >> 16) & 0x7FFF) + lastValue) & 0xF)
		0B F8              or      edi, eax        ; edi = (((val >> 16) & 0x7FFF) + lastValue) >> ((16 - ((val >> 16) & 0x7FFF) + lastValue) & 0xF) | (((val >> 16) & 0x7FFF) + lastValue) << ((((val >> 16) & 0x7FFF) + lastValue) & 0xF)
		89 3E              mov     [esi], edi      ; pLastValue = (((val >> 16) & 0x7FFF) + lastValue) >> ((16 - ((val >> 16) & 0x7FFF) + lastValue) & 0xF) | (((val >> 16) & 0x7FFF) + lastValue) << ((((val >> 16) & 0x7FFF) + lastValue) & 0xF)
	*/
	/*
		F3 AB     rep stosd
		80 3A 00  cmp     byte ptr [edx], 0
		74 15     jz      short loc_404170
		8A 02     mov     al, [edx]
		3C 2E     cmp     al, 2Eh
		74 07     jz      short loc_404168
		3C 20     cmp     al, 20h
		74 03     jz      short loc_404168
		88 06     mov     [esi], al
		46        inc     esi
	*/
	/*
		24 10           and     al, 10h
		0C 10           or      al, 10h
		89 07           mov     [edi], eax
		66 8B 44 24 14  mov     ax, [esp+0Ch+wCipherSuiteID]
		66 3D 00 C0     cmp     ax, 0C000h
		73 34           jnb     short loc_4067C1
		66 2D 35 00     sub     ax, 35h
		66 F7 D8        neg     ax
		1B C0           sbb     eax, eax
		24 80           and     al, 80h
		05 00 01 00 00  add     eax, 100h
		8B D8           mov     ebx, eax
		53              push    ebx             ; hostshort
	*/
	/*
		8A 04 17  mov     al, [edi+edx]
		8B FB     mov     edi, ebx
		34 A7     xor     al, 0A7h
		46        inc     esi
		88 02     mov     [edx], al
		83 C9 FF  or      ecx, 0FFFFFFFFh
		33 C0     xor     eax, eax
		42        inc     edx
		F2 AE     repne scasb
		F7 D1     not     ecx
		49        dec     ecx
		3B F1     cmp     esi, ecx
	*/
	/*
		83 C4 04           add     esp, 4
		50                 push    eax             ; lpProcName
		56                 push    esi             ; hModule
		FF 15 20 F0 40 00  call    ds:GetProcAddress
		68 A8 0C 41 00     push    offset aLo_adlIbr_arYw; "Lo.adL ibr.ar yW"
		A3 DC 3E 41 00     mov     GetProcAddress_0, eax
		E8 7D FF FF FF     call    CleanupString
		83 C4 04           add     esp, 4
		50                 push    eax             ; _DWORD
		56                 push    esi             ; _DWORD
		FF 15 DC 3E 41 00  call    GetProcAddress_0
		68 94 0C 41 00     push    offset aLoad_LibR_arYa; "Load. Lib r.ar yA"
		A3 D4 3E 41 00     mov     LoadLibraryW, eax
		E8 63 FF FF FF     call    CleanupString
		83 C4 04           add     esp, 4
		50                 push    eax             ; _DWORD
		56                 push    esi             ; _DWORD
		FF 15 DC 3E 41 00  call    GetProcAddress_0
		68 80 0C 41 00     push    offset a_frE_eliBr_arY; ".Fr e.eLi br.ar y"
		A3 D8 3E 41 00     mov     LoadLibraryA_0, eax
		E8 49 FF FF FF     call    CleanupString
	*/
	/*
		8A 10     mov     dl, [eax]
		80 F2 73  xor     dl, 73h					<--- for decoding and encoding, this and
		80 EA 3A  sub     dl, 3Ah					<--- this could be reversed, but the sig holds since both are 0x80
		88 10     mov     [eax], dl
		40        inc     eax
		49        dec     ecx
		75 F2     jnz     short loc_1000403C
	*/
	/*
		25 07 00 00 80  and     eax, 80000007h
		79 05           jns     short loc_405EC8; um, nope.. this will always happen
		48              dec     eax
		83 C8 F8        or      eax, 0FFFFFFF8h
		40              inc     eax
	*/
	/*
		66 81 44 24 0C FE FF  add     [esp+1Ch+SystemTime.wYear], 0FFFEh
		FF D6                 call    esi ; rand
		99                    cdq
		B9 0C 00 00 00        mov     ecx, 0Ch
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 0E        mov     [esp+1Ch+SystemTime.wMonth], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 1C 00 00 00        mov     ecx, 1Ch
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 12        mov     [esp+1Ch+SystemTime.wDay], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 17 00 00 00        mov     ecx, 17h
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 14        mov     [esp+1Ch+SystemTime.wHour], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 3B 00 00 00        mov     ecx, 3Bh
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 16        mov     [esp+1Ch+SystemTime.wMinute], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 3B 00 00 00        mov     ecx, 3Bh
		F7 F9                 idiv    ecx
	*/
	/*
		68 00 00 00 80     push    80000000h       ; a2
		8B 02              mov     eax, [edx]
		8B 4A 04           mov     ecx, [edx+4]
		89 4C 24 10        mov     [esp+2Ch+var_1C], ecx
		8B 4A 08           mov     ecx, [edx+8]
		89 4C 24 14        mov     [esp+2Ch+var_18], ecx
		8B 4A 0C           mov     ecx, [edx+0Ch]
		8D 54 24 1C        lea     edx, [esp+2Ch+var_10]
		89 8E 70 03 00 00  mov     [esi+370h], ecx
		52                 push    edx             ; a1
		8B CE              mov     ecx, esi
		89 86 6C 03 00 00  mov     [esi+36Ch], eax
		E8 29 FF FF FF     call    GetCPUIDValues
		8B C8              mov     ecx, eax
		8B 01              mov     eax, [ecx]
		3D 00 00 00 80     cmp     eax, 80000000h
		8B 51 04           mov     edx, [ecx+4]
	*/
	/*
		8D 54 24 08              lea     edx, [esp+128h+argp]
		52                       push    edx             ; argp
		68 7E 66 04 80           push    8004667Eh       ; cmd
		56                       push    esi             ; s
		E8 DB 51 00 00           call    ioctlsocket
		8D 44 24 14              lea     eax, [esp+128h+name]
		6A 10                    push    10h             ; namelen
		50                       push    eax             ; name
		56                       push    esi             ; s
		E8 C8 51 00 00           call    connect
		8B 8C 24 34 01 00 00     mov     ecx, [esp+128h+dwTimeout]
		8D 54 24 0C              lea     edx, [esp+128h+timeout]
		52                       push    edx             ; timeout
		8D 44 24 28              lea     eax, [esp+12Ch+writefds]
		6A 00                    push    0               ; exceptfds
		50                       push    eax             ; writefds
		6A 00                    push    0               ; readfds
		6A 00                    push    0               ; nfds
		89 74 24 3C              mov     [esp+13Ch+writefds.fd_array], esi
		89 7C 24 38              mov     [esp+13Ch+writefds.fd_count], edi
		89 4C 24 20              mov     [esp+13Ch+timeout.tv_sec], ecx
		C7 44 24 24 00 00 00 00  mov     [esp+13Ch+timeout.tv_usec], 0
		E8 92 51 00 00           call    select
		33 C9                    xor     ecx, ecx
		56                       push    esi             ; s
		85 C0                    test    eax, eax
		0F 9F C1                 setnle  cl
		8B F9                    mov     edi, ecx
		E8 7D 51 00 00           call    closesocket
	*/
	/*
		E8 D8 62 00 00                                call    rand
		8B F8                                         mov     edi, eax
		E8 D1 62 00 00                                call    rand
		0F AF F8                                      imul    edi, eax
		E8 C9 62 00 00                                call    rand
		0F AF C7                                      imul    eax, edi
		99                                            cdq
		33 C2                                         xor     eax, edx
		2B C2                                         sub     eax, edx
		33 D2                                         xor     edx, edx
		F7 F6                                         div     esi
		8B FA                                         mov     edi, edx
		57                                            push    edi
		E8 05 13 00 00                                call    sub_402BD0
	*/
		/*
		.text:00403D5A                 mov     word ptr [esi+0Eh], 0C807h
		.text:00403D60                 mov     dword ptr [esi+39h], 800000D4h
		.text:00403D67                 mov     byte ptr [edi], 0Ch							<---- ignored
		.text:00403D6A                 mov     word ptr [esi+25h], 0FFh
		.text:00403D70                 mov     word ptr [esi+27h], 0A4h
		.text:00403D76                 mov     word ptr [esi+29h], 4104h
		.text:00403D7C                 mov     word ptr [esi+2Bh], 32h
		
		or
		
		.text:100036F9                 mov     word ptr [ebx+0Eh], 0C807h
														---- begin ignored -----
		.text:100036FF                 rep movsd
		.text:10003701                 lea     edi, [ebx+60h]
		.text:10003704                 mov     ecx, 9
		.text:10003709                 mov     esi, offset aWindows2000219 ; "windows 2000 2195"
														---- end ignored -----
		.text:1000370E                 mov     dword ptr [ebx+39h], 800000D4h
		.text:10003715                 mov     word ptr [ebx+25h], 0FFh
		.text:1000371B                 mov     word ptr [ebx+27h], 0A4h
		.text:10003721                 mov     word ptr [ebx+29h], 4104h
		.text:10003727                 mov     word ptr [ebx+2Bh], 32h
		*/
		/*
			.text:00402A65                 push    8004667Eh       ; cmd
			.text:00402A6A                 push    esi             ; s
			.text:00402A6B                 call    ioctlsocket
			.text:00402A70                 push    32h             ; dwMilliseconds
			.text:00402A72                 mov     [esp+24Ch+writefds.fd_array], esi
			.text:00402A79                 mov     [esp+24Ch+writefds.fd_count], 1
			.text:00402A84                 mov     [esp+24Ch+timeout.tv_sec], 3
			.text:00402A8C                 mov     [esp+24Ch+timeout.tv_usec], 0			
		*/
	/*
		8B 0D 50 A7 56 00  mov     ecx, DnsFree
		81 F6 8C 3F 7C 5E  xor     esi, 5E7C3F8Ch
		6A 01              push    1               ; _DWORD
		50                 push    eax             ; _DWORD
		85 C9              test    ecx, ecx
		74 3A              jz      short loc_40580B
		FF D1              call    ecx ; DnsFree
	*/
		/*
		.text:10001850                 push    7530h           ; dwTimeout
		.text:10001855                 lea     eax, [esp+420h+a2]
		.text:10001859                 push    4               ; len
		.text:1000185B                 push    eax             ; a2
		.text:1000185C                 push    esi             ; s
		.text:1000185D                 mov     dword ptr [esp+42Ch+a2], 1000h
		.text:10001865                 call    CommSendWithTimeout
		.text:1000186A                 add     esp, 14h
		.text:1000186D                 cmp     eax, 0FFFFFFFFh
		.text:10001870                 jz      loc_10001915
		.text:10001876                 lea     ecx, [esp+418h+random]
		.text:1000187A                 push    ecx             ; a1
		.text:1000187B                 call    Generate16ByteRandomBuffer
		.text:10001880                 push    0               ; fEncrypt
		.text:10001882                 push    7530h           ; dwTimeout		
		*/
	/*
		81 7C 24 24 33 27 00 00  cmp     [esp+1Ch+dwBytesToRead], 2733h
		75 7F                    jnz     short loc_10002B74
		8D 54 24 14              lea     edx, [esp+1Ch+var_8]
		52                       push    edx             ; Time
		FF 15 5C 11 02 10        call    ds:time
		8B 44 24 14              mov     eax, [esp+20h+var_C]
		83 C4 04                 add     esp, 4
		8B C8                    mov     ecx, eax
		40                       inc     eax
		83 F9 64                 cmp     ecx, 64h
	*/
	/*
		E8 74 31 00 00     call    GetStringByIndex
		8B 7C 24 14        mov     edi, [esp+0Ch+dwFuncIndex]
		8B F0              mov     esi, eax
		57                 push    edi             ; index
		E8 68 31 00 00     call    GetStringByIndex
		83 C4 08           add     esp, 8
		85 F6              test    esi, esi
		74 21              jz      short loc_10001040
		85 C0              test    eax, eax
		74 1D              jz      short loc_10001040
		56                 push    esi             ; lpLibFileName
		FF 15 2C 10 02 10  call    ds:LoadLibraryA
		57                 push    edi             ; index
		8B F0              mov     esi, eax
		E8 4E 31 00 00     call    GetStringByIndex
		83 C4 04           add     esp, 4
		50                 push    eax             ; lpProcName
		56                 push    esi             ; hModule
		FF 15 5C 10 02 10  call    ds:GetProcAddress
	*/
	/*
		68 B8 0B 00 00           push    0BB8h           ; dwMilliseconds
		FF 15 18 10 02 10        call    ds:Sleep
		6A 01                    push    1               ; dwTimeout
		8D 4C 24 10              lea     ecx, [esp+4C0h+peerEntries]
		68 B0 04 00 00           push    4B0h            ; dwBytesToRead
		51                       push    ecx             ; pvRecvBuffer
		8B CE                    mov     ecx, esi        ; this
		C7 44 24 14 B0 04 00 00  mov     [esp+4C8h+Memory], 4B0h
		E8 25 F4 FF FF           call    CClientConnection__RecvData
		83 F8 FF                 cmp     eax, 0FFFFFFFFh
	*/
	// joanap, joanapCleaner
		// $firewall is a shared code string
	/*
		50                 push    eax             ; SubStr
		55                 push    ebp             ; Str
		FF D3              call    ebx ; strstr
		83 C4 08           add     esp, 8
		85 C0              test    eax, eax
		75 1A              jnz     short loc_401131
		8A 8E 08 01 00 00  mov     cl, [esi+108h]
		81 C6 08 01 00 00  add     esi, 108h
		47                 inc     edi
		8B C6              mov     eax, esi
		84 C9              test    cl, cl
		75 E2              jnz     short loc_40110C
	*/
	/*
		8D 44 24 10        lea     eax, [esp+2Ch+ServiceStatus]
		50                 push    eax             ; lpServiceStatus
		6A 01              push    1               ; dwControl
		56                 push    esi             ; hService
		FF D3              call    ebx ; ControlService
		83 7C 24 14 01     cmp     [esp+2Ch+ServiceStatus.dwCurrentState], 1
		75 EF              jnz     short loc_4010A5
		56                 push    esi             ; hService
		FF 15 08 70 40 00  call    ds:DeleteService
	*/
		/*
			56                 push    esi             ; hSCObject
			FF D5              call    ebp ; CloseServiceHandle
			68 B8 0B 00 00     push    0BB8h           ; dwMilliseconds
			FF 15 38 70 40 00  call    ds:Sleep
			6A 00              push    0               ; fCreateHighestLevel
			68 60 A9 40 00     push    offset PathName ; lpPathName
			E8 43 FE FF FF     call    RecursivelyCreateDirectories
			83 C4 08           add     esp, 8
			68 60 A9 40 00     push    offset PathName ; lpFileName
			FF 15 3C 70 40 00  call    ds:DeleteFileA
		*/
	/*
		E8 77 07 00 00     call    _rand
		B1 FB              mov     cl, 0FBh
		F6 E9              imul    cl
		88 44 34 08        mov     [esp+esi+10008h+randomData], al
		46                 inc     esi
		81 FE 00 00 01 00  cmp     esi, 10000h
		7C EA              jl      short loc_402E8D
	*/
	/*
		89 58 09              mov     [eax+9], ebx
		C7 40 65 00 00 02 00  mov     dword ptr [eax+65h], 20000h
		C7 40 15 04 00 00 00  mov     dword ptr [eax+15h], 4
		C6 40 08 08           mov     byte ptr [eax+8], 8
		C7 40 04 00 02 00 00  mov     dword ptr [eax+4], 200h
		89 18                 mov     [eax], ebx
		89 58 0D              mov     [eax+0Dh], ebx
		C7 40 11 01 00 00 00  mov     dword ptr [eax+11h], 1
		89 58 69              mov     [eax+69h], ebx
		89 58 19              mov     [eax+19h], ebx
		B8 01 00 00 00        mov     eax, 1
	*/
		// the replacement MBRs in both encoded (XOR 0x53) and decoded form		
	/*
		6A 04              push    4               ; MaxCount  <--- this arg is not found in some variants (41bad..) as wcscmp is used instead
		68 08 82 00 10     push    offset Str2     ; ".doc"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp            <--- d07... variant uses a direct call instead
		83 C4 0C           add     esp, 0Ch										<--- when wcscmp is used, this is add esp, 8
		85 C0              test    eax, eax
		0F 84 5B 02 00 00  jz      loc_100017D5
		6A 05              push    5               ; MaxCount
		68 FC 81 00 10     push    offset a_docx   ; ".docx"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp
		83 C4 0C           add     esp, 0Ch
		85 C0              test    eax, eax
		0F 84 46 02 00 00  jz      loc_100017D5
		6A 04              push    4               ; MaxCount
		68 F0 81 00 10     push    offset a_docm   ; ".docm"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp
		83 C4 0C           add     esp, 0Ch
		85 C0              test    eax, eax
		0F 84 31 02 00 00  jz      loc_100017D5
		6A 04              push    4               ; MaxCount
		68 E4 81 00 10     push    offset a_wpd    ; ".wpd"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp
	*/
	/*
		66 89 55 DC     mov     [ebp+SystemTime.wYear], dx
		E8 1E 16 00 00  call    _rand
		6A 0C           push    0Ch
		99              cdq
		59              pop     ecx
		F7 F9           idiv    ecx
		42              inc     edx
		66 89 55 DE     mov     [ebp+SystemTime.wMonth], dx
		E8 0E 16 00 00  call    _rand
		6A 1C           push    1Ch
		99              cdq
		59              pop     ecx
		F7 F9           idiv    ecx
		42              inc     edx
		66 89 55 E2     mov     [ebp+SystemTime.wDay], dx
		E8 FE 15 00 00  call    _rand
		6A 18           push    18h
		99              cdq
		59              pop     ecx
		F7 F9           idiv    ecx
		66 89 55 E4     mov     [ebp+SystemTime.wHour], dx
		E8 EF 15 00 00  call    _rand
		6A 3C           push    3Ch
		99              cdq
		59              pop     ecx
		F7 F9           idiv    ecx
		66 89 55 E6     mov     [ebp+SystemTime.wMinute], dx
		E8 E0 15 00 00  call    _rand
		6A 3C           push    3Ch
		99              cdq
		59              pop     ecx
		F7 F9           idiv    ecx
	*/
	/*
		F3 A5           rep movsd
		8B 7C 24 30     mov     edi, [esp+28h+arg_4]
		85 FF           test    edi, edi
		7E 3A           jle     short loc_402018
		8B 74 24 2C     mov     esi, [esp+28h+arg_0]
		8A 44 24 08     mov     al, [esp+28h+var_20]
		53              push    ebx
		8A 4C 24 21     mov     cl, [esp+2Ch+var_B]
		8A 5C 24 2B     mov     bl, [esp+2Ch+var_1]
		32 C1           xor     al, cl
		8A 0C 32        mov     cl, [edx+esi]
		32 C3           xor     al, bl
		32 C8           xor     cl, al
		88 0C 32        mov     [edx+esi], cl
		B9 1E 00 00 00  mov     ecx, 1Eh
		8A 5C 0C 0C     mov     bl, [esp+ecx+2Ch+var_20]
		88 5C 0C 0D     mov     [esp+ecx+2Ch+var_1F], bl
		49              dec     ecx
		83 F9 FF        cmp     ecx, 0FFFFFFFFh
		7F F2           jg      short loc_402000
		42              inc     edx
	*/
// EMBEDDED FLASH OBJECT BIN HEADER
// OBJECT APPLICATION TYPE TITLE
// PDB PATH 
// LOADER STRINGS
        //strings present in decoded python script:
        //Base64 encoded versions of these strings
        //EvilOSX
        //get_launch_agent_directory
        //prereqs
        //<plist
        //ProgramArguments
        //Library
        //StartInterval
        /* ransom message */
        /* other strings */
        /* code */
	//$string2 = "Windows China Driver" fullword
	//$string2 = "C:\\Program Files\\Internet Explorer\\iexplore.exe" fullword
    //  0   belong      0xcafebabe
    //  >4  belong      1       Mach-O universal binary with 1 architecture
    //  >4  belong      >1
    //  >>4 belong      <20     Mach-O universal binary with %ld architectures
        // old sample
        // new sample
        //zip
        //all
		//$d = {FFA0??0?0000}
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
		//read file... error..
	// Function: 404344 cc_validation
	// Function: 404539 memory_enum
	//$STR5 = { e8 00 00 00 00 }
		//$S2_CMD_Parse= ""\""%s'"'  /install \""%s\""'"' fullword
		//$S3_CMD_Builder= ""\'"'%s\""  \""%s\'"' \""%s\'"' %s'"' fullword
//inveigh pentesting tools
//specific malicious word document PK archive
//inveigh pentesting tools
//specific malicious word document PK archive
		//$p1 = { 0A F1 2? } 	// Rslinx 44818 only selected 
                //$ms12052_4 = /document\..*?= ?null/ nocase *greedy and ungreedy quantifiers can't be mixed in a regular expression*
		// Generic android
		// iBanking related
      /* C2 Servers */
      /* $ = " \"" ascii */ /* slowing down scanning */
    // Encrypted data
    // Decoded export func names
/*

0x41b7e1L C745B8558BEC83                mov dword ptr [ebp - 0x48], 0x83ec8b55
0x41b7e8L C745BCEC745356                mov dword ptr [ebp - 0x44], 0x565374ec
0x41b7efL C745C08B750833                mov dword ptr [ebp - 0x40], 0x3308758b
0x41b7f6L C745C4C957C745                mov dword ptr [ebp - 0x3c], 0x45c757c9
0x41b7fdL C745C88C4C6F61                mov dword ptr [ebp - 0x38], 0x616f4c8c

*/
/*

0x41ba18L C78534FFFFFF636D642E          mov dword ptr [ebp - 0xcc], 0x2e646d63
0x41ba22L C78538FFFFFF65786520          mov dword ptr [ebp - 0xc8], 0x20657865
0x41ba2cL C7853CFFFFFF2F632063          mov dword ptr [ebp - 0xc4], 0x6320632f
0x41ba36L C78540FFFFFF6F707920          mov dword ptr [ebp - 0xc0], 0x2079706f
0x41ba40L C78544FFFFFF2577696E          mov dword ptr [ebp - 0xbc], 0x6e697725
0x41ba4aL C78548FFFFFF64697225          mov dword ptr [ebp - 0xb8], 0x25726964
0x41ba54L C7854CFFFFFF5C737973          mov dword ptr [ebp - 0xb4], 0x7379735c
0x41ba5eL C78550FFFFFF74656D33          mov dword ptr [ebp - 0xb0], 0x336d6574
0x41ba68L C78554FFFFFF325C636D          mov dword ptr [ebp - 0xac], 0x6d635c32
0x41ba72L C78558FFFFFF642E6578          mov dword ptr [ebp - 0xa8], 0x78652e64
0x41ba7cL C7855CFFFFFF65202577          mov dword ptr [ebp - 0xa4], 0x77252065
0x41ba86L C78560FFFFFF696E6469          mov dword ptr [ebp - 0xa0], 0x69646e69
0x41ba90L C78564FFFFFF72255C73          mov dword ptr [ebp - 0x9c], 0x735c2572
0x41ba9aL C78568FFFFFF79737465          mov dword ptr [ebp - 0x98], 0x65747379
0x41baa4L C7856CFFFFFF6D33325C          mov dword ptr [ebp - 0x94], 0x5c32336d
0x41baaeL C78570FFFFFF73657468          mov dword ptr [ebp - 0x90], 0x68746573
0x41bab8L C78574FFFFFF632E6578          mov dword ptr [ebp - 0x8c], 0x78652e63
0x41bac2L C78578FFFFFF65202F79          mov dword ptr [ebp - 0x88], 0x792f2065
0x41baccL 83A57CFFFFFF00                and dword ptr [ebp - 0x84], 0

*/
/*

0x41baeeL C785D8FEFFFF636D6420          mov dword ptr [ebp - 0x128], 0x20646d63
0x41baf8L C785DCFEFFFF2F632022          mov dword ptr [ebp - 0x124], 0x2220632f
0x41bb02L C785E0FEFFFF6E657420          mov dword ptr [ebp - 0x120], 0x2074656e
0x41bb0cL C785E4FEFFFF75736572          mov dword ptr [ebp - 0x11c], 0x72657375
0x41bb16L C785E8FEFFFF20636573          mov dword ptr [ebp - 0x118], 0x73656320
0x41bb20L C785ECFEFFFF73757070          mov dword ptr [ebp - 0x114], 0x70707573
0x41bb2aL C785F0FEFFFF6F727420          mov dword ptr [ebp - 0x110], 0x2074726f
0x41bb34L C785F4FEFFFF3171617A          mov dword ptr [ebp - 0x10c], 0x7a617131
0x41bb3eL C785F8FEFFFF23454443          mov dword ptr [ebp - 0x108], 0x43444523
0x41bb48L C785FCFEFFFF202F6164          mov dword ptr [ebp - 0x104], 0x64612f20
0x41bb52L C78500FFFFFF64202626          mov dword ptr [ebp - 0x100], 0x26262064
0x41bb5cL C78504FFFFFF206E6574          mov dword ptr [ebp - 0xfc], 0x74656e20
0x41bb66L C78508FFFFFF206C6F63          mov dword ptr [ebp - 0xf8], 0x636f6c20
0x41bb70L C7850CFFFFFF616C6772          mov dword ptr [ebp - 0xf4], 0x72676c61
0x41bb7aL C78510FFFFFF6F757020          mov dword ptr [ebp - 0xf0], 0x2070756f
0x41bb84L C78514FFFFFF61646D69          mov dword ptr [ebp - 0xec], 0x696d6461
0x41bb8eL C78518FFFFFF6E697374          mov dword ptr [ebp - 0xe8], 0x7473696e
0x41bb98L C7851CFFFFFF7261746F          mov dword ptr [ebp - 0xe4], 0x6f746172
0x41bba2L C78520FFFFFF72732063          mov dword ptr [ebp - 0xe0], 0x63207372
0x41bbacL C78524FFFFFF65737375          mov dword ptr [ebp - 0xdc], 0x75737365
0x41bbb6L C78528FFFFFF70706F72          mov dword ptr [ebp - 0xd8], 0x726f7070
0x41bbc0L C7852CFFFFFF74202F61          mov dword ptr [ebp - 0xd4], 0x612f2074
0x41bbcaL C78530FFFFFF64642200          mov dword ptr [ebp - 0xd0], 0x226464
0x41bbd4L 6A5C                          push 0x5c

*/
/*

0x41be22L C745D057696E45                mov dword ptr [ebp - 0x30], 0x456e6957
0x41be29L C745D478656300                mov dword ptr [ebp - 0x2c], 0x636578
0x41be30L C7459C47657450                mov dword ptr [ebp - 0x64], 0x50746547
0x41be37L C745A0726F6341                mov dword ptr [ebp - 0x60], 0x41636f72
0x41be3eL C745A464647265                mov dword ptr [ebp - 0x5c], 0x65726464
0x41be45L C745A873730000                mov dword ptr [ebp - 0x58], 0x7373
0x41be4cL C745C443726561                mov dword ptr [ebp - 0x3c], 0x61657243
0x41be53L C745C874654669                mov dword ptr [ebp - 0x38], 0x69466574
0x41be5aL C745CC6C654100                mov dword ptr [ebp - 0x34], 0x41656c
0x41be61L C745B857726974                mov dword ptr [ebp - 0x48], 0x74697257
0x41be68L C745BC6546696C                mov dword ptr [ebp - 0x44], 0x6c694665
0x41be6fL C745C065000000                mov dword ptr [ebp - 0x40], 0x65
0x41be76L C745AC436C6F73                mov dword ptr [ebp - 0x54], 0x736f6c43
0x41be7dL C745B06548616E                mov dword ptr [ebp - 0x50], 0x6e614865
0x41be84L C745B4646C6500                mov dword ptr [ebp - 0x4c], 0x656c64
0x41be8bL 894DE8                        mov dword ptr [ebp - 0x18], ecx

*/
		// use for less false positives, xor before fnv1a prime
		//$fnv64a_prime_plus_gap_plus_xor_ret = { 61 [0-3] B3 01 00 00 00 01 [8-40] 61 2A }
		// even less false positives, not sure if it misses beef
		//$fnv64a_prime_plus_gap_plus_xor_ret = { 61 [0-3] B3 01 00 00 00 01 [8-40] 61 2A 00 00 }
		// MZ or ELF
      /* Bronce Butler UA String - see google search */
      /* Looks random but present in many samples */
      /* [InternetShortcut]
         URL=https://msofficeupdate.org/ */
      /* Used for beacon config decoding in THOR */
		// Epoch for 01.01.2000
      /* "Copyright 1 - 19" */
      /* $s1 = "Project1.dll" fullword ascii */
      /* Better: Project1.dll\x00D1 */
      // BIOS Extended Write
      /* MOV POS 4BYTE-OF-KEY */
// Case permutations of the word SeRvEr encoded with the Microsoft Script Encoder followed by .scriptrimeOut
      /* {11804ce4-930a-4b09-bf70-9f1a95d0d70d}, Culture=neutral, PublicKeyToken=3e56350693f7355e */
      /* iex([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String( */
      /* Double Base64 encoded : Invoke-Expression */
      /* $a2 = {fb ff ff ff 00 00}  disabled due to performance issues */
      /* $a2 = {fb ff ff ff 00 00} disabled due to performance issues */
      /* $a2 = {fb ff ff ff 00 00} disabled due to performance issues */
      /* $b1 = {fb ff ff ff 00 00} disabled due to performance issues */
      /* $b1 and */ 4 of ($a*)
      /* $x2 = "!!!system" fullword ascii - more specific: */
      /* used for generic approach */
      // Go build
         // valid after Tuesday, January 1, 2019 0:00:00
        /* Too many false positives with these strings
        $au1 = "/icon.png"
        $au2 = "/notepad.png"
        $au3 = "/pic.png"
        */
        //specific malicious word document PK archive
        /* Only 3 characters atom - this is bad for performance - we're trying to leave this out
        $func_call="a(\""
        */
        /* #func_call > 20 and */
      /* Imphash */
      /* SSH binaries - specific strings */
      /* SSH binaries - combo required */
      /* Strings from malicious files */
      /* abafar */
      /* akiva */
      /* alderaan */
      /* ando */
      /* anoat */
      /* batuu */
      /* banodan */
      /* borleias */
      /* ondaron */
      /* polis_massa */
      /* quarren */
      /* chandrilla */
      /* atollon */
      // single byte offset from base pointer
      // dword ss with single byte offset from base pointer
      // 4-bytes offset from base pointer
      // single byte offset from stack pointer
      // 4-bytes offset from stack pointer
      /* other strings */
      /* bespin */
      /* coruscant */
      /* crait */
      /* jakuu */
      /* kamino */
      /* kessel */
      /* mimban */
      /* $ = "ZYSZLRTS^Z@@NM@@G_Y_FE" ascii fullword */
      /* Load eth0 interface*/
      /* Opcode exceptions*/ 
      /* Xor string loop x64*/
        /* $crypt02 = "AES" wide */ /* disabled due to performance reasons */
      /* MZ and PE */
      /* Expected file size */
         /* Imports */
         /* Specific header - possibly Yoda protector*/
         /* Vprotect */
      // fn_register_libtomcrypt
      // fn_decrypt_PE
      // fn_register_libtomcrypt
      // fn_decrypt_PE
      /* $s2 = "Kernel.dll" fullword ascii */
      /* $s2 = "Kernel.dll" fullword ascii */
      /* Primary\x00m\x00s\x00v */
        /* $str2 = "%d" // disabled due to performance concerns */ 
        //( uint16(0) == 0x5a4d and ( 3 of them ) ) or ( all of them )
      /* File Detection */
      /* In Memory */
      /* Incorported from Chris Doman's rule - https://goo.gl/PChE1z*/
      /* ,#1 ..... rundll32.exe */
      // code patterns for process kills
      /* Payload\x00AutoPayload */
      /* RunCmd\x00DumpData */
      /* ZvitWebClientExt\x00MinInfo */
        //file_name = "re:^stream_[0-9]+_[0-9]+.dat$"
        //$code = /[\x01-\x7F]{44}/
        //file_ext = "rtf"
		//having objdata structure
		//hex encoded OLE2Link
		//hex encoded docfile magic - doc file albilae
		//hex encoded "http://"
		//hex encoded "https://"
		//hex encoded "ftp://"
      // has offset
      // first detect 'powershell' keyword case insensitive
      // define the normal cases
      // define the normal cases
      // PowerShell with \x19\x00\x00
      // expected casing
      // adding a keyword with a sufficent length and relevancy
      // define normal cases
         // find all 'powershell' occurances and ignore the expected cases
         // find all '-norpofile' occurances and ignore the expected cases
      // first detect powershell keyword case insensitive
      // define the normal cases
      /* not 'M' at position 29, which is after the BEGIN CERTIFICATE header plus line break */
      /* \r\n */
      /* \n */
        // 2fb198f6ad33d0f26fb94a1aa159fef7296e0421da68887b8f2548bbd227e58f
        // ' 0018     23 LABEL : Cell Value, String Constant - build-in-name 1 Auto_Open
        // 00002d80:
        // 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 01 00 16 00 07 00
        // f4c01e26eb88b72d38be3d6331fafe03b1ae53fdbff57d610173ed797fa26e73
        // 00003460: 00 00 18 00 17 00 20 00 00 01 07 00 00 00 00 00  ...... .........
        // 00003470: 00 00 00 00 00 01 3a 00 00 3f 02 8d 00 c1 01 08  ......:..?......
        // ccef64586d25ffcb2b28affc1f64319b936175c4911e7841a0e28ee6d6d4a02d
        // ' 0018     23 LABEL : Cell Value, String Constant - build-in-name 1 Auto_Open
        // 00003560: 00 00 00 00 00 18 00 17 00 aa 03 00 01 07 00 00  ................
        // 00003570: 00 00 00 00 00 00 00 00 01 3a 00 00 04 00 65 00  .........:....e.
        // some Excel4 files don't have auto_open names e.g.:
        // b8b80e9458ff0276c9a37f5b46646936a08b83ce050a14efb93350f47aa7d269
        // 079be05edcd5793e1e3596cdb5f511324d0bcaf50eb47119236d3cb8defdfa4c
        /* $murica = "murica" fullword */
        // #murica > 10 or 
        /* $typelibguid6 = "94432a8e-3e06-4776-b9b2-3684a62bb96a" ascii nocase wide FIX FPS with Microsoft files */ 
      /* OriginalName GoogleUpdate.exe */
		// Debug Strings - only available when compiled as debug 
		// Function names
		/* $f5 = "xsh" fullword */
		// "key" function
		// "stte" function
		// "chkenv" function
		// "rmarg" function
         // single rar block for a single doc file
      /* Adobe PDF Icon Bitmap */
      /* SFX Icon Bitmap */
      /* Adobe PDF Icon Bitmap */
      /* Exclude actual Adobe software */
      // possible bitcoin wallet. could be coinminer config
      //see 0541fc6a11f4226d52ae3d4158deb8f50ed61b25bb5f889d446102e1ee57b76d
      // see 9a3fd0d2b0bca7d2f7e3c70cb15a7005a1afa1ce78371fd3fa9c526a288b64ce
      // see 9a3fd0d2b0bca7d2f7e3c70cb15a7005a1afa1ce78371fd3fa9c526a288b64ce
      //PAYLOAD_BASE64
      //subprocess
      // #!/usr
      // # -*-
      //add_header
      /* exclude false positives */
      // $xc2 = {6D 69 6D 69 C7 84 24 8C 00 00 00 6C 73 61 2E C7 84 24 90 00 00 00 6C 6F 67} -  mimilsa.log
      /* Encoded Command */
      /* Window Hidden */
      /* Non Profile */
      /* Non Interactive */
      /* Exec Bypass */
      /* Single Threaded - PowerShell Empire */
      //Base64 encoded versions of these strings
      // socket.SOCK_STREAM
      //.connect((
      //time.sleep
      //.recv
		// Versions 2x
		// Versions 3x & 4x & 5x
      /* ipconfig /all */
      /* ping */
      /* arp -a */
      /* netstat */ 
      /* tasklist */ 
        /*
        .text:0000000180004450                                     loc_180004450:                          ; CODE XREF: sub_1800043F0+80?j
        .text:0000000180004450 49 63 D0                                            movsxd  rdx, r8d
        .text:0000000180004453 43 8D 0C 01                                         lea     ecx, [r9+r8]
        .text:0000000180004457 41 FF C0                                            inc     r8d
        .text:000000018000445A 42 32 0C 1A                                         xor     cl, [rdx+r11]
        .text:000000018000445E 0F B6 C1                                            movzx   eax, cl
        .text:0000000180004461 C0 E9 04                                            shr     cl, 4
        .text:0000000180004464 C0 E0 04                                            shl     al, 4
        .text:0000000180004467 02 C1                                               add     al, cl
        .text:0000000180004469 42 88 04 1A                                         mov     [rdx+r11], al
        .text:000000018000446D 44 3B 03                                            cmp     r8d, [rbx]
        .text:0000000180004470 72 DE                                               jb      short loc_180004450
        */
      /* PE Header : LegalCopyright (C) Microsoft Corporation. All rights reserved.*/
      /* PE Header : LegalCopyright (C) Microsoft Corporation. All rights reserved.*/
      /* FileDescription Microsoft Office Software Protection Platform Service */
      /* .exe\x00C:\Users\ */
      /* $s6 = " bypass " ascii wide */
      /* Hex encoded strings */
      /* This program cannot be run in DOS mode */
      /* KERNEL32.dll */
      /* C:\fakepath\ */
      /* DOS Magic Header */
      /* Whitelist */
      /* Blacklist */
      /* covered via Whitelist
      $s1 = "AppPath=C:\\$Recycle.Bin\\" wide
      $s2 = "AppPath=C:\\Perflogs\\" wide
      $s3 = "AppPath=C:\\Temp\\" wide
      $s4 = "AppPath=\\\\" wide // network share, or \\tsclient\c etc.
      $s5 = /AppPath=[C-Z]:\\\\[^\\]{1,64}\.exe/ wide nocase // in the root of a partition - no sub folder
      */
      /* Root of AppData */
//    $file2 = /IconFile=script:/ nocase
      /* VHD */
		//strings from private rule php_false_positive
		// try to use only strings which would be flagged by themselves as suspicous by other rules, e.g. eval 
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
		//strings from private rule php_false_positive_tiny
		// try to use only strings which would be flagged by themselves as suspicous by other rules, e.g. eval 
		//$gfp_tiny1 = "addslashes" fullword
		//$gfp_tiny2 = "escapeshellarg" fullword
		//strings from private rule capa_php_input
        // for passing $_GET to a function 
		// PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
		//strings from private rule capa_php_callback
		//strings from private rule capa_gen_sus
        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        // bonus string for proxylogon exploiting webshells
        // own base64 func
        // single letter paramweter
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        // very suspicious strings, one is enough
        // self remove
        // touch without parameters sets the time to now, not malicious and gives fp
		// exec
		// shell_exec
		// passthru
		// system
		// popen
		// proc_open
		// pcntl_exec
		// eval
		// assert
        // false positives
        // execu
        // esystem like e.g. filesystem
        // opening
        // false positives
        // api.telegram
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
        // new: eval($GLOBALS['_POST'
		//strings from private rule php_false_positive
		// try to use only strings which would be flagged by themselves as suspicous by other rules, e.g. eval 
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule php_false_positive
		// try to use only strings which would be flagged by themselves as suspicous by other rules, e.g. eval 
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_php_obfuscation_multi
		// not excactly a string function but also often used in obfuscation
		// just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
		//strings from private rule capa_php_payload
		// \([^)] to avoid matching on e.g. eval() in comments
		// TODO backticks
			// allow different amounts of potential obfuscation functions depending on filesize
        // one without plain e, one without plain v, to avoid hitting on plain "eval("
        // one without plain a, one without plain s, to avoid hitting on plain "assert("
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
        // "e\x4a\x48\x5a\x70\x63\62\154\x30\131\171\101\x39\111\x43\x52\x66\x51\
		//$mix = /['"]\\x?[0-9a-f]{2,3}[\\\w]{2,20}\\\d{1,3}[\\\w]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
        // 'ev'.'al'
		//strings from private rule php_false_positive
		// try to use only strings which would be flagged by themselves as suspicous by other rules, e.g. eval 
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_php_payload
		// \([^)] to avoid matching on e.g. eval() in comments
		// TODO backticks
		//$hex  = "\\x"
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		// ;@eval(
		// ;@assert(
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_php_callback
		//strings from private rule capa_php_payload
		// \([^)] to avoid matching on e.g. eval() in comments
		// TODO backticks
		//strings from private rule capa_php_obfuscation_single
		//strings from private rule capa_gen_sus
        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        // bonus string for proxylogon exploiting webshells
        // own base64 func
        // single letter paramweter
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        // very suspicious strings, one is enough
        // self remove
        // touch without parameters sets the time to now, not malicious and gives fp
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
		//strings from private rule capa_php_new
		//strings from private rule capa_php_payload
		// \([^)] to avoid matching on e.g. eval() in comments
		// TODO backticks
			// file shouldn't be too small to have big enough data for math.entropy
            // base64 : 
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
            // gzinflated binary sometimes used in php webshells
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		// crawler avoid string
		// <?=($pbs_=@$_GET[2]).@$_($_GET[1])?>
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_bin_files
        // fp on jar with zero compression
        // move malicious code out of sight if line wrapping not enabled
        // rot13 of eval($_POST
        // eval( in hex
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule php_false_positive
		// try to use only strings which would be flagged by themselves as suspicous by other rules, e.g. eval 
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
		//strings from private rule capa_php_input
        // for passing $_GET to a function 
		// PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
		//strings from private rule php_false_positive
		// try to use only strings which would be flagged by themselves as suspicous by other rules, e.g. eval 
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        //$sus13= "<textarea " wide ascii
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_php_input
        // for passing $_GET to a function 
		// PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
		//strings from private rule capa_php_write_file
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
		//strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        // base64 of Request.Form(
        // dynamic form
		//strings from private rule capa_asp_write_file
		// $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
		//$asp_write_way_one1 = /\.open\b/ nocase wide ascii
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
		//strings from private rule capa_asp_payload
        // var Fla = {'E':eval};  Fla.E(code)
		// this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        // execute cmd.exe /c with arguments using ProcessStartInfo
		//strings from private rule capa_asp_write_file
		// $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
		//$asp_write_way_one1 = /\.open\b/ nocase wide ascii
		//strings from private rule capa_asp_obfuscation_multi
        // many Chr or few and a loop????
        //$loop1 = "For "
		//$o1 = "chr(" nocase wide ascii
		//$o2 = "chr (" nocase wide ascii
		// not excactly a string function but also often used in obfuscation
		// just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
		//$o10 = " & \"" wide ascii
		//$o11 = " += \"" wide ascii
        // used for e.g. "scr"&"ipt"
        /*
        $m_multi_one5 = "InStr(" wide ascii
        $m_multi_one6 = "Function" wide ascii

        $m_multi_two1 = "for each" wide ascii
        $m_multi_two2 = "split(" wide ascii
        $m_multi_two3 = " & chr(" wide ascii
        $m_multi_two4 = " & Chr(" wide ascii
        $m_multi_two5 = " & Chr (" wide ascii

        $m_multi_three1 = "foreach" fullword wide ascii
        $m_multi_three2 = "(char" wide ascii

        $m_multi_four1 = "FromBase64String(" wide ascii
        $m_multi_four2 = ".Replace(" wide ascii
        $m_multi_five1 = "String.Join(\"\"," wide ascii
        $m_multi_five2 = ".Trim(" wide ascii
        $m_any1 = " & \"2" wide ascii
        $m_any2 = " += \"2" wide ascii
        */
		//strings from private rule capa_asp_obfuscation_obviously
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
                //( #o1+#o2 ) > 50 or
                //( #o1+#o2 ) > 10 or
                    //( #o1+#o2 ) > 1 and
                //( #o1+#o2 ) > 1 or
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
        // Request and request in b64:
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
		//strings from private rule capa_asp_payload
        // var Fla = {'E':eval};  Fla.E(code)
		// this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        // execute cmd.exe /c with arguments using ProcessStartInfo
		//strings from private rule capa_asp_write_file
		// $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
		//$asp_write_way_one1 = /\.open\b/ nocase wide ascii
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
		//$sus1 = "shell" nocase wide ascii
		//$sus2 = "cmd" fullword wide ascii
		//$sus3 = "password" fullword wide ascii
		//$sus4 = "UserPass" fullword wide ascii
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
        // reversed
        // e+k-v+k-a+k-l
        // e+x-v+x-a+x-l
        // Request.Item["
        // eval( in utf7 in base64 all 3 versions
        // request in utf7 in base64 all 3 versions
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
		//strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        // base64 of Request.Form(
        // dynamic form
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
		//strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        // base64 of Request.Form(
        // dynamic form
		//strings from private rule capa_bin_files
		//strings from private rule capa_asp_payload
        // var Fla = {'E':eval};  Fla.E(code)
		// this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        // execute cmd.exe /c with arguments using ProcessStartInfo
		//strings from private rule capa_asp_write_file
		// $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
		//$asp_write_way_one1 = /\.open\b/ nocase wide ascii
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
        // fp on jar with zero compression
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
		//strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        // base64 of Request.Form(
        // dynamic form
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
        // only match on "load" or variable which might contain "load"
		//strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        // base64 of Request.Form(
        // dynamic form
        //$slightly_sus1 = "select * from " wide ascii
        //$slightly_sus2 = "SELECT * FROM " wide ascii
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
		//strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        // base64 of Request.Form(
        // dynamic form
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
        // two methods: check permissions or write and delete:
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
		//strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        // base64 of Request.Form(
        // dynamic form
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
		//strings from private rule capa_jsp_safe
		// JSF
		//strings from private rule capa_jsp_safe
		// JSF
		//strings from private rule capa_jsp_input
		// request.getParameter
		// request.getHeaders
		//strings from private rule capa_jsp_safe
		// JSF
		// Runtime.getRuntime().exec(
		//strings from private rule capa_jsp_safe
		// JSF
		//strings from private rule capa_jsp_input
		// request.getParameter
		// request.getHeaders
		//strings from private rule capa_bin_files
		//strings from private rule capa_jsp_safe
		// JSF
		//strings from private rule capa_jsp_input
		// request.getParameter
		// request.getHeaders
		//strings from private rule capa_jsp_payload
		// Runtime.getRuntime().exec(
        // fp on jar with zero compression
		// Runtime
		// exec
		// ScriptEngineFactory
		//strings from private rule capa_jsp_safe
		// JSF
		//strings from private rule capa_bin_files
        // fp on jar with zero compression
		//strings from private rule capa_jsp_input
		// request.getParameter
		// request.getHeaders
		//strings from private rule capa_jsp_safe
		// JSF
		//strings from private rule capa_jsp_input
		// request.getParameter
		// request.getHeaders
		//strings from private rule capa_jsp_safe
		// JSF
		//strings from private rule capa_jsp_input
		// request.getParameter
		// request.getHeaders
		//strings from private rule capa_jsp_safe
		// JSF
		//strings from private rule capa_jsp_input
		// request.getParameter
		// request.getHeaders
		//strings from private rule capa_jsp_safe
		// JSF
		//strings from private rule capa_bin_files
        // fp on jar with zero compression
		//strings from private rule capa_jsp_safe
		// JSF
		//strings from private rule capa_jsp_input
		// request.getParameter
		// request.getHeaders
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_jsp_safe
		// JSF
		//strings from private rule capa_os_strings
		// windows = nocase
		// linux stuff, case sensitive:
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
        // MS access
        //$mdb = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }
		//strings from private rule capa_php_old_safe
		// prevent xml and asp from hitting with the short tag
		// of course the new tags should also match
        // already matched by "<?"
		//strings from private rule capa_php_payload
		// \([^)] to avoid matching on e.g. eval() in comments
		// TODO backticks
		//strings from private rule capa_php_write_file
		//strings from private rule capa_jsp
		// JSF
		//strings from private rule capa_jsp_payload
		// Runtime.getRuntime().exec(
		//strings from private rule capa_asp
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        // classids for scripting host etc
        // <% eval
        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>
        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>
        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>           
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        // avoid hitting php
        // avoid hitting jsp
		//strings from private rule capa_asp_payload
        // var Fla = {'E':eval};  Fla.E(code)
		// this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        // execute cmd.exe /c with arguments using ProcessStartInfo
		//strings from private rule capa_asp_write_file
		// $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
		//$asp_write_way_one1 = /\.open\b/ nocase wide ascii
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
      /* Decloaked version */
      /* =\x0A'));if(isset($_COOKIE[' */
    // common
    // server
    // server/main.c SIG_HEAD = 0x7AD8CFB6
/*
        00104bc0 89 f8           MOV        EAX,EDI
        00104bc2 8b 0d 00        MOV        ECX,dword ptr [PTR_s_#Irb4utunQPhJZjSn_0010b000] = 0010a4d0
                 b0 10 00
        00104bc8 99              CDQ
        00104bc9 f7 7d f0        IDIV       dword ptr [EBP + local_14]
        00104bcc 8b 45 08        MOV        EAX,dword ptr [EBP + param_1]
        00104bcf 0f b6 1c 11     MOVZX      EBX,byte ptr [ECX + EDX*0x1]=>s_#Irb4utunQPhJZ   = "#Irb4utunQPhJZjSn"
        00104bd3 32 1c 38        XOR        BL,byte ptr [EAX + EDI*0x1]
        00104bd6 88 1c 3e        MOV        byte ptr [ESI + EDI*0x1],BL
        00104bd9 8d 7f 01        LEA        EDI,[EDI + 0x1]
*/
	//Only when ran on the host itself
	//C:/Users/eugene/Desktop/web/src/aes_sGHR6SQYlVm0COgz.go
	//First variant
	//Second variant
		// Strings from Dubnium below
		// VirtualBox Mac Address
		// Filepaths
		// Drive Size
		// Sandbox usernames
    		// joe sandbox
		// anubis
        // threat expert
        // sandboxie
        // cwsandbox
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		//stupid check if last section is 0
		//not (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x0 and
		//$c0 = { 06 09 2A 86 }
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		//TAGG+4E==packerid
		//(uint32be(@a0+0x4E) == 0x0B51D132) and
		//(uint32be(@a0+0x12) == 0x006092a86) and
		//(uint32be(@a0+0x12)) == uint32be(@c0) and
		//uint32be(@a0+0x04) < (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) and
		//size check is wildcarded
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		//its not always like this:
		//and  uint32(@a0) == (filesize-(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size))
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		//orginal
		//((uint32(uint32(0x3C)+0xA8) >0x0) and (uint32be(uint32(0x3C)+0xAC) >0x0))
		//((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) x64/x32
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		//or
		//doest work
		//pe.imports("", "")
		//need to check if this is ok.. 15:06 2016-08-12
		//uint32( uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))+uint32(uint32(0x3C)+0x34)) == 0x408000
		//this works..
		//uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))+uint32(uint32(0x3C)+0x34) == 0x408000
		//uint32be(uint32be(0x409000)) == 0x005A
		//pe.image_base
		//correct:
		//uint32(uint32(0x3C)+0x80)+pe.image_base == 0x408000
		//this works (file offset):
		//$a0 at 0x4000
		//this does not work rva:
		//$a0 at uint32(0x0408000)
		//(uint32(uint32(uint32(0x3C)+0x80)+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))+pe.image_base) == 0x0)
		//tiny PE files..
		//or
		//uint32(uint32(0x3C)+0x80) == 0x21000
   		//uint32(uint32(uint32(0x3C)+0x80)) == 0x0
		//pe.imports("", "")
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		//UniLink
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		//make check for msvrt.dll
		//too wild ?
//abit weak, needs more targets & testing
	//strings:
		//$c0 = { 55 89 E5 83 EC 1C 8D 45 E4 6A 1C 50 FF 75 08 FF 15 ?? ?? ?? ?? 8B 45 E8 C9 C2 04 00 }
		//linker 1.60..1.79
		//and $c0
		//N
		//taken from r!sc aspr unpacker,
		//needs more samples from diffrent places
		//pe.overlay would be nice ;)
		//pe.overlay would be nice ;)
			//at overlay
		//OEP Jump place
		//needs more samples
		//if this is modified its not really FSG is it ?
		//if this is modified its not really FSG is it ?
		//if this is modified its not really FSG is it ?
		//if this is modified its not really FSG is it ?
					//Time_Date_Stamp
		//check more
		//pe.overlay would be nice ;)
		//look in overlay
		//($c1 in (pe.sections[pe.number_of_sections-1].raw_data_offset..pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size))
		//needs checked more
		//x64
		//probably more sigs
	//strings:
		//$a0 = "CABINET" fullword wide ascii nocase
		//$a1 = "MSCF" wide ascii nocase
		//"C\x00A\x00B\x00I\x00N\x00E\x00T\x00" or
		//checking for GetProcAddress
		//double check
		//needs more work	
		//needs improvements
		//i know this is abit weak
		//$a0 = { 00 00 00 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E }
		//might be wrong also
		//need more samples... replace 20 with wildcard ?
		//($a0 in (pe.sections[pe.section_index(pe.entry_point)].raw_data_offset..pe.sections[pe.section_index(pe.entry_point)].raw_data_offset+pe.sections[pe.section_index(pe.entry_point)].raw_data_size))
		//real old
		//old
		//PE x64 and ELF 64
		//older nsis
		//jcalg1
		//$a1 = { 8B 4D FC 8B E8 33 C0 D3 E5 E8 ?? 00 00 00 0B C5 5D 8B D8 E8 ?? 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 ?? FE FF FF }
		//jcalg1
		//$a1 = { 8B 4D FC 8B E8 33 C0 D3 E5 E8 ?? 00 00 00 0B C5 5D 8B D8 E8 ?? 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 ?? FE FF FF }
		//taken from internal peid db
		//need todo better signature to catch them all
		//0.92
		//0.94
		//0.971 - 0.976
		//0.977
		//0.978
		//0.978.1
		//0.978.2
		//0.98
		//0.99
		//1.00
		//1.10b1
		//1.10b2
		//1.10b3
		//1.10b4
		//1.10b5
		//1.10b6
		//1.10b7
		//1.20 - 1.20.1
		//1.22
		//1.23b3 - 1.24.1
		//1.24.2 - 1.24.3
		//1.25
		//1.26b1 - 1.26b2
		//1.33
		//1.34 - 1.40b1
		//1.40b2 - 1.40b4
		//1.40b5 - 1.40b6
		//1.40 - 1.45
		//1.46
		//1.47 - 1.50
		//1.55
		//1.56
		//1.60 - 1.65
		//1.66
		//1.67
		//1.68 - 1.84
		//$c0 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 }
		//needs to be checked more
		//$c1 = { 89 4A FC 33 C0 C3 B8 78 56 34 12 64 8F 05 00 00 00 00 83 C4 04 55 53 51 57 }
		//older versions 1.56
		//this is not found
		//$c4 = { 73 6B E8 26 02 00 00 8D 9D ?? ?? ?? ?? 53 50 FF 95 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 53 83 BD ?? ?? ?? ?? 01 74 08 8D 8D ?? ?? ?? ?? EB 06 8D 8D ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 57 52 51 53 FF D0 8D 9D ?? ?? ?? ?? 53 FF B5 ?? ?? ?? ?? FF 95 ?? ?? ?? ?? 5B 8D 8D ?? ?? ?? ?? 6A 10 51 53 6A 00 FF D0 FF A5 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 8B BD ?? ?? ?? ?? E8 56 0C 00 00 61 9D 50 68 ?? ?? ?? ?? C2 04 00 }
		//$c0 at pe.entry_point or
		//i know this is abit weak
		//i know this is abit weak
		//pe.overlay would be nice ;)
		//it cannot load the PE properly so it fails to check imports
		//pe.imports ("kernel32.dll","LoadLibraryA") and
		//pe.imports ("kernel32.dll","GetProcAddress") and
		//pe.imports ("kernel32.dll","VirtualProtect") and
		//it cannot load the PE properly so it fails to check imports
		//pe.imports ("kernel32.dll","LoadLibraryA") and
		//pe.imports ("kernel32.dll","GetProcAddress") and
		//pe.imports ("kernel32.dll","VirtualProtect") and
		//pe.overlay would be nice ;)
		//fixed
		//not fixed
		//fixed
		//fixed .. older versions
		//fixed - Themida v1.8.2.0 - v1.9.5.0 detected !
		//fixed - Themida v1.0.0.0 - v1.8.1.0 detected !
		//x64
		//($a0 in (pe.entry_point..pe.entry_point+0x50)
		//this is same as mPack becasuse mPack uses ThunderBolt
		//difference is mPack has overlay
		//$a1 = { 8D 75 5E 56 FF 55 52 0B C0 75 04 56 FF 55 56 8D B5 A7 00 00 00 56 50 FF 55 4E 89 85 B4 00 00 00 6A 04 68 00 10 00 00 FF B5 A3 00 00 00 6A 00 FF 95 B4 00 00 00 50 8B 9D 9F 00 00 00 03 DD 50 53 E8 36 00 00 00 5A B9 03 00 00 00 8D 75 4E 8D BA 06 19 00 00 8B 06 89 07 83 C6 04 83 C7 04 E2 F4 8D 85 A1 02 00 00 89 82 2A 19 00 00 8B 85 B4 00 00 00 89 82 12 19 00 00 0E 52 CB }
		//$a0 = { BE E8 11 40 00 AD 50 AD 50 66 BE 58 01 6A 12 BF ?? ?? ?? ?? 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 B1 04 F3 AB C1 E0 0A B5 10 F3 AB BF ?? ?? ?? ?? E9 ?? ?? ?? ?? 47 65 74 50 }
		//$a0 at pe.entry_point and
		//$a1 = {  }
		//and $a1 at 0 
		//check more
		//($a0 or $a1 or $a2 or $a3)
		//3.03 .. 3.09
		//older upx 0.76 - 0.84
		//unknown ver
		//0.72
		//3.91
		//dll unknown ver
		//x64 dll
		//x64 exe
		//Linux oep.. kinda
			//win
			//linux
			//0xB4 
		//pe.overlay would be nice ;)
		//$aa0 = { 9C 9C ?? ?? ?? ?? ?? E4 72 }
		//BC FB FC 26
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		//vmp x64
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		//1.6
		//1.4.9
		//1.4.4
		//unknown ver
		//wild sig.. unknown ver
		// ELF signature at offset 0 and ...
		// ELF signature at offset 0 and ...
		// MZ signature at offset 0 and ...
		//weirdo yara bug
		// MZ signature at offset 0 and ...
		// ... PE signature at offset stored in MZ header at 0x3C
		//x64
		//x86
		//drop linker checks and allow collissions ? :\
		//this one causes trouble: //does not with 9782 check
		//or //and ((pe.linker_version.major == 5) and (pe.linker_version.minor == 12 )) 
		//need more samples
		//
		//pe.rich_signature.version(31101) and pe.rich_signature.toolid(229) or
/*
YARA rules generated with ./peid2yara.py
BY: Jaume Martin
GITHUB: https://git.todoparami.net/Xumeiquer/PEiD_to_Yara
GENERATED ON: 2016-08-29 21:22:29.883920

Rules generated from:

https://raw.githubusercontent.com/joxeankoret/pyew/VERSION_3X/plugins/UserDB.TXT
https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/peid2yar/dbs/userdb_panda.txt
https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/peid2yar/dbs/userdb_jclausing.txt
https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/peid2yar/dbs/userdb_exeinfope.txt
https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/peid2yar/dbs/eppackersigs.peid
https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/peid2yar/dbs/epcompilersigs.peid
https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/peid2yar/dbs/UserDB.TXT
https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/data/peutils/UserDB.TXT
http://handlers.sans.org/jclausing/userdb.txt
https://raw.githubusercontent.com/seifreed/PEID/master/userdb.txt
https://raw.githubusercontent.com/guelfoweb/peframe/5beta/peframe/signatures/userdb.txt


*/
/*
rule Microsoft_Visual_Cpp_8_additional: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}
*/
/* False positive - #39
rule Armadillo_v171: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 }
    condition:
        $a at pe.entry_point

}*/
/*
rule Armadillo_v4x: PEiD
{
    strings:
        $a = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B }
    condition:
        $a at pe.entry_point

}
*/
/*
rule Microsoft_Visual_Cpp_8: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 }
        $b = { E8 ?? ?? 00 00 E9 ?? ?? FF FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}
*/
