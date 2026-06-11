import "pe"
import "hash"
import "elf"
import "console"
import "dotnet"
import "math"
import "time"

import "elf"
import "math"
import "hash"

rule kobalos {
    meta:
        description = "Kobalos malware"
        author = "Marc-Etienne M.Léveillé"
        date = "2020-11-02"
        reference = "http://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
    strings:
        $encrypted_strings_sizes = {
        05 00 00 00 09 00 00 00 04 00 00 00 06 00 00 00
        08 00 00 00 08 00 00 00 02 00 00 00 02 00 00 00
        01 00 00 00 01 00 00 00 05 00 00 00 07 00 00 00
        05 00 00 00 05 00 00 00 05 00 00 00 0A 00 00 00
    }
    $password_md5_digest = { 3ADD48192654BD558A4A4CED9C255C4C }
    $rsa_512_mod_header = { 10 11 02 00 09 02 00 }
    $strings_RC4_key = { AE0E05090F3AC2B50B1BC6E91D2FE3CE }
    condition:
        any of them
}

rule kobalos_ssh_credential_stealer {
    meta:
        description = "Kobalos SSH credential stealer seen in OpenSSH client"
        author = "Marc-Etienne M.Léveillé"
        date = "2020-11-02"
        reference = "http://www.welivesecurity.com"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
    strings:
        $ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"
    condition:
        any of them
}
rule mumblehard_packer {
    meta:
        description = "Mumblehard i386 assembly code responsible for decrypting Perl code"
        author = "Marc-Etienne M.Léveillé"
        date = "2015-04-07"
        reference = "http://www.welivesecurity.com"
        version = "1"
    strings:
        $decrypt = { 31 db [1-10] ba ?? 00 00 00 [0-6] (56 5f | 89 F7)
        39 d3 75 13 81 fa ?? 00 00 00 75 02 31 d2 81 c2 ?? 00 00
        00 31 db 43 ac 30 d8 aa 43 e2 e2 }
    condition:
        $decrypt
}
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-10
   Identifier: Venom Rootkit
*/

/* Rule Set ----------------------------------------------------------------- */

rule Venom_Rootkit {
   meta:
      description = "Venom Linux Rootkit"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://security.web.cern.ch/security/venom.shtml"
      date = "2017-01-12"
   strings:
      $s1 = "%%VENOM%CTRL%MODE%%" ascii fullword
      $s2 = "%%VENOM%OK%OK%%" ascii fullword
      $s3 = "%%VENOM%WIN%WN%%" ascii fullword
      $s4 = "%%VENOM%AUTHENTICATE%%" ascii fullword
      $s5 = ". entering interactive shell" ascii fullword
      $s6 = ". processing ltun request" ascii fullword
      $s7 = ". processing rtun request" ascii fullword
      $s8 = ". processing get request" ascii fullword
      $s9 = ". processing put request" ascii fullword
      $s10 = "venom by mouzone" ascii fullword
      $s11 = "justCANTbeSTOPPED" ascii fullword
   condition:
      filesize < 4000KB and 2 of them
}
rule APT_MAL_WinntiLinux_Dropper_AzazelFork_May19 : azazel_fork {
    meta:
        description = "Detection of Linux variant of Winnti"
        author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
        version = "1.0"
        date = "2019-05-15"
        TLP = "White"
        sha256 = "4741c2884d1ca3a40dadd3f3f61cb95a59b11f99a0f980dbadc663b85eb77a2a"
    strings:
        $config_decr = { 48 89 45 F0 C7 45 EC 08 01 00 00 C7 45 FC 28 00 00 00 EB 31 8B 45 FC 48 63 D0 48 8B 45 F0 48 01 C2 8B 45 FC 48 63 C8 48 8B 45 F0 48 01 C8 0F B6 00 89 C1 8B 45 F8 89 C6 8B 45 FC 01 F0 31 C8 88 02 83 45 FC 01 }
        $export1 = "our_sockets"
        $export2 = "get_our_pids"
    condition:
        uint16(0) == 0x457f and all of them
}

rule APT_MAL_WinntiLinux_Main_AzazelFork_May19 {
    meta:
        description = "Detection of Linux variant of Winnti"
        author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
        version = "1.0"
        date = "2019-05-15"
        TLP = "White"
        sha256 = "ae9d6848f33644795a0cc3928a76ea194b99da3c10f802db22034d9f695a0c23"
    strings:
        $uuid_lookup = "/usr/sbin/dmidecode  | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null"
        $dbg_msg = "[advNetSrv] can not create a PF_INET socket"
        $rtti_name1 = "CNetBase"
        $rtti_name2 = "CMyEngineNetEvent"
        $rtti_name3 = "CBufferCache"
        $rtti_name4 = "CSocks5Base"
        $rtti_name5 = "CDataEngine"
        $rtti_name6 = "CSocks5Mgr"
        $rtti_name7 = "CRemoteMsg"
    condition:
        uint16(0) == 0x457f and ( ($dbg_msg and 1 of ($rtti*)) or (5 of ($rtti*)) or ($uuid_lookup and 2 of ($rtti*)) )
}
rule SUSP_LNX_Linux_Malware_Indicators_Aug20_1 {
   meta:
      description = "Detects indicators often found in linux malware samples"
      author = "Florian Roth"
      score = 65
      reference = "Internal Research"
      date = "2020-08-03"
   strings:
      $s1 = "&& chmod +x" ascii 
      $s2 = "|base64 -" ascii
      $s3 = " /tmp" ascii 
      $s4 = "|curl " ascii
      $s5 = "whoami" ascii fullword

      $fp1 = "WITHOUT ANY WARRANTY" ascii 
      $fp2 = "postinst" ascii fullword
      $fp3 = "THIS SOFTWARE IS PROVIDED" ascii fullword
      $fp4 = "Free Software Foundation" ascii fullword
   condition:
      filesize < 400KB and
      3 of ($s*) and not 1 of ($fp*)
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

rule Linux_Ransomware_LuckyJoe : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "LUCKYJOE"
        description         = "Yara rule that detects LuckyJoe ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "LuckyJoe"
        tc_detection_factor = 5

    strings:

        $main_call_p1 = {
            55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? 48 
            C7 45 ?? ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 
            48 89 45 ?? 48 8B 55 ?? 48 8B 45 ?? 48 89 D6 48 89 C7 E8 ?? ?? ?? ?? 48 8D 75 ?? 48 
            8B 45 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? BE ?? ?? 
            ?? ?? BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 89 C7 E8 
            ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? E8 ?? ?? 
            ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 35 ?? ?? ?? ?? 48 83 EC ?? 48 8B 45 
            ?? 6A ?? 41 B9 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 C7 
            E8 ?? ?? ?? ?? 48 83 C4 ?? 48 8B 15 ?? ?? ?? ?? 48 8B 45 ?? 48 89 D6 48 89 C7 E8 ?? 
            ?? ?? ?? 48 8B 45 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? 
            ?? ?? 48 98 48 89 45 ?? 48 8B 45 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48
        }

        $main_call_p2 = {
            89 C7 E8 ?? ?? ?? ?? 48 98 48 89 45 ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? 
            ?? 48 89 45 ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 45 
            ?? 89 C2 48 8B 4D ?? 48 8B 45 ?? 48 89 CE 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 89 C2 
            48 8B 4D ?? 48 8B 45 ?? 48 89 CE 48 89 C7 E8 ?? ?? ?? ?? 48 8B 55 ?? 48 8B 45 ?? 48 
            01 D0 C6 00 ?? 48 8B 55 ?? 48 8B 45 ?? 48 01 D0 C6 00 ?? 48 8B 45 ?? 48 8B 55 ?? 48 
            89 D6 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? ?? 75 ?? BF ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 ?? 74 ?? B8 
            ?? ?? ?? ?? E9 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 45 ?? 
            48 83 7D ?? ?? 74 ?? 48 8B 55 ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8
        }

        $main_call_p3 = {
            E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 79 ?? 48 8B 45 ?? 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? 
            ?? ?? E9 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 89 C7 E8 ?? ?? 
            ?? ?? 48 C7 45 ?? ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 45 
            ?? 48 83 7D ?? ?? 74 ?? EB ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? 
            ?? ?? 48 8B 55 ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            89 45 ?? 83 7D ?? ?? 79 ?? 48 8B 45 ?? 89 C7 E8 ?? ?? ?? ?? EB ?? 48 8B 45 ?? 48 89 
            C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 89 C7 E8 ?? ?? ?? ?? EB ?? BF ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 48 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? 
            ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB ?? 8B 45 ?? 48 98 48 8B 84 
            C5 ?? ?? ?? ?? 48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 48 98 
            48 8B 84 C5 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 83 45 ?? ?? 83 7D ?? ?? 74 ?? BF ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 
            ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? C9 C3 
        }

        $encrypt_files_p1 = {
            55 48 89 E5 53 48 81 EC ?? ?? ?? ?? 48 89 BD ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? BA ?? 
            ?? ?? ?? B9 ?? ?? ?? ?? 48 89 C7 48 89 D6 F3 48 A5 48 89 F2 48 89 F8 0F B7 0A 66 89 
            08 48 8D 40 ?? 48 8D 52 ?? 48 C7 45 ?? ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            48 C7 45 ?? ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 89 D7 
            F3 48 AB 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? ?? 75 
            ?? 48 8B 85 ?? ?? ?? ?? 48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? 
            ?? ?? ?? E9 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 D6 48 89 C7 
            E8 ?? ?? ?? ?? 48 8B 45 ?? 0F B6 40 ?? 3C ?? 0F 85 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 
            48 89 C7 E8 ?? ?? ?? ?? 48 89 C3 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 
            01 D8 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 85 ?? ?? ?? ?? BE ?? ?? 
            ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 84 C0 74 ?? 48 8B 45 ?? 48 8D 48 ?? 48 8B 95 ?? ?? ?? 
            ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB ?? 48 8B 45 
            ?? 48 8D 48 ?? 48 8B 95 ?? ?? ?? ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B 4D ?? 48 8D 85 ?? ?? ?? ?? 48 89 CE 48 
            89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? EB ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? 
            ?? 48 89 C2 48 8B 45 ?? 48 89 C6 48 89 D7 E8 ?? ?? ?? ?? 85 C0 75 ?? 48 8B 45 ?? 48
        }

        $encrypt_files_p2 = {
            89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? 
            ?? EB ?? 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 
            89 45 ?? 48 83 7D ?? ?? 75 ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 
            8B 45 ?? 0F B6 40 ?? 3C ?? 0F 85 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C0 ?? BE ?? ?? ?? ?? 
            48 89 C7 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C0 ?? BE ?? ?? ?? 
            ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 45 
            ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 C3 48 8B 45 ?? 48 89 C7 E8 ?? 
            ?? ?? ?? 48 01 D8 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 85 ?? ?? ?? 
            ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 84 C0 74 ?? 48 8B 45 ?? 48 8D 48 ?? 48 8B 
            95 ?? ?? ?? ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 
            ?? 48 8B 45 ?? 48 8D 48 ?? 48 8B 95 ?? ?? ?? ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 
            C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? ?? 0F 
            85 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 5B 5D C3 
        }

        $encrypt_internal_message_p1 = {
            55 48 89 E5 53 48 83 EC ?? 48 89 7D ?? 48 89 75 ?? 48 C7 45 ?? ?? ?? ?? ?? BF ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 89 45 ?? 48 8B 
            45 ?? 48 89 C7 E8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 83 C0 ?? 48 98 48 89 C7 E8 ?? ?? ?? 
            ?? 48 89 45 ?? 8B 45 ?? 83 C0 ?? 48 63 D0 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? 
            ?? ?? ?? 8B 45 ?? 48 63 D0 48 8B 4D ?? 48 8B 45 ?? 48 89 CE 48 89 C7 E8 ?? ?? ?? ?? 
            8B 45 ?? 48 98 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? 8B 45 ?? 83 E8 ?? 89 45 ?? C7 45 ?? ?? ?? ?? ?? 66 0F EF C0 F2 0F 2A 45 ?? 
            66 0F EF C9 F2 0F 2A 4D ?? F2 0F 5E C1 E8 ?? ?? ?? ?? F2 0F 2C C0 89 45 ?? 8B 45 ?? 
            0F AF 45 ?? 48 98 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 8B 45 ?? 0F AF 45 ?? 48 63 D0 
            48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 8B 45 ?? 0F AF 45 ?? 89 C3 48 8B 
            45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 C6 8B 45 ?? 89 C1 89 DA BF ?? ?? ?? ?? B8 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? E9 ?? ?? ?? ?? 8B 45 ?? 2B 45 ?? 3B 45 ?? 7D ?? 8B 45 ?? 2B 45 ?? 89 45 ?? 8B 45 
            ?? 48 63 D0 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 8B 45 ?? 2B 45 ?? 89
        }

        $encrypt_internal_message_p2 = {
            C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 48 63 D0 48 8B 45 ?? 48 8D 
            34 02 48 8B 4D ?? 48 8B 55 ?? 8B 45 ?? 41 B8 ?? ?? ?? ?? 89 C7 E8 ?? ?? ?? ?? 89 45 
            ?? 8B 45 ?? 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 75 ?? E8 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C2 48 8B 45 ?? 48 89 C6 48 89 D7 E8 ?? ?? ?? ?? 48 
            8B 05 ?? ?? ?? ?? 48 8B 55 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 
            48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? 
            ?? ?? 8B 45 ?? 48 63 D0 8B 45 ?? 48 63 C8 48 8B 45 ?? 48 01 C1 48 8B 45 ?? 48 89 C6 
            48 89 CF E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 C6 BF ?? ?? ?? ?? 
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 01 45 ?? 8B 45 ?? 01 45 ?? 48 8B 45 ?? 48 89 
            C7 E8 ?? ?? ?? ?? 83 45 ?? ?? 8B 45 ?? 3B 45 ?? 0F 8E ?? ?? ?? ?? 48 8B 45 ?? 48 89 
            C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 8B 4D ?? 48 8B 45 ?? BA ?? ?? 
            ?? ?? 89 CE 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 
            48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C4 ?? 5B 5D 
            C3 
        }

    condition:
        uint32(0) == 0x464C457F and
        (
           all of ($main_call_p*)
        ) and
        (
           all of ($encrypt_files_p*)
        ) and 
        (
           all of ($encrypt_internal_message_p*)
        )
}

rule Linux_Virus_Vit : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "VIT"
        description         = "Yara rule that detects Vit virus."

        tc_detection_type   = "Virus"
        tc_detection_name   = "Vit"
        tc_detection_factor = 5

    strings:

      $vit_entry_point = {
        55 89 E5 81 EC 40 31 00 00 57 56 50 53 51 52 C7 85 D8 CE FF FF 00 00 00 00 C7 85 D4
        CE FF FF 00 00 00 00 C7 85 FC CF FF FF CA 08 00 00 C7 85 F8 CF FF FF B8 06 00 00 C7
        85 F4 CF FF FF AD 08 00 00 C7 85 F0 CF FF FF 50 06 00 00 6A 00 6A 00 8B 45 08 50 E8
        18 FA FF FF 89 C6 83 C4 0C 85 F6 0F 8C E6 01 00 00 6A 00 68 ?? ?? ?? ?? 56 E8 2E FA
        FF FF 83 C4 0C 85 C0 0F 8C C4 01 00 00 8B 85 FC CF FF FF 50 8D 85 00 D0 FF FF 50 56
        E8 2A FA FF FF 89 C2 8B 85 FC CF FF FF 83 C4 0C 39 C2 0F 85 9D 01 00 00 56 E8 E1 F9
        FF FF BE FF FF FF FF 6A 00 6A 00 E9
      }

      $vit_str = "vi324.tmp"

    condition:
        uint32(0) == 0x464C457F and $vit_entry_point at elf.entry_point and $vit_str
}

rule EXPL_Log4j_CVE_2021_44228_Dec21_Hard {
   meta:
      description = "Detects indicators in server logs that indicate the exploitation of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
      date = "2021-12-10"
      score = 80
   strings:
      $x1 = /\$\{jndi:(ldap|ldaps|rmi|dns):\/[\/]?[a-z-\.0-9]{3,120}:[0-9]{2,5}\/[a-zA-Z\.]{1,32}\}/
      $fp1r = /(ldap|rmi|ldaps|dns):\/[\/]?(127\.0\.0\.1|192\.168\.|172\.[1-3][0-9]\.|10\.)/
   condition:
      $x1 and not 1 of ($fp*)
}

rule SUSP_Base64_Encoded_Exploit_Indicators_Dec21 {
   meta:
      description = "Detects base64 encoded strings found in payloads of exploits against log4j CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/Reelix/status/1469327487243071493"
      date = "2021-12-10"
      score = 70
   strings:
      /* curl -s  */
      $sa1 = "Y3VybCAtcy"
      $sa2 = "N1cmwgLXMg"
      $sa3 = "jdXJsIC1zI"
      /* |wget -q -O-  */
      $sb1 = "fHdnZXQgLXEgLU8tI"
      $sb2 = "x3Z2V0IC1xIC1PLS"
      $sb3 = "8d2dldCAtcSAtTy0g"
   condition:
      1 of ($sa*) and 1 of ($sb*)
}

rule EXPL_JNDI_Exploit_Patterns_Dec21_1 {
   meta:
      description = "Detects JNDI Exploit Kit patterns in files"
      author = "Florian Roth"
      reference = "https://github.com/pimps/JNDI-Exploit-Kit"
      date = "2021-12-12"
      score = 60
   strings:
      $x01 = "/Basic/Command/Base64/"
      $x02 = "/Basic/ReverseShell/"
      $x03 = "/Basic/TomcatMemshell"
      $x04 = "/Basic/JettyMemshell"
      $x05 = "/Basic/WeblogicMemshell"
      $x06 = "/Basic/JBossMemshell"
      $x07 = "/Basic/WebsphereMemshell"
      $x08 = "/Basic/SpringMemshell"
      $x09 = "/Deserialization/URLDNS/"
      $x10 = "/Deserialization/CommonsCollections1/Dnslog/"
      $x11 = "/Deserialization/CommonsCollections2/Command/Base64/"
      $x12 = "/Deserialization/CommonsBeanutils1/ReverseShell/"
      $x13 = "/Deserialization/Jre8u20/TomcatMemshell"
      $x14 = "/TomcatBypass/Dnslog/"
      $x15 = "/TomcatBypass/Command/"
      $x16 = "/TomcatBypass/ReverseShell/"
      $x17 = "/TomcatBypass/TomcatMemshell"
      $x18 = "/TomcatBypass/SpringMemshell"
      $x19 = "/GroovyBypass/Command/"
      $x20 = "/WebsphereBypass/Upload/"

      $fp1 = "<html"
      $fp2 = "GET / HTTP/1.1"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule EXPL_Log4j_CVE_2021_44228_JAVA_Exception_Dec21_1 {
   meta:
      description = "Detects exceptions found in server logs that indicate an exploitation attempt of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b"
      date = "2021-12-12"
      score = 60
   strings:
      $xa1 = "header with value of BadAttributeValueException: "

      $sa1 = ".log4j.core.net.JndiManager.lookup(JndiManager"
      $sa2 = "Error looking up JNDI resource"
   condition:
      $xa1 or all of ($sa*)
}

rule EXPL_Log4j_CVE_2021_44228_Dec21_Soft {
   meta:
      description = "Detects indicators in server logs that indicate an exploitation attempt of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
      date = "2021-12-10"
      modified = "2021-12-13"
      score = 60
   strings:
      $x01 = "${jndi:ldap:/"
      $x02 = "${jndi:rmi:/"
      $x03 = "${jndi:ldaps:/"
      $x04 = "${jndi:dns:/"
      $x05 = "${jndi:iiop:/"
      $x06 = "${jndi:http:/"
      $x07 = "${jndi:nis:/"
      $x08 = "${jndi:nds:/"
      $x09 = "${jndi:corba:/"

      $fp1 = "<html"
      $fp2 = "/root/.bash_history"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule EXPL_Log4j_CVE_2021_44228_Dec21_OBFUSC {
   meta:
      description = "Detects obfuscated indicators in server logs that indicate an exploitation attempt of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
      date = "2021-12-12"
      modified = "2021-12-13"
      score = 60
   strings:
      $x1 = "$%7Bjndi:"
      $x2 = "%2524%257Bjndi"
      $x3 = "%2F%252524%25257Bjndi%3A"
      $x4 = "${jndi:${lower:"
      $x5 = "${::-j}${"
      $x6 = "${${env:BARFOO:-j}"
      $x7 = "${::-l}${::-d}${::-a}${::-p}"
      $x8 = "${base64:JHtqbmRp"

      $fp1 = "<html"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule SUSP_JDNIExploit_Indicators_Dec21 {
   meta:
      description = "Detects indicators of JDNI usage in log files and other payloads"
      author = "Florian Roth"
      reference = "https://github.com/flypig5211/JNDIExploit"
      date = "2021-12-10"
      modified = "2021-12-12"
      score = 70
   strings:
      $xr1 = /(ldap|ldaps|rmi|dns|iiop|http|nis|nds|corba):\/\/[a-zA-Z0-9\.]{7,80}:[0-9]{2,5}\/(Basic\/Command\/Base64|Basic\/ReverseShell|Basic\/TomcatMemshell|Basic\/JBossMemshell|Basic\/WebsphereMemshell|Basic\/SpringMemshell|Basic\/Command|Deserialization\/CommonsCollectionsK|Deserialization\/CommonsBeanutils|Deserialization\/Jre8u20\/TomcatMemshell|Deserialization\/CVE_2020_2555\/WeblogicMemshell|TomcatBypass|GroovyBypass|WebsphereBypass)\//
   condition:
      filesize < 100MB and $xr1
}

rule SUSP_EXPL_OBFUSC_Dec21_1 {
   meta:
      description = "Detects obfuscation methods used to evade detection in log4j exploitation attempt of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/testanull/status/1469549425521348609"
      date = "2021-12-11"
      score = 60
   strings:
      /* ${lower:X} - single character match */
      $x1 = { 24 7B 6C 6F 77 65 72 3A ?? 7D }
      /* ${upper:X} - single character match */
      $x2 = { 24 7B 75 70 70 65 72 3A ?? 7D }
      /* URL encoded lower - obfuscation in URL */
      $x3 = "$%7blower:"
      $x4 = "$%7bupper:"
      $x5 = "%24%7bjndi:"
      $x6 = "$%7Blower:"
      $x7 = "$%7Bupper:"
      $x8 = "%24%7Bjndi:"

      $fp1 = "<html"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule SUSP_JDNIExploit_Error_Indicators_Dec21_1 {
   meta:
      description = "Detects error messages related to JDNI usage in log files that can indicate a Log4Shell / Log4j exploitation"
      author = "Florian Roth"
      reference = "https://twitter.com/marcioalm/status/1470361495405875200?s=20"
      date = "2021-12-10"
      modified = "2021-12-17"
      score = 70
   strings:
      $x1 = "FATAL log4j - Message: BadAttributeValueException: "
      $x2 = "Error looking up JNDI resource"
   condition:
      1 of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_1 {
   meta:
      description = "Detects unknown Linux implants (uploads from KR and MO)"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-05"
      score = 90
      hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
      hash2 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
      hash3 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
      hash4 = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
      hash5 = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
      hash6 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
      hash7 = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
      hash8 = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
      hash9 = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
      hash10 = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"
   strings:
      $s1 = "[-] Connect failed." ascii fullword
      $s2 = "export MYSQL_HISTFILE=" ascii fullword
      $s3 = "udpcmd" ascii fullword
      $s4 = "getshell" ascii fullword

      $op1 = { e8 ?? ff ff ff 80 45 ee 01 0f b6 45 ee 3b 45 d4 7c 04 c6 45 ee 00 80 45 ff 01 80 7d ff 00 }
      $op2 = { 55 48 89 e5 48 83 ec 30 89 7d ec 48 89 75 e0 89 55 dc 83 7d dc 00 75 0? }
      $op3 = { e8 a? fe ff ff 0f b6 45 f6 48 03 45 e8 0f b6 10 0f b6 45 f7 48 03 45 e8 0f b6 00 8d 04 02 }
      $op4 = { c6 80 01 01 00 00 00 48 8b 45 c8 0f b6 90 01 01 00 00 48 8b 45 c8 88 90 00 01 00 00 c6 45 ef 00 0f b6 45 ef 88 45 ee }
   condition:
      uint16(0) == 0x457f and
      filesize < 80KB and 2 of them or 5 of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_2 {
   meta:
      description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-07"
      score = 85
      hash1 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
      hash2 = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
      hash3 = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
      hash4 = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"
   strings:
      $opx1 = { 48 83 c0 0c 48 8b 95 e8 fe ff ff 48 83 c2 0c 8b 0a 8b 55 f0 01 ca 89 10 c9 }
      $opx2 = { 48 01 45 e0 83 45 f4 01 8b 45 f4 3b 45 dc 7c cd c7 45 f4 00 00 00 00 eb 2? 48 8b 05 ?? ?? 20 00 }

      $op1 = { 48 8d 14 c5 00 00 00 00 48 8b 45 d0 48 01 d0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 83 c0 01 48 01 45 e0 }
      $op2 = { 89 c2 8b 85 fc fe ff ff 01 c2 8b 45 f4 01 d0 2d 7b cf 10 2b 89 45 f4 c1 4d f4 10 }
      $op3 = { e8 ?? d? ff ff 8b 45 f0 eb 12 8b 85 3c ff ff ff 89 c7 e8 ?? d? ff ff b8 ff ff ff ff c9 }
   condition:
      uint16(0) == 0x457f and
      filesize < 100KB and 2 of ($opx*) or 4 of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_3 {
   meta:
      description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-08"
      score = 85
      hash1 = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
      hash2 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
   strings:
      $s1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
      $s2 = "/sbin/mingetty /dev" ascii fullword
      $s3 = "pickup -l -t fifo -u" ascii fullword
   condition:
      uint16(0) == 0x457f and
      filesize < 200KB and 2 of them or all of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_Generic_May22_1 {
   meta:
      description = "Detects BPFDoor malware"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-09"
      score = 90
      hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
      hash2 = "1925e3cd8a1b0bba0d297830636cdb9ebf002698c8fa71e0063581204f4e8345"
      hash3 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
      hash4 = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
      hash5 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
      hash6 = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
      hash7 = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
      hash8 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
      hash9 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
      hash10 = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
      hash11 = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
      hash12 = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
      hash13 = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
      hash14 = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"
      hash15 = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
      hash16 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
      hash17 = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"
   strings:
      $op1 = { c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 ?? 88 45 }
      $op2 = { 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 }
      $op3 = { 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 88 45 f? c7 45 f8 00 00 00 00 }
      $op4 = { 48 89 7d d8 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? }
      $op5 = { 48 8b 45 ?8 c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 }
      $op6 = { 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 }
   condition:
      uint16(0) == 0x457f and
      filesize < 200KB and 2 of them or 4 of them
}

rule Linux_Trojan_Ebury_7b13e9b6 {
    meta:
        id = "7b13e9b6-ce96-4bd3-8196-83420280bd1f"
        fingerprint = "a891724ce36e86637540f722bc13b44984771f709219976168f12fe782f08306"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ebury"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 44 24 10 4C 8B 54 24 18 4C 8B 5C 24 20 8B 5C 24 28 74 04 }
    condition:
        all of them
}

rule Dacls_Trojan_Linux {
    meta:
        Author = "Adam M. Swanda"
        Repo = "https://github.com/deadbits/yara-rules"

    strings:
        $cls00 = "c_2910.cls" ascii fullword
        $cls01 = "k_3872.cls" ascii fullword

        $str00 = "{\"result\":\"ok\"}" ascii fullword
        $str01 = "SCAN  %s  %d.%d.%d.%d %d" ascii fullword
        $str02 = "/var/run/init.pid" ascii fullword
        $str03 = "/flash/bin/mountd" ascii fullword
        $str04 = "Name:" ascii fullword
        $str05 = "Uid:" ascii fullword
        $str06 = "Gid:" ascii fullword
        $str08 = "PPid:" ascii fullword
        $str09 = "session_id" ascii fullword

    condition:
        uint32be(0x0) == 0x7f454c46
        and
        (
            (all of ($cls*))

            or

            (all of ($str*))

        )
}

rule ACBackdoor_ELF: linux malware backdoor {
    meta:
        author = "Adam M. Swanda"
        date = "Nov 2019"
        reference = "https://www.intezer.com/blog-acbackdoor-analysis-of-a-new-multiplatform-backdoor/"

    strings:
        $ua_str = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" ascii fullword
        $header1 = "Access-Control:" ascii fullword
        $header2 = "X-Access" ascii

        $initd = "/etc/init.d/update-notifier" ascii fullword
        $str001 = "#!/bin/sh -e" ascii fullword
        $str002 = "### BEGIN INIT INFO" ascii fullword
        $str003 = "# Provides:          update-notifier" ascii fullword
        $str004 = "# Required-Start:    $local_fs" ascii fullword
        $str005 = "# Required-Stop:" ascii fullword
        $str006 = "# Default-Start:     S" ascii fullword
        $str007 = "# Default-Stop:" ascii fullword
        $str008 = "### END INIT INFO" ascii fullword
        $str010 = "  *) echo \"Usage: $0 {start|stop|restart|force-reload}\" >&2; ;;" ascii fullword
        $str011 = "esac" ascii fullword
        $str012 = "[ -x /usr/local/bin/update-notifier ] \\" ascii fullword
        $str013 = "    && exec /usr/local/bin/update-notifier" ascii fullword
        $rcd01 = "/etc/rc2.d/S01update-notifier" ascii fullword
        $rcd02 = "/etc/rc3.d/S01update-notifier" ascii fullword
        $rcd03 = "/etc/rc5.d/S01update-notifier" ascii fullword

    condition:
        /* trigger = '{7f 45 4c 46}' - ELF magic bytes */
        (uint32be(0x0) == 0x7f454c46)
        and
        (
            ($ua_str and all of ($header*) and $initd and all of ($rcd*))
            or
            (
                $ua_str and all of ($header*) and 10 of ($str*)
            )
        )
}

rule Linux_Golang_Ransomware: linux ransomware golang {
    meta:
        author = "Adam M. Swanda"
        reference = "https://www.fortinet.com/blog/threat-research/new-golang-ransomware-targeting-linux-systems.html"

    strings:
        $str001 = "1) Email: fullofdeep@protonmail.com" ascii fullword
        $str002 = "https://ipapi.com/json/idna:" ascii
        $str003 = "%s.encrypted.localhost" ascii
        $str004 = ".local.onion" ascii
        $str005 = "DO NOT TRY TO DO SOMETHING TO YOUR FILES YOU WILL BRAKE YOUR DATA" ascii fullword
        $str006 = "4.We can decrypt few files in quality the evidence that we have the decoder." ascii fullword

    condition:
        uint32be(0x0) == 0x7f454c46
        and all of them
}

rule GodLua_Linux: linuxmalware {
   meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:

      $tmp0 = "/tmp" ascii fullword
      $tmp1 = "TMPDIR" ascii

      $str1 = "\"description\": \"" ascii fullword
      $str2 = "searchers" ascii fullword
      $str3 = "/dev/misc/watchdog" ascii fullword
      $str4 = "/dev/wdt" ascii fullword
      $str5 = "/dev/misc/wdt"
      $str6 = "lcurl.safe" ascii fullword
      $str7 = "luachild" ascii fullword
      $str8 = "cjson.safe" ascii fullword
      $str9 = "HostUrl" ascii fullword
      $str10 = "HostConnect" ascii fullword
      $str11 = "LUABOX" ascii fullword
      $str12 = "Infinity" ascii fullword
      $str13 = "/bin/sh" ascii fullword
      $str14 = /\.onion(\.)?/ ascii fullword
      $str15 = "/etc/resolv.conf" ascii fullword
      $str16 = "hosts:" ascii fullword

      $resolvers = /([0-9]{1,3}\.){3}[0-9]{1,3}:53,([0-9]{1,3}\.){3}[0-9]{1,3},([0-9]{1,3}\.){3}[0-9]{1,3}:5353,([0-9]{1,3}\.){3}[0-9]{1,3}:443/ ascii

      $identifier0 = "$LuaVersion: God " ascii
      $identifier1 = /fbi\/d\.\/d.\/d/ ascii
      $identifier2 = "Copyright (C) FBI Systems, 2012-2019, https://fbi.gov" fullword ascii
      $identifier3 = "God 5.1"

   condition:
      uint16(0) == 0x457f
      and
      (
         all of them
         or
         (
            any of ($identifier*)
            and $resolvers
            and any of ($tmp*)
            and 4 of ($str*)
         )
         or
         (
            any of ($identifier*)
            and any of ($tmp*)
            and 4 of ($str*)
         )
      )
}

rule Winnti_Linux: linuxmalware {
   meta:
      Author = "Adam M. Swanda"
      Website = "https://www.deadbits.org"
      Repo = "https://github.com/deadbits/yara-rules"
      Date = "2019-07-18"

   strings:
      $str0 = "HIDE_THIS_SHELL=x"
      $str1 = "/usr/sbin/dmidecode  | grep -i 'UUID' |cut -d' ' -f2 2>/dev/null" ascii fullword
      $str2 = "mutex.max:  %lu" ascii fullword
      $str3 = "mutex.err:  %lu" ascii fullword
      $str4 = "/tmp/ans.log" ascii fullword
      $str5 = "mutex.used: %lu" ascii fullword
      $str6 = "Warning: Some of the worker threads may have failed to exit." ascii fullword
      $str7 = "line %d - " ascii fullword
      $str8 = "Warning an error has occurred when trying to obtain a worker task." ascii fullword
      $str9 = "6CMutex" ascii fullword
      $str10 = "Failed to obtain an empty task from the free tasks queue." ascii fullword
      $str11 = "A problem was detected in the queue (expected NULL, but found a different value)." ascii fullword
      $str12 = "Failed to a task to the free tasks queue during initialization." ascii fullword
      $str13 = "/var/run/libudev1.pid" ascii fullword
      $str14 = "__pthread_key_create" ascii fullword
      $str15 = "The threadpool received as argument is NULL." ascii fullword
      $str16 = "Failed to enqueue a task to free tasks queue." ascii fullword
      $str17 = "Failed to obtain a task from the jobs queue." ascii fullword
      $str18 = "Failed to add a new task to the tasks queue." ascii fullword
      $str19 = "setsockopt  failed" ascii fullword
      $str20 = "libxselinux.so" ascii fullword
      $str21 = "/lib/libxselinux" ascii fullword

    condition:
      uint16(0) == 0x457f
      and
      8 of them
}

rule WatchDog_Botnet: botnet linuxmalware exploitation cve_2019_11581 cve_2019_10149 {
    meta:

        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-07-22"
        Reference = "https://twitter.com/polarply/status/1153232987762376704"

    strings:

        // $email = "jeff4r@watchbog.com"
        $py0 = "libpython" ascii
        //$py1 = "jail.py" ascii fullword

        //$rcpt1 = "RCPT TO:<${run{\x2Fbin\x2Fsh\t-c\t\x22bash\x20\x2Ftmp\x2Fbaby\x22}}@localhost>" ascii fullword
        //$rcpt2 = /RCPT TO:<\$\{run\{\\x2Fbin\\x2Fsh\\t-c\\t\\x22curl\\x20https\\x3a\\x2F\\x2Fpastebin.com\\x2Fraw/

        $str0 = "*/3 * * * * root wget -q -O- https://pastebin.com/raw/" ascii
        $str1 = "*/1 * * * * root curl -fsSL https://pastebin.com/raw/" ascii
        $str6 = "onion.to"
        $str7 = /https?:\/\/pastebin.com\/raw/ nocase
        $str8 = "http://icanhazip.com/"
        $str9 = "http://ident.me/"

        $scan0 = "Scan_run"
        $scan1 = "scan_nexus"
        $scan2 = "scan_couchdb"
        $scan3 = "scan_jenkins"
        $scan4 = "scan_laravel"
        $scan5 = "scan_redis"

        $exploit01 = "CVE_2015_4335"
        $exploit02 = "CVE_2018_1000861"
        $exploit03 = "CVE_2018_8007"
        $exploit04 = "CVE_2019_1014"
        $exploit05 = "CVE_2019_11581"
        $exploit06 = "CVE_2019_7238"

        $pwn0 = "pwn_couchdb"
        $pwn1 = "pwn_jenkins"
        $pwn2 = "pwn_jira"
        $pwn3 = "pwn_nexus"
        $pwn4 = "pwn_redis"
        $pwn5 = "pwn_exim"

        $payload = /payload(s)/ nocase
        $jira_token = "atlassian.xsrf.token=%s" ascii fullword
        $jira_cmd = "set ($cmd=\"%s\")" ascii fullword
        $jira_id = "JSESSIONID=%s" ascii fullword

        /*
        dont know if i really want to add these
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0_2"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_6_0_3"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_2"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_3"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0_4"
            $user_agent00 = "Mozilla_4_0_compatible_MSIE_7_0b"
            $user_agent00 = "Mozilla_5_0_Macintosh_Intel_Mac"
            $user_agent00 = "Mozilla_5_0_Windows_NT_5_1_Apple"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_2"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_3"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_4"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_5"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_WOW64_6"
            $user_agent00 = "Mozilla_5_0_Windows_NT_6_1_Win64"
            $user_agent00 = "Mozilla_5_0_Windows_U_MSIE_9_0_W"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT_2"
            $user_agent00 = "Mozilla_5_0_Windows_U_Windows_NT_3"
            $user_agent00 = "Mozilla_5_0_X11_Linux_i686_U_Gec"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_en_US_Ap"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_i686_en"
            $user_agent00 = "Mozilla_5_0_X11_U_Linux_x86_64_z"
            $user_agent00 = "Mozilla_5_0_X11_Ubuntu_Linux_x86"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_8_0"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0_2"
            $user_agent00 = "Mozilla_5_0_compatible_MSIE_9_0_3"
            $user_agent00 = "Mozilla_5_0_iPad_U_CPU_OS_4_2_1"
        */

    condition:
        uint32be(0x0) == 0x7f454c46
        and $py0
        and
        (
            (all of ($pwn*) and all of ($scan*))
            or
            ($payload and all of ($jira*) and 5 of ($str*))
            or
            (all of ($str*) and all of ($exploit*))
        )
}

rule RedGhost_Linux: postexploitation linuxmalware {
    meta:

        Author = "Adam M. Swanda"
        Website = "https://www.deadbits.org"
        Repo = "https://github.com/deadbits/yara-rules"
        Date = "2019-08-07"
        Reference = "https://github.com/d4rk007/RedGhost/"

    strings:
        $name = "[ R E D G H O S T - P O S T  E X P L O I T - T O O L]" ascii

        $feature0 = "Payloads" ascii
        $feature1 = "SudoInject" ascii
        $feature2 = "lsInject" ascii
        $feature3 = "Crontab" ascii
        $feature4 = "GetRoot" ascii
        $feature5 = "Clearlogs" ascii
        $feature6 = "MassinfoGrab" ascii
        $feature7 = "CheckVM" ascii
        $feature8 = "MemoryExec" ascii
        $feature9 = "BanIP" ascii

        $func0 = "checkVM(){" ascii
        $func1 = "memoryexec(){" ascii
        $func2 = "banip(){" ascii
        $func3 = "linprivesc(){" ascii
        $func4 = "dirty(){" ascii
        $func5 = "Ocr(){" ascii
        $func6 = "clearlog(){" ascii
        $func7 = "conmethods(){" ascii
        $func8 = "add2sys(){" ascii

        //$header = "#!/bin/bash" ascii

    condition:
      // #!/bin/bash header
      (uint16be(0x0) == 0x2321 and 
      for any i in (0..64) : (
          uint16be(i) == 0x2f62 and uint8(i+2) == 0x68
      ))
      and
      ($name or 5 of them)
}

rule Linux_Trojan_Pornoasset_927f314f {
    meta:
        author = "Elastic Security"
        id = "927f314f-2cbb-4f87-b75c-9aa5ef758599"
        fingerprint = "7214d3132fc606482e3f6236d291082a3abc0359c80255048045dba6e60ec7bf"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Pornoasset"
        reference_sample = "d653598df857535c354ba21d96358d4767d6ada137ee32ce5eb4972363b35f93"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 D3 CB D3 C3 48 31 C3 48 0F AF F0 48 0F AF F0 48 0F AF F0 48 }
    condition:
        all of them
}

rule MALWARE_Multi_Exaramel {
    meta:
        author = "ditekSHen"
        description = "Exaramel Windows/Linux backdoor payload"
        clamav_sig1 = "MALWARE_Linux.Backdoor.Exaramel"
    strings:
        // Linux payload
        $s1 = "vendor/golang_org/x/crypto/" ascii
        $s2 = "vendor/golang_org/x/net/http2" ascii
        $s3 = "vendor/golang_org/x/text/unicode" ascii
        $s4 = "vendor/golang_org/x/text/transform" ascii
        $s5 = "config.json" ascii
        $cmd1 = "App.Update" ascii
        $cmd2 = "App.Delete" ascii
        $cmd3 = "App.SetProxy" ascii
        $cmd4 = "App.SetServer" ascii
        $cmd5 = "App.SetTimeout" ascii
        $cmd6 = "IO.WriteFile" ascii
        $cmd7 = "IO.ReadFile" ascii
        $cmd8 = "OS.ShellExecute" ascii
        $cmd9 = "awk 'match($0, /(upstart|systemd|sysvinit)/){ print substr($0, RSTART, RLENGTH);exit;" ascii
    condition:
        (uint16(0) == 0x457f and (all of ($s*) and 6 of ($cmd*)))
}

rule MALWARE_Linux_ChaChaDDoS {
    meta:
        author = "ditekSHen"
        description = "ChaChaDDoS variant of XorDDoS payload"
    strings:
        $x1 = "[kworker/1:1]" ascii
        $x2 = "-- LuaSocket toolkit." ascii
        $x3 = "/etc/resolv.conf" ascii
        $x4 = "\"macaddress=\" .. DEVICE_MAC .. \"&device=\" .." ascii
        $x5 = "easy_attack_dns" ascii
        $x6 = "easy_attack_udp" ascii
        $x7 = "easy_attack_syn" ascii
        $x8 = "syn_probe" ascii
    condition:
    uint16(0) == 0x457f and 6 of them
}

rule MALWARE_Linux_XORDDoS {
    meta:
        author = "ditekSHen"
        description = "Detects XORDDoS"
    strings:
        $s1 = "for i in `cat /proc/net/dev|grep :|awk -F: {'print $1'}`; do ifconfig $i up& done" fullword ascii
        $s2 = "cp /lib/libudev.so /lib/libudev.so.6" fullword ascii
        $s3 = "sed -i '/\\/etc\\/cron.hourly\\/gcc.sh/d' /etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab" fullword ascii
        $s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; TencentTraveler ; .NET CLR 1.1.4322)" fullword ascii
    condition:
      uint32(0) == 0x464c457f and 3 of them
}

rule Linux_Trojan_Xorddos_2aef46a6 {
    meta:
        author = "Elastic Security"
        id = "2aef46a6-6daf-4f02-b1b4-e512cea12e53"
        fingerprint = "e583729c686b80e5da8e828a846cbd5218a4d787eff1fb2ce84a775ad67a1c4d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 25 64 2D 2D 25 73 5F 25 64 3A 25 73 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_a6572d63 {
    meta:
        author = "Elastic Security"
        id = "a6572d63-f9f3-4dfb-87e6-3b0bafd68a79"
        fingerprint = "fd32a773785f847cdd59d41786a8d8a7ba800a71d40d804aca51286d9bb1e1f0"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2ff33adb421a166895c3816d506a63dff4e1e8fa91f2ac8fb763dc6e8df59d6e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C8 0F B6 46 04 0F B6 56 05 C1 E0 08 09 D0 89 45 CC 0F B6 46 06 0F B6 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_e41143e1 {
    meta:
        author = "Elastic Security"
        id = "e41143e1-52d9-45c7-b19f-a5475b18a510"
        fingerprint = "f621a2e8c289772990093762f371bb6d5736085695881e728a0d2c013c2ad1d4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 1E 80 3C 06 00 8D 14 30 8D 4C 37 FF 74 0D EB 36 0F B6 42 01 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_0eb147ca {
    meta:
        author = "Elastic Security"
        id = "0eb147ca-ec6d-4a6d-b807-4de8c1eff875"
        fingerprint = "6a1667f585a7bee05d5aece397a22e376562d2b264d3f287874e5a1843e67955"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 83 45 F0 01 8B 45 F0 89 45 E8 8B 45 E8 83 C4 18 5F 5D C3 55 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_884cab60 {
    meta:
        author = "Elastic Security"
        id = "884cab60-214f-4879-aa51-c00de1a5ffc4"
        fingerprint = "47895e9c8acf66fc853c7947dc53730967d5a4670ef59c96569c577e1a260a72"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E4 8B 51 64 F6 C2 10 75 12 89 CB 89 D1 83 C9 40 89 D0 F0 0F B1 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ba961ed2 {
    meta:
        author = "Elastic Security"
        id = "ba961ed2-b410-4da5-8452-a03cf5f59808"
        fingerprint = "fff4804164fb9ff1f667d619b6078b00a782b81716e217ad2c11df80cb8677aa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F8 C9 C3 55 89 E5 83 EC 38 C7 45 F8 FF FF FF FF C7 45 FC FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_2084099a {
    meta:
        author = "Elastic Security"
        id = "2084099a-1df6-4481-9d13-3a5bd6a53817"
        fingerprint = "dfb813a5713f0e7bdb5afd500f1e84c6f042c8b1a1d27dd6511dca7f2107c13b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xorddos"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 FC 8B 50 18 8B 45 08 89 50 18 8B 45 FC 8B 40 08 85 C0 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_61c88137 {
    meta:
        author = "Elastic Security"
        id = "61c88137-02f6-4339-b8fc-04c72a5023aa"
        fingerprint = "c09b31424a54e485fe5f89b4ab0a008df6e563a75191f19de12113890a4faa39"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "479ef38fa00bb13a3aa8448aa4a4434613c6729975e193eec29fc5047f339111"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 8B C1 8B 0C 24 8D 64 24 FC 89 0C 24 8B 4D E8 87 0C 24 96 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_debb98a1 {
    meta:
        author = "Elastic Security"
        id = "debb98a1-c861-4458-8bff-fae4f00a17dc"
        fingerprint = "2c5688a82f7d39b0fceaf4458856549b1bce695a160a864f41b12b42e86e3745"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "494f549e3dd144e8bcb230dd7b3faa8ff5107d86d9548b21b619a0318e362cad"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 87 5D F4 5B 9C 51 8B 4C 24 04 8D 49 2A 87 4C 24 04 89 4C }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_1d6e10fd {
    meta:
        author = "Elastic Security"
        id = "1d6e10fd-7404-4597-a97d-cc92849d84f4"
        fingerprint = "bf9d971a13983f1d0fdc8277e76cd1929523e239ce961316fe1f44cbdf0638a8"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "4c7851316f01ae84ee64165be3ba910ab9b415d7f0e2f5b7e5c5a0eaefa3c287"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 9C 83 C5 7B 9D 8D 6D 85 87 54 24 00 9C 83 C5 26 9D 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_e3ffbbcc {
    meta:
        author = "Elastic Security"
        id = "e3ffbbcc-7751-4d96-abec-22dd9618cab1"
        fingerprint = "d5d5117a31da1a0ac3ef4043092eed47e2844938da9d03e2b68a66658e300175"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "28b7ddf2548411910af033b41982cdc74efd8a6ef059a54fda1b6cbd59faa8f6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF 10 52 FB FF D0 52 FB FF 00 52 FB FF D0 52 FB FF F0 51 FB }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_30f3b4d4 {
    meta:
        author = "Elastic Security"
        id = "30f3b4d4-e634-418e-a9d5-7f12ef22f9ac"
        fingerprint = "de1002eb8e9aae984ee5fe2a6c1f91845dab4861e09e01d644248cff8c590e5b"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "5b15d43d3535965ec9b84334cf9def0e8c3d064ffc022f6890320cd6045175bc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 70 9C 83 C5 17 9D 8D 6D E9 0F 10 74 24 60 8B F6 0F 10 6C }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ca75589c {
    meta:
        author = "Elastic Security"
        id = "ca75589c-6354-411b-b0a5-8400e657f956"
        fingerprint = "0bcaeae9ec0f5de241a05c77aadb5c3f2e39c84d03236971a0640ebae528a496"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0448c1b2c7c738404ba11ff4b38cdc8f865ccf1e202f6711345da53ce46e7e16"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6D E0 25 01 00 00 00 55 8B EC C9 87 D1 87 0C 24 87 D1 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_7909cdd2 {
    meta:
        author = "Elastic Security"
        id = "7909cdd2-8a49-4f51-ae16-1ffe321a29d4"
        fingerprint = "5c982596276c8587a88bd910bb2e75a7f72ea7a57c401ffa387aced33f9ac2b9"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0a4a5874f43adbe71da88dc0ef124f1bf2f4e70d0b1b5461b2788587445f79d9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { A5 07 00 EC C5 19 08 EC C5 19 08 18 06 00 00 18 06 00 00 06 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_2522d611 {
    meta:
        author = "Elastic Security"
        id = "2522d611-4ce3-4583-87d6-e5631b62d562"
        fingerprint = "985885a6b5f01e8816027f92148d2496a5535f3c15de151f05f69ec273291506"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0c2be53e298c285db8b028f563e97bf1cdced0c4564a34e740289b340db2aac1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 57 8B 7C 24 02 5F 87 44 24 00 50 8B 44 24 04 8D 40 42 87 44 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_56bd04d3 {
    meta:
        author = "Elastic Security"
        id = "56bd04d3-6b52-43f4-b170-637feb86397a"
        fingerprint = "25cd85e8e65362a993a314f2fc500266fce2f343d21a2e91b146dafbbe8186db"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0d2ce3891851808fb36779a348a83bf4aa9de1a2b2684fd0692434682afac5ec"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5C 87 5C 24 04 89 5C 24 04 8B 1C 24 8D 64 24 04 8B 00 8B F6 87 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_f412e4b4 {
    meta:
        author = "Elastic Security"
        id = "f412e4b4-adec-4011-b4b5-f5bb77b65d84"
        fingerprint = "deb9f80d032c4b3c591935c474523fd6912d7bd2c4f498ec772991504720e683"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "0e3a3f7973f747fcb23c72289116659c7f158c604d937d6ca7302fbab71851e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 C1 E2 05 8B C0 03 C2 9C 83 C5 0F 9D 8D 6D F1 05 0C 00 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_71f8e26c {
    meta:
        author = "Elastic Security"
        id = "71f8e26c-d0ff-49e8-9c20-8df9149e8843"
        fingerprint = "dbd1275bd01fb08342e60cb0c20adaf42971ed6ee0f679fedec9bc6967ecc015"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "13f873f83b84a0d38eb3437102f174f24a0ad3c5a53b83f0ee51c62c29fb1465"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 8D 64 24 04 1B 07 87 DA 8B 5D F4 52 87 DA 5B 83 C2 03 52 8B 54 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_1a562d3b {
    meta:
        author = "Elastic Security"
        id = "1a562d3b-bc59-4cb7-9ac1-7a4a79232869"
        fingerprint = "e052e99f15f5a0f704c04cae412cf4b1f01a8ee6e4ce880aedc79cf5aee9631a"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "15731db615b32c49c34f41fe84944eeaf2fc79dafaaa9ad6bf1b07d26482f055"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F0 87 1C 24 91 8D 64 24 FC 89 0C 24 8B C8 8B 04 24 87 D1 8D 64 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_410256ac {
    meta:
        author = "Elastic Security"
        id = "410256ac-fc7d-47f1-b7b8-82f1ee9f2bfb"
        fingerprint = "aa7f1d915e55c3ef178565ed12668ddd71bf3e982dba1f2436c98cceef2c376d"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "15f44e10ece90dec1a6104d5be1effefa17614d9f0cfb2784305dab85367b741"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 04 87 CA 8B 4D 0C 52 87 CA 59 03 D1 55 8B EC C9 6A 08 F7 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_93fa87f1 {
    meta:
        author = "Elastic Security"
        id = "93fa87f1-ec9d-4b3b-9c9a-a0b80963f41f"
        fingerprint = "3b53e54dfea89258a116dcdf4dde0b6ad583aff08d626c02a6f1bf0c76164ac7"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "165b4a28fd6335d4e4dfefb6c40f41f16d8c7d9ab0941ccd23e36cda931f715e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 87 44 24 04 89 44 24 04 8B 04 24 8D 64 24 04 8B 00 9C 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_8677dca3 {
    meta:
        author = "Elastic Security"
        id = "8677dca3-e36b-439f-bc55-76d951114020"
        fingerprint = "4d276b225f412b3879db19546c09d1dea2ee417c61ab6942c411bc392fee8e26"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "23813dc4aa56683e1426e5823adc3aab854469c9c0f3ec1a3fad40fa906929f2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F2 5E 83 C2 03 8B FF C1 E2 05 9C 83 C5 69 9D 8D 6D 97 03 C2 56 8B 74 }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_ebce4304 {
    meta:
        author = "Elastic Security"
        id = "ebce4304-0a06-454f-ad08-98b323e5b23a"
        fingerprint = "20f0346bf021e3d2a0e25bbb3ed5b9c0a45798d0d5b2516b679f7bf17d1b040d"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2e06caf864595f2df7f6936bb1ccaa1e0cae325aee8659ee283b2857e6ef1e5b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 8D 64 24 04 87 54 24 00 56 8B 74 24 04 5E 9D 9C 83 C5 1E 9D 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_073e6161 {
    meta:
        author = "Elastic Security"
        id = "073e6161-35a3-4e5e-a310-8cc50cb28edf"
        fingerprint = "12d04597fd60ed143a1b256889eefee1f5a8c77f4f300e72743e3cfa98ba8e99"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "2e06caf864595f2df7f6936bb1ccaa1e0cae325aee8659ee283b2857e6ef1e5b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F9 83 F8 1F 77 33 80 BC 35 B9 FF FF FF 63 76 29 8B 44 24 14 40 8D }
    condition:
        all of them
}

rule Linux_Trojan_Xorddos_bef22375 {
    meta:
        author = "Elastic Security"
        id = "bef22375-0a71-4f5b-bfd1-e2e718b5c36f"
        fingerprint = "0128e8725a0949dd23c23addc1158d28c334cfb040aad2b8f8d58f39720c41ef"
        creation_date = "2022-09-12"
        last_modified = "2022-10-18"
        threat_name = "Linux.Trojan.Xorddos"
        reference_sample = "f47baf48deb71910716beab9da1b1e24dc6de9575963e238735b6bcedfe73122"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C5 35 9D 8D 6D CB 8B 12 9C 83 C5 17 9D 8D 6D E9 6A 04 F7 14 24 FF }
    condition:
        all of them
}

rule onimiki {
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

rule IPStorm {
    meta:
        copyright = "Intezer Labs"
        author = "Intezer Labs"
        reference = "https://www.intezer.com"
    strings:
        $package1 = "storm/backshell"
        $package2 = "storm/filetransfer"
        $package3 = "storm/scan_tools"
        $package4 = "storm/malware-guard"
        $package5 = "storm/avbypass"
        $package6 = "storm/powershell"
        $lib2b = "libp2p/go-libp2p"
    condition:
        4 of ($package*) and $lib2b
}

rule MALWARE_Linux_HiddenWasp {
    meta:
        author = "ditekSHen"
        description = "HiddenWasp backdoor payload"
        clamav_sig1 = "MALWARE_Linux.Trojan.HiddenWasp-ELF"
        clamav_sig2 = "MALWARE_Linux.Trojan.HiddenWasp-Script"
    strings:
        $x1 = "I_AM_HIDDEN" fullword ascii
        $x2 = "HIDE_THIS_SHELL" fullword ascii
        $x3 = "NewUploadFile" ascii
        $x4 = "fake_processname" ascii
        $x5 = "swapPayload" ascii
        $x6 = /Trojan-(Platform|Machine|Hostname|OSersion)/ fullword ascii
        $s1 = "FileOpration::GetFileData" fullword ascii
        $s2 = "FileOpration::NewUploadFile" fullword ascii
        $s3 = "Connection::writeBlock" fullword ascii
        $s4 = /hiding_(hidefile|enable_logging|hideproc|makeroot)/ fullword ascii
        $s5 = "Reverse-Port" fullword ascii
        $s6 = "hidden_services" fullword ascii
        $s7 = "check_config" fullword ascii
        $s8 = "__data_start" fullword ascii
        $s9 = /patch_(suger_lib|ld|lib)/ fullword ascii
        $s10 = "hexdump -ve '1/1 \"%%.2X\"' %s | sed \"s/%s/%s/g\" | xxd -r -p > %s.tmp"
    condition:
        uint16(0) == 0x457f and (4 of ($x*) or all of ($s*) or (3 of ($x*) and 5 of ($s*)))
}

rule MALWARE_Linux_Kinsing {
    meta:
      author = "ditekSHen"
      description = "Kinsing RAT payload"
    strings:
      $s1 = "backconnect" ascii
      $s2 = "connectForSocks" ascii
      $s3 = "downloadAndExecute" ascii
      $s4 = "download_and_exec" ascii
      $s5 = "masscan" ascii
      $s6 = "UpdateCommand:" ascii
      $s7 = "exec_out" ascii
      $s8 = "doTask with type %s" ascii
   condition:
      uint16(0) == 0x457f and 6 of them
}

rule MALWARE_Linux_PLEAD {
    meta:
        author = "ditekSHen"
        description = "PLEAD Linux payload"
        clamav_sig = "MALWARE.Linux.Trojan.PLEAD"
    strings:
        $x1 = "CFileTransfer" ascii
        $x2 = "CFileManager" ascii
        $x3 = "CPortForward" ascii
        $x4 = "CPortForwardManager" ascii
        $x5 = "CRemoteShell" ascii
        $x6 = "CSockClient" ascii

        $s1 = "/proc/self/exe" fullword ascii
        $s2 = "/bin/sh" fullword ascii
        $s3 = "echo -e '" ascii
        $s4 = "%s    <DIR>    %s" ascii
        $s5 = "%s    %lld    %s" ascii
        $s6 = "Files: %d        Size: %lld" ascii
        $s7 = "Dirs: %d" ascii
        $s8 = "%s(%s)/" ascii
        $s9 = "%s %s %s %s" ascii
    condition:
    uint16(0) == 0x457f and (all of ($x*) or all of ($s*) or 12 of them)
}

rule MALWARE_Linux_UNK01 {
    meta:
        author = "ditekSHen"
        description = "Detects unknown/unidentified Linux malware"
    strings:
        $f1 = "%sresponse.php?status" ascii
        $f2 = "%supstream.php?mid=%s&os=%s" ascii fullword
        $f3 = "%supstream.php?tid=%" ascii
        $f4 = "%sindex.php?token=%.32s&flag=%d&name=%s" ascii fullword
        $f5 = "%sactive_off.php?id=%d&uniqu=%d" ascii fullword
        $s1 = "lock:%i usable num:%i n:%i" fullword ascii
        $s2 = "tid:%.*s tNumber:%i" fullword ascii
        $s3 = "init.php" fullword ascii
        $s4 = "mod_drone" fullword ascii
        $s5 = "new_mid" fullword ascii
        $s6 = "&exists[]=" fullword ascii
        $s7 = "&mod[]=" fullword ascii
        $s8 = "shutdown" fullword ascii
        $s9 = "&mac[]=%02X%02X%02X%02X%02X%02X" fullword ascii
    condition:
        uint16(0) == 0x457f and (3 of ($f*) or 6 of ($s*))
}

rule MALWARE_Linux_UNK02 {
    meta:
        author = "ditekSHen"
        description = "Detects unknown/unidentified Linux malware"
    strings:
        $rf1 = "[]A\\A]A^A_" ascii
        $rf2 = "[A\\A]A^A_]" ascii
        $f1 = "/bin/basH" ascii fullword
        $f2 = "/proc/seH" ascii fullword
        $f3 = "/dev/ptsH" ascii fullword
        $f4 = "pqrstuvwxyzabcde" ascii fullword
        $f5 = "libnss_%s.so.%d.%d" ascii fullword
    condition:
        uint16(0) == 0x457f and (all of ($f*) and #rf1 > 3 and #rf2 > 3)
}

rule MALWARE_Linux_HelloKitty {
    meta:
        author = "ditekSHen"
        description = "Detects Linux version of HelloKitty ransomware"
    strings:
        $s1 = "exec_pipe:%s" ascii
        $s2 = "Error InitAPI !!!" fullword ascii
        $s3 = "No Files Found !!!" fullword ascii
        $s4 = "Error open log File:%s" fullword ascii
        $s5 = "%ld - Files Found  " fullword ascii
        $s6 = "Total VM run on host:" fullword ascii
        $s7 = "error:%d open:%s" fullword ascii
        $s8 = "work.log" fullword ascii
        $s9 = "esxcli vm process kill" ascii
        $s10 = "readdir64" fullword ascii
        $s11 = "%s_%d.block" fullword ascii
        $s12 = "EVP_EncryptFinal_ex" fullword ascii
        $s13 = ".README_TO_RESTORE" fullword ascii
        $m1 = "COMPROMISED AND YOUR SENSITIVE PRIVATE INFORMATION WAS STOLEN" ascii nocase
        $m2 = "damage them without special software" ascii nocase
        $m3 = "leaking or being sold" ascii nocase
        $m4 = "Data will be Published and/or Sold" ascii nocase
    condition:
        uint16(0) == 0x457f and (6 of ($s*) or (2 of ($m*) and 2 of ($s*)) or 8 of them)
}

rule APT_MAL_LNX_Turla_Apr202004_1 { 
   meta:
      description = "Detects Turla Linux malware x64 x32"
      date = "2020-04-24"
      author = "Leonardo S.p.A."
      reference = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
      hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502" 
      hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc" 
      hash3 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash4 = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905" 
      hash5 = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08" 
      hash6 = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4" 
      hash7 = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8" 
      hash8 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash9 = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"
   strings: 
      $ = "/root/.hsperfdata" ascii fullword
      $ = "Desc| Filename | size |state|" ascii fullword
      $ = "VS filesystem: %s" ascii fullword
      $ = "File already exist on remote filesystem !" ascii fullword 
      $ = "/tmp/.sync.pid" ascii fullword
      $ = "rem_fd: ssl " ascii fullword
      $ = "TREX_PID=%u" ascii fullword
      $ = "/tmp/.xdfg" ascii fullword
      $ = "__we_are_happy__" ascii
      $ = "/root/.sess" ascii fullword
      /* $ = "ZYSZLRTS^Z@@NM@@G_Y_FE" ascii fullword */
   condition:
      uint16(0) == 0x457f and filesize < 5000KB and
      4 of them
}

rule APT_MAL_LNX_Turla_Apr202004_1_opcode { 
   meta:
      description = "Detects Turla Linux malware x64 x32"
      date = "2020-04-24"
      author = "Leonardo S.p.A."
      reference = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
      hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502" 
      hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc" 
      hash3 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash4 = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905" 
      hash5 = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08" 
      hash6 = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4" 
      hash7 = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8" 
      hash8 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" 
      hash9 = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"
   strings:
      $op0 = { 8D 41 05 32 06 48 FF C6 88 81 E0 80 69 00 } /* Xor string loop_p1 x32*/ 
      $op1 = { 48FFC14883F94975E9 } /*Xorstringloop_p2x32*/
      $op2 = { C7 05 9B 7D 29 00 1D 00 00 00 C7 05 2D 7B 29 00 65 74 68 30 C6 05 2A 7B 29 00 00 E8 }
      /* Load eth0 interface*/
      $op3 = { BF FF FF FF FF E8 96 9D 0A 00 90 90 90 90 90 90 90 90 90 90 89 F0}
      /* Opcode exceptions*/ 
      $op4 = { 88D380C305329AC1D60C08889A60A10F084283FA0876E9 }
      /* Xor string loop x64*/
      $op5 = { 8B 8D 50 DF FF FF B8 09 00 00 00 89 44 24 04 89 0C 24 E8 DD E5 02 00 } /* Kill call x32 */ 
      $op6 = { 8D 5A 05 32 9A 60 26 0C 08 88 9A 20 F4 0E 08 42 83 FA 48 76 EB } /* Decrypt init str */ 
      $op7 = { 8D 4A 05 32 8A 25 26 0C 08 88 8A 20 F4 0E 08 42 83 FA 08 76 EB} /* Decrypt init str */
   condition:
      uint16(0) == 0x457f and filesize < 5000KB and
      2 of them
}

rule derusbi_kernel {
    meta:
        description = "Derusbi Driver version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
    strings:
        $token1 = "$$$--Hello"     
        $token2 = "Wrod--$$$"   
        $cfg = "XXXXXXXXXXXXXXX"
        $class = ".?AVPCC_BASEMOD@@"
        $MZ = "MZ"
    condition:
        $MZ at 0 and $token1 and $token2 and $cfg and $class
}

rule derusbi_linux {
    meta:
        description = "Derusbi Server Linux version"
        date = "2015-12-09"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
    strings:
        $PS1 = "PS1=RK# \\u@\\h:\\w \\$"
        $cmd = "unset LS_OPTIONS;uname -a"
        $pname = "[diskio]"
        $rkfile = "/tmp/.secure"
        $ELF = "\x7fELF"
    condition:
        $ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}

rule SUSP_ELF_LNX_UPX_Compressed_File {
   meta:
      description = "Detects a suspicious ELF binary with UPX compression"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-12-12"
      score = 40
      hash1 = "038ff8b2fef16f8ee9d70e6c219c5f380afe1a21761791e8cbda21fa4d09fdb4"
      id = "078937de-59b3-538e-a5c3-57f4e6050212"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "$Id: UPX" fullword ascii
      $s3 = "$Info: This file is packed with the UPX executable packer" ascii

      $fp1 = "check your UCL installation !"
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      filesize > 30KB and 2 of ($s*)
      and not 1 of ($fp*)
}

rule Linux_Trojan_Winnti_61215d98 {
    meta:
        author = "Elastic Security"
        id = "61215d98-f52d-45d3-afa2-4bd25270aa99"
        fingerprint = "20ee92147edbf91447cca2ee0c47768a50ec9c7aa7d081698953d3bdc2a25320"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Winnti"
        reference_sample = "cc1455e3a479602581c1c7dc86a0e02605a3c14916b86817960397d5a2f41c31"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF FF C9 C3 55 48 89 E5 48 83 EC 30 89 F8 66 89 45 DC C7 45 FC FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_4c5a1865 {
    meta:
        author = "Elastic Security"
        id = "4c5a1865-ff41-445b-8616-c83b87498c2b"
        fingerprint = "685fe603e04ff123b3472293d3d83e2dc833effd1a7e6c616ff17ed61df0004c"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Winnti"
        reference = "0d963a713093fc8e5928141f5747640c9b43f3aadc8a5478c949f7ec364b28ad"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C1 E8 1F 84 C0 75 7B 85 D2 89 D5 7E 75 8B 47 0C 39 C6 7D 6E 44 8D }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_6f4ca425 {
    meta:
        author = "Elastic Security"
        id = "6f4ca425-5cd2-4c22-b017-b5fc02b3abc2"
        fingerprint = "dec25af33fc004de3a1f53e0c3006ff052f7c51c95f90be323b281590da7d924"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Winnti"
        reference = "161af780209aa24845863f7a8120aa982aa811f16ec04bcd797ed165955a09c1"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 E5 48 89 7D D8 48 8B 45 D8 0F B6 40 27 0F BE C0 89 45 F8 48 8B }
    condition:
        all of them
}

rule Linux_Trojan_Winnti_de4b0f6e {
    meta:
        author = "Elastic Security"
        id = "de4b0f6e-0183-4ea8-9c03-f716a25f1884"
        fingerprint = "c72eddc2d72ea979ad4f680d060aac129f1cd61dbdf3b0b5a74f5d35a9fe69d7"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Winnti"
        reference = "a6b9b3ea19eaddd4d90e58c372c10bbe37dbfced638d167182be2c940e615710"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 30 FF FF FF 02 00 48 8D 85 30 FF FF FF 48 8D 50 02 0F B7 85 28 FF }
    condition:
        all of them
}

rule rootkit_lin_winnti {
    meta:
        id = "c800038e-7f8a-4f24-bf0b-06aba6a828cb"
        version = "1.0"
        description = "Rootkit used by Winnti"
        author = "Sekoia.io"
        creation_date = "2024-05-22"
        classification = "TLP:CLEAR"
        reference = "https://x.com/naumovax/status/1792902386295394629"
        hash1 = "161344ae61278e09eacb1c76508cda45555eee109e6d6a031716a096ab5c84f3"
        hash2 = "bb56e088739b281c9f56b4fa3fa4d285e45b32c4f9f06b647d7e8cb916054e1a"
        hash3 = "777c1fda4008f122ff3aef9e80b5b5720c9f2dbc3d7e708277e2ccad1afd8cc5"
        hash4 = "9c770b12a2da76c41f921f49a22d7bc6b5a1166875b9dc732bc7c05b6ae39241"

    strings:
        $ = "[CDATA[%s]]></name><type>%o</type><perm>%o</perm><user>%s:%s</user><size>%llu</size><time>%s</time></LIST>"
        $ = "HideFile"
        $ = "DownThread"
        $ = "PortforwardThread"
        $ = "HidePidPort"
        $ = "DownFile"
        $ = "ReadReConnConf"
        $ = "DecRemotePort"
        $ = "DecRemoteIP"

    condition:
        uint32(0)==0x464c457f 
        and 6 of them
        and for any i in (0..elf.number_of_sections-1) : (
            hash.md5(elf.sections[i].offset, elf.sections[i].size) == "7dea362b3fac8e00956a4952a3d4f474"
        )
}

rule WEBSHELL_PHP_Generic
{
    meta:
        description = "php webshell having some kind of input and some kind of payload. restricted to small files or big ones including suspicious strings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 70
        date = "2021-01-14"
        modified = "2024-12-09"
        hash = "bee1b76b1455105d4bfe2f45191071cf05e83a309ae9defcf759248ca9bceddd"
        hash = "6bf351900a408120bee3fc6ea39905c6a35fe6efcf35d0a783ee92062e63a854"
        hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
        hash = "00813155bf7f5eb441e1619616a5f6b21ae31afc99caa000c4aafd54b46c3597"
        hash = "e31788042d9cdeffcb279533b5a7359b3beb1144f39bacdd3acdef6e9b4aff25"
        hash = "36b91575a08cf40d4782e5aebcec2894144f1e236a102edda2416bc75cbac8dd"
        hash = "a34154af7c0d7157285cfa498734cfb77662edadb1a10892eb7f7e2fb5e2486c"
        hash = "791a882af2cea0aa8b8379791b401bebc235296858266ddb7f881c8923b7ea61"
        hash = "9a8ab3c225076a26309230d7eac7681f85b271d2db22bf5a190adbf66faca2e6"
        hash = "0d3ee83adc9ebf8fb1a8c449eed5547ee5e67e9a416cce25592e80963198ae23"
        hash = "3d8708609562a27634df5094713154d8ca784dbe89738e63951e12184ff07ad6"
        hash = "70d64d987f0d9ab46514abcc868505d95dbf458387f858b0d7580e4ee8573786"
        hash = "259b3828694b4d256764d7d01b0f0f36ca0526d5ee75e134c6a754d2ab0d1caa"
        hash = "04d139b48d59fa2ef24fb9347b74fa317cb05bd8b7389aeb0a4d458c49ea7540"
        hash = "58d0e2ff61301fe0c176b51430850239d3278c7caf56310d202e0cdbdde9ac3f"
        hash = "731f36a08b0e63c63b3a2a457667dfc34aa7ff3a2aee24e60a8d16b83ad44ce2"
        hash = "e4ffd4ec67762fe00bb8bd9fbff78cffefdb96c16fe7551b5505d319a90fa18f"
        hash = "fa00ee25bfb3908808a7c6e8b2423c681d7c52de2deb30cbaea2ee09a635b7d4"
        hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
        hash = "e9423ad8e51895db0e8422750c61ef4897b3be4292b36dba67d42de99e714bff"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
        hash = "3de8c04bfdb24185a07f198464fcdd56bb643e1d08199a26acee51435ff0a99f"
        hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
        hash = "a09dcf52da767815f29f66cb7b03f3d8c102da5cf7b69567928961c389eac11f"
        hash = "d9ae762b011216e520ebe4b7abcac615c61318a8195601526cfa11bbc719a8f1"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"

        id = "294ce5d5-55b2-5c79-b0f8-b66f949efbb2"
    strings:
        $wfp_tiny1 = "escapeshellarg" fullword
        $wfp_tiny2 = "addslashes" fullword

        //strings from private rule php_false_positive_tiny
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        //$gfp_tiny1 = "addslashes" fullword
        //$gfp_tiny2 = "escapeshellarg" fullword
        $gfp_tiny3 = "include \"./common.php\";" // xcache
        $gfp_tiny4 = "assert('FALSE');"
        $gfp_tiny5 = "assert(false);"
        $gfp_tiny6 = "assert(FALSE);"
        $gfp_tiny7 = "assert('array_key_exists("
        $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
        $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
        $gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"
        $gfp_tiny11= "; This is the recommended, PHP 4-style version of the php.ini-dist file"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        $inp8 = /\(\s?\$_HEADERS\s?[\)\[]/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii
        $inp20 = "TSOP_" wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.{0,500}|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
        $gen_bit_sus75 = "uploaded" fullword wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "str_rot13" fullword wide ascii

        $gif = { 47 49 46 38 }


        //strings from private rule capa_php_payload_multiple
        // \([^)] to avoid matching on e.g. eval() in comments
        $cmpayload1 = /\beval[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload2 = /\bexec[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload3 = /\bshell_exec[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload4 = /\bpassthru[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload5 = /\bsystem[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload6 = /\bpopen[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload7 = /\bproc_open[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload8 = /\bpcntl_exec[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload9 = /\bassert[\t ]{0,500}\([^)0]/ nocase wide ascii
        $cmpayload10 = /\bpreg_replace[\t ]{0,500}\([^\)]{1,100}\/e/ nocase wide ascii
        $cmpayload11 = /\bpreg_filter[\t ]{0,500}\([^\)]{1,100}\/e/ nocase wide ascii
        $cmpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cmpayload20 = /\bcreate_function[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload21 = /\bReflectionFunction[\t ]{0,500}\([^)]/ nocase wide ascii

        $fp1 = "# Some examples from obfuscated malware:" ascii
        $fp2 = "{@see TFileUpload} for further details." ascii
    condition:
        //any of them or
        not (
            any of ( $gfp_tiny* )
            or 1 of ($fp*)
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and
        ( ( filesize < 1000 and not any of ( $wfp_tiny* ) ) or
        ( (
        $gif at 0 or
        (
            filesize < 4KB and
            (
                1 of ( $gen_much_sus* ) or
                2 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 20KB and
            (
                2 of ( $gen_much_sus* ) or
                3 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 50KB and
            (
                2 of ( $gen_much_sus* ) or
                4 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 100KB and
            (
                2 of ( $gen_much_sus* ) or
                6 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 150KB and
            (
                3 of ( $gen_much_sus* ) or
                7 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 500KB and
            (
                4 of ( $gen_much_sus* ) or
                8 of ( $gen_bit_sus* )
            )
        )
        )
        and
        ( filesize > 5KB or not any of ( $wfp_tiny* ) ) ) or
        ( filesize < 500KB and (
            4 of ( $cmpayload* )
        )
        ) )
}

rule WEBSHELL_PHP_Generic_Callback
{
    meta:
        description = "php webshell having some kind of input and using a callback to execute the payload. restricted to small files or would give lots of false positives"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/14"
        modified = "2023-09-18"
        score = 60
        hash = "e98889690101b59260e871c49263314526f2093f"
        hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
        hash = "81388c8cc99353cdb42572bb88df7d3bd70eefc748c2fa4224b6074aa8d7e6a2"
        hash = "27d3bfabc283d851b0785199da8b1b0384afcb996fa9217687274dd56a7b5f49"
        hash = "ee256d7cc3ceb2bf3a1934d553cdd36e3fbde62a02b20a1b748a74e85d4dbd33"
        hash = "4adc6c5373c4db7b8ed1e7e6df10a3b2ce5e128818bb4162d502056677c6f54a"
        hash = "1fe4c60ea3f32819a98b1725581ac912d0f90d497e63ad81ccf258aeec59fee3"
        hash = "2967f38c26b131f00276bcc21227e54ee6a71881da1d27ec5157d83c4c9d4f51"
        hash = "1ba02fb573a06d5274e30b2b05573305294497769414e964a097acb5c352fb92"
        hash = "f4fe8e3b2c39090ca971a8e61194fdb83d76fadbbace4c5eb15e333df61ce2a4"
        hash = "badda1053e169fea055f5edceae962e500842ad15a5d31968a0a89cf28d89e91"
        hash = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "de1ef827bcd3100a259f29730cb06f7878220a7c02cee0ebfc9090753d2237a8"
        hash = "487e8c08e85774dfd1f5e744050c08eb7d01c6877f7d03d7963187748339e8c4"

        id = "e33dba84-bbeb-5955-a81b-2d2c8637fb48"
    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule php_false_positive_tiny
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        //$gfp_tiny1 = "addslashes" fullword
        //$gfp_tiny2 = "escapeshellarg" fullword
        $gfp_tiny3 = "include \"./common.php\";" // xcache
        $gfp_tiny4 = "assert('FALSE');"
        $gfp_tiny5 = "assert(false);"
        $gfp_tiny6 = "assert(FALSE);"
        $gfp_tiny7 = "assert('array_key_exists("
        $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
        $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
        $gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

        // TODO: arraywalk \n /*
        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback3 = /\barray_diff_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback4 = /\barray_filter[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback7 = /\barray_map[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback8 = /\barray_reduce[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback11 = /\barray_udiff[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback14 = /\barray_uintersect[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback15 = /\barray_walk_recursive[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback16 = /\barray_walk[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback17 = /\bassert_options[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback18 = /\buasort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback19 = /\buksort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback20 = /\busort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback22 = /\bspl_autoload_register[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback23 = /\biterator_apply[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback24 = /\bcall_user_func[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback25 = /\bcall_user_func_array[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback27 = /\bregister_tick_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback28 = /\bset_error_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback29 = /\bset_exception_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback32 = /\bsqlite_create_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii

        $m_callback1 = /\bfilter_var[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $m_callback2 = "FILTER_CALLBACK" fullword wide ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii wide
        $cfp3 = "<?phpclass WPML" ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
        $gen_much_sus93 = "eval(\"/*" wide ascii
        $gen_much_sus94 = "http_response_code(404)" wide ascii

        $gif = { 47 49 46 38 }


    condition:
        //any of them or
        not (
            any of ( $gfp* )
        )
        and not (
            any of ( $gfp_tiny* )
        )
        and (
            any of ( $inp* )
        )
        and (
            not any of ( $cfp* ) and
                (
                    any of ( $callback* )  or
                    all of ( $m_callback* )
                )
            )
            and
            ( filesize < 1000 or (
                $gif at 0 or
                (
                    filesize < 4KB and
                    (
                        1 of ( $gen_much_sus* ) or
                        2 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 20KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        3 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 50KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        4 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 100KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        6 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 150KB and
                    (
                        3 of ( $gen_much_sus* ) or
                        7 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 500KB and
                    (
                        4 of ( $gen_much_sus* ) or
                        8 of ( $gen_bit_sus* )
                    )
                )
            )
        )
}

rule WEBSHELL_PHP_Base64_Encoded_Payloads : FILE {
    meta:
        description = "php webshell containing base64 encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "88d0d4696c9cb2d37d16e330e236cb37cfaec4cd"
        hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
        hash = "e726cd071915534761822805724c6c6bfe0fcac604a86f09437f03f301512dc5"
        hash = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
        hash = "8cc9802769ede56f1139abeaa0735526f781dff3b6c6334795d1d0f19161d076"
        hash = "4cda0c798908b61ae7f4146c6218d7b7de14cbcd7c839edbdeb547b5ae404cd4"
        hash = "afd9c9b0df0b2ca119914ea0008fad94de3bd93c6919f226b793464d4441bdf4"
        hash = "b2048dc30fc7681094a0306a81f4a4cc34f0b35ccce1258c20f4940300397819"
        hash = "da6af9a4a60e3a484764010fbf1a547c2c0a2791e03fc11618b8fc2605dceb04"
        hash = "222cd9b208bd24955bcf4f9976f9c14c1d25e29d361d9dcd603d57f1ea2b0aee"
        hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
        hash = "6b6cd1ef7e78e37cbcca94bfb5f49f763ba2f63ed8b33bc4d7f9e5314c87f646"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "e2b1dfcfaa61e92526a3a444be6c65330a8db4e692543a421e19711760f6ffe2"

        id = "4e42b47d-725b-5e1f-9408-6c6329f60506"
    strings:
        $decode1 = "base64_decode" fullword nocase wide ascii
        $decode2 = "openssl_decrypt" fullword nocase wide ascii
        // exec
        $one1 = "leGVj"
        $one2 = "V4ZW"
        $one3 = "ZXhlY"
        $one4 = "UAeABlAGMA"
        $one5 = "lAHgAZQBjA"
        $one6 = "ZQB4AGUAYw"
        // shell_exec
        $two1 = "zaGVsbF9leGVj"
        $two2 = "NoZWxsX2V4ZW"
        $two3 = "c2hlbGxfZXhlY"
        $two4 = "MAaABlAGwAbABfAGUAeABlAGMA"
        $two5 = "zAGgAZQBsAGwAXwBlAHgAZQBjA"
        $two6 = "cwBoAGUAbABsAF8AZQB4AGUAYw"
        // passthru
        $three1 = "wYXNzdGhyd"
        $three2 = "Bhc3N0aHJ1"
        $three3 = "cGFzc3Rocn"
        $three4 = "AAYQBzAHMAdABoAHIAdQ"
        $three5 = "wAGEAcwBzAHQAaAByAHUA"
        $three6 = "cABhAHMAcwB0AGgAcgB1A"
        // system
        $four1 = "zeXN0ZW"
        $four2 = "N5c3Rlb"
        $four3 = "c3lzdGVt"
        $four4 = "MAeQBzAHQAZQBtA"
        $four5 = "zAHkAcwB0AGUAbQ"
        $four6 = "cwB5AHMAdABlAG0A"
        // popen
        $five1 = "wb3Blb"
        $five2 = "BvcGVu"
        $five3 = "cG9wZW"
        $five4 = "AAbwBwAGUAbg"
        $five5 = "wAG8AcABlAG4A"
        $five6 = "cABvAHAAZQBuA"
        // proc_open
        $six1 = "wcm9jX29wZW"
        $six2 = "Byb2Nfb3Blb"
        $six3 = "cHJvY19vcGVu"
        $six4 = "AAcgBvAGMAXwBvAHAAZQBuA"
        $six5 = "wAHIAbwBjAF8AbwBwAGUAbg"
        $six6 = "cAByAG8AYwBfAG8AcABlAG4A"
        // pcntl_exec
        $seven1 = "wY250bF9leGVj"
        $seven2 = "BjbnRsX2V4ZW"
        $seven3 = "cGNudGxfZXhlY"
        $seven4 = "AAYwBuAHQAbABfAGUAeABlAGMA"
        $seven5 = "wAGMAbgB0AGwAXwBlAHgAZQBjA"
        $seven6 = "cABjAG4AdABsAF8AZQB4AGUAYw"
        // eval
        $eight1 = "ldmFs"
        $eight2 = "V2YW"
        $eight3 = "ZXZhb"
        $eight4 = "UAdgBhAGwA"
        $eight5 = "lAHYAYQBsA"
        $eight6 = "ZQB2AGEAbA"
        // assert
        $nine1 = "hc3Nlcn"
        $nine2 = "Fzc2Vyd"
        $nine3 = "YXNzZXJ0"
        $nine4 = "EAcwBzAGUAcgB0A"
        $nine5 = "hAHMAcwBlAHIAdA"
        $nine6 = "YQBzAHMAZQByAHQA"

        // false positives

        // execu
        $execu1 = "leGVjd"
        $execu2 = "V4ZWN1"
        $execu3 = "ZXhlY3"

        // esystem like e.g. filesystem
        $esystem1 = "lc3lzdGVt"
        $esystem2 = "VzeXN0ZW"
        $esystem3 = "ZXN5c3Rlb"

        // opening
        $opening1 = "vcGVuaW5n"
        $opening2 = "9wZW5pbm"
        $opening3 = "b3BlbmluZ"

        // false positives
        $fp1 = { D0 CF 11 E0 A1 B1 1A E1 }
        // api.telegram
        $fp2 = "YXBpLnRlbGVncmFtLm9"
        // Log files
        $fp3 = " GET /"
        $fp4 = " POST /"

    $fpa1 = "/cn=Recipients"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 300KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not any of ( $fp* ) and any of ( $decode* ) and
        ( ( any of ( $one* ) and not any of ( $execu* ) ) or any of ( $two* ) or any of ( $three* ) or
        ( any of ( $four* ) and not any of ( $esystem* ) ) or
        ( any of ( $five* ) and not any of ( $opening* ) ) or any of ( $six* ) or any of ( $seven* ) or any of ( $eight* ) or any of ( $nine* ) )
}

rule WEBSHELL_PHP_Unknown_1
{
    meta:
        description = "obfuscated php webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "12ce6c7167b33cc4e8bdec29fb1cfc44ac9487d1"
        hash = "cf4abbd568ce0c0dfce1f2e4af669ad2"
        date = "2021/01/07"
        modified = "2023-04-05"

        id = "93d01a4c-4c18-55d2-b682-68a1f6460889"
    strings:
        $sp0 = /^<\?php \$[a-z]{3,30} = '/ wide ascii
        $sp1 = "=explode(chr(" wide ascii
        $sp2 = "; if (!function_exists('" wide ascii
        $sp3 = " = NULL; for(" wide ascii

    condition:
        filesize <300KB and all of ($sp*)
}

rule WEBSHELL_PHP_Generic_Eval
{
    meta:
        description = "Generic PHP webshell which uses any eval/exec function in the same line with user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "a61437a427062756e2221bfb6d58cd62439d09d9"
        hash = "90c5cc724ec9cf838e4229e5e08955eec4d7bf95"
        hash = "2b41abc43c5b6c791d4031005bf7c5104a98e98a00ee24620ce3e8e09a78e78f"
        hash = "5c68a0fa132216213b66a114375b07b08dc0cb729ddcf0a29bff9ca7a22eaaf4"
        hash = "de3c01f55d5346577922bbf449faaaaa1c8d1aaa64c01e8a1ee8c9d99a41a1be"
        hash = "124065176d262bde397b1911648cea16a8ff6a4c8ab072168d12bf0662590543"
        hash = "cd7450f3e5103e68741fd086df221982454fbcb067e93b9cbd8572aead8f319b"
        hash = "ab835ce740890473adf5cc804055973b926633e39c59c2bd98da526b63e9c521"
        hash = "31ff9920d401d4fbd5656a4f06c52f1f54258bc42332fc9456265dca7bb4c1ea"
        hash = "64e6c08aa0b542481b86a91cdf1f50c9e88104a8a4572a8c6bd312a9daeba60e"
        hash = "80e98e8a3461d7ba15d869b0641cdd21dd5b957a2006c3caeaf6f70a749ca4bb"
        hash = "93982b8df76080e7ba4520ae4b4db7f3c867f005b3c2f84cb9dff0386e361c35"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
        hash = "fd5f0f81204ca6ca6e93343500400d5853012e88254874fc9f62efe0fde7ab3c"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "6d042b6393669bb4d98213091cabe554ab192a6c916e86c04d06cc2a4ca92c00"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"


        id = "79cfbd88-f6f7-5cba-a325-0a99962139ca"
    strings:
        // new: eval($GLOBALS['_POST'
        $geval = /\b(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]{0,300}(\(base64_decode)?(\(stripslashes)?[\t ]{0,300}(\(trim)?[\t ]{0,300}\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/ wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
        // Log files
        $gfp_3 = " GET /"
        $gfp_4 = " POST /"
    condition:
        filesize < 300KB and not (
            any of ( $gfp* )
        )
        and $geval
}

rule WEBSHELL_PHP_Double_Eval_Tiny
{
    meta:
        description = "PHP webshell which probably hides the input inside an eval()ed obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021-01-11"
        modified = "2023-07-05"
        hash = "f66fb918751acc7b88a17272a044b5242797976c73a6e54ac6b04b02f61e9761"
        hash = "6b2f0a3bd80019dea536ddbf92df36ab897dd295840cb15bb7b159d0ee2106ff"
        hash = "aabfd179aaf716929c8b820eefa3c1f613f8dcac"
        hash = "9780c70bd1c76425d4313ca7a9b89dda77d2c664"
        hash = "006620d2a701de73d995fc950691665c0692af11"


        id = "868db363-83d3-57e2-ac8d-c6125e9bdd64"
    strings:
        $payload = /(\beval[\t ]{0,500}\([^)]|\bassert[\t ]{0,500}\([^)])/ nocase wide ascii
        $fp1 = "clone" fullword wide ascii
        $fp2 = "* @assert" ascii
        $fp3 = "*@assert" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize > 70 and filesize < 300 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and #payload >= 2 and not any of ( $fp* )
}

rule WEBSHELL_PHP_OBFUSC
{
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2024-03-11"
        hash = "eec9ac58a1e763f5ea0f7fa249f1fe752047fa60"
        hash = "181a71c99a4ae13ebd5c94bfc41f9ec534acf61cd33ef5bce5fb2a6f48b65bf4"
        hash = "76d4e67e13c21662c4b30aab701ce9cdecc8698696979e504c288f20de92aee7"
        hash = "1d0643927f04cb1133f00aa6c5fa84aaf88e5cf14d7df8291615b402e8ab6dc2"
        id = "f66e337b-8478-5cd3-b01a-81133edaa8e5"
    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_obfuscation_multi
        $o1 = "chr(" nocase wide ascii
        $o2 = "chr (" nocase wide ascii
        // not excactly a string function but also often used in obfuscation
        $o3 = "goto" fullword nocase wide ascii
        $o4 = "\\x9" wide ascii
        $o5 = "\\x3" wide ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" wide ascii
        $o7 = "\\44" wide ascii
        $o8 = "\\112" wide ascii
        $o9 = "\\120" wide ascii
        $fp1 = "$goto" wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            // allow different amounts of potential obfuscation functions depending on filesize
            not $fp1 and (
                (
                        filesize < 20KB and
                        (
                            ( #o1+#o2 ) > 50 or
                            #o3 > 10 or
                            ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20
                        )
                ) or (
                        filesize < 200KB and
                        (
                            ( #o1+#o2 ) > 200 or
                            #o3 > 30 or
                            ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 30
                        )

                )
            )


        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )

}

rule WEBSHELL_PHP_OBFUSC_Encoded
{
    meta:
        description = "PHP webshell obfuscated by encoding"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/04/18"
        modified = "2023-04-05"
        score = 70
        hash = "119fc058c9c5285498a47aa271ac9a27f6ada1bf4d854ccd4b01db993d61fc52"
        hash = "d5ca3e4505ea122019ea263d6433221030b3f64460d3ce2c7d0d63ed91162175"
        hash = "8a1e2d72c82f6a846ec066d249bfa0aaf392c65149d39b7b15ba19f9adc3b339"


        id = "134c1189-1b41-58d5-af66-beaa4795a704"
    strings:
        // one without plain e, one without plain v, to avoid hitting on plain "eval("
        $enc_eval1 = /(e|\\x65|\\101)(\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
        $enc_eval2 = /(\\x65|\\101)(v|\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
        // one without plain a, one without plain s, to avoid hitting on plain "assert("
        $enc_assert1 = /(a|\\97|\\x61)(\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
        $enc_assert2 = /(\\97|\\x61)(s|\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $enc* )
}

rule WEBSHELL_PHP_OBFUSC_Encoded_Mixed_Dec_And_Hex
{
    meta:
        description = "PHP webshell obfuscated by encoding of mixed hex and dec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/18"
        modified = "2023-04-05"
        hash = "0e21931b16f30b1db90a27eafabccc91abd757fa63594ba8a6ad3f477de1ab1c"
        hash = "929975272f0f42bf76469ed89ebf37efcbd91c6f8dac1129c7ab061e2564dd06"
        hash = "88fce6c1b589d600b4295528d3fcac161b581f739095b99cd6c768b7e16e89ff"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "50389c3b95a9de00220fc554258fda1fef01c62dad849e66c8a92fc749523457"
        hash = "c4ab4319a77b751a45391aa01cde2d765b095b0e3f6a92b0b8626d5c7e3ad603"
        hash = "df381f04fca2522e2ecba0f5de3f73a655d1540e1cf865970f5fa3bf52d2b297"
        hash = "401388d8b97649672d101bf55694dd175375214386253d0b4b8d8d801a89549c"
        hash = "99fc39a12856cc1a42bb7f90ffc9fe0a5339838b54a63e8f00aa98961c900618"
        hash = "fb031af7aa459ee88a9ca44013a76f6278ad5846aa20e5add4aeb5fab058d0ee"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
        hash = "0ff05e6695074f98b0dee6200697a997c509a652f746d2c1c92c0b0a0552ca47"

        id = "9ae920e2-17c8-58fd-8566-90d461a54943"
    strings:
        // "e\x4a\x48\x5a\x70\x63\62\154\x30\131\171\101\x39\111\x43\x52\x66\x51\
        //$mix = /['"]\\x?[0-9a-f]{2,3}[\\\w]{2,20}\\\d{1,3}[\\\w]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase
        $mix = /['"](\w|\\x?[0-9a-f]{2,3})[\\x0-9a-f]{2,20}\\\d{1,3}[\\x0-9a-f]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $mix* )
}

rule WEBSHELL_PHP_OBFUSC_Tiny
{
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2024-03-11"
        hash = "b7b7aabd518a2f8578d4b1bc9a3af60d155972f1"
        hash = "694ec6e1c4f34632a9bd7065f73be473"
        hash = "5c871183444dbb5c8766df6b126bd80c624a63a16cc39e20a0f7b002216b2ba5"

        id = "d78e495f-54d2-5f5f-920f-fb6612afbca3"
    strings:
        // 'ev'.'al'
        $obf1 = /\w'\.'\w/ wide ascii
        $obf2 = /\w\"\.\"\w/ wide ascii
        $obf3 = "].$" wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        //any of them or
        filesize < 500 and not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and
        ( ( #obf1 + #obf2 ) > 2 or #obf3 > 10 )
}

rule WEBSHELL_PHP_OBFUSC_Str_Replace
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "691305753e26884d0f930cda0fe5231c6437de94"
        hash = "7efd463aeb5bf0120dc5f963b62463211bd9e678"
        hash = "fb655ddb90892e522ae1aaaf6cd8bde27a7f49ef"
        hash = "d1863aeca1a479462648d975773f795bb33a7af2"
        hash = "4d31d94b88e2bbd255cf501e178944425d40ee97"
        hash = "e1a2af3477d62a58f9e6431f5a4a123fb897ea80"

        id = "1f5b93c9-bdeb-52c7-a99a-69869634a574"
    strings:
        $payload1 = "str_replace" fullword wide ascii
        $payload2 = "function" fullword wide ascii
        $goto = "goto" fullword wide ascii
        //$hex  = "\\x"
        $chr1  = "\\61" wide ascii
        $chr2  = "\\112" wide ascii
        $chr3  = "\\120" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 300KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $payload* ) and #goto > 1 and
        ( #chr1 > 10 or #chr2 > 10 or #chr3 > 10 )
}

rule WEBSHELL_PHP_OBFUSC_Fopo
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "fbcff8ea5ce04fc91c05384e847f2c316e013207"
        hash = "6da57ad8be1c587bb5cc8a1413f07d10fb314b72"
        hash = "a698441f817a9a72908a0d93a34133469f33a7b34972af3e351bdccae0737d99"
        date = "2021/01/12"
        modified = "2023-04-05"

        id = "a298e99d-1ba8-58c8-afb9-fc988ea91e9a"
    strings:
        $payload = /(\beval[\t ]{0,500}\([^)]|\bassert[\t ]{0,500}\([^)])/ nocase wide ascii
        // ;@eval(
        $one1 = "7QGV2YWwo" wide ascii
        $one2 = "tAZXZhbC" wide ascii
        $one3 = "O0BldmFsK" wide ascii
        $one4 = "sAQABlAHYAYQBsACgA" wide ascii
        $one5 = "7AEAAZQB2AGEAbAAoA" wide ascii
        $one6 = "OwBAAGUAdgBhAGwAKA" wide ascii
        // ;@assert(
        $two1 = "7QGFzc2VydC" wide ascii
        $two2 = "tAYXNzZXJ0K" wide ascii
        $two3 = "O0Bhc3NlcnQo" wide ascii
        $two4 = "sAQABhAHMAcwBlAHIAdAAoA" wide ascii
        $two5 = "7AEAAYQBzAHMAZQByAHQAKA" wide ascii
        $two6 = "OwBAAGEAcwBzAGUAcgB0ACgA" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 3000KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $payload and
        ( any of ( $one* ) or any of ( $two* ) )
}

rule WEBSHELL_PHP_Gzinflated
{
    meta:
        description = "PHP webshell which directly eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "49e5bc75a1ec36beeff4fbaeb16b322b08cf192d"
        hash = "6f36d201cd32296bad9d5864c7357e8634f365cc"
        hash = "ab10a1e69f3dfe7c2ad12b2e6c0e66db819c2301"
        hash = "a6cf337fe11fe646d7eee3d3f09c7cb9643d921d"
        hash = "07eb6634f28549ebf26583e8b154c6a579b8a733"

        id = "9cf99ae4-9f7c-502f-9294-b531002953d6"
    strings:
        $payload2 = /eval\s?\(\s?("\?>".)?gzinflate\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload4 = /eval\s?\(\s?("\?>".)?gzuncompress\s?\(\s?(base64_decode|gzuncompress)/ wide ascii nocase
        $payload6 = /eval\s?\(\s?("\?>".)?gzdecode\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload7 = /eval\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload8 = /eval\s?\(\s?pack\s?\(/ wide ascii nocase

        // api.telegram
        $fp1 = "YXBpLnRlbGVncmFtLm9"

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and 1 of ( $payload* ) and not any of ( $fp* )
}

rule WEBSHELL_PHP_OBFUSC_3
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 70
        date = "2021/04/17"
        modified = "2024-12-09"
        hash = "11bb1fa3478ec16c00da2a1531906c05e9c982ea"
        hash = "d6b851cae249ea6744078393f622ace15f9880bc"
        hash = "14e02b61905cf373ba9234a13958310652a91ece"
        hash = "6f97f607a3db798128288e32de851c6f56e91c1d"

        id = "f2017e6f-0623-53ff-aa26-a479f3a02024"
    strings:
        $obf1 = "chr(" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback3 = /\barray_diff_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback4 = /\barray_filter[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback7 = /\barray_map[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback8 = /\barray_reduce[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback11 = /\barray_udiff[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback14 = /\barray_uintersect[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback15 = /\barray_walk_recursive[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback16 = /\barray_walk[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback17 = /\bassert_options[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback18 = /\buasort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback19 = /\buksort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback20 = /\busort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback22 = /\bspl_autoload_register[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback23 = /\biterator_apply[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback24 = /\bcall_user_func[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback25 = /\bcall_user_func_array[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback27 = /\bregister_tick_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback28 = /\bset_error_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback29 = /\bset_exception_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback32 = /\bsqlite_create_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii

        $m_callback1 = /\bfilter_var[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $m_callback2 = "FILTER_CALLBACK" fullword wide ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii wide
        $cfp3 = "<?phpclass WPML" ascii
        $cfp4 = "      return implode('', "

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_php_obfuscation_single
        $cobfs1 = "gzinflate" fullword nocase wide ascii
        $cobfs2 = "gzuncompress" fullword nocase wide ascii
        $cobfs3 = "gzdecode" fullword nocase wide ascii
        $cobfs4 = "base64_decode" fullword nocase wide ascii
        $cobfs5 = "pack" fullword nocase wide ascii
        $cobfs6 = "undecode" fullword nocase wide ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
        $gen_much_sus93 = "eval(\"/*" wide ascii
        $gen_much_sus94 = "=$_COOKIE;" wide ascii

        $gif = { 47 49 46 38 }


    condition:
        //any of them or
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and
        ( (
            not any of ( $cfp* ) and
        (
            any of ( $callback* )  or
            all of ( $m_callback* )
        )
        )
        or (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        ) and (
            any of ( $cobfs* )
        )
        and
        ( filesize < 1KB or
        ( filesize < 3KB and
        ( (
        $gif at 0 or
        (
            filesize < 4KB and
            (
                1 of ( $gen_much_sus* ) or
                2 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 20KB and
            (
                2 of ( $gen_much_sus* ) or
                3 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 50KB and
            (
                2 of ( $gen_much_sus* ) or
                4 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 100KB and
            (
                2 of ( $gen_much_sus* ) or
                6 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 150KB and
            (
                3 of ( $gen_much_sus* ) or
                7 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 500KB and
            (
                4 of ( $gen_much_sus* ) or
                8 of ( $gen_bit_sus* )
            )
        )
        )
        or #obf1 > 10 ) ) )
}

rule WEBSHELL_PHP_Includer_Eval
{
    meta:
        description = "PHP webshell which eval()s another included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/13"
        modified = "2023-04-05"
        hash = "3a07e9188028efa32872ba5b6e5363920a6b2489"
        hash = "ab771bb715710892b9513b1d075b4e2c0931afb6"
        hash = "202dbcdc2896873631e1a0448098c820c82bcc8385a9f7579a0dc9702d76f580"
        hash = "b51a6d208ec3a44a67cce16dcc1e93cdb06fe150acf16222815333ddf52d4db8"

        id = "995fcc34-f91e-5c9c-97b1-84eed1714d40"
    strings:
        $payload1 = "eval" fullword wide ascii
        $payload2 = "assert" fullword wide ascii
        $include1 = "$_FILE" wide ascii
        $include2 = "include" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 200 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and 1 of ( $payload* ) and 1 of ( $include* )
}

rule WEBSHELL_PHP_Includer_Tiny
{
    meta:
        description = "Suspicious: Might be PHP webshell includer, check the included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/17"
        modified = "2023-07-05"
        hash = "0687585025f99596508783b891e26d6989eec2ba"
        hash = "9e856f5cb7cb901b5003e57c528a6298341d04dc"
        hash = "b3b0274cda28292813096a5a7a3f5f77378b8905205bda7bb7e1a679a7845004"

        id = "9bf96ddc-d984-57eb-9803-0b01890711b5"
    strings:
        $php_include1 = /include\(\$_(GET|POST|REQUEST)\[/ nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 100 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $php_include* )
}

rule WEBSHELL_PHP_Dynamic
{
    meta:
        description = "PHP webshell using function name from variable, e.g. $a='ev'.'al'; $a($code)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/13"
        modified = "2024-12-09"
        score = 60
        hash = "65dca1e652d09514e9c9b2e0004629d03ab3c3ef"
        hash = "b8ab38dc75cec26ce3d3a91cb2951d7cdd004838"
        hash = "c4765e81550b476976604d01c20e3dbd415366df"
        hash = "2e11ba2d06ebe0aa818e38e24a8a83eebbaae8877c10b704af01bf2977701e73"

        id = "58ad94bc-93c8-509c-9d3a-c9a26538d60c"
    strings:
        $pd_fp1 = "whoops_add_stack_frame" wide ascii
        $pd_fp2 = "new $ec($code, $mode, $options, $userinfo);" wide ascii
        $pd_fp3 = "($i)] = 600;" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
        // ${'_'.$_}["_"](${'_'.$_}["__"]
        $dynamic8 = /\$\{[^}]{1,20}}(\[[^\]]{1,20}\])?\(\$\{/ wide ascii

        $fp1 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 24 63 29 3B } /* <?php\x0a\x0a$a($b = 3, $c); */
        $fp2 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 2E 2E 2E 20 24 63 29 3B } /* <?php\x0a\x0a$a($b = 3, ... $c); */
        $fp3 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 74 61 74 69 63 3A 3A 24 62 28 29 3B} /* <?php\x0a\x0a$a = new static::$b(); */
        $fp4 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 65 6C 66 3A 3A 24 62 28 29 3B } /* <?php\x0a\x0a$a = new self::$b(); */
        $fp5 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 5C 22 7B 24 76 61 72 43 61 6C 6C 61 62 6C 65 28 29 7D 5C 22 3B } /* <?php\x0a\x0a$a = \"{$varCallable()}\"; */
        $fp6 = "// TODO error about missing expression" /* <?php\x0a// TODO error about missing expression\x0a$a($b = 3, $c,); */
        $fp7 = "// This is an invalid location for an attribute, "
        $fp8 = "/* Auto-generated from php/php-langspec tests */"
        $fp_dynamic1 = /"\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii // e.g. echo "$callback($text)";
    condition:
        filesize > 20 and filesize < 200 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $dynamic* )
        )
        and not any of ( $pd_fp* )
        and not 1 of ($fp*)
}

rule WEBSHELL_PHP_Dynamic_Big
{
    meta:
        description = "PHP webshell using $a($code) for kind of eval with encoded blob to decode, e.g. b374k"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/02/07"
        modified = "2024-02-23"
        score = 50
        hash = "6559bfc4be43a55c6bb2bd867b4c9b929713d3f7f6de8111a3c330f87a9b302c"
        hash = "9e82c9c2fa64e26fd55aa18f74759454d89f968068d46b255bd4f41eb556112e"
        hash = "6def5296f95e191a9c7f64f7d8ac5c529d4a4347ae484775965442162345dc93"
        hash = "dadfdc4041caa37166db80838e572d091bb153815a306c8be0d66c9851b98c10"
        hash = "0a4a292f6e08479c04e5c4fdc3857eee72efa5cd39db52e4a6e405bf039928bd"
        hash = "4326d10059e97809fb1903eb96fd9152cc72c376913771f59fa674a3f110679e"
        hash = "b49d0f942a38a33d2b655b1c32ac44f19ed844c2479bad6e540f69b807dd3022"
        hash = "575edeb905b434a3b35732654eedd3afae81e7d99ca35848c509177aa9bf9eef"
        hash = "ee34d62e136a04e2eaf84b8daa12c9f2233a366af83081a38c3c973ab5e2c40f"

        id = "a5caab93-7b94-59d7-bbca-f9863e81b9e5"
    strings:
        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_php_new_long
        // no <?=
        $new_php2 = "<?php" nocase wide ascii
        $new_php3 = "<script language=\"php" nocase wide ascii
        $php_short = "<?"

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
        $dynamic8 = "eval(" wide ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        $gen_bit_sus27 = "zuncomp" wide ascii
        $gen_bit_sus28 = "ase6" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        $gen_bit_sus65 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
        $gen_bit_sus99 = "$password = " wide ascii
        $gen_bit_sus100 = "();$" wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "DEFACE" fullword wide ascii
        $gen_much_sus93 = "Bypass" fullword wide ascii
        $gen_much_sus94 = /eval\s{2,20}\(/ nocase wide ascii
        $gen_much_sus100 = "rot13" wide ascii
        $gen_much_sus101 = "ini_set('error_log'" wide ascii
        $gen_much_sus102 = "base64_decode(base64_decode(" wide ascii
        $gen_much_sus103 = "=$_COOKIE;" wide ascii
        // {1}.$ .. |{9}.$
        $gen_much_sus104 = { C0 A6 7B 3? 7D 2E 24 }
        $gen_much_sus105 = "$GLOBALS[\"__" wide ascii
        // those calculations don't make really sense :)
        $gen_much_sus106 = ")-0)" wide ascii
        $gen_much_sus107 = "-0)+" wide ascii
        $gen_much_sus108 = "+0)+" wide ascii
        $gen_much_sus109 = "+(0/" wide ascii
        $gen_much_sus110 = "+(0+" wide ascii
        $gen_much_sus111 = "extract($_REQUEST)" wide ascii
        $gen_much_sus112 = "<?php\t\t\t\t\t\t\t\t\t\t\t" wide ascii
        $gen_much_sus113 = "\t\t\t\t\t\t\t\t\t\t\textract" wide ascii
        $gen_much_sus114 = "\" .\"" wide ascii
        $gen_much_sus115 = "end($_POST" wide ascii

        $weevely1 = /';\n\$\w\s?=\s?'/ wide ascii
        $weevely2 = /';\x0d\n\$\w\s?=\s?'/ wide ascii // same with \r\n
        $weevely3 = /';\$\w{1,2}='/ wide ascii
        $weevely4 = "str_replace" fullword wide ascii

        $gif = { 47 49 46 38 }

        $fp1 = "# Some examples from obfuscated malware:" ascii
        $fp2 = "* @package   PHP_CodeSniffer" ascii
        $fp3 = ".jQuery===" ascii
        $fp4 = "* @param string $lstat encoded LStat string" ascii
    condition:
        //any of them or
        not (
            uint16(0) == 0x5a4d or
            // <?xml
            uint32be(0) == 0x3c3f786d  or
            // <?XML
            uint32be(0) == 0x3c3f584d  or
            $dex at 0 or
            $pack at 0 or
            // fp on jar with zero compression
            uint16(0) == 0x4b50 or
            1 of ($fp*)
        )
        and (
            any of ( $new_php* ) or
            $php_short at 0
        )
        and (
            any of ( $dynamic* )
        )
        and
            (
            $gif at 0 or
        (
            (
                filesize < 1KB and
                (
                    1 of ( $gen_much_sus* )
                )
            ) or (
                filesize < 2KB and
                (
                    ( #weevely1 + #weevely2 + #weevely3 ) > 2 and
                    #weevely4 > 1
                )
            ) or (
                filesize < 4000 and
                (
                    1 of ( $gen_much_sus* ) or
                    2 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 20KB and
                (
                    2 of ( $gen_much_sus* ) or
                    4 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 50KB and
                (
                    3 of ( $gen_much_sus* ) or
                    5 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 100KB and
                (
                    3 of ( $gen_much_sus* ) or
                    6 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 160KB and
                (
                    3 of ( $gen_much_sus* ) or
                    7 of ( $gen_bit_sus* ) or
                    (
                        // php files which use strings in the full ascii8 spectrum have a much hioher deviation than normal php-code
                        // e.g. 4057005718bb18b51b02d8b807265f8df821157ac47f78ace77f21b21fc77232
                        math.deviation(500, filesize-500, 89.0) > 70
                        // uncomment and include an "and" above for debugging, also import on top of file. needs yara 4.2.0
                        //console.log("high deviation") and
                        //console.log(math.deviation(500, filesize-500, 89.0))
                    )
                    // TODO: requires yara 4.2.0 so wait a bit until that's more common
                    //or
                    //(
                        // big file and just one line = minified
                        //filesize > 10KB and
                        //math.count(0x0A) < 2
                    //)
                )
            ) or (
                filesize < 500KB and
                (
                    4 of ( $gen_much_sus* ) or
                    8 of ( $gen_bit_sus* ) or
                    #gen_much_sus104 > 4

                )
            )
        ) or (
            // file shouldn't be too small to have big enough data for math.entropy
            filesize > 2KB and filesize < 1MB and
            (
                (
                    // base64 :
                    // ignore first and last 500bytes because they usually contain code for decoding and executing
                    math.entropy(500, filesize-500) >= 5.7 and
                    // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                    math.mean(500, filesize-500) > 80 and
                    // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                    // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                    // 89 is the mean of the base64 chars
                    math.deviation(500, filesize-500, 89.0) < 23
                ) or (
                    // gzinflated binary sometimes used in php webshells
                    // ignore first and last 500bytes because they usually contain code for decoding and executing
                    math.entropy(500, filesize-500) >= 7.7 and
                    // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                    math.mean(500, filesize-500) > 120 and
                    math.mean(500, filesize-500) < 136 and
                    // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                    // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                    // 89 is the mean of the base64 chars
                    math.deviation(500, filesize-500, 89.0) > 65
                )
            )
        )
        )
}

rule WEBSHELL_PHP_Encoded_Big
{
    meta:
        description = "PHP webshell using some kind of eval with encoded blob to decode, which is checked with YARAs math.entropy module"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/02/07"
        modified = "2024-12-16"
        score = 50
        hash = "1d4b374d284c12db881ba42ee63ebce2759e0b14"
        hash = "fc0086caee0a2cd20609a05a6253e23b5e3245b8"
        hash = "b15b073801067429a93e116af1147a21b928b215"
        hash = "74c92f29cf15de34b8866db4b40748243fb938b4"
        hash = "042245ee0c54996608ff8f442c8bafb8"

        id = "c3bb7b8b-c554-5802-8955-c83722498f8b"
    strings:

        //strings from private rule capa_php_new
        $new_php1 = /<\?=[\w\s@$]/ wide ascii
        $new_php2 = "<?php" nocase wide ascii
        $new_php3 = "<script language=\"php" nocase wide ascii
        $php_short = "<?"

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        //console.log(math.entropy(500, filesize-500)) and
        //console.log(math.mean(500, filesize-500)) and
        //console.log(math.deviation(500, filesize-500, 89.0)) and
        //any of them or
        filesize < 1000KB and (
            any of ( $new_php* ) or
        $php_short at 0
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and (
            // file shouldn't be too small to have big enough data for math.entropy
            filesize > 2KB and
        (
            // base64 :
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            math.entropy(500, filesize-500) >= 5.7 and
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            math.mean(500, filesize-500) > 80 and
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
            math.deviation(500, filesize-500, 89.0) < 24
        ) or (
            // gzinflated binary sometimes used in php webshells
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            math.entropy(500, filesize-500) >= 7.7 and
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            math.mean(500, filesize-500) > 120 and
            math.mean(500, filesize-500) < 136 and
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
            math.deviation(500, filesize-500, 89.0) > 65
        )
        )

}

rule WEBSHELL_PHP_Generic_Backticks
{
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "339f32c883f6175233f0d1a30510caa52fdcaa37"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
        hash = "af987b0eade03672c30c095cee0c7c00b663e4b3c6782615fb7e430e4a7d1d75"
        hash = "67339f9e70a17af16cf51686918cbe1c0604e129950129f67fe445eaff4b4b82"
        hash = "144e242a9b219c5570973ca26d03e82e9fbe7ba2773305d1713288ae3540b4ad"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

        id = "b2f1d8d0-8668-5641-8ce9-c8dd71f51f58"
    strings:
        $backtick = /`\s*\{?\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $backtick and filesize < 200
}

rule WEBSHELL_PHP_Generic_Backticks_OBFUSC
{
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "23dc299f941d98c72bd48659cdb4673f5ba93697"
        hash = "e3f393a1530a2824125ecdd6ac79d80cfb18fffb89f470d687323fb5dff0eec1"
        hash = "1e75914336b1013cc30b24d76569542447833416516af0d237c599f95b593f9b"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

        id = "5ecb329f-0755-536d-8bfa-e36158474a0b"
    strings:
        $s1 = /echo[\t ]{0,500}\(?`\$/ wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 500 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $s1
}

rule WEBSHELL_PHP_By_String_Known_Webshell
{
    meta:
        description = "Known PHP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021-01-09"
        modified = "2023-04-05"
        score = 70
        hash = "d889da22893536d5965541c30896f4ed4fdf461d"
        hash = "10f4988a191774a2c6b85604344535ee610b844c1708602a355cf7e9c12c3605"
        hash = "7b6471774d14510cf6fa312a496eed72b614f6fc"
        hash = "decda94d40c3fd13dab21e197c8d05f48020fa498f4d0af1f60e29616009e9bf"
        hash = "ef178d332a4780e8b6db0e772aded71ac1a6ed09b923cc359ba3c4efdd818acc"
        hash = "a7a937c766029456050b22fa4218b1f2b45eef0db59b414f79d10791feca2c0b"
        hash = "e7edd380a1a2828929fbde8e7833d6e3385f7652ea6b352d26b86a1e39130ee8"
        hash = "0038946739956c80d75fa9eeb1b5c123b064bbb9381d164d812d72c7c5d13cac"
        hash = "3a7309bad8a5364958081042b5602d82554b97eca04ee8fdd8b671b5d1ddb65d"
        hash = "a78324b9dc0b0676431af40e11bd4e26721a960c55e272d718932bdbb755a098"
        hash = "a27f8cd10cedd20bff51e9a8e19e69361cc8a6a1a700cc64140e66d160be1781"
        hash = "9bbd3462993988f9865262653b35b4151386ed2373592a1e2f8cf0f0271cdb00"
        hash = "459ed1d6f87530910361b1e6065c05ef0b337d128f446253b4e29ae8cc1a3915"
        hash = "12b34d2562518d339ed405fb2f182f95dce36d08fefb5fb67cc9386565f592d1"
        hash = "96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636"
        hash = "312ee17ec9bed4278579443b805c0eb75283f54483d12f9add7d7d9e5f9f6105"
        hash = "15c4e5225ff7811e43506f0e123daee869a8292fc8a38030d165cc3f6a488c95"
        hash = "0c845a031e06925c22667e101a858131bbeb681d78b5dbf446fdd5bca344d765"
        hash = "d52128bcfff5e9a121eab3d76382420c3eebbdb33cd0879fbef7c3426e819695"

        //TODO regex for 96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636 would it be fast enough?

        id = "05ac0e0a-3a19-5c60-b89a-4a300d8c22e7"
    strings:
        $pbs1 = "b374k shell" wide ascii
        $pbs2 = "b374k/b374k" wide ascii
        $pbs3 = "\"b374k" wide ascii
        $pbs4 = "$b374k(\"" wide ascii
        $pbs5 = "b374k " wide ascii
        $pbs6 = "0de664ecd2be02cdd54234a0d1229b43" wide ascii
        $pbs7 = "pwnshell" wide ascii
        $pbs8 = "reGeorg" fullword wide ascii
        $pbs9 = "Georg says, 'All seems fine" fullword wide ascii
        $pbs10 = "My PHP Shell - A very simple web shell" wide ascii
        $pbs11 = "<title>My PHP Shell <?echo VERSION" wide ascii
        $pbs12 = "F4ckTeam" fullword wide ascii
        $pbs15 = "MulCiShell" fullword wide ascii
        // crawler avoid string
        $pbs30 = "bot|spider|crawler|slurp|teoma|archive|track|snoopy|java|lwp|wget|curl|client|python|libwww" wide ascii
        // <?=($pbs_=@$_GET[2]).@$_($_GET[1])?>
        $pbs35 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
        $pbs36 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_POST\s?\[\d\]\)/ wide ascii
        $pbs37 = /@\$_POST\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
        $pbs38 = /@\$_POST\[\d\]\)\.@\$_\(\$_POST\[\d\]\)/ wide ascii
        $pbs39 = /@\$_REQUEST\[\d\]\)\.@\$_\(\$_REQUEST\[\d\]\)/ wide ascii
        $pbs42 = "array(\"find config.inc.php files\", \"find / -type f -name config.inc.php\")" wide ascii
        $pbs43 = "$_SERVER[\"\\x48\\x54\\x54\\x50" wide ascii
        $pbs52 = "preg_replace(\"/[checksql]/e\""
        $pbs53 = "='http://www.zjjv.com'"
        $pbs54 = "=\"http://www.zjjv.com\""

        $pbs60 = /setting\["AccountType"\]\s?=\s?3/
        $pbs61 = "~+d()\"^\"!{+{}"
        $pbs62 = "use function \\eval as "
        $pbs63 = "use function \\assert as "
        $pbs64 = "eval(`/*" wide ascii
        $pbs65 = "/* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" wide ascii
        $pbs66 = "Tas9er" fullword wide ascii
        $pbs67 = "\"TSOP_\";" fullword wide ascii // reverse _POST
        $pbs68 = "str_rot13('nffreg')" wide ascii // rot13(assert)
        $pbs69 = "<?=`{$'" wide ascii
        $pbs70 = "{'_'.$_}[\"_\"](${'_'.$_}[\"_" wide ascii
        $pbs71 = "\"e45e329feb5d925b\"" wide ascii
        $pbs72 = "| PHP FILE MANAGER" wide ascii
        $pbs73 = "\neval(htmlspecialchars_decode(gzinflate(base64_decode($" wide ascii
        $pbs74 = "/*\n\nShellindir.org\n\n*/" wide ascii
        $pbs75 = "$shell = 'uname -a; w; id; /bin/sh -i';" wide ascii
        $pbs76 = "'password' . '/' . 'id' . '/' . " wide ascii
        $pbs77 = "= create_function /*" wide ascii
        $pbs78 = "W3LL M!N! SH3LL" wide ascii
        $pbs79 = "extract($_REQUEST)&&@$" wide ascii
        $pbs80 = "\"P-h-p-S-p-y\"" wide ascii
        $pbs81 = "\\x5f\\x72\\x6f\\x74\\x31\\x33" wide ascii
        $pbs82 = "\\x62\\x61\\x73\\x65\\x36\\x34\\x5f" wide ascii
        $pbs83 = "*/base64_decode/*" wide ascii
        $pbs84 = "\n@eval/*" wide ascii
        $pbs85 = "*/eval/*" wide ascii
        $pbs86 = "*/ array /*" wide ascii
        $pbs87 = "2jtffszJe" wide ascii
        $pbs88 = "edocne_46esab" wide ascii
        $pbs89 = "eval($_HEADERS" wide ascii
        $pbs90 = ">Infinity-Sh3ll<" ascii

        $front1 = "<?php eval(" nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        filesize < 1000KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and
        ( any of ( $pbs* ) or $front1 in ( 0 .. 60 ) )
}

rule WEBSHELL_PHP_Strings_SUSP
{
    meta:
        description = "typical webshell strings, suspicious"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/12"
        modified = "2023-07-05"
        score = 50
        hash = "0dd568dbe946b5aa4e1d33eab1decbd71903ea04"
        hash = "dde2bdcde95730510b22ae8d52e4344997cb1e74"
        hash = "499db4d70955f7d40cf5cbaf2ecaf7a2"
        hash = "281b66f62db5caab2a6eb08929575ad95628a690"
        hash = "1ab3ae4d613b120f9681f6aa8933d66fa38e4886"

        id = "25f25df5-4398-562b-9383-e01ccb17e8de"
    strings:
        $sstring1 = "eval(\"?>\"" nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not (
            any of ( $gfp* )
        )
        and
        ( 1 of ( $sstring* ) and (
            any of ( $inp* )
        )
        )
}

rule WEBSHELL_PHP_In_Htaccess
{
    meta:
        description = "Use Apache .htaccess to execute php code inside .htaccess"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
        hash = "d79e9b13a32a9e9f3fa36aa1a4baf444bfd2599a"
        hash = "e1d1091fee6026829e037b2c70c228344955c263"
        hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
        hash = "8c9e65cd3ef093cd9c5b418dc5116845aa6602bc92b9b5991b27344d8b3f7ef2"

        id = "0f5edff9-22b2-50c9-ae81-72698ea8e7db"
    strings:
        $hta = "AddType application/x-httpd-php .htaccess" wide ascii

    condition:
        filesize <100KB and $hta
}

rule WEBSHELL_PHP_Function_Via_Get
{
    meta:
        description = "Webshell which sends eval/assert via GET"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/09"
        modified = "2023-04-05"
        hash = "ce739d65c31b3c7ea94357a38f7bd0dc264da052d4fd93a1eabb257f6e3a97a6"
        hash = "d870e971511ea3e082662f8e6ec22e8a8443ca79"
        hash = "73fa97372b3bb829835270a5e20259163ecc3fdbf73ef2a99cb80709ea4572be"

        id = "5fef1063-2f9f-516e-86f6-cfd98bb05e6e"
    strings:
        $sr0 = /\$_GET\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
        $sr1 = /\$_POST\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
        $sr2 = /\$_POST\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
        $sr3 = /\$_GET\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
        $sr4 = /\$_REQUEST\s?\[.{1,30}\]\(\$_REQUEST\s?\[/ wide ascii
        $sr5 = /\$_SERVER\s?\[HTTP_.{1,30}\]\(\$_SERVER\s?\[HTTP_/ wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

    condition:
        filesize < 500KB and not (
            any of ( $gfp* )
        )
        and any of ( $sr* )
}

rule WEBSHELL_PHP_Writer
{
    meta:
        description = "PHP webshell which only writes an uploaded file to disk"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/04/17"
        modified = "2023-07-05"
        score = 50
        hash = "ec83d69512aa0cc85584973f5f0850932fb1949fb5fb2b7e6e5bbfb121193637"
        hash = "407c15f94a33232c64ddf45f194917fabcd2e83cf93f38ee82f9720e2635fa64"
        hash = "988b125b6727b94ce9a27ea42edc0ce282c5dfeb"
        hash = "0ce760131787803bbef216d0ee9b5eb062633537"
        hash = "20281d16838f707c86b1ff1428a293ed6aec0e97"

        id = "05bb3e0c-69b2-5176-a3eb-e6ba2d72a205"
    strings:
        $sus3 = "'upload'" wide ascii
        $sus4 = "\"upload\"" wide ascii
        $sus5 = "\"Upload\"" wide ascii
        $sus6 = "gif89" wide ascii
        //$sus13= "<textarea " wide ascii
        $sus16= "Army" fullword wide ascii
        $sus17= "error_reporting( 0 )" wide ascii
        $sus18= "' . '" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" wide ascii
        $php_multi_write2 = "fwrite(" wide ascii
        $php_write1 = "move_uploaded_file" fullword wide ascii
        $php_write2 = "copy" fullword wide ascii

    condition:
        //any of them or
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
        any of ( $php_write* ) or
        all of ( $php_multi_write* )
        )
        and
        (
            filesize < 400 or
            (
                filesize < 4000 and 1 of ( $sus* )
            )
        )
}

rule WEBSHELL_ASP_Writer
{
    meta:
        description = "ASP webshell which only writes an uploaded file to disk"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/07"
        modified = "2023-07-05"
        score = 60
        hash = "df6eaba8d643c49c6f38016531c88332e80af33c"
        hash = "83642a926291a499916e8c915dacadd0d5a8b91f"
        hash = "5417fad68a6f7320d227f558bf64657fe3aa9153"
        hash = "97d9f6c411f54b56056a145654cd00abca2ff871"
        hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"

        id = "a1310e22-f485-5f06-8f1a-4cf9ae8413a1"
    strings:
        $sus1 = "password" fullword wide ascii
        $sus2 = "pwd" fullword wide ascii
        $sus3 = "<asp:TextBox" fullword nocase wide ascii
        $sus4 = "\"upload\"" wide ascii
        $sus5 = "\"Upload\"" wide ascii
        $sus6 = "gif89" wide ascii
        $sus7 = "\"&\"" wide ascii
        $sus8 = "authkey" fullword wide ascii
        $sus9 = "AUTHKEY" fullword wide ascii
        $sus10= "test.asp" fullword wide ascii
        $sus11= "cmd.asp" fullword wide ascii
        $sus12= ".Write(Request." wide ascii
        $sus13= "<textarea " wide ascii
        $sus14= "\"unsafe" fullword wide ascii
        $sus15= "'unsafe" fullword wide ascii
        $sus16= "Army" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        and
        ( filesize < 400 or
        ( filesize < 6000 and 1 of ( $sus* ) ) )
}

rule WEBSHELL_ASP_OBFUSC
{
    meta:
        description = "ASP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "ad597eee256de51ffb36518cd5f0f4aa0f254f27517d28fb7543ae313b15e112"
        hash = "e0d21fdc16e0010b88d0197ebf619faa4aeca65243f545c18e10859469c1805a"
        hash = "54a5620d4ea42e41beac08d8b1240b642dd6fd7c"
        hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"
        hash = "be2fedc38fc0c3d1f925310d5156ccf3d80f1432"
        hash = "3175ee00fc66921ebec2e7ece8aa3296d4275cb5"
        hash = "d6b96d844ac395358ee38d4524105d331af42ede"
        hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"

        id = "3960b692-9f6f-52c5-b881-6f9e1b3ac555"
    strings:
        $asp_obf1 = "/*-/*-*/" wide ascii
        $asp_obf2 = "u\"+\"n\"+\"s" wide ascii
        $asp_obf3 = "\"e\"+\"v" wide ascii
        $asp_obf4 = "a\"+\"l\"" wide ascii
        $asp_obf5 = "\"+\"(\"+\"" wide ascii
        $asp_obf6 = "q\"+\"u\"" wide ascii
        $asp_obf7 = "\"u\"+\"e" wide ascii
        $asp_obf8 = "/*//*/" wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

        //strings from private rule capa_asp_obfuscation_multi
        // many Chr or few and a loop????
        //$loop1 = "For "
        //$o1 = "chr(" nocase wide ascii
        //$o2 = "chr (" nocase wide ascii
        // not excactly a string function but also often used in obfuscation
        $o4 = "\\x8" wide ascii
        $o5 = "\\x9" wide ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" wide ascii
        $o7 = "\\44" wide ascii
        $o8 = "\\112" wide ascii
        $o9 = "\\120" wide ascii
        //$o10 = " & \"" wide ascii
        //$o11 = " += \"" wide ascii
        // used for e.g. "scr"&"ipt"

        $m_multi_one1 = "Replace(" wide ascii
        $m_multi_one2 = "Len(" wide ascii
        $m_multi_one3 = "Mid(" wide ascii
        $m_multi_one4 = "mid(" wide ascii
        $m_multi_one5 = ".ToString(" wide ascii

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

        $m_fp1 = "Author: Andre Teixeira - andret@microsoft.com" /* FPs with 0227f4c366c07c45628b02bae6b4ad01 */
        $m_fp2 = "DataBinder.Eval(Container.DataItem" ascii wide


        //strings from private rule capa_asp_obfuscation_obviously
        $oo1 = /\w\"&\"\w/ wide ascii
        $oo2 = "*/\").Replace(\"/*" wide ascii

    condition:
        filesize < 100KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) and
        ( (
        (
            filesize < 100KB and
            (
                //( #o1+#o2 ) > 50 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20
            )
        ) or (
            filesize < 5KB and
            (
                //( #o1+#o2 ) > 10 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 5 or
                (
                    //( #o1+#o2 ) > 1 and
                    ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 3
                )

            )
        ) or (
            filesize < 700 and
            (
                //( #o1+#o2 ) > 1 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 3 or
                ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 2
            )
        )
        )
        or any of ( $asp_obf* ) ) or (
        (
            filesize < 100KB and
            (
                ( #oo1 ) > 2 or
                $oo2
            )
        ) or (
            filesize < 25KB and
            (
                ( #oo1 ) > 1
            )
        ) or (
            filesize < 1KB and
            (
                ( #oo1 ) > 0
            )
        )
        )
        )
        and not any of ( $m_fp* )
}

rule WEBSHELL_ASP_Generic_Eval_On_Input
{
    meta:
        description = "Generic ASP webshell which uses any eval/exec function directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "d6b96d844ac395358ee38d4524105d331af42ede"
        hash = "9be2088d5c3bfad9e8dfa2d7d7ba7834030c7407"
        hash = "a1df4cfb978567c4d1c353e988915c25c19a0e4a"
        hash = "069ea990d32fc980939fffdf1aed77384bf7806bc57c0a7faaff33bd1a3447f6"

        id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
    strings:
        $payload_and_input0 = /\beval_r\s{0,20}\(Request\(/ nocase wide ascii
        $payload_and_input1 = /\beval[\s\(]{1,20}request[.\(\[]/ nocase wide ascii
        $payload_and_input2 = /\bexecute[\s\(]{1,20}request\(/ nocase wide ascii
        $payload_and_input4 = /\bExecuteGlobal\s{1,20}request\(/ nocase wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        ( filesize < 1100KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and any of ( $payload_and_input* ) ) or
        ( filesize < 100 and any of ( $payload_and_input* ) )
}

rule WEBSHELL_ASP_Nano
{
    meta:
        description = "Generic ASP webshell which uses any eval/exec function"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/13"
        modified = "2023-04-05"
        hash = "3b7910a499c603715b083ddb6f881c1a0a3a924d"
        hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
        hash = "22345e956bce23304f5e8e356c423cee60b0912c"
        hash = "c84a6098fbd89bd085526b220d0a3f9ab505bcba"
        hash = "b977c0ad20dc738b5dacda51ec8da718301a75d7"
        hash = "c69df00b57fd127c7d4e0e2a40d2f6c3056e0af8bfb1925938060b7e0d8c630f"
        hash = "f3b39a5da1cdde9acde077208e8e5b27feb973514dab7f262c7c6b2f8f11eaa7"
        hash = "0e9d92807d990144c637d8b081a6a90a74f15c7337522874cf6317092ea2d7c1"
        hash = "ebbc485e778f8e559ef9c66f55bb01dc4f5dcce9c31ccdd150e2c702c4b5d9e1"
        hash = "44b4068bfbbb8961e16bae238ad23d181ac9c8e4fcb4b09a66bbcd934d2d39ee"
        hash = "c5a4e188780b5513f34824904d56bf6e364979af6782417ccc5e5a8a70b4a95a"
        hash = "41a3cc668517ec207c990078bccfc877e239b12a7ff2abe55ff68352f76e819c"
        hash = "2faad5944142395794e5e6b90a34a6204412161f45e130aeb9c00eff764f65fc"
        hash = "d0c5e641120b8ea70a363529843d9f393074c54af87913b3ab635189fb0c84cb"
        hash = "28cfcfe28419a399c606bf96505bc68d6fe05624dba18306993f9fe0d398fbe1"

        id = "5f2f24c2-159d-51e1-80d9-11eeb77e8760"
    strings:
        $susasp1  = "/*-/*-*/"
        $susasp2  = "(\"%1"
        $susasp3  = /[Cc]hr\([Ss]tr\(/
        $susasp4  = "cmd.exe"
        $susasp5  = "cmd /c"
        $susasp7  = "FromBase64String"
        // Request and request in b64:
        $susasp8  = "UmVxdWVzdC"
        $susasp9  = "cmVxdWVzdA"
        $susasp10 = "/*//*/"
        $susasp11 = "(\"/*/\""
        $susasp12 = "eval(eval("
        $fp1      = "eval a"
        $fp2      = "'Eval'"
        $fp3      = "Eval(\""

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) and not any of ( $fp* ) and
        ( filesize < 200 or
        ( filesize < 1000 and any of ( $susasp* ) ) )
}

rule WEBSHELL_ASP_Encoded
{
    meta:
        description = "Webshell in VBscript or JScript encoded using *.Encode plus a suspicious string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "1bc7327f9d3dbff488e5b0b69a1b39dcb99b3399"
        hash = "9885ee1952b5ad9f84176c9570ad4f0e32461c92"
        hash = "27a020c5bc0dbabe889f436271df129627b02196"
        hash = "f41f8c82b155c3110fc1325e82b9ee92b741028b"
        hash = "af40f4c36e3723236c59dc02f28a3efb047d67dd"

        id = "67c0e1f6-6da5-569c-ab61-8b8607429471"
    strings:
        $encoded1 = "VBScript.Encode" nocase wide ascii
        $encoded2 = "JScript.Encode" nocase wide ascii
        $data1 = "#@~^" wide ascii
        $sus1 = "shell" nocase wide ascii
        $sus2 = "cmd" fullword wide ascii
        $sus3 = "password" fullword wide ascii
        $sus4 = "UserPass" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 500KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and any of ( $encoded* ) and any of ( $data* ) and
        ( any of ( $sus* ) or
        ( filesize < 20KB and #data1 > 4 ) or
        ( filesize < 700 and #data1 > 0 ) )
}

rule WEBSHELL_ASP_Encoded_AspCoding
{
    meta:
        description = "ASP Webshell encoded using ASPEncodeDLL.AspCoding"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/14"
        modified = "2023-07-05"
        score = 60
        hash = "7cfd184ab099c4d60b13457140493b49c8ba61ee"
        hash = "f5095345ee085318235c11ae5869ae564d636a5342868d0935de7582ba3c7d7a"

        id = "788a8dae-bcb8-547c-ba17-e1f14bc28f34"
    strings:
        $encoded1 = "ASPEncodeDLL" fullword nocase wide ascii
        $encoded2 = ".Runt" nocase wide ascii
        $encoded3 = "Request" fullword nocase wide ascii
        $encoded4 = "Response" fullword nocase wide ascii
        $data1 = "AspCoding.EnCode" wide ascii
        //$sus1 = "shell" nocase wide ascii
        //$sus2 = "cmd" fullword wide ascii
        //$sus3 = "password" fullword wide ascii
        //$sus4 = "UserPass" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 500KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and all of ( $encoded* ) and any of ( $data* )
}

rule WEBSHELL_ASP_By_String
{
    meta:
        description = "Known ASP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021-01-13"
        modified = "2023-04-05"
        hash = "f72252b13d7ded46f0a206f63a1c19a66449f216"
        hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
        hash = "56a54fe1f8023455800fd0740037d806709ffb9ece1eb9e7486ad3c3e3608d45"
        hash = "4ef5d8b51f13b36ce7047e373159d7bb42ca6c9da30fad22e083ab19364c9985"
        hash = "e90c3c270a44575c68d269b6cf78de14222f2cbc5fdfb07b9995eb567d906220"
        hash = "8a38835f179e71111663b19baade78cc3c9e1f6fcc87eb35009cbd09393cbc53"
        hash = "f2883e9461393b33feed4139c0fc10fcc72ff92924249eb7be83cb5b76f0f4ee"
        hash = "10cca59c7112dfb1c9104d352e0504f842efd4e05b228b6f34c2d4e13ffd0eb6"
        hash = "ed179e5d4d365b0332e9ffca83f66ee0afe1f1b5ac3c656ccd08179170a4d9f7"
        hash = "ce3273e98e478a7e95fccce0a3d3e8135c234a46f305867f2deacd4f0efa7338"
        hash = "65543373b8bd7656478fdf9ceeacb8490ff8976b1fefc754cd35c89940225bcf"
        hash = "de173ea8dcef777368089504a4af0804864295b75e51794038a6d70f2bcfc6f5"


        id = "4705b28b-2ffa-53d1-b727-1a9fc2a7dd69"
    strings:
        // reversed
        $asp_string1  = "tseuqer lave" wide ascii
        $asp_string2  = ":eval request(" wide ascii
        $asp_string3  = ":eval request(" wide ascii
        $asp_string4  = "SItEuRl=\"http://www.zjjv.com\"" wide ascii
        $asp_string5  = "ServerVariables(\"HTTP_HOST\"),\"gov.cn\"" wide ascii
        // e+k-v+k-a+k-l
        // e+x-v+x-a+x-l
        $asp_string6  = /e\+.-v\+.-a\+.-l/ wide ascii
        $asp_string7  = "r+x-e+x-q+x-u" wide ascii
        $asp_string8  = "add6bb58e139be10" fullword wide ascii
        $asp_string9  = "WebAdmin2Y.x.y(\"" wide ascii
        $asp_string10 = "<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request[" wide ascii
        $asp_string11 = "<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request(" wide ascii
        // Request.Item["
        $asp_string12 = "UmVxdWVzdC5JdGVtWyJ" wide ascii

        // eval( in utf7 in base64 all 3 versions
        $asp_string13 = "UAdgBhAGwAKA" wide ascii
        $asp_string14 = "lAHYAYQBsACgA" wide ascii
        $asp_string15 = "ZQB2AGEAbAAoA" wide ascii
        // request in utf7 in base64 all 3 versions
        $asp_string16 = "IAZQBxAHUAZQBzAHQAKA" wide ascii
        $asp_string17 = "yAGUAcQB1AGUAcwB0ACgA" wide ascii
        $asp_string18 = "cgBlAHEAdQBlAHMAdAAoA" wide ascii

        $asp_string19 = "\"ev\"&\"al" wide ascii
        $asp_string20 = "\"Sc\"&\"ri\"&\"p" wide ascii
        $asp_string21 = "C\"&\"ont\"&\"" wide ascii
        $asp_string22 = "\"vb\"&\"sc" wide ascii
        $asp_string23 = "\"A\"&\"do\"&\"d" wide ascii
        $asp_string24 = "St\"&\"re\"&\"am\"" wide ascii
        $asp_string25 = "*/eval(" wide ascii
        $asp_string26 = "\"e\"&\"v\"&\"a\"&\"l" nocase
        $asp_string27 = "<%eval\"\"&(\"" nocase wide ascii
        $asp_string28 = "6877656D2B736972786677752B237E232C2A"  wide ascii
        $asp_string29 = "ws\"&\"cript.shell" wide ascii
        $asp_string30 = "SerVer.CreAtEoBjECT(\"ADODB.Stream\")" wide ascii
        $asp_string31 = "ASPShell - web based shell" wide ascii
        $asp_string32 = "<++ CmdAsp.asp ++>" wide ascii
        $asp_string33 = "\"scr\"&\"ipt\"" wide ascii
        $asp_string34 = "Regex regImg = new Regex(\"[a-z|A-Z]{1}:\\\\\\\\[a-z|A-Z| |0-9|\\u4e00-\\u9fa5|\\\\~|\\\\\\\\|_|{|}|\\\\.]*\");" wide ascii
        $asp_string35 = "\"she\"&\"ll." wide ascii
        $asp_string36 = "LH\"&\"TTP" wide ascii
        $asp_string37 = "<title>Web Sniffer</title>" wide ascii
        $asp_string38 = "<title>WebSniff" wide ascii
        $asp_string39 = "cript\"&\"ing" wide ascii
        $asp_string40 = "tcejbOmetsySeliF.gnitpircS" wide ascii
        $asp_string41 = "tcejbOetaerC.revreS" wide ascii
        $asp_string42 = "This file is part of A Black Path Toward The Sun (\"ABPTTS\")" wide ascii
        $asp_string43 = "if ((Request.Headers[headerNameKey] != null) && (Request.Headers[headerNameKey].Trim() == headerValueKey.Trim()))" wide ascii
        $asp_string44 = "if (request.getHeader(headerNameKey).toString().trim().equals(headerValueKey.trim()))" wide ascii
        $asp_string45 = "Response.Write(Server.HtmlEncode(ExcutemeuCmd(txtArg.Text)));" wide ascii
        $asp_string46 = "\"c\" + \"m\" + \"d\"" wide ascii
        $asp_string47 = "\".\"+\"e\"+\"x\"+\"e\"" wide ascii
        $asp_string48 = "Tas9er" fullword wide ascii
        $asp_string49 = "<%@ Page Language=\"\\u" wide ascii
        $asp_string50 = "BinaryRead(\\u" wide ascii
        $asp_string51 = "Request.\\u" wide ascii
        $asp_string52 = "System.Buffer.\\u" wide ascii
        $asp_string53 = "System.Net.\\u" wide ascii
        $asp_string54 = ".\\u0052\\u0065\\u0066\\u006c\\u0065\\u0063\\u0074\\u0069\\u006f\\u006e\"" wide ascii
        $asp_string55 = "\\u0041\\u0073\\u0073\\u0065\\u006d\\u0062\\u006c\\u0079.\\u004c\\u006f\\u0061\\u0064" wide ascii
        $asp_string56 = "\\U00000052\\U00000065\\U00000071\\U00000075\\U00000065\\U00000073\\U00000074[\"" wide ascii
        $asp_string57 = "*/\\U0000" wide ascii
        $asp_string58 = "\\U0000FFFA" wide ascii
        $asp_string59 = "\"e45e329feb5d925b\"" wide ascii
        $asp_string60 = ">POWER!shelled<" wide ascii
        $asp_string61 = "@requires xhEditor" wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 200KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and any of ( $asp_string* )
}

rule WEBSHELL_ASP_Sniffer
{
    meta:
        description = "ASP webshell which can sniff local traffic"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "1206c22de8d51055a5e3841b4542fb13aa0f97dd"
        hash = "60d131af1ed23810dbc78f85ee32ffd863f8f0f4"
        hash = "c3bc4ab8076ef184c526eb7f16e08d41b4cec97e"
        hash = "ed5938c04f61795834751d44a383f8ca0ceac833"

        id = "b5704c19-fce1-5210-8185-4839c1c5a344"
    strings:
        $sniff1 = "Socket(" wide ascii
        $sniff2 = ".Bind(" wide ascii
        $sniff3 = ".SetSocketOption(" wide ascii
        $sniff4 = ".IOControl(" wide ascii
        $sniff5 = "PacketCaptureWriter" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and filesize < 30KB and all of ( $sniff* )
}

rule WEBSHELL_ASP_Generic_Tiny
{
    meta:
        description = "Generic tiny ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
        hash = "52ce724580e533da983856c4ebe634336f5fd13a"
        hash = "0864f040a37c3e1cef0213df273870ed6a61e4bc"
        hash = "b184dc97b19485f734e3057e67007a16d47b2a62"

        id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
    strings:
        $fp1 = "net.rim.application.ipproxyservice.AdminCommand.execute"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and not 1 of ( $fp* ) and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and
        ( filesize < 700 and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) )
}

rule WEBSHELL_ASP_Generic : FILE {
    meta:
        description = "Generic ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021-03-07"
        modified = "2023-07-05"
        score = 60
        hash = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"
        hash = "4cf6fbad0411b7d33e38075f5e00d4c8ae9ce2f6f53967729974d004a183b25c"
        hash = "a91320483df0178eb3cafea830c1bd94585fc896"
        hash = "f3398832f697e3db91c3da71a8e775ebf66c7e73"
        id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
    strings:
        $asp_much_sus7  = "Web Shell" nocase
        $asp_much_sus8  = "WebShell" nocase
        $asp_much_sus3  = "hidded shell"
        $asp_much_sus4  = "WScript.Shell.1" nocase
        $asp_much_sus5  = "AspExec"
        $asp_much_sus14 = "\\pcAnywhere\\" nocase
        $asp_much_sus15 = "antivirus" nocase
        $asp_much_sus16 = "McAfee" nocase
        $asp_much_sus17 = "nishang"
        $asp_much_sus18 = "\"unsafe" fullword wide ascii
        $asp_much_sus19 = "'unsafe" fullword wide ascii
        $asp_much_sus28 = "exploit" fullword wide ascii
        $asp_much_sus30 = "TVqQAAMAAA" wide ascii
        $asp_much_sus31 = "HACKED" fullword wide ascii
        $asp_much_sus32 = "hacked" fullword wide ascii
        $asp_much_sus33 = "hacker" wide ascii
        $asp_much_sus34 = "grayhat" nocase wide ascii
        $asp_much_sus35 = "Microsoft FrontPage" wide ascii
        $asp_much_sus36 = "Rootkit" wide ascii
        $asp_much_sus37 = "rootkit" wide ascii
        $asp_much_sus38 = "/*-/*-*/" wide ascii
        $asp_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $asp_much_sus40 = "\"e\"+\"v" wide ascii
        $asp_much_sus41 = "a\"+\"l\"" wide ascii
        $asp_much_sus42 = "\"+\"(\"+\"" wide ascii
        $asp_much_sus43 = "q\"+\"u\"" wide ascii
        $asp_much_sus44 = "\"u\"+\"e" wide ascii
        $asp_much_sus45 = "/*//*/" wide ascii
        $asp_much_sus46 = "(\"/*/\"" wide ascii
        $asp_much_sus47 = "eval(eval(" wide ascii
        $asp_much_sus48 = "Shell.Users" wide ascii
        $asp_much_sus49 = "PasswordType=Regular" wide ascii
        $asp_much_sus50 = "-Expire=0" wide ascii
        $asp_much_sus51 = "sh\"&\"el" wide ascii

        $asp_gen_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $asp_gen_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $asp_gen_sus6  = "self.delete"
        $asp_gen_sus9  = "\"cmd /c" nocase
        $asp_gen_sus10 = "\"cmd\"" nocase
        $asp_gen_sus11 = "\"cmd.exe" nocase
        $asp_gen_sus12 = "%comspec%" wide ascii
        $asp_gen_sus13 = "%COMSPEC%" wide ascii
        //TODO:$asp_gen_sus12 = ".UserName" nocase
        $asp_gen_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $asp_gen_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $asp_gen_sus21 = "\"upload\"" wide ascii
        $asp_gen_sus22 = "\"Upload\"" wide ascii
        $asp_gen_sus25 = "shell_" wide ascii
        //$asp_gen_sus26 = "password" fullword wide ascii
        //$asp_gen_sus27 = "passw" fullword wide ascii
        // own base64 or base 32 func
        $asp_gen_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $asp_gen_sus30 = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $asp_gen_sus31 = "serv-u" wide ascii
        $asp_gen_sus32 = "Serv-u" wide ascii
        $asp_gen_sus33 = "Army" fullword wide ascii

        $asp_slightly_sus1 = "<pre>" wide ascii
        $asp_slightly_sus2 = "<PRE>" wide ascii


        // "e"+"x"+"e"
        $asp_gen_obf1 = "\"+\"" wide ascii

        $fp1 = "DataBinder.Eval"
        $fp2 = "B2BTools"
        $fp3 = "<b>Failed to execute cache update. See the log file for more information" ascii
        $fp4 = "Microsoft. All rights reserved."
        $fp5 = "\"unsafe\"," ascii wide

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = "Start" fullword wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

        //strings from private rule capa_asp_classid
        $tagasp_capa_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_capa_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_capa_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_capa_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_capa_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii

    condition:
        //any of them or
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        and not any of ( $fp* ) and
        ( ( filesize < 3KB and
        ( 1 of ( $asp_slightly_sus* ) ) ) or
        ( filesize < 25KB and
        ( 1 of ( $asp_much_sus* ) or 1 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 2 ) ) ) or
        ( filesize < 50KB and
        ( 1 of ( $asp_much_sus* ) or 3 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 6 ) ) ) or
        ( filesize < 150KB and
        ( 1 of ( $asp_much_sus* ) or 4 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 6 ) or
        ( (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        and
        ( 1 of ( $asp_much_sus* ) or 2 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 3 ) ) ) ) ) or
        ( filesize < 100KB and (
        any of ( $tagasp_capa_classid* )
        )
        ) )
}

rule WEBSHELL_ASP_Generic_Registry_Reader
{
    meta:
        description = "Generic ASP webshell which reads the registry (might look for passwords, license keys, database settings, general recon, ..."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/14"
        modified = "2023-07-05"
        score = 50
        hash = "4d53416398a89aef3a39f63338a7c1bf2d3fcda4"
        hash = "f85cf490d7eb4484b415bea08b7e24742704bdda"
        hash = "898ebfa1757dcbbecb2afcdab1560d72ae6940de"

        id = "02d6f95f-1801-5fb0-8ab8-92176cf2fdd7"
    strings:
        /* $asp_reg1  = "Registry" fullword wide ascii */ /* too many matches issues */
        $asp_reg2  = "LocalMachine" fullword wide ascii
        $asp_reg3  = "ClassesRoot" fullword wide ascii
        $asp_reg4  = "CurrentUser" fullword wide ascii
        $asp_reg5  = "Users" fullword wide ascii
        $asp_reg6  = "CurrentConfig" fullword wide ascii
        $asp_reg7  = "Microsoft.Win32" fullword wide ascii
        $asp_reg8  = "OpenSubKey" fullword wide ascii

        $sus1 = "shell" fullword nocase wide ascii
        $sus2 = "cmd.exe" fullword wide ascii
        $sus3 = "<form " wide ascii
        $sus4 = "<table " wide ascii
        $sus5 = "System.Security.SecurityException" wide ascii

        $fp1 = "Avira Operations GmbH" wide

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and all of ( $asp_reg* ) and any of ( $sus* ) and not any of ( $fp* ) and
        ( filesize < 10KB or
        ( filesize < 150KB and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        ) )
}

rule WEBSHELL_ASPX_Regeorg_CSHARP
{
    meta:
        description = "Webshell regeorg aspx c# version"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://github.com/sensepost/reGeorg"
        hash = "c1f43b7cf46ba12cfc1357b17e4f5af408740af7ae70572c9cf988ac50260ce1"
        author = "Arnim Rupp (https://github.com/ruppde)"
        score = 75
        date = "2021/01/11"
        modified = "2023-07-05"
        hash = "479c1e1f1c263abe339de8be99806c733da4e8c1"
        hash = "38a1f1fc4e30c0b4ad6e7f0e1df5a92a7d05020b"
        hash = "e54f1a3eab740201feda235835fc0aa2e0c44ba9"
        hash = "aea0999c6e5952ec04bf9ee717469250cddf8a6f"

        id = "0a53d368-5f1b-55b7-b08f-36b0f8c5612f"
    strings:
        $input_sa1 = "Request.QueryString.Get" fullword nocase wide ascii
        $input_sa2 = "Request.Headers.Get" fullword nocase wide ascii
        $sa1 = "AddressFamily.InterNetwork" fullword nocase wide ascii
        $sa2 = "Response.AddHeader" fullword nocase wide ascii
        $sa3 = "Request.InputStream.Read" nocase wide ascii
        $sa4 = "Response.BinaryWrite" nocase wide ascii
        $sa5 = "Socket" nocase wide ascii
        $georg = "Response.Write(\"Georg says, 'All seems fine'\")"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 300KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( $georg or
        ( all of ( $sa* ) and any of ( $input_sa* ) ) )
}

rule WEBSHELL_CSHARP_Generic
{
    meta:
        description = "Webshell in c#"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "b6721683aadc4b4eba4f081f2bc6bc57adfc0e378f6d80e2bfa0b1e3e57c85c7"
        date = "2021/01/11"
        modified = "2023-07-05"
        hash = "4b365fc9ddc8b247a12f4648cd5c91ee65e33fae"
        hash = "019eb61a6b5046502808fb5ab2925be65c0539b4"
        hash = "620ee444517df8e28f95e4046cd7509ac86cd514"
        hash = "a91320483df0178eb3cafea830c1bd94585fc896"

        id = "6d38a6b0-b1d2-51b0-9239-319f1fea7cae"
    strings:
        $input_http = "Request." nocase wide ascii
        $input_form1 = "<asp:" nocase wide ascii
        $input_form2 = ".text" nocase wide ascii
        $exec_proc1 = "new Process" nocase wide ascii
        $exec_proc2 = "start(" nocase wide ascii
        $exec_shell1 = "cmd.exe" nocase wide ascii
        $exec_shell2 = "powershell.exe" nocase wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and filesize < 300KB and
        ( $input_http or all of ( $input_form* ) ) and all of ( $exec_proc* ) and any of ( $exec_shell* )
}

rule WEBSHELL_ASP_Runtime_Compile : FILE {
    meta:
        description = "ASP webshell compiling payload in memory at runtime, e.g. sharpyshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "https://github.com/antonioCoco/SharPyShell"
        date = "2021/01/11"
        modified = "2023-04-05"
        score = 75
        hash = "e826c4139282818d38dcccd35c7ae6857b1d1d01"
        hash = "e20e078d9fcbb209e3733a06ad21847c5c5f0e52"
        hash = "57f758137aa3a125e4af809789f3681d1b08ee5b"
        hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
        hash = "e44058dd1f08405e59d411d37d2ebc3253e2140385fa2023f9457474031b48ee"
        hash = "f6092ab5c8d491ae43c9e1838c5fd79480055033b081945d16ff0f1aaf25e6c7"
        hash = "dfd30139e66cba45b2ad679c357a1e2f565e6b3140a17e36e29a1e5839e87c5e"
        hash = "89eac7423dbf86eb0b443d8dd14252b4208e7462ac2971c99f257876388fccf2"
        hash = "8ce4eaf111c66c2e6c08a271d849204832713f8b66aceb5dadc293b818ccca9e"
        id = "5da9318d-f542-5603-a111-5b240f566d47"
    strings:
        $payload_reflection1 = "System" fullword nocase wide ascii
        $payload_reflection2 = "Reflection" fullword nocase wide ascii
        $payload_reflection3 = "Assembly" fullword nocase wide ascii
        $payload_load_reflection1 = /[."']Load\b/ nocase wide ascii
        // only match on "load" or variable which might contain "load"
        $payload_load_reflection2 = /\bGetMethod\(("load|\w)/ nocase wide ascii
        $payload_compile1 = "GenerateInMemory" nocase wide ascii
        $payload_compile2 = "CompileAssemblyFromSource" nocase wide ascii
        $payload_invoke1 = "Invoke" fullword nocase wide ascii
        $payload_invoke2 = "CreateInstance" fullword nocase wide ascii
        $payload_xamlreader1 = "XamlReader" fullword nocase wide ascii
        $payload_xamlreader2 = "Parse" fullword nocase wide ascii
        $payload_xamlreader3 = "assembly=" nocase wide ascii
        $payload_powershell1 = "PSObject" fullword nocase wide ascii
        $payload_powershell2 = "Invoke" fullword nocase wide ascii
        $payload_powershell3 = "CreateRunspace" fullword nocase wide ascii
        $rc_fp1 = "Request.MapPath"
        $rc_fp2 = "<body><mono:MonoSamplesHeader runat=\"server\"/>" wide ascii

        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_input4 = "\\u0065\\u0071\\u0075" wide ascii // equ of Request
        $asp_input5 = "\\u0065\\u0073\\u0074" wide ascii // est of Request
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        $sus_refl1 = " ^= " wide ascii
        $sus_refl2 = "SharPy" wide ascii

    condition:
        //any of them or
        (
            (
                filesize < 50KB and
                any of ( $sus_refl* )
            ) or
            filesize < 10KB
        ) and
        (
                any of ( $asp_input* ) or
            (
                $asp_xml_http and
                any of ( $asp_xml_method* )
            ) or
            (
                any of ( $asp_form* ) and
                any of ( $asp_text* ) and
                $asp_asp
            )
        )
        and not any of ( $rc_fp* ) and
        (
            (
                all of ( $payload_reflection* ) and
                any of ( $payload_load_reflection* )
            )
            or
            (
                all of ( $payload_compile* ) and
                any of ( $payload_invoke* )
            )
            or all of ( $payload_xamlreader* )
            or all of ( $payload_powershell* )
        )
}

rule WEBSHELL_ASP_SQL
{
    meta:
        description = "ASP webshell giving SQL access. Might also be a dual use tool."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "216c1dd950e0718e35bc4834c5abdc2229de3612"
        hash = "ffe44e9985d381261a6e80f55770833e4b78424bn"
        hash = "3d7cd32d53abc7f39faed133e0a8f95a09932b64"
        hash = "f19cc178f1cfad8601f5eea2352cdbd2d6f94e7e"
        hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"

        id = "e534dcb9-40ab-544f-ae55-89fb21c422e9"
    strings:
        $sql1 = "SqlConnection" fullword wide ascii
        $sql2 = "SQLConnection" fullword wide ascii
        $sql3 = "System" fullword wide ascii
        $sql4 = "Data" fullword wide ascii
        $sql5 = "SqlClient" fullword wide ascii
        $sql6 = "SQLClient" fullword wide ascii
        $sql7 = "Open" fullword wide ascii
        $sql8 = "SqlCommand" fullword wide ascii
        $sql9 = "SQLCommand" fullword wide ascii

        $o_sql1 = "SQLOLEDB" fullword wide ascii
        $o_sql2 = "CreateObject" fullword wide ascii
        $o_sql3 = "open" fullword wide ascii

        $a_sql1 = "ADODB.Connection" fullword wide ascii
        $a_sql2 = "adodb.connection" fullword wide ascii
        $a_sql3 = "CreateObject" fullword wide ascii
        $a_sql4 = "createobject" fullword wide ascii
        $a_sql5 = "open" fullword wide ascii

        $c_sql1 = "System.Data.SqlClient" fullword wide ascii
        $c_sql2 = "sqlConnection" fullword wide ascii
        $c_sql3 = "open" fullword wide ascii

        $sus1 = "shell" fullword nocase wide ascii
        $sus2 = "xp_cmdshell" fullword nocase wide ascii
        $sus3 = "aspxspy" fullword nocase wide ascii
        $sus4 = "_KillMe" wide ascii
        $sus5 = "cmd.exe" fullword wide ascii
        $sus6 = "cmd /c" fullword wide ascii
        $sus7 = "net user" fullword wide ascii
        $sus8 = "\\x2D\\x3E\\x7C" wide ascii
        $sus9 = "Hacker" fullword wide ascii
        $sus10 = "hacker" fullword wide ascii
        $sus11 = "HACKER" fullword wide ascii
        $sus12 = "webshell" wide ascii
        $sus13 = "equest[\"sql\"]" wide ascii
        $sus14 = "equest(\"sql\")" wide ascii
        $sus15 = { e5 bc 80 e5 a7 8b e5 af bc e5 }
        $sus16 = "\"sqlCommand\"" wide ascii
        $sus17 = "\"sqlcommand\"" wide ascii

        //$slightly_sus1 = "select * from " wide ascii
        //$slightly_sus2 = "SELECT * FROM " wide ascii
        $slightly_sus3 = "SHOW COLUMNS FROM " wide ascii
        $slightly_sus4 = "show columns from " wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and
        ( 6 of ( $sql* ) or all of ( $o_sql* ) or 3 of ( $a_sql* ) or all of ( $c_sql* ) ) and
        ( ( filesize < 150KB and any of ( $sus* ) ) or
        ( filesize < 5KB and any of ( $slightly_sus* ) ) )
}

rule WEBSHELL_ASP_Scan_Writable
{
    meta:
        description = "ASP webshell searching for writable directories (to hide more webshells ...)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-04-05"
        hash = "2409eda9047085baf12e0f1b9d0b357672f7a152"
        hash = "af1c00696243f8b062a53dad9fb8b773fa1f0395631ffe6c7decc42c47eedee7"

        id = "1766e081-0591-59ab-b546-b13207764b4d"
    strings:
        $scan1 = "DirectoryInfo" nocase fullword wide ascii
        $scan2 = "GetDirectories" nocase fullword wide ascii
        $scan3 = "Create" nocase fullword wide ascii
        $scan4 = "File" nocase fullword wide ascii
        $scan5 = "System.IO" nocase fullword wide ascii
        // two methods: check permissions or write and delete:
        $scan6 = "CanWrite" nocase fullword wide ascii
        $scan7 = "Delete" nocase fullword wide ascii


        $sus1 = "upload" nocase fullword wide ascii
        $sus2 = "shell" nocase wide ascii
        $sus3 = "orking directory" nocase fullword wide ascii
        $sus4 = "scan" nocase wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        filesize < 10KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and 6 of ( $scan* ) and any of ( $sus* )
}

rule WEBSHELL_JSP_ReGeorg
{
    meta:
        description = "Webshell regeorg JSP version"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://github.com/sensepost/reGeorg"
        hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/24"
        modified = "2024-12-09"
        score = 75
        hash = "650eaa21f4031d7da591ebb68e9fc5ce5c860689"
        hash = "00c86bf6ce026ccfaac955840d18391fbff5c933"
        hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
        hash = "9108a33058aa9a2fb6118b719c5b1318f33f0989"

        id = "cbb90005-d8f8-5c64-85d1-29e466f48c25"
    strings:
        $jgeorg1 = "request" fullword wide ascii
        $jgeorg2 = "getHeader" fullword wide ascii
        $jgeorg3 = "X-CMD" fullword wide ascii
        $jgeorg4 = "X-STATUS" fullword wide ascii
        $jgeorg5 = "socket" fullword wide ascii
        $jgeorg6 = "FORWARD" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        filesize < 300KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and all of ( $jgeorg* )
}

rule WEBSHELL_JSP_HTTP_Proxy
{
    meta:
        description = "Webshell JSP HTTP proxy"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        hash = "2f9b647660923c5262636a5344e2665512a947a4"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "97c1e2bf7e769d3fc94ae2fc74ac895f669102c6"
        hash = "2f9b647660923c5262636a5344e2665512a947a4"

        id = "55be246e-30a8-52ed-bc5f-507e63bbfe16"
    strings:
        $jh1 = "OutputStream" fullword wide ascii
        $jh2 = "InputStream"  wide ascii
        $jh3 = "BufferedReader" fullword wide ascii
        $jh4 = "HttpRequest" fullword wide ascii
        $jh5 = "openConnection" fullword wide ascii
        $jh6 = "getParameter" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        filesize < 10KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and all of ( $jh* )
}

rule WEBSHELL_JSP_Writer_Nano
{
    meta:
        description = "JSP file writer"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "ac91e5b9b9dcd373eaa9360a51aa661481ab9429"
        hash = "c718c885b5d6e29161ee8ea0acadb6e53c556513"
        hash = "9f1df0249a6a491cdd5df598d83307338daa4c43"
        hash = "5e241d9d3a045d3ade7b6ff6af6c57b149fa356e"

        id = "422a18f2-d6d4-5b42-be15-1eafe44e01cf"
    strings:
        // writting file to disk
        $payload1 = ".write" wide ascii
        $payload2 = "getBytes" fullword wide ascii
        $payload3 = ".decodeBuffer" wide ascii
        $payload4 = "FileOutputStream" fullword wide ascii

        // writting using java logging, e.g 9f1df0249a6a491cdd5df598d83307338daa4c43
        $logger1 = "getLogger" fullword ascii wide
        $logger2 = "FileHandler" fullword ascii wide
        $logger3 = "addHandler" fullword ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        $jw_sus1 = /getParameter\("."\)/ ascii wide // one char param
        $jw_sus4 = "yoco" fullword ascii wide // webshell coder

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        //any of them or
        (
            any of ( $input* ) and
            any of ( $req* )
        ) and (
            filesize < 200 or
            (
                filesize < 1000 and
                any of ( $jw_sus* )
            )
        )
        and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            2 of ( $payload* ) or
            all of ( $logger* )
            )
}

rule WEBSHELL_JSP_Generic
{
    meta:
        description = "Generic JSP webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2024-12-09"
        hash = "4762f36ca01fb9cda2ab559623d2206f401fc0b1"
        hash = "bdaf9279b3d9e07e955d0ce706d9c42e4bdf9aa1"
        hash = "ee9408eb923f2d16f606a5aaac7e16b009797a07"

        id = "7535ade8-fc65-5558-a72c-cc14c3306390"
    strings:
        $susp0 = "cmd" fullword nocase ascii wide
        $susp1 = "command" fullword nocase ascii wide
        $susp2 = "shell" fullword nocase ascii wide
        $susp3 = "download" fullword nocase ascii wide
        $susp4 = "upload" fullword nocase ascii wide
        $susp5 = "Execute" fullword nocase ascii wide
        $susp6 = "\"pwd\"" ascii wide
        $susp7 = "\"</pre>" ascii wide
        $susp8 = /\\u00\d\d\\u00\d\d\\u00\d\d\\u00\d\d/ ascii wide
        $susp9 = "*/\\u00" ascii wide // perfect match of 2 obfuscation methods: /**/\u00xx :)

        $fp1 = "command = \"cmd.exe /c set\";"

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii wide
        $payload2 = "processCmd" fullword ascii wide
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii wide
        $rt_payload2 = "getRuntime" fullword ascii wide
        $rt_payload3 = "exec" fullword ascii wide

    condition:
        filesize < 300KB and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and (
        1 of ( $payload* ) or
        all of ( $rt_payload* )
        )
        and not any of ( $fp* ) and any of ( $susp* )
}

rule WEBSHELL_JSP_Generic_Base64
{
    meta:
        description = "Generic JSP webshell with base64 encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "8b5fe53f8833df3657ae2eeafb4fd101c05f0db0"
        hash = "1b916afdd415dfa4e77cecf47321fd676ba2184d"

        id = "2eabbad2-7d10-573a-9120-b9b763fa2352"
    strings:
        // Runtime
        $one1 = "SdW50aW1l" wide ascii
        $one2 = "J1bnRpbW" wide ascii
        $one3 = "UnVudGltZ" wide ascii
        $one4 = "IAdQBuAHQAaQBtAGUA" wide ascii
        $one5 = "SAHUAbgB0AGkAbQBlA" wide ascii
        $one6 = "UgB1AG4AdABpAG0AZQ" wide ascii
        // exec
        $two1 = "leGVj" wide ascii
        $two2 = "V4ZW" wide ascii
        $two3 = "ZXhlY" wide ascii
        $two4 = "UAeABlAGMA" wide ascii
        $two5 = "lAHgAZQBjA" wide ascii
        $two6 = "ZQB4AGUAYw" wide ascii
        // ScriptEngineFactory
        $three1 = "TY3JpcHRFbmdpbmVGYWN0b3J5" wide ascii
        $three2 = "NjcmlwdEVuZ2luZUZhY3Rvcn" wide ascii
        $three3 = "U2NyaXB0RW5naW5lRmFjdG9ye" wide ascii
        $three4 = "MAYwByAGkAcAB0AEUAbgBnAGkAbgBlAEYAYQBjAHQAbwByAHkA" wide ascii
        $three5 = "TAGMAcgBpAHAAdABFAG4AZwBpAG4AZQBGAGEAYwB0AG8AcgB5A" wide ascii
        $three6 = "UwBjAHIAaQBwAHQARQBuAGcAaQBuAGUARgBhAGMAdABvAHIAeQ" wide ascii


        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and filesize < 300KB and
        ( any of ( $one* ) and any of ( $two* ) or any of ( $three* ) )
}

rule WEBSHELL_JSP_Generic_ProcessBuilder
{
    meta:
        description = "Generic JSP webshell which uses processbuilder to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "82198670ac2072cd5c2853d59dcd0f8dfcc28923"
        hash = "c05a520d96e4ebf9eb5c73fc0fa446ceb5caf343"
        hash = "347a55c174ee39ec912d9107e971d740f3208d53af43ea480f502d177106bbe8"
        hash = "d0ba29b646274e8cda5be1b940a38d248880d9e2bba11d994d4392c80d6b65bd"

        id = "2a7c5f44-24a1-5f43-996e-945c209b79b1"
    strings:
        $exec = "ProcessBuilder" fullword wide ascii
        $start = "start" fullword wide ascii

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 2000 and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and $exec and $start
}

rule WEBSHELL_JSP_Generic_Reflection
{
    meta:
        description = "Generic JSP webshell which uses reflection to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2024-12-09"
        hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"
        hash = "bf0ff88cbb72c719a291c722ae3115b91748d5c4920afe7a00a0d921d562e188"

        id = "806ffc8b-1dc8-5e28-ae94-12ad3fee18cd"
    strings:
        $ws_exec = "invoke" fullword wide ascii
        $ws_class = "Class" fullword wide ascii
        $fp1 = "SOAPConnection"
        $fp2 = "/CORBA/"

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        $cj_encoded1 = "\"java.util.Base64$Decoder\"" ascii wide
    condition:
        //any of them or
        all of ( $ws_* ) and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and not any of ( $fp* ) and
        (
            // either some kind of code input from the a web request ...
            filesize < 10KB and
            (
                any of ( $input* ) and
                any of ( $req* )
            )
            or
            (
                // ... or some encoded payload (which might get code input from a web request)
                filesize < 30KB and
                any of ( $cj_encoded* ) and
                // base64 :
                // ignore first and last 500bytes because they usually contain code for decoding and executing
                math.entropy(500, filesize-500) >= 5.5 and
                // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                math.mean(500, filesize-500) > 80 and
                // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                // 89 is the mean of the base64 chars
                math.deviation(500, filesize-500, 89.0) < 23
            )
        )

}

rule WEBSHELL_JSP_Generic_Classloader
{
    meta:
        description = "Generic JSP webshell which uses classloader to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "6b546e78cc7821b63192bb8e087c133e8702a377d17baaeb64b13f0dd61e2347"
        date = "2021/01/07"
        modified = "2024-12-09"
        hash = "f3a7e28e1c38fa5d37811bdda1d6b0893ab876023d3bd696747a35c04141dcf0"
        hash = "8ea2a25344e6094fa82dfc097bbec5f1675f6058f2b7560deb4390bcbce5a0e7"
        hash = "b9ea1e9f91c70160ee29151aa35f23c236d220c72709b2b75123e6fa1da5c86c"
        hash = "80211c97f5b5cd6c3ab23ae51003fd73409d273727ba502d052f6c2bd07046d6"
        hash = "8e544a5f0c242d1f7be503e045738369405d39731fcd553a38b568e0889af1f2"

        id = "037e6b24-9faf-569b-bb52-dbe671ab2e87"
    strings:
        $exec = "extends ClassLoader" wide ascii
        $class = "defineClass" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        //any of them or
        (
            (
                $cjsp_short1 at 0 or
                    any of ( $cjsp_long* ) or
                    ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
                (
                    $cjsp_short2 and (
                        $cjsp_short1 in ( 0..1000 ) or
                        $cjsp_short1 in ( filesize-1000..filesize )
                    )
                )
            )
            and (
                any of ( $input* ) and
                any of ( $req* )
            )
            and $exec and $class
        ) and
        (
            filesize < 10KB or
            (
                filesize < 50KB and
                (
                    // filled with same characters
                    math.entropy(500, filesize-500) <= 1 or
                    // filled with random garbage
                    math.entropy(500, filesize-500) >= 7.7
                )
            )
        )
}

rule WEBSHELL_JSP_Generic_Encoded_Shell
{
    meta:
        description = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "3eecc354390d60878afaa67a20b0802ce5805f3a9bb34e74dd8c363e3ca0ea5c"
        hash = "f6c2112e3a25ec610b517ff481675b2ce893cb9f"
        hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"

        id = "359949d7-1793-5e13-9fdc-fe995ae12117"
    strings:
        $sj0 = /\{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ wide ascii
        $sj1 = /\{ ?99, 109, 100}/ wide ascii
        $sj2 = /\{ ?99, 109, 100, 46, 101, 120, 101/ wide ascii
        $sj3 = /\{ ?47, 98, 105, 110, 47, 98, 97/ wide ascii
        $sj4 = /\{ ?106, 97, 118, 97, 46, 108, 97, 110/ wide ascii
        $sj5 = /\{ ?101, 120, 101, 99 }/ wide ascii
        $sj6 = /\{ ?103, 101, 116, 82, 117, 110/ wide ascii

    condition:
        filesize <300KB and any of ($sj*)
}

rule WEBSHELL_JSP_NetSpy
{
    meta:
        description = "JSP netspy webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "94d1aaabde8ff9b4b8f394dc68caebf981c86587"
        hash = "3870b31f26975a7cb424eab6521fc9bffc2af580"

        id = "41f5c171-878d-579f-811d-91d74f7e3e24"
    strings:
        $scan1 = "scan" nocase wide ascii
        $scan2 = "port" nocase wide ascii
        $scan3 = "web" fullword nocase wide ascii
        $scan4 = "proxy" fullword nocase wide ascii
        $scan5 = "http" fullword nocase wide ascii
        $scan6 = "https" fullword nocase wide ascii
        $write1 = "os.write" fullword wide ascii
        $write2 = "FileOutputStream" fullword wide ascii
        $write3 = "PrintWriter" fullword wide ascii
        $http = "java.net.HttpURLConnection" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 30KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and 4 of ( $scan* ) and 1 of ( $write* ) and $http
}

rule WEBSHELL_JSP_By_String
{
    meta:
        description = "JSP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/09"
        modified = "2024-12-09"
        hash = "e9060aa2caf96be49e3b6f490d08b8a996c4b084"
        hash = "4c2464503237beba54f66f4a099e7e75028707aa"
        hash = "06b42d4707e7326aff402ecbb585884863c6351a"
        hash = "dada47c052ec7fcf11d5cfb25693bc300d3df87de182a254f9b66c7c2c63bf2e"
        hash = "f9f6c696c1f90df6421cd9878a1dec51a62e91b4b4f7eac4920399cb39bc3139"
        hash = "f1d8360dc92544cce301949e23aad6eb49049bacf9b7f54c24f89f7f02d214bb"
        hash = "1d1f26b1925a9d0caca3fdd8116629bbcf69f37f751a532b7096a1e37f4f0076"
        hash = "850f998753fde301d7c688b4eca784a045130039512cf51292fcb678187c560b"

        id = "8d64e40b-5583-5887-afe1-b926d9880913"
    strings:
        $jstring1 = "<title>Boot Shell</title>" wide ascii
        $jstring2 = "String oraPWD=\"" wide ascii
        $jstring3 = "Owned by Chinese Hackers!" wide ascii
        $jstring4 = "AntSword JSP" wide ascii
        $jstring5 = "JSP Webshell</" wide ascii
        $jstring6 = "motoME722remind2012" wide ascii
        $jstring7 = "EC(getFromBase64(toStringHex(request.getParameter(\"password" wide ascii
        $jstring8 = "http://jmmm.com/web/index.jsp" wide ascii
        $jstring9 = "list.jsp = Directory & File View" wide ascii
        $jstring10 = "jdbcRowSet.setDataSourceName(request.getParameter(" wide ascii
        $jstring11 = "Mr.Un1k0d3r RingZer0 Team" wide ascii
        $jstring12 = "MiniWebCmdShell" fullword wide ascii
        $jstring13 = "pwnshell.jsp" fullword wide ascii
        $jstring14 = "session set &lt;key&gt; &lt;value&gt; [class]<br>"  wide ascii
        $jstring15 = "Runtime.getRuntime().exec(request.getParameter(" nocase wide ascii
        $jstring16 = "GIF98a<%@page" wide ascii
        $jstring17 = "Tas9er" fullword wide ascii
        $jstring18 = "uu0028\\u" wide ascii //obfuscated /
        $jstring19 = "uu0065\\u" wide ascii //obfuscated e
        $jstring20 = "uu0073\\u" wide ascii //obfuscated s
        $jstring21 = /\\uuu{0,50}00/ wide ascii //obfuscated via javas unlimited amount of u in \uuuuuu
        $jstring22 = /[\w\.]\\u(FFFB|FEFF|FFF9|FFFA|200C|202E|202D)[\w\.]/ wide ascii // java ignores the unicode Interlinear Annotation Terminator inbetween any command
        $jstring23 = "\"e45e329feb5d925b\"" wide ascii
        $jstring24 = "u<![CDATA[n" wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        //any of them or
        not (
            uint16(0) == 0x5a4d or
            $dex at 0 or
            $pack at 0 or
            // fp on jar with zero compression
            uint16(0) == 0x4b50
        ) and
        (
            (
                filesize < 100KB and
                (
                    $cjsp_short1 at 0 or
                    any of ( $cjsp_long* ) or
                    ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
                    (
                        $cjsp_short2 and (
                            $cjsp_short1 in ( 0..1000 ) or
                            $cjsp_short1 in ( filesize-1000..filesize )
                        )
                    )
                )
                and any of ( $jstring* )
            ) or (
                filesize < 500KB and
                (
                    #jstring21 > 20 or
                    $jstring18 or
                    $jstring19 or
                    $jstring20

                )
            )
        )
}

rule WEBSHELL_JSP_Input_Upload_Write
{
    meta:
        description = "JSP uploader which gets input, writes files and contains \"upload\""
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2024-12-09"
        hash = "ef98ca135dfb9dcdd2f730b18e883adf50c4ab82"
        hash = "583231786bc1d0ecca7d8d2b083804736a3f0a32"
        hash = "19eca79163259d80375ebebbc440b9545163e6a3"

        id = "bbf26edd-88b7-5ec5-a16e-d96a086dcd19"
    strings:
        $upload = "upload" nocase wide ascii
        $write1 = "os.write" fullword wide ascii
        $write2 = "FileOutputStream" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 10KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and $upload and 1 of ( $write* )
}

rule WEBSHELL_Generic_OS_Strings : FILE {
    meta:
        description = "typical webshell strings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/12"
        modified = "2024-12-09"
        score = 50
        hash = "d5bfe40283a28917fcda0cefd2af301f9a7ecdad"
        hash = "fd45a72bda0a38d5ad81371d68d206035cb71a14"
        hash = "b4544b119f919d8cbf40ca2c4a7ab5c1a4da73a3"
        hash = "569259aafe06ba3cef9e775ee6d142fed6edff5f"
        hash = "48909d9f4332840b4e04b86f9723d7427e33ac67"
        hash = "0353ae68b12b8f6b74794d3273967b530d0d526f"
        id = "ea85e415-4774-58ac-b063-0f5eb535ec49"
    strings:
        $fp1 = "http://evil.com/" wide ascii
        $fp2 = "denormalize('/etc/shadow" wide ascii
      $fp3 = "vim.org>"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_os_strings
        // windows = nocase
        $w1 = "net localgroup administrators" nocase wide ascii
        $w2 = "net user" nocase wide ascii
        $w3 = "/add" nocase wide ascii
        // linux stuff, case sensitive:
        $l1 = "/etc/shadow" wide ascii
        $l2 = "/etc/ssh/sshd_config" wide ascii
        $take_two1 = "net user" nocase wide ascii
        $take_two2 = "/add" nocase wide ascii

    condition:
        filesize < 70KB and
        ( (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        or (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        or (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            ($cjsp_short1 and $cjsp_short2 in ( filesize-100..filesize )) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        ) and (
            filesize < 300KB and
        not uint16(0) == 0x5a4d and (
            all of ( $w* ) or
            all of ( $l* ) or
            2 of ( $take_two* )
        )
        )
        and not any of ( $fp* )
}

rule WEBSHELL_In_Image
{
    meta:
        description = "Webshell in GIF, PNG or JPG"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        hash = "d4fde4e691db3e70a6320e78657480e563a9f87935af873a99db72d6a9a83c78"
        hash = "84938133ee6e139a2816ab1afc1c83f27243c8ae76746ceb2e7f20649b5b16a4"
        hash = "52b918a64afc55d28cd491de451bb89c57bce424f8696d6a94ec31fb99b17c11"
        date = "2021/02/27"
        modified = "2024-03-11"
        score = 55

        id = "b1185b69-9b08-5925-823a-829fee6fa4cf"
    strings:
        $png = { 89 50 4E 47 }
        $jpg = { FF D8 FF E0 }
        $gif = "GIF8" wide ascii // doesn't make sense for a GIF but some webshells are utf8 :)
        $gif2 = "gif89" // not a valid gif but used in webshells
        $gif3 = "Gif89" // not a valid gif but used in webshells
        // MS access
        $mdb = { 00 01 00 00 53 74 }
        //$mdb = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" wide ascii
        $php_multi_write2 = "fwrite(" wide ascii
        $php_write1 = "move_uploaded_file" fullword wide ascii

        //strings from private rule capa_jsp
        $cjsp1 = "<%" ascii wide
        $cjsp2 = "<jsp:" ascii wide
        $cjsp3 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp4 = "/jstl/core" ascii wide

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii wide
        $payload2 = "processCmd" fullword ascii wide
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii wide
        $rt_payload2 = "getRuntime" fullword ascii wide
        $rt_payload3 = "exec" fullword ascii wide

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

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
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        // reduce fp
        //any of them or
        filesize < 5MB and
        // also check for GIF8 at 0x3 because some folks write their webshell in a text editor and have a BOM in front of GIF8 (which probably wouldn't be a valif GIF anymore :)
        ( $png at 0 or $jpg at 0 or $gif at 0 or $gif at 3 or $gif2 at 0 or $gif2 at 3 or $gif3 at 0 or $mdb at 0 ) and
        ( ( (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and
        ( (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        or (
        any of ( $php_write* ) or
        all of ( $php_multi_write* )
        )
        ) ) or
        ( (
            any of ( $cjsp* )
        )
        and (
        1 of ( $payload* ) or
        all of ( $rt_payload* )
        )
        ) or
        ( (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) ) )
}

rule WEBSHELL_Mixed_OBFUSC {
   meta:
      description = "Detects webshell with mixed obfuscation commands"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "Internal Research"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      date = "2023-01-28"
      modified = "2023-04-05"
      hash1 = "8c4e5c6bdfcc86fa27bdfb075a7c9a769423ec6d53b73c80cbc71a6f8dd5aace"
      hash2 = "78f2086b6308315f5f0795aeaa75544128f14889a794205f5fc97d7ca639335b"
      hash3 = "3bca764d44074820618e1c831449168f220121698a7c82e9909f8eab2e297cbd"
      hash4 = "b26b5e5cba45482f486ff7c75b54c90b7d1957fd8e272ddb4b2488ec65a2936e"
      hash5 = "e217be2c533bfddbbdb6dc6a628e0d8756a217c3ddc083894e07fd3a7408756c"
      score = 50
      id = "dcb4054b-0c87-5cd0-9297-7fd5f2e37437"
   strings:
      $s1 = "rawurldecode/*" ascii
      $s2 = "preg_replace/*" ascii
      $s3 = " __FILE__/*" ascii
      $s4 = "strlen/*" ascii
      $s5 = "str_repeat/*" ascii
      $s6 = "basename/*" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 4 of them ))
}

rule WEBSHELL_Cookie_Post_Obfuscation {
    meta:
        description = "Detects webshell using cookie POST"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2023-01-28"
        modified = "2023-04-05"
        license = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        hash = "d08a00e56feb78b7f6599bad6b9b1d8626ce9a6ea1dfdc038358f4c74e6f65c9"
        hash = "2ce5c4d31682a5a59b665905a6f698c280451117e4aa3aee11523472688edb31"
        hash = "ff732d91a93dfd1612aed24bbb4d13edb0ab224d874f622943aaeeed4356c662"
        hash = "a3b64e9e065602d2863fcab641c75f5d8ec67c8632db0f78ca33ded0f4cea257"
        hash = "d41abce305b0dc9bd3a9feb0b6b35e8e39db9e75efb055d0b1205a9f0c89128e"
        hash = "333560bdc876fb0186fae97a58c27dd68123be875d510f46098fc5a61615f124"
        hash = "2efdb79cdde9396ff3dd567db8876607577718db692adf641f595626ef64d3a4"
        hash = "e1bd3be0cf525a0d61bf8c18e3ffaf3330c1c27c861aede486fd0f1b6930f69a"
        hash = "f8cdedd21b2cc29497896ec5b6e5863cd67cc1a798d929fd32cdbb654a69168a"

        id = "cc5ded80-5e58-5b25-86d1-1c492042c740"
    strings:
        $s1 = "]($_COOKIE, $_POST) as $"
        $s2 = "function"
        $s3 = "Array"
    condition:
    ( uint16(0) == 0x3f3c and filesize < 100KB and ( all of them ))
}