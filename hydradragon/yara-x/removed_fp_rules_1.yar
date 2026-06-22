// 14 false-positive rule(s) removed by false_positive_remover.py

rule spyeye_plugins: banker {
  meta:
    author      = "Jean-Philippe Teissier / @Jipe_"
    description = "SpyEye X.Y Plugins memory"
    date        = "2012-05-23"
    version     = "1.0"
    filetype    = "memory"

  strings:
    $a = "webfakes.dll"
    $b = "config.dat"  //may raise some FP
    $c = "collectors.txt"
    $d = "webinjects.txt"
    $e = "screenshots.txt"
    $f = "billinghammer.dll"
    $g = "block.dll"  //may raise some FP
    $h = "bugreport.dll"  //may raise some FP
    $i = "ccgrabber.dll"
    $j = "connector2.dll"
    $k = "creditgrab.dll"
    $l = "customconnector.dll"
    $m = "ffcertgrabber.dll"
    $n = "ftpbc.dll"
    $o = "rdp.dll"  //may raise some FP
    $p = "rt_2_4.dll"
    $q = "socks5.dll"  //may raise some FP
    $r = "spySpread.dll"
    $s = "w2chek4_4.dll"
    $t = "w2chek4_6.dll"

  condition:
    any of them
}

rule network_ftp {
  meta:
    author      = "x0r"
    description = "Communications over FTP"
    version     = "0.1"

  strings:
    $f1  = "Wininet.dll" nocase
    $c1  = "FtpGetCurrentDirectory"
    $c2  = "FtpGetFile"
    $c3  = "FtpPutFile"
    $c4  = "FtpSetCurrentDirectory"
    $c5  = "FtpOpenFile"
    $c6  = "FtpGetFileSize"
    $c7  = "FtpDeleteFile"
    $c8  = "FtpCreateDirectory"
    $c9  = "FtpRemoveDirectory"
    $c10 = "FtpRenameFile"
    $c11 = "FtpDownload"
    $c12 = "FtpUpload"
    $c13 = "FtpGetDirectory"

  condition:
    $f1 and (4 of ($c*))
}

rule Win_Trojan_Java_98 {
  strings:
    $a0 = "GetWindowsDirectory"

    $a1 = ".exe"

    $a2 = "URLDownloadToFile"

    $a3 = "Runtime"

    $a4 = "exec"

  condition:
    $a0 and $a1 and $a2 and $a3 and $a4
}

rule _ACProtect_13x__14x_DLL__Risco_Software_Inc_ {
  meta:
    description = "ACProtect 1.3x - 1.4x DLL -> Risco Software Inc."

  strings:
    $0 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 ?? BA ?? ?? CD 21 B8 ?? ?? CD 21 }
    $1 = { 80 7C 24 08 01 0F 85 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _UPX_v0896__v102__v105__v122_DLL__Laszlo__Markus_ {
  meta:
    description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 DLL -> Laszlo & Markus"

  strings:
    $0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }

  condition:
    $0 at pe.entry_point
}

rule AtomTable_Inject {
  meta:
    Author      = "Thomas Roccia - @fr0gger_ - Unprotect Project"
    Description = " Detect AtomBombing technique"

  strings:
    $var1 = "GlobalAddAtom"
    $var2 = "GlobalGetAtomName"
    $var3 = "QueueUserAPC"

  condition:
    all of them
}

rule Atom_Bombing {
  meta:
    author      = "McAfee ATR - Thomas Roccia - @fr0gger_ "
    description = "Detect AtomBombing Injection"
    reference   = "https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows"
    mitre_id    = "T1055"

  strings:
    $var1 = "GlobalAddAtom" nocase
    $var2 = "GlobalGetAtomName" nocase
    $var3 = "QueueUserAPC" nocase
    $var4 = "NtQueueApcThread" nocase
    $var5 = "NtSetContextThread" nocase

  condition:
    uint16(0) == 0x5A4D and (all of them or
      pe.imports("Kernel32.dll", "GlobalAddAtom") and
      pe.imports("Kernel32.dll", "GlobalGetAtomName") and
      pe.imports("Kernel32.dll", "QueueUserAPC"))
}

rule APC_Inject {
  meta:
    author      = "McAfee ATR - Thomas Roccia - @fr0gger_ "
    description = "Detect APC Injection"
    mitre_id    = "T1055"

  strings:
    $func1 = "NtQueueApcThread" nocase
    $func2 = "NtResumeThread" nocase
    $func3 = "NTTestAlert" nocase
    $func4 = "QueueUserApc" nocase

  condition:
    uint16(0) == 0x5A4D and ($func1 and $func2 or all of them)
}

rule CTRL_Inject {
  meta:
    author      = "McAfee ATR - Thomas Roccia - @fr0gger_ "
    description = "Detect Control Inject"
    reference   = "https://blog.ensilo.com/ctrl-inject"
    mitre_id    = "T1055"

  strings:
    $func1 = "OpenProcess" nocase
    $func2 = "VirtualAllocEx" nocase
    $func3 = "WriteProcessMemory" nocase
    $func4 = "EncodePointer" nocase
    $func5 = "EncodeRemotePointer" nocase
    $func6 = "SetProcessValidCallTargets" nocase

  condition:
    uint16(0) == 0x5A4D and ($func1 and $func2 and ($func4 or $func5) and $func6 or (all of them))

}

rule upx_dll {
  meta:
    author      = "PEiD"
    description = "UPX 0.80 - 1.24 DLL -> Markus & Laszlo"
    group       = "183"
    function    = "0"

  strings:
    $a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }

  condition:
    $a0 at pe.entry_point
}

rule upx_dll2 {
  meta:
    author      = "PEiD"
    description = "UPX 0.80 - 1.24 DLL -> Markus & Laszlo"
    group       = "BoB"
    function    = "0"

  strings:
    $a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB }

  condition:
    $a0
}

rule MASM {
  meta:
    author = "_pusher_"
    date   = "2016-08"
    linker = "5.12"
  //drop linker checks and allow collissions ? :\

  condition:
    (pe.rich_signature.version(8078) and pe.rich_signature.version(8444) and pe.rich_signature.toolid(19))
    or  //and ((pe.linker_version.major == 5) and (pe.linker_version.minor == 12 ) or (pe.linker_version.major == 12) and (pe.linker_version.minor == 0 ) ) or
    (pe.rich_signature.version(8078) and pe.rich_signature.version(30319) and pe.rich_signature.toolid(19))
    or  //and (pe.linker_version.major == 5) and (pe.linker_version.minor == 12 ) or
    (pe.rich_signature.version(1735) and pe.rich_signature.version(8803) and pe.rich_signature.toolid(6))
    or
    (pe.rich_signature.version(1735) and pe.rich_signature.version(8444) and pe.rich_signature.toolid(6) and not pe.rich_signature.version(9782))

    or
    pe.rich_signature.version(1735) and pe.rich_signature.version(8447) and pe.rich_signature.toolid(6) and not ((pe.rich_signature.version(8168) and not pe.rich_signature.version(9782)))

    or  //and (pe.linker_version.major == 5) and (pe.linker_version.minor == 12 ) or
    (pe.rich_signature.version(1735) and pe.rich_signature.version(8078) and pe.rich_signature.toolid(19))
    or
    //this one causes trouble: //does not with 9782 check
    (pe.rich_signature.version(8444) and pe.rich_signature.toolid(18) and not pe.rich_signature.version(30319) and not pe.rich_signature.version(9782))

    //or //and ((pe.linker_version.major == 5) and (pe.linker_version.minor == 12 )) 
    or
    (pe.rich_signature.version(7274) and pe.rich_signature.version(9049) and pe.rich_signature.toolid(19))
}

rule MALWARE_Win_RDPCredsStealer {
    meta:
        author = "ditekSHen"
        description = "Detects RDP Credentials Stealer"
        clamav1 = "MALWARE.Win.Trojan.RDPCredsStealer"
    strings:
        $x1 = "MyCredUnPackAuthenticationBufferW Hooked Function" ascii
        $x2 = "\\RDPCredsStealerDLL\\" ascii
        $x3 = "\\RDPCreds.txt" ascii
        $s1 = "CredUnPackAuthenticationBufferW" ascii
        $s2 = "Installing Hooked Function" ascii
        $s3 = "SymLoadModule64" fullword ascii
        $s4 = "memmove" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and 2 of ($s*)) or 3 of ($s*))
}

rule Linux_Exploit_Dirtycow_8555f149 {
  meta:
    author           = "Elastic Security"
    id               = "8555f149-0c91-4384-9199-8250c0fd74fd"
    fingerprint      = "3d607c7ba6667c375eaab454debf8745746230d08a00499395a275e5bd05b3e4"
    creation_date    = "2021-04-06"
    last_modified    = "2021-09-16"
    threat_name      = "Linux.Exploit.Dirtycow"
    reference_sample = "0fd66e120f97100e48c65322b946b812fa9df4cfb533fb327760a999e4d43945"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $a = { 83 45 F8 01 81 7D F8 FF E0 F5 05 7E ?? 8B 45 }

  condition:
    all of them
}

rule Linux_Exploit_Lotoor_f8e9f93c {
  meta:
    author           = "Elastic Security"
    id               = "f8e9f93c-78ad-4ca5-a210-e62072e6f8c8"
    fingerprint      = "bdf87b68d1101cd3fcbc505de0d2e9b2aed9535aaafa9f746f7a3c4fba03b464"
    creation_date    = "2021-04-06"
    last_modified    = "2021-09-16"
    threat_name      = "Linux.Exploit.Lotoor"
    reference_sample = "50a6d546d4c45dc33c5ece3c09dbc850b469b9b8deeb7181a45ba84459cb24c9"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $a = { 61 ?? 3A 20 4C 69 6E 75 78 20 32 2E 36 2E 33 }

  condition:
    all of them
}

rule Linux_Trojan_Pidief_635667d1 {
  meta:
    author           = "Elastic Security"
    id               = "635667d1-4b51-4e18-9e6b-5873194ce4f1"
    fingerprint      = "29e1795f941990ca18fbe61154d3cfe23d43d13af298e763cd40fb9c40d7204e"
    creation_date    = "2021-01-12"
    last_modified    = "2021-09-16"
    threat_name      = "Linux.Trojan.Pidief"
    reference_sample = "e27ad676ae12188de7a04a3781aa487c11bab01d7848705bac5010d2735b19cf"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $a = { 06 4C 89 F7 FF 50 10 48 8B 45 00 48 89 EF FF 50 10 85 DB 75 15 4D }

  condition:
    all of them
}

rule Linux_Trojan_Torii_fa253f2a {
  meta:
    author           = "Elastic Security"
    id               = "fa253f2a-d1a5-48b0-a3d6-aba06231e1ed"
    fingerprint      = "fddf2a12f09add31fffc6b11bb3fe9e0666dae57ac8cef4dbbdee58f66df2c0a"
    creation_date    = "2022-01-05"
    last_modified    = "2022-01-26"
    threat_name      = "Linux.Trojan.Torii"
    reference_sample = "19004f250b578b3b53273e8426285df2030fac0aee3227ef98e7fcbf2a8acb86"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $a = { 69 6D 65 00 47 4C 49 42 43 5F 32 2E 31 34 00 47 4C 49 42 43 5F }

  condition:
    all of them
}

rule Linux_Trojan_Tsunami_47f93be2 {
  meta:
    author           = "Elastic Security"
    id               = "47f93be2-687c-42d2-9627-29f114beb234"
    fingerprint      = "f4a2262cfa0f0db37e15149cf33e639fd2cd6d58f4b89efe7860f73014b47c4e"
    creation_date    = "2021-01-12"
    last_modified    = "2021-09-16"
    threat_name      = "Linux.Trojan.Tsunami"
    reference_sample = "2e4f89c76dfefd4b2bfd1cf0467ac0324026355723950d12d7ed51195fd998cf"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "linux"

  strings:
    $a = { FA 48 63 C6 48 89 94 C5 70 FF FF FF 8B 85 5C FF FF FF 8D 78 01 48 8D 95 60 FF }

  condition:
    all of them
}

rule MacOS_Cryptominer_Generic_333129b7 {
  meta:
    author           = "Elastic Security"
    id               = "333129b7-8137-4641-bd86-ebcf62257d7b"
    fingerprint      = "baa9e777683d31c27170239752f162799a511bf40269a06a2eab8971fabb098a"
    creation_date    = "2021-09-30"
    last_modified    = "2021-10-25"
    threat_name      = "MacOS.Cryptominer.Generic"
    reference_sample = "bf47d27351d6b0be0ffe1d6844e87fe8f4f4d33ea17b85c11907266d36e4b827"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "macos"

  strings:
    $a = { 6D BF 81 55 D4 4C D4 19 4C 81 18 24 3C 14 3C 30 14 18 26 79 5F 35 5F 4C 35 26 }

  condition:
    all of them
}

rule Windows_Ransomware_Snake_0cfc8ef3: beta {
  meta:
    author        = "Elastic Security"
    id            = "0cfc8ef3-d8cc-4fc0-9ca2-8e84dbcb45bd"
    fingerprint   = "4dd2565c42d52f20b9787a6ede9be24837f6df19dfbbd4e58e5208894741ba26"
    creation_date = "2020-06-30"
    last_modified = "2021-08-23"
    description   = "Identifies SNAKE ransomware"
    threat_name   = "Windows.Ransomware.Snake"
    reference     = "https://labs.sentinelone.com/new-snake-ransomware-adds-itself-to-the-increasing-collection-of-golang-crimeware/"
    severity      = 100
    arch_context  = "x86"
    scan_context  = "file, memory"
    license       = "Elastic License v2"
    os            = "windows"

  strings:
    $d1 = { 96 88 44 2C 1E 96 45 }
    $d2 = { 39 C5 7D ?? 0F B6 34 2B 39 D5 73 ?? 0F B6 3C 29 31 FE 83 FD 1A 72 }

  condition:
    1 of ($d*)
}

rule Windows_Trojan_Donutloader_f40e3759 {
  meta:
    author        = "Elastic Security"
    id            = "f40e3759-2531-4e21-946a-fb55104814c0"
    fingerprint   = "6400b34f762cebb4f91a8d24c5fce647e069a971fb3ec923a63aa98c8cfffab7"
    creation_date = "2021-09-15"
    last_modified = "2022-01-13"
    threat_name   = "Windows.Trojan.Donutloader"
    severity      = 100
    arch_context  = "x86"
    scan_context  = "file, memory"
    license       = "Elastic License v2"
    os            = "windows"

  strings:
    $x64 = { 06 B8 03 40 00 80 C3 4C 8B 49 10 49 }
    $x86 = { 04 75 EE 89 31 F0 FF 46 04 33 C0 EB }

  condition:
    any of them
}

rule Windows_Trojan_Generic_a160ca52 {
  meta:
    author           = "Elastic Security"
    id               = "a160ca52-8911-4649-a1fa-ac8f6f75e18d"
    fingerprint      = "06eca9064ca27784b61994844850f05c47c07ba6c4242a2572d6d0c484a920f0"
    creation_date    = "2022-02-17"
    last_modified    = "2022-04-12"
    threat_name      = "Windows.Trojan.Generic"
    reference_sample = "650bf19e73ac2d9ebbf62f15eeb603c2b4a6a65432c70b87edc429165d6706f3"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a1 = { 1C 85 C9 74 02 8B 09 8D 41 FF 89 45 F0 89 55 EC 8B 55 EC 8B }

  condition:
    all of them
}

rule Windows_Trojan_Lucifer_ce9d4cc8 {
  meta:
    author           = "Elastic Security"
    id               = "ce9d4cc8-8f16-4272-a54b-e500d4edea9b"
    fingerprint      = "77c86dfbbd4fb113dabf6016f22d879322357de8ea4a8a598ce9fba761419c55"
    creation_date    = "2022-02-17"
    last_modified    = "2022-04-12"
    threat_name      = "Windows.Trojan.Lucifer"
    reference_sample = "1c63d83084d84d9269e3ce164c2f28438eadf723d46372064fe509fb08f94c3c"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a = { 00 0A 28 47 00 00 0A 00 DE 02 00 DC 00 28 09 00 00 06 02 6F 48 }

  condition:
    all of them
}

rule Windows_Trojan_Qbot_92c67a6d {
  meta:
    author           = "Elastic Security"
    id               = "92c67a6d-9290-4cd9-8123-7dace2cf333d"
    fingerprint      = "4719993107243a22552b65e6ec8dc850842124b0b9919a6ecaeb26377a1a5ebd"
    creation_date    = "2021-02-16"
    last_modified    = "2021-08-23"
    threat_name      = "Windows.Trojan.Qbot"
    reference_sample = "636e2904276fe33e10cce5a562ded451665b82b24c852cbdb9882f7a54443e02"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a = { 33 C0 59 85 F6 74 2D 83 66 0C 00 40 89 06 6A 20 89 46 04 C7 46 08 08 00 }

  condition:
    all of them
}

rule Windows_Trojan_RedLineStealer_d25e974b {
  meta:
    author           = "Elastic Security"
    id               = "d25e974b-7cf0-4c0e-bf57-056cbb90d77e"
    fingerprint      = "f936511802dcce39dfed9ec898f3ab0c4b822fd38bac4e84d60966c7b791688c"
    creation_date    = "2022-02-17"
    last_modified    = "2022-04-12"
    threat_name      = "Windows.Trojan.RedLineStealer"
    reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a = { 48 43 3F FF 48 42 3F FF 48 42 3F FF 48 42 3E FF 48 42 3E FF }

  condition:
    all of them
}

rule Windows_Trojan_RedLineStealer_ed346e4c {
  meta:
    author           = "Elastic Security"
    id               = "ed346e4c-7890-41ee-8648-f512682fe20e"
    fingerprint      = "834c13b2e0497787e552bb1318664496d286e7cf57b4661e5e07bf1cffe61b82"
    creation_date    = "2022-02-17"
    last_modified    = "2022-04-12"
    threat_name      = "Windows.Trojan.RedLineStealer"
    reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a = { 55 8B EC 8B 45 14 56 57 8B 7D 08 33 F6 89 47 0C 39 75 10 76 15 8B }

  condition:
    all of them
}

rule Windows_Trojan_Remotemanipulator_9ec52153 {
  meta:
    author           = "Elastic Security"
    id               = "9ec52153-3b62-432d-b87c-895035df1a46"
    fingerprint      = "02220e8af70ecffb3a7585f756c59ef5d9e17e6690c36d6bffc458e1d17dbd0c"
    creation_date    = "2021-09-02"
    last_modified    = "2022-01-13"
    threat_name      = "Windows.Trojan.Remotemanipulator"
    reference_sample = "1dd15c830c0a159b53ed21b8c2ce1b7e8093256368d7b96c1347c6851ee6c4f6"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a1 = "killself.bat" wide fullword
    $a2 = "rutserv.exe" wide fullword
    $a3 = "rfusclient.exe" wide fullword
    $a4 = "install.log" wide fullword
    $a5 = "Unable to create Agent's path." wide fullword

  condition:
    all of them
}

rule Windows_Trojan_Smokeloader_3687686f {
  meta:
    author           = "Elastic Security"
    id               = "3687686f-8fbf-4f09-9afa-612ee65dc86c"
    fingerprint      = "0f483f9f79ae29b944825c1987366d7b450312f475845e2242a07674580918bc"
    creation_date    = "2021-07-21"
    last_modified    = "2021-08-23"
    threat_name      = "Windows.Trojan.Smokeloader"
    reference_sample = "8b3014ecd962a335b246f6c70fc820247e8bdaef98136e464b1fdb824031eef7"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a = { 0C 8B 45 F0 89 45 C8 8B 45 C8 8B 40 3C 8B 4D F0 8D 44 01 04 89 }

  condition:
    all of them
}

rule Windows_Trojan_SomniRecord_097e66bd {
  meta:
    author           = "Elastic Security"
    id               = "097e66bd-5ce3-4f05-92f3-ed03719dc60a"
    fingerprint      = "db4896c85b5a8aa75a4ca3f6944041a4548b6998880c689cb7a318023893ff04"
    creation_date    = "2023-03-01"
    last_modified    = "2023-03-20"
    threat_name      = "Windows.Trojan.SomniRecord"
    reference_sample = "54114c23f499738a06fd8b8ab2a8458c03ac8cc81e706702fcd1c64a075e4dcc"
    severity         = 100
    arch_context     = "x86"
    scan_context     = "file, memory"
    license          = "Elastic License v2"
    os               = "windows"

  strings:
    $a    = { 66 81 38 4E 52 75 06 80 78 02 3A 74 34 48 FF C0 4C 8D 47 FE 4C 2B C0 48 8B C8 BA 4E 00 00 00 }
    $str0 = "%s-%s-%s.%s" ascii fullword
    $str1 = "ECM-" ascii fullword
    $str2 = "RESP:" ascii fullword
    $str3 = "PROBE" ascii fullword
    $str4 = "SYS" ascii fullword
    $str5 = "PSL" ascii fullword
    $str6 = "WS-" ascii fullword
    $str7 = "There were no commands" ascii fullword
    $str8 = "String abc = Request.Form" ascii fullword

  condition:
    $a or all of ($str*)
}

rule APT_Turla_IronPython_Jan_2021_1 {
  meta:
    description = "Detect IronPython loader used by Turla Group"
    author      = "Arkbird_SOLG"
    reference   = "https://twitter.com/DrunkBinary/status/1349759986595995653"
    date        = "2021-01-14"
    hash1       = "3aa37559ef282ee3ee67c4a61ce4786e38d5bbe19bdcbeae0ef504d79be752b6"
    hash2       = "8df0c705da0eab20ba977b608f5a19536e53e89b14e4a7863b7fd534bd75fd72"
    hash3       = "b5b4d06e1668d11114b99dbd267cde784d33a3f546993d09ede8b9394d90ebb3"
    hash4       = "b095fd3bd3ed8be178dafe47fc00c5821ea31d3f67d658910610a06a1252f47d"

  strings:
    $lambda = { 3d 6c 61 6d 62 64 61 20 [1-6] 2c [1-6] 3a 27 27 2e 6a 6f 69 6e 28 5b 63 68 72 28 28 6f 72 64 28 [1-6] 29 5e [1-6] 29 25 30 78 [1-4] 29 20 66 6f 72 20 [1-6] 20 69 6e 20 [1-6] 5d 29 0a }  // -> =lambda .,.:''.join([chr((ord(.)^.)%0x.) for . in .])
    $lib1   = "import base64"  // import base64
    $lib2   = "from System.Security.Cryptography"  // from System.Security.Cryptography import*
    $lib3   = "from System.Reflection"  // from System.Reflection import*
    $shcode = /(\w.){6}.(', \d{1,3}\)){1}/ nocase  // \x??\x??\x??', ???)
    $cmd1   = "os.getenv" fullword ascii
    $cmd2   = "except System.SystemException as ex:" fullword ascii
    $cmd3   = ".format(ex.Message,ex.StackTrace))" fullword ascii
    $cmd4   = "return System.Array[System.Byte]([ord(" fullword ascii

  condition:
    filesize > 120KB and $lambda and $shcode and all of ($lib*) and all of ($cmd*)
}

rule APT_DustSquad_PE_Nov19_1 {
  meta:
    description = "Detection Rule for APT DustSquad campaign Nov19"
    author      = "Arkbird_SOLG"
    reference   = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
    date        = "2019-11-29"
    hash1       = "105402dd65ec1c53b6db68a0e21fcee5b72e161bc3b53e644695a4c9fae32909"

  strings:
    $x1  = "The credentials supplied were not complete, and could not be verified. Additional information can be returned from the context.4" wide
    $s2  = "The logon attempt failed;The credentials supplied to the package were not recognized4No credentials are available in the securit" wide
    $s3  = "Address type not supported.\"%s: Circular links are not allowed\"Not enough data in buffer. (%d/%d)" fullword wide
    $s4  = "@TList<System.DateUtils.TLocalTimeZone.TYearlyChanges>.TEmptyFunc" fullword ascii
    $s5  = "Error getting SSL method.%Error setting File Descriptor for SSL!Error binding data to SSL socket.'Maximum number of line allowed" wide
    $s6  = "Checksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide
    $s7  = "Download: " fullword wide
    $s8  = "An attempt was made by this server to make a Kerberos constrained delegation request for a target outside of the server's realm." wide
    $s9  = "D:\\Projects\\WinRAR\\rar\\build\\rar32\\Release\\RAR.pdb" fullword ascii
    $s10 = " computersystem get Name /format:list" fullword wide
    $s11 = "Enter password (will not be echoed) for %s: " fullword wide
    $s12 = "Remove: " fullword wide
    $s13 = "rarinfo.log" fullword wide
    $s14 = "?WThe given \"%s\" local time is invalid (situated within the missing period prior to DST).8String index out of range (%d).  Mus" wide
    $s15 = "OnExecuteH}H" fullword ascii
    $s16 = "ffffffffffffffg" fullword ascii  /* reversed goodware string 'gffffffffffffff' */
    $s17 = "Successfull API call7Not enough memory is available to complete this request" wide
    $s18 = "The handle specified is invalid'The function reques" wide
    $s19 = "1????????.*" wide
    $s20 = "/d.php?servers" wide

  condition:
    uint16(0) == 0x5a4d and filesize < 8000KB and
    (pe.imphash() == "9a622f807282a29fb32811b734622622" or (1 of ($x*) or 4 of them))
}

rule APT_DustSquad_BAT_Nov19_1 {
  meta:
    description = "Detection Rule for APT DustSquad campaign Nov19"
    author      = "Arkbird_SOLG"
    reference   = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
    date        = "2019-11-29"
    hash1       = "500983f7e9fb67bbe6651a5780e637474f1cd813600d4ae8b362dcf27d23b3d2"

  strings:
    $x1 = "if exist \"C:\\Users\\admin\\AppData\\Local\\Temp\\62fb5aa21f62e92586829520078c2561.exe\" (" fullword ascii
    $x2 = "del \"C:\\Users\\admin\\AppData\\Local\\Temp\\62fb5aa21f62e92586829520078c2561.exe\"" fullword ascii
    $x3 = "del \"C:\\Users\\admin\\AppData\\Local\\Temp\\s.bat\"" fullword ascii
    $s4 = "ping 192.168.100.84 -n 1 > nul" fullword ascii
    $s5 = "for /L %%n in (1,1,50) do (" fullword ascii
    $s6 = "chcp 1251 > nul" fullword ascii
    $s7 = ") else (" fullword ascii
    $s8 = "62fb5aa21f62e9258682952" ascii

  condition:
    uint16(0) == 0x6863 and filesize < 1KB and
    1 of ($x*) and all of them
}

rule UPX_v0_89_6___v1_02___v1_05___v1_22_DLL {
  strings:
    $a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }

  condition:
    $a0 at pe.entry_point
}
