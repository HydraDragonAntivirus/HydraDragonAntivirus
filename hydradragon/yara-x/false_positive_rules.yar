
rule INDICATOR_SUSPICIOUS_Stomped_PECompilation_Timestamp_InTheFuture {
    meta:
        author = "ditekSHen"
        description = "Detect executables with stomped PE compilation timestamp that is greater than local current time"
    condition:
        uint16(0) == 0x5a4d and pe.timestamp > time.now()
}

rule Win_Trojan_Packed_146 {
  strings:
    $a0 = { 03 d1 03 d1 03 d1 03 d1 03 d1 03 d1 03 d1 03 d1 }

  condition:
    $a0
}

rule Sandboxie_Detection: AntiVM {
  meta:
    description = "Looks for Sandboxie presence"
    author      = "Ivan Kwiatkowski (@JusticeRage)"

  strings:
    $sbie           = "SbieDll.dll" nocase wide ascii
    $buster         = /LOG_API(_VERBOSE)?.DLL/ nocase wide ascii
    $sbie_process_1 = "SbieSvc.exe" nocase wide ascii
    $sbie_process_2 = "SbieCtrl.exe" nocase wide ascii
    $sbie_process_3 = "SandboxieRpcSs.exe" nocase wide ascii
    $sbie_process_4 = "SandboxieDcomLaunch.exe" nocase wide ascii
    $sbie_process_5 = "SandboxieCrypto.exe" nocase wide ascii
    $sbie_process_6 = "SandboxieBITS.exe" nocase wide ascii
    $sbie_process_7 = "SandboxieWUAU.exe" nocase wide ascii

  condition:
    any of them
}

rule NET_executable_: PEiD {
  strings:
    $a = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a at pe.entry_point

}

rule ttp_lib_openssl_no_version_str_unsigned: ttp {
  meta:
    author = "stvemillertime"
    // this is a dumb, exploratory rule, not sure what i'm doing here
    // most legit and non-obfuscated binaries that use openssl libraries have the plaintext version string
    // figured id look for unsigned pes that have *some* openssl string, but without the common version strings
    ref    = "47dc997d08d53e55b8450940d9de94e2b5db631e"  //attor
    ref    = "941be28004afc2c7c8248a86b5857a35ab303beb33c704640852741b925558a1"
    ref    = "582cd41417aeb2f3f86d2c9fb7f8add4e5edacfed7cae0aecc8cb088a823d240"

  strings:
    $s    = "openssl" nocase ascii
    // $s = /\x00[\x01-\x7f]{,500}OpenSSL[\x01-\x7f]{,500}\x00/ ascii // use this when testing or printing strings
    // excluding common openssl version strings.. why? shrug, why not! 
    $z0   = "OpenSSL 0.9.0b"
    $z1   = "OpenSSL 0.9.1b"
    $z2   = "OpenSSL 0.9.1c"
    $z3   = "OpenSSL 0.9.2b"
    $z4   = "OpenSSL 0.9.3"
    $z5   = "OpenSSL 0.9.3a"
    $z6   = "OpenSSL 0.9.4"
    $z7   = "OpenSSL 0.9.5"
    $z8   = "OpenSSL 0.9.5a"
    $z9   = "OpenSSL 0.9.6"
    $z10  = "OpenSSL 0.9.6a"
    $z11  = "OpenSSL 0.9.6b"
    $z12  = "OpenSSL 0.9.6c"
    $z13  = "OpenSSL 0.9.6d"
    $z14  = "OpenSSL 0.9.6e"
    $z15  = "OpenSSL 0.9.6f"
    $z16  = "OpenSSL 0.9.6g"
    $z17  = "OpenSSL 0.9.6h"
    $z18  = "OpenSSL 0.9.6i"
    $z19  = "OpenSSL 0.9.6j"
    $z20  = "OpenSSL 0.9.6k"
    $z21  = "OpenSSL 0.9.6l"
    $z22  = "OpenSSL 0.9.6m"
    $z23  = "OpenSSL 0.9.7"
    $z24  = "OpenSSL 0.9.7a"
    $z25  = "OpenSSL 0.9.7b"
    $z26  = "OpenSSL 0.9.7c"
    $z27  = "OpenSSL 0.9.7d"
    $z28  = "OpenSSL 0.9.7e"
    $z29  = "OpenSSL 0.9.7f"
    $z30  = "OpenSSL 0.9.7g"
    $z31  = "OpenSSL 0.9.7h"
    $z32  = "OpenSSL 0.9.7i"
    $z33  = "OpenSSL 0.9.7j"
    $z34  = "OpenSSL 0.9.7k"
    $z35  = "OpenSSL 0.9.7l"
    $z36  = "OpenSSL 0.9.7m"
    $z37  = "OpenSSL 0.9.8"
    $z38  = "OpenSSL 0.9.8a"
    $z39  = "OpenSSL 0.9.8b"
    $z40  = "OpenSSL 0.9.8c"
    $z41  = "OpenSSL 0.9.8d"
    $z42  = "OpenSSL 0.9.8e"
    $z43  = "OpenSSL 0.9.8f"
    $z44  = "OpenSSL 0.9.8g"
    $z45  = "OpenSSL 0.9.8h"
    $z46  = "OpenSSL 0.9.8i"
    $z47  = "OpenSSL 0.9.8j"
    $z48  = "OpenSSL 0.9.8k"
    $z49  = "OpenSSL 0.9.8l"
    $z50  = "OpenSSL 0.9.8m"
    $z51  = "OpenSSL 0.9.8n"
    $z52  = "OpenSSL 1.0.0"
    $z53  = "OpenSSL 1.0.0a"
    $z54  = "OpenSSL 1.0.0b"
    $z55  = "OpenSSL 1.0.0c"
    $z56  = "OpenSSL 1.0.0d"
    $z57  = "OpenSSL 1.0.0e"
    $z58  = "OpenSSL 1.0.0f"
    $z59  = "OpenSSL 1.0.0g"
    $z60  = "OpenSSL 1.0.0h"
    $z61  = "OpenSSL 1.0.0i"
    $z62  = "OpenSSL 1.0.0j"
    $z63  = "OpenSSL 1.0.0k"
    $z64  = "OpenSSL 1.0.0l"
    $z65  = "OpenSSL 1.0.0m"
    $z66  = "OpenSSL 1.0.0n"
    $z67  = "OpenSSL 1.0.0o"
    $z68  = "OpenSSL 1.0.0p"
    $z69  = "OpenSSL 1.0.0q"
    $z70  = "OpenSSL 1.0.0r"
    $z71  = "OpenSSL 1.0.0s"
    $z72  = "OpenSSL 1.0.0t"
    $z73  = "OpenSSL 1.0.1"
    $z74  = "OpenSSL 1.0.1a"
    $z75  = "OpenSSL 1.0.1b"
    $z76  = "OpenSSL 1.0.1c"
    $z77  = "OpenSSL 1.0.1d"
    $z78  = "OpenSSL 1.0.1e"
    $z79  = "OpenSSL 1.0.1f"
    $z80  = "OpenSSL 1.0.1g"
    $z81  = "OpenSSL 1.0.1h"
    $z82  = "OpenSSL 1.0.1i"
    $z83  = "OpenSSL 1.0.1j"
    $z84  = "OpenSSL 1.0.1k"
    $z85  = "OpenSSL 1.0.1l"
    $z86  = "OpenSSL 1.0.1m"
    $z87  = "OpenSSL 1.0.1n"
    $z88  = "OpenSSL 1.0.1o"
    $z89  = "OpenSSL 1.0.1p"
    $z90  = "OpenSSL 1.0.1q"
    $z91  = "OpenSSL 1.0.1r"
    $z92  = "OpenSSL 1.0.1s"
    $z93  = "OpenSSL 1.0.1t"
    $z94  = "OpenSSL 1.0.1u"
    $z95  = "OpenSSL 1.0.2"
    $z96  = "OpenSSL 1.0.2a"
    $z97  = "OpenSSL 1.0.2b"
    $z98  = "OpenSSL 1.0.2c"
    $z99  = "OpenSSL 1.0.2d"
    $z100 = "OpenSSL 1.0.2e"
    $z101 = "OpenSSL 1.0.2f"
    $z102 = "OpenSSL 1.0.2g"
    $z103 = "OpenSSL 1.0.2h"
    $z104 = "OpenSSL 1.0.2i"
    $z105 = "OpenSSL 1.0.2j"
    $z106 = "OpenSSL 1.0.2k"
    $z107 = "OpenSSL 1.0.2l"
    $z108 = "OpenSSL 1.0.2m"
    $z109 = "OpenSSL 1.0.2n"
    $z110 = "OpenSSL 1.0.2o"
    $z111 = "OpenSSL 1.0.2p"
    $z112 = "OpenSSL 1.0.2q"
    $z113 = "OpenSSL 1.0.2r"
    $z114 = "OpenSSL 1.0.2s"
    $z115 = "OpenSSL 1.0.2t"
    $z116 = "OpenSSL 1.1.0"
    $z117 = "OpenSSL 1.1.0a"
    $z118 = "OpenSSL 1.1.0b"
    $z119 = "OpenSSL 1.1.0c"
    $z120 = "OpenSSL 1.1.0d"
    $z121 = "OpenSSL 1.1.0e"
    $z122 = "OpenSSL 1.1.0f"
    $z123 = "OpenSSL 1.1.0g"
    $z124 = "OpenSSL 1.1.0h"
    $z125 = "OpenSSL 1.1.0i"
    $z126 = "OpenSSL 1.1.0j"
    $z127 = "OpenSSL 1.1.0k"
    $z128 = "OpenSSL 1.1.0l"
    $z129 = "OpenSSL 1.1.1"
    $z130 = "OpenSSL 1.1.1a"
    $z131 = "OpenSSL 1.1.1b"
    $z132 = "OpenSSL 1.1.1c"
    $z133 = "OpenSSL 1.1.1d"
    $z134 = "OpenSSL 1.1.1e"
    $z135 = "OpenSSL 1.1.1f"
    $z136 = "OpenSSL 1.1.1g"
    $z137 = "OpenSSL 1.1.1h"
    $z138 = "OpenSSL 1.1.1i"
    $z139 = "OpenSSL 1.1.1j"
    $z140 = "OpenSSL 1.1.1k"
    $z141 = "OpenSSL 1.1.1l"
    $z142 = "OpenSSL 1.1.1m"
    $z143 = "OpenSSL 1.1.1n"
    $z144 = "OpenSSL 3.0"
    $z145 = "OpenSSL 3.0.0"
    $z146 = "OpenSSL 3.0.1"
    $z147 = "OpenSSL 3.0.2"
    $z148 = "OpenSSL 3.0.3"
    $z149 = "OpenSSL 3.0.4"
    $z150 = "OpenSSL 3.0.5"
    $z151 = "OpenSSL 3.0.6"
    $z152 = "OpenSSL 3.0.7"
    $z153 = "OpenSSL 3.0.8"
    $z154 = "OpenSSL 3.1"
    $z155 = "OpenSSL 3.1.0"
    $z156 = "OpenSSL 3.1.1"
    $z157 = "OpenSSL 3.1.2"
    $z158 = "OpenSSL 3.1.3"
    $z159 = "OpenSSL 3.1.4"
    $z160 = "OpenSSL 3.1.5"
    $z161 = "OpenSSL 3.2"
    $z162 = "OpenSSL 3.2.0"
    $z163 = "OpenSSL 3.2.1"
    $z164 = "OpenSSL 3.3"
    $x01  = "OpenSSL version mismatch"  // from openssh etc
    $x02  = "libcrypto.pdb\x00"  // libcrypto.dll

  condition:
    uint16be(0) == 0x4d5a
    and pe.signatures.len() == 0
    and $s
    and not any of ($z*)
    and not any of ($x*)
}

rule self_inject: suspicious feature dll injection windows {
  meta:
    description = "Self Injecting code - like code packers"
    link        = ""

  strings:
    // Allocate new memory
    $self01 = "VirtualAlloc"
    // Change the executable bit of te new memory
    $self02 = "VirtualProtect"
    // Create new process
    $self03 = "CreateProcessInternal"

  condition:
    // MZ at the beginning of file
    uint16be(0) == 0x4d5a and
    all of them
}

rule BitRock_InstallBuilder: BitRock Inc {
  meta:
    author = "_pusher_"
    date   = "2015-12"

  strings:
    $a0 = { 0E 00 00 00 2E 65 68 5F 66 72 61 6D 65 00 }

  condition:
    //at overlay
    $a0 at (pe.sections[pe.sections.len() - 1].raw_data_offset + pe.sections[pe.sections.len() - 1].raw_data_size)
}

rule MinGW_GCC_3x_additional: PEiD {
  strings:
    $a = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? ?? E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? 55 }

  condition:
    $a at pe.entry_point

}

rule NET_executable: PEiD {
  strings:
    $a = { FF 15 FC 81 40 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 }
    $b = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

