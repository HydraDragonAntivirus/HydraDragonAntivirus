
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

rule Electronic_Arts_TQI_base_table2__8_byt_64_ {
  strings:
    $a0 = { 08 10 13 16 1a 1b 1d 22 10 10 16 18 1b 1d 22 25 13 16 1a 1b 1d 22 22 26 16 16 1a 1b 1d 22 25 28 16 1a 1b 1d 20 23 28 30 1a 1b 1d 20 23 28 30 3a 1a 1b 1d 22 26 2e 38 45 1b 1d 23 26 2e 38 45 53 }

  condition:
    $a0
}
rule mimikatz0 {
  meta:
    description   = "Detection patterns for the tool 'mimikatz' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "mimikatz"
    rule_category = "offensive_tool_keyword"

  strings:
    // Description: mimikatz default strings
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string1   = /\sBenjamin\sDELPY\s/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string2   = /\'\sp::d\s\'/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string3   = /\'\ss::l\s\'/ nocase ascii wide
    // Description: removing process protection for the lsass.exe process can potentially enable adversaries to inject malicious code or manipulate the process to escalate privileges or gather sensitive information such as credentials. command: !processprotect /process:lsass.exe /remove
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string4   = /\!processprotect\s.*lsass\.exe/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string5   = /\.kirbi\s/ nocase ascii wide
    // Description: Mimikatz Using domain trust key From the DC dump the hash of the currentdomain\targetdomain$ trust account using Mimikatz (e.g. with LSADump or DCSync). Then using this trust key and the domain SIDs. forge an inter-realm TGT using Mimikatz adding the SID for the target domains enterprise admins group to our SID history.
    // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
    $string6   = /\/domain:.*\s\/sid:.*\s\/sids:.*\s\/rc4:.*\s\/user:.*\s\/service:krbtgt\s\/target:.*\.kirbi/ nocase ascii wide
    // Description: Invoke-Mimikatz.ps1 script argument
    // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
    $string7   = /\/DumpCerts/ nocase ascii wide
    // Description: Invoke-Mimikatz.ps1 script argument
    // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
    $string8   = /\/DumpCreds/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/vyrus001/go-mimikatz
    $string9   = /\/go\-mimikatz/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string10  = /\/kiwi_passwords\.yar/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string11  = /\/mimi32\.exe/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string12  = /\/mimi64\.exe/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string13  = /\/mimicom\.idl/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string14  = /\/mimidrv\.sys/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string15  = /\/mimidrv\.zip/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string16  = /\/mimikatz\.sln/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string17  = /\/mimikatz_bypass\/mimikatz\.py/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string18  = /\/mimikatz_bypass\/mimikatz2\.py/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string19  = /\/mimikatz_bypassAV\/main\.exe/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string20  = /\/mimikatz_bypassAV\/mimikatz_load\.exe/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string21  = /\/mimikatz_load\.exe/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string22  = /\/mimilib\.def/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string23  = /\/mimilove\.c/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string24  = /\/mimilove\.h/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string25  = /\/mimilove\.rc/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/skelsec/pypykatz
    $string26  = /\/pypykatz\.py/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string27  = /\/rakjong\/mimikatz_bypassAV\// nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/skelsec/pypykatz
    $string28  = /\/skelsec\/pypykatz/ nocase ascii wide
    // Description: mimikatz powershell alternative name
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string29  = /\\katz\.ps1/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string30  = /\\mimi32\.exe/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string31  = /\\mimi64\.exe/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string32  = /\<3\seo\.oe/ nocase ascii wide
    // Description: mimikatz default strings
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string33  = /A\sLa\sVie.*\sA\sL\'Amour/ nocase ascii wide
    // Description: mimikatz default strings
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string34  = /benjamin\@gentilkiwi\.com/ nocase ascii wide
    // Description: mimikatz exploitation command
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string35  = /chocolate\.kirbi/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string36  = /Copyright\s\(c\)\s2007\s\-\s2021\sgentilkiwi\s\(Benjamin\sDELPY\)/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string37  = /crypto::capi/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string38  = /crypto::certificates/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string39  = /crypto::certtohw/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string40  = /crypto::cng/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string41  = /crypto::extract/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string42  = /crypto::hash/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string43  = /crypto::keys/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string44  = /crypto::providers/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string45  = /crypto::sc/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string46  = /crypto::scauth/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string47  = /crypto::stores/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string48  = /crypto::system/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string49  = /crypto::tpminfo/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string50  = /dpapi::blob/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string51  = /dpapi::cache/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string52  = /dpapi::capi/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string53  = /dpapi::chrome/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string54  = /dpapi::cloudapkd/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string55  = /dpapi::cloudapreg/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string56  = /dpapi::cng/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string57  = /dpapi::create/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string58  = /dpapi::cred/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string59  = /dpapi::credhist/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string60  = /dpapi::luna/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string61  = /dpapi::masterkey/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string62  = /dpapi::protect/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string63  = /dpapi::ps/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string64  = /dpapi::rdg/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string65  = /dpapi::sccm/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string66  = /dpapi::ssh/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string67  = /dpapi::tpm/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string68  = /dpapi::vault/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string69  = /dpapi::wifi/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string70  = /dpapi::wwman/ nocase ascii wide
    // Description: Invoke-Mimikatz.ps1 script argument
    // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
    $string71  = /\-DumpCreds/ nocase ascii wide
    // Description: Invoke-Mimikatz.ps1 function name
    // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
    $string72  = /Enable\-SeDebugPrivilege/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string73  = /eo\.oe\.kiwi/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string74  = /event::clear/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string75  = /event::drop/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string76  = /gentilkiwi\s\(Benjamin\sDELPY\)/ nocase ascii wide
    // Description: author of mimikatz and multiple other windows exploitation tools
    // Reference: https://github.com/gentilkiwi/
    $string77  = /gentilkiwi/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string78  = /Hello\sfrom\sDCShadow/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string79  = /id::modify/ nocase ascii wide
    // Description: Invoke-Mimikatz.ps1 function name
    // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
    $string80  = /Import\-DllInRemoteProcess/ nocase ascii wide
    // Description: Invoke-Mimikatz.ps1 function name
    // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
    $string81  = /Invoke\-CreateRemoteThread/ nocase ascii wide
    // Description: Invoke-Mimikatz.ps1 function name
    // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
    $string82  = /Invoke\-Mimikatz/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/g4uss47/Invoke-Mimikatz
    $string83  = /Invoke\-Mimikatz/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/g4uss47/Invoke-Mimikatz
    $string84  = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/g4uss47/Invoke-Mimikatz
    $string85  = /Invoke\-UpdateMimikatzScript\.ps1/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string86  = /kerberos::ask/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string87  = /kerberos::clist/ nocase ascii wide
    // Description: mimikatz exploitation command
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string88  = /kerberos::golden/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string89  = /kerberos::golden/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string90  = /kerberos::hash/ nocase ascii wide
    // Description: mimikatz exploitation command
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string91  = /kerberos::list/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. This function lists all Kerberos tickets in memory
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string92  = /kerberos::list/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string93  = /kerberos::ptc/ nocase ascii wide
    // Description: mimikatz exploitation command
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string94  = /kerberos::ptt/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string95  = /kerberos::ptt/ nocase ascii wide
    // Description: Mimikatz Unconstrained delegation. With administrative privileges on a server with Unconstrained Delegation set we can dump the TGTs for other users that have a connection. If we do this successfully. we can impersonate the victim user towards any service in the domain.
    // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
    $string96  = /kerberos::ptt.*\.kirbi/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string97  = /kerberos::purge/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string98  = /kerberos::tgt/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string99  = /Kiwi\sLegit\sPrinter/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string100 = /kuhl_m_sekurlsa_nt6\.c/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string101 = /kuhl_m_sekurlsa_nt6\.h/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string102 = /kuhl_m_sekurlsa_packages\.c/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string103 = /kuhl_m_sekurlsa_packages\.h/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string104 = /kuhl_m_sekurlsa_utils\.c/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string105 = /kuhl_m_sekurlsa_utils\.h/ nocase ascii wide
    // Description: mimikatz exploitation command
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string106 = /lsadump::/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string107 = /lsadump::backupkeys/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string108 = /lsadump::cache/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string109 = /lsadump::changentlm/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string110 = /lsadump::dcshadow/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string111 = /lsadump::dcsync/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string112 = /lsadump::lsa/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string113 = /lsadump::mbc/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string114 = /lsadump::netsync/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string115 = /lsadump::packages/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string116 = /lsadump::postzerologon/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string117 = /lsadump::RpData/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string118 = /lsadump::sam/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string119 = /lsadump::secrets/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string120 = /lsadump::setntlm/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string121 = /lsadump::trust/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string122 = /lsadump::zerologon/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string123 = /mimi32\.exe\s/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string124 = /mimi64\.exe\s/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string125 = /mimidrv\s\(mimikatz\)/ nocase ascii wide
    // Description: mimikatz exploitation 
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string126 = /mimidrv/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string127 = /mimidrv\.pdb/ nocase ascii wide
    // Description: mimikatz exploitation 
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string128 = /mimidrv\.sys/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string129 = /mimidrv\.sys/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string130 = /mimidrv\.sys/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string131 = /mimidrv\.zip/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string132 = /mimikatz\sfor\sWindows/ nocase ascii wide
    // Description: Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets.
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string133 = /Mimikatz/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string134 = /mimikatz\.exe/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string135 = /mimikatz_trunk/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string136 = /mimilib\s\(mimikatz\)/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string137 = /mimilib\sfor\sWindows\s\(mimikatz\)/ nocase ascii wide
    // Description: mimikatz exploitation 
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string138 = /mimilib/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string139 = /mimilib\.dll/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string140 = /mimilib\.dll/ nocase ascii wide
    // Description: mimikatz exploitation 
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string141 = /mimilove/ nocase ascii wide
    // Description: mimikatz exploitation 
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string142 = /mimilove\.exe/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string143 = /mimilove\.vcxproj/ nocase ascii wide
    // Description: mimikatz exploitation 
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string144 = /mimispool\.dll/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string145 = /misc::aadcookie/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string146 = /misc::clip/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string147 = /misc::cmd/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string148 = /misc::compress/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string149 = /misc::detours/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string150 = /misc::efs/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string151 = /misc::lock/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string152 = /misc::memssp/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string153 = /misc::mflt/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string154 = /misc::ncroutemon/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string155 = /misc::ngcsign/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string156 = /misc::printnightmare/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string157 = /misc::regedit/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string158 = /misc::sccm/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string159 = /misc::shadowcopies/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string160 = /misc::skeleton/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string161 = /misc::spooler/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string162 = /misc::taskmgr/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string163 = /misc::wp/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string164 = /misc::xor/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string165 = /net::alias/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string166 = /net::deleg/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string167 = /net::group/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string168 = /net::if/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string169 = /net::serverinfo/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string170 = /net::session/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string171 = /net::share/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string172 = /net::stats/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string173 = /net::tod/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string174 = /net::trust/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string175 = /net::user/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string176 = /net::wsession/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/Stealthbits/poshkatz
    $string177 = /poshkatz\.psd1/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string178 = /privilege::backup/ nocase ascii wide
    // Description: mimikatz exploitation command
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string179 = /privilege::debug/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string180 = /privilege::debug/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string181 = /privilege::driver/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string182 = /privilege::id/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string183 = /privilege::name/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string184 = /privilege::restore/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string185 = /privilege::security/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string186 = /privilege::sysenv/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string187 = /privilege::tcb/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string188 = /process::exports/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string189 = /process::imports/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string190 = /process::list/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string191 = /process::resume/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string192 = /process::run/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string193 = /process::runp/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string194 = /process::start/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string195 = /process::stop/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string196 = /process::suspend/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/skelsec/pypykatz
    $string197 = /pypykatz\slsa\sminidump/ nocase ascii wide
    // Description: invoke mimiaktz string found used by the tool EDRaser 
    // Reference: https://github.com/SafeBreach-Labs/EDRaser
    $string198 = /QWRkLU1lbWJlciBOb3RlUHJvcGVydHkgLU5hbWUgVmlydHVhbFByb3RlY3QgLVZhbHVlICRWaXJ0dWFsUHJvdGVjdA/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string199 = /rpc::close/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string200 = /rpc::connect/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string201 = /rpc::enum/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string202 = /rpc::server/ nocase ascii wide
    // Description: mimikatz exploitation command
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string203 = /sekurlsa\s/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string204 = /sekurlsa::backupkeys/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string205 = /sekurlsa::bootkey/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string206 = /sekurlsa::cloudap/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string207 = /sekurlsa::credman/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string208 = /sekurlsa::dpapi/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string209 = /sekurlsa::dpapisystem/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. This function dumps DPAPI backup keys for users who have logged on to the system
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string210 = /sekurlsa::ekeys/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string211 = /sekurlsa::kerberos/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string212 = /sekurlsa::krbtgt/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string213 = /sekurlsa::livessp/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. This function retrieves plaintext credentials from the LSA secrets in memory.
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string214 = /sekurlsa::logonpasswords/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string215 = /sekurlsa::minidump/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string216 = /sekurlsa::msv/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string217 = /sekurlsa::process/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash.This function performs pass-the-hash attacks allowing an attacker to authenticate to a remote system with a stolen hash.
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string218 = /sekurlsa::pth/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string219 = /sekurlsa::ssp/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string220 = /sekurlsa::tickets/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string221 = /sekurlsa::trust/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string222 = /sekurlsa::tspkg/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string223 = /sekurlsa::wdigest/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string224 = /service::me/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string225 = /service::preshutdown/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string226 = /service::remove/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string227 = /service::resume/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string228 = /service::shutdown/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string229 = /service::start/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string230 = /service::stop/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string231 = /service::suspend/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string232 = /sid::add/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string233 = /sid::clear/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string234 = /sid::lookup/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string235 = /sid::modify/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string236 = /sid::patch/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string237 = /sid::query/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string238 = /standard::answer/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string239 = /standard::base64/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string240 = /standard::cd/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string241 = /standard::cls/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string242 = /standard::coffee/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string243 = /standard::exit/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string244 = /standard::hostname/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string245 = /standard::localtime/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string246 = /standard::log/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string247 = /standard::sleep/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string248 = /standard::version/ nocase ascii wide
    // Description: Mimikatz Unconstrained delegation. With administrative privileges on a server with Unconstrained Delegation set we can dump the TGTs for other users that have a connection. If we do this successfully. we can impersonate the victim user towards any service in the domain.
    // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
    $string249 = /ticket\.kirbi/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string250 = /token::elevate/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string251 = /token::list/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string252 = /token::revert/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string253 = /token::run/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string254 = /token::whoami/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string255 = /ts::logonpasswords/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string256 = /ts::mstsc/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string257 = /ts::multirdp/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string258 = /ts::remote/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string259 = /ts::sessions/ nocase ascii wide
    // Description: mimikatz exploitation command
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string260 = /vault::/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string261 = /vault::cred/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string262 = /vault::list/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string263 = /vincent\.letoux\@gmail\.com/ nocase ascii wide
    // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
    // Reference: https://github.com/vyrus001/go-mimikatz
    $string264 = /vyrus001\/go\-mimikatz/ nocase ascii wide
    // Description: mimikatz exploitation default password
    // Reference: https://github.com/gentilkiwi/mimikatz
    $string265 = /waza1234/ nocase ascii wide

  condition:
    any of them
}

rule INDICATOR_SUSPICIOUS_CAPABILITY_CaptureScreenShot {
    meta:
        author = "ditekSHen"
        description = "Detects .NET executables with screen capture cabability"
    strings:
        $dll = "gdiplus.dll" ascii wide nocase
        $c1 = "gdipcreatebitmapfromhbitmap" ascii wide nocase
        $c2 = "gdipcreatebitmapfromscan0" ascii wide nocase
        $save = "gdipsaveimagetofile" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and ($dll and $save and (1 of ($c*)))
}

rule Microsoft_Visual_Basic_v50v60: PEiD {
  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 00 00 00 00 30 00 00 00 }

  condition:
    $a at pe.entry_point

}

rule Microsoft_Visual_Basic_v50_v60: PEiD {
  strings:
    $a = { 5A 68 68 52 E9 }
    $b = { FF 25 ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF }
    $c = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 ?? 00 00 00 30 ?? 00 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule libavcodec_nuppelvideo_fallback_lquant__8_byt_64_ {
  strings:
    $a0 = { 10 0b 0a 10 18 28 33 3d 0c 0c 0e 13 1a 3a 3c 37 0e 0d 10 18 28 39 45 38 0e 11 16 1d 33 57 50 3e 12 16 25 38 44 6d 67 4d 18 23 37 40 51 68 71 5c 31 40 4e 57 67 79 78 65 48 5c 5f 62 70 64 67 63 }

  condition:
    $a0
}

rule with_images: mail {
  meta:
    author      = "Antonio Sanchez <asanchez@hispasec.com>"
    reference   = "http://laboratorio.blogs.hispasec.com/"
    description = "Rule to detect the presence of an or several images"

  strings:
    $eml_01 = "From:"
    $eml_02 = "To:"
    $eml_03 = "Subject:"
    $img_a  = ".jpg" nocase
    $img_b  = ".png" nocase
    $img_c  = ".bmp" nocase

  condition:
    all of ($eml_*) and
    any of ($img_*)
}

rule ASPack_107b_DLL: PEiD {
  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 3E D9 43 00 B8 38 D9 43 00 03 C5 2B 85 0B DE 43 00 89 85 17 DE 43 00 80 BD 01 DE 43 00 00 75 15 FE 85 01 DE 43 00 E8 1D 00 00 00 E8 79 02 00 00 E8 12 03 00 00 8B 85 03 DE 43 00 03 85 17 DE 43 00 89 44 24 1C 61 FF }

  condition:
    $a at pe.entry_point

}

rule RAR_Archive_ren: RarLab {
  meta:
    author = "_pusher_"
    date   = "2016-09"

  strings:
    //RAR
    $a0 = { 52 61 72 21 1A 07 (00 | 01) ?? ?? 73 ?? 00 0D 00 00 00 00 00 00 00 }
    //RAR5
    $a1 = { 52 61 72 21 1A 07 01 00 ?? ?? ?? ?? ?? 01 05 ?? 00 ?? 01 01 }
  //$a1 = "RarSFX" wide ascii nocase
  //$a2 = "GETPASSWORD1" wide ascii nocase

  condition:
    //$a0 or
    (
      any of ($a*)
      //$a0 
      //and $a1 and $a2 
      //and
      //uint32be( (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) ) == 0x52617221
    )

}

rule MSVC2005 {
  meta:
    author = "_pusher_"
    date   = "2016-08"
    linker = "8.00"

  condition:
    pe.rich_signature.version(40310) and (pe.rich_signature.version(21022) or pe.rich_signature.version(30729)) and pe.rich_signature.toolid(124) or
    pe.rich_signature.version(3094) and pe.rich_signature.version(50736) and pe.rich_signature.toolid(113) or
    pe.rich_signature.version(40310) and pe.rich_signature.version(4035) and pe.rich_signature.toolid(125)
    //more samples needed 00:21 2017-05-19
    or (
      pe.rich_signature.version(50727)
    )
    and ((pe.linker_version.major == 8) and (pe.linker_version.minor == 0))
}

rule Qemu_Detection_ren1: AntiVM {
  meta:
    description = "Looks for Qemu presence"

  strings:
    $a0 = "qemu" nocase wide ascii

  condition:
    any of them
}

rule kryptor8 {
  meta:
    author      = "PEiD"
    description = "k.kryptor 8 -> r!sc & noodlespa"
    group       = "128"
    function    = "0"

  strings:
    $a0 = { EB 6A 87 DB }

  condition:
    $a0
}

rule png: PNG {
  meta:
    author = "Joan Bono"

  strings:
    $a = { 89 50 4E 47 0D 0A 1A 0A }
    $b = "IHDR"
    $c = "IDAT"
    $d = "IEND"

  condition:
    $a at 0 and for any of ($b, $c): (@ > @a) and $d
}

rule IsZipFile {
  condition:
    uint16(0) == 0x4B50
}

rule ffuf {
  meta:
    description   = "Detection patterns for the tool 'ffuf' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "ffuf"
    rule_category = "offensive_tool_keyword"

  strings:
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string1  = /\s\-o\sffuf\.csv/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string2  = /\/ffuf\.git/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string3  = /\/ffuf\/ffufrc/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string4  = /cd\sffuf/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string5  = /ffuf\s.*\-input\-cmd/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string6  = /ffuf\s.*\-u\shttp/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string7  = /ffuf\s\-c\s/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string8  = /ffuf\s\-w\s/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string9  = /ffuf\.exe/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string10 = /ffuf\/ffuf/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string11 = /ffuf_.*_freebsd_.*\.tar\.gz/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string12 = /ffuf_.*_linux_.*\.tar\.gz/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string13 = /ffuf_.*_macOS_.*\.tar\.gz/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string14 = /ffuf_.*_openbsd_.*\.tar\.gz/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string15 = /ffuf_.*_windows_.*\.zip/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string16 = /ffuf\-master\.zip/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string17 = /fuff\s.*\-input\-shell/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string18 = /fuff\s.*\-scraperfile/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string19 = /fuff\s.*\-scrapers/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string20 = /https:\/\/ffuf\.io\.fi/ nocase ascii wide
    // Description: Fast web fuzzer written in Go
    // Reference: https://github.com/ffuf/ffuf
    $string21 = /https:\/\/ffuf\.io\/FUZZ/ nocase ascii wide

  condition:
    any of them
}

rule UPX_: RAT {
  meta:
    author = " Kevin Breen <kevin@techanarchy.net>"
    date   = "2014/04"

  strings:
    $a = "UPX0"
    $b = "UPX1"
    $c = "UPX!"

  condition:
    all of them
}
