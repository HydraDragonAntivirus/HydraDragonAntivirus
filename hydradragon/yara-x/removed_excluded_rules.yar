// ===== removed from C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\yara-x\rules\clean_rules.yar (20260620_162022) =====
rule DebuggerCheck__GlobalFlags: AntiDebug DebuggerCheck {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = "NtGlobalFlags"

  condition:
    any of them
}

rule DebuggerCheck__QueryInfo: AntiDebug DebuggerCheck {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = "QueryInformationProcess"

  condition:
    any of them
}

rule DebuggerCheck__RemoteAPI: AntiDebug DebuggerCheck {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = "CheckRemoteDebuggerPresent"

  condition:
    any of them
}

rule DebuggerHiding__Thread: AntiDebug DebuggerHiding {
  meta:
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
    weight    = 1

  strings:
    $ = "SetInformationThread"

  condition:
    any of them
}

rule DebuggerHiding__Active: AntiDebug DebuggerHiding {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = "DebugActiveProcess"

  condition:
    any of them
}

rule DebuggerException__ConsoleCtrl: AntiDebug DebuggerException {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = "GenerateConsoleCtrlEvent"

  condition:
    any of them
}

rule DebuggerException__SetConsoleCtrl: AntiDebug DebuggerException {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = "SetConsoleCtrlHandler"

  condition:
    any of them
}

rule ThreadControl__Context: AntiDebug ThreadControl {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = "SetThreadContext"

  condition:
    any of them
}

rule SEH__vba: AntiDebug SEH {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = "vbaExceptHandler"

  condition:
    any of them
}

rule SEH__vectored: AntiDebug SEH {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = "AddVectoredExceptionHandler"
    $ = "RemoveVectoredExceptionHandler"

  condition:
    any of them
}

rule SEH_Save: Tactic_DefensiveEvasion Technique_AntiDebugging SubTechnique_SEH {
  meta:
    author          = "Malware Utkonos"
    original_author = "naxonez"
    source          = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $a = { 64 ff 35 00 00 00 00 }

  condition:
    AVASTTI_EXE_PRIVATE and $a
}

rule SEH_Init: Tactic_DefensiveEvasion Technique_AntiDebugging SubTechnique_SEH {
  meta:
    author          = "Malware Utkonos"
    original_author = "naxonez"
    source          = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $a = { 64 A3 00 00 00 00 }
    $b = { 64 89 25 00 00 00 00 }

  condition:
    AVASTTI_EXE_PRIVATE and ($a or $b)
}

rule DebuggerCheck__MemoryWorkingSet: AntiDebug DebuggerCheck {
  meta:
    author      = "Fernando Mercês"
    date        = "2015-06"
    description = "Anti-debug process memory working set size check"
    reference   = "http://www.gironsec.com/blog/2015/06/anti-debugger-trick-quicky/"

  condition:
    pe.imports("kernel32.dll", "K32GetProcessMemoryInfo") and
    pe.imports("kernel32.dll", "GetCurrentProcess")
}

rule vmdetect_misc: vmdetect {
  meta:
    author      = "@abhinavbom"
    maltype     = "NA"
    version     = "0.1"
    date        = "31/10/2015"
    description = "Following Rule is referenced from AlienVault's Yara rule repository.This rule contains additional processes and driver names."

  strings:
    $vbox1 = "VBoxService" nocase ascii wide
    $vbox2 = "VBoxTray" nocase ascii wide
    $vbox3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase ascii wide
    $vbox4 = "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions" nocase ascii wide

    $wine1 = "wine_get_unix_file_name" ascii wide

    $vmware1 = "vmmouse.sys" ascii wide
    $vmware2 = "VMware Virtual IDE Hard Drive" ascii wide

    $miscvm1 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase ascii wide
    $miscvm2 = "SYSTEM\\\\ControlSet001\\\\Services\\\\Disk\\\\Enum" nocase ascii wide

    // Drivers
    $vmdrv1  = "hgfs.sys" ascii wide
    $vmdrv2  = "vmhgfs.sys" ascii wide
    $vmdrv3  = "prleth.sys" ascii wide
    $vmdrv4  = "prlfs.sys" ascii wide
    $vmdrv5  = "prlmouse.sys" ascii wide
    $vmdrv6  = "prlvideo.sys" ascii wide
    $vmdrv7  = "prl_pv32.sys" ascii wide
    $vmdrv8  = "vpc-s3.sys" ascii wide
    $vmdrv9  = "vmsrvc.sys" ascii wide
    $vmdrv10 = "vmx86.sys" ascii wide
    $vmdrv11 = "vmnet.sys" ascii wide

    // SYSTEM\ControlSet001\Services
    $vmsrvc1  = "vmicheartbeat" ascii wide
    $vmsrvc2  = "vmicvss" ascii wide
    $vmsrvc3  = "vmicshutdown" ascii wide
    $vmsrvc4  = "vmicexchange" ascii wide
    $vmsrvc5  = "vmci" ascii wide
    $vmsrvc6  = "vmdebug" ascii wide
    $vmsrvc7  = "vmmouse" ascii wide
    $vmsrvc8  = "VMTools" ascii wide
    $vmsrvc9  = "VMMEMCTL" ascii wide
    $vmsrvc10 = "vmware" ascii wide
    $vmsrvc11 = "vmx86" ascii wide
    $vmsrvc12 = "vpcbus" ascii wide
    $vmsrvc13 = "vpc-s3" ascii wide
    $vmsrvc14 = "vpcuhub" ascii wide
    $vmsrvc15 = "msvmmouf" ascii wide
    $vmsrvc16 = "VBoxMouse" ascii wide
    $vmsrvc17 = "VBoxGuest" ascii wide
    $vmsrvc18 = "VBoxSF" ascii wide
    $vmsrvc19 = "xenevtchn" ascii wide
    $vmsrvc20 = "xennet" ascii wide
    $vmsrvc21 = "xennet6" ascii wide
    $vmsrvc22 = "xensvc" ascii wide
    $vmsrvc23 = "xenvdb" ascii wide

    // Processes
    $miscproc1 = "vmware2" ascii wide
    $miscproc2 = "vmount2" ascii wide
    $miscproc3 = "vmusrvc" ascii wide
    $miscproc4 = "vmsrvc" ascii wide
    $miscproc5 = "vboxservice" ascii wide
    $miscproc6 = "vboxtray" ascii wide
    $miscproc7 = "xenservice" ascii wide

    $vmware_mac_1a     = "00-05-69"
    $vmware_mac_1b     = "00:05:69"
    $vmware_mac_2a     = "00-50-56"
    $vmware_mac_2b     = "00:50:56"
    $vmware_mac_3a     = "00-0C-29"
    $vmware_mac_3b     = "00:0C:29"
    $vmware_mac_4a     = "00-1C-14"
    $vmware_mac_4b     = "00:1C:14"
    $virtualbox_mac_1a = "08-00-27"
    $virtualbox_mac_1b = "08:00:27"

  condition:
    2 of them
}

rule EzcobStrings: Ezcob Family {
  meta:
    description   = "Ezcob Identifying Strings"
    author        = "Seth Hardy"
    last_modified = "2014-06-23"

  strings:
    $ = "\x12F\x12F\x129\x12E\x12A\x12E\x12B\x12A\x12-\x127\x127\x128\x123\x12"
    $ = "\x121\x12D\x128\x123\x12B\x122\x12E\x128\x12-\x12B\x122\x123\x12D\x12"
    $ = "Ezcob" wide ascii
    $ = "l\x12i\x12u\x122\x120\x121\x123\x120\x124\x121\x126"
    $ = "20110113144935"

  condition:
    any of them
}

rule GlassesCode: Glasses Family {
  meta:
    description   = "Glasses code features"
    author        = "Seth Hardy"
    last_modified = "2014-07-22"

  strings:
    $ = { B8 AB AA AA AA F7 E1 D1 EA 8D 04 52 2B C8 }
    $ = { B8 56 55 55 55 F7 E9 8B 4C 24 1C 8B C2 C1 E8 1F 03 D0 49 3B CA }

  condition:
    any of them
}

rule Insta11Strings: Insta11 Family {
  meta:
    description   = "Insta11 Identifying Strings"
    author        = "Seth Hardy"
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

rule spyeye: banker {
  meta:
    author      = "Jean-Philippe Teissier / @Jipe_"
    description = "SpyEye X.Y memory"
    date        = "2012-05-23"
    version     = "1.0"
    filetype    = "memory"

  strings:
    $spyeye = "SpyEye"
    $a      = "%BOTNAME%"
    $b      = "globplugins"
    $c      = "data_inject"
    $d      = "data_before"
    $e      = "data_after"
    $f      = "data_end"
    $g      = "bot_version"
    $h      = "bot_guid"
    $i      = "TakeBotGuid"
    $j      = "TakeGateToCollector"
    $k      = "[ERROR] : Omfg! Process is still active? Lets kill that mazafaka!"
    $l      = "[ERROR] : Update is not successfull for some reason"
    $m      = "[ERROR] : dwErr == %u"
    $n      = "GRABBED DATA"

  condition:
    $spyeye or (any of ($a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k, $l, $m, $n))
}

rule OlyxCode: Olyx Family {
  meta:
    description   = "Olyx code tricks"
    author        = "Seth Hardy"
    last_modified = "2014-06-19"

  strings:
    $six   = { C7 40 04 36 36 36 36 C7 40 08 36 36 36 36 }
    $slash = { C7 40 04 5C 5C 5C 5C C7 40 08 5C 5C 5C 5C }

  condition:
    any of them
}

rule suspicious_packer_section: packer PE {
  meta:
    author      = "@j0sm1"
    date        = "2016/10/21"
    description = "The packer/protector section names/keywords"
    reference   = "http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
    filetype    = "binary"

  strings:
    $s1  = ".aspack" wide ascii
    $s2  = ".adata" wide ascii
    $s3  = "ASPack" wide ascii
    $s4  = ".ASPack" wide ascii
    $s5  = ".ccg" wide ascii
    $s6  = "BitArts" wide ascii
    $s7  = "DAStub" wide ascii
    $s8  = "!EPack" wide ascii
    $s9  = "FSG!" wide ascii
    $s10 = "kkrunchy" wide ascii
    $s11 = ".mackt" wide ascii
    $s12 = ".MaskPE" wide ascii
    $s13 = "MEW" wide ascii
    $s14 = ".MPRESS1" wide ascii
    $s15 = ".MPRESS2" wide ascii
    $s16 = ".neolite" wide ascii
    $s17 = ".neolit" wide ascii
    $s18 = ".nsp1" wide ascii
    $s19 = ".nsp2" wide ascii
    $s20 = ".nsp0" wide ascii
    $s21 = "nsp0" wide ascii
    $s22 = "nsp1" wide ascii
    $s23 = "nsp2" wide ascii
    $s24 = ".packed" wide ascii
    $s25 = "pebundle" wide ascii
    $s26 = "PEBundle" wide ascii
    $s27 = "PEC2TO" wide ascii
    $s28 = "PECompact2" wide ascii
    $s29 = "PEC2" wide ascii
    $s30 = "pec1" wide ascii
    $s31 = "pec2" wide ascii
    $s32 = "PEC2MO" wide ascii
    $s33 = "PELOCKnt" wide ascii
    $s34 = ".perplex" wide ascii
    $s35 = "PESHiELD" wide ascii
    $s36 = ".petite" wide ascii
    $s37 = "ProCrypt" wide ascii
    $s38 = ".RLPack" wide ascii
    $s39 = "RCryptor" wide ascii
    $s40 = ".RPCrypt" wide ascii
    $s41 = ".sforce3" wide ascii
    $s42 = ".spack" wide ascii
    $s43 = ".svkp" wide ascii
    $s44 = "Themida" wide ascii
    $s45 = ".Themida" wide ascii
    $s46 = ".packed" wide ascii
    $s47 = ".Upack" wide ascii
    $s48 = ".ByDwing" wide ascii
    $s49 = "UPX0" wide ascii
    $s50 = "UPX1" wide ascii
    $s51 = "UPX2" wide ascii
    $s52 = ".UPX0" wide ascii
    $s53 = ".UPX1" wide ascii
    $s54 = ".UPX2" wide ascii
    $s55 = ".vmp0" wide ascii
    $s56 = ".vmp1" wide ascii
    $s57 = ".vmp2" wide ascii
    $s58 = "VProtect" wide ascii
    $s59 = "WinLicen" wide ascii
    $s60 = "WWPACK" wide ascii
    $s61 = ".yP" wide ascii
    $s62 = ".y0da" wide ascii
    $s63 = "UPX!" wide ascii

  condition:
    // DOS stub signature                           PE signature
    uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (
      for any of them: ($ in (0..1024))
    )
}

rule Ponmocup: plugins memory {
  meta:
    description = "Ponmocup plugin detection (memory)"
    author      = "Danny Heppener, Fox-IT"
    reference   = "https://foxitsecurity.files.wordpress.com/2015/12/foxit-whitepaper_ponmocup_1_1.pdf"

  strings:
    $1100 = { 4D 5A 90 [29] 4C 04 }
    $1201 = { 4D 5A 90 [29] B1 04 }
    $1300 = { 4D 5A 90 [29] 14 05 }
    $1350 = { 4D 5A 90 [29] 46 05 }
    $1400 = { 4D 5A 90 [29] 78 05 }
    $1402 = { 4D 5A 90 [29] 7A 05 }
    $1403 = { 4D 5A 90 [29] 7B 05 }
    $1404 = { 4D 5A 90 [29] 7C 05 }
    $1405 = { 4D 5A 90 [29] 7D 05 }
    $1406 = { 4D 5A 90 [29] 7E 05 }
    $1500 = { 4D 5A 90 [29] DC 05 }
    $1501 = { 4D 5A 90 [29] DD 05 }
    $1502 = { 4D 5A 90 [29] DE 05 }
    $1505 = { 4D 5A 90 [29] E1 05 }
    $1506 = { 4D 5A 90 [29] E2 05 }
    $1507 = { 4D 5A 90 [29] E3 05 }
    $1508 = { 4D 5A 90 [29] E4 05 }
    $1509 = { 4D 5A 90 [29] E5 05 }
    $1510 = { 4D 5A 90 [29] E6 05 }
    $1511 = { 4D 5A 90 [29] E7 05 }
    $1512 = { 4D 5A 90 [29] E8 05 }
    $1600 = { 4D 5A 90 [29] 40 06 }
    $1601 = { 4D 5A 90 [29] 41 06 }
    $1700 = { 4D 5A 90 [29] A4 06 }
    $1800 = { 4D 5A 90 [29] 08 07 }
    $1801 = { 4D 5A 90 [29] 09 07 }
    $1802 = { 4D 5A 90 [29] 0A 07 }
    $1803 = { 4D 5A 90 [29] 0B 07 }
    $2001 = { 4D 5A 90 [29] D1 07 }
    $2002 = { 4D 5A 90 [29] D2 07 }
    $2003 = { 4D 5A 90 [29] D3 07 }
    $2004 = { 4D 5A 90 [29] D4 07 }
    $2500 = { 4D 5A 90 [29] C4 09 }
    $2501 = { 4D 5A 90 [29] C5 09 }
    $2550 = { 4D 5A 90 [29] F6 09 }
    $2600 = { 4D 5A 90 [29] 28 0A }
    $2610 = { 4D 5A 90 [29] 32 0A }
    $2700 = { 4D 5A 90 [29] 8C 0A }
    $2701 = { 4D 5A 90 [29] 8D 0A }
    $2750 = { 4D 5A 90 [29] BE 0A }
    $2760 = { 4D 5A 90 [29] C8 0A }
    $2810 = { 4D 5A 90 [29] FA 0A }

  condition:
    any of ($1100, $1201, $1300, $1350, $1400, $1402, $1403, $1404, $1405, $1406,
      $1500, $1501, $1502, $1505, $1506, $1507, $1508, $1509, $1510, $1511, $1512, $1600, $1601, $1700, $1800, $1801,
      $1802, $1803, $2001, $2002, $2003, $2004, $2500, $2501, $2550, $2600, $2610, $2700, $2701, $2750, $2760, $2810)
}

rule QuarianCode: Quarian Family {
  meta:
    description   = "Quarian code features"
    author        = "Seth Hardy"
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

rule RooterStrings: Rooter Family {
  meta:
    description   = "Rooter Identifying Strings"
    author        = "Seth Hardy"
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

rule with_sqlite: sqlite {
  meta:
    author      = "Julian J. Gonzalez <info@seguridadparatodos.es>"
    reference   = "http://www.st2labs.com"
    description = "Rule to detect the presence of SQLite data in raw image"

  strings:
    $hex_string = { 53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00 }

  condition:
    all of them
}

rule RSharedStrings: Surtr Family {
  meta:
    description  = "identifiers for remote and gmremote"
    author       = "Katie Kleemola"
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

rule WarpStrings: Warp Family {
  meta:
    description   = "Warp Identifying Strings"
    author        = "Seth Hardy"
    last_modified = "2014-07-10"

  strings:
    $ = "/2011/n325423.shtml?"
    $ = "wyle"
    $ = "\\~ISUN32.EXE"

  condition:
    any of them
}

rule WimmieStrings: Wimmie Family {
  meta:
    description   = "Strings used by Wimmie"
    author        = "Seth Hardy"
    last_modified = "2014-07-17"

  strings:
    $ = "\x00ScriptMan"
    $ = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" wide ascii
    $ = "ProbeScriptFint" wide ascii
    $ = "ProbeScriptKids"

  condition:
    any of them

}

rule Bolonyokte: rat {
  meta:
    description = "UnknownDotNet RAT - Bolonyokte"
    author      = "Jean-Philippe Teissier / @Jipe_"
    date        = "2013-02-01"
    filetype    = "memory"
    version     = "1.0"

  strings:
    $campaign1 = "Bolonyokte" ascii wide
    $campaign2 = "donadoni" ascii wide

    $decoy1 = "nyse.com" ascii wide
    $decoy2 = "NYSEArca_Listing_Fees.pdf" ascii wide
    $decoy3 = "bf13-5d45cb40" ascii wide

    $artifact1 = "Backup.zip" ascii wide
    $artifact2 = "updates.txt" ascii wide
    $artifact3 = "vdirs.dat" ascii wide
    $artifact4 = "default.dat"
    $artifact5 = "index.html"
    $artifact6 = "mime.dat"

    $func1 = "FtpUrl"
    $func2 = "ScreenCapture"
    $func3 = "CaptureMouse"
    $func4 = "UploadFile"

    $ebanking1  = "Internet Banking" wide
    $ebanking2  = "(Online Banking)|(Online banking)"
    $ebanking3  = "(e-banking)|(e-Banking)" nocase
    $ebanking4  = "login"
    $ebanking5  = "en ligne" wide
    $ebanking6  = "bancaires" wide
    $ebanking7  = "(eBanking)|(Ebanking)" wide
    $ebanking8  = "Anmeldung" wide
    $ebanking9  = "internet banking" nocase wide
    $ebanking10 = "Banking Online" nocase wide
    $ebanking11 = "Web Banking" wide
    $ebanking12 = "Power"

  condition:
    any of ($campaign*) or 2 of ($decoy*) or 2 of ($artifact*) or all of ($func*) or 3 of ($ebanking*)
}

rule Cerberus: RAT memory {
  meta:
    description = "Cerberus"
    author      = "Jean-Philippe Teissier / @Jipe_"
    date        = "2013-01-12"
    filetype    = "memory"
    version     = "1.0"

  strings:
    $checkin    = "Ypmw1Syv023QZD"
    $clientpong = "wZ2pla"
    $serverping = "wBmpf3Pb7RJe"
    $generic    = "cerberus" nocase

  condition:
    any of them
}

rule JavaDropper: RAT {
  meta:
    author   = " Kevin Breen <kevin@techanarchy.net>"
    date     = "2015/10"
    ref      = "http://malwareconfig.com/stats/AlienSpy"
    maltype  = "Remote Access Trojan"
    filetype = "exe"

  strings:
    $jar = "META-INF/MANIFEST.MF"

    $a1 = "ePK"
    $a2 = "kPK"

    $b1 = "config.ini"
    $b2 = "password.ini"

    $c1 = "stub/stub.dll"

    $d1 = "c.dat"

  condition:
    $jar and (all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*))
}

rule xtreme_rat: Trojan {
  meta:
    author      = "Kevin Falcoz"
    date        = "23/02/2013"
    description = "Xtreme RAT"

  strings:
    $signature1 = { 58 00 54 00 52 00 45 00 4D 00 45 }  /*X.T.R.E.M.E*/

  condition:
    $signature1
}

rule maldoc_getEIP_method_1: maldoc {
  meta:
    author = "Didier Stevens (https://DidierStevens.com)"

  strings:
    $a = { E8 00 00 00 00 (58 | 59 | 5A | 5B | 5C | 5D | 5E | 5F) }

  condition:
    not IsPeFile and $a
}

rule misc_no_dosmode_header: suspicious {
  meta:
    author      = "Jason Batchelor"
    created     = "2016-03-02"
    modified    = "2016-03-02"
    university  = "Carnegie Mellon University"
    description = "Detect on absence of 'DOS Mode' heaader between MZ and PE boundries"

  strings:
    $dosmode = "This program cannot be run in DOS mode."

  condition:
    // (0 .. (uint32(0x3C))) = between end of MZ and start of PE headers
    // 0x3C = e_lfanew = offset of PE header
    IsPeFile and not $dosmode in (0x3C..(uint32(0x3C)))
}

rule embedded_archive_cab: info embedded archive cab windows {
  meta:
    //author = "@h3x2b <tracker _AT h3x.eu>"
    description = "Detect CAB archive"

  strings:
    $mscf_h3xstring = { 4D 53 43 46 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 }

  condition:
    //MSCF on the beginning of cab file foolowed by resered zeroes
    $mscf_h3xstring
}

rule executable_au3: info compiler autit {
  meta:
    // author = "@h3x2b <tracker _AT h3x.eu>"
    description = "Match AU3 autoit executables"

  strings:
    $str_au3_01 = "AU3"
    $str_au3_02 = { A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D }

  condition:
    all of them
}

rule dotnet_libraries: info compiler dotnet {
  meta:
    // author = "@h3x2b <tracker _AT h3x.eu>"
    description = ".Net runtime mscoree.dll mscorwks.dll"

  strings:
    $str_dn_01 = "mscoree.dll"
    $str_dn_02 = "_CorExeMain"
    $str_dn_03 = "mscorwks.dll"
    $str_dn_04 = "CoInitializeEE"

  condition:
    2 of ($str_dn_*)

}

rule executable_elf32: info executable linux {
  meta:
    author      = "@h3x2b <tracker _AT h3x.eu>"
    description = "Detect ELF 32 bit executable"

  condition:
    //ELF magic
    uint32(0) == 0x464c457f and
    uint8(4) == 0x01
}

rule executable_elf64: info executable linux {
  meta:
    author      = "@h3x2b <tracker _AT h3x.eu>"
    description = "Detect ELF 64 bit executable"

  condition:
    //ELF magic
    uint32(0) == 0x464c457f and
    uint8(4) == 0x02
}

rule winsocks: feature networking windows {
  meta:
    description = "Imports Winsock Library"

  condition:
    // MZ at the beginning of file
    uint16(0) == 0x5a4d and

    pe.imports("wsock32.dll", "WSAStartup") and
    pe.imports("wsock32.dll", "socket")
}

rule obfuscation_singlebyte_mov: feature obfuscation {
  meta:
    author      = "Andreas Schuster"
    description = "Detects strings obfuscated by single-byte mov ex: mov [ebp+String+1], A"
  //Check also:
  //https://insights.sei.cmu.edu/sei_blog/2012/11/writing-effective-yara-signatures-to-identify-malware.html

  strings:
    $singleb_mov = { c6 45 [2] c6 45 [2] c6 45 [2] c6 45 }

  condition:
    //Contains all of the strings
    all of them
}

rule plugx_loader_apphelp: APT {
  meta:
    description = "Identify the PlugX side loader used to trojan legit software like KMPlayer"
    author      = "@h3x2b <tracker _AT h3x.eu>"

  strings:
    $yes_s1 = "RtlUnwind"
    $yes_s2 = "LoadLibraryA"
    $no_s1  = "ApphelpUpdateCacheEntry"

  condition:
    // file_type contains "pedll"
    uint16(0) == 0x5a4d
    and pe.characteristics & pe.DLL

    and all of ($yes_*)
    and not $no_s1

  //and file_name contains "apphelp.dll"
}

rule visual_basic_5_6: Compiler {
  meta:
    author      = "Kevin Falcoz"
    date_create = "24/02/2013"
    description = "Miscrosoft Visual Basic 5.0/6.0"

  strings:
    $str1 = { 68 ?? ?? ?? 00 E8 ?? FF FF FF 00 00 ?? 00 00 00 30 00 00 00 ?? 00 00 00 00 00 00 00 [16] 00 00 00 00 00 00 01 00 }

  condition:
    $str1 at (pe.entry_point)
}

rule visual_studio_net: Compiler {
  meta:
    author      = "Kevin Falcoz"
    date_create = "24/02/2013"
    description = "Miscrosoft Visual Studio .NET/C#"

  strings:
    $str1 = { FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }  /*EntryPoint*/

  condition:
    $str1 at (pe.entry_point)
}

rule visual_c_plus_plus_6: Compiler {
  meta:
    author      = "Kevin Falcoz"
    date_create = "25/02/2013"
    description = "Miscrosoft Visual C++ 6.0"

  strings:
    $str1 = { 55 8B EC 6A FF 68 [3] 00 68 [3] 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC [1] 53 56 57 89 65 E8 }  /*EntryPoint*/

  condition:
    $str1 at (pe.entry_point)
}

rule upx_3: Packer {
  meta:
    author      = "Kevin Falcoz"
    date_create = "25/02/2013"
    description = "UPX 3.X"

  strings:
    $str1 = { 60 BE 00 [2] 00 8D BE 00 [2] FF [1-12] EB 1? 90 90 90 90 90 [1-3] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 }

  condition:
    $str1 at (pe.entry_point)
}

rule DebuggerCheck__API: AntiDebug DebuggerCheck {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = "IsDebuggerPresent"

  condition:
    any of them
}

rule DebuggerTiming__PerformanceCounter: AntiDebug DebuggerTiming {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = "QueryPerformanceCounter"

  condition:
    any of them
}

rule DebuggerTiming__Ticks: AntiDebug DebuggerTiming {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = "GetTickCount"

  condition:
    any of them
}

rule DebuggerOutput__String: AntiDebug DebuggerOutput {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = "OutputDebugString"

  condition:
    any of them
}

rule DebuggerException__UnhandledFilter: AntiDebug DebuggerException {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = "SetUnhandledExceptionFilter"

  condition:
    any of them
}

rule DebuggerPattern__SEH_Saves: AntiDebug DebuggerPattern {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = { 64 ff 35 00 00 00 00 }

  condition:
    any of them
}

rule GenerateTLSClientHelloPacket_Test: sharedcode {
  meta:
    copyright = "2015 Novetta Solutions"
    author    = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
    Source    = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

  strings:
    /*
    	25 07 00 00 80  and     eax, 80000007h
    	79 05           jns     short loc_405EC8; um, nope.. this will always happen
    	48              dec     eax
    	83 C8 F8        or      eax, 0FFFFFFF8h
    	40              inc     eax
    */

    $a = {
      25 07 00 00 80
      79 ??
      4?
      83 ?? F8
      4?
    }

  condition:
    $a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule IDAnt_wanna: antidissemble antianalysis {
  meta:
    author      = "Tim 'diff' Strazzere <diff@sentinelone.com><strazz@gmail.com>"
    reference   = "https://sentinelone.com/blogs/breaking-and-evading/"
    filetype    = "elf"
    description = "Detect a misalligned program header which causes some analysis engines to fail"
    version     = "1.0"
    date        = "2015-12"

  condition:
    for any i in (0..elf.segments.len() - 1): (elf.segments[i].offset >= filesize) and elf.sections.len() == 0 and elf.sh_entry_size == 0
}

rule IsPE32: PECheck {
  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint16(uint32(0x3C) + 0x18) == 0x010B
}

rule IsPE64: PECheck {
  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint16(uint32(0x3C) + 0x18) == 0x020B
}

rule IsNET_EXE: PECheck {
  condition:
    pe.imports("mscoree.dll", "_CorExeMain")
}

rule IsNET_DLL: PECheck {
  condition:
    pe.imports("mscoree.dll", "_CorDllMain")
}

rule IsDLL: PECheck {
  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    (uint16(uint32(0x3C) + 0x16) & 0x2000) == 0x2000

}

rule IsConsole: PECheck {
  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint16(uint32(0x3C) + 0x5C) == 0x0003
}

rule IsWindowsGUI: PECheck {
  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint16(uint32(0x3C) + 0x5C) == 0x0002
}

rule IsPacked: PECheck {
  meta:
    description = "Entropy Check"

  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint32(uint32(0x3C)) == 0x00004550 and
    math.entropy(0, filesize) >= 7.0
}

rule HasOverlay: PECheck {
  meta:
    author      = "_pusher_"
    description = "Overlay Check"

  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint32(uint32(0x3C)) == 0x00004550 and
    //stupid check if last section is 0
    //not (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x0 and

    (pe.sections[pe.sections.len() - 1].raw_data_offset + pe.sections[pe.sections.len() - 1].raw_data_size) < filesize

}

rule HasDigitalSignature: PECheck {
  meta:
    author      = "_pusher_"
    description = "DigitalSignature Check"
    date        = "2016-07"

  strings:
    //size check is wildcarded
    $a0 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0B 30 09 06 05 2B 0E 03 02 1A 05 00 30 68 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 5A 30 58 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 }
    $a1 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0B 30 09 06 05 2B 0E 03 02 1A 05 00 30 ?? 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 ?? 30 ?? 30 ?? 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 ?? 03 01 00 A0 ?? A2 ?? 80 00 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 }
    $a2 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0E 30 ?? 06 ?? ?? 86 48 86 F7 0D 02 05 05 00 30 67 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 59 30 57 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 20 30 0C 06 08 2A 86 48 86 F7 0D 02 05 05 00 04 }
    $a3 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0F 30 ?? 06 ?? ?? 86 48 01 65 03 04 02 01 05 00 30 78 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 6A 30 68 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 }

  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint32(uint32(0x3C)) == 0x00004550 and
    (for any of ($a*): ($ in ((pe.sections[pe.sections.len() - 1].raw_data_offset + pe.sections[pe.sections.len() - 1].raw_data_size)..filesize)))
  //its not always like this:
  //and  uint32(@a0) == (filesize-(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size))
}

rule HasDebugData: PECheck {
  meta:
    author      = "_pusher_"
    description = "DebugData Check"
    date        = "2016-07"

  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint32(uint32(0x3C)) == 0x00004550 and
    //orginal
    //((uint32(uint32(0x3C)+0xA8) >0x0) and (uint32be(uint32(0x3C)+0xAC) >0x0))
    //((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) x64/x32
    (IsPE32 or IsPE64) and
    ((uint32(uint32(0x3C) + 0xA8 + ((uint16(uint32(0x3C) + 0x18) & 0x200) >> 5)) > 0x0) and (uint32be(uint32(0x3C) + 0xAC + ((uint16(uint32(0x3C) + 0x18) & 0x200) >> 5)) > 0x0))
}

rule ImportTableIsBad: PECheck {
  meta:
    author      = "_pusher_ & mrexodia"
    date        = "2016-07"
    description = "ImportTable Check"

  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint32(uint32(0x3C)) == 0x00004550 and
    (IsPE32 or IsPE64) and
    (  //Import_Table_RVA+Import_Data_Size .. cannot be outside imagesize
      ((uint32(uint32(0x3C) + 0x80 + ((uint16(uint32(0x3C) + 0x18) & 0x200) >> 5))) + (uint32(uint32(0x3C) + 0x84 + ((uint16(uint32(0x3C) + 0x18) & 0x200) >> 5)))) > (uint32(uint32(0x3C) + 0x50))
      or
      (((uint32(uint32(0x3C) + 0x80 + ((uint16(uint32(0x3C) + 0x18) & 0x200) >> 5))) + (uint32(uint32(0x3C) + 0x84 + ((uint16(uint32(0x3C) + 0x18) & 0x200) >> 5)))) == 0x0)
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

      or
      //tiny PE files..
      (uint32(0x3C) + 0x80 + ((uint16(uint32(0x3C) + 0x18) & 0x200) >> 5) > filesize)

      //or
      //uint32(uint32(0x3C)+0x80) == 0x21000
      //uint32(uint32(uint32(0x3C)+0x80)) == 0x0
      //pe.imports("", "")
    )
}

rule HasModified_DOS_Message: PECheck {
  meta:
    author      = "_pusher_"
    description = "DOS Message Check"
    date        = "2016-07"

  strings:
    $a0 = "This program must be run under Win32" wide ascii nocase
    $a1 = "This program cannot be run in DOS mode" wide ascii nocase
    //UniLink
    $a2 = "This program requires Win32" wide ascii nocase
    $a3 = "This program must be run under Win64" wide ascii nocase

  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint32(uint32(0x3C)) == 0x00004550 and not
    (for any of ($a*): ($ in (0x0..uint32(0x3c))))
}

rule HasRichSignature: PECheck {
  meta:
    author      = "_pusher_"
    description = "Rich Signature Check"
    date        = "2016-07"

  strings:
    $a0 = "Rich" ascii

  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint32(uint32(0x3C)) == 0x00004550 and
    (for any of ($a*): ($ in (0x0..uint32(0x3c))))
}

rule AdvancedInstaller: Caphyon {
  meta:
    author = "_pusher_"
    date   = "2016-07"

  strings:
    $a0 = "AI_SETUPEXEPATH" wide ascii nocase
    $a1 = "Advanced Installer" wide ascii nocase

  condition:
    $a0 and $a1
}

rule Cabinet_Archive: Microsoft {
  meta:
    author = "_pusher_"
    date   = "2016-09"

  strings:
    $a0 = { 4D 53 43 46 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? 00 00 00 00 00 00 03 01 ?? 00 ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }

  condition:
    any of ($a*)
}

rule InnoSetupInstaller: Jordan Russel {
  meta:
    author = "_pusher_"
    date   = "2015-11"

  strings:
    $a0 = "rDlPtS"
    $a1 = "Inno Setup Setup Data"
    $a2 = "zlb"

  condition:
    $a0 and $a1 and
    $a2 at (pe.sections[pe.sections.len() - 1].raw_data_offset + pe.sections[pe.sections.len() - 1].raw_data_size)
}

rule SFX_CAB: Microsoft {
  meta:
    author = "_pusher_"
    date   = "2016-07"
  //strings:
  //$a0 = "CABINET" fullword wide ascii nocase
  //$a1 = "MSCF" wide ascii nocase
  //"C\x00A\x00B\x00I\x00N\x00E\x00T\x00" or

  condition:
    for any i in (0..pe.resources.len() - 1):
    ((pe.resources[i].name_string == "C\x00A\x00B\x00I\x00N\x00E\x00T\x00" or "CABINET") and uint32be(pe.resources[i].offset) == 0x4D534346)
}

rule DotNET_Reactor: Eziriz {
  meta:
    author = "_pusher_"
    date   = "2016-07"

  strings:
    //needs more work	
    //needs improvements
    $a0 = { 38 02 ?? ?? ?? 26 16 }
    $a1 = "System.Void System.Array::Reverse(System.Array)" fullword wide ascii nocase
    $a2 = "System.Security.Cryptography.SymmetricAlgorithm" fullword wide ascii nocase
    $a3 = "System.Security.Cryptography.AesCryptoServiceProvider" fullword wide ascii nocase

    $b0 = "System.Diagnostics.Process" fullword wide ascii nocase
    $b1 = "System.Diagnostics.StackFrame" fullword wide ascii nocase

    $c0 = "Rijndael" fullword wide ascii nocase
    $c1 = "System.Security.Cryptography" fullword wide ascii nocase
    $c2 = "ICryptoTransform" fullword wide ascii nocase

  condition:
    (pe.imports("mscoree.dll", "_CorExeMain") or pe.imports("mscoree.dll", "_CorDllMain"))
    and
    (
      3 of ($c*)
      or
      2 of ($b*)
      or
      1 of ($a*)
    )
}

rule Nullsoft_NSIS: NullSoft {
  meta:
    author      = "_pusher_"
    description = "Nullsoft Installer"
    date        = "2016-01"
    version     = "0.2"

  strings:
    $c0 = { EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 }
    //older nsis
    $c1 = { 5C 54 65 6D 70 00 00 00 4E 53 49 53 20 45 72 72 6F 72 00 00 FF FF FF FF }

  condition:
    $c0 or $c1
}

rule _7_Zip_Installer: Igor Pavlov {
  meta:
    author = "_pusher_"
    date   = "2015-12"

  strings:
    $a0 = ";!@Install@!" wide ascii nocase
    $a1 = ";!@InstallEnd@!7z" wide ascii nocase
    $a2 = ";!@InstallEnd@!\x0D\x0A7z" wide ascii nocase

  condition:
    $a0 and ($a1 or $a2)

}

rule IsELF32: ELFCheck {
  condition:
    // ELF signature at offset 0 and ...
    uint32(0) == 0x464C457F and
    uint8(0x4) == 0x01
}

rule IsELF64: ELFCheck {
  condition:
    // ELF signature at offset 0 and ...
    uint32(0) == 0x464C457F and
    uint8(0x4) == 0x02
}

rule IsNotPacked: PE ELF Check {
  meta:
    author      = "_pusher_"
    description = "PE & ELF Entropy Check"
    date        = "2017.05"
    version     = "1.0"

  condition:
    // MZ signature at offset 0 and ...
    ((IsPE32 or IsPE64) or (IsELF32 or IsELF64)) and
    math.entropy(0, filesize - pe.overlay.size) < 7.0
}

rule IsResourceLess: PECheck {
  meta:
    description = "PE File has no resources"

  condition:
    (IsPE32 or IsPE64) and (pe.resources.len() == 0)
}

rule NeedsAdminAccess: PECheck {
  meta:
    author      = "_pusher_"
    description = "AdminAccess Signature Check"
    date        = "2017-05"

  strings:
    //weirdo yara bug
    $a0 = "requestedExecutionLevel" fullword ascii nocase
    $a1 = "level=\"requireAdministrator" fullword ascii nocase
    $a2 = "level=\"highestAvailable" fullword ascii nocase

  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint32(uint32(0x3C)) == 0x00004550 and
    $a0 and ($a1 or $a2)
}

rule UPX_v0896_v102_v105_v122_Delphi_stub_additional: PEiD {
  strings:
    $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B }

  condition:
    $a at pe.entry_point

}

rule PackerUPX_CompresorGratuito_wwwupxsourceforgenet: PEiD {
  strings:
    $a = { 60 BE ?? ?0 ?? 00 8D BE ?? ?? F? FF }

  condition:
    $a at pe.entry_point

}

rule Borland_Delphi_40_additional: PEiD {
  strings:
    $a = { 55 8B EC 83 C4 }

  condition:
    $a at pe.entry_point

}

rule Armadillo_v171: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 }
    condition:
        $a at pe.entry_point

}

rule Safeguard_103_Simonzh: PEiD {
  strings:
    $a = { E8 ?? 00 00 00 }

  condition:
    $a at pe.entry_point

}

rule UPX_wwwupxsourceforgenet_additional: PEiD {
  strings:
    $a = { 60 BE ?? ?? ?? 00 8D BE ?? ?? ?? FF }

  condition:
    $a at pe.entry_point

}

rule Microsoft_Visual_Cpp_v50v60_MFC_additional: PEiD {
  strings:
    $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 }

  condition:
    $a at pe.entry_point

}

rule Visual_Cpp_2005_DLL_Microsoft: PEiD {
  strings:
    $a = { 8B FF 55 8B EC 83 7D 0C 01 }

  condition:
    $a at pe.entry_point

}

rule MSLRH_V031_emadicius: PEiD {
  strings:
    $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B }
    $b = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Microsoft_Visual_Cpp_v50v60_MFC: PEiD {
  strings:
    $a = { 55 8B EC ?? }
    $b = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Microsoft_Visual_Studio_NET: PEiD {
  strings:
    $a = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a at pe.entry_point

}

rule Microsoft_Visual_C_v70_Basic_NET_additional: PEiD {
  strings:
    $a = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a at pe.entry_point

}

rule Borland_Delphi_30_additional: PEiD {
  strings:
    $a = { 55 8B EC 83 }

  condition:
    $a at pe.entry_point

}

rule UPX_v0896_v102_v105_v122_Delphi_stub: PEiD {
  strings:
    $a = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 ?? ?? ?? 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 }
    $b = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Borland_Delphi_Setup_Module: PEiD {
  strings:
    $a = { 55 8B EC 83 C4 }
    $b = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Netopsystems_FEAD_Optimizer_1: PEiD {
  strings:
    $a = { 60 BE 00 ?? ?? 00 8D BE 00 ?? ?? FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }

  condition:
    $a at pe.entry_point

}

rule UPX_290_LZMA: PEiD {
  strings:
    $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
    $b = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Microsoft_Visual_C_Basic_NET: PEiD {
  strings:
    $a = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }
    $b = { FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Borland_Delphi_v40_v50: PEiD {
  strings:
    $a = { 55 8B EC 83 }
    $b = { 50 6A 00 E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Visual_Cpp_2003_DLL_Microsoft: PEiD {
  strings:
    $a = { 8B FF 55 8B EC }

  condition:
    $a at pe.entry_point

}

rule UPX_290_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD {
  strings:
    $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 }
    $b = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Microsoft_Visual_C_v70_Basic_NET: PEiD {
  strings:
    $a = { 53 55 56 8B 74 24 14 85 F6 57 B8 }
    $b = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Microsoft_Visual_Cpp_80: PEiD {
  strings:
    $a = { 83 3D ?? ?? ?? ?? 00 74 1A 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 59 74 0B FF 74 24 04 FF 15 ?? ?? ?? ?? 59 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 59 59 75 54 56 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 8B C6 BF }
    $b = { 83 3D ?? ?? ?? ?? 00 74 1A 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 59 74 0B FF 74 24 04 FF 15 ?? ?? ?? ?? 59 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 59 59 75 54 56 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 8B C6 BF ?? ?? ?? ?? 3B C7 59 73 0F 8B 06 85 C0 74 02 FF D0 83 C6 04 3B F7 72 F1 }
    $c = { 48 83 EC 28 E8 ?? ?? 00 00 48 83 C4 28 E9 ?? ?? FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC CC }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Microsoft_Visual_Cpp: PEiD {
  strings:
    $a = { 8B 44 24 08 83 }
    $b = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule UPX_290_LZMA_additional: PEiD {
  strings:
    $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }

  condition:
    $a at pe.entry_point

}

rule UPX_wwwupxsourceforgenet: PEiD {
  strings:
    $a = { 60 BE ?? ?? ?? 00 8D BE ?? ?? ?? FF }
    $b = { 60 BE ?? ?0 ?? 00 8D BE ?? ?? F? FF }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Netopsystems_FEAD_Optimizer: PEiD {
  strings:
    $a = { E8 00 00 00 00 58 BB 00 00 40 00 8B }
    $b = { 60 BE 00 50 43 00 8D BE 00 C0 FC FF }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Borland_Delphi_v30: PEiD {
  strings:
    $a = { 55 8B EC 83 }
    $b = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 55 8B EC 33 C0 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Borland_Delphi_DLL: PEiD {
  strings:
    $a = { 55 8B EC 83 }
    $b = { 55 8B EC 83 C4 B4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 40 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule Microsoft_Visual_Cpp_80_DLL: PEiD {
  strings:
    $a = { 48 83 EC 28 83 FA 01 48 89 5C 24 38 48 89 74 24 40 48 89 7C 24 48 ?? ?? ?? 8B ?? ?? 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 }
    $b = { 48 83 EC 28 }

  condition:
    for any of ($*): ($ at pe.entry_point)

}

rule DebuggerPattern__RDTSC: AntiDebug DebuggerPattern {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = { 0F 31 }

  condition:
    any of them
}

rule DebuggerPattern__CPUID: AntiDebug DebuggerPattern {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = { 0F A2 }

  condition:
    any of them
}

rule DebuggerPattern__SEH_Inits: AntiDebug DebuggerPattern {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = { 64 89 25 00 00 00 00 }

  condition:
    any of them
}

rule vmdetect_misc0: vmdetect {
  meta:
    author      = "@abhinavbom"
    maltype     = "NA"
    version     = "0.1"
    date        = "31/10/2015"
    description = "Following Rule is referenced from AlienVault's Yara rule repository.This rule contains additional processes and driver names."

  strings:
    $vbox1             = "VBoxService" nocase ascii wide
    $vbox2             = "VBoxTray" nocase ascii wide
    $vbox3             = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase ascii wide
    $vbox4             = "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions" nocase ascii wide
    $wine1             = "wine_get_unix_file_name" ascii wide
    $vmware1           = "vmmouse.sys" ascii wide
    $vmware2           = "VMware Virtual IDE Hard Drive" ascii wide
    $miscvm1           = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase ascii wide
    $miscvm2           = "SYSTEM\\\\ControlSet001\\\\Services\\\\Disk\\\\Enum" nocase ascii wide
    // Drivers
    $vmdrv1            = "hgfs.sys" ascii wide
    $vmdrv2            = "vmhgfs.sys" ascii wide
    $vmdrv3            = "prleth.sys" ascii wide
    $vmdrv4            = "prlfs.sys" ascii wide
    $vmdrv5            = "prlmouse.sys" ascii wide
    $vmdrv6            = "prlvideo.sys" ascii wide
    $vmdrv7            = "prl_pv32.sys" ascii wide
    $vmdrv8            = "vpc-s3.sys" ascii wide
    $vmdrv9            = "vmsrvc.sys" ascii wide
    $vmdrv10           = "vmx86.sys" ascii wide
    $vmdrv11           = "vmnet.sys" ascii wide
    // SYSTEM\ControlSet001\Services
    $vmsrvc1           = "vmicheartbeat" ascii wide
    $vmsrvc2           = "vmicvss" ascii wide
    $vmsrvc3           = "vmicshutdown" ascii wide
    $vmsrvc4           = "vmicexchange" ascii wide
    $vmsrvc5           = "vmci" ascii wide
    $vmsrvc6           = "vmdebug" ascii wide
    $vmsrvc7           = "vmmouse" ascii wide
    $vmsrvc8           = "VMTools" ascii wide
    $vmsrvc9           = "VMMEMCTL" ascii wide
    $vmsrvc10          = "vmware" ascii wide
    $vmsrvc11          = "vmx86" ascii wide
    $vmsrvc12          = "vpcbus" ascii wide
    $vmsrvc13          = "vpc-s3" ascii wide
    $vmsrvc14          = "vpcuhub" ascii wide
    $vmsrvc15          = "msvmmouf" ascii wide
    $vmsrvc16          = "VBoxMouse" ascii wide
    $vmsrvc17          = "VBoxGuest" ascii wide
    $vmsrvc18          = "VBoxSF" ascii wide
    $vmsrvc19          = "xenevtchn" ascii wide
    $vmsrvc20          = "xennet" ascii wide
    $vmsrvc21          = "xennet6" ascii wide
    $vmsrvc22          = "xensvc" ascii wide
    $vmsrvc23          = "xenvdb" ascii wide
    // Processes
    $miscproc1         = "vmware2" ascii wide
    $miscproc2         = "vmount2" ascii wide
    $miscproc3         = "vmusrvc" ascii wide
    $miscproc4         = "vmsrvc" ascii wide
    $miscproc5         = "vboxservice" ascii wide
    $miscproc6         = "vboxtray" ascii wide
    $miscproc7         = "xenservice" ascii wide
    $vmware_mac_1a     = "00-05-69"
    $vmware_mac_1b     = "00:05:69"
    $vmware_mac_2a     = "00-50-56"
    $vmware_mac_2b     = "00:50:56"
    $vmware_mac_3a     = "00-0C-29"
    $vmware_mac_3b     = "00:0C:29"
    $vmware_mac_4a     = "00-1C-14"
    $vmware_mac_4b     = "00:1C:14"
    $virtualbox_mac_1a = "08-00-27"
    $virtualbox_mac_1b = "08:00:27"

  condition:
    2 of them
}

rule ttp_pe_size_of_code_gt_filesize: ttp {
  meta:
    author      = "stvemillertime"
    description = "where size_of_code IMAGE_OPTIONAL_HEADER::SizeOfCode is larger than the actual file size. weird."
    hash        = "3dc11072110077584b00003536d0f3ba"

  condition:
    uint16be(0) == 0x4d5a
    and pe.size_of_code > filesize
}

rule maldoc_find_kernel32_base_method_1: maldoc {
  meta:
    author = "Didier Stevens (https://DidierStevens.com)"

  strings:
    $a1 = { 64 8B (05 | 0D | 15 | 1D | 25 | 2D | 35 | 3D) 30 00 00 00 }
    $a2 = { 64 A1 30 00 00 00 }

  condition:
    any of them
}

rule OLETitle: Title OLEMetadata {
  meta:
    description   = "Identifier for known OLE document titles"
    author        = "Seth Hardy"
    last_modified = "2014-05-07"

  strings:
    $ = "\x0001:00\x00\x1e"
    $ = "\x00    23-Aprel  chushidin keyin saet bir yirim,Xitayning 3 neper paylaqchisi seriqbuya yezida oy arilap yurup paylaqchiliq qiliwatqanda bir oyge toplann\xcaghan bir gurup uyghur yashlarni korgen we ularning yenida pichaq we tam teshidighan eswablarni korup gum\x00\x1e"
    $ = "\x0046-120603   fice W648\x00\x1e"
    $ = "\x0054-120602   15s\xb7K\x0c]\xb7\x00\x1e"
    $ = "\x005-Iyul Urumchi Qirghinchiliqi heqide qisqiche Dokilat \x00\x1e"
    $ = "\x00April 20-21, 2013\x00\x1e"
    $ = "\x00asdfasdfasdf\x00\x1e"
    $ = "\x00Bamako, le 04 d\x00\x1e"
    $ = "\x00Best\x00\x1e"
    $ = "\x00Dear All,\x00\x1e"
    $ = "\x00Dear President and Executive Members,\x00\x1e"
    $ = "\x00Full list of self-immolations in Tibet\x00\x1e"
    $ = "\x00Help stop the destruction of my home, Lhasa, Tibet\x00\x1e"
    $ = "\x00HHDL'visit in European\x00\x1e"
    $ = "\x00II) Overview & Analysis:\x00\x1e"
    $ = "\x00Institute for Defence Studies and Analyses\x00\x1e"
    $ = "\x00IPT  APPLICATION FORM\x00\x1e"
    $ = "\x00Jharkhand supports Indian Parliamentary resolution on Tibet crisis\x00\x1e"
    $ = "\x00Lieutenant General KENOSE BARRY PHILLIPE,\x00\x1e"
    $ = "\x00OPERATIONAL MANUAL:\x00\x1e"
    $ = "\x00PART 2 - Overview and Analysis\x00\x1e"
    $ = "\x00PowerPoint Presentation\x00\x1e"
    $ = "\x00Progress Chart: 15\x00\x1e"
    $ = "\x00Progress Chart:\x00\x1e"
    $ = "\x00Progress Chart\x00\x1e"
    $ = "\x00RC\x00\x1e"
    $ = "\x00(RESENDING)\x00\x1e"
    $ = "\x00Talking Points EU-China Human Rights Dialogue June 2011\x00\x1e"
    $ = "\x00TANC Community Center\x00\x1e"
    $ = "\x00The Charg\x00\x1e"
    $ = "\x00The following schedule of plans has been finalized for the purpose of holding the Second Special General Meeting of Tibetans being organized jointly by the Tibetan Parliament-in-Exile and the Kashag headed by the Kalon Tripa in accordance with the provis\x00\x1e"
    $ = "\x00The Tibet Museum Project\x00\x1e"
    $ = "\x00Tibetan Community in Switzerland & Liechtenstein, Binzstrasse 15, CH-8045 Zurich, Switzerland \x00\x1e"
    $ = "\x00TSERING BHUTI\x00\x1e"
    $ = "\x00Tsering Bhuti\x00\x1e"
    $ = "\x00 \x00\x1e"
    $ = "\x00#\x00\x1e"
    $ = "\x00\x8d\x00\x1e"
    $ = "\x00\x8d\x9a\x06\xb7\x00\x1e"
    $ = "\x00\xc8\xf8!\xb7\x00\x1e"
    $ = "\x00Yes, I would like to raise this point: how many more young Tibetan lives are to be sacrificed in these awful self immolations before China is likely to change its Tibet policies in favour of Tibetan autonomy\x00\x1e"

  condition:
    IsOLE and (any of them)
}

rule android_meterpreter: android {
  meta:
    author  = "73mp74710n"
    ref     = "https://github.com/zombieleet/yara-rules/blob/master/android_metasploit.yar"
    comment = "Metasploit Android Meterpreter Payload"

  strings:
    $checkPK        = "META-INF/PK"
    $checkHp        = "[Hp^"
    $checkSdeEncode = /;.Sk/
    $stopEval       = "eval"
    $stopBase64     = "base64_decode"

  condition:
    any of ($check*) or any of ($stop*)
}

rule invalid_trailer_structure: PDF raw {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    weight  = 1

  strings:
    $magic = "%PDF"
    // Required for a valid PDF
    $reg0  = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
    $reg1  = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

  condition:
    $magic in (0..1024) and not $reg0 and not $reg1
}

rule multiple_versions: PDF raw {
  meta:
    author      = "Glenn Edwards (@hiddenillusion)"
    version     = "0.1"
    description = "Written very generically and doesn't hold any weight - just something that might be useful to know about to help show incremental updates to the file being analyzed"
    weight      = 1

  strings:
    $magic = "%PDF"
    $s0    = "trailer"
    $s1    = "%%EOF"

  condition:
    $magic in (0..1024) and #s0 > 1 and #s1 > 1
}

rule maldoc_function_prolog_signature : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {55 8B EC 81 EC}
        $a2 = {55 8B EC 83 C4}
        $a3 = {55 8B EC E8}
        $a4 = {55 8B EC E9}
        $a5 = {55 8B EC EB}
    condition:
        any of them
}

rule RTF_Shellcode: maldoc {
  meta:
    author      = "RSA-IR – Jared Greenhill"
    date        = "01/21/13"
    description = "identifies RTF's with potential shellcode"
    filetype    = "RTF"

  strings:
    $rtfmagic = "{\\rtf"
    /* $scregex=/[39 30]{2,20}/ */
    $scregex  = /(90){2,20}/

  condition:
    ($rtfmagic at 0) and ($scregex)
}

rule Armadillo_v171_additional: PEiD {
  strings:
    $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 }

  condition:
    $a at pe.entry_point

}

rule without_images: mail {
  meta:
    author      = "Antonio Sanchez <asanchez@hispasec.com>"
    reference   = "http://laboratorio.blogs.hispasec.com/"
    description = "Rule to detect the no presence of any image"

  strings:
    $eml_01 = "From:"
    $eml_02 = "To:"
    $eml_03 = "Subject:"

    $a = ".jpg" nocase
    $b = ".png" nocase
    $c = ".bmp" nocase

  condition:
    all of ($eml_*) and
    not $a and not $b and not $c
}

rule with_urls: mail {
  meta:
    author      = "Antonio Sanchez <asanchez@hispasec.com>"
    reference   = "http://laboratorio.blogs.hispasec.com/"
    description = "Rule to detect the presence of an or several urls"

  strings:
    $eml_01 = "From:"
    $eml_02 = "To:"
    $eml_03 = "Subject:"

    $url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/

  condition:
    all of them
}

rule mimikatz: FILE {
  meta:
    description = "mimikatz"
    author      = "Benjamin DELPY (gentilkiwi)"
    tool_author = "Benjamin DELPY (gentilkiwi)"
    modified    = "2022-11-16"

  strings:
    $exe_x86_1 = { 89 71 04 89 [0-3] 30 8d 04 bd }
    $exe_x86_2 = { 8b 4d e? 8b 45 f4 89 75 e? 89 01 85 ff 74 }

    $exe_x64_1 = { 33 ff 4? 89 37 4? 8b f3 45 85 c? 74 }
    $exe_x64_2 = { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }

    /*
          $dll_1         = { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
          $dll_2         = { c7 0? 10 02 00 00 ?? 89 4? }
    */

    $sys_x86 = { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
    $sys_x64 = { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

  condition:
    (all of ($exe_x86_*)) or (all of ($exe_x64_*))
    // or (all of ($dll_*))
    or (any of ($sys_*))
}

rule crypto_LM_DES: info crypto {
  meta:
    description = "String constant 'KGS!@#$%' used in LM DES"

  strings:
    $lm_des = "KGS!@#$%"

  condition:
    all of them
}

rule executable_pe: info executable windows {
  meta:
    //author = "@h3x2b <tracker _AT h3x.eu>"
    description = "Detect PE executable based on MZ and PE magic"

  strings:
    $pe = "PE"

  condition:
    //MZ on the beginning of file
    uint16be(0) == 0x4d5a and
    //PE at offset given by 0x3c
    ($pe at (uint32(0x3c)))
}

rule dll_injection_thread: suspicious feature dll injection windows {
  meta:
    description = "Injection using kernel32.dll:VirtualAllocEx"
    link        = "http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html"

  strings:
    $load_01 = "LoadLibraryA"

    $remote_01 = "NtCreateThreadEx"

  condition:
    // MZ at the beginning of file
    uint16be(0) == 0x4d5a and

    // Access other process
    //(
    //	pe.imports("kernel32.dll","OpenProcess")
    //) and

    // Allocate memory in remote process
    (
      pe.imports("kernel32.dll", "VirtualAllocEx")
    ) and

    // Write code section to the remote process
    (
      pe.imports("kernel32.dll", "WriteProcessMemory") or
      pe.imports("kernel32.dll", "LoadLibraryExA") or
      pe.imports("kernel32.dll", "LoadLibraryExW") or
      (
        pe.imports("kernel32.dll", "GetProcAddress") and
        (pe.imports("kernel32.dll", "GetModuleHandleA") or pe.imports("kernel32.dll", "GetModuleHandleA")) and
        $load_01
      )
    ) and

    //Execute
    (
      pe.imports("kernel32.dll", "CreateRemoteThread") or
      pe.imports("ntdll.dll", "NtCreateThreadEx") or
      (
        pe.imports("kernel32.dll", "GetProcAddress") and
        (pe.imports("kernel32.dll", "GetModuleHandleA") or pe.imports("kernel32.dll", "GetModuleHandleA")) and
        $remote_01
      )
    )

}

rule dll_injection_hook: suspicious feature dll injection windows {
  meta:
    description = "Injection using User32.dll:VirtualAllocEx"

  condition:
    // MZ at the beginning of file
    uint16(0) == 0x5a4d and

    (
      pe.imports("user32.dll", "SetWindowsHookExA") or
      pe.imports("user32.dll", "SetWindowsHookExW")
    )
}

rule math_entropy_close_8: info statistics {
  meta:
    description = "Very high entropy - random stream, packed data or encryption"

  condition:
    math.entropy(0, filesize) >= 7.5
}

rule math_entropy_7: info statistics {
  meta:
    description = "High entropy - probably random stream, packed data or encryption"

  condition:
    math.entropy(0, filesize) >= 7 and
    math.entropy(0, filesize) < 7.5
}

rule math_entropy_6: info statistics {
  meta:
    description = "High entropy - like binary code or base64 encoded random stream"

  condition:
    math.entropy(0, filesize) >= 6 and
    math.entropy(0, filesize) < 7
}

rule math_entropy_5: info statistics {
  meta:
    description = "Medium entropy - like binary data"

  condition:
    math.entropy(0, filesize) >= 5 and
    math.entropy(0, filesize) < 6
}

rule math_entropy_4: info statistics {
  meta:
    description = "Low entropy - like plaintext or HTML or sparse data"

  condition:
    math.entropy(0, filesize) >= 4 and
    math.entropy(0, filesize) < 5
}

rule math_entropy_3: info statistics {
  meta:
    description = "Low entropy - very sparse data or repeating plaintext"

  condition:
    math.entropy(0, filesize) >= 3 and
    math.entropy(0, filesize) < 4
}

rule math_entropy_2: info statistics {
  meta:
    description = "Very low entropy - repeating sequence of couple of bytes"

  condition:
    math.entropy(0, filesize) >= 2 and
    math.entropy(0, filesize) < 3
}

rule math_entropy_1: info statistics {
  meta:
    description = "Very low entropy - repeating 2 bytes"

  condition:
    math.entropy(0, filesize) >= 1 and
    math.entropy(0, filesize) < 2
}

rule math_entropy_0: info statistics {
  meta:
    description = "Very low entropy - all zeroes or same bytes"

  condition:
    math.entropy(0, filesize) >= 0 and
    math.entropy(0, filesize) < 1
}

rule ole_object: info ole windows {
  meta:
    //author = "@h3x2b <tracker _AT h3x.eu>"
    description = "Detect OLE (Object Linking and Embedding)"

  condition:
    //d0cf11e0a1b11ae1 on the beginning of file
    uint32be(0) == 0xd0cf11e0 and
    uint32be(4) == 0xa1b11ae1
}

rule embedded_ole_object: info embedded ole windows {
  meta:
    //author = "@h3x2b <tracker _AT h3x.eu>"
    description = "Detect embedded OLE (Object Linking and Embedding)"

  strings:
    $msdocfile_hexstring = { D0 CF 11 E0 A1 B1 1A E1 }

  condition:
    //DOCFILEALBILAE string anywhere within file
    $msdocfile_hexstring
}

rule upx_sections: info packer upx {
  meta:
    // author = "@h3x2b <tracker _AT h3x.eu>"
    description = "Contains UPX sections"

  strings:
    $str_upx_01 = "UPX0"
    $str_upx_02 = "UPX1"

  condition:
    uint16(0) == 0x5a4d and
    all of ($str_upx_*)
}

rule Detect_EventLogTampering: AntiForensic {
  meta:
    description = "Detect NtLoadDriver and other as anti-forensic"
    author      = "Unprotect"
    comment     = "Experimental rule"

  strings:
    $1 = "NtLoadDriver " fullword ascii
    $2 = "NdrClientCall2" fullword ascii

  condition:
    uint16(0) == 0x5A4D and filesize < 1000KB and any of them
}

rule Detect_SuspendThread: AntiDebug {
  meta:
    description = "Detect SuspendThread as anti-debug"
    author      = "Unprotect"
    comment     = "Experimental rule"

  strings:
    $1 = "UnhandledExcepFilter" fullword ascii
    $2 = "SetUnhandledExceptionFilter" fullword ascii

  condition:
    uint16(0) == 0x5A4D and filesize < 1000KB and any of them
}

rule Detect_GuardPages: AntiDebug {
  meta:
    description = "Detect Guard Pages as anti-debug"
    author      = "Unprotect"
    comment     = "Experimental rule"

  strings:
    $1 = "GetSystemInfo" fullword ascii
    $2 = "VirtualAlloc" fullword ascii
    $3 = "RtlFillMemory" fullword ascii
    $4 = "VirtualProtect" fullword ascii
    $5 = "VirtualFree" fullword ascii

  condition:
    uint16(0) == 0x5A4D and filesize < 1000KB and 4 of them
}

rule Detect_LocalSize: AntiDebug {
  meta:
    description = "Detect LocalSize as anti-debug"
    author      = "Unprotect"
    comment     = "Experimental rule"

  strings:
    $1 = "LocalSize" fullword ascii

  condition:
    uint16(0) == 0x5A4D and filesize < 1000KB and $1
}

rule Detect_NtQueryInformationProcess: AntiDebug {
  meta:
    description = "Detect NtQueryInformationProcess as anti-debug"
    author      = "Unprotect"
    comment     = "Experimental rule"

  strings:
    $1 = "NtQueryInformationProcess" fullword ascii

  condition:
    uint16(0) == 0x5A4D and filesize < 1000KB and $1
}

rule Detect_NtQueryObject: AntiDebug {
  meta:
    description = "Detect NtQueryObject as anti-debug"
    author      = "Unprotect"
    comment     = "Experimental rule"

  strings:
    $1 = "NtQueryObject" fullword ascii

  condition:
    uint16(0) == 0x5A4D and filesize < 1000KB and $1
}

rule Detect_NtSetInformationThread: AntiDebug {
  meta:
    description = "Detect NtSetInformationThread as anti-debug"
    author      = "Unprotect"
    comment     = "Experimental rule"

  strings:
    $1 = "NtSetInformationThread" fullword ascii

  condition:
    uint16(0) == 0x5A4D and filesize < 1000KB and $1
}

rule cn_utf8_windows_terminal: capability hacktool {
  meta:
    author      = "Thomas Barabosch, Deutsche Telekom Security"
    description = "This is a (dirty) hack to display UTF-8 on Windows command prompt."
    date        = "2022-01-14"
    reference   = "https://dev.to/mattn/please-stop-hack-chcp-65001-27db"
    reference2  = "https://www.bitdefender.com/files/News/CaseStudies/study/401/Bitdefender-PR-Whitepaper-FIN8-creat5619-en-EN.pdf"

  strings:
    $a = "chcp 65001" ascii wide

  condition:
    $a
}

rule APT32_KerrDown: apt apt32 winmalware downloader {
  meta:
    Author  = "Adam M. Swanda"
    Website = "https://www.deadbits.org"
    Repo    = "https://github.com/deadbits/yara-rules"
    Date    = "2019-08-08"
    Note    = "List of samples used to create rule at end of file as block comment"

  strings:
    $hijack = "DllHijack.dll" ascii fullword
    $fmain  = "FMain" ascii fullword
    $gfids  = ".gfids" ascii fullword
    $sec01  = ".xdata$x" ascii fullword
    $sec02  = ".rdata$zzzdbg" ascii fullword
    $sec03  = ".rdata$sxdata" ascii fullword

    $str01 = "wdCommandDispatch" ascii fullword
    $str02 = "TerminateProcess" ascii fullword
    $str03 = "IsProcessorFeaturePresent" ascii fullword
    $str04 = "IsDebuggerPresent" ascii fullword
    $str05 = "SetUnhandledExceptionFilter" ascii fullword
    $str06 = "QueryPerformanceCounter" ascii fullword

  condition:
    (uint16(0) == 0x5a4d)
    and
    (
      ($hijack and $fmain and $gfids)
      or
      ($gfids and 6 of them)
    )
}

rule Detect_EnumProcess: AntiDebug {
  meta:
    description = "Detect EnumProcessas anti-debug"
    author      = "Unprotect"
    comment     = "Experimental rule"

  strings:
    $1 = "EnumProcessModulesEx" fullword ascii
    $2 = "EnumProcesses" fullword ascii
    $3 = "EnumProcessModules" fullword ascii

  condition:
    uint16(0) == 0x5A4D and filesize < 1000KB and any of them
}

rule without_attachments: mail {
  meta:
    author      = "Antonio Sanchez <asanchez@hispasec.com>"
    reference   = "http://laboratorio.blogs.hispasec.com/"
    description = "Rule to detect the no presence of any attachment"

  strings:
    $eml_01        = "From:"
    $eml_02        = "To:"
    $eml_03        = "Subject:"
    $attachment_id = "X-Attachment-Id"
    $mime_type     = "Content-Type: multipart/mixed"

  condition:
    all of ($eml_*) and
    not $attachment_id and
    not $mime_type
}

rule Email_Generic_Phishing: email {
  meta:
    Author      = "Tyler <@InfoSecTyler>"
    Description = "Generic rule to identify phishing emails"

  strings:
    $eml_1 = "From:"
    $eml_2 = "To:"
    $eml_3 = "Subject:"

    $greeting_1 = "Hello sir/madam" nocase
    $greeting_2 = "Attention" nocase
    $greeting_3 = "Dear user" nocase
    $greeting_4 = "Account holder" nocase

    $url_1 = "Click" nocase
    $url_2 = "Confirm" nocase
    $url_3 = "Verify" nocase
    $url_4 = "Here" nocase
    $url_5 = "Now" nocase
    $url_6 = "Change password" nocase

    $lie_1 = "Unauthorized" nocase
    $lie_2 = "Expired" nocase
    $lie_3 = "Deleted" nocase
    $lie_4 = "Suspended" nocase
    $lie_5 = "Revoked" nocase
    $lie_6 = "Unable" nocase

  condition:
    all of ($eml*) and
    any of ($greeting*) and
    any of ($url*) and
    any of ($lie*)
}

rule maldoc_OLE_file_magic_number: maldoc {
  meta:
    author = "Didier Stevens (https://DidierStevens.com)"

  strings:
    $a = { D0 CF 11 E0 }

  condition:
    $a
}

rule VM_Generic_Detection: AntiVM {
  meta:
    description = "Tries to detect virtualized environments"

  strings:
    $a0      = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
    $a1      = "HARDWARE\\Description\\System" nocase wide ascii
    $a2      = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation" nocase wide ascii
    $a3      = "SYSTEM\\CurrentControlSet\\Enum\\IDE" nocase wide ascii
    $redpill = { 0F 01 0D 00 00 00 00 C3 }  // Copied from the Cuckoo project

    // CLSIDs used to detect if speakers are present. Hoping this will not cause false positives.
    $teslacrypt1 = { D1 29 06 E3 E5 27 CE 11 87 5D 00 60 8C B7 80 66 }  // CLSID_AudioRender
    $teslacrypt2 = { B3 EB 36 E4 4F 52 CE 11 9F 53 00 20 AF 0B A7 70 }  // CLSID_FilterGraph

  condition:
    any of ($a*) or $redpill or all of ($teslacrypt*)
}

rule VMWare_Detection: AntiVM {
  meta:
    description = "Looks for VMWare presence"
    author      = "Cuckoo project"

  strings:
    $a0       = "VMXh"
    $a1       = "vmware" nocase wide ascii
    $vmware4  = "hgfs.sys" nocase wide ascii
    $vmware5  = "mhgfs.sys" nocase wide ascii
    $vmware6  = "prleth.sys" nocase wide ascii
    $vmware7  = "prlfs.sys" nocase wide ascii
    $vmware8  = "prlmouse.sys" nocase wide ascii
    $vmware9  = "prlvideo.sys" nocase wide ascii
    $vmware10 = "prl_pv32.sys" nocase wide ascii
    $vmware11 = "vpc-s3.sys" nocase wide ascii
    $vmware12 = "vmsrvc.sys" nocase wide ascii
    $vmware13 = "vmx86.sys" nocase wide ascii
    $vmware14 = "vmnet.sys" nocase wide ascii
    $vmware15 = "vmicheartbeat" nocase wide ascii
    $vmware16 = "vmicvss" nocase wide ascii
    $vmware17 = "vmicshutdown" nocase wide ascii
    $vmware18 = "vmicexchange" nocase wide ascii
    $vmware19 = "vmdebug" nocase wide ascii
    $vmware20 = "vmmouse" nocase wide ascii
    $vmware21 = "vmtools" nocase wide ascii
    $vmware22 = "VMMEMCTL" nocase wide ascii
    $vmware23 = "vmx86" nocase wide ascii

    // VMware MAC addresses
    $vmware_mac_1a = "00-05-69" wide ascii
    $vmware_mac_1b = "00:05:69" wide ascii
    $vmware_mac_1c = "000569" wide ascii
    $vmware_mac_2a = "00-50-56" wide ascii
    $vmware_mac_2b = "00:50:56" wide ascii
    $vmware_mac_2c = "005056" wide ascii
    $vmware_mac_3a = "00-0C-29" nocase wide ascii
    $vmware_mac_3b = "00:0C:29" nocase wide ascii
    $vmware_mac_3c = "000C29" nocase wide ascii
    $vmware_mac_4a = "00-1C-14" nocase wide ascii
    $vmware_mac_4b = "00:1C:14" nocase wide ascii
    $vmware_mac_4c = "001C14" nocase wide ascii

    // PCI Vendor IDs, from Hacking Team's leak
    $virtualbox_vid_1 = "VEN_15ad" nocase wide ascii

  condition:
    any of them
}

rule VirtualPC_Detection: AntiVM {
  meta:
    description = "Looks for VirtualPC presence"
    author      = "Cuckoo project"

  strings:
    $a0         = { 0F 3F 07 0B }
    $virtualpc1 = "vpcbus" nocase wide ascii
    $virtualpc2 = "vpc-s3" nocase wide ascii
    $virtualpc3 = "vpcuhub" nocase wide ascii
    $virtualpc4 = "msvmmouf" nocase wide ascii

  condition:
    any of them
}

rule VirtualBox_Detection: AntiVM {
  meta:
    description = "Looks for VirtualBox presence"
    author      = "Cuckoo project"

  strings:
    $virtualbox1  = "VBoxHook.dll" nocase wide ascii
    $virtualbox2  = "VBoxService" nocase wide ascii
    $virtualbox3  = "VBoxTray" nocase wide ascii
    $virtualbox4  = "VBoxMouse" nocase wide ascii
    $virtualbox5  = "VBoxGuest" nocase wide ascii
    $virtualbox6  = "VBoxSF" nocase wide ascii
    $virtualbox7  = "VBoxGuestAdditions" nocase wide ascii
    $virtualbox8  = "VBOX HARDDISK" nocase wide ascii
    $virtualbox9  = "vboxservice" nocase wide ascii
    $virtualbox10 = "vboxtray" nocase wide ascii

    // MAC addresses
    $virtualbox_mac_1a = "08-00-27"
    $virtualbox_mac_1b = "08:00:27"
    $virtualbox_mac_1c = "080027"

    // PCI Vendor IDs, from Hacking Team's leak
    $virtualbox_vid_1 = "VEN_80EE" nocase wide ascii

    // Registry keys
    $virtualbox_reg_1 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase wide ascii
    $virtualbox_reg_2 = /HARDWARE\\ACPI\\(DSDT|FADT|RSDT)\\VBOX__/ nocase wide ascii

    // Other
    $virtualbox_files    = /C:\\Windows\\System32\\drivers\\vbox.{15}\.(sys|dll)/ nocase wide ascii
    $virtualbox_services = "System\\ControlSet001\\Services\\VBox[A-Za-z]+" nocase wide ascii
    $virtualbox_pipe     = /\\\\.\\pipe\\(VBoxTrayIPC|VBoxMiniRdDN)/ nocase wide ascii
    $virtualbox_window   = /VBoxTrayToolWnd(Class)?/ nocase wide ascii

  condition:
    any of them
}

global rule isExecutable {
  meta:
    author      = "73mp74710n"
    description = "Yara rule to check for unobfuscated rat created with njrat"

  strings:
    $MZ = { 4D 5A 90 00 }
    $PE = { 50 45 00 00 }

  condition:
    $MZ at 0 and $PE

}

rule avi: AVI {
  meta:
    author = "Joan Bono"

  strings:
    $a = "RIFF"

  condition:
    $a at 0
}

rule gif_animated: GIF {
  meta:
    author = "Joan Bono"

  strings:
    $a = "GIF89a"

  condition:
    $a at 0
}

rule ICMLuaUtil_UACMe_M41: uac_bypass {
  meta:
    description = "A Yara rule for UACMe Method 41 -> ICMLuaUtil Elevated COM interface"
    author      = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
    date        = "2021-01-19"
    TLP         = "WHITE"
    reference   = "https://github.com/hfiref0x/UACME"

  strings:
    $elevation = "Elevation:Administrator!new:" wide ascii

    // IDs as strings, e.g. UACMe Implementation / Ataware Ransomware
    $clsid_CMSTPLUA = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide ascii
    $iid_ICMLuaUtil = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" wide ascii

    // IDs as embedded data structures, e.g. LockBit Ransomware
    $clsid_bytes = { 95 D1 16 0A 47 6F 64 49 92 87 9F 4B AB 6D 98 27 }
    $iid_bytes   = { 74 6D DD 6E 07 C0 75 4E B7 6A E5 74 09 95 E2 4C }

  condition:
    uint16(0) == 0x5a4d
    and (($elevation and $clsid_CMSTPLUA and $iid_ICMLuaUtil) or ($clsid_bytes and $iid_bytes))
}

rule nSpackV2x: LiuXingPing {
  meta:
    author = "malware-lu"

  strings:
    $a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 }

  condition:
    $a0
}


// ===== removed from C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\yara-x\rules\clean_rules.yar (20261002_161802) =====
rule VxCompiler {
  strings:
    $a0 = { 8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E }

  condition:
    $a0 at (pe.entry_point)
}

rule _Vx_Compiler_ {
  meta:
    description = "Vx: Compiler"

  strings:
    $0 = { 8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E }

  condition:
    $0 at pe.entry_point
}

rule _VideoLanClient__UnknownCompiler_ {
  meta:
    description = "Video-Lan-Client -> (UnknownCompiler)"

  strings:
    $0 = { 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Basic_Compiler_v560_198297_ {
  meta:
    description = "Microsoft Basic Compiler v5.60 1982-97"

  strings:
    $0 = { 9A ?? ?? ?? ?? 9A ?? ?? ?? ?? 9A ?? ?? ?? ?? 33 DB BA ?? ?? 9A ?? ?? ?? ?? C7 06 ?? ?? ?? ?? 33 DB }

  condition:
    $0 at pe.entry_point
}

rule _File_Analyzer_Compiled_Datafile_Version_ {
  meta:
    description = "File Analyzer Compiled Datafile Version"

  strings:
    $0 = "File Analyzer Compiled Datafile Version"

  condition:
    $0 at pe.entry_point
}

rule _Exact_Audio_Copy__UnknownCompiler_ {
  meta:
    description = "Exact Audio Copy -> (UnknownCompiler)"

  strings:
    $0 = { E8 ?? ?? ?? 00 31 ED 55 89 E5 81 EC ?? 00 00 00 8D BD ?? FF FF FF B9 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_precompiled_header_file_ {
  meta:
    description = "Borland precompiled header file"

  strings:
    $0 = "TPS"

  condition:
    $0 at pe.entry_point
}

rule _MASMTASM_Lenguaje_Compilador_ {
  meta:
    description = "MASM/TASM (Lenguaje Compilador)"

  strings:
    $0 = { 6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $0 at pe.entry_point
}

rule _MultiEdits_compiled_macros_ {
  meta:
    description = "MultiEdit`s compiled macros"

  strings:
    $0 = { 1E AA }

  condition:
    $0 at pe.entry_point
}

rule _Batch_Compiler_10_ {
  meta:
    description = "Batch Compiler 1.0"

  strings:
    $0 = { FC BD 58 01 8B 6E 00 8B 66 02 8B 5E 04 B4 4A CD 21 A1 2C 00 89 46 1A 8B 5E 00 FF E3 }

  condition:
    $0 at pe.entry_point
}

rule _Unknown_Protected_Mode_compiler_1_ {
  meta:
    description = "Unknown Protected Mode compiler (1)"

  strings:
    $0 = { FA BC ?? ?? 8C C8 8E D8 E8 ?? ?? E8 ?? ?? E8 ?? ?? 66 B8 ?? ?? ?? ?? 66 C1 }

  condition:
    $0 at pe.entry_point
}

rule _MS_RunTime_Library_OS2__FORTRAN_Compiler_1989_ {
  meta:
    description = "MS Run-Time Library (OS/2) & FORTRAN Compiler 1989"

  strings:
    $0 = { B4 30 CD 21 86 E0 2E A3 ?? ?? 3D ?? ?? 73 }

  condition:
    $0 at pe.entry_point
}

rule _Unknown_Protected_Mode_compiler_2_ {
  meta:
    description = "Unknown Protected Mode compiler (2)"

  strings:
    $0 = { FA FC 0E 1F E8 ?? ?? 8C C0 66 0F B7 C0 66 C1 E0 ?? 66 67 A3 }

  condition:
    $0 at pe.entry_point
}

rule _Compiled_InstallSHIELD_Installation_Script_ {
  meta:
    description = "Compiled InstallSHIELD Installation Script"

  strings:
    $0 = { B8 C9 0C 00 }

  condition:
    $0 at pe.entry_point
}

rule _CRK_Compiler_120_ {
  meta:
    description = "CRK Compiler 1.20"

  strings:
    $0 = { 2F 4D 47 2F EB 04 00 00 00 00 C8 08 00 00 E8 00 00 0E 07 C6 46 FE 00 E8 00 00 E8 00 00 8B 0E 00 00 E3 02 EB 03 E9 D4 00 2B C0 89 46 F8 B8 00 00 89 46 FC C7 46 FA 00 00 51 BA 00 00 F6 06 00 07 01 74 03 BA 00 00 E8 B5 00 8B 56 FC BB 0F 00 E8 }

  condition:
    $0 at pe.entry_point
}

rule Compilation_in_LNK {
  meta:
    description = "Identifies compilation artefacts in shortcut (LNK) files."
    author      = "@bartblaze"
    date        = "2020-01"
    tlp         = "White"

  strings:
    $ = "vbc.exe" ascii wide nocase
    $ = "csc.exe" ascii wide nocase

  condition:
    isLNK and any of them
}

rule compiler_midl {
  meta:
    author = "@tylabs"

  strings:
    $s1 = "Created by MIDL version " wide

  condition:
    any of them
}

rule Video_Lan_Client_____UnknownCompiler_ {
  strings:
    $a0 = { 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 }

  condition:
    $a0 at pe.entry_point
}


// ===== removed from c:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\yara-x\rules\clean_rules.yar (20261002_185714) =====

rule HKTL_CobaltStrike_CS_Core_Oct23 {
    meta:
        description = "Hunts for opcodes used in Cobaltstrike 4.9.1 and earlier"
        version = "0.1"
        author = "@ninjaparanoid"
        reference = "https://github.com/paranoidninja/Cobaltstrike-Detection/blob/main/cs49.yara"
        date = "2023-10-12"
        score = 75
    strings:
        $socks = { 49 8D 55 02 48 8D 4C 24 30 44 0F B7 F8 B8 FF 03 00 00 }
        $core = { 49 B9 01 01 01 01 01 01 01 01 49 0F AF D1 49 83 F8 40 }
    condition:
        1 of them
}

rule sig_4641_tdrE934 {
  meta:
    description = "4641 - file tdrE934.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-08-02"
    hash1       = "48f2e2a428ec58147a4ad7cc0f06b3cf7d2587ccd47bad2ea1382a8b9c20731c"

  strings:
    $s1  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s2  = "D:\\1W7w3cZ63gF\\wFIFSV\\YFU1GTi1\\i5G3cr\\Wb2f\\Cvezk3Oz\\2Zi9ir\\S76RW\\RE5kLijcf.pdb" fullword ascii
    $s3  = "https://sectigo.com/CPS0" fullword ascii
    $s4  = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
    $s5  = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
    $s6  = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
    $s7  = "ntdll.dlH" fullword ascii
    $s8  = "http://ocsp.sectigo.com0" fullword ascii
    $s9  = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
    $s10 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
    $s11 = "tmnEt6XElyFyz2dg5EP4TMpAvGdGtork5EZcpw3eBwJQFABWlUZa5slcF6hqfGb2HgPed49gr2baBCLwRel8zM5cbMfsrOdS1yd6bMpepebebyT4NIN6zOvk" fullword ascii
    $s12 = "ealagi@aol.com0" fullword ascii
    $s13 = "operator co_await" fullword ascii
    $s14 = "ZGetModuleHandle" fullword ascii
    $s15 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
    $s16 = "RtlExitUserThrea`NtFlushInstruct" fullword ascii
    $s17 = "UAWAVAUATVWSH" fullword ascii
    $s18 = "AWAVAUATVWUSH" fullword ascii
    $s19 = "AWAVVWSH" fullword ascii
    $s20 = "UAWAVATVWSH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and
    (pe.imphash() == "4f1ec786c25f2d49502ba19119ebfef6" or 8 of them)
}

rule libavcodec_wp_exp2_table__8_byt_256_ {
  strings:
    $a0 = { 00 01 01 02 03 03 04 05 06 06 07 08 08 09 0a 0b 0b 0c 0d 0e 0e 0f 10 10 11 12 13 13 14 15 16 16 17 18 19 19 1a 1b 1c 1d 1d 1e 1f 20 20 21 22 23 24 24 25 26 27 28 28 29 2a 2b 2c 2c 2d 2e 2f 30 30 31 32 33 34 35 35 36 37 38 39 3a 3a 3b 3c 3d 3e 3f 40 41 41 42 43 44 45 46 47 48 48 49 4a 4b 4c 4d 4e 4f 50 51 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 95 96 97 98 99 9a 9b 9c 9d 9f a0 a1 a2 a3 a4 a5 a6 a8 a9 aa ab ac ad af b0 b1 b2 b3 b4 b6 b7 b8 b9 ba bc bd be bf c0 c2 c3 c4 c5 c6 c8 c9 ca cb cd ce cf d0 d2 d3 d4 d6 d7 d8 d9 db dc dd de e0 e1 e2 e4 e5 e6 e8 e9 ea ec ed ee f0 f1 f2 f4 f5 f6 f8 f9 fa fc fd ff }

  condition:
    $a0
}


// ===== removed from hydradragon\yara-x\rules\clean_rules.yar (20261003_145949) =====
rule TTP_contains_XMR_address {
  meta:
    description   = "Matches regex for Monero wallet addresses."
    last_modified = "2024-01-10"
    author        = "@petermstewart"
    DaysofYara    = "10/100"

  strings:
    $r1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ fullword ascii wide

  condition:
    filesize < 5MB and
    $r1
}

rule Win_Spyware_Zbot_1289 {
  strings:
    $a0 = { 51 f7 d7 c3 }

  condition:
    $a0
}

rule Win_Trojan_Agent_36902 {
  strings:
    $a0 = "Fuck"

  condition:
    $a0
}

rule Vorbis_FLOOR1_fromdB_LOOKUP__flt32___32_lil_1024_ {
  strings:
    $a0 = { 3e b4 e4 33 09 91 f3 33 8b b2 01 34 3c 20 0a 34 23 1a 13 34 60 a9 1c 34 a7 d7 26 34 4b af 31 34 50 3b 3d 34 70 87 49 34 23 a0 56 34 b8 92 64 34 55 6d 73 34 88 9f 81 34 fc 0b 8a 34 93 04 93 34 69 92 9c 34 32 bf a6 34 3f 95 b1 34 93 1f bd 34 e4 69 c9 34 ad 80 d6 34 36 71 e4 34 a6 49 f3 34 88 8c 01 35 c0 f7 09 35 06 ef 12 35 76 7b 1c 35 c0 a6 26 35 37 7b 31 35 da 03 3d 35 5e 4c 49 35 3b 61 56 35 b9 4f 64 35 fc 25 73 35 8a 79 81 35 86 e3 89 35 7c d9 92 35 85 64 9c 35 52 8e a6 35 33 61 b1 35 25 e8 bc 35 dc 2e c9 35 ce 41 d6 35 41 2e e4 35 57 02 f3 35 8f 66 01 36 4f cf 09 36 f5 c3 12 36 98 4d 1c 36 e8 75 26 36 32 47 31 36 74 cc 3c 36 5e 11 49 36 65 22 56 36 ce 0c 64 36 b8 de 72 36 97 53 81 36 1c bb 89 36 72 ae 92 36 af 36 9c 36 81 5d a6 36 35 2d b1 36 c7 b0 bc 36 e4 f3 c8 36 01 03 d6 36 60 eb e3 36 1e bb f2 36 a2 40 01 37 eb a6 09 37 f1 98 12 37 c9 1f 1c 37 1e 45 26 37 3d 13 31 37 1e 95 3c 37 6f d6 48 37 a2 e3 55 37 f7 c9 63 37 89 97 72 37 af 2d 81 37 be 92 89 37 74 83 92 37 e6 08 9c 37 be 2c a6 37 47 f9 b0 37 79 79 bc 37 fe b8 c8 37 47 c4 d5 37 92 a8 e3 37 f8 73 f2 37 c0 1a 01 38 93 7e 09 38 f9 6d 12 38 06 f2 1b 38 62 14 26 38 56 df 30 38 d8 5d 3c 38 92 9b 48 38 f2 a4 55 38 33 87 63 38 6e 50 72 38 d3 07 81 38 6b 6a 89 38 82 58 92 38 2a db 9b 38 09 fc a5 38 68 c5 b0 38 3b 42 bc 38 29 7e c8 38 a0 85 d5 38 d9 65 e3 38 e8 2c f2 38 e9 f4 00 39 46 56 09 39 0e 43 12 39 51 c4 1b 39 b5 e3 25 39 7f ab 30 39 a2 26 3c 39 c5 60 48 39 53 66 55 39 83 44 63 39 68 09 72 39 01 e2 80 39 24 42 89 39 9d 2d 92 39 7b ad 9b 39 63 cb a5 39 99 91 b0 39 0d 0b bc 39 66 43 c8 39 0b 47 d5 39 32 23 e3 39 ed e5 f1 39 1d cf 00 3a 05 2e 09 3a 30 18 12 3a a9 96 1b 3a 15 b3 25 3a b7 77 30 3a 7c ef 3b 3a 0a 26 48 3a c7 27 55 3a e6 01 63 3a 78 c2 71 3a 3b bc 80 3a e9 19 89 3a c6 02 92 3a db 7f 9b 3a cb 9a a5 3a d8 5d b0 3a ef d3 bb 3a b3 08 c8 3a 88 08 d5 3a 9f e0 e2 3a 07 9f f1 3a 5c a9 00 3b d0 05 09 3b 5e ed 11 3b 0f 69 1b 3b 84 82 25 3b fd 43 30 3b 67 b8 3b 3b 61 eb 47 3b 4d e9 54 3b 5d bf 62 3b 9c 7b 71 3b 7f 96 80 3b ba f1 88 3b f9 d7 91 3b 47 52 9b 3b 41 6a a5 3b 27 2a b0 3b e2 9c bb 3b 12 ce c7 3b 17 ca d4 3b 20 9e e2 3b 35 58 f1 3b a6 83 00 3c a7 dd 08 3c 98 c2 11 3c 82 3b 1b 3c 01 52 25 3c 54 10 30 3c 61 81 3b 3c c8 b0 47 3c e5 aa 54 3c e8 7c 62 3c d4 34 71 3c cf 70 80 3c 96 c9 88 3c 3a ad 91 3c c0 24 9b 3c c5 39 a5 3c 85 f6 af 3c e5 65 bb 3c 82 93 c7 3c b9 8b d4 3c b4 5b e2 3c 79 11 f1 3c fb 5d 00 3d 89 b5 08 3d df 97 11 3d 02 0e 1b 3d 8d 21 25 3d b9 dc 2f 3d 6d 4a 3b 3d 40 76 47 3d 91 6c 54 3d 85 3a 62 3d 22 ee 70 3d 2a 4b 80 3d 7f a1 88 3d 88 82 91 3d 48 f7 9a 3d 58 09 a5 3d f2 c2 af 3d f8 2e bb 3d 03 59 c7 3d 6d 4d d4 3d 5c 19 e2 3d d1 ca f0 3d 5b 38 00 3e 77 8d 08 3e 33 6d 11 3e 90 e0 1a 3e 27 f1 24 3e 2e a9 2f 3e 87 13 3b 3e ca 3b 47 3e 4d 2e 54 3e 37 f8 61 3e 84 a7 70 3e 8f 25 80 3e 73 79 88 3e e2 57 91 3e dc c9 9a 3e f9 d8 a4 3e 6d 8f af 3e 1b f8 ba 3e 95 1e c7 3e 33 0f d4 3e 17 d7 e1 3e 3d 84 f0 3e c6 12 00 3f 72 65 08 3f 93 42 11 3f 2b b3 1a 3f ce c0 24 3f b1 75 2f 3f b2 dc 3a 3f 65 01 47 3f 1d f0 53 3f fb b5 61 3f fb 60 70 3f 00 00 80 3f }

  condition:
    $a0
}

rule sfb_32_512__16_lil_74_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 2c 00 30 00 34 00 38 00 40 00 48 00 50 00 58 00 60 00 6c 00 78 00 84 00 90 00 a0 00 b0 00 c0 00 d4 00 ec 00 04 01 20 01 40 01 60 01 80 01 a0 01 c0 01 e0 01 00 02 }

  condition:
    $a0
}

rule sfb_48_512__16_lil_72_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 2c 00 30 00 34 00 38 00 3c 00 44 00 4c 00 54 00 5c 00 64 00 70 00 7c 00 88 00 94 00 a4 00 b8 00 d0 00 ec 00 0c 01 2c 01 4c 01 6c 01 8c 01 ac 01 cc 01 00 02 }

  condition:
    $a0
}

rule DESX_pc2__8_byt_48_ {
  strings:
    $a0 = { 0d 10 0a 17 00 04 02 1b 0e 05 14 09 16 12 0b 03 19 07 0f 06 1a 13 0c 01 28 33 1e 24 2e 36 1d 27 32 2c 20 2f 2b 30 26 37 21 34 2d 29 31 23 1c 1f }

  condition:
    $a0
}

rule ARIA_encryption_X2__8_byt_256_ {
  strings:
    $a0 = { 30 68 99 1b 87 b9 21 78 50 39 db e1 72 09 62 3c 3e 7e 5e 8e f1 a0 cc a3 2a 1d fb b6 d6 20 c4 8d 81 65 f5 89 cb 9d 77 c6 57 43 56 17 d4 40 1a 4d c0 63 6c e3 b7 c8 64 6a 53 aa 38 98 0c f4 9b ed 7f 22 76 af dd 3a 0b 58 67 88 06 c3 35 0d 01 8b 8c c2 e6 5f 02 24 75 93 66 1e e5 e2 54 d8 10 ce 7a e8 08 2c 12 97 32 ab b4 27 0a 23 df ef ca d9 b8 fa dc 31 6b d1 ad 19 49 bd 51 96 ee e4 a8 41 da ff cd 55 86 36 be 61 52 f8 bb 0e 82 48 69 9a e0 47 9e 5c 04 4b 34 15 79 26 a7 de 29 ae 92 d7 84 e9 d2 ba 5d f3 c5 b0 bf a4 3b 71 44 46 2b fc eb 6f d5 f6 14 fe 7c 70 5a 7d fd 2f 18 83 16 a5 91 1f 05 95 74 a9 c1 5b 4a 85 6d 13 07 4f 4e 45 b2 0f c9 1c a6 bc ec 73 90 7b cf 59 8f a1 f9 2d f2 b1 00 94 37 9f d0 2e 9c 6e 28 3f 80 f0 3d d3 25 8a b5 e7 42 b3 c7 ea f7 4c 11 33 03 a2 ac 60 }

  condition:
    $a0
}

rule sfb_16_1024__16_lil_86_ {
  strings:
    $a0 = { 08 00 10 00 18 00 20 00 28 00 30 00 38 00 40 00 48 00 50 00 58 00 64 00 70 00 7c 00 88 00 94 00 a0 00 ac 00 b8 00 c4 00 d4 00 e4 00 f4 00 04 01 18 01 2c 01 40 01 58 01 70 01 8c 01 a8 01 c8 01 ec 01 14 02 3c 02 68 02 98 02 cc 02 04 03 40 03 80 03 c0 03 00 04 }

  condition:
    $a0
}

rule sfb_32_480__16_lil_74_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 2c 00 30 00 34 00 38 00 3c 00 40 00 48 00 50 00 58 00 60 00 68 00 70 00 7c 00 88 00 94 00 a4 00 b4 00 c8 00 e0 00 00 01 20 01 40 01 60 01 80 01 a0 01 c0 01 e0 01 }

  condition:
    $a0
}

rule sfb_16_960__16_lil_84_ {
  strings:
    $a0 = { 08 00 10 00 18 00 20 00 28 00 30 00 38 00 40 00 48 00 50 00 58 00 64 00 70 00 7c 00 88 00 94 00 a0 00 ac 00 b8 00 c4 00 d4 00 e4 00 f4 00 04 01 18 01 2c 01 40 01 58 01 70 01 8c 01 a8 01 c8 01 ec 01 14 02 3c 02 68 02 98 02 cc 02 04 03 40 03 80 03 c0 03 }

  condition:
    $a0
}

rule camellia_sp0222__32_big_1024_ {
  strings:
    $a0 = { 00 e0 e0 e0 00 05 05 05 00 58 58 58 00 d9 d9 d9 00 67 67 67 00 4e 4e 4e 00 81 81 81 00 cb cb cb 00 c9 c9 c9 00 0b 0b 0b 00 ae ae ae 00 6a 6a 6a 00 d5 d5 d5 00 18 18 18 00 5d 5d 5d 00 82 82 82 00 46 46 46 00 df df df 00 d6 d6 d6 00 27 27 27 00 8a 8a 8a 00 32 32 32 00 4b 4b 4b 00 42 42 42 00 db db db 00 1c 1c 1c 00 9e 9e 9e 00 9c 9c 9c 00 3a 3a 3a 00 ca ca ca 00 25 25 25 00 7b 7b 7b 00 0d 0d 0d 00 71 71 71 00 5f 5f 5f 00 1f 1f 1f 00 f8 f8 f8 00 d7 d7 d7 00 3e 3e 3e 00 9d 9d 9d 00 7c 7c 7c 00 60 60 60 00 b9 b9 b9 00 be be be 00 bc bc bc 00 8b 8b 8b 00 16 16 16 00 34 34 34 00 4d 4d 4d 00 c3 c3 c3 00 72 72 72 00 95 95 95 00 ab ab ab 00 8e 8e 8e 00 ba ba ba 00 7a 7a 7a 00 b3 b3 b3 00 02 02 02 00 b4 b4 b4 00 ad ad ad 00 a2 a2 a2 00 ac ac ac 00 d8 d8 d8 00 9a 9a 9a 00 17 17 17 00 1a 1a 1a 00 35 35 35 00 cc cc cc 00 f7 f7 f7 00 99 99 99 00 61 61 61 00 5a 5a 5a 00 e8 e8 e8 00 24 24 24 00 56 56 56 00 40 40 40 00 e1 e1 e1 00 63 63 63 00 09 09 09 00 33 33 33 00 bf bf bf 00 98 98 98 00 97 97 97 00 85 85 85 00 68 68 68 00 fc fc fc 00 ec ec ec 00 0a 0a 0a 00 da da da 00 6f 6f 6f 00 53 53 53 00 62 62 62 00 a3 a3 a3 00 2e 2e 2e 00 08 08 08 00 af af af 00 28 28 28 00 b0 b0 b0 00 74 74 74 00 c2 c2 c2 00 bd bd bd 00 36 36 36 00 22 22 22 00 38 38 38 00 64 64 64 00 1e 1e 1e 00 39 39 39 00 2c 2c 2c 00 a6 a6 a6 00 30 30 30 00 e5 e5 e5 00 44 44 44 00 fd fd fd 00 88 88 88 00 9f 9f 9f 00 65 65 65 00 87 87 87 00 6b 6b 6b 00 f4 f4 f4 00 23 23 23 00 48 48 48 00 10 10 10 00 d1 d1 d1 00 51 51 51 00 c0 c0 c0 00 f9 f9 f9 00 d2 d2 d2 00 a0 a0 a0 00 55 55 55 00 a1 a1 a1 00 41 41 41 00 fa fa fa 00 43 43 43 00 13 13 13 00 c4 c4 c4 00 2f 2f 2f 00 a8 a8 a8 00 b6 b6 b6 00 3c 3c 3c 00 2b 2b 2b 00 c1 c1 c1 00 ff ff ff 00 c8 c8 c8 00 a5 a5 a5 00 20 20 20 00 89 89 89 00 00 00 00 00 90 90 90 00 47 47 47 00 ef ef ef 00 ea ea ea 00 b7 b7 b7 00 15 15 15 00 06 06 06 00 cd cd cd 00 b5 b5 b5 00 12 12 12 00 7e 7e 7e 00 bb bb bb 00 29 29 29 00 0f 0f 0f 00 b8 b8 b8 00 07 07 07 00 04 04 04 00 9b 9b 9b 00 94 94 94 00 21 21 21 00 66 66 66 00 e6 e6 e6 00 ce ce ce 00 ed ed ed 00 e7 e7 e7 00 3b 3b 3b 00 fe fe fe 00 7f 7f 7f 00 c5 c5 c5 00 a4 a4 a4 00 37 37 37 00 b1 b1 b1 00 4c 4c 4c 00 91 91 91 00 6e 6e 6e 00 8d 8d 8d 00 76 76 76 00 03 03 03 00 2d 2d 2d 00 de de de 00 96 96 96 00 26 26 26 00 7d 7d 7d 00 c6 c6 c6 00 5c 5c 5c 00 d3 d3 d3 00 f2 f2 f2 00 4f 4f 4f 00 19 19 19 00 3f 3f 3f 00 dc dc dc 00 79 79 79 00 1d 1d 1d 00 52 52 52 00 eb eb eb 00 f3 f3 f3 00 6d 6d 6d 00 5e 5e 5e 00 fb fb fb 00 69 69 69 00 b2 b2 b2 00 f0 f0 f0 00 31 31 31 00 0c 0c 0c 00 d4 d4 d4 00 cf cf cf 00 8c 8c 8c 00 e2 e2 e2 00 75 75 75 00 a9 a9 a9 00 4a 4a 4a 00 57 57 57 00 84 84 84 00 11 11 11 00 45 45 45 00 1b 1b 1b 00 f5 f5 f5 00 e4 e4 e4 00 0e 0e 0e 00 73 73 73 00 aa aa aa 00 f1 f1 f1 00 dd dd dd 00 59 59 59 00 14 14 14 00 6c 6c 6c 00 92 92 92 00 54 54 54 00 d0 d0 d0 00 78 78 78 00 70 70 70 00 e3 e3 e3 00 49 49 49 00 80 80 80 00 50 50 50 00 a7 a7 a7 00 f6 f6 f6 00 77 77 77 00 93 93 93 00 86 86 86 00 83 83 83 00 2a 2a 2a 00 c7 c7 c7 00 5b 5b 5b 00 e9 e9 e9 00 ee ee ee 00 8f 8f 8f 00 01 01 01 00 3d 3d 3d }

  condition:
    $a0
}

rule sfb_24_512__16_lil_62_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 2c 00 34 00 3c 00 44 00 50 00 5c 00 68 00 78 00 8c 00 a4 00 c0 00 e0 00 00 01 20 01 40 01 60 01 80 01 a0 01 c0 01 e0 01 00 02 }

  condition:
    $a0
}

rule sfb_24_1024__16_lil_94_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 2c 00 34 00 3c 00 44 00 4c 00 54 00 5c 00 64 00 6c 00 74 00 7c 00 88 00 94 00 a0 00 ac 00 bc 00 cc 00 dc 00 f0 00 04 01 1c 01 34 01 50 01 6c 01 8c 01 b0 01 d4 01 fc 01 28 02 58 02 8c 02 c0 02 00 03 40 03 80 03 c0 03 00 04 }

  condition:
    $a0
}

rule Generic_squared_map__16_lil_32_ {
  strings:
    $a0 = { 00 00 01 00 04 00 05 00 10 00 11 00 14 00 15 00 40 00 41 00 44 00 45 00 50 00 51 00 54 00 55 00 }

  condition:
    $a0
}

rule sfb_96_1024__16_lil_82_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 2c 00 30 00 34 00 38 00 40 00 48 00 50 00 58 00 60 00 6c 00 78 00 84 00 90 00 9c 00 ac 00 bc 00 d4 00 f0 00 14 01 40 01 80 01 c0 01 00 02 40 02 80 02 c0 02 00 03 40 03 80 03 c0 03 00 04 }

  condition:
    $a0
}

rule Generic_squared_map__16_big_32_ {
  strings:
    $a0 = { 00 00 00 01 00 04 00 05 00 10 00 11 00 14 00 15 00 40 00 41 00 44 00 45 00 50 00 51 00 54 00 55 }

  condition:
    $a0
}

rule ARIA_encryption_S2__8_byt_256_ {
  strings:
    $a0 = { e2 4e 54 fc 94 c2 4a cc 62 0d 6a 46 3c 4d 8b d1 5e fa 64 cb b4 97 be 2b bc 77 2e 03 d3 19 59 c1 1d 06 41 6b 55 f0 99 69 ea 9c 18 ae 63 df e7 bb 00 73 66 fb 96 4c 85 e4 3a 09 45 aa 0f ee 10 eb 2d 7f f4 29 ac cf ad 91 8d 78 c8 95 f9 2f ce cd 08 7a 88 38 5c 83 2a 28 47 db b8 c7 93 a4 12 53 ff 87 0e 31 36 21 58 48 01 8e 37 74 32 ca e9 b1 b7 ab 0c d7 c4 56 42 26 07 98 60 d9 b6 b9 11 40 ec 20 8c bd a0 c9 84 04 49 23 f1 4f 50 1f 13 dc d8 c0 9e 57 e3 c3 7b 65 3b 02 8f 3e e8 25 92 e5 15 dd fd 17 a9 bf d4 9a 7e c5 39 67 fe 76 9d 43 a7 e1 d0 f5 68 f2 1b 34 70 05 a3 8a d5 79 86 a8 30 c6 51 4b 1e a6 27 f6 35 d2 6e 24 16 82 5f da e6 75 a2 ef 2c b2 1c 9f 5d 6f 80 0a 72 44 9b 6c 90 0b 5b 33 7d 5a 52 f3 61 a1 f7 b0 d6 3f 7c 6d ed 14 e0 a5 3d 22 b3 f8 89 de 71 1a af ba b5 81 }

  condition:
    $a0
}

rule sfb_48_1024__16_lil_98_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 30 00 38 00 40 00 48 00 50 00 58 00 60 00 6c 00 78 00 84 00 90 00 a0 00 b0 00 c4 00 d8 00 f0 00 08 01 24 01 40 01 60 01 80 01 a0 01 c0 01 e0 01 00 02 20 02 40 02 60 02 80 02 a0 02 c0 02 e0 02 00 03 20 03 40 03 60 03 80 03 a0 03 00 04 }

  condition:
    $a0
}

rule ima_adpcm_step_table__32_lil_356_ {
  strings:
    $a0 = { 07 00 00 00 08 00 00 00 09 00 00 00 0a 00 00 00 0b 00 00 00 0c 00 00 00 0d 00 00 00 0e 00 00 00 10 00 00 00 11 00 00 00 13 00 00 00 15 00 00 00 17 00 00 00 19 00 00 00 1c 00 00 00 1f 00 00 00 22 00 00 00 25 00 00 00 29 00 00 00 2d 00 00 00 32 00 00 00 37 00 00 00 3c 00 00 00 42 00 00 00 49 00 00 00 50 00 00 00 58 00 00 00 61 00 00 00 6b 00 00 00 76 00 00 00 82 00 00 00 8f 00 00 00 9d 00 00 00 ad 00 00 00 be 00 00 00 d1 00 00 00 e6 00 00 00 fd 00 00 00 17 01 00 00 33 01 00 00 51 01 00 00 73 01 00 00 98 01 00 00 c1 01 00 00 ee 01 00 00 20 02 00 00 56 02 00 00 92 02 00 00 d4 02 00 00 1c 03 00 00 6c 03 00 00 c3 03 00 00 24 04 00 00 8e 04 00 00 02 05 00 00 83 05 00 00 10 06 00 00 ab 06 00 00 56 07 00 00 12 08 00 00 e0 08 00 00 c3 09 00 00 bd 0a 00 00 d0 0b 00 00 ff 0c 00 00 4c 0e 00 00 ba 0f 00 00 4c 11 00 00 07 13 00 00 ee 14 00 00 06 17 00 00 54 19 00 00 dc 1b 00 00 a5 1e 00 00 b6 21 00 00 15 25 00 00 ca 28 00 00 df 2c 00 00 5b 31 00 00 4b 36 00 00 b9 3b 00 00 b2 41 00 00 44 48 00 00 7e 4f 00 00 71 57 00 00 2f 60 00 00 ce 69 00 00 62 74 00 00 ff 7f 00 00 }

  condition:
    $a0
}

rule sfb_48_480__16_lil_70_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 2c 00 30 00 34 00 38 00 40 00 48 00 50 00 58 00 60 00 6c 00 78 00 84 00 90 00 9c 00 ac 00 bc 00 d4 00 f0 00 10 01 30 01 50 01 70 01 90 01 b0 01 e0 01 }

  condition:
    $a0
}

rule sfb_24_480__16_lil_60_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 2c 00 34 00 3c 00 44 00 50 00 5c 00 68 00 78 00 8c 00 a4 00 c0 00 e0 00 00 01 20 01 40 01 60 01 80 01 a0 01 c0 01 e0 01 }

  condition:
    $a0
}

rule sfb_64_1024__16_lil_94_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 2c 00 30 00 34 00 38 00 40 00 48 00 50 00 58 00 64 00 70 00 7c 00 8c 00 9c 00 ac 00 c0 00 d8 00 f0 00 0c 01 30 01 58 01 80 01 a8 01 d0 01 f8 01 20 02 48 02 70 02 98 02 c0 02 e8 02 10 03 38 03 60 03 88 03 b0 03 d8 03 00 04 }

  condition:
    $a0
}

rule sfb_32_1024__16_lil_102_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 30 00 38 00 40 00 48 00 50 00 58 00 60 00 6c 00 78 00 84 00 90 00 a0 00 b0 00 c4 00 d8 00 f0 00 08 01 24 01 40 01 60 01 80 01 a0 01 c0 01 e0 01 00 02 20 02 40 02 60 02 80 02 a0 02 c0 02 e0 02 00 03 20 03 40 03 60 03 80 03 a0 03 c0 03 e0 03 00 04 }

  condition:
    $a0
}

rule liba52_scale_factor_float__flt32___32_lil_100_ {
  strings:
    $a0 = { 00 00 00 38 00 00 80 37 00 00 00 37 00 00 80 36 00 00 00 36 00 00 80 35 00 00 00 35 00 00 80 34 00 00 00 34 00 00 80 33 00 00 00 33 00 00 80 32 00 00 00 32 00 00 80 31 00 00 00 31 00 00 80 30 00 00 00 30 00 00 80 2f 00 00 00 2f 00 00 80 2e 00 00 00 2e 00 00 80 2d 00 00 00 2d 00 00 80 2c 00 00 00 2c }

  condition:
    $a0
}

rule anti_debug__Detect_and_crash_SoftICE_with_an_illegal_form_of_the_instruction_CMPXCHG8B__8_byt_4_ {
  strings:
    $a0 = { f0 0f c7 c8 }

  condition:
    $a0
}

rule TEA_encryption_decryption__0xc6ef3720__0x9e3779b9___32_lil_AND_ {
  strings:
    $a0 = { 20 37 ef c6 [0-20] b9 79 37 9e }

  condition:
    $a0
}

rule possible_exploit: PDF {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    weight  = 3

  strings:
    $magic = "%PDF"

    $attrib0 = /\/JavaScript /
    $attrib3 = /\/ASCIIHexDecode/
    $attrib4 = /\/ASCII85Decode/

    $action0 = /\/Action/
    $action1 = "Array"
    //$shell = "A"
    $cond0   = "unescape"
    $cond1   = "String.fromCharCode"

    $nop = "%u9090%u9090"

  condition:
    $magic at 0 and (2 of ($attrib*)) or ($action0  /*and #shell > 10*/ and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule RogueFakePAVSample {
  meta:
    Description = "Rogue.FakePAV.sm"
    ThreatLevel = "5"

  strings:
    $ = "ZALERT" ascii wide
    $ = "ZAPFrm" ascii wide
    $ = "ZAbout" ascii wide
    $ = "ZAutoRunFrame" ascii wide
    $ = "ZCheckBox" ascii wide
    $ = "ZCplAll" ascii wide
    $ = "ZFogWnd" ascii wide
    $ = "ZFrameDEt" ascii wide
    $ = "ZIEWnd" ascii wide
    $ = "ZMainFrame" ascii wide
    $ = "ZMainWnd" ascii wide
    $ = "ZOptionsFrame" ascii wide
    $ = "ZProcessFrame" ascii wide
    $ = "ZProgressBar" ascii wide
    $ = "ZPromo" ascii wide
    $ = "ZReg" ascii wide
    $ = "ZResFR" ascii wide
    $ = "ZServiceFrame" ascii wide
    $ = "ZUpdate" ascii wide
    $ = "ZWarn" ascii wide

  condition:
    any of them
}

rule APT_malware_1 {
  meta:
    description = "inveigh pen testing tools & related artifacts"
    author      = "US-CERT Code Analysis Team"
    reference   = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
    date        = "2017/07/17"
    hash0       = "61C909D2F625223DB2FB858BBDF42A76"
    hash1       = "A07AA521E7CAFB360294E56969EDA5D6"
    hash2       = "BA756DD64C1147515BA2298B6A760260"
    hash3       = "8943E71A8C73B5E343AA9D2E19002373"
    hash4       = "04738CA02F59A5CD394998A99FCD9613"
    hash5       = "038A97B4E2F37F34B255F0643E49FC9D"
    hash6       = "65A1A73253F04354886F375B59550B46"
    hash7       = "AA905A3508D9309A93AD5C0EC26EBC9B"
    hash8       = "5DBEF7BDDAF50624E840CCBCE2816594"
    hash9       = "722154A36F32BA10E98020A8AD758A7A"
    hash10      = "4595DBE00A538DF127E0079294C87DA0"

  strings:
    $s0  = "file://"
    $s1  = "/ame_icon.png"
    $s2  = "184.154.150.66"
    $s3  = { 87 D0 81 F6 0C 67 F5 08 6A 00 33 15 D4 9A 40 00 F7 D6 E8 EB 12 00 00 81 F7 F0 1B DD 21 F7 DE }
    $s4  = { 33 C4 2B CB 33 3D C0 AD 40 00 43 C1 C6 1A 33 C3 F7 DE 33 F0 42 C7 05 B5 AC 40 00 26 AF 21 02 }
    $s5  = "(g.charCodeAt(c)^l[(l[b]+l[e])%256])"
    $s6  = "for(b=0;256>b;b++)k[b]=b;for(b=0;256>b;b++)"
    $s7  = "VXNESWJfSjY3grKEkEkRuZeSvkE="
    $s8  = "NlZzSZk="
    $s9  = "WlJTb1q5kaxqZaRnser3sw=="
    $s10 = "for(b=0;256>b;b++)k[b]=b;for(b=0;256>b;b++)"
    $s11 = "fromCharCode(d.charCodeAt(e)^k[(k[b]+k[h])%256])"
    $s12 = "ps.exe -accepteula \\%ws% -u %user% -p %pass% -s cmd /c netstat"
    $s13 = "\"Tokens=1 delims=\\\\\" %%I IN (list.txt)"
    $s14 = "hell.exe -noexit -executionpolicy bypass -command \". .\\Inveigh.p"
    $s15 = "Go build ID: \"fbd3797b1c14e0e1"

    //inveigh pentesting tools

    $s16 = "$inveigh.status_queue.Add(\"Press any key to stop real time"

    //specific malicious word document PK archive

    $s17 = { 2F 73 65 74 74 69 6E 67 73 2E 78 6D 6C B4 56 61 6F DB 36 13 FE FE 02 EF 7F 10 F4 79 8E 64 C5 4D 06 A1 4E D1 25 F1 9A 22 5E 87 C9 FD 01 94 48 5B }
    $s18 = { 6C 73 2F 73 65 74 74 69 6E 67 73 2E 78 6D 6C 2E 72 65 6C 73 55 54 05 00 01 00 76 A4 12 75 78 0B 00 01 04 00 00 00 00 04 00 00 00 00 8D 90 B9 4E 03 31 10 86 EB F0 14 D6 F4 D8 7B 48 21 44 71 D2 }
    $s19 = { 8D 90 B9 4E 03 31 10 86 EB F0 14 D6 F4 D8 7B 48 21 44 71 D2 10 A4 14 50 A0 E5 01 46 EB D9 43 F8 92 3D 41 C9 DB E3 A5 4A 24 0A CA 39 4A 24 0A CA 39 }
    $s20 = { 8C 90 CD 4E EB 30 10 85 D7 BD 4F 61 CD FE DA 09 21 50 A1 BA DD 00 52 17 B0 40 E1 01 46 F1 24 B1 F0 9F EC 01 B5 6F 8F C3 AA 95 58 B0 B4 }
    $s21 = { 8C 90 CD 4E EB 30 10 85 D7 BD 4F 61 CD FE DA 09 21 50 A1 BA DD 00 52 17 B0 40 E1 01 46 F1 24 B1 F0 9F EC 01 B5 6F 8F C3 AA 95 58 B0 B4 }
    $s22 = "5.153.58.45"
    $s23 = "62.8.193.206"
    $s24 = "/1/ree_stat/p"
    $s25 = "/icon.png"
    $s26 = "/pshare1/icon"
    $s27 = "/notepad.png"
    $s28 = "/pic.png"
    $s29 = "http://bit.ly/2m0x8IH"

  condition:
    ($s0 and $s1 or $s2) or ($s3 or $s4) or ($s5 and $s6 or $s7 and $s8 and $s9) or ($s10 and $s11) or ($s12 and $s13) or ($s14) or ($s15) or ($s16) or ($s17) or ($s18) or ($s19) or ($s20) or ($s21) or ($s0 and $s22 or $s24) or ($s0 and $s22 or $s25) or ($s0 and $s23 or $s26) or ($s0 and $s22 or $s27) or ($s0 and $s23 or $s28) or ($s29)
}

rule pen31 {
  meta:
    author      = "PEiD"
    description = "PEncrypt 3.1 -> junkcode"
    group       = "142"
    function    = "0"

  strings:
    $a0 = { E9 ?? ?? ?? ?? F0 0F C6 }

  condition:
    $a0
}

rule touch {
  meta:
    description   = "Detection patterns for the tool 'touch' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "touch"
    rule_category = "greyware_tool_keyword"

  strings:
    // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
    // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
    $string1 = /touch\s\-a/ nocase ascii wide
    // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
    // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
    $string2 = /touch\s\-m/ nocase ascii wide
    // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
    // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
    $string3 = /touch\s\-r\s/ nocase ascii wide
    // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
    // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
    $string4 = /touch\s\-t\s/ nocase ascii wide

  condition:
    any of them
}

rule TEA_DELTA2 {
  meta:
    author      = "_pusher_"
    description = "TEA DELTA"
    date        = "2016-02"

  strings:
    $c0 = { 9E 37 79 B9 }
    $c1 = { 61 C8 86 47 }

  condition:
    any of them
}

rule Maldoc_CVE_2017_11882: Exploit {
  meta:
    description = "Detects maldoc With exploit for CVE_2017_11882"
    author      = "Marc Salinas (@Bondey_m)"
    reference   = "c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8"
    date        = "2017-10-20"

  strings:
    $s0 = "Equation"
    $s1 = "1c000000020"
    $h0 = { 1C 00 00 00 02 00 }

  condition:
    $s0 and ($h0 or $s1)
}

rule ARIA_SB2 {
  meta:
    author      = "spelissier"
    description = "Aria SBox 2"
    date        = "2020-12"
    reference   = "http://210.104.33.10/ARIA/doc/ARIA-specification-e.pdf#page=7"

  strings:
    $c0 = { E2 4E 54 FC 94 C2 4A CC 62 0D 6A 46 3C 4D 8B D1 5E FA 64 CB B4 97 BE 2B BC 77 2E 03 D3 19 59 C1 }

  condition:
    $c0
}

rule crypto_vertical_transposition: info crypto {
  meta:
    description = "Alphabet plaintext writtent in transposition cipher"
  /* Vertical transposition with 4 rows such as
  	AEIMQU DHLPTX UQMIEA XTPLHD
  	BFJNRV CGKOSW VRNJFB WSOKGC
  	CGKOSW BFJNRV WSOKGC VRNJFB
  	DHLPTX AEIMQU XTPLHD UQMIEA
  */

  strings:
    $s_topleft_01  = "AEIMQU"
    $s_topleft_02  = "BFJNRV"
    $s_topleft_03  = "CGKOSW"
    $s_topleft_04  = "DHLPTX"
    $s_topright_01 = "UQMIEA"
    $s_topright_02 = "VRNJFB"
    $s_topright_03 = "WSOKGC"
    $s_topright_04 = "XTPLHD"

    $sl_topleft_01  = "aeimqu"
    $sl_topleft_02  = "bfjnrv"
    $sl_topleft_03  = "cgkosw"
    $sl_topleft_04  = "dhlptx"
    $sl_topright_01 = "umqmiea"
    $sl_topright_02 = "vrnjfb"
    $sl_topright_03 = "wsokgc"
    $sl_topright_04 = "xtplhd"

  condition:
    4 of ($s_*) or 4 of ($sl_*)
}

rule davivienda: mail {
  strings:
    $nombre = "davivienda" nocase

  condition:
    all of them
}

rule libfaad2_t_huff_iid_fine__8_byt_120_ {
  strings:
    $a0 = { 01 E1 E2 02 03 E0 04 05 06 07 DF E3 08 DE E4 09 DD E5 0A 0B E6 0C 0D 0E DB E7 0F 10 11 DC 12 DA E8 13 14 15 EA 16 17 18 D9 E9 19 1A EC 1B 1C 1D D7 EB 1E 1F 20 D8 21 D4 EE 22 23 24 25 D5 ED 26 27 D6 28 29 2A 2B 2C 2D 2E D2 F0 2F D3 EF 30 31 CC CD F3 F4 CE CF 32 33 34 35 36 37 38 D0 F2 39 3A D1 F1 3B C7 FB C5 C6 FE FF FC FD C3 C4 C8 FA C9 F9 CA F8 CB F7 F5 F6 }

  condition:
    $a0
}

rule libfaad2_codebook__flt32___32_lil_32_ {
  strings:
    $a0 = { d9 21 12 3f 6d 55 32 3f 08 21 50 3f 38 4b 69 3f 68 22 7c 3f c0 b0 88 3f b0 e8 98 3f db 4c af 3f }

  condition:
    $a0
}

rule AES_Rijndael_Logtable__8_byt_256_ {
  strings:
    $a0 = { 00 00 19 01 32 02 1a c6 4b c7 1b 68 33 ee df 03 64 04 e0 0e 34 8d 81 ef 4c 71 08 c8 f8 69 1c c1 7d c2 1d b5 f9 b9 27 6a 4d e4 a6 72 9a c9 09 78 65 2f 8a 05 21 0f e1 24 12 f0 82 45 35 93 da 8e 96 8f db bd 36 d0 ce 94 13 5c d2 f1 40 46 83 38 66 dd fd 30 bf 06 8b 62 b3 25 e2 98 22 88 91 10 7e 6e 48 c3 a3 b6 1e 42 3a 6b 28 54 fa 85 3d ba 2b 79 0a 15 9b 9f 5e ca 4e d4 ac e5 f3 73 a7 57 af 58 a8 50 f4 ea d6 74 4f ae e9 d5 e7 e6 ad e8 2c d7 75 7a eb 16 0b f5 59 cb 5f b0 9c a9 51 a0 7f 0c f6 6f 17 c4 49 ec d8 43 1f 2d a4 76 7b b7 cc bb 3e 5a fb 60 b1 86 3b 52 a1 6c aa 55 29 9d 97 b2 87 90 61 be dc fc bc 95 cf cd 37 3f 5b d1 53 39 84 3c 41 a2 6d 47 14 2a 9e 5d 56 f2 d3 ab 44 11 92 d9 23 20 2e 89 b4 7c b8 26 77 99 e3 a5 67 4a ed de c5 31 fe 18 0d 63 8c 80 c0 f7 70 07 }

  condition:
    $a0
}

rule sfb_8_1024__16_lil_80_ {
  strings:
    $a0 = { 0c 00 18 00 24 00 30 00 3c 00 48 00 54 00 60 00 6c 00 78 00 84 00 90 00 9c 00 ac 00 bc 00 cc 00 dc 00 ec 00 fc 00 0c 01 20 01 34 01 48 01 5c 01 74 01 8c 01 a4 01 c0 01 dc 01 fc 01 20 02 44 02 6c 02 98 02 c8 02 fc 02 34 03 70 03 b0 03 00 04 }

  condition:
    $a0
}

rule DESX_pc1__8_byt_56_ {
  strings:
    $a0 = { 38 30 28 20 18 10 08 00 39 31 29 21 19 11 09 01 3a 32 2a 22 1a 12 0a 02 3b 33 2b 23 3e 36 2e 26 1e 16 0e 06 3d 35 2d 25 1d 15 0d 05 3c 34 2c 24 1c 14 0c 04 1b 13 0b 03 }

  condition:
    $a0
}

rule ADPCM_index_table__step_variation___32_lil_64_ {
  strings:
    $a0 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 02 00 00 00 04 00 00 00 06 00 00 00 08 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 02 00 00 00 04 00 00 00 06 00 00 00 08 00 00 00 }

  condition:
    $a0
}

rule RC5_and_RC6_magic_values__0xb7e15163L_0x9e3779b9L___32_lil_AND_ {
  strings:
    $a0 = { 63 51 e1 b7 [0-20] b9 79 37 9e }

  condition:
    $a0
}

rule camellia_sp1110__32_big_1024_ {
  strings:
    $a0 = { 70 70 70 00 82 82 82 00 2c 2c 2c 00 ec ec ec 00 b3 b3 b3 00 27 27 27 00 c0 c0 c0 00 e5 e5 e5 00 e4 e4 e4 00 85 85 85 00 57 57 57 00 35 35 35 00 ea ea ea 00 0c 0c 0c 00 ae ae ae 00 41 41 41 00 23 23 23 00 ef ef ef 00 6b 6b 6b 00 93 93 93 00 45 45 45 00 19 19 19 00 a5 a5 a5 00 21 21 21 00 ed ed ed 00 0e 0e 0e 00 4f 4f 4f 00 4e 4e 4e 00 1d 1d 1d 00 65 65 65 00 92 92 92 00 bd bd bd 00 86 86 86 00 b8 b8 b8 00 af af af 00 8f 8f 8f 00 7c 7c 7c 00 eb eb eb 00 1f 1f 1f 00 ce ce ce 00 3e 3e 3e 00 30 30 30 00 dc dc dc 00 5f 5f 5f 00 5e 5e 5e 00 c5 c5 c5 00 0b 0b 0b 00 1a 1a 1a 00 a6 a6 a6 00 e1 e1 e1 00 39 39 39 00 ca ca ca 00 d5 d5 d5 00 47 47 47 00 5d 5d 5d 00 3d 3d 3d 00 d9 d9 d9 00 01 01 01 00 5a 5a 5a 00 d6 d6 d6 00 51 51 51 00 56 56 56 00 6c 6c 6c 00 4d 4d 4d 00 8b 8b 8b 00 0d 0d 0d 00 9a 9a 9a 00 66 66 66 00 fb fb fb 00 cc cc cc 00 b0 b0 b0 00 2d 2d 2d 00 74 74 74 00 12 12 12 00 2b 2b 2b 00 20 20 20 00 f0 f0 f0 00 b1 b1 b1 00 84 84 84 00 99 99 99 00 df df df 00 4c 4c 4c 00 cb cb cb 00 c2 c2 c2 00 34 34 34 00 7e 7e 7e 00 76 76 76 00 05 05 05 00 6d 6d 6d 00 b7 b7 b7 00 a9 a9 a9 00 31 31 31 00 d1 d1 d1 00 17 17 17 00 04 04 04 00 d7 d7 d7 00 14 14 14 00 58 58 58 00 3a 3a 3a 00 61 61 61 00 de de de 00 1b 1b 1b 00 11 11 11 00 1c 1c 1c 00 32 32 32 00 0f 0f 0f 00 9c 9c 9c 00 16 16 16 00 53 53 53 00 18 18 18 00 f2 f2 f2 00 22 22 22 00 fe fe fe 00 44 44 44 00 cf cf cf 00 b2 b2 b2 00 c3 c3 c3 00 b5 b5 b5 00 7a 7a 7a 00 91 91 91 00 24 24 24 00 08 08 08 00 e8 e8 e8 00 a8 a8 a8 00 60 60 60 00 fc fc fc 00 69 69 69 00 50 50 50 00 aa aa aa 00 d0 d0 d0 00 a0 a0 a0 00 7d 7d 7d 00 a1 a1 a1 00 89 89 89 00 62 62 62 00 97 97 97 00 54 54 54 00 5b 5b 5b 00 1e 1e 1e 00 95 95 95 00 e0 e0 e0 00 ff ff ff 00 64 64 64 00 d2 d2 d2 00 10 10 10 00 c4 c4 c4 00 00 00 00 00 48 48 48 00 a3 a3 a3 00 f7 f7 f7 00 75 75 75 00 db db db 00 8a 8a 8a 00 03 03 03 00 e6 e6 e6 00 da da da 00 09 09 09 00 3f 3f 3f 00 dd dd dd 00 94 94 94 00 87 87 87 00 5c 5c 5c 00 83 83 83 00 02 02 02 00 cd cd cd 00 4a 4a 4a 00 90 90 90 00 33 33 33 00 73 73 73 00 67 67 67 00 f6 f6 f6 00 f3 f3 f3 00 9d 9d 9d 00 7f 7f 7f 00 bf bf bf 00 e2 e2 e2 00 52 52 52 00 9b 9b 9b 00 d8 d8 d8 00 26 26 26 00 c8 c8 c8 00 37 37 37 00 c6 c6 c6 00 3b 3b 3b 00 81 81 81 00 96 96 96 00 6f 6f 6f 00 4b 4b 4b 00 13 13 13 00 be be be 00 63 63 63 00 2e 2e 2e 00 e9 e9 e9 00 79 79 79 00 a7 a7 a7 00 8c 8c 8c 00 9f 9f 9f 00 6e 6e 6e 00 bc bc bc 00 8e 8e 8e 00 29 29 29 00 f5 f5 f5 00 f9 f9 f9 00 b6 b6 b6 00 2f 2f 2f 00 fd fd fd 00 b4 b4 b4 00 59 59 59 00 78 78 78 00 98 98 98 00 06 06 06 00 6a 6a 6a 00 e7 e7 e7 00 46 46 46 00 71 71 71 00 ba ba ba 00 d4 d4 d4 00 25 25 25 00 ab ab ab 00 42 42 42 00 88 88 88 00 a2 a2 a2 00 8d 8d 8d 00 fa fa fa 00 72 72 72 00 07 07 07 00 b9 b9 b9 00 55 55 55 00 f8 f8 f8 00 ee ee ee 00 ac ac ac 00 0a 0a 0a 00 36 36 36 00 49 49 49 00 2a 2a 2a 00 68 68 68 00 3c 3c 3c 00 38 38 38 00 f1 f1 f1 00 a4 a4 a4 00 40 40 40 00 28 28 28 00 d3 d3 d3 00 7b 7b 7b 00 bb bb bb 00 c9 c9 c9 00 43 43 43 00 c1 c1 c1 00 15 15 15 00 e3 e3 e3 00 ad ad ad 00 f4 f4 f4 00 77 77 77 00 c7 c7 c7 00 80 80 80 00 9e 9e 9e 00 }

  condition:
    $a0
}

rule Dolby_window_dol_short__flt32___32_lil_512_ {
  strings:
    $a0 = { 47 b1 37 38 89 e0 f8 38 82 ec 71 39 28 32 cc 39 67 cf 1e 3a e7 d4 69 3a 7b 60 a5 3a f4 c6 e2 3a 99 a6 17 3b 6f aa 46 3b c8 b8 7f 3b f1 19 a2 3b d0 ca ca 3b 2d b7 fa 3b d7 58 19 3c 44 cb 39 3c 31 25 5f 3c 44 ee 84 3c 07 35 9d 3c 4e a4 b8 3c 1a 7a d7 3c 8c f4 f9 3c af 28 10 3d af 66 25 3d ee d1 3c 3d 0d 87 56 3d 59 a1 72 3d 3f 9d 88 3d 1e 35 99 3d 0e 23 ab 3d 92 70 be 3d c9 25 d3 3d 4a 49 e9 3d 04 70 00 3e 97 f6 0c 3e 07 39 1a 3e ff 36 28 3e 28 ef 36 3e 1f 5f 46 3e 70 83 56 3e 90 57 67 3e e2 d5 78 3e da 7b 85 3e a1 da 8e 3e e4 82 98 3e bc 6f a2 3e cc 9b ac 3e 44 01 b7 3e ea 99 c1 3e 23 5f cc 3e fe 49 d7 3e 40 53 e2 3e 6e 73 ed 3e de a2 f8 3e e0 ec 01 3f 19 88 07 3f 24 1f 0d 3f 10 ae 12 3f f6 30 18 3f 02 a4 1d 3f 7a 03 23 3f c5 4b 28 3f 72 79 2d 3f 3b 89 32 3f 11 78 37 3f 1c 43 3c 3f c3 e7 40 3f af 63 45 3f cf b4 49 3f 5a d9 4d 3f d3 cf 51 3f 09 97 55 3f 18 2e 59 3f 69 94 5c 3f b2 c9 5f 3f f2 cd 62 3f 71 a1 65 3f bd 44 68 3f a3 b8 6a 3f 30 fe 6c 3f a6 16 6f 3f 7d 03 71 3f 59 c6 72 3f 04 61 74 3f 6a d5 75 3f 92 25 77 3f 96 53 78 3f a0 61 79 3f de 51 7a 3f 83 26 7b 3f be e1 7b 3f b2 85 7c 3f 77 14 7d 3f 13 90 7d 3f 73 fa 7d 3f 70 55 7e 3f c3 a2 7e 3f 0c e4 7e 3f ca 1a 7f 3f 5d 48 7f 3f 07 6e 7f 3f eb 8c 7f 3f 0d a6 7f 3f 54 ba 7f 3f 8c ca 7f 3f 66 d7 7f 3f 7c e1 7f 3f 53 e9 7f 3f 5a ef 7f 3f ee f3 7f 3f 5f f7 7f 3f ec f9 7f 3f c9 fb 7f 3f 21 fd 7f 3f 15 fe 7f 3f bf fe 7f 3f 33 ff 7f 3f 80 ff 7f 3f b3 ff 7f 3f d3 ff 7f 3f e7 ff 7f 3f f3 ff 7f 3f f9 ff 7f 3f fd ff 7f 3f ff ff 7f 3f 00 00 80 3f 00 00 80 3f 00 00 80 3f }

  condition:
    $a0
}

rule MPEG_2_NBC_sfb_96_128_and_sfb_64_128__avcodec___faad___16_lil_24_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 20 00 28 00 30 00 40 00 5c 00 80 00 }

  condition:
    $a0
}

rule libfaad2_f_huff_ipd__8_byt_14_ {
  strings:
    $a0 = { 01 E1 02 03 E2 04 05 06 E5 E6 E4 E7 E3 E8 }

  condition:
    $a0
}

rule libfaad2_t_huff_icc__8_byt_28_ {
  strings:
    $a0 = { E1 01 E2 02 E0 03 E3 04 DF 05 E4 06 DE 07 E5 08 DD 09 E6 0A DC 0B E7 0C DB 0D DA E8 }

  condition:
    $a0
}

rule MPEG_2_NBC_sfb_24_128__avcodec___faad___16_big_30_ {
  strings:
    $a0 = { 00 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 24 00 2c 00 34 00 40 00 4c 00 5c 00 6c 00 80 }

  condition:
    $a0
}

rule libavcodec_swb_offset_1024_32__16_lil_104_ {
  strings:
    $a0 = { 00 00 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 24 00 28 00 30 00 38 00 40 00 48 00 50 00 58 00 60 00 6c 00 78 00 84 00 90 00 a0 00 b0 00 c4 00 d8 00 f0 00 08 01 24 01 40 01 60 01 80 01 a0 01 c0 01 e0 01 00 02 20 02 40 02 60 02 80 02 a0 02 c0 02 e0 02 00 03 20 03 40 03 60 03 80 03 a0 03 c0 03 e0 03 00 04 }

  condition:
    $a0
}

rule libfaad2_f_huff_icc__8_byt_28_ {
  strings:
    $a0 = { E1 01 E2 02 E0 03 E3 04 DF 05 E4 06 DE 07 E5 08 E6 09 DD 0A E7 0B DC 0C E8 0D DB DA }

  condition:
    $a0
}

rule MPEG_2_NBC_sfb_96_128_and_sfb_64_128__avcodec___faad___16_big_24_ {
  strings:
    $a0 = { 00 04 00 08 00 0c 00 10 00 14 00 18 00 20 00 28 00 30 00 40 00 5c 00 80 }

  condition:
    $a0
}

rule libfaad2_f_huff_iid_fine__8_byt_120_ {
  strings:
    $a0 = { 01 E1 02 03 04 E0 E2 05 DF E3 06 07 DE E4 08 09 DD E5 0A 0B DC E6 0C 0D DB E7 0E 0F E8 10 11 12 13 D9 E9 14 15 DA EB 16 17 D8 EA 18 D6 EC 19 1A 1B D7 1C D5 ED 1D 1E 1F 20 D3 EF 21 22 D4 EE 23 24 25 26 D2 F0 27 28 29 2A 2B D0 F2 2C 2D 2E 2F 30 31 D1 F1 CC F6 CE F4 CF F3 32 33 34 35 36 37 38 39 3A 3B C7 C8 C5 C6 CB F7 C9 CA FA FB F8 F9 FE FF FC FD C3 C4 CD F5 }

  condition:
    $a0
}

rule MPEG_2_NBC_sfb_16_128__avcodec___faad___16_lil_30_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 28 00 30 00 3c 00 48 00 58 00 6c 00 80 00 }

  condition:
    $a0
}

rule libfaad2_t_huff_iid_def__8_byt_56_ {
  strings:
    $a0 = { E1 01 E0 02 E2 03 DF 04 E3 05 DE 06 E4 07 DD 08 E5 09 DC 0A E6 0B DB 0C E7 0D E8 0E DA 0F 10 11 E9 D9 12 13 14 15 16 17 EA D3 D4 D5 18 19 1A 1B D6 D7 D8 EB EC ED EE EF }

  condition:
    $a0
}

rule MPEG_2_NBC_sfb_8_128__avcodec___faad___16_lil_30_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 24 00 2c 00 34 00 3c 00 48 00 58 00 6c 00 80 00 }

  condition:
    $a0
}

rule MPEG_2_NBC_sfb_16_128__avcodec___faad___16_big_30_ {
  strings:
    $a0 = { 00 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 20 00 28 00 30 00 3c 00 48 00 58 00 6c 00 80 }

  condition:
    $a0
}

rule libfaad2_f_huff_opd__8_byt_14_ {
  strings:
    $a0 = { 01 E1 02 03 E8 E2 04 05 E4 E7 E3 06 E6 E5 }

  condition:
    $a0
}

rule Dolby_window_dol_long__flt32___32_lil_4096_ {
  strings:
    $a0 = { f2 62 99 39 b3 6f e1 39 26 53 0f 3a 6e a8 2b 3a a0 e3 46 3a 71 99 61 3a a8 1f 7c 3a 68 56 8b 3a 09 b3 98 3a 10 33 a6 3a 7c e0 b3 3a 10 c3 c1 3a 00 e1 cf 3a 64 3f de 3a 83 e2 ec 3a 05 ce fb 3a 8f 82 05 3b 50 45 0d 3b 8d 30 15 3b 6f 45 1d 3b 06 85 25 3b 53 f0 2d 3b 43 88 36 3b ba 4d 3f 3b 90 41 48 3b 92 64 51 3b 88 b7 5a 3b 33 3b 64 3b 50 f0 6d 3b 94 d7 77 3b d9 f8 80 3b ae 1f 86 3b 9e 60 8b 3b ff bb 90 3b 24 32 96 3b 62 c3 9b 3b 09 70 a1 3b 6c 38 a7 3b dc 1c ad 3b a8 1d b3 3b 21 3b b9 3b 97 75 bf 3b 57 cd c5 3b b1 42 cc 3b f4 d5 d2 3b 6c 87 d9 3b 69 57 e0 3b 38 46 e7 3b 27 54 ee 3b 82 81 f5 3b 97 ce fc 3b da 1d 02 3c 92 e4 05 3c 9a bb 09 3c 19 a3 0d 3c 35 9b 11 3c 14 a4 15 3c dc bd 19 3c b4 e8 1d 3c c1 24 22 3c 2a 72 26 3c 15 d1 2a 3c a7 41 2f 3c 06 c4 33 3c 59 58 38 3c c5 fe 3c 3c 71 b7 41 3c 80 82 46 3c 1b 60 4b 3c 65 50 50 3c 85 53 55 3c a1 69 5a 3c dd 92 5f 3c 5f cf 64 3c 4d 1f 6a 3c cc 82 6f 3c 01 fa 74 3c 11 85 7a 3c 11 12 80 3c ac eb 82 3c 6d cf 85 3c 66 bd 88 3c a8 b5 8b 3c 48 b8 8e 3c 56 c5 91 3c e6 dc 94 3c 09 ff 97 3c d3 2b 9b 3c 54 63 9e 3c 9f a5 a1 3c c7 f2 a4 3c dd 4a a8 3c f3 ad ab 3c 1b 1c af 3c 68 95 b2 3c ea 19 b6 3c b5 a9 b9 3c d8 44 bd 3c 67 eb c0 3c 73 9d c4 3c 0c 5b c8 3c 46 24 cc 3c 30 f9 cf 3c dd d9 d3 3c 5d c6 d7 3c c3 be db 3c 1e c3 df 3c 81 d3 e3 3c fb ef e7 3c 9e 18 ec 3c 7b 4d f0 3c a3 8e f4 3c 25 dc f8 3c 14 36 fd 3c 3f ce 00 3d ba 07 03 3d 84 47 05 3d a5 8d 07 3d 24 da 09 3d 09 2d 0c 3d 5e 86 0e 3d 28 e6 10 3d 71 4c 13 3d 40 b9 15 3d 9d 2c 18 3d 90 a6 1a 3d 20 27 1d 3d 55 ae 1f 3d 37 3c 22 3d cd d0 24 3d 1e 6c 27 3d 31 0e 2a 3d 0f b7 2c 3d bf 66 2f 3d 47 1d 32 3d af da 34 3d fd 9e 37 3d 3a 6a 3a 3d 6c 3c 3d 3d 99 15 40 3d c9 f5 42 3d 03 dd 45 3d 4d cb 48 3d ad c0 4b 3d 2b bd 4e 3d cd c0 51 3d 99 cb 54 3d 96 dd 57 3d c9 f6 5a 3d 3a 17 5e 3d ef 3e 61 3d ed 6d 64 3d 3b a4 67 3d de e1 6a 3d dc 26 6e 3d 3c 73 71 3d 02 c7 74 3d 35 22 78 3d da 84 7b 3d f7 ee 7e 3d 48 30 81 3d d6 ec 82 3d 28 ad 84 3d 40 71 86 3d 21 39 88 3d cd 04 8a 3d 47 d4 8b 3d 92 a7 8d 3d af 7e 8f 3d a1 59 91 3d 6a 38 93 3d 0d 1b 95 3d 8c 01 97 3d e8 eb 98 3d 25 da 9a 3d 43 cc 9c 3d 46 c2 9e 3d 2f bc a0 3d ff b9 a2 3d ba bb a4 3d 61 c1 a6 3d f4 ca a8 3d 78 d8 aa 3d ec e9 ac 3d 53 ff ae 3d ae 18 b1 3d ff 35 b3 3d 47 57 b5 3d 88 7c b7 3d c3 a5 b9 3d fa d2 bb 3d 2d 04 be 3d 5f 39 c0 3d 90 72 c2 3d c2 af c4 3d f5 f0 c6 3d 2b 36 c9 3d 64 7f cb 3d a3 cc cd 3d e7 1d d0 3d 31 73 d2 3d 82 cc d4 3d dc 29 d7 3d 3e 8b d9 3d a9 f0 db 3d 1f 5a de 3d 9f c7 e0 3d 2a 39 e3 3d c0 ae e5 3d 62 28 e8 3d 10 a6 ea 3d cb 27 ed 3d 92 ad ef 3d 66 37 f2 3d 46 c5 f4 3d 34 57 f7 3d 2f ed f9 3d 36 87 fc 3d 4a 25 ff 3d b6 e3 00 3e cc 36 02 3e e9 8b 03 3e 0b e3 04 3e 34 3c 06 3e 61 97 07 3e 94 f4 08 3e cc 53 0a 3e 08 b5 0b 3e 49 18 0d 3e 8d 7d 0e 3e d5 e4 0f 3e 20 4e 11 3e 6e b9 12 3e be 26 14 3e 10 96 15 3e 62 07 17 3e b5 7a 18 3e 09 f0 19 3e 5b 67 1b 3e ac e0 1c 3e fb 5b 1e 3e 47 d9 1f 3e 90 58 21 3e d5 d9 22 3e 14 5d 24 3e 4e e2 25 3e 81 69 27 3e ac f2 28 3e ce 7d 2a 3e e8 0a 2c 3e f6 99 2d 3e f9 2a 2f 3e f0 bd 30 3e d9 52 32 3e b3 e9 33 3e 7e 82 35 3e 37 1d 37 3e df b9 38 3e 73 58 3a 3e f2 f8 3b 3e 5b 9b 3d 3e ae 3f 3f 3e e8 e5 40 3e 07 8e 42 3e 0c 38 44 3e f4 e3 45 3e be 91 47 3e 68 41 49 3e f1 f2 4a 3e 58 a6 4c 3e 9a 5b 4e 3e b6 12 50 3e ab cb 51 3e 77 86 53 3e 18 43 55 3e 8d 01 57 3e d3 c1 58 3e ea 83 5a 3e ce 47 5c 3e 7f 0d 5e 3e fb d4 5f 3e 3f 9e 61 3e 4a 69 63 3e 1a 36 65 3e ad 04 67 3e 00 d5 68 3e 12 a7 6a 3e e1 7a 6c 3e 6b 50 6e 3e ad 27 70 3e a6 00 72 3e 53 db 73 3e b2 b7 75 3e c1 95 77 3e 7d 75 79 3e e5 56 7b 3e f6 39 7d 3e ad 1e 7f 3e 85 82 80 3e 83 76 81 3e 52 6b 82 3e ef 60 83 3e 5a 57 84 3e 91 4e 85 3e 92 46 86 3e 5d 3f 87 3e f0 38 88 3e 4a 33 89 3e 6a 2e 8a 3e 4e 2a 8b 3e f5 26 8c 3e 5e 24 8d 3e 87 22 8e 3e 6f 21 8f 3e 14 21 90 3e 76 21 91 3e 92 22 92 3e 68 24 93 3e f5 26 94 3e 39 2a 95 3e 31 2e 96 3e dd 32 97 3e 3b 38 98 3e 4a 3e 99 3e 07 45 9a 3e 72 4c 9b 3e 89 54 9c 3e 4a 5d 9d 3e b4 66 9e 3e c5 70 9f 3e 7c 7b a0 3e d6 86 a1 3e d4 92 a2 3e 72 9f a3 3e af ac a4 3e 8a ba a5 3e 01 c9 a6 3e 12 d8 a7 3e bb e7 a8 3e fc f7 a9 3e d2 08 ab 3e 3b 1a ac 3e 37 2c ad 3e c2 3e ae 3e dc 51 af 3e 83 65 b0 3e b4 79 b1 3e 6f 8e b2 3e b1 a3 b3 3e 78 b9 b4 3e c4 cf b5 3e 91 e6 b6 3e df fd b7 3e ab 15 b9 3e f4 2d ba 3e b7 46 bb 3e f4 5f bc 3e a8 79 bd 3e d0 93 be 3e 6d ae bf 3e 7a c9 c0 3e f8 e4 c1 3e e3 00 c3 3e 3a 1d c4 3e fb 39 c5 3e 24 57 c6 3e b3 74 c7 3e a6 92 c8 3e fb b0 c9 3e b1 cf ca 3e c5 ee cb 3e 36 0e cd 3e 01 2e ce 3e 25 4e cf 3e 9f 6e d0 3e 6d 8f d1 3e 8f b0 d2 3e 00 d2 d3 3e c1 f3 d4 3e ce 15 d6 3e 25 38 d7 3e c5 5a d8 3e ac 7d d9 3e d7 a0 da 3e 44 c4 db 3e f2 e7 dc 3e df 0b de 3e 08 30 df 3e 6b 54 e0 3e 06 79 e1 3e d8 9d e2 3e dd c2 e3 3e 15 e8 e4 3e 7d 0d e6 3e 13 33 e7 3e d4 58 e8 3e bf 7e e9 3e d3 a4 ea 3e 0b cb eb 3e 67 f1 ec 3e e5 17 ee 3e 82 3e ef 3e 3c 65 f0 3e 12 8c f1 3e 00 b3 f2 3e 05 da f3 3e 20 01 f5 3e 4c 28 f6 3e 8a 4f f7 3e d6 76 f8 3e 2e 9e f9 3e 91 c5 fa 3e fc ec fb 3e 6d 14 fd 3e e2 3b fe 3e 59 63 ff 3e 67 45 00 3f 21 d9 00 3f d9 6c 01 3f 8e 00 02 3f 3e 94 02 3f e8 27 03 3f 8c bb 03 3f 29 4f 04 3f bd e2 04 3f 47 76 05 3f c6 09 06 3f 3a 9d 06 3f a1 30 07 3f fa c3 07 3f 44 57 08 3f 7e ea 08 3f a6 7d 09 3f bd 10 0a 3f c1 a3 0a 3f b0 36 0b 3f 8a c9 0b 3f 4e 5c 0c 3f fb ee 0c 3f 8f 81 0d 3f 09 14 0e 3f 69 a6 0e 3f ae 38 0f 3f d6 ca 0f 3f e1 5c 10 3f cc ee 10 3f 99 80 11 3f 44 12 12 3f ce a3 12 3f 35 35 13 3f 78 c6 13 3f 96 57 14 3f 8f e8 14 3f 61 79 15 3f 0b 0a 16 3f 8c 9a 16 3f e3 2a 17 3f 0f bb 17 3f 10 4b 18 3f e3 da 18 3f 89 6a 19 3f 00 fa 19 3f 47 89 1a 3f 5d 18 1b 3f 41 a7 1b 3f f3 35 1c 3f 70 c4 1c 3f b9 52 1d 3f cc e0 1d 3f a9 6e 1e 3f 4e fc 1e 3f ba 89 1f 3f ed 16 20 3f e5 a3 20 3f a1 30 21 3f 21 bd 21 3f 64 49 22 3f 69 d5 22 3f 2e 61 23 3f b3 ec 23 3f f7 77 24 3f f9 02 25 3f b8 8d 25 3f 33 18 26 3f 6a a2 26 3f 5a 2c 27 3f 05 b6 27 3f 67 3f 28 3f 82 c8 28 3f 53 51 29 3f da d9 29 3f 17 62 2a 3f 07 ea 2a 3f ab 71 2b 3f 01 f9 2b 3f 09 80 2c 3f c1 06 2d 3f 2a 8d 2d 3f 41 13 2e 3f 07 99 2e 3f 7a 1e 2f 3f 9a a3 2f 3f 65 28 30 3f dc ac 30 3f fd 30 31 3f c7 b4 31 3f 3a 38 32 3f 54 bb 32 3f 16 3e 33 3f 7d c0 33 3f 8b 42 34 3f 3d c4 34 3f 93 45 35 3f 8c c6 35 3f 27 47 36 3f 65 c7 36 3f 43 47 37 3f c2 c6 37 3f e0 45 38 3f 9d c4 38 3f f9 42 39 3f f1 c0 39 3f 87 3e 3a 3f b8 bb 3a 3f 85 38 3b 3f ed b4 3b 3f ef 30 3c 3f 8a ac 3c 3f be 27 3d 3f 8a a2 3d 3f ed 1c 3e 3f e8 96 3e 3f 78 10 3f 3f 9e 89 3f 3f 5a 02 40 3f a9 7a 40 3f 8d f2 40 3f 03 6a 41 3f 0c e1 41 3f a8 57 42 3f d4 cd 42 3f 92 43 43 3f e0 b8 43 3f be 2d 44 3f 2b a2 44 3f 27 16 45 3f b2 89 45 3f ca fc 45 3f 6f 6f 46 3f a1 e1 46 3f 5f 53 47 3f a9 c4 47 3f 7f 35 48 3f df a5 48 3f c9 15 49 3f 3d 85 49 3f 3b f4 49 3f c2 62 4a 3f d2 d0 4a 3f 69 3e 4b 3f 88 ab 4b 3f 2f 18 4c 3f 5d 84 4c 3f 11 f0 4c 3f 4b 5b 4d 3f 0b c6 4d 3f 51 30 4e 3f 1c 9a 4e 3f 6b 03 4f 3f 3f 6c 4f 3f 97 d4 4f 3f 72 3c 50 3f d1 a3 50 3f b3 0a 51 3f 18 71 51 3f ff d6 51 3f 68 3c 52 3f 53 a1 52 3f c0 05 53 3f af 69 53 3f 1e cd 53 3f 0e 30 54 3f 7f 92 54 3f 71 f4 54 3f e2 55 55 3f d4 b6 55 3f 45 17 56 3f 36 77 56 3f a6 d6 56 3f 95 35 57 3f 03 94 57 3f f0 f1 57 3f 5c 4f 58 3f 46 ac 58 3f af 08 59 3f 96 64 59 3f fb bf 59 3f de 1a 5a 3f 3e 75 5a 3f 1d cf 5a 3f 79 28 5b 3f 53 81 5b 3f aa d9 5b 3f 7f 31 5c 3f d1 88 5c 3f a0 df 5c 3f ed 35 5d 3f b7 8b 5d 3f fe e0 5d 3f c2 35 5e 3f 03 8a 5e 3f c1 dd 5e 3f fd 30 5f 3f b5 83 5f 3f eb d5 5f 3f 9e 27 60 3f ce 78 60 3f 7b c9 60 3f a6 19 61 3f 4e 69 61 3f 73 b8 61 3f 15 07 62 3f 35 55 62 3f d3 a2 62 3f ee ef 62 3f 87 3c 63 3f 9e 88 63 3f 33 d4 63 3f 46 1f 64 3f d7 69 64 3f e6 b3 64 3f 74 fd 64 3f 81 46 65 3f 0c 8f 65 3f 16 d7 65 3f a0 1e 66 3f a8 65 66 3f 30 ac 66 3f 38 f2 66 3f bf 37 67 3f c7 7c 67 3f 4e c1 67 3f 56 05 68 3f df 48 68 3f e9 8b 68 3f 74 ce 68 3f 80 10 69 3f 0e 52 69 3f 1d 93 69 3f af d3 69 3f c3 13 6a 3f 5a 53 6a 3f 74 92 6a 3f 11 d1 6a 3f 31 0f 6b 3f d5 4c 6b 3f fe 89 6b 3f ab c6 6b 3f dc 02 6c 3f 93 3e 6c 3f cf 79 6c 3f 90 b4 6c 3f d8 ee 6c 3f a6 28 6d 3f fb 61 6d 3f d7 9a 6d 3f 3b d3 6d 3f 26 0b 6e 3f 9a 42 6e 3f 96 79 6e 3f 1b b0 6e 3f 29 e6 6e 3f c2 1b 6f 3f e4 50 6f 3f 91 85 6f 3f c9 b9 6f 3f 8c ed 6f 3f db 20 70 3f b6 53 70 3f 1e 86 70 3f 13 b8 70 3f 96 e9 70 3f a6 1a 71 3f 45 4b 71 3f 73 7b 71 3f 30 ab 71 3f 7c da 71 3f 59 09 72 3f c7 37 72 3f c6 65 72 3f 57 93 72 3f 79 c0 72 3f 2f ed 72 3f 77 19 73 3f 53 45 73 3f c3 70 73 3f c8 9b 73 3f 62 c6 73 3f 91 f0 73 3f 57 1a 74 3f b3 43 74 3f a6 6c 74 3f 31 95 74 3f 55 bd 74 3f 11 e5 74 3f 66 0c 75 3f 55 33 75 3f de 59 75 3f 03 80 75 3f c2 a5 75 3f 1e cb 75 3f 16 f0 75 3f ab 14 76 3f de 38 76 3f af 5c 76 3f 1f 80 76 3f 2e a3 76 3f dd c5 76 3f 2c e8 76 3f 1c 0a 77 3f ae 2b 77 3f e2 4c 77 3f b9 6d 77 3f 33 8e 77 3f 51 ae 77 3f 13 ce 77 3f 7a ed 77 3f 87 0c 78 3f 3a 2b 78 3f 94 49 78 3f 95 67 78 3f 3e 85 78 3f 90 a2 78 3f 8b bf 78 3f 2f dc 78 3f 7e f8 78 3f 78 14 79 3f 1d 30 79 3f 6f 4b 79 3f 6d 66 79 3f 18 81 79 3f 72 9b 79 3f 7a b5 79 3f 31 cf 79 3f 97 e8 79 3f ae 01 7a 3f 76 1a 7a 3f ef 32 7a 3f 1b 4b 7a 3f f9 62 7a 3f 8a 7a 7a 3f d0 91 7a 3f ca a8 7a 3f 79 bf 7a 3f de d5 7a 3f f9 eb 7a 3f cb 01 7b 3f 54 17 7b 3f 96 2c 7b 3f 90 41 7b 3f 44 56 7b 3f b2 6a 7b 3f da 7e 7b 3f be 92 7b 3f 5d a6 7b 3f b8 b9 7b 3f d0 cc 7b 3f a6 df 7b 3f 3a f2 7b 3f 8d 04 7c 3f 9f 16 7c 3f 71 28 7c 3f 03 3a 7c 3f 57 4b 7c 3f 6c 5c 7c 3f 43 6d 7c 3f dd 7d 7c 3f 3b 8e 7c 3f 5c 9e 7c 3f 43 ae 7c 3f ee bd 7c 3f 5f cd 7c 3f 96 dc 7c 3f 95 eb 7c 3f 5a fa 7c 3f e8 08 7d 3f 3e 17 7d 3f 5e 25 7d 3f 47 33 7d 3f fa 40 7d 3f 79 4e 7d 3f c3 5b 7d 3f d8 68 7d 3f bb 75 7d 3f 6a 82 7d 3f e7 8e 7d 3f 32 9b 7d 3f 4c a7 7d 3f 35 b3 7d 3f ee be 7d 3f 77 ca 7d 3f d1 d5 7d 3f fc e0 7d 3f fa eb 7d 3f c9 f6 7d 3f 6c 01 7e 3f e3 0b 7e 3f 2d 16 7e 3f 4c 20 7e 3f 40 2a 7e 3f 09 34 7e 3f a9 3d 7e 3f 1f 47 7e 3f 6c 50 7e 3f 91 59 7e 3f 8e 62 7e 3f 63 6b 7e 3f 12 74 7e 3f 9a 7c 7e 3f fc 84 7e 3f 39 8d 7e 3f 50 95 7e 3f 44 9d 7e 3f 13 a5 7e 3f be ac 7e 3f 46 b4 7e 3f ac bb 7e 3f ef c2 7e 3f 11 ca 7e 3f 12 d1 7e 3f f1 d7 7e 3f b0 de 7e 3f 50 e5 7e 3f cf eb 7e 3f 30 f2 7e 3f 72 f8 7e 3f 96 fe 7e 3f 9b 04 7f 3f 84 0a 7f 3f 50 10 7f 3f ff 15 7f 3f 92 1b 7f 3f 09 21 7f 3f 65 26 7f 3f a6 2b 7f 3f cc 30 7f 3f d9 35 7f 3f cb 3a 7f 3f a5 3f 7f 3f 65 44 7f 3f 0d 49 7f 3f 9c 4d 7f 3f 14 52 7f 3f 74 56 7f 3f bd 5a 7f 3f f0 5e 7f 3f 0c 63 7f 3f 12 67 7f 3f 02 6b 7f 3f dd 6e 7f 3f a3 72 7f 3f 55 76 7f 3f f2 79 7f 3f 7b 7d 7f 3f f1 80 7f 3f 53 84 7f 3f a3 87 7f 3f df 8a 7f 3f 0a 8e 7f 3f 22 91 7f 3f 28 94 7f 3f 1e 97 7f 3f 02 9a 7f 3f d5 9c 7f 3f 98 9f 7f 3f 4a a2 7f 3f ed a4 7f 3f 80 a7 7f 3f 03 aa 7f 3f 78 ac 7f 3f de ae 7f 3f 35 b1 7f 3f 7e b3 7f 3f b9 b5 7f 3f e6 b7 7f 3f 05 ba 7f 3f 18 bc 7f 3f 1d be 7f 3f 16 c0 7f 3f 02 c2 7f 3f e2 c3 7f 3f b6 c5 7f 3f 7e c7 7f 3f 3b c9 7f 3f ec ca 7f 3f 93 cc 7f 3f 2e ce 7f 3f bf cf 7f 3f 45 d1 7f 3f c1 d2 7f 3f 34 d4 7f 3f 9c d5 7f 3f fb d6 7f 3f 50 d8 7f 3f 9c d9 7f 3f e0 da 7f 3f 1a dc 7f 3f 4c dd 7f 3f 75 de 7f 3f 97 df 7f 3f b0 e0 7f 3f c1 e1 7f 3f ca e2 7f 3f cc e3 7f 3f c7 e4 7f 3f ba e5 7f 3f a7 e6 7f 3f 8c e7 7f 3f 6b e8 7f 3f 43 e9 7f 3f 15 ea 7f 3f e1 ea 7f 3f a6 eb 7f 3f 65 ec 7f 3f 1f ed 7f 3f d3 ed 7f 3f 82 ee 7f 3f 2b ef 7f 3f ce ef 7f 3f 6d f0 7f 3f 07 f1 7f 3f 9b f1 7f 3f 2b f2 7f 3f b7 f2 7f 3f 3d f3 7f 3f c0 f3 7f 3f 3e f4 7f 3f b8 f4 7f 3f 2e f5 7f 3f a0 f5 7f 3f 0e f6 7f 3f 78 f6 7f 3f df f6 7f 3f 42 f7 7f 3f a1 f7 7f 3f fe f7 7f 3f 57 f8 7f 3f ac f8 7f 3f ff f8 7f 3f 4f f9 7f 3f 9c f9 7f 3f e6 f9 7f 3f 2d fa 7f 3f 72 fa 7f 3f b4 fa 7f 3f f3 fa 7f 3f 31 fb 7f 3f 6b fb 7f 3f a4 fb 7f 3f da fb 7f 3f 0e fc 7f 3f 40 fc 7f 3f 70 fc 7f 3f 9e fc 7f 3f ca fc 7f 3f f5 fc 7f 3f 1d fd 7f 3f 44 fd 7f 3f 69 fd 7f 3f 8d fd 7f 3f af fd 7f 3f d0 fd 7f 3f ef fd 7f 3f 0d fe 7f 3f 29 fe 7f 3f 44 fe 7f 3f 5e fe 7f 3f 77 fe 7f 3f 8e fe 7f 3f a5 fe 7f 3f ba fe 7f 3f ce fe 7f 3f e2 fe 7f 3f f4 fe 7f 3f 05 ff 7f 3f 16 ff 7f 3f 26 ff 7f 3f 34 ff 7f 3f 42 ff 7f 3f 50 ff 7f 3f 5c ff 7f 3f 68 ff 7f 3f 73 ff 7f 3f 7e ff 7f 3f 88 ff 7f 3f 91 ff 7f 3f 9a ff 7f 3f a3 ff 7f 3f aa ff 7f 3f b2 ff 7f 3f b9 ff 7f 3f bf ff 7f 3f c5 ff 7f 3f ca ff 7f 3f d0 ff 7f 3f d5 ff 7f 3f d9 ff 7f 3f dd ff 7f 3f e1 ff 7f 3f e5 ff 7f 3f e8 ff 7f 3f eb ff 7f 3f ee ff 7f 3f f0 ff 7f 3f f3 ff 7f 3f f5 ff 7f 3f f7 ff 7f 3f f8 ff 7f 3f fa ff 7f 3f fb ff 7f 3f fc ff 7f 3f fd ff 7f 3f fe ff 7f 3f ff ff 7f 3f }

  condition:
    $a0
}

rule libfaad2_exp_table__flt32___32_lil_504_ {
  strings:
    $a0 = { 00 00 00 3f 00 00 80 3e 00 00 00 3e 00 00 80 3d 00 00 00 3d 00 00 80 3c 00 00 00 3c 00 00 80 3b 00 00 00 3b 00 00 80 3a 00 00 00 3a 00 00 80 39 00 00 00 39 00 00 80 38 00 00 00 38 00 00 80 37 00 00 00 37 00 00 80 36 00 00 00 36 00 00 80 35 00 00 00 35 00 00 80 34 00 00 00 34 00 00 80 33 00 00 00 33 00 00 80 32 00 00 00 32 00 00 80 31 00 00 00 31 00 00 80 30 00 00 00 30 00 00 80 2f 00 00 00 2f 00 00 80 2e 00 00 00 2e 00 00 80 2d 00 00 00 2d 00 00 80 2c 00 00 00 2c 00 00 80 2b 00 00 00 2b 00 00 80 2a 00 00 00 2a 00 00 80 29 00 00 00 29 00 00 80 28 00 00 00 28 00 00 80 27 00 00 00 27 00 00 80 26 00 00 00 26 00 00 80 25 00 00 00 25 00 00 80 24 00 00 00 24 00 00 80 23 00 00 00 23 00 00 80 22 00 00 00 22 00 00 80 21 00 00 00 21 00 00 80 20 00 00 00 20 00 00 80 1f 00 00 00 1f 00 00 80 1e 00 00 00 1e 00 00 80 1d 00 00 00 1d 00 00 80 1c 00 00 00 1c 00 00 80 1b 00 00 00 1b 00 00 80 1a 00 00 00 1a 00 00 80 19 00 00 00 19 00 00 80 18 00 00 00 18 00 00 80 17 00 00 00 17 00 00 80 16 00 00 00 16 00 00 80 15 00 00 00 15 00 00 80 14 00 00 00 14 00 00 80 13 00 00 00 13 00 00 80 12 00 00 00 12 00 00 80 11 00 00 00 11 00 00 80 10 00 00 00 10 00 00 80 0f 00 00 00 0f 00 00 80 0e 00 00 00 0e 00 00 80 0d 00 00 00 0d 00 00 80 0c 00 00 00 0c 00 00 80 0b 00 00 00 0b 00 00 80 0a 00 00 00 0a 00 00 80 09 00 00 00 09 00 00 80 08 00 00 00 08 00 00 80 07 00 00 00 07 00 00 80 06 00 00 00 06 00 00 80 05 00 00 00 05 00 00 80 04 00 00 00 04 00 00 80 03 00 00 00 03 00 00 80 02 00 00 00 02 00 00 80 01 00 00 00 01 00 00 80 00 }

  condition:
    $a0
}

rule libfaad2_f_huff_iid_def__8_byt_56_ {
  strings:
    $a0 = { E1 01 02 03 E2 E0 04 05 E3 DF 06 07 E4 DE 08 09 DD E5 E6 0A DC 0B E7 0C DB 0D DA 0E E8 0F 10 11 E9 D9 12 13 EA EB 14 15 D8 EC 16 17 D7 18 19 1A D6 D3 D4 D5 ED 1B EE EF }

  condition:
    $a0
}

rule MPEG_2_NBC_sfb_48_128__avcodec___faad___16_big_28_ {
  strings:
    $a0 = { 00 04 00 08 00 0c 00 10 00 14 00 1c 00 24 00 2c 00 38 00 44 00 50 00 60 00 70 00 80 }

  condition:
    $a0
}

rule mp3lib_huffman_tab_c1__16_lil_62_ {
  strings:
    $a0 = { F1 FF F9 FF FD FF FF FF 0F 00 0E 00 FF FF 0D 00 0C 00 FD FF FF FF 0B 00 0A 00 FF FF 09 00 08 00 F9 FF FD FF FF FF 07 00 06 00 FF FF 05 00 04 00 FD FF FF FF 03 00 02 00 FF FF 01 00 00 00 }

  condition:
    $a0
}

rule MPEG_2_NBC_sfb_24_128__avcodec___faad___16_lil_30_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 24 00 2c 00 34 00 40 00 4c 00 5c 00 6c 00 80 00 }

  condition:
    $a0
}

rule Gost_sBox__8_byt_128_ {
  strings:
    $a0 = { 04 0a 09 02 0d 08 00 0e 06 0b 01 0c 07 0f 05 03 0e 0b 04 0c 06 0d 0f 0a 02 03 08 01 00 07 05 09 05 08 01 0d 0a 03 04 02 0e 0f 0c 07 06 00 09 0b 07 0d 0a 01 00 08 09 0f 0e 04 06 0c 0b 02 05 03 06 0c 07 01 05 0f 0d 08 04 0a 09 0e 00 03 0b 02 04 0b 0a 00 07 02 01 0d 03 06 08 05 09 0c 0f 0e 0d 0b 04 01 03 0f 05 09 00 0a 0e 07 06 08 02 0c 01 0f 0d 00 05 07 0a 04 09 02 03 0e 06 0b 08 0c }

  condition:
    $a0
}

rule MPEG_2_NBC_sfb_8_128__avcodec___faad___16_big_30_ {
  strings:
    $a0 = { 00 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 24 00 2c 00 34 00 3c 00 48 00 58 00 6c 00 80 }

  condition:
    $a0
}

rule libfaad2_mnt_table__flt32___32_lil_512_ {
  strings:
    $a0 = { 00 00 74 3f 00 00 72 3f 00 00 70 3f 00 00 6e 3f 00 00 6d 3f 00 00 6b 3f 00 00 69 3f 00 00 67 3f 00 00 66 3f 00 00 64 3f 00 00 62 3f 00 00 61 3f 00 00 5f 3f 00 00 5e 3f 00 00 5c 3f 00 00 5a 3f 00 00 59 3f 00 00 57 3f 00 00 56 3f 00 00 54 3f 00 00 53 3f 00 00 52 3f 00 00 50 3f 00 00 4f 3f 00 00 4d 3f 00 00 4c 3f 00 00 4b 3f 00 00 49 3f 00 00 48 3f 00 00 47 3f 00 00 46 3f 00 00 44 3f 00 00 43 3f 00 00 42 3f 00 00 41 3f 00 00 40 3f 00 00 3e 3f 00 00 3d 3f 00 00 3c 3f 00 00 3b 3f 00 00 3a 3f 00 00 39 3f 00 00 38 3f 00 00 37 3f 00 00 36 3f 00 00 35 3f 00 00 33 3f 00 00 32 3f 00 00 31 3f 00 00 30 3f 00 00 2f 3f 00 00 2e 3f 00 00 2e 3f 00 00 2d 3f 00 00 2c 3f 00 00 2b 3f 00 00 2a 3f 00 00 29 3f 00 00 28 3f 00 00 27 3f 00 00 26 3f 00 00 25 3f 00 00 24 3f 00 00 24 3f 00 00 23 3f 00 00 22 3f 00 00 21 3f 00 00 20 3f 00 00 1f 3f 00 00 1f 3f 00 00 1e 3f 00 00 1d 3f 00 00 1c 3f 00 00 1b 3f 00 00 1b 3f 00 00 1a 3f 00 00 19 3f 00 00 18 3f 00 00 18 3f 00 00 17 3f 00 00 16 3f 00 00 15 3f 00 00 15 3f 00 00 14 3f 00 00 13 3f 00 00 13 3f 00 00 12 3f 00 00 11 3f 00 00 11 3f 00 00 10 3f 00 00 0f 3f 00 00 0f 3f 00 00 0e 3f 00 00 0d 3f 00 00 0d 3f 00 00 0c 3f 00 00 0b 3f 00 00 0b 3f 00 00 0a 3f 00 00 0a 3f 00 00 09 3f 00 00 08 3f 00 00 08 3f 00 00 07 3f 00 00 07 3f 00 00 06 3f 00 00 05 3f 00 00 05 3f 00 00 04 3f 00 00 04 3f 00 00 03 3f 00 00 03 3f 00 00 02 3f 00 00 02 3f 00 00 01 3f 00 00 01 3f 00 00 00 3f 00 00 ff 3e 00 00 fe 3e 00 00 fd 3e 00 00 fc 3e 00 00 fb 3e 00 00 fa 3e 00 00 f9 3e 00 00 f8 3e 00 00 f7 3e 00 00 f6 3e 00 00 f5 3e }

  condition:
    $a0
}

rule mp3lib_huffman_tab_c0__16_lil_62_ {
  strings:
    $a0 = { E3 FF EB FF F3 FF F9 FF FD FF FF FF 0B 00 0F 00 FF FF 0D 00 0E 00 FD FF FF FF 07 00 05 00 09 00 FD FF FF FF 06 00 03 00 FF FF 0A 00 0C 00 FD FF FF FF 02 00 01 00 FF FF 04 00 08 00 00 00 }

  condition:
    $a0
}

rule libfaad2_Phi_Fract_Qmf__flt32___32_lil_512_ {
  strings:
    $a0 = { 43 72 51 3f 8b 33 13 3f 5e 1a 87 be 3c ed 76 3f f9 35 7f bf 2a af a0 3d 03 b2 d2 be ba 51 69 bf 20 d7 37 3f 57 27 32 bf 23 e5 65 3f b5 3f e1 3e 62 bc e0 bd 3a 74 7e 3f 3c ed 78 bf 4d 0c 6f 3e c2 8c 0c bf 79 f7 55 bf 24 b5 19 3f 22 b8 4c bf da ae 74 3f 74 8c 96 3e b2 f2 40 3d 3f b7 7f 3f 5e 83 6c bf 15 ef c3 3e 8c 4a 2c bf 77 58 3d bf 7f 94 ef 3e 77 3e 62 bf 31 72 7d 3f 6a 48 10 3e 79 a7 4f 3e 59 ae 7a 3f a0 46 5a bf 77 c2 05 3f 4a ca 47 bf e7 0f 20 bf 81 d8 a5 3e a6 32 72 bf ea f7 7f 3f a2 ac 80 bc a8 fa b4 3e 43 79 6f 3f f7 a9 42 bf 3a 42 26 3f a3 5e 5e bf c2 ac fd be 2f 0e 30 3e 20 30 7c bf 20 30 7c 3f 2f 0e 30 be c2 ac fd 3e a3 5e 5e 3f 3a 42 26 bf f7 a9 42 3f 43 79 6f bf a8 fa b4 be a2 ac 80 3c ea f7 7f bf a6 32 72 3f 81 d8 a5 be e7 0f 20 3f 4a ca 47 3f 77 c2 05 bf a0 46 5a 3f 59 ae 7a bf 79 a7 4f be 6a 48 10 be 31 72 7d bf 77 3e 62 3f 7f 94 ef be 77 58 3d 3f 8c 4a 2c 3f 15 ef c3 be 5e 83 6c 3f 3f b7 7f bf b2 f2 40 bd 74 8c 96 be da ae 74 bf 22 b8 4c 3f 24 b5 19 bf 79 f7 55 3f c2 8c 0c 3f 4d 0c 6f be 3c ed 78 3f 3a 74 7e bf 62 bc e0 3d b5 3f e1 be 23 e5 65 bf 57 27 32 3f 20 d7 37 bf ba 51 69 3f 03 b2 d2 3e 2a af a0 bd f9 35 7f 3f 3c ed 76 bf 5e 1a 87 3e 8b 33 13 bf 43 72 51 bf 8b 33 13 3f 43 72 51 bf 3c ed 76 3f 5e 1a 87 3e 2a af a0 3d f9 35 7f 3f ba 51 69 bf 03 b2 d2 3e 57 27 32 bf 20 d7 37 bf b5 3f e1 3e 23 e5 65 bf 3a 74 7e 3f 62 bc e0 3d 4d 0c 6f 3e 3c ed 78 3f 79 f7 55 bf c2 8c 0c 3f 22 b8 4c bf 24 b5 19 bf 74 8c 96 3e da ae 74 bf 3f b7 7f 3f b2 f2 40 bd 15 ef c3 3e 5e 83 6c 3f 77 58 3d bf 8c 4a 2c 3f }

  condition:
    $a0
}

rule libfaad2_t_huff_ipd__8_byt_14_ {
  strings:
    $a0 = { 01 E1 02 03 04 05 E2 E8 E6 06 E3 E7 E5 E4 }

  condition:
    $a0
}

rule MMX_codes__32_lil_124_ {
  strings:
    $a0 = { 85 27 00 3f 8b 66 01 3f 5b f4 03 3f 68 f2 07 3f 38 98 0d 3f 3a 3b 15 3f 6e 5c 1f 3f 3d c0 2c 3f ee 99 3e 3f 9e df 56 3f 3b fa 78 3f 35 b0 95 3f 1b f9 bd 3f af b2 03 40 42 16 5a 40 46 0a 23 41 8d 9e 00 3f 78 c2 05 3f 3f 23 11 3f 1d 96 25 3f 80 c4 49 3f 49 c4 87 3f 26 79 dc 3f 9c 3c a3 40 f7 81 02 3f bd f1 19 3f d7 64 66 3f cf 06 24 40 d4 8b 0a 3f 75 3d a7 3f f3 04 35 3f }

  condition:
    $a0
}

rule mp3lib_intwinbase__32_lil_1028_ {
  strings:
    $a0 = { 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE FF FF FF FE FF FF FF FE FF FF FF FE FF FF FF FD FF FF FF FD FF FF FF FC FF FF FF FC FF FF FF FB FF FF FF FB FF FF FF FA FF FF FF F9 FF FF FF F9 FF FF FF F8 FF FF FF F7 FF FF FF F6 FF FF FF F5 FF FF FF F3 FF FF FF F2 FF FF FF F0 FF FF FF EF FF FF FF ED FF FF FF EB FF FF FF E8 FF FF FF E6 FF FF FF E3 FF FF FF E1 FF FF FF DD FF FF FF DA FF FF FF D7 FF FF FF D3 FF FF FF CF FF FF FF CB FF FF FF C6 FF FF FF C1 FF FF FF BC FF FF FF B7 FF FF FF B1 FF FF FF AB FF FF FF A5 FF FF FF 9F FF FF FF 98 FF FF FF 91 FF FF FF 8B FF FF FF 83 FF FF FF 7C FF FF FF 75 FF FF FF 6D FF FF FF 66 FF FF FF 5F FF FF FF 57 FF FF FF 50 FF FF FF 49 FF FF FF 42 FF FF FF 3C FF FF FF 36 FF FF FF 30 FF FF FF 2B FF FF FF 26 FF FF FF 22 FF FF FF 1F FF FF FF 1D FF FF FF 1C FF FF FF 1C FF FF FF 1D FF FF FF 20 FF FF FF 23 FF FF FF 29 FF FF FF 30 FF FF FF 38 FF FF FF 43 FF FF FF 4F FF FF FF 5D FF FF FF 6E FF FF FF 81 FF FF FF 96 FF FF FF AD FF FF FF C7 FF FF FF E3 FF FF FF 02 00 00 00 24 00 00 00 48 00 00 00 6F 00 00 00 99 00 00 00 C5 00 00 00 F4 00 00 00 26 01 00 00 5B 01 00 00 91 01 00 00 CB 01 00 00 07 02 00 00 45 02 00 00 85 02 00 00 C7 02 00 00 0B 03 00 00 50 03 00 00 97 03 00 00 DF 03 00 00 28 04 00 00 71 04 00 00 BA 04 00 00 03 05 00 00 4C 05 00 00 94 05 00 00 DA 05 00 00 1F 06 00 00 62 06 00 00 A2 06 00 00 DF 06 00 00 19 07 00 00 4E 07 00 00 7F 07 00 00 AA 07 00 00 D1 07 00 00 F0 07 00 00 09 08 00 00 1B 08 00 00 25 08 00 00 27 08 00 00 20 08 00 00 0F 08 00 00 F5 07 00 00 D0 07 00 00 A0 07 00 00 65 07 00 00 1E 07 00 00 CB 06 00 00 6C 06 00 00 FF 05 00 00 86 05 00 00 00 05 00 00 6B 04 00 00 CA 03 00 00 1A 03 00 00 5D 02 00 00 92 01 00 00 B9 00 00 00 D3 FF FF FF E0 FE FF FF DF FD FF FF D2 FC FF FF B9 FB FF FF 94 FA FF FF 64 F9 FF FF 2A F8 FF FF E6 F6 FF FF 99 F5 FF FF 44 F4 FF FF E9 F2 FF FF 87 F1 FF FF 21 F0 FF FF B7 EE FF FF 4C ED FF FF DF EB FF FF 73 EA FF FF 09 E9 FF FF A3 E7 FF FF 43 E6 FF FF E9 E4 FF FF 99 E3 FF FF 53 E2 FF FF 1A E1 FF FF EF DF FF FF D5 DE FF FF CD DD FF FF DA DC FF FF FD DB FF FF 38 DB FF FF 8F DA FF FF 01 DA FF FF 92 D9 FF FF 44 D9 FF FF 19 D9 FF FF 12 D9 FF FF 31 D9 FF FF 79 D9 FF FF EA D9 FF FF 88 DA FF FF 53 DB FF FF 4D DC FF FF 78 DD FF FF D4 DE FF FF 64 E0 FF FF 28 E2 FF FF 22 E4 FF FF 52 E6 FF FF B9 E8 FF FF 58 EB FF FF 2F EE FF FF 40 F1 FF FF 89 F4 FF FF 0B F8 FF FF C6 FB FF FF BA FF FF FF E6 03 00 00 4A 08 00 00 E4 0C 00 00 B5 11 00 00 BA 16 00 00 F2 1B 00 00 5C 21 00 00 F7 26 00 00 BF 2C 00 00 B4 32 00 00 D4 38 00 00 1B 3F 00 00 87 45 00 00 16 4C 00 00 C5 52 00 00 91 59 00 00 76 60 00 00 72 67 00 00 81 6E 00 00 A0 75 00 00 CB 7C 00 00 FF 83 00 00 38 8B 00 00 71 92 00 00 A8 99 00 00 D8 A0 00 00 FE A7 00 00 15 AF 00 00 19 B6 00 00 06 BD 00 00 D9 C3 00 00 8D CA 00 00 1E D1 00 00 8A D7 00 00 CA DD 00 00 DD E3 00 00 BE E9 00 00 69 EF 00 00 DC F4 00 00 13 FA 00 00 0A FF 00 00 BE 03 01 00 2D 08 01 00 54 0C 01 00 2F 10 01 00 BE 13 01 00 FC 16 01 00 E9 19 01 00 83 1C 01 00 C7 1E 01 00 B4 20 01 00 49 22 01 00 86 23 01 00 68 24 01 00 F0 24 01 00 1E 25 01 00 }

  condition:
    $a0
}

rule MPEG_2_NBC_sfb_48_128__avcodec___faad___16_lil_28_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 1c 00 24 00 2c 00 38 00 44 00 50 00 60 00 70 00 80 00 }

  condition:
    $a0
}

rule libfaad2_Q_Fract_allpass_Qmf__flt32___32_lil_1536_ {
  strings:
    $a0 = { 49 ca 47 3f e7 0f 20 3f 15 ef c3 3e 5e 83 6c 3f 5e e7 5a 3f c4 ba 04 3f b6 3f e1 be 22 e5 65 3f 5e 83 6c bf 15 ef c3 be 35 ce 83 bd 23 78 7f 3f 3c ed 78 bf 51 0c 6f be 5e 83 6c 3f 15 ef c3 be b2 23 6a bf 1f 06 cf 3e cc ac 80 3c ea f7 7f bf 15 ef c3 be 5e 83 6c 3f 96 0a 48 bf 83 bf 1f bf 59 ae 7a 3f 72 a7 4f be 15 ef c3 be 5e 83 6c bf cb 9d 44 3e 98 3c 7b bf ff b1 d2 3e ba 51 69 3f 5e 83 6c 3f 15 ef c3 3e f3 7e 75 3f a5 28 91 be 24 b8 4c bf 22 b5 19 3f 5e 83 6c bf 15 ef c3 3e 5b dd 31 3f b6 1e 38 3f f5 a9 42 bf 3c 42 26 bf 15 ef c3 3e 5e 83 6c bf 47 09 a2 be 76 d7 72 3f 85 94 ef 3e 75 3e 62 bf 15 ef c3 3e 5e 83 6c 3f f6 c8 7c bf fe c6 21 3e 3b ed 76 3f 65 1a 87 3e 5e 83 6c bf 15 ef c3 be bb bd 18 bf fc 70 4d bf f1 f2 40 bd 3f b7 7f 3f 5e 83 6c 3f 15 ef c3 be 67 14 df 3e 58 6c 66 bf 21 30 7c bf 1e 0e 30 3e 15 ef c3 be 5e 83 6c 3f d1 e2 7f 3f 44 74 f4 bc 0d ef c3 be 60 83 6c bf 15 ef c3 be 5e 83 6c bf 8d 2c fa 3e e7 5b 5f 3f 45 72 51 3f 87 33 13 bf 5e 83 6c 3f 15 ef c3 3e ae 36 0c bf eb 2f 56 3f 73 58 3d 3f 90 4a 2c 3f 5e 83 6c bf 15 ef c3 3e 5c bf 7e bf 0e 57 ca bd cc ac fd be a0 5e 5e 3f 15 ef c3 3e 5e 83 6c bf 8e b8 be be 79 93 6d bf d8 ae 74 bf 80 8c 96 be 15 ef c3 3e 5e 83 6c 3f 76 90 26 3f 0a 67 42 bf 5e af a0 3d f9 35 7f bf 5e 83 6c bf 15 ef c3 be 6d 63 79 3f 7d 38 67 3e 32 72 7d 3f 4e 48 10 be 5e 83 6c 3f 15 ef c3 be a3 1b 80 3e 64 db 77 3f 9a fa b4 3e 45 79 6f 3f 15 ef c3 be 5e 83 6c 3f c8 27 3e bf a1 65 2b 3f 7d f7 55 bf bc 8c 0c 3f 15 ef c3 be 5e 83 6c bf bd e5 6f bf 60 b8 b2 be 1a d7 37 bf 5d 27 32 bf 5e 83 6c 3f 15 ef c3 3e 79 7d fd bd 0d 08 7e bf 7f c2 05 3f 9c 46 5a bf 5e 83 6c bf 15 ef c3 3e 94 98 52 3f 42 8d 11 bf a4 32 72 3f 92 d8 a5 3e 15 ef c3 3e 5e 83 6c bf 8f 6e 62 3f 7d de ee 3e ab bc e0 bd 39 74 7e 3f 15 ef c3 3e 5e 83 6c 3f 16 6c 9a bb 46 ff 7f 3f 3b 74 7e bf 15 bc e0 3d 5e 83 6c bf 15 ef c3 be 28 8c 63 bf 18 97 ea 3e 6e d8 a5 be aa 32 72 bf 5e 83 6c 3f 15 ef c3 be fe 36 51 bf bc 87 13 bf a6 46 5a 3f 6e c2 05 bf 15 ef c3 be 5e 83 6c 3f 06 51 08 3e b6 b8 7d bf 50 27 32 3f 27 d7 37 3f 15 ef c3 be 5e 83 6c bf 9f ba 70 3f b0 30 ae be cc 8c 0c bf 73 f7 55 3f 5e 83 6c 3f 15 ef c3 3e 11 88 3c 3f 7e 2e 2d 3f 3e 79 6f bf bd fa b4 be 5e 83 6c bf 15 ef c3 3e 40 c6 84 be 05 3e 77 3f 99 48 10 3e 2f 72 7d bf 15 ef c3 3e 5e 83 6c bf 10 ec 79 bf f1 ce 5d 3e fa 35 7f 3f c8 ae a0 bd 15 ef c3 3e 5e 83 6c 3f 82 b9 24 bf b8 f6 43 bf 5c 8c 96 3e de ae 74 3f 5e 83 6c bf 15 ef c3 be d8 30 c3 3e af aa 6c bf a9 5e 5e bf ac ac fd 3e 5e 83 6c 3f 15 ef c3 be 7d f9 7e 3f 79 1f b7 bd 82 4a 2c bf 80 58 3d bf 15 ef c3 be 5e 83 6c 3f 4b 30 0a 3f cb 7f 57 3f 97 33 13 3f 3b 72 51 bf 15 ef c3 be 5e 83 6c bf 8e 5f fe be 8d 2b 5e 3f 59 83 6c 3f 2f ef c3 3e 5e 83 6c 3f 15 ef c3 3e 79 cd 7f bf 41 cf 20 bd 68 0e 30 be 1d 30 7c 3f 5e 83 6c bf 15 ef c3 3e ed b9 da be da 76 67 bf 40 b7 7f bf c4 f1 40 3d 15 ef c3 3e 5e 83 6c bf b0 ab 1a 3f 1c fe 4b bf 41 1a 87 be 40 ed 76 bf 15 ef c3 3e 5e 83 6c 3f 80 64 7c 3f da 4c 2b 3e 7e 3e 62 3f 63 94 ef be 5e 83 6c bf 15 ef c3 be 92 73 9d 3e 2f 98 73 3f 2e 42 26 3f 02 aa 42 3f 5e 83 6c 3f 15 ef c3 be 95 97 33 bf 76 6f 36 3f 31 b5 19 bf 18 b8 4c 3f 15 ef c3 be 5e 83 6c 3f 09 cd 74 bf ab c7 95 be b3 51 69 bf 21 b2 d2 be 15 ef c3 be 5e 83 6c bf cd 22 3b be 56 b0 7b bf bc a7 4f 3e 55 ae 7a bf 5e 83 6c 3f 15 ef c3 3e c2 89 49 3f 08 db 1d bf eb f7 7f 3f 71 aa 80 bc 5e 83 6c bf 15 ef c3 3e 47 27 69 3f a4 6d d3 3e 08 0c 6f 3e 40 ed 78 3f 15 ef c3 3e 5e 83 6c bf fe 12 61 3d fc 9c 7f 3f 2b e5 65 bf 94 3f e1 3e 15 ef c3 3e 5e 83 6c 3f 22 25 5c bf 15 a9 02 3f d9 0f 20 bf 55 ca 47 bf 5e 83 6c bf 15 ef c3 be a0 a4 59 bf 6e c9 06 bf f6 0f 20 3f 3e ca 47 bf 5e 83 6c 3f 15 ef c3 be eb 0f 97 3d 7a 4d 7f bf 1a e5 65 3f d8 3f e1 3e 15 ef c3 be 5e 83 6c 3f ca 1a 6b 3f e5 99 ca be 9a 0c 6f be 38 ed 78 3f 15 ef c3 be 5e 83 6c bf df 86 46 3f 5c a0 21 3f ea f7 7f bf 27 af 80 bc 5e 83 6c 3f 15 ef c3 3e 50 14 4e be 23 c3 7a 3f 29 a7 4f be 5d ae 7a bf 5e 83 6c bf 15 ef c3 3e 47 2b 76 bf 52 86 8c 3e c2 51 69 3f dc b1 d2 be 15 ef c3 3e 5e 83 6c bf 16 1f 30 bf c5 c9 39 bf 13 b5 19 3f 2f b8 4c 3f 15 ef c3 3e 5e 83 6c 3f 4d 9b a6 3e 38 11 72 bf 4b 42 26 bf e9 a9 42 3f 5e 83 6c bf 15 ef c3 be ac 27 7d 3f 74 3d 18 be 6d 3e 62 bf a6 94 ef be 5e 83 6c 3f 15 ef c3 be 4d cc 16 3f 2f df 4e 3f 8a 1a 87 3e 36 ed 76 bf 15 ef c3 be 5e 83 6c 3f ce 69 e3 be 9a 5c 65 3f 3e b7 7f 3f 1e f4 40 3d 15 ef c3 be 5e 83 6c bf 56 f2 7f bf 77 44 a7 3c d3 0d 30 3e 24 30 7c 3f 5e 83 6c 3f 15 ef c3 3e db f3 f5 be 2d 87 60 bf 67 83 6c bf ea ee c3 3e 5e 83 6c bf 15 ef c3 3e e2 39 0e 3f 2c db 54 bf 78 33 13 bf 50 72 51 bf 15 ef c3 3e 5e 83 6c bf 70 7f 7e 3f 08 8a dd 3d }

  condition:
    $a0
}

// ===== MANUALLY EXCLUDED RULE: executable_win_rtl =====
// Reason: High False Positive (FP) risk in antivirus / threat detection.
// Analysis: Informational/classification rule from QuickSand (@tylabs, rank=10).
// Matches LZNT1 (Windows RtlCompressBuffer) compressed PE DOS stub ("This program cannot be run in DOS mode").
// Does NOT detect malicious payload or exploit; triggers on legitimate Windows binaries,
// installers (MSI/setup), Windows updates, and clean software packages.
rule executable_win_rtl {
  meta:
    is_exe    = true
    type      = "win-rtl"
    rank      = 10
    revision  = "100"
    date      = "July 29 2015"
    desc      = "Right to Left compression LZNT1"
    author    = "@tylabs"
    copyright = "QuickSand.io 2015"
    tlp       = "green"

  strings:
    $s1 = { 20 70 72 6F 67 72 61 6D 00 20 63 61 6E 6E 6F 74 20 00 62 65 20 72 75 6E 20 69 00 6E 20 44 4F 53 20 6D 6F }  // string.RTL.This program cannot be run in DOS mode

  condition:
    1 of them
}

// ===== MANUALLY EXCLUDED RULE: IsBeyondImageSize =====
// Reason: Critical False Positive (FP) risk in antivirus / threat detection.
// Analysis: PE header anomaly / sanity check rule by _pusher_ (PECheck).
// Architectural Flaw: Hardcodes 32-bit PE offset (0x50) for SizeOfImage. On 64-bit (PE32+)
// executables, ImageBase is 8 bytes so offset 0x50 reads OS version numbers (~10) instead
// of SizeOfImage, making the condition evaluate to TRUE on almost ALL modern 64-bit binaries.
// Furthermore, section alignment anomalies and SFX/installer overlays are common in clean software.
rule IsBeyondImageSize: PECheck {
  meta:
    author      = "_pusher_"
    date        = "2016-07"
    description = "Data Beyond ImageSize Check"

  condition:
    // MZ signature at offset 0 and ...
    uint16(0) == 0x5A4D and
    // ... PE signature at offset stored in MZ header at 0x3C
    uint32(uint32(0x3C)) == 0x00004550 and
    for any i in (0..pe.sections.len() - 1):
    (
      (pe.sections[i].virtual_address + pe.sections[i].virtual_size) > (uint32(uint32(0x3C) + 0x50)) or
      (pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size) > filesize
    )
}

// C:\Program Files\OpenVPN Connect\agent_ovpnconnect.exe
rule case_4485_ekix4 {
  meta:
    description = "4485 - file ekix4.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-07-13"
    hash1       = "e27b71bd1ba7e1f166c2553f7f6dba1d6e25fa2f3bb4d08d156073d49cbc360a"

  strings:
    $s1  = "f159.dll" fullword ascii
    $s2  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s3  = "ossl_store_get0_loader_int" fullword ascii
    $s4  = "loader incomplete" fullword ascii
    $s5  = "log conf missing description" fullword ascii
    $s6  = "SqlExec" fullword ascii
    $s7  = "process_include" fullword ascii
    $s8  = "EVP_PKEY_get0_siphash" fullword ascii
    $s9  = "process_pci_value" fullword ascii
    $s10 = "EVP_PKEY_get_raw_public_key" fullword ascii
    $s11 = "EVP_PKEY_get_raw_private_key" fullword ascii
    $s12 = "OSSL_STORE_INFO_get1_NAME_description" fullword ascii
    $s13 = "divisor->top > 0 && divisor->d[divisor->top - 1] != 0" fullword wide
    $s14 = "ladder post failure" fullword ascii
    $s15 = "operation fail" fullword ascii
    $s16 = "ssl command section not found" fullword ascii
    $s17 = "log key invalid" fullword ascii
    $s18 = "cms_get0_econtent_type" fullword ascii
    $s19 = "log conf missing key" fullword ascii
    $s20 = "ssl command section empty" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 11000KB and
    (pe.imphash() == "547a74a834f9965f00df1bd9ed30b8e5" or 8 of them)
}

// C:\Users\semae\AppData\Local\GitHubDesktop\app-3.6.6\resources\app\git\mingw64\bin\git.exe
rule plist_persistence {
  meta:
    description = "Identify common Property List keys in malware."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.01.12"
    reference   = "https://www.launchd.info"
    DaysofYARA  = "12/100"

  strings:
    $s1 = "RunAtLoad"
    $s2 = "KeepAlive"
    $s3 = "UserName"

  condition:
    file_plist and
    any of them
}

// C:\Windows\SysWOW64\mspaint.exe
rule _Visual_Cpp_2005_Release__Microsoft_ {
  meta:
    description = "Visual C++ 2005 Release -> Microsoft"

  strings:
    $0 = { E8 ?? ?? ?? ?? E9 ?? FD FF FF }

  condition:
    $0 at pe.entry_point
}


rule _Microsoft_Cpp_199092_ {
  meta:
    description = "Microsoft C++ (1990/92)"

  strings:
    $0 = { B4 30 CD 21 3C 02 73 05 33 C0 06 50 CB BF 00 00 8B 36 02 00 2B F7 81 FE 00 10 72 03 BE 00 10 FA 8E D7 81 C4 00 00 FB 73 00 16 1F }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_v71_DLL_ {
  meta:
    description = "Microsoft Visual C++ v7.1 DLL"

  strings:
    $0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 E4 53 56 57 89 65 E8 C7 45 E4 01 00 00 00 C7 45 FC }
    $1 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D ?? ?? 40 00 00 EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 }
    $2 = { 83 7C 24 08 01 75 ?? ?? ?? 24 04 50 A3 ?? ?? ?? 50 FF 15 00 10 ?? 50 33 C0 40 C2 0C 00 }
    $3 = { 55 8B EC ?? ?? 0C 83 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 8B }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point or $3 at pe.entry_point
}

rule _Microsoft_Windows_Update_CAB_SFX_module_ {
  meta:
    description = "Microsoft Windows Update CAB SFX module"

  strings:
    $0 = { E9 C5 FA FF FF 55 8B EC 56 8B 75 08 68 04 08 00 00 FF D6 59 33 C9 3B C1 75 0F 51 6A 05 FF 75 28 E8 2E 11 00 00 33 C0 EB 69 8B 55 0C 83 88 88 00 00 00 FF 83 88 84 00 00 00 FF 89 50 04 8B 55 10 89 50 0C 8B 55 14 89 50 10 8B 55 18 89 50 14 8B 55 1C 89 50 18 }
    $1 = { E9 C5 FA FF FF 55 8B EC 56 8B 75 08 68 04 08 00 00 FF D6 59 33 C9 3B C1 75 0F 51 6A 05 FF 75 28 E8 2E 11 00 00 33 C0 EB 69 8B 55 0C 83 88 88 00 00 00 FF 83 88 84 00 00 00 FF 89 50 04 8B 55 10 89 50 0C 8B 55 14 89 50 10 8B 55 18 89 50 14 8B 55 1C 89 50 18 8B 55 20 89 50 1C 8B 55 24 89 50 20 8B 55 28 89 48 48 89 48 44 89 48 4C B9 FF FF 00 00 89 70 08 89 10 66 C7 80 B2 00 00 00 0F 00 89 88 A0 00 00 00 89 88 A8 00 00 00 89 88 A4 00 00 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Microsoft_Visual_Cpp__ {
  meta:
    description = "Microsoft Visual C++ ?.?"

  strings:
    $0 = { 83 ?? ?? 6A 00 FF 15 F8 10 0B B0 8D ?? ?? ?? 51 6A 08 6A 00 6A 00 68 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_60_DLL_Debug_ {
  meta:
    description = "Microsoft Visual C++ 6.0 DLL (Debug)"

  strings:
    $0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 ?? ?? 83 }

  condition:
    $0
}

rule _Microsoft_Visual_Cpp_70_MFC_ {
  meta:
    description = "Microsoft Visual C++ 7.0 MFC"

  strings:
    $0 = { 6A 60 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 94 00 00 00 8B C7 E8 ?? ?? ?? ?? 89 }

  condition:
    $0 at pe.entry_point
}


rule _Borland_Delphi_v60_ {
  meta:
    description = "Borland Delphi v6.0"

  strings:
    $0 = { 55 8B EC 83 C4 F0 B8 45 ?? E8 FF A1 45 ?? 8B ?? E8 FF FF 8B }
    $1 = { 55 8B EC 83 C4 F0 B8 40 ?? E8 FF FF A1 72 40 ?? 33 D2 E8 FF FF A1 72 40 ?? 8B ?? 83 C0 14 E8 FF FF E8 FF }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Cygwin32_ {
  meta:
    description = "Cygwin32"

  strings:
    $0 = { 6A FF 15 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_for_Win32_1995_ {
  meta:
    description = "Borland C++ for Win32 1995"

  strings:
    $0 = { A1 C1 A3 83 75 80 }
    $1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_v42_ {
  meta:
    description = "Microsoft Visual C++ v4.2"

  strings:
    $0 = { 64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 83 53 56 57 89 }
    $1 = { 53 B8 8B 56 57 85 DB 55 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _MinGW_v32x__mainCRTStartup_ {
  meta:
    description = "MinGW v3.2.x (_mainCRTStartup)"

  strings:
    $0 = { E8 FF FF E8 FF }

  condition:
    $0 at pe.entry_point
}

rule _FASM_v13x_ {
  meta:
    description = "FASM v1.3x"

  strings:
    $0 = { E8 ?? 6E ?? ?? 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 }

  condition:
    $0 at pe.entry_point
}

rule _LCC_Win32_DLL_ {
  meta:
    description = "LCC Win32 DLL"

  strings:
    $0 = { 8B 44 24 08 56 83 E8 74 48 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_v60_KOL_ {
  meta:
    description = "Borland Delphi v6.0 KOL"

  strings:
    $0 = { 55 8B EC 83 C4 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 }

  condition:
    $0 at pe.entry_point
}

rule _LCC_Win32_v1x_ {
  meta:
    description = "LCC Win32 v1.x"

  strings:
    $0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 FF 75 10 FF 75 0C FF 75 08 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_v60_SPx_ {
  meta:
    description = "Microsoft Visual C++ v6.0 SPx"

  strings:
    $0 = { 55 8B EC 83 EC 44 56 FF 15 6A 01 8B F0 FF }
    $1 = { 55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Borland_Delphi_vxx_Component_ {
  meta:
    description = "Borland Delphi vx.x (Component)"

  strings:
    $0 = { 55 8B EC 83 C4 B4 B8 E8 E8 8D }

  condition:
    $0 at pe.entry_point
}

rule _MinGW_GCC_DLL_v2xx_ {
  meta:
    description = "MinGW GCC DLL v2xx"

  strings:
    $0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 ?? ?? 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D ?? 30 ?? 10 85 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_Component_ {
  meta:
    description = "Borland Delphi (Component)"

  strings:
    $0 = { 55 89 E5 83 EC 04 83 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_v20_ {
  meta:
    description = "Borland Delphi v2.0"

  strings:
    $0 = { 50 6A E8 FF FF BA 52 89 05 89 42 04 E8 5A 58 E8 C3 55 8B EC 33 }

  condition:
    $0 at pe.entry_point
}

rule _MinGW_v32x_WinMain_ {
  meta:
    description = "MinGW v3.2.x (WinMain)"

  strings:
    $0 = { 55 89 E5 83 EC 08 6A ?? 6A ?? 6A ?? 6A ?? E8 0D ?? ?? ?? B8 ?? ?? ?? ?? C9 C3 90 90 90 90 90 90 FF 25 38 20 ?? 10 90 90 ?? ?? ?? ?? ?? ?? ?? ?? FF FF FF FF ?? ?? ?? ?? FF FF FF }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Basic_v60_DLL_ {
  meta:
    description = "Microsoft Visual Basic v6.0 DLL"

  strings:
    $0 = { 55 89 E5 E8 C9 C3 45 58 }

  condition:
    $0 at pe.entry_point
}


rule _Borland_Delphi_v60_ {
  meta:
    description = "Borland Delphi v6.0"

  strings:
    $0 = { 55 8B EC 83 C4 F0 B8 45 ?? E8 FF A1 45 ?? 8B ?? E8 FF FF 8B }
    $1 = { 55 8B EC 83 C4 F0 B8 40 ?? E8 FF FF A1 72 40 ?? 33 D2 E8 FF FF A1 72 40 ?? 8B ?? 83 C0 14 E8 FF FF E8 FF }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Cygwin32_ {
  meta:
    description = "Cygwin32"

  strings:
    $0 = { 6A FF 15 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_for_Win32_1995_ {
  meta:
    description = "Borland C++ for Win32 1995"

  strings:
    $0 = { A1 C1 A3 83 75 80 }
    $1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_v42_ {
  meta:
    description = "Microsoft Visual C++ v4.2"

  strings:
    $0 = { 64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 83 53 56 57 89 }
    $1 = { 53 B8 8B 56 57 85 DB 55 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _MinGW_v32x__mainCRTStartup_ {
  meta:
    description = "MinGW v3.2.x (_mainCRTStartup)"

  strings:
    $0 = { E8 FF FF E8 FF }

  condition:
    $0 at pe.entry_point
}

rule _FASM_v13x_ {
  meta:
    description = "FASM v1.3x"

  strings:
    $0 = { E8 ?? 6E ?? ?? 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 }

  condition:
    $0 at pe.entry_point
}

rule _LCC_Win32_DLL_ {
  meta:
    description = "LCC Win32 DLL"

  strings:
    $0 = { 8B 44 24 08 56 83 E8 74 48 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_v60_KOL_ {
  meta:
    description = "Borland Delphi v6.0 KOL"

  strings:
    $0 = { 55 8B EC 83 C4 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 }

  condition:
    $0 at pe.entry_point
}

rule _LCC_Win32_v1x_ {
  meta:
    description = "LCC Win32 v1.x"

  strings:
    $0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 FF 75 10 FF 75 0C FF 75 08 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_v60_SPx_ {
  meta:
    description = "Microsoft Visual C++ v6.0 SPx"

  strings:
    $0 = { 55 8B EC 83 EC 44 56 FF 15 6A 01 8B F0 FF }
    $1 = { 55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _Borland_Delphi_vxx_Component_ {
  meta:
    description = "Borland Delphi vx.x (Component)"

  strings:
    $0 = { 55 8B EC 83 C4 B4 B8 E8 E8 8D }

  condition:
    $0 at pe.entry_point
}

rule _MinGW_GCC_DLL_v2xx_ {
  meta:
    description = "MinGW GCC DLL v2xx"

  strings:
    $0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 ?? ?? 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D ?? 30 ?? 10 85 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_Component_ {
  meta:
    description = "Borland Delphi (Component)"

  strings:
    $0 = { 55 89 E5 83 EC 04 83 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_v20_ {
  meta:
    description = "Borland Delphi v2.0"

  strings:
    $0 = { 50 6A E8 FF FF BA 52 89 05 89 42 04 E8 5A 58 E8 C3 55 8B EC 33 }

  condition:
    $0 at pe.entry_point
}

rule _MinGW_v32x_WinMain_ {
  meta:
    description = "MinGW v3.2.x (WinMain)"

  strings:
    $0 = { 55 89 E5 83 EC 08 6A ?? 6A ?? 6A ?? 6A ?? E8 0D ?? ?? ?? B8 ?? ?? ?? ?? C9 C3 90 90 90 90 90 90 FF 25 38 20 ?? 10 90 90 ?? ?? ?? ?? ?? ?? ?? ?? FF FF FF FF ?? ?? ?? ?? FF FF FF }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Basic_v60_DLL_ {
  meta:
    description = "Microsoft Visual Basic v6.0 DLL"

  strings:
    $0 = { 55 89 E5 E8 C9 C3 45 58 }

  condition:
    $0 at pe.entry_point
}


rule AutoIt_Script {
  meta:
    description = "AutoIt Script - used by attackers"

  strings:
    $keyword1 = "#include <FTPEX.au3>"
    $keyword2 = "#include <updateftp.au3>"
    $keyword3 = "#include <WinAPI.au3>"
    $keyword4 = "Global $FTPServer" fullword
    $keyword5 = "Global $FTPUser" fullword
    $keyword6 = "= _FTP_Connect"

  condition:
    1 of ($keyword*)
}

rule _WATCOM_CCpp_32_RunTime_System_19881994_ {
  meta:
    description = "WATCOM C/C++ 32 Run-Time System 1988-1994"

  strings:
    $0 = { E9 57 }

  condition:
    $0 at pe.entry_point
}

rule _WATCOM_CCpp_ {
  meta:
    description = "WATCOM C/C++"

  strings:
    $0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F }

  condition:
    $0 at pe.entry_point
}

rule _MinGW_v32x_Dll_WinMain_ {
  meta:
    description = "MinGW v3.2.x (Dll_WinMain)"

  strings:
    $0 = { 55 89 E5 83 EC 08 C7 04 24 01 ?? ?? ?? FF 15 E4 40 40 ?? E8 68 ?? ?? ?? 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 ?? ?? ?? FF 15 E4 40 40 ?? E8 48 ?? ?? ?? 89 EC 31 C0 5D C3 89 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_v50_KOL_ {
  meta:
    description = "Borland Delphi v5.0 KOL"

  strings:
    $0 = { 53 8B D8 33 C0 A3 6A ?? E8 FF A3 A1 A3 33 C0 A3 33 C0 A3 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_DLL_ {
  meta:
    description = "Microsoft Visual C++ DLL"

  strings:
    $0 = { 53 56 57 BB 01 8B 24 }
    $1 = { 53 B8 01 ?? ?? ?? 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D 75 09 33 }
    $2 = { 55 8B EC 56 57 BF 01 ?? ?? ?? 8B 75 }
    $3 = { 55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point or $3 at pe.entry_point
}

rule _Microsoft_Visual_C_v20_ {
  meta:
    description = "Microsoft Visual C v2.0"

  strings:
    $0 = { 55 8B EC 56 57 BF 8B 3B F7 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_v42_DLL_ {
  meta:
    description = "Microsoft Visual C++ v4.2 DLL"

  strings:
    $0 = { 55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56 }

  condition:
    $0 at pe.entry_point
}

rule _MinGW_v32x_Dll_main_ {
  meta:
    description = "MinGW v3.2.x (Dll_main)"

  strings:
    $0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 76 01 ?? ?? 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D ?? 30 ?? 10 85 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_v70_ {
  meta:
    description = "Microsoft Visual C++ v7.0"

  strings:
    $0 = "jh"
    $1 = { 55 8D 6C 81 EC 8B 45 83 F8 01 56 0F 84 85 C0 0F }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _WATCOM_CCpp_32_RunTime_System_19881995_ {
  meta:
    description = "WATCOM C/C++ 32 Run-Time System 1988-1995"

  strings:
    $0 = { FB 83 89 E3 89 89 66 66 BB 29 C0 B4 30 CD }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_v50_KOLMCK_ {
  meta:
    description = "Borland Delphi v5.0 KOL/MCK"

  strings:
    $0 = { 55 8B EC 83 C4 F0 B8 40 ?? E8 FF FF E8 FF FF E8 FF FF 8B }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_vxx_ {
  meta:
    description = "Microsoft Visual C++ vx.x"

  strings:
    $0 = { 53 55 56 8B 85 F6 57 B8 75 8B 85 C9 75 33 C0 5F 5E 5D 5B }
    $1 = { 64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56 }
    $2 = { 55 8B EC 83 EC 44 56 FF 15 8B F0 8A 3C }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}

rule _Borland_Cpp_for_Win32_1994_ {
  meta:
    description = "Borland C++ for Win32 1994"

  strings:
    $0 = { A1 C1 A3 57 51 33 C0 BF B9 3B CF }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_v60_Debug_Version_ {
  meta:
    description = "Microsoft Visual C++ v6.0 (Debug Version)"

  strings:
    $0 = { 6A 68 E8 BF 8B C7 E8 89 65 8B F4 89 3E 56 FF 15 8B 4E 89 0D 8B 46 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_v4x_ {
  meta:
    description = "Microsoft Visual C++ v4.x"

  strings:
    $0 = { 64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 83 53 56 57 89 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_v50_ {
  meta:
    description = "Microsoft Visual C++ v5.0"

  strings:
    $0 = { 24 ?? 8B 24 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Cpp_v50_DLL_ {
  meta:
    description = "Microsoft Visual C++ v5.0 DLL"

  strings:
    $0 = { 55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? }

  condition:
    $0 at pe.entry_point
}

rule _MinGW_v32x_Dll_mainCRTStartup_ {
  meta:
    description = "MinGW v3.2.x (Dll_mainCRTStartup)"

  strings:
    $0 = { 55 89 E5 83 EC 08 6A ?? 6A ?? 6A ?? 6A ?? E8 0D ?? ?? ?? B8 ?? ?? ?? ?? C9 C3 90 90 90 90 90 90 FF 25 38 20 40 ?? 90 90 ?? ?? ?? ?? ?? ?? ?? ?? FF FF FF FF ?? ?? ?? ?? FF FF FF }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_ {
  meta:
    description = "Borland C++"

  strings:
    $0 = { A1 C1 E0 02 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_for_Win32_1999_ {
  meta:
    description = "Borland C++ for Win32 1999"

  strings:
    $0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B }
    $1 = { A1 C1 E0 02 A3 57 51 33 C0 BF B9 3B CF 76 05 2B CF FC F3 AA 59 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule _MinGW_v32x_main_ {
  meta:
    description = "MinGW v3.2.x (main)"

  strings:
    $0 = { 55 89 E5 83 EC 08 C7 04 24 01 ?? ?? ?? FF 15 FC 40 40 ?? E8 68 ?? ?? ?? 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 ?? ?? ?? FF 15 FC 40 40 ?? E8 48 ?? ?? ?? 89 EC 31 C0 5D C3 89 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Delphi_ {
  meta:
    description = "Borland Delphi"

  strings:
    $0 = { C3 E9 FF 8D }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Visual_Basic_v50__v60_ {
  meta:
    description = "Microsoft Visual Basic v5.0 / v6.0"

  strings:
    $0 = { 5A 68 68 52 E9 }

  condition:
    $0 at pe.entry_point
}

rule _Borland_Cpp_DLL_ {
  meta:
    description = "Borland C++ DLL"

  strings:
    $0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 }
    $1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3 }
    $2 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3 }
    $3 = { C3 E9 FF 8D }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point or $3 at pe.entry_point
}


rule _PE_Spin_v0b_ {
  meta:
    description = "PE Spin v0.b"

  strings:
    $0 = { 66 9C 60 E8 CA 03 04 05 06 07 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_CAB_SFX_module_ {
  meta:
    description = "Microsoft CAB SFX module"

  strings:
    $0 = { 55 8B EC 83 EC 44 56 FF 15 94 13 42 ?? 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E }

  condition:
    $0 at pe.entry_point
}


rule _Microsoft_Cpp_19901992_ {
  meta:
    description = "Microsoft C++ (1990/1992)"

  strings:
    $0 = { B8 00 30 CD 21 3C 03 73 ?? 0E 1F BA ?? ?? B4 09 CD 21 06 33 C0 50 CB }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_Cpp_NE_Loader_ {
  meta:
    description = "Microsoft C++ NE Loader"

  strings:
    $0 = { 30 CD 21 86 E0 2E A3 00 00 3D 00 02 73 00 B8 00 00 8E D8 }

  condition:
    $0 at pe.entry_point
}


rule _Microsoft_C_for_Windows_1_ {
  meta:
    description = "Microsoft C for Windows (1)"

  strings:
    $0 = { 33 ED 55 9A ?? ?? ?? ?? 0B C0 74 }

  condition:
    $0 at pe.entry_point
}


rule _Microsoft_C_19901992_ {
  meta:
    description = "Microsoft C (1990/1992)"

  strings:
    $0 = { B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7 }

  condition:
    $0 at pe.entry_point
}


rule _Microsoft_C_ {
  meta:
    description = "Microsoft C"

  strings:
    $0 = { B4 30 CD 21 3C 02 73 ?? B8 }

  condition:
    $0 at pe.entry_point
}

rule Microsoft_CAB_SFX_module_ren {
  strings:
    $a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? 10 00 01 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D ?? EB 0A 3C 20 }

  condition:
    $a0 at pe.entry_point
}


rule _Microsoft_C_v104_ {
  meta:
    description = "Microsoft C v1.04"

  strings:
    $0 = { FA B8 ?? ?? 8E D8 8E D0 26 8B ?? ?? ?? 2B D8 F7 ?? ?? ?? 75 ?? B1 04 D3 E3 EB }

  condition:
    $0 at pe.entry_point
}


rule _Microsoft_C_for_Windows_2_ {
  meta:
    description = "Microsoft C for Windows (2)"

  strings:
    $0 = { 8C D8 ?? 45 55 8B EC 1E 8E D8 57 56 89 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_C_Library_1985_ {
  meta:
    description = "Microsoft C Library 1985"

  strings:
    $0 = { BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7 81 C4 ?? ?? FB 73 }

  condition:
    $0 at pe.entry_point
}


rule _Microsoft_C_19881989_ {
  meta:
    description = "Microsoft C (1988/1989)"

  strings:
    $0 = { B4 30 CD 21 3C 02 73 ?? CD 20 BF ?? ?? 8B ?? ?? ?? 2B F7 81 ?? ?? ?? 72 }

  condition:
    $0 at pe.entry_point
}

rule _Nullsoft_Install_System_1xx_ {
  meta:
    description = "Nullsoft Install System 1.xx"

  strings:
    $0 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 }
    $1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 }

  condition:
    $0 at pe.entry_point or $1
}


rule _Microsoft_C_198889_ {
  meta:
    description = "Microsoft C (1988/89)"

  strings:
    $0 = { B4 30 CD 21 3C 02 73 02 CD 20 BF 00 00 8B 36 02 00 2B F7 81 FE 00 10 72 03 BE 00 10 FA 8E D7 81 C4 00 00 FB 73 }

  condition:
    $0 at pe.entry_point
}

rule _Microsoft_CAB_SFX_ {
  meta:
    description = "Microsoft CAB SFX"

  strings:
    $0 = { E8 0A 00 00 00 E9 7A FF FF FF CC CC CC CC CC }
    $1 = { 55 8B EC 83 EC 44 56 FF 15 ?? 10 00 01 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D ?? EB 0A 3C 20 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}

rule TASM___MASM {
  strings:
    $a0 = { 6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 }

  condition:
    $a0 at pe.entry_point
}

// wiresock.sys 77653fa1cfae5ecc2b537040bc2b263848a2e0ede8e011552d93ab9a4979e036

rule SUSP_PE_Unusual_Imported_Library_Names {
  meta:
    description = "look for PE's whose imported libraries don't end in DLL, and aren't common EXE names"
    author      = "Greg Lesnewich"
    date        = "2024-01-14"
    version     = "1.0"
    DaysOfYARA  = "14/100"

  condition:
    for any imp in pe.import_details:
    (
      not imp.library_name iendswith ".dll" and
      not imp.library_name iequals "WINSPOOL.DRV" and
      not imp.library_name iequals "ntoskrnl.exe"
    )
}

// Time	Client	Event	File	Size	Threat / detail	Time
// 20:34:37	93.182.105.9 #5	malicious	ieframe.dll.mui	1.0 MB	RogueBraviaxSampleA — RogueBraviaxSampleA (YARA)	5078 ms
// 20:34:03	93.182.105.9 #5	malicious	KernelBase.dll.mui	1.3 MB	APT_DustSquad_PE_Nov19_2 — APT_DustSquad_PE_Nov19_2 (YARA)	2249 ms

rule APT_DustSquad_PE_Nov19_2 {
  meta:
    description = "Detection Rule for APT DustSquad campaign Nov19"
    author      = "Arkbird_SOLG"
    reference   = "https://twitter.com/Rmy_Reserve/status/1197448735422238721"
    date        = "2019-11-29"
    hash1       = "f5941f3d8dc8d60581d4915d06d56acba74f3ffad543680a85037a8d3bf3f8bc"

  strings:
    $x1  = "The credentials supplied were not complete, and could not be verified. Additional information can be returned from the context.4" wide
    $x2  = "The domain controller certificate used for smartcard logon has been revoked. Please contact your system administrator with the c" wide
    $s3  = "VTDictionary<System.Word,System.DateUtils.TLocalTimeZone.TYearlyChanges>.TKeyEnumeratorxsN" fullword ascii
    $s4  = ";The certificate chain was issued by an untrusted authority.7The message received was unexpected or badly formatted.;An unknown " wide
    $s5  = "The logon attempt failed;The credentials supplied to the package were not recognized4No credentials are available in the securit" wide
    $s6  = "8The message supplied for verification is out of sequence3No authority could be contacted for authentication.UThe function compl" wide
    $s7  = "The security context could not be established due to a failure in the requested quality of service (e.g. mutual authentication o" wide
    $s8  = "Error reading %s%s%s: %s\"Character index out of bounds (%d)" fullword wide
    $s9  = "OnExecutel" fullword ascii
    $s10 = "?WThe given \"%s\" local time is invalid (situated within the missing period prior to DST).8String index out of range (%d).  Mus" wide
    $s11 = "Address type not supported.\"%s: Circular links are not allowed\"Not enough data in buffer. (%d/%d)" fullword wide
    $s12 = "@TList<System.DateUtils.TLocalTimeZone.TYearlyChanges>.TEmptyFunc !@" fullword ascii
    $s13 = "dTList<System.DateUtils.TPair<System.Word,System.DateUtils.TLocalTimeZone.TYearlyChanges>>.TEmptyFunc !@" fullword ascii
    $s14 = "EVP_PKEY_CTX_get_operation" fullword wide
    $s15 = "http://www.borland.com/namespaces/Types" fullword wide
    $s16 = "OnGetPassword" fullword ascii
    $s17 = "OnGetPasswordExp" fullword ascii
    $s18 = "a1.exe" fullword ascii
    $s19 = "EIdSocksServerCommandError " fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 6000KB and
    (pe.imphash() == "7b3af4ed73c83b1a16f6f299b3eb654e" or (1 of ($x*) or 4 of them))
}


rule RogueBraviaxSampleA {
  meta:
    Description = "Rogue.Braviax.sm"
    ThreatLevel = "5"

  strings:
    $      = "background_gradient_red.jpg" ascii wide
    $      = "red_shield_48.png" ascii wide
    $      = "pagerror.gif" ascii wide
    $      = "green_shield.png" ascii wide
    $      = "refresh.gif" ascii wide
    $      = "red_shield.png" ascii wide
    $      = "avp:scan" ascii wide
    $      = "avp:site" ascii wide
    $str1  = "Trojan-BNK.Win32.Keylogger.gen" ascii wide
    $str2  = "Trojan-PSW.Win32.Coced.219" ascii wide
    $str3  = "Email-Worm.Win32.Eyeveg.f" ascii wide
    $str4  = "Virus.BAT.Batalia1.840" ascii wide
    $str5  = "Trojan-SMS.SymbOS.Viver.a" ascii wide
    $str6  = "Trojan-Spy.HTML.Bankfraud.jk" ascii wide
    $str7  = "glohhstt7.com" ascii wide
    //$str8 = "Zorton" ascii wide
    //$str9 = "Rango" ascii wide
    //$str10 = "Sirius" ascii wide
    //$str11 = "A-Secure" ascii wide
    $str12 = "%1 Protection 201" ascii wide
    $str13 = "%1 Antivirus 201" ascii wide
    $str14 = "siriuc2014.com" ascii wide
    $str15 = "siriucs2016.com" ascii wide
    $str16 = "zorton2016.com" ascii wide
    $str17 = "zorton2015.com" ascii wide
    $str18 = "stormo10.com" ascii wide
    $str19 = "fscurat20.com" ascii wide
    $str20 = "fscurat21.com" ascii wide

  condition:
    (3 of them) or (any of ($str*))
}
