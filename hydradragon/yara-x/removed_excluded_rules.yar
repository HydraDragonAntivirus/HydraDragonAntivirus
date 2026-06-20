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


