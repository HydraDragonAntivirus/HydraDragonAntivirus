import "pe"
import "hash"
import "elf"
import "console"
import "dotnet"
import "macho"
import "math"
import "time"

rule avdetect_procs: avdetect {
  meta:
    author      = "AlienVault Labs"
    type        = "info"
    severity    = 1
    description = "Antivirus detection tricks"

  strings:
    $proc2   = "LMon.exe" ascii wide
    $proc3   = "sagui.exe" ascii wide
    $proc4   = "RDTask.exe" ascii wide
    $proc5   = "kpf4gui.exe" ascii wide
    $proc6   = "ALsvc.exe" ascii wide
    $proc7   = "pxagent.exe" ascii wide
    $proc8   = "fsma32.exe" ascii wide
    $proc9   = "licwiz.exe" ascii wide
    $proc10  = "SavService.exe" ascii wide
    $proc11  = "prevxcsi.exe" ascii wide
    $proc12  = "alertwall.exe" ascii wide
    $proc13  = "livehelp.exe" ascii wide
    $proc14  = "SAVAdminService.exe" ascii wide
    $proc15  = "csi-eui.exe" ascii wide
    $proc16  = "mpf.exe" ascii wide
    $proc17  = "lookout.exe" ascii wide
    $proc18  = "savprogress.exe" ascii wide
    $proc19  = "lpfw.exe" ascii wide
    $proc20  = "mpfcm.exe" ascii wide
    $proc21  = "emlproui.exe" ascii wide
    $proc22  = "savmain.exe" ascii wide
    $proc23  = "outpost.exe" ascii wide
    $proc24  = "fameh32.exe" ascii wide
    $proc25  = "emlproxy.exe" ascii wide
    $proc26  = "savcleanup.exe" ascii wide
    $proc27  = "filemon.exe" ascii wide
    $proc28  = "AntiHook.exe" ascii wide
    $proc29  = "endtaskpro.exe" ascii wide
    $proc30  = "savcli.exe" ascii wide
    $proc31  = "procmon.exe" ascii wide
    $proc32  = "xfilter.exe" ascii wide
    $proc33  = "netguardlite.exe" ascii wide
    $proc34  = "backgroundscanclient.exe" ascii wide
    $proc35  = "Sniffer.exe" ascii wide
    $proc36  = "scfservice.exe" ascii wide
    $proc37  = "oasclnt.exe" ascii wide
    $proc38  = "sdcservice.exe" ascii wide
    $proc39  = "acs.exe" ascii wide
    $proc40  = "scfmanager.exe" ascii wide
    $proc41  = "omnitray.exe" ascii wide
    $proc42  = "sdcdevconx.exe" ascii wide
    $proc43  = "aupdrun.exe" ascii wide
    $proc44  = "spywaretermin" ascii wide
    $proc45  = "atorshield.exe" ascii wide
    $proc46  = "onlinent.exe" ascii wide
    $proc47  = "sdcdevconIA.exe" ascii wide
    $proc48  = "sppfw.exe" ascii wide
    $proc49  = "spywat~1.exe" ascii wide
    $proc50  = "opf.exe" ascii wide
    $proc51  = "sdcdevcon.exe" ascii wide
    $proc52  = "spfirewallsvc.exe" ascii wide
    $proc53  = "ssupdate.exe" ascii wide
    $proc54  = "pctavsvc.exe" ascii wide
    $proc55  = "configuresav.exe" ascii wide
    $proc56  = "fwsrv.exe" ascii wide
    $proc57  = "terminet.exe" ascii wide
    $proc58  = "pctav.exe" ascii wide
    $proc59  = "alupdate.exe" ascii wide
    $proc60  = "opfsvc.exe" ascii wide
    $proc61  = "tscutynt.exe" ascii wide
    $proc62  = "pcviper.exe" ascii wide
    $proc63  = "InstLsp.exe" ascii wide
    $proc64  = "uwcdsvr.exe" ascii wide
    $proc65  = "umxtray.exe" ascii wide
    $proc66  = "persfw.exe" ascii wide
    $proc67  = "CMain.exe" ascii wide
    $proc68  = "dfw.exe" ascii wide
    $proc69  = "updclient.exe" ascii wide
    $proc70  = "pgaccount.exe" ascii wide
    $proc71  = "CavAUD.exe" ascii wide
    $proc72  = "ipatrol.exe" ascii wide
    $proc73  = "webwall.exe" ascii wide
    $proc74  = "privatefirewall3.exe" ascii wide
    $proc75  = "CavEmSrv.exe" ascii wide
    $proc76  = "pcipprev.exe" ascii wide
    $proc77  = "winroute.exe" ascii wide
    $proc78  = "protect.exe" ascii wide
    $proc79  = "Cavmr.exe" ascii wide
    $proc80  = "prifw.exe" ascii wide
    $proc81  = "apvxdwin.exe" ascii wide
    $proc82  = "rtt_crc_service.exe" ascii wide
    $proc83  = "Cavvl.exe" ascii wide
    $proc84  = "tzpfw.exe" ascii wide
    $proc85  = "as3pf.exe" ascii wide
    $proc86  = "schedulerdaemon.exe" ascii wide
    $proc87  = "CavApp.exe" ascii wide
    $proc88  = "privatefirewall3.exe" ascii wide
    $proc89  = "avas.exe" ascii wide
    $proc90  = "sdtrayapp.exe" ascii wide
    $proc91  = "CavCons.exe" ascii wide
    $proc92  = "pfft.exe" ascii wide
    $proc93  = "avcom.exe" ascii wide
    $proc94  = "siteadv.exe" ascii wide
    $proc95  = "CavMud.exe" ascii wide
    $proc96  = "armorwall.exe" ascii wide
    $proc97  = "avkproxy.exe" ascii wide
    $proc98  = "sndsrvc.exe" ascii wide
    $proc99  = "CavUMAS.exe" ascii wide
    $proc100 = "app_firewall.exe" ascii wide
    $proc101 = "avkservice.exe" ascii wide
    $proc102 = "snsmcon.exe" ascii wide
    $proc103 = "UUpd.exe" ascii wide
    $proc104 = "blackd.exe" ascii wide
    $proc105 = "avktray.exe" ascii wide
    $proc106 = "snsupd.exe" ascii wide
    $proc107 = "cavasm.exe" ascii wide
    $proc108 = "blackice.exe" ascii wide
    $proc109 = "avkwctrl.exe" ascii wide
    $proc110 = "procguard.exe" ascii wide
    $proc111 = "CavSub.exe" ascii wide
    $proc112 = "umxagent.exe" ascii wide
    $proc113 = "avmgma.exe" ascii wide
    $proc114 = "DCSUserProt.exe" ascii wide
    $proc115 = "CavUserUpd.exe" ascii wide
    $proc116 = "kpf4ss.exe" ascii wide
    $proc117 = "avtask.exe" ascii wide
    $proc118 = "avkwctl.exe" ascii wide
    $proc119 = "CavQ.exe" ascii wide
    $proc120 = "tppfdmn.exe" ascii wide
    $proc121 = "aws.exe" ascii wide
    $proc122 = "firewall.exe" ascii wide
    $proc123 = "Cavoar.exe" ascii wide
    $proc124 = "blinksvc.exe" ascii wide
    $proc125 = "bgctl.exe" ascii wide
    $proc126 = "THGuard.exe" ascii wide
    $proc127 = "CEmRep.exe" ascii wide
    $proc128 = "sp_rsser.exe" ascii wide
    $proc129 = "bgnt.exe" ascii wide
    $proc130 = "spybotsd.exe" ascii wide
    $proc131 = "OnAccessInstaller.exe" ascii wide
    $proc132 = "op_mon.exe" ascii wide
    $proc133 = "bootsafe.exe" ascii wide
    $proc134 = "xauth_service.exe" ascii wide
    $proc135 = "SoftAct.exe" ascii wide
    $proc136 = "cmdagent.exe" ascii wide
    $proc137 = "bullguard.exe" ascii wide
    $proc138 = "xfilter.exe" ascii wide
    $proc139 = "CavSn.exe" ascii wide
    $proc140 = "VCATCH.EXE" ascii wide
    $proc141 = "cdas2.exe" ascii wide
    $proc142 = "zlh.exe" ascii wide
    $proc143 = "Packetizer.exe" ascii wide
    $proc144 = "SpyHunter3.exe" ascii wide
    $proc145 = "cmgrdian.exe" ascii wide
    $proc146 = "adoronsfirewall.exe" ascii wide
    $proc147 = "Packetyzer.exe" ascii wide
    $proc148 = "wwasher.exe" ascii wide
    $proc149 = "configmgr.exe" ascii wide
    $proc150 = "scfservice.exe" ascii wide
    $proc151 = "zanda.exe" ascii wide
    $proc152 = "authfw.exe" ascii wide
    $proc153 = "cpd.exe" ascii wide
    $proc154 = "scfmanager.exe" ascii wide
    $proc155 = "zerospywarele.exe" ascii wide
    $proc156 = "dvpapi.exe" ascii wide
    $proc157 = "espwatch.exe" ascii wide
    $proc158 = "dltray.exe" ascii wide
    $proc159 = "zerospywarelite_installer.exe" ascii wide
    $proc160 = "clamd.exe" ascii wide
    $proc161 = "fgui.exe" ascii wide
    $proc162 = "dlservice.exe" ascii wide
    $proc163 = "Wireshark.exe" ascii wide
    $proc164 = "sab_wab.exe" ascii wide
    $proc165 = "filedeleter.exe" ascii wide
    $proc166 = "ashwebsv.exe" ascii wide
    $proc167 = "tshark.exe" ascii wide
    $proc168 = "SUPERAntiSpyware.exe" ascii wide
    $proc169 = "firewall.exe" ascii wide
    $proc170 = "ashdisp.exe" ascii wide
    $proc171 = "rawshark.exe" ascii wide
    $proc172 = "vdtask.exe" ascii wide
    $proc173 = "firewall2004.exe" ascii wide
    $proc174 = "ashmaisv.exe" ascii wide
    $proc175 = "Ethereal.exe" ascii wide
    $proc176 = "asr.exe" ascii wide
    $proc177 = "firewallgui.exe" ascii wide
    $proc178 = "ashserv.exe" ascii wide
    $proc179 = "Tethereal.exe" ascii wide
    $proc180 = "NetguardLite.exe" ascii wide
    $proc181 = "gateway.exe" ascii wide
    $proc182 = "aswupdsv.exe" ascii wide
    $proc183 = "Windump.exe" ascii wide
    $proc184 = "nstzerospywarelite.exe" ascii wide
    $proc185 = "hpf_.exe" ascii wide
    $proc186 = "avastui.exe" ascii wide
    $proc187 = "Tcpdump.exe" ascii wide
    $proc188 = "cdinstx.exe" ascii wide
    $proc189 = "iface.exe" ascii wide
    $proc190 = "avastsvc.exe" ascii wide
    $proc191 = "Netcap.exe" ascii wide
    $proc192 = "cdas17.exe" ascii wide
    $proc193 = "invent.exe" ascii wide
    $proc194 = "Netmon.exe" ascii wide
    $proc195 = "fsrt.exe" ascii wide
    $proc196 = "ipcserver.exe" ascii wide
    $proc197 = "CV.exe" ascii wide
    $proc198 = "VSDesktop.exe" ascii wide
    $proc199 = "ipctray.exe" ascii wide

  condition:
    3 of them
}

rule dbgdetect_files: dbgdetect {
  meta:
    author      = "AlienVault Labs"
    type        = "info"
    severity    = 1
    description = "Debugger detection tricks"

  strings:
    $file1 = "syserdbgmsg" nocase ascii wide
    $file2 = "syserboot" nocase ascii wide
    $file3 = "SICE" nocase ascii wide
    $file4 = "NTICE" nocase ascii wide

  condition:
    2 of them
}

rule dbgdetect_funcs: dbgdetect {
  meta:
    author      = "AlienVault Labs"
    type        = "info"
    severity    = 1
    description = "Debugger detection tricks"

  strings:
    $func1 = "IsDebuggerPresent"
    $func2 = "OutputDebugString"
    $func3 = "ZwQuerySystemInformation"
    $func4 = "ZwQueryInformationProcess"
    $func5 = "IsDebugged"
    $func6 = "NtGlobalFlags"
    $func7 = "CheckRemoteDebuggerPresent"
    $func8 = "SetInformationThread"
    $func9 = "DebugActiveProcess"

  condition:
    2 of them
}

rule dbgdetect_procs: dbgdetect {
  meta:
    author      = "AlienVault Labs"
    type        = "info"
    severity    = 1
    description = "Debugger detection tricks"

  strings:
    $proc1 = "wireshark" nocase ascii wide
    $proc2 = "filemon" nocase ascii wide
    $proc3 = "procexp" nocase ascii wide
    $proc4 = "procmon" nocase ascii wide
    $proc5 = "regmon" nocase ascii wide
    $proc6 = "idag" nocase ascii wide
    $proc7 = "immunitydebugger" nocase ascii wide
    $proc8 = "ollydbg" nocase ascii wide
    $proc9 = "petools" nocase ascii wide

  condition:
    2 of them
}

rule sandboxdetect_misc: sandboxdetect {
  meta:
    author      = "AlienVault Labs"
    type        = "info"
    severity    = 1
    description = "Sandbox detection tricks"

  strings:
    $sbxie1 = "sbiedll" nocase ascii wide

    // CWSandbox
    $prodid1 = "55274-640-2673064-23950" ascii wide
    $prodid2 = "76487-644-3177037-23510" ascii wide
    $prodid3 = "76487-337-8429955-22614" ascii wide

    $proc1 = "joeboxserver" ascii wide
    $proc2 = "joeboxcontrol" ascii wide

  condition:
    any of them
}

rule INFO_LNK_Findstr_NSLookup_CMD_LNK {
  meta:
    author      = "Joe Wise"
    description = "Identify LNK files that contain findstr, nslookup, and .cmd"
    date        = "2024-02-08"
    version     = "1.0"
    hash1       = "37f0cd954554e4bd3b766c79f6224c03dbcfbb4c0f23ac1f48292ce88d2dc767"
    DaysOfYara  = "39/100"

  strings:
    $s1 = "nslookup" nocase ascii wide
    $s2 = "findstr" nocase ascii wide
    $s3 = ".cmd" nocase ascii wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule capa_get_file_version_info: CAPA HOST_INTERACTION FILE_SYSTEM META FUNCTION T1083 {
  meta:
    description  = "get file version info (converted from capa rule)"
    namespace    = "host-interaction/file-system/meta"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "function"
    attack       = "Discovery::File and Directory Discovery [T1083]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-file-version-info.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      (
        pe.imports(/version/i, /GetFileVersionInfo/)
        or pe.imports(/version/i, /GetFileVersionInfoEx/)
      )
    )
}

rule info_dyld_env_vars {
  meta:
    description = "Identify executables with environment variables changing the dynamic loader settings. See `man dyld` or `strings /usr/lib/dyld/ | grep DYLD_`"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.02.07"
    DaysofYARA  = "38/100"

  strings:
    $1  = "DYLD_SHARED_REGION"
    $2  = "DYLD_IN_CACHE"
    $3  = "DYLD_JUST_BUILD_CLOSURE"
    $4  = "DYLD_SHARED_CACHE_DIR"
    $5  = "DYLD_PAGEIN_LINKING"
    $6  = "DYLD_FORCE_PLATFORM"
    $7  = "DYLD_SKIP_MAIN"
    $8  = "DYLD_AMFI_FAKE"
    $9  = "DYLD_PRINT_SEGMENTS"
    $10 = "DYLD_PRINT_LIBRARIES"
    $11 = "DYLD_PRINT_BINDINGS"
    $12 = "DYLD_PRINT_INITIALIZERS"
    $13 = "DYLD_PRINT_APIS"
    $14 = "DYLD_PRINT_NOTIFICATIONS"
    $15 = "DYLD_PRINT_INTERPOSING"
    $16 = "DYLD_PRINT_LOADERS"
    $17 = "DYLD_PRINT_SEARCHING"
    $18 = "DYLD_PRINT_ENV"
    $19 = "DYLD_PRINT_TO_STDERR"
    $20 = "DYLD_PRINT_TO_FILE"
    $21 = "DYLD_LIBRARY_PATH"
    $22 = "DYLD_FRAMEWORK_PATH"
    $23 = "DYLD_FALLBACK_FRAMEWORK_PATH"
    $24 = "DYLD_FALLBACK_LIBRARY_PATH"
    $25 = "DYLD_VERSIONED_FRAMEWORK_PATH"
    $26 = "DYLD_VERSIONED_LIBRARY_PATH"
    $27 = "DYLD_INSERT_LIBRARIES"
    $28 = "DYLD_IMAGE_SUFFIX"
    $29 = "DYLD_ROOT_PATH"
    $30 = "DYLD_CLOSURE_DIR"

  condition:
    any of them
}

rule info_macho_python {
  meta:
    description = "Identify Mach-O executables with bundled python content."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.31"
    references  = "https://www.uptycs.com/blog/macstealer-command-and-control-c2-malware"
    sample      = "1153fca0b395b3f219a6ec7ecfc33f522e7b8fc6676ecb1e40d1827f43ad22be"
    DaysofYARA  = "90/100"

  strings:
    $s0 = "@_Py"
    $s1 = "@executable_path/Python"

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    #s0 > 10 or $s1
}

rule info_macos_file_metadata {
  meta:
    description = "Identify macho executable with references to file metadata."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.04.08"
    DaysofYARA  = "98/100"

  strings:
    $cmd0 = "mdls"
    $cmd1 = { 6C 73 [0-6] 20 [0-6] 2D [0-8] 6C [0-8] 40 }

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    uint32(0xc) == 0x2 and  // mach_header->filetype == MH_EXECUTE
    any of them
}

rule info_macos_scpt_applet {
  meta:
    description = "Identify macOS AppleScript Applet stubs."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.04.06"
    DaysofYARA  = "96/100"

  strings:
    $s0 = "_OpenDefaultComponent"
    $s1 = "_CallComponentDispatch"

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and
    all of them
}

rule info_padded_dmg {
  meta:
    description = "Identify Apple DMG with padding between the plist and trailer sections."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.04.01"
    reference   = "https://objective-see.org/blog/blog_0x70.html"
    DaysofYARA  = "91/100"

  strings:
    $plist = "</plist>\x0a"

  condition:
    uint32be(filesize - 512) == 0x6b6f6c79 and  // "koly" trailer of DMG
    not $plist at filesize - 521  // trailer is not prefixed by property list
}

rule info_python_nuitka {
  meta:
    description = "Identify Nuitka-compiled Python executable"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.28"
    reference   = "https://nuitka.net"
    DaysofYARA  = "87/100"

  strings:
    $nuitka = "nuitka" nocase

  condition:
    (
      int16(0) == 0x5a4d or  // PE
      uint32(0) == 0x464c457f or  // ELF
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and #nuitka > 10
}

rule INFO_7z_File {
  meta:
    author     = "Greg Lesnewich"
    date       = "2024-01-22"
    version    = "1.0"
    DaysOfYara = "22/100"

  condition:
    uint16be(0x0) == 0x377A
}

rule INFO_ELF_Contains_iptables {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-21"
    version     = "1.0"
    description = "track ELF files that reference iptables likely for portforwarding, redirecting, or listening "
    DaysofYARA  = "21/100"

  strings:
    $ = "iptables" ascii wide

  condition:
    uint32be(0) == 0x7F454C46 and all of them
}

rule INFO_ELF_Contains_iptables_b64 {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-21"
    version     = "1.0"
    description = "track ELF files that reference iptables likely for portforwarding, redirecting, or listening "
    DaysofYARA  = "21/100"

  strings:
    $ = "iptables" base64 base64wide

  condition:
    uint32be(0) == 0x7F454C46 and all of them
}

rule INFO_ELF_Contains_iptables_xor {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-21"
    version     = "1.0"
    description = "track ELF files that reference iptables likely for portforwarding, redirecting, or listening "
    DaysofYARA  = "21/100"

  strings:
    $ = "iptables" xor(0x01-0xff) ascii wide

  condition:
    uint32be(0) == 0x7F454C46 and all of them
}

rule INFO_ELF_Contains_HTML_Page {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-16"
    version     = "1.0"
    description = "track executable files with equities related to HTML"
    DaysofYARA  = "16/100"

  strings:
    $ = "<!DOCTYPE" ascii wide
    $ = "<html>" ascii wide
    $ = "<title>" ascii wide

  condition:
    uint32be(0) == 0x7F454C46 and all of them
}

rule INFO_PE_Contains_NotFound {
  strings:
    $ = "not found.<" nocase ascii wide

  condition:
    uint16be(0) == 0x4d5a and all of them
}

rule INFO_ELF_Contains_404_Title {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-16"
    version     = "1.0"
    description = "track executable files with equities related to a 404 response page"
    DaysofYARA  = "16/100"

  strings:
    $ = "<title>404" ascii wide

  condition:
    uint32be(0) == 0x7F454C46 and all of them
}

rule INFO_PE_WebServer_References_Microsoft_IIS {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-17"
    version     = "1.0"
    description = "track executable files that reference the Microsoft-IIS web server, which might be a fake response page to being probed "
    DaysofYARA  = "17/100"

  strings:
    $ = "Microsoft-IIS" nocase ascii wide

  condition:
    uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_WebServer_References_OpenResty {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-17"
    version     = "1.0"
    description = "track executable files that reference the OpenResty web server, which might be a fake response page to being probed "
    DaysofYARA  = "17/100"

  strings:
    $ = "OpenResty" nocase ascii wide

  condition:
    uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_WebServer_References_LiteSpeed {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-17"
    version     = "1.0"
    description = "track executable files that reference the LiteSpeed web server, which might be a fake response page to being probed "
    DaysofYARA  = "17/100"

  strings:
    $ = "LiteSpeed" nocase ascii wide

  condition:
    uint16be(0) == 0x4d5a and all of them
}

rule INFO_PE_Imports_NDIS_NetworkInterface {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-20"
    version     = "1.0"
    description = "track executable files that import NDIS which is a legitimate driver for the network interface controller."
    DaysofYARA  = "20/100"

  condition:
    for any imp in pe.import_details: (
      imp.library_name == "NDIS.SYS"
    )
}

rule INFO_PE_Imports_HardwareAbstractionLayer {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-20"
    version     = "1.0"
    description = "track executable files that import hardware abstraction layer (HAL) components"
    DaysofYARA  = "20/100"

  condition:
    for any s in ("hal.dll", "halacpi.dll", "halmacpi.dll"): (
      for any imp in pe.import_details: (
        imp.library_name iequals s
      ))
}

rule INFO_LNK_File_Ref_wsf {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference .wsf"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = ".wsf" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_js {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference .js"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = ".js" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_hta {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference .hta"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = ".hta" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_vbscript {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference vbscript"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "vbscript" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_javascript {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference javascript"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "javascript" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_7z {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference 7z"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "7z" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_java {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference java"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "java" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_File_Ref_py {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference .py"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = ".py" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_certutil {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference certutil"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "certutil" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_msbuild {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference msbuild"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "msbuild" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_curl {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference curl"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "curl" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_regsvr {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference regsvr"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "regsvr" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_scriptrunner {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference scriptrunner"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "scriptrunner" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_registerocx {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference registerocx"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "registerocx" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_advpackdll {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference advpack.dll"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "advpack.dll" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Execution_Ref_shellexec {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference shellexec"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "shellexec" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_set {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference set"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "set" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_exit {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference exit"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "exit" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_copy {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference copy"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "copy" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_xcopy {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference xcopy"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "xcopy" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_echo {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference echo"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "echo" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_findstr {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference findstr"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "findstr" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_call {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference call"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "call" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_attrib {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference attrib"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "attrib" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_cls {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference cls"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "cls" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_rem {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference rem"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "rem" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_goto {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference goto"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "goto" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_msg {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference msg"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "msg" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_app {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference --app="
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "--app=" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_package {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference -package"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "-package" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_getcontent {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference get-content"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "get-content" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_odbcconf {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference odbcconf"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "odbcconf" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_rsp {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference .rsp"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = ".rsp" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_sleep {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference sleep"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "sleep" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_taskkill {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference taskkill"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "taskkill" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_pcalua {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference pcalua"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "pcalua" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_expand {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference expand"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "expand" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_conhost {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference conhost"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "conhost" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_mount {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference mount"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "mount" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_unblock_file {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference unblock-file"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "unblock-file" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_Command_expand_archive {
  meta:
    author      = "Greg Lesnewich stolen inspo from @cbecks_2"
    description = "identify LNK with commandlines that reference expand-archive"
    date        = "2024-01-31"
    version     = "1.0"
    DaysOfYara  = "31/100"

  strings:
    $ = "expand-archive" wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_References_WildCard_LNK_FileHandle {
  meta:
    author      = "Greg Lesnewich"
    description = "identify LNK files that might look for themselves, by referencing a wildcarded LNK filename"
    date        = "2024-01-30"
    version     = "1.0"
    DaysOfYara  = "30/100"

  strings:
    $ = "*.lnk" ascii wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_SelfParsing_Findstr_LNK_FileHandle {
  meta:
    author      = "Greg Lesnewich"
    description = "identify LNK files that likely parse themselves looking for additional files or commands"
    date        = "2024-01-30"
    version     = "1.0"
    DaysOfYara  = "30/100"

  strings:
    $ = ".lnk" ascii wide
    $ = "findstr" ascii wide

  condition:
    uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_Macho_ExternalLibary_Load_Count_0 {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-24"
    version     = "1.0"
    description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

  strings:
    $load_cmd = { 00 00 00 00 0C 00 00 00 }

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    #load_cmd in (0..0x1000) == 0

}

rule INFO_Macho_ExternalLibary_Load_Count_1 {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-24"
    version     = "1.0"
    description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

  strings:
    $load_cmd = { 00 00 00 00 0C 00 00 00 }

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    #load_cmd in (0..0x1000) == 1

}

rule INFO_Macho_ExternalLibary_Load_Count_2 {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-24"
    version     = "1.0"
    description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

  strings:
    $load_cmd = { 00 00 00 00 0C 00 00 00 }

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    #load_cmd in (0..0x1000) == 2

}

rule INFO_Macho_ExternalLibary_Load_Count_3 {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-24"
    version     = "1.0"
    description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

  strings:
    $load_cmd = { 00 00 00 00 0C 00 00 00 }

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    #load_cmd in (0..0x1000) == 3

}

rule INFO_Macho_ExternalLibary_Load_Count_4 {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-24"
    version     = "1.0"
    description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

  strings:
    $load_cmd = { 00 00 00 00 0C 00 00 00 }

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    #load_cmd in (0..0x1000) == 4

}

rule INFO_Macho_ExternalLibary_Load_Count_5 {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-24"
    version     = "1.0"
    description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

  strings:
    $load_cmd = { 00 00 00 00 0C 00 00 00 }

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    #load_cmd in (0..0x1000) == 5

}

rule INFO_Macho_ExternalLibary_Load_Count_More_Than_5 {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-24"
    version     = "1.0"
    description = "highlight the volume of external libraries loaded by a Macho sample, derived from number of LOAD_DYLIB commands in the LoadCommand header"

  strings:
    $load_cmd = { 00 00 00 00 0C 00 00 00 }

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    #load_cmd in (0..0x1000) > 5

}

rule INFO_Macho_Has_CodeSignature {
  meta:
    author      = "Greg Lesnewich"
    description = "check Macho files for an LC_CODE_SIGNATURE load command"
    date        = "2023-01-29"
    version     = "1.0"

  condition:
    (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    for any cs_sig in (0..0x1000): (
      uint32be(cs_sig) == 0x1D000000
    )
}

rule INFO_Macho_LoadCommands_Less_Than_10 {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-24"
    version     = "1.0"
    description = "check for Macho files with less than 10 load commands"

  condition:
    (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    uint32(0x10) <= 0x0a
}

rule INFO_Macho_Long_RPATH {
  meta:
    author      = "Greg Lesnewich"
    description = "check for Macho's that contain an RPath load command, where the data size is larger than 30 bytes"
    date        = "2024-01-02"
    version     = "1.0"
    DaysofYARA  = "2/100"
    reference   = "https://securelist.com/trojan-proxy-for-macos/111325/"

  strings:
    $rpath = { 1c 00 00 80 }

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and filesize < 10MB and
    $rpath in (0..2000) and uint16(@rpath + 4) >= 30
}

rule INFO_Macho_LOObin_csrutil {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin csrutil"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "csrutil" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_ditto {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin ditto"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "ditto" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_dnssd {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin dns"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "dns-sd" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_dscl {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin dscl"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "dscl" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_dsexport {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin dsexport"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "dsexport" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_GetFileInfo {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin GetFileInfo"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "GetFileInfo" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_hdiutil {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin hdiutil"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "hdiutil" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_ioreg {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin ioreg"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "ioreg" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_lsregister {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin lsregister"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "lsregister" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_mdfind {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin mdfind"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "mdfind" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_networksetup {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin networksetup"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "networksetup" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_nscurl {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin nscurl"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "nscurl" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_nvram {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin nvram"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "nvram" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_osacompile {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin osacompile"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "osacompile" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_osascript {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin osascript"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "osascript" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_pbpaste {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin pbpaste"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "pbpaste" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_plutil {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin plutil"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "plutil" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_profiles {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin profiles"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "profiles" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_safaridriver {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin safaridriver"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "safaridriver" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_screencapture {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin screencapture"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "screencapture" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_SetFile {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin SetFile"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "SetFile" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_softwareupdate {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin softwareupdate"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "softwareupdate" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_spctl {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin spctl"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "spctl" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_sqlite3 {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin sqlite3"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "sqlite3" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_sshkeygen {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin ssh"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "ssh-keygen" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_sysctl {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin sysctl"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "sysctl" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_tclsh {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin tclsh"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "tclsh" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_textutil {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin textutil"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "textutil" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_tmutil {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin tmutil"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "tmutil" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LOObin_xattr {
  meta:
    author      = "Greg Lesnewich"
    description = "find Macho files using LOOBin xattr"
    reference   = "https://www.loobins.io/"
    date        = "2024-01-12"
    version     = "1.0"
    DaysofYARA  = "12/100"

  strings:
    $ = "xattr" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_LowLevel_API_task_info {
  meta:
    description = "check Macho files for low level API of task_info, used by _xpn_ to get dydl in memory base address"
    author      = "Greg Lesnewich"
    date        = "2023-01-17"
    version     = "1.0"
    reference   = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"

  strings:
    $ = "task_info" nocase ascii wide

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    all of them
}

rule INFO_Macho_LowLevel_Dydl_API_mmap {
  meta:
    description = "check Macho files for low level API of mmap to map a file into memory"
    author      = "Greg Lesnewich"
    date        = "2023-01-17"
    version     = "1.0"
    reference   = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"

  strings:
    $ = "mmap" ascii wide

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    all of them
}

rule INFO_Macho_LowLevel_Dydl_API_pread {
  meta:
    description = "check Macho files for low level API of pread to read from a given input"
    author      = "Greg Lesnewich"
    date        = "2023-01-17"
    version     = "1.0"
    reference   = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"

  strings:
    $ = "pread" ascii wide

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    all of them
}

rule INFO_Macho_LowLevel_Dydl_API_fcntl {
  meta:
    description = "check Macho files for low level API of fcntl which is used to control open files and provides for control over descriptors"
    author      = "Greg Lesnewich"
    date        = "2023-01-17"
    version     = "1.0"
    reference   = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"

  strings:
    $ = "fcntl" ascii wide

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    all of them
}

rule INFO_Macho_Multiple_Init_Funcs {
  meta:
    author      = "Greg Lesnewich"
    description = "check Macho files for multiple initialization methods, via presence of a Mod Init Func section"
    date        = "2023-01-26"
    version     = "1.0"

  strings:
    $section = "mod_init_func" ascii wide

  condition:
    (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    all of them
}

rule INFO_Macho_Hunting_Osascript {
  meta:
    author      = "Greg Lesnewich"
    description = "checking Macho files for potential scripting interfaces like osascript"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"
    date        = "2024-01-10"
    version     = "1.0"
    DaysofYARA  = "11/100"

  strings:
    $ = "osascript" nocase ascii wide
    $ = "osacompile" nocase ascii wide
    $ = ".scpt" nocase ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and any of them
}

rule INFO_Macho_Hunting_AppleScript_URL {
  meta:
    author      = "Greg Lesnewich"
    description = "checking Macho files for potential scripting interfaces like AppleScript"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"
    date        = "2024-01-10"
    version     = "1.0"
    DaysofYARA  = "11/100"

  strings:
    $ = "applescript://" nocase ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and any of them
}

rule INFO_Macho_Hunting_Python {
  meta:
    author      = "Greg Lesnewich"
    description = "checking Macho files for additional execution strings like python"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"
    date        = "2024-01-10"
    version     = "1.0"
    DaysofYARA  = "11/100"

  strings:
    $str = "python" nocase ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and all of them
}

rule INFO_Macho_Hunting_Ruby {
  meta:
    author      = "Greg Lesnewich"
    description = "checking Macho files for additional execution strings like Ruby"
    date        = "2024-01-10"
    version     = "1.0"
    DaysofYARA  = "11/100"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

  strings:
    $str = "Ruby" nocase ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and all of them
}

rule INFO_Macho_Hunting_Perl {
  meta:
    author      = "Greg Lesnewich"
    description = "checking Macho files for additional execution strings like perl"
    date        = "2024-01-10"
    version     = "1.0"
    DaysofYARA  = "11/100"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

  strings:
    $str = "perl" nocase ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and all of them
}

rule INFO_Macho_Execution_BinBash {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-01"
    version     = "1.0"
    DaysofYARA  = "11/100"
    description = "checking Macho files for additional execution strings like bash shell"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

  strings:
    $ = "bin/bash" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    )
    and all of them
}

rule INFO_Macho_Execution_Bin_sh {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-01"
    version     = "1.0"
    DaysofYARA  = "11/100"
    description = "checking Macho files for additional execution strings like sh shell"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

  strings:
    $ = "bin/sh" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and all of them
}

rule INFO_Macho_Execution_BinZsh {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-01"
    version     = "1.0"
    DaysofYARA  = "11/100"
    description = "checking Macho files for additional execution strings like zsh shell"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

  strings:
    $ = "bin/zsh" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and all of them
}

rule INFO_Macho_Execution_Bin_tcsh {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-01"
    version     = "1.0"
    DaysofYARA  = "11/100"
    description = "checking Macho files for additional execution strings like tcsh shell"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

  strings:
    $ = "bin/tcsh" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and all of them
}

rule INFO_Macho_Execution_BinKsh {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-01"
    version     = "1.0"
    DaysofYARA  = "11/100"
    description = "checking Macho files for additional execution strings like ksh shell"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

  strings:
    $ = "bin/ksh" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and all of them
}

rule INFO_Macho_Execution_Bincsh {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-01"
    version     = "1.0"
    DaysofYARA  = "11/100"
    description = "checking Macho files for additional execution strings like csh shell"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

  strings:
    $ = "bin/csh" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and all of them
}

rule INFO_Macho_Execution_tclsh {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-01"
    version     = "1.0"
    DaysofYARA  = "11/100"
    description = "checking Macho files for additional execution strings like tclsh shell"
    reference   = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

  strings:
    $ = "usr/bin/tclsh" ascii wide
    $ = "bin/tclsh" ascii wide

  condition:
    (
      uint32(0) == 0xfeedface or  // Mach-O MH_MAGIC
      uint32(0) == 0xcefaedfe or  // Mach-O MH_CIGAM
      uint32(0) == 0xfeedfacf or  // Mach-O MH_MAGIC_64
      uint32(0) == 0xcffaedfe or  // Mach-O MH_CIGAM_64
      uint32(0) == 0xcafebabe or  // Mach-O FAT_MAGIC
      uint32(0) == 0xbebafeca  // Mach-O FAT_CIGAM
    ) and all of them
}

rule INFO_MacOS_NamedPipe_ObjC_NSXPC {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-28"
    version     = "1.0"
    description = "check for references to XPC, MacOS low-level interprocess communications, via the NSXPCConnection API classes"

  strings:
    $ = "NSXPCConnection" ascii wide
    $ = "NSXPCInterface" ascii wide
    $ = "NSXPCListener" ascii wide
    $ = "NSXPCListenerEndpoint" ascii wide

  condition:
    any of them
}

rule INFO_MacOS_NamedPipe_ObjC_XPC_API {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-28"
    version     = "1.0"
    description = "check for references to XPC, MacOS low-level interprocess communications, via the XPC APIs"

  strings:
    $ = "IOSurfaceLookupFromXPCObject" ascii wide
    $ = "IOSurfaceCreateXPCObject" ascii wide

  condition:
    any of them
}

rule INFO_MacOS_NamedPipe_ObjC_NSPipe {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-28"
    version     = "1.0"
    description = "check for ObjectiveC interface NSPipe"

  strings:
    $ = "$_NSPipe" ascii wide
    $ = "NSPipe" ascii wide

  condition:
    any of them
}

rule INFO_MacOS_NamedPipe_ObjC_NSConnection {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-28"
    version     = "1.0"
    description = "check for deprecated ObjectiveC interface NSConnection, used in distributed objects mechanism, often to vend an object to other applications"

  strings:
    $ = "NSConnection" ascii wide

  condition:
    any of them
}

rule INFO_PList_Param_StartInterval {
  strings:
    $ = "<key>StartInterval</key>" ascii wide

  condition:
    all of them
}

rule INFO_PList_Param_ThrottleInterval {
  strings:
    $ = "<key>ThrottleInterval</key>" ascii wide

  condition:
    all of them
}

rule INFO_PList_Param_AbandonProcessGroup {
  strings:
    $ = "<key>AbandonProcessGroup</key>" ascii wide

  condition:
    all of them
}

rule INFO_PList_Param_RootDirectory {
  strings:
    $ = "<key>RootDirectory</key>" ascii wide

  condition:
    all of them
}

rule INFO_PList_Param_Umask {
  strings:
    $ = "<key>Umask</key>" ascii wide

  condition:
    all of them
}

rule INFO_PList_Param_OtherJobEnabled {
  strings:
    $ = "<key>OtherJobEnabled</key>" ascii wide

  condition:
    all of them
}

rule INFO_PList_Param_QueueDirectories {
  strings:
    $ = "<key>QueueDirectories</key>" ascii wide

  condition:
    all of them
}

rule INFO_PList_Param_WatchPaths {
  strings:
    $ = "<key>WatchPaths</key>" ascii wide

  condition:
    all of them
}

rule INFO_PList_Param_StartCalendarInterval {
  strings:
    $ = "<key>StartCalendarInterval</key>" ascii wide

  condition:
    all of them
}

rule INFO_PList_Param_StartOnMount {
  strings:
    $ = "<key>StartOnMount</key>" ascii wide

  condition:
    all of them
}

rule INFO_PList_Param_EnvironmentVariables {
  strings:
    $ = "<key>EnvironmentVariables</key>" ascii wide

  condition:
    all of them
}

rule INFO_PList_Param_ProgramArguments {
  strings:
    $ = "<key>ProgramArguments</key>" ascii wide

  condition:
    all of them
}
