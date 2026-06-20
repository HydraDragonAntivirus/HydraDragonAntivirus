import "pe"
import "hash"
import "elf"
import "console"
import "dotnet"
import "macho"
import "math"
import "time"

rule capa_delete_volume_shadow_copies: CAPA IMPACT INHIBIT_SYSTEM_RECOVERY FUNCTION T1490 T1070_004 F0014_001 {
  meta:
    description  = "delete volume shadow copies (converted from capa rule)"
    namespace    = "impact/inhibit-system-recovery"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Impact::Inhibit System Recovery [T1490]"
    attack       = "Defense Evasion::Indicator Removal on Host::File Deletion [T1070.004]"
    mbc          = "Impact::Disk Content Wipe::Delete Shadow Drive [F0014.001]"
    hash         = "B87E9DD18A5533A09D3E48A7A1EFBCF6"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/impact/inhibit-system-recovery/delete-volume-shadow-copies.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_aaw = /vssadmin.\\\{,1000\\\} delete shadows/ nocase ascii wide
    $func_re_aax = /vssadmin.\\\{,1000\\\} resize shadowstorage/ nocase ascii wide
    $func_re_aay = /wmic.\\\{,1000\\\} shadowcopy delete/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_aaw
      or $func_re_aax
      or $func_re_aay
    )
}

rule capa_reference_analysis_tools_strings: CAPA ANTI_ANALYSIS FILE B0013_001 {
  meta:
    description  = "reference analysis tools strings (converted from capa rule)"
    namespace    = "anti-analysis"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "file"
    mbc          = "Discovery::Analysis Tool Discovery::Process Detection [B0013.001]"
    hash         = "al-khaser_x86.exe_"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/reference-analysis-tools-strings.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_aaz = /ollydbg\.exe/ nocase ascii wide
    $file_re_aba = /ProcessHacker\.exe/ nocase ascii wide
    $file_re_abb = /tcpview\.exe/ nocase ascii wide
    $file_re_abc = /autoruns\.exe/ nocase ascii wide
    $file_re_abd = /autorunsc\.exe/ nocase ascii wide
    $file_re_abe = /filemon\.exe/ nocase ascii wide
    $file_re_abf = /procmon\.exe/ nocase ascii wide
    $file_re_abg = /regmon\.exe/ nocase ascii wide
    $file_re_abh = /procexp\.exe/ nocase ascii wide
    $file_re_abi = /idaq\.exe/ nocase ascii wide
    $file_re_abj = /idaq64\.exe/ nocase ascii wide
    $file_re_abk = /ImmunityDebugger\.exe/ nocase ascii wide
    $file_re_abl = /Wireshark\.exe/ nocase ascii wide
    $file_re_abm = /dumpcap\.exe/ nocase ascii wide
    $file_re_abn = /HookExplorer\.exe/ nocase ascii wide
    $file_re_abo = /ImportREC\.exe/ nocase ascii wide
    $file_re_abp = /PETools\.exe/ nocase ascii wide
    $file_re_abq = /LordPE\.exe/ nocase ascii wide
    $file_re_abr = /SysInspector\.exe/ nocase ascii wide
    $file_re_abs = /proc_analyzer\.exe/ nocase ascii wide
    $file_re_abt = /sysAnalyzer\.exe/ nocase ascii wide
    $file_re_abu = /sniff_hit\.exe/ nocase ascii wide
    $file_re_abv = /windbg\.exe/ nocase ascii wide
    $file_re_abw = /joeboxcontrol\.exe/ nocase ascii wide
    $file_re_abx = /joeboxserver\.exe/ nocase ascii wide
    $file_re_aby = /ResourceHacker\.exe/ nocase ascii wide
    $file_re_abz = /x32dbg\.exe/ nocase ascii wide
    $file_re_aca = /x64dbg\.exe/ nocase ascii wide
    $file_re_acb = /Fiddler\.exe/ nocase ascii wide
    $file_re_acc = /httpdebugger\.exe/ nocase ascii wide
    $file_re_acd = /fakenet\.exe/ nocase ascii wide
    $file_re_ace = /netmon\.exe/ nocase ascii wide
    $file_re_acf = /WPE PRO\.exe/ nocase ascii wide
    $file_re_acg = /decompile\.exe/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_aaz
      or $file_re_aba
      or $file_re_abb
      or $file_re_abc
      or $file_re_abd
      or $file_re_abe
      or $file_re_abf
      or $file_re_abg
      or $file_re_abh
      or $file_re_abi
      or $file_re_abj
      or $file_re_abk
      or $file_re_abl
      or $file_re_abm
      or $file_re_abn
      or $file_re_abo
      or $file_re_abp
      or $file_re_abq
      or $file_re_abr
      or $file_re_abs
      or $file_re_abt
      or $file_re_abu
      or $file_re_abv
      or $file_re_abw
      or $file_re_abx
      or $file_re_aby
      or $file_re_abz
      or $file_re_aca
      or $file_re_acb
      or $file_re_acc
      or $file_re_acd
      or $file_re_ace
      or $file_re_acf
      or $file_re_acg
    )
}

rule capa_check_for_sandbox_and_av_modules: CAPA ANTI_ANALYSIS ANTI_AV BASICBLOCK B0009 B0007 {
  meta:
    description  = "check for sandbox and av modules (converted from capa rule)"
    namespace    = "anti-analysis/anti-av"
    author       = "@_re_fox"
    scope        = "basic block"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    mbc          = "Anti-Behavioral Analysis::Sandbox Detection [B0007]"
    hash         = "ccbf7cba35bab56563c0fbe4237fdc41"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-av/check-for-sandbox-and-av-modules.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_ach      = /\bGetModuleHandle(A|W)?\b/ ascii wide
    $basic_re_aci = /avghook(x|a)\.dll/ nocase ascii wide  // AVG
    $basic_re_acj = /snxhk\.dll/ nocase ascii wide  // Avast
    $basic_re_ack = /sf2\.dll/ nocase ascii wide  // Avast
    $basic_re_acl = /sbiedll\.dll/ nocase ascii wide  // Sandboxie
    $basic_re_acm = /dbghelp\.dll/ nocase ascii wide  // WindBG
    $basic_re_acn = /api_log\.dll/ nocase ascii wide  // iDefense Lab
    $basic_re_aco = /dir_watch\.dll/ ascii wide  // iDefense Lab
    $basic_re_acp = /pstorec\.dll/ nocase ascii wide  // SunBelt Sandbox
    $basic_re_acq = /vmcheck\.dll/ nocase ascii wide  // Virtual PC
    $basic_re_acr = /wpespy\.dll/ nocase ascii wide  // WPE Pro
    $basic_re_acs = /cmdvrt(64|32).dll/ nocase ascii wide  // Comodo Container
    $basic_re_act = /sxin.dll/ nocase ascii wide  // 360 SOFTWARE
    $basic_re_acu = /dbghelp\.dll/ nocase ascii wide  // WINE
    $basic_re_acv = /printfhelp\.dll/ nocase ascii wide  // Unknown Sandbox

  condition:
    capa_pe_file and
    (
      $api_ach
      and (
        $basic_re_aci
        or $basic_re_acj
        or $basic_re_ack
        or $basic_re_acl
        or $basic_re_acm
        or $basic_re_acn
        or $basic_re_aco
        or $basic_re_acp
        or $basic_re_acq
        or $basic_re_acr
        or $basic_re_acs
        or $basic_re_act
        or $basic_re_acu
        or $basic_re_acv
      )
    )
}

rule capa_packed_with_ASPack: CAPA ANTI_ANALYSIS PACKER ASPACK FILE T1027_002 F0001 {
  meta:
    description  = "packed with ASPack (converted from capa rule)"
    namespace    = "anti-analysis/packer/aspack"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    hash         = "2055994ff75b4309eee3a49c5749d306"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/aspack/packed-with-aspack.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_adc = "The procedure entry point %s could not be located in the dynamic link library %s" ascii wide
    $file_str_add = "The ordinal %u could not be located in the dynamic link library %s" ascii wide

  condition:
    capa_pe_file and
    (
      for any acy in pe.sections: (acy.name == ".aspack")
      or for any acz in pe.sections: (acz.name == ".adata")
      or for any ada in pe.sections: (ada.name == ".ASPack")
      or for any adb in pe.sections: (adb.name == "ASPack")
      or $file_str_adc
      or $file_str_add
    )
}

rule capa_packed_with_upack: CAPA ANTI_ANALYSIS PACKER UPACK FILE T1027_002 F0001 {
  meta:
    description  = "packed with upack (converted from capa rule)"
    namespace    = "anti-analysis/packer/upack"
    author       = "@_re_fox"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    hash         = "9d98f8519d9fee8219caca5b31eef0bd"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/upack/packed-with-upack.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_adm = "UpackByDwing@" ascii wide

  condition:
    capa_pe_file and
    (
      for any adk in pe.sections: (adk.name == ".Upack")
      or for any adl in pe.sections: (adl.name == ".ByDwing")
      or $file_str_adm
    )
}

rule capa_packed_with_Confuser: CAPA ANTI_ANALYSIS PACKER CONFUSER FILE T1027_002 F0001_009 {
  meta:
    description  = "packed with Confuser (converted from capa rule)"
    namespace    = "anti-analysis/packer/confuser"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing::Confuser [F0001.009]"
    hash         = "b9f5bd514485fb06da39beff051b9fdc"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/confuser/packed-with-confuser.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_adq = "ConfusedByAttribute" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_adq
    )
}

rule capa_packed_with_amber: CAPA ANTI_ANALYSIS PACKER AMBER FILE T1027_002 F0001 {
  meta:
    description  = "packed with amber (converted from capa rule)"
    namespace    = "anti-analysis/packer/amber"
    author       = "john.gorman@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    hash         = "bb7922d368a9a9c8d981837b5ad988f1"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/amber/packed-with-amber.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_adr = "Amber - Reflective PE Packer" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_adr
    )
}

rule capa_packed_with_VMProtect: CAPA ANTI_ANALYSIS PACKER VMPROTECT FILE T1027_002 F0001_010 {
  meta:
    description  = "packed with VMProtect (converted from capa rule)"
    namespace    = "anti-analysis/packer/vmprotect"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing::VMProtect [F0001.010]"
    hash         = "971e599e6e707349eccea2fd4c8e5f67"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/vmprotect/packed-with-vmprotect.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_ads = "A debugger has been found running in your system." ascii wide
    $file_str_adt = "Please, unload it from memory and restart your program." ascii wide
    $file_str_adu = "File corrupted!. This program has been manipulated and maybe" ascii wide
    $file_str_adv = "it's infected by a Virus or cracked. This file won't work anymore." ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_ads
      or $file_str_adt
      or $file_str_adu
      or $file_str_adv
      or for any adw in pe.sections: (adw.name == ".vmp0")
      or for any adx in pe.sections: (adx.name == ".vmp1")
      or for any ady in pe.sections: (ady.name == ".vmp2")
    )
}

rule capa_packed_with_peshield: CAPA ANTI_ANALYSIS PACKER PESHIELD FILE T1027_002 F0001 {
  meta:
    description  = "packed with peshield (converted from capa rule)"
    namespace    = "anti-analysis/packer/peshield"
    author       = "@_re_fox"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    hash         = "a3c0a2425ea84103adde03a92176424c"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/packer/peshield/packed-with-peshield.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_aef = / PE-SHiELD v[0-9]\.[0-9]/ ascii wide

  condition:
    capa_pe_file and
    (
      for any aed in pe.sections: (aed.name == "PESHiELD")
      or for any aee in pe.sections: (aee.name == "PESHiELD_1")
      or $file_re_aef
    )
}

rule capa_reference_anti_VM_strings_targeting_VMWare: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FILE T1497_001 B0009 {
  meta:
    description  = "reference anti-VM strings targeting VMWare (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    hash         = "al-khaser_x86.exe_"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-vmware.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_aei = /VMWare/ nocase ascii wide
    $file_re_aej = /VMTools/ nocase ascii wide
    $file_re_aek = /SOFTWARE\\VMware, Inc\.\\VMware Tools/ nocase ascii wide
    $file_re_ael = /vmnet\.sys/ nocase ascii wide
    $file_re_aem = /vmmouse\.sys/ nocase ascii wide
    $file_re_aen = /vmusb\.sys/ nocase ascii wide
    $file_re_aeo = /vm3dmp\.sys/ nocase ascii wide
    $file_re_aep = /vmci\.sys/ nocase ascii wide
    $file_re_aeq = /vmhgfs\.sys/ nocase ascii wide
    $file_re_aer = /vmmemctl\.sys/ nocase ascii wide
    $file_re_aes = /vmx86\.sys/ nocase ascii wide
    $file_re_aet = /vmrawdsk\.sys/ nocase ascii wide
    $file_re_aeu = /vmusbmouse\.sys/ nocase ascii wide
    $file_re_aev = /vmkdb\.sys/ nocase ascii wide
    $file_re_aew = /vmnetuserif\.sys/ nocase ascii wide
    $file_re_aex = /vmnetadapter\.sys/ nocase ascii wide
    $file_re_aey = /\\\\.\\HGFS/ nocase ascii wide
    $file_re_aez = /\\\\.\\vmci/ nocase ascii wide
    $file_re_afa = /vmtoolsd\.exe/ nocase ascii wide
    $file_re_afb = /vmwaretray\.exe/ nocase ascii wide
    $file_re_afc = /vmwareuser\.exe/ nocase ascii wide
    $file_re_afd = /VGAuthService\.exe/ nocase ascii wide
    $file_re_afe = /vmacthlp\.exe/ nocase ascii wide
    $file_re_aff = /vmci/ nocase ascii wide  // VMWare VMCI Bus Driver
    $file_re_afg = /vmhgfs/ nocase ascii wide  // VMWare Host Guest Control Redirector
    $file_re_afh = /vmmouse/ nocase ascii wide
    $file_re_afi = /vmmemctl/ nocase ascii wide  // VMWare Guest Memory Controller Driver
    $file_re_afj = /vmusb/ nocase ascii wide
    $file_re_afk = /vmusbmouse/ nocase ascii wide
    $file_re_afl = /vmx_svga/ nocase ascii wide
    $file_re_afm = /vmxnet/ nocase ascii wide
    $file_re_afn = /vmx86/ nocase ascii wide
    $file_re_afo = /VMwareVMware/ nocase ascii wide
    $file_re_afp = /vmGuestLib\.dll/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_aei
      or $file_re_aej
      or $file_re_aek
      or $file_re_ael
      or $file_re_aem
      or $file_re_aen
      or $file_re_aeo
      or $file_re_aep
      or $file_re_aeq
      or $file_re_aer
      or $file_re_aes
      or $file_re_aet
      or $file_re_aeu
      or $file_re_aev
      or $file_re_aew
      or $file_re_aex
      or $file_re_aey
      or $file_re_aez
      or $file_re_afa
      or $file_re_afb
      or $file_re_afc
      or $file_re_afd
      or $file_re_afe
      or $file_re_aff
      or $file_re_afg
      or $file_re_afh
      or $file_re_afi
      or $file_re_afj
      or $file_re_afk
      or $file_re_afl
      or $file_re_afm
      or $file_re_afn
      or $file_re_afo
      or $file_re_afp
    )
}

rule capa_check_for_windows_sandbox_via_device: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION BASICBLOCK T1497_001 B0009 {
  meta:
    description  = "check for windows sandbox via device (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "@_re_fox"
    scope        = "basic block"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    hash         = "773290480d5445f11d3dc1b800728966"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-device.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_afq       = /\bCreateFile(A|W)?\b/ ascii wide
    $basic_str_afr = "\\\\.\\GLOBALROOT\\device\\vmsmb" ascii wide

  condition:
    capa_pe_file and
    (
      $api_afq
      and $basic_str_afr
    )
}

rule capa_check_for_microsoft_office_emulation: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FUNCTION T1497_001 B0007_005 {
  meta:
    description  = "check for microsoft office emulation (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection::Product Key/ID Testing [B0007.005]"
    hash         = "773290480d5445f11d3dc1b800728966"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-microsoft-office-emulation.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_afs = /OfficePackagesForWDAG/ ascii wide
    $api_aft     = /\bGetWindowsDirectory(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_afs
      and $api_aft
    )
}

rule capa_check_for_sandbox_username: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FUNCTION T1497 B0009 {
  meta:
    description  = "check for sandbox username (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion [T1497]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    hash         = "ccbf7cba35bab56563c0fbe4237fdc41"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-sandbox-username.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_afu     = /\bGetUserName(A|W)?\b/ ascii wide
    $func_re_afv = /MALTEST/ nocase ascii wide  // Betabot Username Check
    $func_re_afw = /TEQUILABOOMBOOM/ nocase ascii wide  // VirusTotal Sandbox
    $func_re_afx = /SANDBOX/ nocase ascii wide  // Gookit Username Check
    $func_re_afy = /\x00VIRUS/ nocase ascii wide  // Satan Username Check
    $func_re_afz = /MALWARE/ nocase ascii wide  // Betabot Username Check
    $func_re_aga = /SAND\sBOX/ nocase ascii wide  // Betabot Username Check
    $func_re_agb = /Test\sUser/ nocase ascii wide  // Betabot Username Check
    $func_re_agc = /CurrentUser/ nocase ascii wide  // Gookit Username Check
    $func_re_agd = /7SILVIA/ nocase ascii wide  // Gookit Username Check
    $func_re_age = /FORTINET/ nocase ascii wide  // Shifu Username Check
    $func_re_agf = /John\sDoe/ nocase ascii wide  // Emotet Username Check
    $func_re_agg = /Emily/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_agh = /HANSPETER\-PC/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_agi = /HAPUBWS/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_agj = /Hong\sLee/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_agk = /IT\-ADMIN/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_agl = /JOHN\-PC/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_agm = /Johnson/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_agn = /Miller/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_ago = /MUELLER\-PC/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_agp = /Peter\sWilson/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_agq = /SystemIT/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_agr = /Timmy/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_ags = /WIN7\-TRAPS/ nocase ascii wide  // Trickbot Downloader Username Check
    $func_re_agt = /WDAGUtilityAccount/ nocase ascii wide  // Windows Defender Application Guard

  condition:
    capa_pe_file and
    (
      $api_afu
      and (
        $func_re_afv
        or $func_re_afw
        or $func_re_afx
        or $func_re_afy
        or $func_re_afz
        or $func_re_aga
        or $func_re_agb
        or $func_re_agc
        or $func_re_agd
        or $func_re_age
        or $func_re_agf
        or $func_re_agg
        or $func_re_agh
        or $func_re_agi
        or $func_re_agj
        or $func_re_agk
        or $func_re_agl
        or $func_re_agm
        or $func_re_agn
        or $func_re_ago
        or $func_re_agp
        or $func_re_agq
        or $func_re_agr
        or $func_re_ags
        or $func_re_agt
      )
    )
}

rule capa_reference_anti_VM_strings_targeting_Parallels: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FILE T1497_001 B0009 {
  meta:
    description  = "reference anti-VM strings targeting Parallels (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    hash         = "al-khaser_x86.exe_"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-parallels.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_agu = /Parallels/ nocase ascii wide
    $file_re_agv = /prl_cc.exe/ nocase ascii wide
    $file_re_agw = /prl_tools.exe/ nocase ascii wide
    $file_re_agx = /prl hyperv/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_agu
      or $file_re_agv
      or $file_re_agw
      or $file_re_agx
    )
}

rule capa_reference_anti_VM_strings_targeting_VirtualBox: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FILE T1497_001 B0009 {
  meta:
    description  = "reference anti-VM strings targeting VirtualBox (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    hash         = "al-khaser_x86.exe_"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-virtualbox.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_agy = /VBOX/ nocase ascii wide
    $file_re_agz = /VEN_VBOX/ nocase ascii wide
    $file_re_aha = /VirtualBox/ nocase ascii wide
    $file_re_ahb = /06\/23\/99/ nocase ascii wide
    $file_re_ahc = /HARDWARE\\ACPI\\DSDT\\VBOX__/ nocase ascii wide
    $file_re_ahd = /HARDWARE\\ACPI\\FADT\\VBOX__/ nocase ascii wide
    $file_re_ahe = /HARDWARE\\ACPI\\RSDT\\VBOX__/ nocase ascii wide
    $file_re_ahf = /SOFTWARE\\Oracle\\VirtualBox Guest Additions/ nocase ascii wide
    $file_re_ahg = /SYSTEM\\ControlSet001\\Services\\VBoxGuest/ nocase ascii wide
    $file_re_ahh = /SYSTEM\\ControlSet001\\Services\\VBoxMouse/ nocase ascii wide
    $file_re_ahi = /SYSTEM\\ControlSet001\\Services\\VBoxService/ nocase ascii wide
    $file_re_ahj = /SYSTEM\\ControlSet001\\Services\\VBoxSF/ nocase ascii wide
    $file_re_ahk = /SYSTEM\\ControlSet001\\Services\\VBoxVideo/ nocase ascii wide
    $file_re_ahl = /VBoxMouse\.sys/ nocase ascii wide
    $file_re_ahm = /VBoxGuest\.sys/ nocase ascii wide
    $file_re_ahn = /VBoxSF\.sys/ nocase ascii wide
    $file_re_aho = /VBoxVideo\.sys/ nocase ascii wide
    $file_re_ahp = /vboxdisp\.dll/ nocase ascii wide
    $file_re_ahq = /vboxhook\.dll/ nocase ascii wide
    $file_re_ahr = /vboxmrxnp\.dll/ nocase ascii wide
    $file_re_ahs = /vboxogl\.dll/ nocase ascii wide
    $file_re_aht = /vboxoglarrayspu\.dll/ nocase ascii wide
    $file_re_ahu = /vboxoglcrutil\.dll/ nocase ascii wide
    $file_re_ahv = /vboxoglerrorspu\.dll/ nocase ascii wide
    $file_re_ahw = /vboxoglfeedbackspu\.dll/ nocase ascii wide
    $file_re_ahx = /vboxoglpackspu\.dll/ nocase ascii wide
    $file_re_ahy = /vboxoglpassthroughspu\.dll/ nocase ascii wide
    $file_re_ahz = /vboxservice\.exe/ nocase ascii wide
    $file_re_aia = /vboxtray\.exe/ nocase ascii wide
    $file_re_aib = /VBoxControl\.exe/ nocase ascii wide
    $file_re_aic = /oracle\\virtualbox guest additions\\/ nocase ascii wide
    $file_re_aid = /\\\\.\\VBoxMiniRdrDN/ nocase ascii wide
    $file_re_aie = /\\\\.\\VBoxGuest/ nocase ascii wide
    $file_re_aif = /\\\\.\\pipe\\VBoxMiniRdDN/ nocase ascii wide
    $file_re_aig = /\\\\.\\VBoxTrayIPC/ nocase ascii wide
    $file_re_aih = /\\\\.\\pipe\\VBoxTrayIPC/ nocase ascii wide
    $file_re_aii = /VBoxTrayToolWndClass/ nocase ascii wide
    $file_re_aij = /VBoxTrayToolWnd/ nocase ascii wide
    $file_re_aik = /vboxservice\.exe/ nocase ascii wide
    $file_re_ail = /vboxtray.exe/ nocase ascii wide
    $file_re_aim = /vboxvideo/ nocase ascii wide
    $file_re_ain = /VBoxVideoW8/ nocase ascii wide
    $file_re_aio = /VBoxWddm/ nocase ascii wide
    $file_re_aip = /PCI\\VEN_80EE&DEV_CAFE/ nocase ascii wide
    $file_re_aiq = /82801FB/ nocase ascii wide
    $file_re_air = /82441FX/ nocase ascii wide
    $file_re_ais = /82371SB/ nocase ascii wide
    $file_re_ait = /OpenHCD/ nocase ascii wide
    $file_re_aiu = /ACPIBus_BUS_0/ nocase ascii wide
    $file_re_aiv = /PCI_BUS_0/ nocase ascii wide
    $file_re_aiw = /PNP_BUS_0/ nocase ascii wide
    $file_re_aix = /Oracle Corporation/ nocase ascii wide
    $file_re_aiy = /VBoxWdd/ nocase ascii wide
    $file_re_aiz = /VBoxS/ nocase ascii wide  // VirtualBox Shared Folders
    $file_re_aja = /VBoxMouse/ nocase ascii wide  // VirtualBox Guest Mouse
    $file_re_ajb = /VBoxGuest/ nocase ascii wide  // VirtualBox Guest Driver
    $file_re_ajc = /VBoxVBoxVBox/ nocase ascii wide
    $file_re_ajd = /innotek GmbH/ nocase ascii wide
    $file_re_aje = /drivers\\vboxdrv/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_agy
      or $file_re_agz
      or $file_re_aha
      or $file_re_ahb
      or $file_re_ahc
      or $file_re_ahd
      or $file_re_ahe
      or $file_re_ahf
      or $file_re_ahg
      or $file_re_ahh
      or $file_re_ahi
      or $file_re_ahj
      or $file_re_ahk
      or $file_re_ahl
      or $file_re_ahm
      or $file_re_ahn
      or $file_re_aho
      or $file_re_ahp
      or $file_re_ahq
      or $file_re_ahr
      or $file_re_ahs
      or $file_re_aht
      or $file_re_ahu
      or $file_re_ahv
      or $file_re_ahw
      or $file_re_ahx
      or $file_re_ahy
      or $file_re_ahz
      or $file_re_aia
      or $file_re_aib
      or $file_re_aic
      or $file_re_aid
      or $file_re_aie
      or $file_re_aif
      or $file_re_aig
      or $file_re_aih
      or $file_re_aii
      or $file_re_aij
      or $file_re_aik
      or $file_re_ail
      or $file_re_aim
      or $file_re_ain
      or $file_re_aio
      or $file_re_aip
      or $file_re_aiq
      or $file_re_air
      or $file_re_ais
      or $file_re_ait
      or $file_re_aiu
      or $file_re_aiv
      or $file_re_aiw
      or $file_re_aix
      or $file_re_aiy
      or $file_re_aiz
      or $file_re_aja
      or $file_re_ajb
      or $file_re_ajc
      or $file_re_ajd
      or $file_re_aje
    )
}

rule capa_check_for_windows_sandbox_via_registry: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FUNCTION T1497_001 B0009 {
  meta:
    description  = "check for windows sandbox via registry (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    hash         = "773290480d5445f11d3dc1b800728966"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-registry.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_ajf     = /\bRegOpenKeyEx(A|W)?\b/ ascii wide
    $api_ajg     = /\bRegEnumValue(A|W)?\b/ ascii wide
    $func_re_ajh = /\\Microsoft\\Windows\\CurrentVersion\\RunOnce/ ascii wide
    $func_re_aji = /wmic useraccount where \"name='WDAGUtilityAccount'\"/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $api_ajf
      and $api_ajg
      and $func_re_ajh
      and $func_re_aji
    )
}

rule capa_reference_anti_VM_strings_targeting_Xen: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FILE T1497_001 B0009 {
  meta:
    description  = "reference anti-VM strings targeting Xen (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    hash         = "al-khaser_x86.exe_"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-xen.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_ajj = /\x00Xen/ nocase ascii wide
    $file_re_ajk = /XenVMMXenVMM/ nocase ascii wide
    $file_re_ajl = /xenservice.exe/ nocase ascii wide
    $file_re_ajm = /XenVMMXenVMM/ nocase ascii wide
    $file_re_ajn = /HVM domU/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_ajj
      or $file_re_ajk
      or $file_re_ajl
      or $file_re_ajm
      or $file_re_ajn
    )
}

rule capa_reference_anti_VM_strings: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FILE T1497_001 B0009 {
  meta:
    description  = "reference anti-VM strings (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "moritz.raabe@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    hash         = "Practical Malware Analysis Lab 17-02.dll_"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_ajo = /HARDWARE\\ACPI\\(DSDT|FADT|RSDT)\\BOCHS/ nocase ascii wide
    $file_re_ajp = /HARDWARE\\DESCRIPTION\\System\\(SystemBiosVersion|VideoBiosVersion)/ nocase ascii wide
    $file_re_ajq = /HARDWARE\\DESCRIPTION\\System\\CentralProcessor/ nocase ascii wide
    $file_re_ajr = /HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0/ nocase ascii wide
    $file_re_ajs = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Enum\\IDE/ nocase ascii wide
    $file_re_ajt = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Services\\Disk\\Enum\\/ nocase ascii wide
    $file_re_aju = /SYSTEM\\(CurrentControlSet|ControlSet001)\\Control\\SystemInformation\\SystemManufacturer/ nocase ascii wide
    $file_re_ajv = /A M I/ nocase ascii wide
    $file_re_ajw = /Hyper-V/ nocase ascii wide
    $file_re_ajx = /Kernel-VMDetection-Private/ nocase ascii wide
    $file_re_ajy = /KVMKVMKVM/ nocase ascii wide  // KVM
    $file_re_ajz = /Microsoft Hv/ nocase ascii wide  // Microsoft Hyper-V or Windows Virtual PC
    $file_re_aka = /avghookx.dll/ nocase ascii wide  // AVG
    $file_re_akb = /avghooka.dll/ nocase ascii wide  // AVG
    $file_re_akc = /snxhk.dll/ nocase ascii wide  // Avast
    $file_re_akd = /pstorec.dll/ nocase ascii wide  // SunBelt Sandbox
    $file_re_ake = /vmcheck.dll/ nocase ascii wide  // Virtual PC
    $file_re_akf = /wpespy.dll/ nocase ascii wide  // WPE Pro
    $file_re_akg = /cmdvrt64.dll/ nocase ascii wide  // Comodo Container
    $file_re_akh = /cmdvrt32.dll/ nocase ascii wide  // Comodo Container
    $file_re_aki = /sample.exe/ nocase ascii wide
    $file_re_akj = /bot.exe/ nocase ascii wide
    $file_re_akk = /sandbox.exe/ nocase ascii wide
    $file_re_akl = /malware.exe/ nocase ascii wide
    $file_re_akm = /test.exe/ nocase ascii wide
    $file_re_akn = /klavme.exe/ nocase ascii wide
    $file_re_ako = /myapp.exe/ nocase ascii wide
    $file_re_akp = /testapp.exe/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_ajo
      or $file_re_ajp
      or $file_re_ajq
      or $file_re_ajr
      or $file_re_ajs
      or $file_re_ajt
      or $file_re_aju
      or $file_re_ajv
      or $file_re_ajw
      or $file_re_ajx
      or $file_re_ajy
      or $file_re_ajz
      or $file_re_aka
      or $file_re_akb
      or $file_re_akc
      or $file_re_akd
      or $file_re_ake
      or $file_re_akf
      or $file_re_akg
      or $file_re_akh
      or $file_re_aki
      or $file_re_akj
      or $file_re_akk
      or $file_re_akl
      or $file_re_akm
      or $file_re_akn
      or $file_re_ako
      or $file_re_akp
    )
}

rule capa_reference_anti_VM_strings_targeting_Qemu: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FILE T1497_001 B0009 {
  meta:
    description  = "reference anti-VM strings targeting Qemu (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    hash         = "al-khaser_x86.exe_"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-qemu.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_akq = /Qemu/ nocase ascii wide
    $file_re_akr = /qemu-ga.exe/ nocase ascii wide
    $file_re_aks = /BOCHS/ nocase ascii wide
    $file_re_akt = /BXPC/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_akq
      or $file_re_akr
      or $file_re_aks
      or $file_re_akt
    )
}

rule capa_reference_anti_VM_strings_targeting_VirtualPC: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FILE T1497_001 B0009 {
  meta:
    description  = "reference anti-VM strings targeting VirtualPC (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    hash         = "al-khaser_x86.exe_"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/reference-anti-vm-strings-targeting-virtualpc.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_aku = /VirtualPC/ nocase ascii wide
    $file_re_akv = /VMSrvc.exe/ nocase ascii wide
    $file_re_akw = /VMUSrvc.exe/ nocase ascii wide
    $file_re_akx = /SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_aku
      or $file_re_akv
      or $file_re_akw
      or $file_re_akx
    )
}

rule capa_check_if_process_is_running_under_wine: CAPA ANTI_ANALYSIS ANTI_EMULATION WINE FUNCTION T1497_001 B0004 {
  meta:
    description  = "check if process is running under wine (converted from capa rule)"
    namespace    = "anti-analysis/anti-emulation/wine"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Emulator Detection [B0004]"
    hash         = "ccbf7cba35bab56563c0fbe4237fdc41"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-emulation/wine/check-if-process-is-running-under-wine.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_aky  = /SOFTWARE\\Wine/ nocase ascii wide
    $api_akz      = /\bGetModuleHandle(A|W)?\b/ ascii wide
    $api_ala      = /\bGetProcAddress(A|W)?\b/ ascii wide
    $func_str_alb = "wine_get_unix_file_name" ascii wide
    $func_str_alc = "kernel32.dll" ascii wide
    $func_str_ald = "ntdll.dll" ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_aky
      or (
        $api_akz
        and $api_ala
        and $func_str_alb
        and (
          $func_str_alc
          or $func_str_ald
        )
      )
    )
}

rule capa_contains_PDB_path: CAPA EXECUTABLE PE PDB FILE {
  meta:
    description  = "contains PDB path (converted from capa rule)"
    namespace    = "executable/pe/pdb"
    author       = "moritz.raabe@fireeye.com"
    scope        = "file"
    hash         = "464EF2CA59782CE697BC329713698CCC"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/pe/pdb/contains-pdb-path.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_alf = /:\\.\\\{,1000\\\}\.pdb/ ascii wide

  condition:
    capa_pe_file and

    $file_re_alf
}

rule capa_packaged_as_an_IExpress_self_extracting_archive: CAPA EXECUTABLE INSTALLER IEXPRESS FILE {
  meta:
    description  = "packaged as an IExpress self-extracting archive (converted from capa rule)"
    namespace    = "executable/installer/iexpress"
    author       = "@recvfrom"
    scope        = "file"
    hash         = "ac742739cae0d411dfcb78ae99a7baee"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/executable/installer/iexpress/packaged-as-an-iexpress-self-extracting-archive.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_alj = "wextract_cleanup%d" ascii wide
    $file_str_alk = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
    $file_str_all = "  <description>IExpress extraction tool</description>" ascii wide

  condition:
    capa_pe_file and
    (
      (
        $file_str_alj
        and $file_str_alk
      )
      or $file_str_all
    )
}

rule capa_access_firewall_settings_via_INetFwMgr: CAPA HOST_INTERACTION FIREWALL MODIFY FUNCTION T1518_001 T1562_004 {
  meta:
    description  = "access firewall settings via INetFwMgr (converted from capa rule)"
    namespace    = "host-interaction/firewall/modify"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Discovery::Software Discovery::Security Software Discovery [T1518.001]"
    attack       = "Defense Evasion::Impair Defenses::Disable or Modify System Firewall [T1562.004]"
    hash         = "EB355BD63BDDCE02955792B4CD6539FB"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/firewall/modify/access-firewall-settings-via-inetfwmgr.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_als = { 42 E9 4C 30 39 6E D8 40 94 3A B9 13 C4 0C 9C D4 }  // CLSID_NetFwMgr
    $func_alt = { F5 8A 89 F7 C4 CA 32 46 A2 EC DA 06 E5 11 1A F2 }  // IID_INetFwMgr

  condition:
    capa_pe_file and
    (
      pe.imports(/ole32/i, /CoCreateInstance/)
      and $func_als
      and $func_alt
    )
}

rule capa_bypass_Mark_of_the_Web: CAPA HOST_INTERACTION FILE_SYSTEM FUNCTION T1553_005 {
  meta:
    description  = "bypass Mark of the Web (converted from capa rule)"
    namespace    = "host-interaction/file-system"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Subvert Trust Controls::Mark-of-the-Web Bypass [T1553.005]"
    hash         = "48c7ad2d9d482cb11898f2719638ceed"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/bypass-mark-of-the-web.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_amd      = /\bDeleteFile(A|W)?\b/ ascii wide
    $func_str_ame = ":Zone.Identifier" ascii wide  // NTFS ADS name recognized by Windows Defender SmartScreen
    $func_str_amf = "%s:Zone.Identifier" ascii wide  // NTFS ADS name recognized by Windows Defender SmartScreen

  condition:
    capa_pe_file and
    (
      $api_amd
      and (
        $func_str_ame
        or $func_str_amf
      )
    )
}

rule capa_get_number_of_processor_cores: CAPA HOST_INTERACTION HARDWARE CPU FUNCTION T1082 {
  meta:
    description  = "get number of processor cores (converted from capa rule)"
    namespace    = "host-interaction/hardware/cpu"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "function"
    attack       = "Discovery::System Information Discovery [T1082]"
    hash         = "al-khaser_x86.exe_:0x435BA0"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/cpu/get-number-of-processor-cores.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_aog  = /SELECT\s+\*\s+FROM\s+Win32_Processor/ ascii wide
    $func_str_aoh = "NumberOfCores" ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_aog
      and $func_str_aoh
    )
}

rule capa_manipulate_CD_ROM_drive: CAPA HOST_INTERACTION HARDWARE CDROM FUNCTION B0042_001 {
  meta:
    description  = "manipulate CD-ROM drive (converted from capa rule)"
    namespace    = "host-interaction/hardware/cdrom"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "function"
    mbc          = "Impact::Modify Hardware::CDROM [B0042.001]"
    hash         = "39C05B15E9834AC93F206BC114D0A00C357C888DB567BA8F5345DA0529CBED41"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/cdrom/manipulate-cd-rom-drive.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_aoi = "set cdaudio door closed wait" ascii wide
    $func_str_aoj = "set cdaudio door open" ascii wide

  condition:
    capa_pe_file and
    (
      pe.imports(/winmm/i, /mciSendString/)
      and (
        $func_str_aoi
        or $func_str_aoj
      )
    )
}

rule capa_disable_driver_code_integrity: CAPA HOST_INTERACTION DRIVER FUNCTION {
  meta:
    description  = "disable driver code integrity (converted from capa rule)"
    namespace    = "host-interaction/driver"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    hash         = "31CEE4F66CF3B537E3D2D37A71F339F4"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/driver/disable-driver-code-integrity.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_aol = "CiInitialize" ascii wide  // exported symbol name used to resolve code integrity configuration
    $func_re_aom  = /g_CiEnabled/ ascii wide  // non-exported name for code integrity flag
    $func_re_aon  = /g_CiOptions/ ascii wide  // non-exported name for code integrity settings

  condition:
    capa_pe_file and
    (
      (
        $func_str_aol
        or $func_re_aom
        or $func_re_aon
      )
    )
}

rule capa_manipulate_boot_configuration: CAPA HOST_INTERACTION BOOTLOADER FUNCTION {
  meta:
    description  = "manipulate boot configuration (converted from capa rule)"
    namespace    = "host-interaction/bootloader"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    hash         = "7FBC17A09CF5320C515FC1C5BA42C8B3"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/bootloader/manipulate-boot-configuration.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_aor = /bcdedit.exe/ nocase ascii wide
    $func_re_aos = /boot.ini/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_aor
      )
      or (
        $func_re_aos
      )
    )
}

rule capa_references_logon_banner: CAPA HOST_INTERACTION GUI LOGON BASICBLOCK {
  meta:
    description  = "references logon banner (converted from capa rule)"
    namespace    = "host-interaction/gui/logon"
    author       = "@_re_fox"
    scope        = "basic block"
    hash         = "c3341b7dfbb9d43bca8c812e07b4299f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/logon/references-logon-banner.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_re_aoy = /\\Microsoft\\Windows\\CurrentVersion\\Policies\\System/ ascii wide
    $basic_re_aoz = /LegalNoticeCaption/ ascii wide
    $basic_re_apa = /LegalNoticeText/ ascii wide

  condition:
    capa_pe_file and
    (
      $basic_re_aoy
      and (
        $basic_re_aoz
        or $basic_re_apa
      )
    )
}

rule capa_use_process_doppelganging: CAPA HOST_INTERACTION PROCESS INJECT FILE T1055_013 {
  meta:
    description  = "use process doppelganging (converted from capa rule)"
    namespace    = "host-interaction/process/inject"
    author       = "moritz.raabe@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Process Injection::Process Doppelganging [T1055.013]"
    hash         = "A5D66324DAAEE5672B913AA461D4BD3A"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/process/inject/use-process-doppelganging.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_ape  = /CreateFileTransacted./ ascii wide
    $file_str_apf = "ZwCreateSection" ascii wide
    $file_str_apg = "NtCreateSection" ascii wide
    $file_str_aph = "RollbackTransaction" ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_ape
      and (
        $file_str_apf
        or $file_str_apg
      )
      and $file_str_aph
    )
}

rule capa_bypass_UAC_via_token_manipulation: CAPA HOST_INTERACTION UAC BYPASS FUNCTION T1548_002 {
  meta:
    description  = "bypass UAC via token manipulation (converted from capa rule)"
    namespace    = "host-interaction/uac/bypass"
    author       = "richard.cole@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
    hash         = "2f43138aa75fb12ac482b486cbc98569"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/uac/bypass/bypass-uac-via-token-manipulation.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_aqa = "wusa.exe" ascii wide
    $api_aqb      = /\bShellExecuteExW(A|W)?\b/ ascii wide
    $api_aqc      = /\bImpersonateLoggedOnUser(A|W)?\b/ ascii wide
    $api_aqd      = /\bGetStartupInfoW(A|W)?\b/ ascii wide
    $api_aqe      = /\bCreateProcessWithLogonW(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_aqa
      and $api_aqb
      and $api_aqc
      and $api_aqd
      and $api_aqe
    )
}

rule capa_bypass_UAC_via_AppInfo_ALPC: CAPA HOST_INTERACTION UAC BYPASS FUNCTION T1548_002 {
  meta:
    description  = "bypass UAC via AppInfo ALPC (converted from capa rule)"
    namespace    = "host-interaction/uac/bypass"
    author       = "richard.cole@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
    hash         = "2f43138aa75fb12ac482b486cbc98569"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/uac/bypass/bypass-uac-via-appinfo-alpc.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_aqf = "winver.exe" ascii wide
    $func_str_aqg = "WinSta0\\Default" ascii wide
    $func_str_aqh = "taskmgr.exe" ascii wide
    $api_aqi      = /\bWaitForDebugEvent(A|W)?\b/ ascii wide
    $api_aqj      = /\bContinueDebugEvent(A|W)?\b/ ascii wide
    $api_aqk      = /\bTerminateProcess(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_aqf
      and $func_str_aqg
      and $func_str_aqh
      and $api_aqi
      and $api_aqj
      and $api_aqk
    )
}

rule capa_set_registry_value: CAPA HOST_INTERACTION REGISTRY CREATE FUNCTION C0036_001 {
  meta:
    description  = "set registry value (converted from capa rule)"
    namespace    = "host-interaction/registry/create"
    scope        = "function"
    mbc          = "Operating System::Registry::Set Registry Key [C0036.001]"
    hash         = "BFB9B5391A13D0AFD787E87AB90F14F5"
    hash         = "B5F85C26D7AA5A1FB4AF5821B6B5AB9B"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/registry/create/set-registry-value.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_ass     = /\bZwSetValueKey(A|W)?\b/ ascii wide
    $api_ast     = /\bNtSetValueKey(A|W)?\b/ ascii wide
    $api_asu     = /\bRtlWriteRegistryValue(A|W)?\b/ ascii wide
    $api_asv     = /\bSHSetValue(A|W)?\b/ ascii wide
    $api_asw     = /\bSHRegSetPath(A|W)?\b/ ascii wide
    $api_asx     = /\bSHRegSetValue(A|W)?\b/ ascii wide
    $api_asy     = /\bSHRegSetUSValue(A|W)?\b/ ascii wide
    $api_asz     = /\bSHRegWriteUSValue(A|W)?\b/ ascii wide
    $func_re_ata = /reg(.exe)? add / nocase ascii wide

  condition:
    capa_pe_file and
    (
      (
        (
          pe.imports(/advapi32/i, /RegSetValue/)
          or pe.imports(/advapi32/i, /RegSetValueEx/)
          or pe.imports(/advapi32/i, /RegSetKeyValue/)
          or $api_ass
          or $api_ast
          or $api_asu
          or $api_asv
          or $api_asw
          or $api_asx
          or $api_asy
          or $api_asz
        )
      )
      or (
        capa_create_process

        and $func_re_ata
      )
    )
}

rule capa_linked_against_Crypto__: CAPA LINKING STATIC CRYPTOPP FILE C0059 {
  meta:
    description  = "linked against Crypto++ (converted from capa rule)"
    namespace    = "linking/static/cryptopp"
    author       = "moritz.raabe@fireeye.com"
    scope        = "file"
    mbc          = "Cryptography::Crypto Library [C0059]"
    hash         = "8BA66E4B618FFDC8255F1DF01F875DDE6FD0561305D9F8307BE7BB11D02AE363"
    hash         = "66602B5FAB602CB4E6F754748D249542"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/cryptopp/linked-against-crypto.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_atb = "Cryptographic algorithms are disabled after a power-up self test failed." ascii wide
    $file_str_atc = ": this object requires an IV" ascii wide
    $file_str_atd = "BER decode error" ascii wide
    $file_str_ate = ".?AVException@CryptoPP@@" ascii wide
    $file_str_atf = "FileStore: error reading file" ascii wide
    $file_str_atg = "StreamTransformationFilter: PKCS_PADDING cannot be used with " ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_atb
      or $file_str_atc
      or $file_str_atd
      or $file_str_ate
      or $file_str_atf
      or $file_str_atg
    )
}

rule capa_linked_against_OpenSSL: CAPA LINKING STATIC OPENSSL FILE C0059 {
  meta:
    description  = "linked against OpenSSL (converted from capa rule)"
    namespace    = "linking/static/openssl"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    mbc          = "Cryptography::Crypto Library [C0059]"
    hash         = "6cc148363200798a12091b97a17181a1"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/openssl/linked-against-openssl.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_ath = "RC4 for x86_64, CRYPTOGAMS by <appro@openssl.org>" ascii wide
    $file_str_ati = "AES for x86_64, CRYPTOGAMS by <appro@openssl.org>" ascii wide
    $file_str_atj = "DSA-SHA1-old" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_ath
      or $file_str_ati
      or $file_str_atj
    )
}

rule capa_linked_against_PolarSSL_mbed_TLS: CAPA LINKING STATIC POLARSSL FILE C0059 {
  meta:
    description  = "linked against PolarSSL/mbed TLS (converted from capa rule)"
    namespace    = "linking/static/polarssl"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    mbc          = "Cryptography::Crypto Library [C0059]"
    hash         = "232b0a8546035d9017fadf68398826edb0a1e055566bc1d356d6c9fdf1d7e485"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/polarssl/linked-against-polarsslmbed-tls.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_atk = "PolarSSLTest" ascii wide
    $file_str_atl = "mbedtls_cipher_setup" ascii wide
    $file_str_atm = "mbedtls_pk_verify" ascii wide
    $file_str_atn = "mbedtls_ssl_write_record" ascii wide
    $file_str_ato = "mbedtls_ssl_fetch_input" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_atk
      or $file_str_atl
      or $file_str_atm
      or $file_str_atn
      or $file_str_ato
    )
}

rule capa_linked_against_libcurl: CAPA LINKING STATIC LIBCURL FILE {
  meta:
    description  = "linked against libcurl (converted from capa rule)"
    namespace    = "linking/static/libcurl"
    author       = "moritz.raabe@fireeye.com"
    scope        = "file"
    hash         = "A90E5B3454AA71D9700B2EA54615F44B"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/libcurl/linked-against-libcurl.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_atp = /CLIENT libcurl/ ascii wide
    $file_re_atq = /curl\.haxx\.se/ ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_atp
      or $file_re_atq
    )
}

rule capa_linked_against_ZLIB: CAPA LINKING STATIC ZLIB FILE C0060 {
  meta:
    description  = "linked against ZLIB (converted from capa rule)"
    namespace    = "linking/static/zlib"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    mbc          = "Data::Compression Library [C0060]"
    hash         = "6cc148363200798a12091b97a17181a1"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/linking/static/zlib/linked-against-zlib.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_att = /deflate .\\\{,1000\\\} Copyright/ ascii wide
    $file_re_atu = /inflate .\\\{,1000\\\} Copyright/ ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_att
      or $file_re_atu
    )
}

rule capa_reference_Base64_string: CAPA DATA_MANIPULATION ENCODING BASE64 FILE T1027 C0026_001 C0019 {
  meta:
    description  = "reference Base64 string (converted from capa rule)"
    namespace    = "data-manipulation/encoding/base64"
    author       = "moritz.raabe@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Data::Encode Data::Base64 [C0026.001]"
    mbc          = "Data::Check String [C0019]"
    hash         = "BFB9B5391A13D0AFD787E87AB90F14F5"
    hash         = "074072B261FC27B65C72671F13510C05"
    hash         = "5DB2D2BE20D59AA0BE6709A6850F1775"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encoding/base64/reference-base64-string.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_atv = /ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ ascii wide

  condition:
    capa_pe_file and

    $file_re_atv
}

rule capa_encrypt_data_using_Camellia: CAPA DATA_MANIPULATION ENCRYPTION CAMELLIA BASICBLOCK T1027 E1027_m05 C0027_003 {
  meta:
    description  = "encrypt data using Camellia (converted from capa rule)"
    namespace    = "data-manipulation/encryption/camellia"
    author       = "@_re_fox"
    scope        = "basic block"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
    mbc          = "Cryptography::Encrypt Data::Camellia [C0027.003]"
    hash         = "0761142efbda6c4b1e801223de723578"
    hash         = "112f9f0e8d349858a80dd8c14190e620"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/camellia/encrypt-data-using-camellia.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_aua     = { 00 70 70 70 00 82 82 82 00 2C 2C 2C 00 EC EC EC 00 B3 B3 B3 00 27 27 27 00 C0 C0 C0 00 E5 E5 E5 00 E4 E4 E4 00 85 85 85 00 57 57 57 00 35 35 35 00 EA EA EA 00 0C 0C 0C 00 AE AE AE 00 41 41 41 00 23 23 23 00 EF EF EF 00 6B 6B 6B 00 93 93 93 00 45 45 45 00 19 19 19 00 A5 A5 A5 00 21 21 21 00 ED ED ED 00 0E 0E 0E 00 4F 4F 4F 00 4E 4E 4E 00 1D 1D 1D 00 65 65 65 00 92 92 92 00 BD BD BD 00 86 86 86 00 B8 B8 B8 00 AF AF AF 00 8F 8F 8F 00 7C 7C 7C 00 EB EB EB 00 1F 1F 1F 00 CE CE CE 00 3E 3E 3E 00 30 30 30 00 DC DC }  // libgcrypt_sp1110
    $basic_aub     = { E0 E0 E0 00 05 05 05 00 58 58 58 00 D9 D9 D9 00 67 67 67 00 4E 4E 4E 00 81 81 81 00 CB CB CB 00 C9 C9 C9 00 0B 0B 0B 00 AE AE AE 00 6A 6A 6A 00 D5 D5 D5 00 18 18 18 00 5D 5D 5D 00 82 82 82 00 46 46 46 00 DF DF DF 00 D6 D6 D6 00 27 27 27 00 8A 8A 8A 00 32 32 32 00 4B 4B 4B 00 42 42 42 00 DB DB DB 00 1C 1C 1C 00 9E 9E 9E 00 9C 9C 9C 00 3A 3A 3A 00 CA CA CA 00 25 25 25 00 7B 7B 7B 00 0D 0D 0D 00 71 71 71 00 5F 5F 5F 00 1F 1F 1F 00 F8 F8 F8 00 D7 D7 D7 00 3E 3E 3E 00 9D 9D 9D 00 7C 7C 7C 00 60 60 60 00 B9 B9 B9 }  // libgcrypt_sp0222
    $basic_auc     = { 38 38 00 38 41 41 00 41 16 16 00 16 76 76 00 76 D9 D9 00 D9 93 93 00 93 60 60 00 60 F2 F2 00 F2 72 72 00 72 C2 C2 00 C2 AB AB 00 AB 9A 9A 00 9A 75 75 00 75 06 06 00 06 57 57 00 57 A0 A0 00 A0 91 91 00 91 F7 F7 00 F7 B5 B5 00 B5 C9 C9 00 C9 A2 A2 00 A2 8C 8C 00 8C D2 D2 00 D2 90 90 00 90 F6 F6 00 F6 07 07 00 07 A7 A7 00 A7 27 27 00 27 8E 8E 00 8E B2 B2 00 B2 49 49 00 49 DE DE 00 DE 43 43 00 43 5C 5C 00 5C D7 D7 00 D7 C7 C7 00 C7 3E 3E 00 3E F5 F5 00 F5 8F 8F 00 8F 67 67 00 67 1F 1F 00 1F 18 18 00 18 6E 6E 00 }  // libgcrypt_sp3033
    $basic_aud     = { 70 00 70 70 2C 00 2C 2C B3 00 B3 B3 C0 00 C0 C0 E4 00 E4 E4 57 00 57 57 EA 00 EA EA AE 00 AE AE 23 00 23 23 6B 00 6B 6B 45 00 45 45 A5 00 A5 A5 ED 00 ED ED 4F 00 4F 4F 1D 00 1D 1D 92 00 92 92 86 00 86 86 AF 00 AF AF 7C 00 7C 7C 1F 00 1F 1F 3E 00 3E 3E DC 00 DC DC 5E 00 5E 5E 0B 00 0B 0B A6 00 A6 A6 39 00 39 39 D5 00 D5 D5 5D 00 5D 5D D9 00 D9 D9 5A 00 5A 5A 51 00 51 51 6C 00 6C 6C 8B 00 8B 8B 9A 00 9A 9A FB 00 FB FB B0 00 B0 B0 74 00 74 74 2B 00 2B 2B F0 00 F0 F0 84 00 84 84 DF 00 DF DF CB 00 CB CB 34 00 34 }  // libgcrypt_sp4404
    $basic_aue     = { 70 82 2C EC B3 27 C0 E5 E4 85 57 35 EA 0C AE 41 23 EF 6B 93 45 19 A5 21 ED 0E 4F 4E 1D 65 92 BD 86 B8 AF 8F 7C EB 1F CE 3E 30 DC 5F 5E C5 0B 1A A6 E1 39 CA D5 47 5D 3D D9 01 5A D6 51 56 6C 4D 8B 0D 9A 66 FB CC B0 2D 74 12 2B 20 F0 B1 84 99 DF 4C CB C2 34 7E 76 05 6D B7 A9 31 D1 17 04 D7 14 58 3A 61 DE 1B 11 1C 32 0F 9C 16 53 18 F2 22 FE 44 CF B2 C3 B5 7A 91 24 08 E8 A8 60 FC 69 50 AA D0 A0 7D A1 89 62 97 54 5B 1E 95 E0 FF 64 D2 10 C4 00 48 A3 F7 75 DB 8A 03 E6 DA 09 3F DD 94 87 5C 83 02 CD 4A 90 33 73 67 F6 F3 9D 7F BF E2 52 9B D8 26 C8 37 C6 3B 81 96 6F 4B 13 BE 63 2E E9 79 A7 8C 9F 6E BC 8E 29 F5 F9 B6 2F FD B4 59 78 98 06 6A E7 46 71 BA D4 25 AB 42 88 A2 8D FA 72 07 B9 55 F8 EE AC 0A 36 49 2A 68 3C 38 F1 A4 40 28 D3 7B BB C9 43 C1 15 E3 AD F4 77 C7 80 9E }  // calccrypto_sbox
    $num_auf       = { 8B 90 CC 3B }  // CAMELLIA_SIGMA1R
    $num_aug       = { 7F 66 9E A0 }  // CAMELLIA_SIGMA1L
    $num_auh       = { B2 73 AA 4C }  // CAMELLIA_SIGMA2R
    $num_aui       = { 58 E8 7A B6 }  // CAMELLIA_SIGMA2L
    $num_auj       = { 2F 37 EF C6 }  // CAMELLIA_SIGMA3L
    $num_auk       = { BE 82 4F E9 }  // CAMELLIA_SIGMA3R
    $num_aul       = { A5 53 FF 54 }  // CAMELLIA_SIGMA4L
    $num_aum       = { 1C 6F D3 F1 }  // CAMELLIA_SIGMA4R
    $num_aun       = { FA 27 E5 10 }  // CAMELLIA_SIGMA5L
    $num_auo       = { 1D 2D 68 DE }  // CAMELLIA_SIGMA5R
    $num_aup       = { C2 88 56 B0 }  // CAMELLIA_SIGMA6L
    $num_auq       = { FD C1 E6 B3 }  // CAMELLIA_SIGMA6R
    $basic_aur     = { 8B 90 CC 3B 7F 66 9E A0 }  // sigma1
    $basic_aus     = { B2 73 AA 4C 58 E8 7A B6 }  // sigma2
    $basic_aut     = { BE 82 4F E9 2F 37 EF C6 }  // sigma3
    $basic_auu     = { 1C 6F D3 F1 A5 53 FF 54 }  // sigma4
    $basic_auv     = { 1D 2D 68 DE FA 27 E5 10 }  // sigma5
    $basic_auw     = { FD C1 E6 B3 C2 88 56 B0 }  // sigma6
    $basic_re_aux  = /A09E667F3BCC908B/ nocase ascii wide  // sigma1_str
    $basic_str_auy = "/B67AE8584CAA73B" ascii wide  // sigma2_str
    $basic_re_auz  = /C6EF372FE94F82BE/ nocase ascii wide  // sigma3_str
    $basic_re_ava  = /54FF53A5F1D36F1C/ nocase ascii wide  // sigma4_str
    $basic_re_avb  = /10E527FADE682D1D/ nocase ascii wide  // sigma5_str
    $basic_re_avc  = /B05688C2B3E6C1FD/ nocase ascii wide  // sigma6_str

  condition:
    capa_pe_file and
    (
      $basic_aua
      or $basic_aub
      or $basic_auc
      or $basic_aud
      or $basic_aue
      or (
        (
          $num_auf
          and $num_aug
          and $num_auh
          and $num_aui
          and $num_auj
          and $num_auk
          and $num_aul
          and $num_aum
          and $num_aun
          and $num_auo
          and $num_aup
          and $num_auq
        )
        or (
          $basic_aur
          and $basic_aus
          and $basic_aut
          and $basic_auu
          and $basic_auv
          and $basic_auw
        )
        or (
          $basic_re_aux
          and $basic_str_auy
          and $basic_re_auz
          and $basic_re_ava
          and $basic_re_avb
          and $basic_re_avc
        )
      )
    )
}

rule capa_encrypt_data_using_RC6: CAPA DATA_MANIPULATION ENCRYPTION RC6 FUNCTION T1027 E1027_m05 C0027_010 {
  meta:
    description  = "encrypt data using RC6 (converted from capa rule)"
    namespace    = "data-manipulation/encryption/rc6"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
    mbc          = "Cryptography::Encrypt Data::RC6 [C0027.010]"
    hash         = "D87BA0BFCE1CDB17FD243B8B1D247E88"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/rc6/encrypt-data-using-rc6.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $num_avd = { 63 51 E1 B7 }  // RC5 and RC6 (more common)
    $num_ave = { B9 79 37 9E }  // encrypt via add an unsigned
    $num_avf = { 47 86 C8 61 }  // encrypt via subtract an unsigned

  condition:
    capa_pe_file and
    (
      $num_avd
      and (
        $num_ave
        or $num_avf
      )
    )
}

rule capa_encrypt_data_using_twofish: CAPA DATA_MANIPULATION ENCRYPTION TWOFISH BASICBLOCK T1027 E1027_m05 C0027_005 {
  meta:
    description  = "encrypt data using twofish (converted from capa rule)"
    namespace    = "data-manipulation/encryption/twofish"
    author       = "@_re_fox"
    scope        = "basic block"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
    mbc          = "Cryptography::Encrypt Data::Twofish [C0027.005]"
    hash         = "0761142efbda6c4b1e801223de723578"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/twofish/encrypt-data-using-twofish.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_avg = { A9 67 B3 E8 04 FD A3 76 9A 92 80 78 E4 DD D1 38 0D C6 35 98 18 F7 EC 6C 43 75 37 26 FA 13 94 48 F2 D0 8B 30 84 54 DF 23 19 5B 3D 59 F3 AE A2 82 63 01 83 2E D9 51 9B 7C A6 EB A5 BE 16 0C E3 61 C0 8C 3A F5 73 2C 25 0B BB 4E 89 6B 53 6A B4 F1 E1 E6 BD 45 E2 F4 B6 66 CC 95 03 56 D4 1C 1E D7 FB C3 8E B5 E9 CF BF BA EA 77 39 AF 33 C9 62 71 81 79 09 AD 24 CD F9 D8 E5 C5 B9 4D 44 08 86 E7 A1 1D AA ED 06 70 B2 D2 41 7B A0 11 31 C2 27 90 20 F6 60 FF 96 5C B1 AB 9E 9C 52 1B 5F 93 0A EF 91 85 49 EE 2D 4F 8F 3B 47 87 6D }  // Q0
    $basic_avh = { 75 F3 C6 F4 DB 7B FB C8 4A D3 E6 6B 45 7D E8 4B D6 32 D8 FD 37 71 F1 E1 30 0F F8 1B 87 FA 06 3F 5E BA AE 5B 8A 00 BC 9D 6D C1 B1 0E 80 5D D2 D5 A0 84 07 14 B5 90 2C A3 B2 73 4C 54 92 74 36 51 38 B0 BD 5A FC 60 62 96 6C 42 F7 10 7C 28 27 8C 13 95 9C C7 24 46 3B 70 CA E3 85 CB 11 D0 93 B8 A6 83 20 FF 9F 77 C3 CC 03 6F 08 BF 40 E7 2B E2 79 0C AA 82 41 3A EA B9 E4 9A A4 97 7E DA 7A 17 66 94 A1 1D 3D F0 DE B3 0B 72 A7 1C EF D1 53 3E 8F 33 26 5F EC 76 2A 49 81 88 EE 21 C4 1A EB D9 C5 39 99 CD AD 31 8B 01 18 23 DD }  // Q1
    $basic_avi = { 75 32 BC BC F3 21 EC EC C6 43 20 20 F4 C9 B3 B3 DB 03 DA DA 7B 8B 02 02 FB 2B E2 E2 C8 FA 9E 9E 4A EC C9 C9 D3 09 D4 D4 E6 6B 18 18 6B 9F 1E 1E 45 0E 98 98 7D 38 B2 B2 E8 D2 A6 A6 4B B7 26 26 D6 57 3C 3C 32 8A 93 93 D8 EE 82 82 FD 98 52 52 37 D4 7B 7B 71 37 BB BB F1 97 5B 5B E1 83 47 47 30 3C 24 24 0F E2 51 51 F8 C6 BA BA 1B F3 4A 4A 87 48 BF BF FA 70 0D 0D 06 B3 B0 B0 3F DE 75 75 5E FD D2 D2 BA 20 7D 7D AE 31 66 66 5B A3 3A 3A 8A 1C 59 59 00 00 00 00 BC 93 CD CD 9D E0 1A 1A 6D 2C AE AE C1 AB 7F 7F B1 C7 2B }  // MDS1
    $basic_avj = { 39 39 D9 A9 17 17 90 67 9C 9C 71 B3 A6 A6 D2 E8 07 07 05 04 52 52 98 FD 80 80 65 A3 E4 E4 DF 76 45 45 08 9A 4B 4B 02 92 E0 E0 A0 80 5A 5A 66 78 AF AF DD E4 6A 6A B0 DD 63 63 BF D1 2A 2A 36 38 E6 E6 54 0D 20 20 43 C6 CC CC 62 35 F2 F2 BE 98 12 12 1E 18 EB EB 24 F7 A1 A1 D7 EC 41 41 77 6C 28 28 BD 43 BC BC 32 75 7B 7B D4 37 88 88 9B 26 0D 0D 70 FA 44 44 F9 13 FB FB B1 94 7E 7E 5A 48 03 03 7A F2 8C 8C E4 D0 B6 B6 47 8B 24 24 3C 30 E7 E7 A5 84 6B 6B 41 54 DD DD 06 DF 60 60 C5 23 FD FD 45 19 3A 3A A3 5B C2 C2 68 }  // MDS2
    $basic_avk = { 32 BC 75 BC 21 EC F3 EC 43 20 C6 20 C9 B3 F4 B3 03 DA DB DA 8B 02 7B 02 2B E2 FB E2 FA 9E C8 9E EC C9 4A C9 09 D4 D3 D4 6B 18 E6 18 9F 1E 6B 1E 0E 98 45 98 38 B2 7D B2 D2 A6 E8 A6 B7 26 4B 26 57 3C D6 3C 8A 93 32 93 EE 82 D8 82 98 52 FD 52 D4 7B 37 7B 37 BB 71 BB 97 5B F1 5B 83 47 E1 47 3C 24 30 24 E2 51 0F 51 C6 BA F8 BA F3 4A 1B 4A 48 BF 87 BF 70 0D FA 0D B3 B0 06 B0 DE 75 3F 75 FD D2 5E D2 20 7D BA 7D 31 66 AE 66 A3 3A 5B 3A 1C 59 8A 59 00 00 00 00 93 CD BC CD E0 1A 9D 1A 2C AE 6D AE AB 7F C1 7F C7 2B B1 }  // MDS3
    $basic_avl = { D9 A9 39 D9 90 67 17 90 71 B3 9C 71 D2 E8 A6 D2 05 04 07 05 98 FD 52 98 65 A3 80 65 DF 76 E4 DF 08 9A 45 08 02 92 4B 02 A0 80 E0 A0 66 78 5A 66 DD E4 AF DD B0 DD 6A B0 BF D1 63 BF 36 38 2A 36 54 0D E6 54 43 C6 20 43 62 35 CC 62 BE 98 F2 BE 1E 18 12 1E 24 F7 EB 24 D7 EC A1 D7 77 6C 41 77 BD 43 28 BD 32 75 BC 32 D4 37 7B D4 9B 26 88 9B 70 FA 0D 70 F9 13 44 F9 B1 94 FB B1 5A 48 7E 5A 7A F2 03 7A E4 D0 8C E4 47 8B B6 47 3C 30 24 3C A5 84 E7 A5 41 54 6B 41 06 DF DD 06 C5 23 60 C5 45 19 FD 45 A3 5B 3A A3 68 3D C2 }  // MDS4
    $basic_avm = { 01 02 04 08 10 20 40 80 4D 9A 79 F2 A9 1F 3E 7C F8 BD 37 6E DC F5 A7 03 06 0C 18 30 60 C0 CD D7 E3 8B 5B B6 21 42 84 45 8A 59 B2 29 52 A4 05 0A 14 28 50 A0 0D 1A 34 68 D0 ED 97 63 C6 C1 CF D3 EB 9B 7B F6 A1 0F 1E 3C 78 F0 AD 17 2E 5C B8 3D 7A F4 A5 07 0E 1C 38 70 E0 8D 57 AE 11 22 44 88 5D BA 39 72 E4 85 47 8E 51 A2 09 12 24 48 90 6D DA F9 BF 33 66 CC D5 E7 83 4B 96 61 C2 C9 DF F3 AB 1B 36 6C D8 FD B7 23 46 8C 55 AA 19 32 64 C8 DD F7 A3 0B 16 2C 58 B0 2D 5A B4 25 4A 94 65 CA D9 FF B3 2B 56 AC 15 2A 54 A8 1D }  // EXP_TO_POLY
    $basic_avn = { A9 75 67 F3 B3 C6 E8 F4 04 DB FD 7B A3 FB 76 C8 9A 4A 92 D3 80 E6 78 6B E4 45 DD 7D D1 E8 38 4B 0D D6 C6 32 35 D8 98 FD 18 37 F7 71 EC F1 6C E1 43 30 75 0F 37 F8 26 1B FA 87 13 FA 94 06 48 3F F2 5E D0 BA 8B AE 30 5B 84 8A 54 00 DF BC 23 9D 19 6D 5B C1 3D B1 59 0E F3 80 AE 5D A2 D2 82 D5 63 A0 01 84 83 07 2E 14 D9 B5 51 90 9B 2C 7C A3 A6 B2 EB 73 A5 4C BE 54 16 92 0C 74 E3 36 61 51 C0 38 8C B0 3A BD F5 5A 73 FC 2C 60 25 62 0B 96 BB 6C 4E 42 89 F7 6B 10 53 7C 6A 28 B4 27 F1 8C E1 13 E6 95 BD 9C 45 C7 E2 24 F4 }  // CALC_SB_TBL

  condition:
    capa_pe_file and
    (
      $basic_avg
      or $basic_avh
      or $basic_avi
      or $basic_avj
      or $basic_avk
      or $basic_avl
      or $basic_avm
      or $basic_avn
    )
}

rule capa_encrypt_data_using_AES_via__NET: CAPA DATA_MANIPULATION ENCRYPTION AES FILE T1027 E1027_m05 C0027_001 {
  meta:
    description  = "encrypt data using AES via .NET (converted from capa rule)"
    namespace    = "data-manipulation/encryption/aes"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
    mbc          = "Cryptography::Encrypt Data::AES [C0027.001]"
    hash         = "b9f5bd514485fb06da39beff051b9fdc"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/aes/encrypt-data-using-aes-via-net.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_awg = "RijndaelManaged" ascii wide
    $file_str_awh = "CryptoStream" ascii wide
    $file_str_awi = "System.Security.Cryptography" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_awg
      and $file_str_awh
      and $file_str_awi
    )
}

rule capa_encrypt_data_using_skipjack: CAPA DATA_MANIPULATION ENCRYPTION SKIPJACK BASICBLOCK T1027 E1027_m05 C0027_013 {
  meta:
    description  = "encrypt data using skipjack (converted from capa rule)"
    namespace    = "data-manipulation/encryption/skipjack"
    author       = "@_re_fox"
    scope        = "basic block"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
    mbc          = "Cryptography::Encrypt Data::Skipjack [C0027.013]"
    hash         = "94d3c854aadbcfde46b2f82801015c31"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/skipjack/encrypt-data-using-skipjack.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_awj = { A3 D7 09 83 F8 48 F6 F4 B3 21 15 78 99 B1 AF F9 E7 2D 4D 8A CE 4C CA 2E 52 95 D9 1E 4E 38 44 28 0A DF 02 A0 17 F1 60 68 12 B7 7A C3 E9 FA 3D 53 96 84 6B BA F2 63 9A 19 7C AE E5 F5 F7 16 6A A2 39 B6 7B 0F C1 93 81 1B EE B4 1A EA D0 91 2F B8 55 B9 DA 85 3F 41 BF E0 5A 58 80 5F 66 0B D8 90 35 D5 C0 A7 33 06 65 69 45 00 94 56 6D 98 9B 76 97 FC B2 C2 B0 FE DB 20 E1 EB D6 E4 DD 47 4A 1D 42 ED 9E 6E 49 3C CD 43 27 D2 07 D4 DE C7 67 18 89 CB 30 1F 8D C6 8F AA C8 74 DC C9 5D 5C 31 A4 70 88 61 2C 9F 0D 2B 87 50 82 54 64 26 7D 03 40 34 4B 1C 73 D1 C4 FD 3B CC FB 7F AB E6 3E 5B A5 AD 04 23 9C 14 51 22 F0 29 79 71 7E FF 8C 0E E2 0C EF BC 72 75 6F 37 A1 EC D3 8E 62 8B 86 10 E8 08 77 11 BE 92 4F 24 C5 32 36 9D CF F3 A6 BB AC 5E 6C A9 13 57 25 B5 E3 BD A8 3A 01 05 59 2A 46 }  // FTable

  condition:
    capa_pe_file and
    (
      $basic_awj
    )
}

rule capa_reference_public_RSA_key: CAPA DATA_MANIPULATION ENCRYPTION RSA FUNCTION C0028 {
  meta:
    description  = "reference public RSA key (converted from capa rule)"
    namespace    = "data-manipulation/encryption/rsa"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    mbc          = "Cryptography::Encryption Key [C0028]"
    hash         = "b7b5e1253710d8927cbe07d52d2d2e10"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/rsa/reference-public-rsa-key.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_awk = { 06 02 00 00 00 A4 00 00 52 53 41 31 }

  condition:
    capa_pe_file and
    (
      $func_awk
    )
}

rule capa_encrypt_data_using_vest: CAPA DATA_MANIPULATION ENCRYPTION VEST BASICBLOCK T1027 E1027_m05 C0027 {
  meta:
    description  = "encrypt data using vest (converted from capa rule)"
    namespace    = "data-manipulation/encryption/vest"
    author       = "@_re_fox"
    scope        = "basic block"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
    mbc          = "Cryptography::Encrypt Data [C0027]"
    hash         = "9a00ebe67d833edb70ed6dd0f4652592"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/vest/encrypt-data-using-vest.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_awl = { 07 56 D2 37 3A F7 0A 52 5D C6 2C 87 DA 05 C1 D7 F4 1F 8C 34 }  // vest_sbox
    $basic_awm = { 41 4B 1B DD 0D 65 72 EE 09 E7 A1 93 3F 0E 55 9C 63 89 3F B2 AB 5A 0E CB 2F 13 E3 9A C7 09 C5 8D C9 09 0D D7 59 1F A2 D6 CB B0 61 E5 39 44 F8 C5 8B C6 E5 B2 BD E3 82 D2 AB 04 DD D6 1F 94 CA EC 73 43 E7 94 5D 52 66 86 4F 4B 05 D4 AD 0F 66 A3 F9 15 9C C6 C9 3E 3A B8 9D 31 65 F8 C7 9A CE E0 6D BD 18 8D 63 F5 0A CD 11 B4 B5 EE 9B 28 9C A5 93 78 5B D1 D3 B1 2B 84 17 AB F4 85 EF 22 E1 D1 }  // rns_f
    $basic_awn = { 4F 70 46 DA E1 8D F6 41 59 E8 5D 26 1E CC 2F 89 26 6D 52 BA BC 11 6B A9 C6 47 E4 9C 1E B6 65 A2 B6 CD 90 47 1C DF F8 10 4B D2 7C C4 72 25 C6 97 25 5D C6 1D 4B 36 BC 38 36 33 F8 89 B4 4C 65 A7 96 CA 1B 63 C3 4B 6A 63 DC 85 4C 57 EE 2A 05 C7 0C E7 39 35 8A C1 BF 13 D9 52 51 3D 2E 41 F5 72 85 23 FE A1 AA 53 61 3B 25 5F 62 B4 36 EE 2A 51 AF 18 8E 9A C6 CF C4 07 4A 9B 25 9B 76 62 0E 3E 96 3A A7 64 23 6B B6 19 BC 2D 40 D7 36 3E E2 85 9A D1 22 9F BC 30 15 9F C2 5D F1 23 E6 3A 73 C0 A6 AD 71 B0 94 1C 9D B6 56 B6 2B }  // vest_f

  condition:
    capa_pe_file and
    (
      $basic_awl
      or $basic_awm
      or $basic_awn
    )
}

rule capa_encrypt_data_using_blowfish: CAPA DATA_MANIPULATION ENCRYPTION BLOWFISH BASICBLOCK T1027 E1027_m05 C0027_002 {
  meta:
    description  = "encrypt data using blowfish (converted from capa rule)"
    namespace    = "data-manipulation/encryption/blowfish"
    author       = "@_re_fox"
    scope        = "basic block"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
    mbc          = "Cryptography::Encrypt Data::Blowfish [C0027.002]"
    hash         = "0761142efbda6c4b1e801223de723578"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/blowfish/encrypt-data-using-blowfish.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $num_awp   = { 37 CE 39 3A }  // u32 ks3 sbox4
    $num_awq   = { 68 5A 3D E9 }  // u32 ks2 sbox3
    $num_awr   = { E9 70 7A 4B }  // u32 ks1 sbox2
    $num_aws   = { A6 0B 31 D1 }  // u32 ks0 sbox1
    $basic_awt = { 88 6A 3F 24 D3 08 A3 85 2E 8A 19 13 44 73 70 03 22 38 09 A4 D0 31 9F 29 98 FA 2E 08 89 6C 4E EC E6 21 28 45 77 13 D0 38 CF 66 54 BE 6C 0C E9 34 B7 29 AC C0 DD 50 7C C9 B5 D5 84 3F 17 09 47 B5 D9 D5 16 92 1B FB 79 89 }  // ps
    $basic_awu = { A6 0B 31 D1 AC B5 DF 98 DB 72 FD 2F B7 DF 1A D0 ED AF E1 B8 96 7E 26 6A 45 90 7C BA 99 7F 2C F1 47 99 A1 24 F7 6C 91 B3 E2 F2 01 08 16 FC 8E 85 D8 20 69 63 69 4E 57 71 A3 FE 58 A4 7E 3D 93 F4 8F 74 95 0D 58 B6 8E 72 58 CD 8B 71 EE 4A 15 82 1D A4 54 7B B5 59 5A C2 39 D5 30 9C 13 60 F2 2A 23 B0 D1 C5 F0 85 60 28 18 79 41 CA EF 38 DB B8 B0 DC 79 8E 0E 18 3A 60 8B 0E 9E 6C 3E 8A 1E B0 C1 77 15 D7 27 4B 31 BD DA 2F AF 78 60 5C 60 55 F3 25 55 E6 94 AB 55 AA 62 98 48 57 40 14 E8 63 6A 39 CA 55 B6 10 AB 2A 34 5C CC }  // ks0 sbox1
    $basic_awv = { E9 70 7A 4B 44 29 B3 B5 2E 09 75 DB 23 26 19 C4 B0 A6 6E AD 7D DF A7 49 B8 60 EE 9C 66 B2 ED 8F 71 8C AA EC FF 17 9A 69 6C 52 64 56 E1 9E B1 C2 A5 02 36 19 29 4C 09 75 40 13 59 A0 3E 3A 18 E4 9A 98 54 3F 65 9D 42 5B D6 E4 8F 6B D6 3F F7 99 07 9C D2 A1 F5 30 E8 EF E6 38 2D 4D C1 5D 25 F0 86 20 DD 4C 26 EB 70 84 C6 E9 82 63 5E CC 1E 02 3F 6B 68 09 C9 EF BA 3E 14 18 97 3C A1 70 6A 6B 84 35 7F 68 86 E2 A0 52 05 53 9C B7 37 07 50 AA 1C 84 07 3E 5C AE DE 7F EC 44 7D 8E B8 F2 16 57 37 DA 3A B0 0D 0C 50 F0 04 1F 1C }  // ks1 sbox2
    $basic_aww = { 68 5A 3D E9 F7 40 81 94 1C 26 4C F6 34 29 69 94 F7 20 15 41 F7 D4 02 76 2E 6B F4 BC 68 00 A2 D4 71 24 08 D4 6A F4 20 33 B7 D4 B7 43 AF 61 00 50 2E F6 39 1E 46 45 24 97 74 4F 21 14 40 88 8B BF 1D FC 95 4D AF 91 B5 96 D3 DD F4 70 45 2F A0 66 EC 09 BC BF 85 97 BD 03 D0 6D AC 7F 04 85 CB 31 B3 27 EB 96 41 39 FD 55 E6 47 25 DA 9A 0A CA AB 25 78 50 28 F4 29 04 53 DA 86 2C 0A FB 6D B6 E9 62 14 DC 68 00 69 48 D7 A4 C0 0E 68 EE 8D A1 27 A2 FE 3F 4F 8C AD 87 E8 06 E0 8C B5 B6 D6 F4 7A 7C 1E CE AA EC 5F 37 D3 99 A3 78 }  // ks2 sbox3
    $basic_awx = { 37 CE 39 3A CF F5 FA D3 37 77 C2 AB 1B 2D C5 5A 9E 67 B0 5C 42 37 A3 4F 40 27 82 D3 BE 9B BC 99 9D 8E 11 D5 15 73 0F BF 7E 1C 2D D6 7B C4 00 C7 6B 1B 8C B7 45 90 A1 21 BE B1 6E B2 B4 6E 36 6A 2F AB 48 57 79 6E 94 BC D2 76 A3 C6 C8 C2 49 65 EE F8 0F 53 7D DE 8D 46 1D 0A 73 D5 C6 4D D0 4C DB BB 39 29 50 46 BA A9 E8 26 95 AC 04 E3 5E BE F0 D5 FA A1 9A 51 2D 6A E2 8C EF 63 22 EE 86 9A B8 C2 89 C0 F6 2E 24 43 AA 03 1E A5 A4 D0 F2 9C BA 61 C0 83 4D 6A E9 9B 50 15 E5 8F D6 5B 64 BA F9 A2 26 28 E1 3A 3A A7 86 95 A9 }  // ks3 sbox4

  condition:
    capa_pe_file and
    (
      (
        $num_awp
        and $num_awq
        and $num_awr
        and $num_aws
      )
      or (
        $basic_awt
        or $basic_awu
        or $basic_awv
        or $basic_aww
        or $basic_awx
      )
    )
}

rule capa_compress_data_via_WinAPI: CAPA DATA_MANIPULATION COMPRESSION FUNCTION T1560_002 C0024 {
  meta:
    description  = "compress data via WinAPI (converted from capa rule)"
    namespace    = "data-manipulation/compression"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Collection::Archive Collected Data::Archive via Library [T1560.002]"
    mbc          = "Data::Compress Data [C0024]"
    hash         = "638dcc3d37b3a574044233c9637d7288"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/compression/compress-data-via-winapi.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_axj      = /\bRtlDecompressBuffer(A|W)?\b/ ascii wide
    $func_str_axk = "RtlDecompressBuffer" ascii wide
    $api_axl      = /\bRtlDecompressBufferEx(A|W)?\b/ ascii wide
    $func_str_axm = "RtlDecompressBufferEx" ascii wide
    $api_axn      = /\bRtlDecompressBufferEx2(A|W)?\b/ ascii wide
    $func_str_axo = "RtlDecompressBufferEx2" ascii wide
    $api_axp      = /\bRtlCompressBuffer(A|W)?\b/ ascii wide
    $func_str_axq = "RtlCompressBuffer" ascii wide
    $api_axr      = /\bRtlCompressBufferLZNT1(A|W)?\b/ ascii wide
    $func_str_axs = "RtlCompressBufferLZNT1" ascii wide

  condition:
    capa_pe_file and
    (
      $api_axj
      or $func_str_axk
      or $api_axl
      or $func_str_axm
      or $api_axn
      or $func_str_axo
      or $api_axp
      or $func_str_axq
      or $api_axr
      or $func_str_axs
    )
}

rule capa_schedule_task_via_command_line: CAPA PERSISTENCE SCHEDULED_TASKS FUNCTION T1053_005 {
  meta:
    description  = "schedule task via command line (converted from capa rule)"
    namespace    = "persistence/scheduled-tasks"
    author       = "0x534a@mailbox.org"
    scope        = "function"
    attack       = "Persistence::Scheduled Task/Job::Scheduled Task [T1053.005]"
    hash         = "79cde1aa711e321b4939805d27e160be"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/scheduled-tasks/schedule-task-via-command-line.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_azh = /schtasks/ nocase ascii wide
    $func_re_azi = /\/create / nocase ascii wide
    $func_re_azj = /Register-ScheduledTask / nocase ascii wide

  condition:
    capa_pe_file and
    (
      capa_create_process

      and (
        (
          $func_re_azh
          and $func_re_azi
        )
        or $func_re_azj
      )
    )
}

rule capa_persist_via_Active_Setup_registry_key: CAPA PERSISTENCE REGISTRY FUNCTION T1547_014 {
  meta:
    description  = "persist via Active Setup registry key (converted from capa rule)"
    namespace    = "persistence/registry"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Persistence::Boot or Logon Autostart Execution::Active Setup [T1547.014]"
    hash         = "c335a9d41185a32ad918c5389ee54235"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/persist-via-active-setup-registry-key.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $num_azm      = { 02 00 00 80 }  // HKEY_LOCAL_MACHINE
    $func_re_azn  = /Software\\Microsoft\\Active Setup\\Installed Components/ nocase ascii wide
    $func_str_azo = "StubPath" ascii wide

  condition:
    capa_pe_file and
    (
      (
        capa_set_registry_value

        or $num_azm
      )
      and $func_re_azn
      and $func_str_azo
    )
}

rule capa_persist_via_GinaDLL_registry_key: CAPA PERSISTENCE REGISTRY GINADLL FUNCTION T1546 {
  meta:
    description  = "persist via GinaDLL registry key (converted from capa rule)"
    namespace    = "persistence/registry/ginadll"
    author       = "michael.hunhoff@fireye.com"
    scope        = "function"
    attack       = "Persistence::Event Triggered Execution [T1546]"
    hash         = "Practical Malware Analysis Lab 11-01.exe_:0x401000"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/ginadll/persist-via-ginadll-registry-key.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $num_azp     = { 02 00 00 80 }  // HKEY_LOCAL_MACHINE
    $func_re_azq = /SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon/ nocase ascii wide
    $func_re_azr = /GinaDLL/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      (
        capa_set_registry_value

        or $num_azp
      )
      and $func_re_azq
      and $func_re_azr
    )
}

rule capa_persist_via_AppInit_DLLs_registry_key: CAPA PERSISTENCE REGISTRY APPINITDLLS FUNCTION T1546_010 {
  meta:
    description  = "persist via AppInit_DLLs registry key (converted from capa rule)"
    namespace    = "persistence/registry/appinitdlls"
    author       = "michael.hunhoff@fireye.com"
    scope        = "function"
    attack       = "Persistence::Event Triggered Execution::AppInit DLLs [T1546.010]"
    hash         = "Practical Malware Analysis Lab 11-02.dll_:0x1000158b"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/appinitdlls/persist-via-appinit_dlls-registry-key.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $num_azs     = { 02 00 00 80 }  // HKEY_LOCAL_MACHINE
    $func_re_azt = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows/ nocase ascii wide
    $func_re_azu = /Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows/ nocase ascii wide
    $func_re_azv = /AppInit_DLLs/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      (
        capa_set_registry_value

        or $num_azs
      )
      and (
        $func_re_azt
        or $func_re_azu
      )
      and $func_re_azv
    )
}

rule capa_persist_via_Run_registry_key: CAPA PERSISTENCE REGISTRY RUN FUNCTION T1547_001 {
  meta:
    description  = "persist via Run registry key (converted from capa rule)"
    namespace    = "persistence/registry/run"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]"
    hash         = "Practical Malware Analysis Lab 06-03.exe_:0x401130"
    hash         = "b87e9dd18a5533a09d3e48a7a1efbcf6"
    hash         = "9ff8e68343cc29c1036650fc153e69f7"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/run/persist-via-run-registry-key.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $num_azx     = { 01 00 00 80 }  // HKEY_CURRENT_USER
    $num_azy     = { 02 00 00 80 }  // HKEY_LOCAL_MACHINE
    $func_re_azz = /Software\\Microsoft\\Windows\\CurrentVersion/ nocase ascii wide
    $func_re_baa = /Run/ nocase ascii wide
    $func_re_bab = /Explorer\\Shell Folders/ nocase ascii wide
    $func_re_bac = /User Shell Folders/ nocase ascii wide
    $func_re_bad = /RunServices/ nocase ascii wide
    $func_re_bae = /Policies\\Explorer\\Run/ nocase ascii wide
    $func_re_baf = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load/ nocase ascii wide
    $func_re_bag = /System\\CurrentControlSet\\Control\\Session Manager\\BootExecute/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      (
        capa_set_registry_value

        or $num_azx
        or $num_azy
      )
      and (
        (
          $func_re_azz
          and (
            $func_re_baa
            or $func_re_bab
            or $func_re_bac
            or $func_re_bad
            or $func_re_bae
          )
        )
        or $func_re_baf
        or $func_re_bag
      )
    )
}

rule capa_persist_via_Winlogon_Helper_DLL_registry_key: CAPA PERSISTENCE REGISTRY WINLOGON_HELPER FUNCTION T1547_004 {
  meta:
    description  = "persist via Winlogon Helper DLL registry key (converted from capa rule)"
    namespace    = "persistence/registry/winlogon-helper"
    author       = "0x534a@mailbox.org"
    scope        = "function"
    attack       = "Persistence::Boot or Logon Autostart Execution::Winlogon Helper DLL [T1547.004]"
    hash         = "9ff8e68343cc29c1036650fc153e69f7"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/registry/winlogon-helper/persist-via-winlogon-helper-dll-registry-key.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $num_bah     = { 01 00 00 80 }  // HKEY_CURRENT_USER
    $num_bai     = { 02 00 00 80 }  // HKEY_LOCAL_MACHINE
    $func_re_baj = /Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon/ nocase ascii wide
    $func_re_bak = /Notify/ nocase ascii wide
    $func_re_bal = /Userinit/ nocase ascii wide
    $func_re_bam = /Shell/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      (
        capa_set_registry_value

        or $num_bah
        or $num_bai
      )
      and $func_re_baj
      and (
        $func_re_bak
        or $func_re_bal
        or $func_re_bam
      )
    )
}

rule capa_reference_Quad9_DNS_server: CAPA COMMUNICATION DNS FUNCTION {
  meta:
    description  = "reference Quad9 DNS server (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-quad9-dns-server.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_baq = "9.9.9.9" ascii wide
    $func_str_bar = "149.112.112.112" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_baq
      or $func_str_bar
    )
}

rule capa_run_PowerShell_expression: CAPA LOAD_CODE POWERSHELL FUNCTION T1059_001 {
  meta:
    description  = "run PowerShell expression (converted from capa rule)"
    namespace    = "load-code/powershell/"
    author       = "anamaria.martinezgom@fireeye.com"
    scope        = "function"
    attack       = "Execution::Command and Scripting Interpreter::PowerShell [T1059.001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/run-powershell-expression.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bas = / iex\(/ nocase ascii wide
    $func_re_bat = / iex / nocase ascii wide
    $func_re_bau = /Invoke-Expression/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_bas
        or $func_re_bat
        or $func_re_bau
      )
    )
}

rule capa_encrypt_data_using_Salsa20_or_ChaCha: CAPA DATA_MANIPULATION ENCRYPTION SALSA20 FUNCTION T1027 {
  meta:
    description  = "encrypt data using Salsa20 or ChaCha (converted from capa rule)"
    namespace    = "data-manipulation/encryption/salsa20"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/encrypt-data-using-salsa20-or-chacha.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    // part of key setup
    $func_str_baz = "expand 32-byte k = sigma" ascii wide
    $func_str_bba = "expand 16-byte k = tau" ascii wide
    $func_str_bbb = "expand 32-byte kexpand 16-byte k" ascii wide
    $func_str_bbc = "expa" ascii wide
    $func_str_bbd = "nd 3" ascii wide
    $func_str_bbe = "2-by" ascii wide
    $func_str_bbf = "te k" ascii wide
    $num_bbg      = "expa"  // "apxe"
    $num_bbh      = "nd 3"  // "3 dn"
    $num_bbi      = "2-by"  // "yb-2"
    $num_bbj      = "te k"  // "k et"

  condition:
    capa_pe_file and
    (
      $func_str_baz
      or $func_str_bba
      or $func_str_bbb
      or (
        $func_str_bbc
        and $func_str_bbd
        and $func_str_bbe
        and $func_str_bbf
      )
      or (
        $num_bbg
        and $num_bbh
        and $num_bbi
        and $num_bbj
      )
    )
}

rule capa_reference_Verisign_DNS_server: CAPA COMMUNICATION DNS FUNCTION {
  meta:
    description  = "reference Verisign DNS server (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-verisign-dns-server.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bbm = "64.6.64.6" ascii wide
    $func_str_bbn = "64.6.65.6" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bbm
      or $func_str_bbn
    )
}

rule capa_packaged_as_a_NSIS_installer: CAPA EXECUTABLE INSTALLER NSIS FILE {
  meta:
    description  = "packaged as a NSIS installer (converted from capa rule)"
    namespace    = "executable/installer/nsis"
    author       = "moritz.raabe@fireeye.com"
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-nsis-installer.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_bbo = /http:\/\/nsis\.sf\.net/ ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_bbo
    )
}

rule capa_reference_AliDNS_DNS_server: CAPA COMMUNICATION DNS FUNCTION {
  meta:
    description  = "reference AliDNS DNS server (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-alidns-dns-server.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bbp = "223.5.5.5" ascii wide
    $func_str_bbq = "223.6.6.6" ascii wide
    $func_str_bbr = "2400:3200::1" ascii wide
    $func_str_bbs = "2400:3200:baba::1" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bbp
      or $func_str_bbq
      or $func_str_bbr
      or $func_str_bbs
    )
}

rule capa_get_proxy: CAPA HOST_INTERACTION NETWORK PROXY FUNCTION T1016 {
  meta:
    description  = "get proxy (converted from capa rule)"
    namespace    = "host-interaction/network/proxy"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Discovery::System Network Configuration Discovery [T1016]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/get-proxy.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bcf = "ProxyServer" ascii wide

  condition:
    capa_pe_file and
    (
      capa_create_or_open_registry_key

      and $func_str_bcf
    )
}

rule capa_reference_DNS_over_HTTPS_endpoints: CAPA COMMUNICATION DNS FILE {
  meta:
    description  = "reference DNS over HTTPS endpoints (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "markus.neis@swisscom.com / @markus_neis"
    scope        = "file"
    hash         = "749e7becf00fccc6dff324a83976dc0d"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-dns-over-https-endpoints.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_bcg = /https:\/\/doh.seby.io:8443\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bch = /https:\/\/family.cloudflare-dns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bci = /https:\/\/free.bravedns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcj = /https:\/\/doh.familyshield.opendns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bck = /https:\/\/doh-de.blahdns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcl = /https:\/\/adblock.mydns.network\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcm = /https:\/\/bravedns.com\/configure.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcn = /https:\/\/cloudflare-dns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bco = /https:\/\/commons.host.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcp = /https:\/\/dns.aa.net.uk\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcq = /https:\/\/dns.alidns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcr = /https:\/\/dns-asia.wugui.zone\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcs = /https:\/\/dns.containerpi.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bct = /https:\/\/dns.containerpi.com\/doh\/family-filter\/.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcu = /https:\/\/dns.containerpi.com\/doh\/secure-filter\/.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcv = /https:\/\/dns.digitale-gesellschaft.ch\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcw = /https:\/\/dns.dnshome.de\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcx = /https:\/\/dns.dns-over-https.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcy = /https:\/\/dns.dnsoverhttps.net\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bcz = /https:\/\/dns.flatuslifir.is\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bda = /https:\/\/dnsforge.de\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdb = /https:\/\/dns.google\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdc = /https:\/\/dns.nextdns.io\/<config_id>.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdd = /https:\/\/dns.rubyfish.cn\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bde = /https:\/\/dns.switch.ch\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdf = /https:\/\/dns.twnic.tw\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdg = /https:\/\/dns.wugui.zone\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdh = /https:\/\/doh-2.seby.io\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdi = /https:\/\/doh.42l.fr\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdj = /https:\/\/doh.applied-privacy.net\/query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdk = /https:\/\/doh.armadillodns.net\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdl = /https:\/\/doh.captnemo.in\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdm = /https:\/\/doh.centraleu.pi-dns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdn = /https:\/\/doh.cleanbrowsing.org\/doh\/family-filter\/.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdo = /https:\/\/doh.crypto.sx\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdp = /https:\/\/doh.dnslify.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdq = /https:\/\/doh.dns.sb\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdr = /https:\/\/dohdot.coxlab.net\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bds = /https:\/\/doh.eastas.pi-dns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdt = /https:\/\/doh.eastau.pi-dns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdu = /https:\/\/doh.eastus.pi-dns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdv = /https:\/\/doh.ffmuc.net\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdw = /https:\/\/doh.libredns.gr\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdx = /https:\/\/doh.li\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdy = /https:\/\/doh.northeu.pi-dns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bdz = /https:\/\/doh.pi-dns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bea = /https:\/\/doh.powerdns.org.\\\{,1000\\\}/ nocase ascii wide
    $file_re_beb = /https:\/\/doh.tiarap.org\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bec = /https:\/\/doh.tiar.app\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bed = /https:\/\/doh.westus.pi-dns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bee = /https:\/\/doh.xfinity.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bef = /https:\/\/example.doh.blockerdns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_beg = /https:\/\/fi.doh.dns.snopyta.org\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_beh = /https:\/\/ibksturm.synology.me\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bei = /https:\/\/ibuki.cgnat.net\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bej = /https:\/\/jcdns.fun\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bek = /https:\/\/jp.tiarap.org\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bel = /https:\/\/jp.tiar.app\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bem = /https:\/\/odvr.nic.cz\/doh.\\\{,1000\\\}/ nocase ascii wide
    $file_re_ben = /https:\/\/ordns.he.net\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_beo = /https:\/\/rdns.faelix.net\/.\\\{,1000\\\}/ nocase ascii wide
    $file_re_bep = /https:\/\/resolver-eu.lelux.fi\/dns-query.\\\{,1000\\\}/ nocase ascii wide
    $file_re_beq = /https:\/\/doh-jp.blahdns.com\/dns-query.\\\{,1000\\\}/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_bcg
      or $file_re_bch
      or $file_re_bci
      or $file_re_bcj
      or $file_re_bck
      or $file_re_bcl
      or $file_re_bcm
      or $file_re_bcn
      or $file_re_bco
      or $file_re_bcp
      or $file_re_bcq
      or $file_re_bcr
      or $file_re_bcs
      or $file_re_bct
      or $file_re_bcu
      or $file_re_bcv
      or $file_re_bcw
      or $file_re_bcx
      or $file_re_bcy
      or $file_re_bcz
      or $file_re_bda
      or $file_re_bdb
      or $file_re_bdc
      or $file_re_bdd
      or $file_re_bde
      or $file_re_bdf
      or $file_re_bdg
      or $file_re_bdh
      or $file_re_bdi
      or $file_re_bdj
      or $file_re_bdk
      or $file_re_bdl
      or $file_re_bdm
      or $file_re_bdn
      or $file_re_bdo
      or $file_re_bdp
      or $file_re_bdq
      or $file_re_bdr
      or $file_re_bds
      or $file_re_bdt
      or $file_re_bdu
      or $file_re_bdv
      or $file_re_bdw
      or $file_re_bdx
      or $file_re_bdy
      or $file_re_bdz
      or $file_re_bea
      or $file_re_beb
      or $file_re_bec
      or $file_re_bed
      or $file_re_bee
      or $file_re_bef
      or $file_re_beg
      or $file_re_beh
      or $file_re_bei
      or $file_re_bej
      or $file_re_bek
      or $file_re_bel
      or $file_re_bem
      or $file_re_ben
      or $file_re_beo
      or $file_re_bep
      or $file_re_beq
    )
}

rule capa_packed_with_Pepack: CAPA ANTI_ANALYSIS PACKER PEPACK FILE T1027_002 F0001 {
  meta:
    description  = "packed with Pepack (converted from capa rule)"
    namespace    = "anti-analysis/packer/pepack"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-pepack.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bfi in pe.sections: (bfi.name == "PEPACK!!")
    )
}

rule capa_reference_Google_Public_DNS_server: CAPA COMMUNICATION DNS FUNCTION {
  meta:
    description  = "reference Google Public DNS server (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-google-public-dns-server.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bfn = "8.8.8.8" ascii wide
    $func_str_bfo = "8.8.4.4" ascii wide
    $func_str_bfp = "2001:4860:4860::8888" ascii wide
    $func_str_bfq = "2001:4860:4860::8844" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bfn
      or $func_str_bfo
      or $func_str_bfp
      or $func_str_bfq
    )
}

rule capa_linked_against_C___regex_library: CAPA LINKING STATIC CPPREGEX FILE {
  meta:
    description  = "linked against C++ regex library (converted from capa rule)"
    namespace    = "linking/static/cppregex"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-c-regex-library.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bfr = "regex_error(error_syntax)" ascii wide  // C++ STL regex library
    $file_str_bfs = "regex_error(error_collate): The expression contained an invalid collating element name." ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bfr
      or $file_str_bfs
    )
}

rule capa_packed_with_MEW: CAPA ANTI_ANALYSIS PACKER MEW FILE T1027_002 F0001 {
  meta:
    description  = "packed with MEW (converted from capa rule)"
    namespace    = "anti-analysis/packer/mew"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-mew.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bfx in pe.sections: (bfx.name == "MEW")
    )
}

rule capa_reference_114DNS_DNS_server: CAPA COMMUNICATION DNS FUNCTION {
  meta:
    description  = "reference 114DNS DNS server (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-114dns-dns-server.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bfy = "114.114.114.114" ascii wide
    $func_str_bfz = "114.114.115.115" ascii wide
    $func_str_bga = "114.114.114.119" ascii wide
    $func_str_bgb = "114.114.115.119" ascii wide
    $func_str_bgc = "114.114.114.110" ascii wide
    $func_str_bgd = "114.114.115.110" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bfy
      or $func_str_bfz
      or $func_str_bga
      or $func_str_bgb
      or $func_str_bgc
      or $func_str_bgd
    )
}

rule capa_migrate_process_to_active_window_station: CAPA HOST_INTERACTION GUI WINDOW_STATION FUNCTION {
  meta:
    description  = "migrate process to active window station (converted from capa rule)"
    namespace    = "host-interaction/gui/window-station"
    author       = "william.ballenthin@fireeye.com"
    description  = "set process to the active window station so it can receive GUI events. commonly seen in keyloggers."
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/migrate-process-to-active-window-station.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_bgf      = /\bOpenWindowStation(A|W)?\b/ ascii wide
    $func_str_bgg = "winsta0" ascii wide
    $func_str_bgh = "WinSta0" ascii wide
    $api_bgi      = /\bSetProcessWindowStation(A|W)?\b/ ascii wide
    $api_bgj      = /\bOpenInputDesktop(A|W)?\b/ ascii wide
    $api_bgk      = /\bSetThreadDesktop(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      $api_bgf
      and (
        $func_str_bgg
        or $func_str_bgh
      )
      and $api_bgi
      and $api_bgj
      and $api_bgk
    )
}

rule capa_packed_with_Epack: CAPA ANTI_ANALYSIS PACKER EPACK FILE T1027_002 F0001 {
  meta:
    description  = "packed with Epack (converted from capa rule)"
    namespace    = "anti-analysis/packer/epack"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-epack.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bgl in pe.sections: (bgl.name == "!Epack")
    )
}

rule capa_packaged_as_a_Pintool: CAPA EXECUTABLE PINTOOL FILE {
  meta:
    description  = "packaged as a Pintool (converted from capa rule)"
    namespace    = "executable/pintool"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-pintool.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bgm in pe.sections: (bgm.name == ".charmve")
      or for any bgn in pe.sections: (bgn.name == ".pinclie")
    )
}

rule capa_rebuilt_by_ImpRec: CAPA EXECUTABLE IMPREC FILE {
  meta:
    description  = "rebuilt by ImpRec (converted from capa rule)"
    namespace    = "executable/imprec"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/rebuilt-by-imprec.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bgp in pe.sections: (bgp.name == ".mackt")
    )
}

rule capa_reference_Comodo_Secure_DNS_server: CAPA COMMUNICATION DNS FUNCTION {
  meta:
    description  = "reference Comodo Secure DNS server (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-comodo-secure-dns-server.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bgq = "8.26.56.26" ascii wide
    $func_str_bgr = "8.20.247.20" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bgq
      or $func_str_bgr
    )
}

rule capa_reference_L3_DNS_server: CAPA COMMUNICATION DNS FUNCTION {
  meta:
    description  = "reference L3 DNS server (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-l3-dns-server.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bgt = "4.2.2.1" ascii wide
    $func_str_bgu = "4.2.2.2" ascii wide
    $func_str_bgv = "4.2.2.3" ascii wide
    $func_str_bgw = "4.2.2.4" ascii wide
    $func_str_bgx = "4.2.2.5" ascii wide
    $func_str_bgy = "4.2.2.6" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bgt
      or $func_str_bgu
      or $func_str_bgv
      or $func_str_bgw
      or $func_str_bgx
      or $func_str_bgy
    )
}

rule capa_packaged_as_a_Wise_installer: CAPA EXECUTABLE INSTALLER WISEINSTALL FILE {
  meta:
    description  = "packaged as a Wise installer (converted from capa rule)"
    namespace    = "executable/installer/wiseinstall"
    author       = "moritz.raabe@fireeye.com"
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-a-wise-installer.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bgz = "WiseMain" ascii wide
    $file_re_bha  = /Wise Installation Wizard/ ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bgz
      or $file_re_bha
    )
}

rule capa_acquire_debug_privileges: CAPA HOST_INTERACTION PROCESS MODIFY BASICBLOCK T1134 {
  meta:
    description  = "acquire debug privileges (converted from capa rule)"
    namespace    = "host-interaction/process/modify"
    author       = "william.ballenthin@fireeye.com"
    scope        = "basic block"
    attack       = "Privilege Escalation::Access Token Manipulation [T1134]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/acquire-debug-privileges.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_str_bhe = "SeDebugPrivilege" ascii wide

  condition:
    capa_pe_file and
    (
      $basic_str_bhe
    )
}

rule capa_empty_the_recycle_bin: CAPA HOST_INTERACTION RECYCLE_BIN FUNCTION {
  meta:
    description  = "empty the recycle bin (converted from capa rule)"
    namespace    = "host-interaction/recycle-bin"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/empty-the-recycle-bin.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_bhf = /\bSHEmptyRecycleBin(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      $api_bhf
    )
}

rule capa_packed_with_enigma: CAPA ANTI_ANALYSIS PACKER ENIGMA FILE T1027_002 F0001 {
  meta:
    description  = "packed with enigma (converted from capa rule)"
    namespace    = "anti-analysis/packer/enigma"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-enigma.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bhg in pe.sections: (bhg.name == ".enigma1")
      or for any bhh in pe.sections: (bhh.name == ".enigma2")
    )
}

rule capa_packed_with_StarForce: CAPA ANTI_ANALYSIS PACKER STARFORCE FILE T1027_002 F0001 {
  meta:
    description  = "packed with StarForce (converted from capa rule)"
    namespace    = "anti-analysis/packer/starforce"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-starforce.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bhi in pe.sections: (bhi.name == ".sforce3")
    )
}

rule capa_packed_with_ProCrypt: CAPA ANTI_ANALYSIS PACKER PROCRYPT FILE T1027_002 F0001 {
  meta:
    description  = "packed with ProCrypt (converted from capa rule)"
    namespace    = "anti-analysis/packer/procrypt"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-procrypt.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bhj in pe.sections: (bhj.name == "ProCrypt")
    )
}

rule capa_packed_with_WWPACK: CAPA ANTI_ANALYSIS PACKER WWPACK FILE T1027_002 F0001 {
  meta:
    description  = "packed with WWPACK (converted from capa rule)"
    namespace    = "anti-analysis/packer/wwpack"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-wwpack.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bhk in pe.sections: (bhk.name == ".WWPACK")
      or for any bhl in pe.sections: (bhl.name == ".WWP32")
    )
}

rule capa_reference_Cloudflare_DNS_server: CAPA COMMUNICATION DNS FUNCTION {
  meta:
    description  = "reference Cloudflare DNS server (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-cloudflare-dns-server.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bhm = "1.1.1.1" ascii wide
    $func_str_bhn = "1.0.0.1" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bhm
      or $func_str_bhn
    )
}

rule capa_check_license_value: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FUNCTION T1497_001 {
  meta:
    description  = "check license value (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/check-license-value.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_bho      = /\bNtQueryLicenseValue(A|W)?\b/ ascii wide
    $func_str_bhp = "Kernel-VMDetection-Private" ascii wide

  condition:
    capa_pe_file and
    (
      $api_bho
      and $func_str_bhp
    )
}

rule capa_bypass_UAC_via_ICMLuaUtil: CAPA HOST_INTERACTION UAC BYPASS FUNCTION T1548_002 {
  meta:
    description  = "bypass UAC via ICMLuaUtil (converted from capa rule)"
    namespace    = "host-interaction/uac/bypass"
    author       = "anamaria.martinezgom@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/bypass-uac-via-icmluautil.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bhq = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide  // T_CLSID_CMSTPLUA
    $func_bhr     = { F9 C7 5F 3E 51 9A 67 43 90 63 A1 20 24 4F BE C7 }  // T_CLSID_CMSTPLUA

  condition:
    capa_pe_file and
    (
      (
        $func_str_bhq
        or $func_bhr
      )
    )
}

rule capa_reference_screen_saver_executable: CAPA PERSISTENCE SCREENSAVER FUNCTION T1546_002 {
  meta:
    description  = "reference screen saver executable (converted from capa rule)"
    namespace    = "persistence/screensaver"
    author       = "michael.hunhoff@fireeye.com"
    description  = "SCRNSAVE.EXE registry value specifies the name of the screen saver executable file"
    scope        = "function"
    attack       = "Persistence::Event Triggered Execution::Screensaver [T1546.002]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-screen-saver-executable.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bhs = "SCRNSAVE.EXE" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bhs
    )
}

rule capa_reference_kornet_DNS_server: CAPA COMMUNICATION DNS FUNCTION {
  meta:
    description  = "reference kornet DNS server (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-kornet-dns-server.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bht = "168.126.63.1" ascii wide  // kns.kornet.net

  condition:
    capa_pe_file and
    (
      $func_str_bht
    )
}

rule capa_packed_with_Themida: CAPA ANTI_ANALYSIS PACKER THEMIDA FILE T1027_002 F0001 {
  meta:
    description  = "packed with Themida (converted from capa rule)"
    namespace    = "anti-analysis/packer/themida"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-themida.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bhu in pe.sections: (bhu.name == "Themida")
      or for any bhv in pe.sections: (bhv.name == ".Themida")
      or for any bhw in pe.sections: (bhw.name == "WinLicen")
    )
}

rule capa_read_raw_disk_data: CAPA HOST_INTERACTION FILE_SYSTEM FILE {
  meta:
    description  = "read raw disk data (converted from capa rule)"
    namespace    = "host-interaction/file-system"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/read-raw-disk-data.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bhx = "\\\\.\\PhysicalDrive0" ascii wide
    $file_str_bhy = "\\\\.\\C:" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bhx
      or $file_str_bhy
    )
}

rule capa_bypass_UAC_via_scheduled_task_environment_variable: CAPA HOST_INTERACTION UAC BYPASS FUNCTION T1548_002 {
  meta:
    description  = "bypass UAC via scheduled task environment variable (converted from capa rule)"
    namespace    = "host-interaction/uac/bypass"
    author       = "anamaria.martinezgom@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Abuse Elevation Control Mechanism::Bypass User Access Control [T1548.002]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/bypass-uac-via-scheduled-task-environment-variable.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bhz = "schtasks.exe" ascii wide
    $func_re_bia  = /Microsoft\\Windows\\DiskCleanup\\SilentCleanup/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bhz
      and $func_re_bia
      and capa_create_process

    )
}

rule capa_reference_AES_constants: CAPA DATA_MANIPULATION ENCRYPTION AES FUNCTION T1027 {
  meta:
    description  = "reference AES constants (converted from capa rule)"
    namespace    = "data-manipulation/encryption/aes"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-aes-constants.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_big = { 50 A7 F4 51 53 65 41 7E }  // d-0
    $func_bih = { 63 7C 77 7B F2 6B 6F C5 }  // s-box
    $func_bii = { 52 09 6A D5 30 36 A5 38 }  // inv-s-box

  condition:
    capa_pe_file and
    (
      $func_big
      or $func_bih
      or $func_bii
    )
}

rule capa_compiled_with_Nim: CAPA COMPILER NIM FILE {
  meta:
    description  = "compiled with Nim (converted from capa rule)"
    namespace    = "compiler/nim"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/compiled-with-nim.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_bij = /NimMain/ ascii wide
    $file_re_bik = /NimMainModule/ ascii wide
    $file_re_bil = /NimMainInner/ ascii wide
    $file_re_bim = /io\.nim$/ ascii wide
    $file_re_bin = /fatal\.nim$/ ascii wide
    $file_re_bio = /system\.nim$/ ascii wide
    $file_re_bip = /alloc\.nim$/ ascii wide
    $file_re_biq = /osalloc\.nim$/ ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_bij
      or $file_re_bik
      or $file_re_bil
      or $file_re_bim
      or $file_re_bin
      or $file_re_bio
      or $file_re_bip
      or $file_re_biq
    )
}

rule capa_hook_routines_via_microsoft_detours: CAPA FUNCTION {
  meta:
    description  = "hook routines via microsoft detours (converted from capa rule)"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/hook-routines-via-microsoft-detours.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $num_bir = "dtrR"  // DETOUR_REGION_SIGNATURE

  condition:
    capa_pe_file and
    (
      $num_bir
    )
}

rule capa_packed_with_SVKP: CAPA ANTI_ANALYSIS PACKER SVKP FILE T1027_002 F0001 {
  meta:
    description  = "packed with SVKP (converted from capa rule)"
    namespace    = "anti-analysis/packer/svkp"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-svkp.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bis in pe.sections: (bis.name == ".svkp")
    )
}

rule capa_reference_startup_folder: CAPA PERSISTENCE STARTUP_FOLDER FILE T1547_001 {
  meta:
    description  = "reference startup folder (converted from capa rule)"
    namespace    = "persistence/startup-folder"
    author       = "matthew.williams@fireeye.com"
    scope        = "file"
    attack       = "Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-startup-folder.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_bit = /Start Menu\\Programs\\Startup/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_bit
    )
}

rule capa_encrypt_or_decrypt_data_via_BCrypt: CAPA DATA_MANIPULATION ENCRYPTION FUNCTION T1027 C0031 C0027 {
  meta:
    description  = "encrypt or decrypt data via BCrypt (converted from capa rule)"
    namespace    = "data-manipulation/encryption"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Cryptography::Decrypt Data [C0031]"
    mbc          = "Cryptography::Encrypt Data [C0027]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/encrypt-or-decrypt-data-via-bcrypt.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_biu = /\bBCryptDecrypt(A|W)?\b/ ascii wide
    $api_biv = /\bBCryptEncrypt(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $api_biu
        or $api_biv
      )
    )
}

rule capa_packed_with_Shrinker: CAPA ANTI_ANALYSIS PACKER SHRINKER FILE T1027_002 F0001 {
  meta:
    description  = "packed with Shrinker (converted from capa rule)"
    namespace    = "anti-analysis/packer/shrinker"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-shrinker.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bix in pe.sections: (bix.name == ".shrink1")
      or for any biy in pe.sections: (biy.name == ".shrink2")
      or for any biz in pe.sections: (biz.name == ".shrink3")
    )
}

rule capa_packed_with_VProtect: CAPA ANTI_ANALYSIS PACKER VPROTECT FILE T1027_002 F0001 {
  meta:
    description  = "packed with VProtect (converted from capa rule)"
    namespace    = "anti-analysis/packer/vprotect"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-vprotect.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bja in pe.sections: (bja.name == "VProtect")
    )
}

rule capa_packed_with_CCG: CAPA ANTI_ANALYSIS PACKER CCG FILE T1027_002 F0001 {
  meta:
    description  = "packed with CCG (converted from capa rule)"
    namespace    = "anti-analysis/packer/ccg"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-ccg.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bjb in pe.sections: (bjb.name == ".ccg")
    )
}

rule capa_reference_Hurricane_Electric_DNS_server: CAPA COMMUNICATION DNS FUNCTION {
  meta:
    description  = "reference Hurricane Electric DNS server (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-hurricane-electric-dns-server.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bjc = "216.218.130.2" ascii wide  // ns1.he.net
    $func_str_bjd = "216.218.131.2" ascii wide  // ns2.he.net
    $func_str_bje = "216.218.132.2" ascii wide  // ns3.he.net
    $func_str_bjf = "216.66.1.2" ascii wide  // ns4.he.net
    $func_str_bjg = "216.66.80.18" ascii wide  // ns5.he.net

  condition:
    capa_pe_file and
    (
      $func_str_bjc
      or $func_str_bjd
      or $func_str_bje
      or $func_str_bjf
      or $func_str_bjg
    )
}

rule capa_packed_with_Mpress: CAPA ANTI_ANALYSIS PACKER MPRESS FILE T1027_002 F0001 {
  meta:
    description  = "packed with Mpress (converted from capa rule)"
    namespace    = "anti-analysis/packer/mpress"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-mpress.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bjh in pe.sections: (bjh.name == ".MPRESS1")
      or for any bji in pe.sections: (bji.name == ".MPRESS2")
    )
}

rule capa_packaged_as_an_InstallShield_installer: CAPA EXECUTABLE INSTALLER INSTALLSHIELD FILE {
  meta:
    description  = "packaged as an InstallShield installer (converted from capa rule)"
    namespace    = "executable/installer/installshield"
    author       = "moritz.raabe@fireeye.com"
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packaged-as-an-installshield-installer.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bjj = "InstallShield" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bjj
    )
}

rule capa_mine_cryptocurrency: CAPA IMPACT CRYPTOCURRENCY FILE T1496 {
  meta:
    description  = "mine cryptocurrency (converted from capa rule)"
    namespace    = "impact/cryptocurrency"
    author       = "moritz.raabe@fireeye.com"
    scope        = "file"
    attack       = "Impact::Resource Hijacking [T1496]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/mine-cryptocurrency.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bjk = "stratum+tcp://" ascii wide
    $file_str_bjl = "xmrig" ascii wide
    $file_str_bjm = "xmr-stak" ascii wide
    $file_str_bjn = "supportxmr.com:" ascii wide
    $file_str_bjo = "dwarfpool.com:" ascii wide
    $file_str_bjp = "minergate" ascii wide
    $file_str_bjq = "xmr." ascii wide
    $file_str_bjr = "monero." ascii wide
    $file_str_bjs = "Bitcoin" ascii wide
    $file_str_bjt = "Bitcoin" ascii wide
    $file_str_bju = "BitcoinGold" ascii wide
    $file_str_bjv = "BtcCash" ascii wide
    $file_str_bjw = "Ethereum" ascii wide
    $file_str_bjx = "BlackCoin" ascii wide
    $file_str_bjy = "ByteCoin" ascii wide
    $file_str_bjz = "EmerCoin" ascii wide
    $file_str_bka = "ReddCoin" ascii wide
    $file_str_bkb = "Peercoin" ascii wide
    $file_str_bkc = "Ripple" ascii wide
    $file_str_bkd = "Miota" ascii wide
    $file_str_bke = "Cardano" ascii wide
    $file_str_bkf = "Lisk" ascii wide
    $file_str_bkg = "Stratis" ascii wide
    $file_str_bkh = "Waves" ascii wide
    $file_str_bki = "Qtum" ascii wide
    $file_str_bkj = "Stellar" ascii wide
    $file_str_bkk = "ViaCoin" ascii wide
    $file_str_bkl = "Electroneum" ascii wide
    $file_str_bkm = "Dash" ascii wide
    $file_str_bkn = "Doge" ascii wide
    $file_str_bko = "Monero" ascii wide
    $file_str_bkp = "Graft" ascii wide
    $file_str_bkq = "Zcash" ascii wide
    $file_str_bkr = "Ya.money" ascii wide
    $file_str_bks = "Ya.disc" ascii wide
    $file_str_bkt = "Steam" ascii wide
    $file_str_bku = "vk.cc" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bjk
      or $file_str_bjl
      or $file_str_bjm
      or $file_str_bjn
      or $file_str_bjo
      or $file_str_bjp
      or $file_str_bjq
      or $file_str_bjr
      or $file_str_bjs
      or $file_str_bjt
      or $file_str_bju
      or $file_str_bjv
      or $file_str_bjw
      or $file_str_bjx
      or $file_str_bjy
      or $file_str_bjz
      or $file_str_bka
      or $file_str_bkb
      or $file_str_bkc
      or $file_str_bkd
      or $file_str_bke
      or $file_str_bkf
      or $file_str_bkg
      or $file_str_bkh
      or $file_str_bki
      or $file_str_bkj
      or $file_str_bkk
      or $file_str_bkl
      or $file_str_bkm
      or $file_str_bkn
      or $file_str_bko
      or $file_str_bkp
      or $file_str_bkq
      or $file_str_bkr
      or $file_str_bks
      or $file_str_bkt
      or $file_str_bku
    )
}

rule capa_packed_with_SeauSFX: CAPA ANTI_ANALYSIS PACKER SEAUSFX FILE T1027_002 F0001 {
  meta:
    description  = "packed with SeauSFX (converted from capa rule)"
    namespace    = "anti-analysis/packer/seausfx"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-seausfx.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bkv in pe.sections: (bkv.name == ".seau")
    )
}

rule capa_debug_build: CAPA EXECUTABLE PE DEBUG FILE {
  meta:
    description  = "debug build (converted from capa rule)"
    namespace    = "executable/pe/debug"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/debug-build.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bkw = "Assertion failed!" ascii wide
    $file_str_bkx = "Assertion failed:" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bkw
      or $file_str_bkx
    )
}

rule capa_packed_with_Simple_Pack: CAPA ANTI_ANALYSIS PACKER SIMPLE_PACK FILE T1027_002 F0001 {
  meta:
    description  = "packed with Simple Pack (converted from capa rule)"
    namespace    = "anti-analysis/packer/simple-pack"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-simple-pack.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bky in pe.sections: (bky.name == ".spack")
    )
}

rule capa_resolve_function_by_hash: CAPA LINKING RUNTIME_LINKING FUNCTION T1027_005 {
  meta:
    description  = "resolve function by hash (converted from capa rule)"
    namespace    = "linking/runtime-linking"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Obfuscated Files or Information::Indicator Removal from Tools [T1027.005]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/resolve-function-by-hash.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $num_bkz = { 5B BC 4A 6A }  // ROR13(kernel32.dll)
    $num_bla = { 5D 68 FA 3C }  // ROR13(ntdll.dll)
    $num_blb = { 8E 4E 0E EC }  // ROR13(LoadLibraryA)
    $num_blc = { AA FC 0D 7C }  // ROR13(GetProcAddress)
    $num_bld = { 54 CA AF 91 }  // ROR13(VirtualAlloc)
    $num_ble = { B8 0A 4C 53 }  // ROR13(NtFlushInstructionCache)
    $num_blf = { 1A 06 7F FF }  // ROR13(RtlExitUserThread)
    $num_blg = { EF CE E0 60 }  // ROR13(ExitThread)

  condition:
    capa_pe_file and
    (
      $num_bkz
      or $num_bla
      or $num_blb
      or $num_blc
      or $num_bld
      or $num_ble
      or $num_blf
      or $num_blg
    )
}

rule capa_hash_data_via_BCrypt: CAPA DATA_MANIPULATION HASHING FUNCTION T1027 C0029 {
  meta:
    description  = "hash data via BCrypt (converted from capa rule)"
    namespace    = "data-manipulation/hashing"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Cryptography::Cryptographic Hash [C0029]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/hash-data-via-bcrypt.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_blh = /\bBCryptHash(A|W)?\b/ ascii wide
    $api_bli = /\bBCryptHashData(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $api_blh
        or (
          $api_bli
        )
      )
    )
}

rule capa_reference_OpenDNS_DNS_server: CAPA COMMUNICATION DNS FUNCTION {
  meta:
    description  = "reference OpenDNS DNS server (converted from capa rule)"
    namespace    = "communication/dns"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/reference-opendns-dns-server.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_blk = "208.67.222.222" ascii wide
    $func_str_bll = "208.67.220.220" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_blk
      or $func_str_bll
    )
}

rule capa_linked_against_XZip: CAPA LINKING STATIC XZIP FILE C0060 {
  meta:
    description  = "linked against XZip (converted from capa rule)"
    namespace    = "linking/static/xzip"
    author       = "moritz.raabe@fireeye.com"
    scope        = "file"
    mbc          = "Data::Compression Library [C0060]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-xzip.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_blm = "ct_init: length != 256" ascii wide
    $file_str_bln = "ct_init: dist != 256" ascii wide
    $file_str_blo = "ct_init: 256+dist != 512" ascii wide
    $file_str_blp = "bit length overflow" ascii wide
    $file_str_blq = "code %d bits %d->%d" ascii wide
    $file_str_blr = "inconsistent bit counts" ascii wide
    $file_str_bls = "gen_codes: max_code %d " ascii wide
    $file_str_blt = "dyn trees: dyn %ld, stat %ld" ascii wide
    $file_str_blu = "bad pack level" ascii wide
    $file_str_blv = "Code too clever" ascii wide
    $file_str_blw = "unknown zip result code" ascii wide
    $file_str_blx = "Culdn't duplicate handle" ascii wide
    $file_str_bly = "File not found in the zipfile" ascii wide
    $file_str_blz = "Still more data to unzip" ascii wide
    $file_str_bma = "Caller: the file had already been partially unzipped" ascii wide
    $file_str_bmb = "Caller: can only get memory of a memory zipfile" ascii wide
    $file_str_bmc = "Zip-bug: internal initialisation not completed" ascii wide
    $file_str_bmd = "Zip-bug: an internal error during flation" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_blm
      or $file_str_bln
      or $file_str_blo
      or $file_str_blp
      or $file_str_blq
      or $file_str_blr
      or $file_str_bls
      or $file_str_blt
      or $file_str_blu
      or $file_str_blv
      or $file_str_blw
      or $file_str_blx
      or $file_str_bly
      or $file_str_blz
      or $file_str_bma
      or $file_str_bmb
      or $file_str_bmc
      or $file_str_bmd
    )
}

rule capa_compiled_from_EPL: CAPA COMPILER EPL FILE {
  meta:
    description  = "compiled from EPL (converted from capa rule)"
    namespace    = "compiler/epl"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/compiled-from-epl.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bme = "GetNewSock" ascii wide
    $file_str_bmf = "Software\\FlySky\\E\\Install" ascii wide
    $file_str_bmg = "Not found the kernel library or the kernel library is invalid!" ascii wide
    $file_str_bmh = "Failed to allocate memory!" ascii wide
    $file_str_bmi = "/ MADE BY E COMPILER – WUTAO" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bme
      or $file_str_bmf
      or $file_str_bmg
      or $file_str_bmh
      or $file_str_bmi
      or for any bmj in pe.sections: (bmj.name == ".ecode")
      or for any bmk in pe.sections: (bmk.name == ".edata")
      or pe.imports(/krnln/i, /fne/)
      or pe.imports(/krnln/i, /fnr/)
      or pe.imports(/eAPI/i, /fne/)
      or pe.imports(/RegEx/i, /fnr/)
    )
}

rule capa_packed_with_Perplex: CAPA ANTI_ANALYSIS PACKER PERPLEX FILE T1027_002 F0001 {
  meta:
    description  = "packed with Perplex (converted from capa rule)"
    namespace    = "anti-analysis/packer/perplex"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]"
    mbc          = "Anti-Static Analysis::Software Packing [F0001]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/packed-with-perplex.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bml in pe.sections: (bml.name == ".perplex")
    )
}

rule capa_compiled_with_Go: CAPA COMPILER GO FILE {
  meta:
    description  = "compiled with Go (converted from capa rule)"
    namespace    = "compiler/go"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "file"
    hash         = "49a34cfbeed733c24392c9217ef46bb6"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/go/compiled-with-go.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bmm = "Go build ID:" ascii wide
    $file_str_bmn = "go.buildid" ascii wide
    $file_str_bmo = "Go buildinf:" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bmm
      or $file_str_bmn
      or $file_str_bmo
    )
}

rule capa_compiled_with_ps2exe: CAPA COMPILER PS2EXE FILE {
  meta:
    description  = "compiled with ps2exe (converted from capa rule)"
    namespace    = "compiler/ps2exe"
    author       = "@_re_fox"
    scope        = "file"
    hash         = "8775ed26068788279726e08ff9665aab"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/ps2exe/compiled-with-ps2exe.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bmp = "PS2EXEApp" ascii wide
    $file_str_bmq = "PS2EXE" ascii wide
    $file_str_bmr = "PS2EXE_Host" ascii wide

  condition:
    capa_pe_file and
    (
      capa_compiled_to_the__NET_platform

      and $file_str_bmp
      and $file_str_bmq
      and $file_str_bmr
    )
}

rule capa_compiled_with_MinGW_for_Windows: CAPA COMPILER MINGW FILE {
  meta:
    description  = "compiled with MinGW for Windows (converted from capa rule)"
    namespace    = "compiler/mingw"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    hash         = "5b3968b47eb16a1cb88525e3b565eab1"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/mingw/compiled-with-mingw-for-windows.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bms = "Mingw runtime failure:" ascii wide
    $file_str_bmt = "_Jv_RegisterClasses" ascii wide  // from GCC

  condition:
    capa_pe_file and
    (
      $file_str_bms
      and $file_str_bmt
    )
}

rule capa_compiled_from_Visual_Basic: CAPA COMPILER VB FILE {
  meta:
    description  = "compiled from Visual Basic (converted from capa rule)"
    namespace    = "compiler/vb"
    author       = "@williballenthin"
    scope        = "file"
    hash         = "9bca6b99e7981208af4c7925b96fb9cf"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/vb/compiled-from-visual-basic.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_re_bmu = /VB5!.\\\{,1000\\\}/ ascii wide

  condition:
    capa_pe_file and
    (
      $file_re_bmu
      and pe.imports(/msvbvm60/i, /ThunRTMain/)
    )
}

rule capa_compiled_with_pyarmor: CAPA COMPILER PYARMOR FILE T1059_006 {
  meta:
    description  = "compiled with pyarmor (converted from capa rule)"
    namespace    = "compiler/pyarmor"
    author       = "@stvemillertime, @itreallynick"
    scope        = "file"
    attack       = "Execution::Command and Scripting Interpreter::Python [T1059.006]"
    hash         = "a0fb20bc9aa944c3a0a6c4545c195818"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/pyarmor/compiled-with-pyarmor.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bmy = "pyarmor_runtimesh" ascii wide
    $file_str_bmz = "PYARMOR" ascii wide
    $file_str_bna = "__pyarmor__" ascii wide
    $file_str_bnb = "PYARMOR_SIGNATURE" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bmy
      or $file_str_bmz
      or $file_str_bna
      or $file_str_bnb
    )
}

rule capa_compiled_with_exe4j: CAPA COMPILER EXE4J FILE {
  meta:
    description  = "compiled with exe4j (converted from capa rule)"
    namespace    = "compiler/exe4j"
    author       = "johnk3r"
    scope        = "file"
    hash         = "6b25f1e754ef486bbb28a66d46bababe"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/exe4j/compiled-with-exe4j.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bnc = "exe4j_log" ascii wide
    $file_str_bnd = "install4j_log" ascii wide
    $file_str_bne = "exe4j_java_home" ascii wide
    $file_str_bnf = "install4j" ascii wide
    $file_str_bng = "exe4j.isinstall4j" ascii wide
    $file_re_bnh  = /com\/exe4j\/runtime\/exe4jcontroller/ nocase ascii wide
    $file_re_bni  = /com\/exe4j\/runtime\/winlauncher/ nocase ascii wide
    $file_str_bnj = "EXE4J_LOG" ascii wide
    $file_str_bnk = "INSTALL4J_LOG" ascii wide
    $file_str_bnl = "EXE4J_JAVA_HOME" ascii wide
    $file_str_bnm = "INSTALL4J" ascii wide
    $file_str_bnn = "EXE4J.ISINSTALL4J" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bnc
      or $file_str_bnd
      or $file_str_bne
      or $file_str_bnf
      or $file_str_bng
      or $file_re_bnh
      or $file_re_bni
      or $file_str_bnj
      or $file_str_bnk
      or $file_str_bnl
      or $file_str_bnm
      or $file_str_bnn
    )
}

rule capa_compiled_with_AutoIt: CAPA COMPILER AUTOIT FILE T1059 {
  meta:
    description  = "compiled with AutoIt (converted from capa rule)"
    namespace    = "compiler/autoit"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    attack       = "Execution::Command and Scripting Interpreter [T1059]"
    hash         = "55D77AB16377A8A314982F723FCC6FAE"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/autoit/compiled-with-autoit.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bno = "AutoIt has detected the stack has become corrupt.\n\nStack corruption typically occurs when either the wrong calling convention is used or when the function is called with the wrong number of arguments.\n\nAutoIt supports the __stdcall (WINAPI) and __cdecl calling conventions.  The __stdcall (WINAPI) convention is used by default but __cdecl can be used instead.  See the DllCall() documentation for details on changing the calling convention." ascii wide
    $file_str_bnp = "AutoIt Error" ascii wide
    $file_re_bnq  = />>>AUTOIT SCRIPT<<</ ascii wide
    $file_str_bnr = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
    $file_str_bns = "#requireadmin" ascii wide
    $file_str_bnt = "#OnAutoItStartRegister" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bno
      or $file_str_bnp
      or $file_re_bnq
      or $file_str_bnr
      or $file_str_bns
      or $file_str_bnt
    )
}

rule capa_compiled_with_Borland_Delphi: CAPA COMPILER DELPHI FILE {
  meta:
    description  = "compiled with Borland Delphi (converted from capa rule)"
    namespace    = "compiler/delphi"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    hash         = "4BDD67FF852C221112337FECD0681EAC"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/delphi/compiled-with-borland-delphi.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bnu = "Borland C++ - Copyright 2002 Borland Corporation" ascii wide
    $file_re_bnv  = /SOFTWARE\\Borland\\Delphi\\RTL/ ascii wide
    $file_str_bnw = "Sysutils::Exception" ascii wide
    $file_str_bnx = "TForm1" ascii wide

  condition:
    capa_pe_file and
    (
      $file_str_bnu
      or $file_re_bnv
      or $file_str_bnw
      or $file_str_bnx
      or pe.imports(/BORLNDMM/i, /DLL/)
    )
}

rule capa_compiled_with_dmd: CAPA COMPILER D FILE {
  meta:
    description  = "compiled with dmd (converted from capa rule)"
    namespace    = "compiler/d"
    author       = "@_re_fox"
    scope        = "file"
    hash         = "321338196a46b600ea330fc5d98d0699"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/d/compiled-with-dmd.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  condition:
    capa_pe_file and
    (
      for any bny in pe.sections: (bny.name == "._deh")
      and for any bnz in pe.sections: (bnz.name == ".tp")
      and for any boa in pe.sections: (boa.name == ".dp")
      and for any bob in pe.sections: (bob.name == ".minfo")
    )
}

rule capa_compiled_with_py2exe: CAPA COMPILER PY2EXE BASICBLOCK {
  meta:
    description  = "compiled with py2exe (converted from capa rule)"
    namespace    = "compiler/py2exe"
    author       = "@_re_fox"
    scope        = "basic block"
    hash         = "ed888dc2f04f5eac83d6d14088d002de"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/compiler/py2exe/compiled-with-py2exe.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_str_boc = "PY2EXE_VERBOSE" ascii wide
    $api_bod       = /\bgetenv(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      $basic_str_boc
      and $api_bod
    )
}

rule capa_identify_ATM_dispenser_service_provider: CAPA TARGETING AUTOMATED_TELLER_MACHINE FILE {
  meta:
    description  = "identify ATM dispenser service provider (converted from capa rule)"
    namespace    = "targeting/automated-teller-machine"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    hash         = "b2ad4409323147b63e370745e5209996"
    hash         = "1f094dd65be477d15d871e72f0fdce5e"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/identify-atm-dispenser-service-provider.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_boe = "CurrencyDispenser1" ascii wide  // NCR
    $file_str_bof = "CDM30" ascii wide  // Wincor
    $file_str_bog = "DBD_AdvFuncDisp" ascii wide  // Diebold

  condition:
    capa_pe_file and
    (
      $file_str_boe
      or $file_str_bof
      or $file_str_bog
    )
}

rule capa_load_NCR_ATM_library: CAPA TARGETING AUTOMATED_TELLER_MACHINE NCR FILE {
  meta:
    description  = "load NCR ATM library (converted from capa rule)"
    namespace    = "targeting/automated-teller-machine/ncr"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    hash         = "971e599e6e707349eccea2fd4c8e5f67"
    hash         = "4bdd67ff852c221112337fecd0681eac"
    hash         = "32d1f4b9c0cf2bb9512d88d27ca23c07"
    hash         = "dc9eb40429d6fa2f15cd34479cb320c8"
    hash         = "5b3968b47eb16a1cb88525e3b565eab1"
    hash         = "dc4dc746d8a14060fb5fc7edd4ef5282"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/ncr/load-ncr-atm-library.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_boh = "MSXFS.dll" ascii wide
    $file_str_boi = "msxfs.dll" ascii wide

  condition:
    capa_pe_file and
    (
      pe.imports(/msxfs/i, /dll/)
      or $file_str_boh
      or $file_str_boi
    )
}

rule capa_reference_NCR_ATM_library_routines: CAPA TARGETING AUTOMATED_TELLER_MACHINE NCR FUNCTION {
  meta:
    description  = "reference NCR ATM library routines (converted from capa rule)"
    namespace    = "targeting/automated-teller-machine/ncr"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    hash         = "84a1212f4a91066babcf594d87a85894"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/ncr/reference-ncr-atm-library-routines.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_boj = "msxfs.dll" ascii wide
    $func_str_bok = "WFSCleanUp" ascii wide
    $func_str_bol = "WFSClose" ascii wide
    $func_str_bom = "WFSExecute" ascii wide
    $func_str_bon = "WFSFreeResult" ascii wide
    $func_str_boo = "WFSGetInfo" ascii wide
    $func_str_bop = "WFSLock" ascii wide
    $func_str_boq = "WFSOpen" ascii wide
    $func_str_bor = "WFSRegister" ascii wide
    $func_str_bos = "WFSStartUp" ascii wide
    $func_str_bot = "WFSUnlock" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_boj
      or pe.imports(/msxfs/i, /WFSCleanUp/)
      or $func_str_bok
      or pe.imports(/msxfs/i, /WFSClose/)
      or $func_str_bol
      or pe.imports(/msxfs/i, /WFSExecute/)
      or $func_str_bom
      or pe.imports(/msxfs/i, /WFSFreeResult/)
      or $func_str_bon
      or pe.imports(/msxfs/i, /WFSGetInfo/)
      or $func_str_boo
      or pe.imports(/msxfs/i, /WFSLock/)
      or $func_str_bop
      or pe.imports(/msxfs/i, /WFSOpen/)
      or $func_str_boq
      or pe.imports(/msxfs/i, /WFSRegister/)
      or $func_str_bor
      or pe.imports(/msxfs/i, /WFSStartUp/)
      or $func_str_bos
      or pe.imports(/msxfs/i, /WFSUnlock/)
      or $func_str_bot
    )
}

rule capa_reference_Diebold_ATM_routines: CAPA TARGETING AUTOMATED_TELLER_MACHINE DIEBOLD_NIXDORF FILE {
  meta:
    description  = "reference Diebold ATM routines (converted from capa rule)"
    namespace    = "targeting/automated-teller-machine/diebold-nixdorf"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    hash         = "b2ad4409323147b63e370745e5209996"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/diebold-nixdorf/reference-diebold-atm-routines.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bou = "DBD_AdvFuncDisp" ascii wide  // dispenser function
    $file_str_bov = "DBD_EPP4" ascii wide  // pin pad function

  condition:
    capa_pe_file and
    (
      $file_str_bou
      or $file_str_bov
    )
}

rule capa_load_Diebold_Nixdorf_ATM_library: CAPA TARGETING AUTOMATED_TELLER_MACHINE DIEBOLD_NIXDORF FILE {
  meta:
    description  = "load Diebold Nixdorf ATM library (converted from capa rule)"
    namespace    = "targeting/automated-teller-machine/diebold-nixdorf"
    author       = "william.ballenthin@fireeye.com"
    scope        = "file"
    hash         = "658b0502b53f718bd0611a638dfd5969"
    hash         = "8683c43f1e22363ce98f0a89ca4ed389"
    hash         = "953bc3e68f0a49c6ade30b52a2bfaaab"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/targeting/automated-teller-machine/diebold-nixdorf/load-diebold-nixdorf-atm-library.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_bow = "CSCWCNG.dll" ascii wide
    $file_str_box = "CscCngStatusWrite" ascii wide
    $file_str_boy = "CscCngCasRefInit" ascii wide
    $file_str_boz = "CscCngEncryption" ascii wide
    $file_str_bpa = "CscCngRecovery" ascii wide
    $file_str_bpb = "CscCngService" ascii wide
    $file_str_bpc = "CscCngOpen" ascii wide
    $file_str_bpd = "CscCngReset" ascii wide
    $file_str_bpe = "CscCngClose" ascii wide
    $file_str_bpf = "CscCngDispense" ascii wide
    $file_str_bpg = "CscCngTransport" ascii wide
    $file_str_bph = "CscCngStatusRead" ascii wide
    $file_str_bpi = "CscCngInit" ascii wide
    $file_str_bpj = "CscCngGetRelease" ascii wide
    $file_str_bpk = "CscCngLock" ascii wide
    $file_str_bpl = "CscCngUnlock" ascii wide
    $file_str_bpm = "CscCngShutter" ascii wide
    $file_str_bpn = "CscCngPowerOff" ascii wide
    $file_str_bpo = "CscCngSelStatus" ascii wide
    $file_str_bpp = "CscCngBim" ascii wide
    $file_str_bpq = "CscCngConfigure" ascii wide
    $file_str_bpr = "CscCngStatistics" ascii wide
    $file_str_bps = "CscCngControl" ascii wide
    $file_str_bpt = "CscCngPsm" ascii wide
    $file_str_bpu = "CscCngGetTrace" ascii wide
    $file_str_bpv = "CscCngOptimization" ascii wide
    $file_str_bpw = "CscCngSelftest" ascii wide
    $file_str_bpx = "CscCngEco" ascii wide

  condition:
    capa_pe_file and
    (
      pe.imports(/cscwcng/i, /dll/)
      or $file_str_bow
      or pe.imports(/cscwcng/i, /CscCngStatusWrite/)
      or pe.imports(/cscwcng/i, /CscCngCasRefInit/)
      or pe.imports(/cscwcng/i, /CscCngEncryption/)
      or pe.imports(/cscwcng/i, /CscCngRecovery/)
      or pe.imports(/cscwcng/i, /CscCngService/)
      or pe.imports(/cscwcng/i, /CscCngOpen/)
      or pe.imports(/cscwcng/i, /CscCngReset/)
      or pe.imports(/cscwcng/i, /CscCngClose/)
      or pe.imports(/cscwcng/i, /CscCngDispense/)
      or pe.imports(/cscwcng/i, /CscCngTransport/)
      or pe.imports(/cscwcng/i, /CscCngStatusRead/)
      or pe.imports(/cscwcng/i, /CscCngInit/)
      or pe.imports(/cscwcng/i, /CscCngGetRelease/)
      or pe.imports(/cscwcng/i, /CscCngLock/)
      or pe.imports(/cscwcng/i, /CscCngUnlock/)
      or pe.imports(/cscwcng/i, /CscCngShutter/)
      or pe.imports(/cscwcng/i, /CscCngPowerOff/)
      or pe.imports(/cscwcng/i, /CscCngSelStatus/)
      or pe.imports(/cscwcng/i, /CscCngBim/)
      or pe.imports(/cscwcng/i, /CscCngConfigure/)
      or pe.imports(/cscwcng/i, /CscCngStatistics/)
      or pe.imports(/cscwcng/i, /CscCngControl/)
      or pe.imports(/cscwcng/i, /CscCngPsm/)
      or pe.imports(/cscwcng/i, /CscCngGetTrace/)
      or pe.imports(/cscwcng/i, /CscCngOptimization/)
      or pe.imports(/cscwcng/i, /CscCngSelftest/)
      or pe.imports(/cscwcng/i, /CscCngEco/)
      or $file_str_box
      or $file_str_boy
      or $file_str_boz
      or $file_str_bpa
      or $file_str_bpb
      or $file_str_bpc
      or $file_str_bpd
      or $file_str_bpe
      or $file_str_bpf
      or $file_str_bpg
      or $file_str_bph
      or $file_str_bpi
      or $file_str_bpj
      or $file_str_bpk
      or $file_str_bpl
      or $file_str_bpm
      or $file_str_bpn
      or $file_str_bpo
      or $file_str_bpp
      or $file_str_bpq
      or $file_str_bpr
      or $file_str_bps
      or $file_str_bpt
      or $file_str_bpu
      or $file_str_bpv
      or $file_str_bpw
      or $file_str_bpx
    )
}

rule capa_initialize_IWebBrowser2: CAPA COMMUNICATION HTTP BASICBLOCK C0002_010 {
  meta:
    description  = "initialize IWebBrowser2 (converted from capa rule)"
    namespace    = "communication/http"
    author       = "matthew.williams@fireeye.com"
    scope        = "basic block"
    mbc          = "Communication::HTTP Communication::IWebBrowser [C0002.010]"
    hash         = "395EB0DDD99D2C9E37B6D0B73485EE9C"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/initialize-iwebbrowser2.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_bpy = { 01 DF 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }  // CLSID_InternetExplorer
    $basic_bpz = { 61 16 0C D3 AF CD D0 11 8A 3E 00 C0 4F C9 E2 6E }  // IID_IWebBrowser2

  condition:
    capa_pe_file and
    (
      pe.imports(/ole32/i, /CoCreateInstance/)
      and $basic_bpy
      and $basic_bpz
    )
}

rule capa_send_ICMP_echo_request: CAPA COMMUNICATION ICMP FUNCTION C0014_002 {
  meta:
    description  = "send ICMP echo request (converted from capa rule)"
    namespace    = "communication/icmp"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "function"
    mbc          = "Communication::ICMP Communication::Echo Request [C0014.002]"
    hash         = "al-khaser_x86.exe_:0x449510"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/icmp/send-icmp-echo-request.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_bqc = /\bIcmpSendEcho(A|W)?\b/ ascii wide
    $api_bqd = /\bIcmpSendEcho2(A|W)?\b/ ascii wide
    $api_bqe = /\bIcmpSendEcho2Ex(A|W)?\b/ ascii wide
    $api_bqf = /\bIcmp6SendEcho2(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $api_bqc
        or $api_bqd
        or $api_bqe
        or $api_bqf
      )
    )
}

rule capa_access_PE_header: CAPA LOAD_CODE PE FUNCTION T1129 {
  meta:
    description  = "access PE header (converted from capa rule)"
    namespace    = "load-code/pe"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Execution::Shared Modules [T1129]"
    hash         = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/load-code/pe/access-pe-header.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_bqg = /\bRtlImageNtHeader(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      $api_bqg
      or pe.imports(/ntdll/i, /RtlImageNtHeaderEx/)
    )
}

rule capa_acquire_credentials_from_Windows_Credential_Manager: CAPA COLLECTION FUNCTION T1555_004 {
  meta:
    description  = "acquire credentials from Windows Credential Manager (converted from capa rule)"
    namespace    = "collection"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores::Windows Credential Manager [T1555.004]"
    hash         = "c56af5561e3f20bed435fb4355cffc29"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/acquire-credentials-from-windows-credential-manager.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bqh = ".vcrd" ascii wide
    $func_str_bqi = "*.vcrd" ascii wide
    $func_str_bqj = "Policy.vpol" ascii wide
    $func_re_bqk  = /AppData\\Local\\Microsoft\\(Vault|Credentials)/ ascii wide
    $api_bql      = /\bCredEnumerate(A|W)?\b/ ascii wide
    $func_re_bqm  = /vaultcmd(\.exe)?/ ascii wide
    $func_re_bqn  = /\/listcreds:/ ascii wide
    $func_re_bqo  = /"Windows Credentials"/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bqh
      or $func_str_bqi
      or $func_str_bqj
      or $func_re_bqk
      or $api_bql
      or (
        (
          $func_re_bqm
          or $func_re_bqn
          or $func_re_bqo
        )
      )
    )
}

rule capa_get_geographical_location: CAPA COLLECTION FUNCTION T1614 {
  meta:
    description  = "get geographical location (converted from capa rule)"
    namespace    = "collection"
    author       = "moritz.raabe"
    scope        = "function"
    attack       = "Discovery::System Location Discovery [T1614]"
    hash         = "9879D201DC5ACA863F357184CD1F170E"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/get-geographical-location.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_bqp     = /\bGetLocaleInfo(A|W)?\b/ ascii wide
    $api_bqq     = /\bGetLocaleInfoEx(A|W)?\b/ ascii wide
    $func_re_bqr = /geolocation/ nocase ascii wide
    $func_re_bqs = /geo-location/ nocase ascii wide
    $func_re_bqt = /\x00city/ nocase ascii wide
    $func_re_bqu = /region_code/ nocase ascii wide
    $func_re_bqv = /region_name/ nocase ascii wide
    $func_re_bqw = /\x00country/ nocase ascii wide
    $func_re_bqx = /country_code/ nocase ascii wide
    $func_re_bqy = /countrycode/ nocase ascii wide
    $func_re_bqz = /country_name/ nocase ascii wide
    $func_re_bra = /continent_code/ nocase ascii wide
    $func_re_brb = /continent_name/ nocase ascii wide
    $func_re_brc = /\x00latitude/ nocase ascii wide
    $func_re_brd = /\x00longitude/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $api_bqp
      or $api_bqq
      or $func_re_bqr
      or $func_re_bqs
      or $func_re_bqt
      or $func_re_bqu
      or $func_re_bqv
      or $func_re_bqw
      or $func_re_bqx
      or $func_re_bqy
      or $func_re_bqz
      or $func_re_bra
      or $func_re_brb
      or $func_re_brc
      or $func_re_brd
    )
}

rule capa_log_keystrokes: CAPA COLLECTION KEYLOG FUNCTION T1056_001 {
  meta:
    description  = "log keystrokes (converted from capa rule)"
    namespace    = "collection/keylog"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Collection::Input Capture::Keylogging [T1056.001]"
    hash         = "C91887D861D9BD4A5872249B641BC9F9"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/keylog/log-keystrokes.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_brf = /\bSetWindowsHookEx(A|W)?\b/ ascii wide
    $api_brg = /\bGetKeyState(A|W)?\b/ ascii wide
    $api_brh = /\bRegisterHotKey(A|W)?\b/ ascii wide
    $api_bri = /\bUnregisterHotKey(A|W)?\b/ ascii wide
    $api_brj = /\bCallNextHookEx(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $api_brf
        and $api_brg
      )
      or (
        $api_brh
        and pe.imports(/user32/i, /keybd_event/)
        and $api_bri
      )
      or (
        $api_brj
        and pe.imports(/user32/i, /GetKeyNameText/)
        and pe.imports(/user32/i, /GetAsyncKeyState/)
        and pe.imports(/user32/i, /GetForgroundWindow/)
      )
      or pe.imports(/user32/i, /AttachThreadInput/)
      or pe.imports(/user32/i, /MapVirtualKey/)
    )
}

rule capa_capture_microphone_audio: CAPA COLLECTION MICROPHONE FUNCTION T1123 {
  meta:
    description  = "capture microphone audio (converted from capa rule)"
    namespace    = "collection/microphone"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Collection::Audio Capture [T1123]"
    hash         = "a70052c45e907820187c7e6bcdc7ecca"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/microphone/capture-microphone-audio.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_brk     = /\bmciSendString(A|W)?\b/ ascii wide
    $func_re_brl = /\x00open/ nocase ascii wide
    $func_re_brm = /waveaudio/ nocase ascii wide
    $func_re_brn = /\x00record/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $api_brk
      and $func_re_brl
      and $func_re_brm
      and $func_re_brn
    )
}

rule capa_get_domain_trust_relationships: CAPA COLLECTION NETWORK FUNCTION T1482 {
  meta:
    description  = "get domain trust relationships (converted from capa rule)"
    namespace    = "collection/network"
    author       = "johnk3r"
    scope        = "function"
    attack       = "Discovery::Domain Trust Discovery  [T1482]"
    hash         = "0796f1c1ea0a142fc1eb7109a44c86cb"
    hash         = "0731679c5f99e8ee65d8b29a3cabfc6b"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/network/get-domain-trust-relationships.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bro = /nltest/ nocase ascii wide
    $func_re_brp = /\/domain_trusts/ nocase ascii wide
    $func_re_brq = /\/dclist/ nocase ascii wide
    $func_re_brr = /\/all_trusts/ nocase ascii wide
    $api_brs     = /\bDsEnumerateDomainTrusts(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_bro
        and (
          $func_re_brp
          or $func_re_brq
          or $func_re_brr
        )
      )
      or $api_brs
    )
}

rule capa_capture_network_configuration_via_ipconfig: CAPA COLLECTION NETWORK BASICBLOCK T1016 {
  meta:
    description  = "capture network configuration via ipconfig (converted from capa rule)"
    namespace    = "collection/network"
    author       = "@_re_fox"
    scope        = "basic block"
    attack       = "Discovery::System Network Configuration Discovery [T1016]"
    hash         = "7204e3efc2434012e13ca939db0d0b02"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/network/capture-network-configuration-via-ipconfig.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_re_brt = /ipconfig(\.exe)?/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      $basic_re_brt
      and pe.imports(/msvcr100/i, /system/)
    )
}

rule capa_capture_public_ip: CAPA COLLECTION NETWORK FUNCTION T1016 {
  meta:
    description  = "capture public ip (converted from capa rule)"
    namespace    = "collection/network"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Discovery::System Network Configuration Discovery [T1016]"
    hash         = "84f1b049fa8962b215a77f51af6714b3"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/network/capture-public-ip.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_bru     = /\bInternetOpen(A|W)?\b/ ascii wide
    $api_brv     = /\bInternetOpenUrl(A|W)?\b/ ascii wide
    $api_brw     = /\bInternetReadFile(A|W)?\b/ ascii wide
    $func_re_brx = /bot\.whatismyipaddress\.com/ ascii wide
    $func_re_bry = /ipinfo\.io\/ip/ ascii wide
    $func_re_brz = /checkip\.dyndns\.org/ ascii wide
    $func_re_bsa = /ifconfig\.me/ ascii wide
    $func_re_bsb = /ipecho\.net\/plain/ ascii wide
    $func_re_bsc = /api\.ipify\.org/ ascii wide
    $func_re_bsd = /checkip\.amazonaws\.com/ ascii wide
    $func_re_bse = /icanhazip\.com/ ascii wide
    $func_re_bsf = /wtfismyip\.com\/text/ ascii wide
    $func_re_bsg = /api\.myip\.com/ ascii wide
    $func_re_bsh = /ip\-api\.com\/line/ ascii wide

  condition:
    capa_pe_file and
    (
      $api_bru
      and $api_brv
      and $api_brw
      and (
        $func_re_brx
        or $func_re_bry
        or $func_re_brz
        or $func_re_bsa
        or $func_re_bsb
        or $func_re_bsc
        or $func_re_bsd
        or $func_re_bse
        or $func_re_bsf
        or $func_re_bsg
        or $func_re_bsh
      )
    )
}

rule capa_gather_cuteftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather cuteftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-cuteftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bsi = /\\sm\.dat/ ascii wide
    $func_re_bsj = /\\GlobalSCAPE\\CuteFTP/ nocase ascii wide
    $func_re_bsk = /\\GlobalSCAPE\\CuteFTP Pro/ nocase ascii wide
    $func_re_bsl = /\\CuteFTP/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bsi
      and (
        $func_re_bsj
        or $func_re_bsk
        or $func_re_bsl
      )
    )
}

rule capa_gather_ftprush_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather ftprush information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftprush-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bsm = /\\FTPRush/ ascii wide
    $func_re_bsn = /RushSite\.xml/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bsm
      and $func_re_bsn
    )
}

rule capa_gather_smart_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather smart-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-smart-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bso  = /\\SmartFTP/ ascii wide
    $func_str_bsp = ".xml" ascii wide
    $func_re_bsq  = /Favorites\.dat/ nocase ascii wide
    $func_re_bsr  = /History\.dat/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_bso
        and $func_str_bsp
        and $func_re_bsq
        and $func_re_bsr
      )
    )
}

rule capa_gather_cyberduck_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather cyberduck information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-cyberduck-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bss  = /\\Cyberduck/ ascii wide
    $func_str_bst = "user.config" ascii wide
    $func_str_bsu = ".duck" ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bss
      and (
        $func_str_bst
        or $func_str_bsu
      )
    )
}

rule capa_gather_ws_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather ws-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ws-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bsv = /\\Ipswitch\\WS_FTP/ ascii wide
    $func_re_bsw = /\\win\.ini/ ascii wide
    $func_re_bsx = /WS_FTP/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bsv
      and $func_re_bsw
      and $func_re_bsx
    )
}

rule capa_gather_fling_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather fling-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-fling-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bsy  = /SOFTWARE\\NCH Software\\Fling\\Accounts/ ascii wide
    $func_str_bsz = "FtpPassword" ascii wide
    $func_str_bta = "_FtpPassword" ascii wide
    $func_str_btb = "FtpServer" ascii wide
    $func_str_btc = "FtpUserName" ascii wide
    $func_str_btd = "FtpDirectory" ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bsy
      or (
        $func_str_bsz
        and $func_str_bta
        and $func_str_btb
        and $func_str_btc
        and $func_str_btd
      )
    )
}

rule capa_gather_directory_opus_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather directory-opus information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-directory-opus-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bte  = /\\GPSoftware\\Directory Opus/ ascii wide
    $func_str_btf = ".oxc" ascii wide
    $func_str_btg = ".oll" ascii wide
    $func_str_bth = "ftplast.osd" ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bte
      and $func_str_btf
      and $func_str_btg
      and $func_str_bth
    )
}

rule capa_gather_coreftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather coreftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-coreftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bti  = /Software\\FTPWare\\COREFTP\\Sites/ ascii wide
    $func_str_btj = "Host" ascii wide
    $func_str_btk = "User" ascii wide
    $func_str_btl = "Port" ascii wide
    $func_str_btm = "PthR" ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bti
      or (
        $func_str_btj
        and $func_str_btk
        and $func_str_btl
        and $func_str_btm
      )
    )
}

rule capa_gather_wise_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather wise-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-wise-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_btn = "wiseftpsrvs.ini" ascii wide
    $func_str_bto = "wiseftp.ini" ascii wide
    $func_str_btp = "wiseftpsrvs.bin" ascii wide
    $func_str_btq = "wiseftpsrvs.bin" ascii wide
    $func_re_btr  = /\\AceBIT/ ascii wide
    $func_re_bts  = /Software\\AceBIT/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_str_btn
        and $func_str_bto
        and $func_str_btp
      )
      or (
        $func_str_btq
        and (
          $func_re_btr
          or $func_re_bts
        )
      )
    )
}

rule capa_gather_winzip_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather winzip information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-winzip-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_btt  = /Software\\Nico Mak Computing\\WinZip\\FTP/ ascii wide
    $func_re_btu  = /Software\\Nico Mak Computing\\WinZip\\mru\\jobs/ ascii wide
    $func_str_btv = "Site" ascii wide
    $func_str_btw = "UserID" ascii wide
    $func_str_btx = "xflags" ascii wide
    $func_str_bty = "Port" ascii wide
    $func_str_btz = "Folder" ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_btt
        and $func_re_btu
      )
      or (
        $func_str_btv
        and $func_str_btw
        and $func_str_btx
        and $func_str_bty
        and $func_str_btz
      )
    )
}

rule capa_gather_southriver_webdrive_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather southriver-webdrive information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-southriver-webdrive-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bua  = /Software\\South River Technologies\\WebDrive\\Connections/ ascii wide
    $func_str_bub = "PassWord" ascii wide
    $func_str_buc = "UserName" ascii wide
    $func_str_bud = "RootDirectory" ascii wide
    $func_str_bue = "Port" ascii wide
    $func_str_buf = "ServerType" ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bua
      or (
        $func_str_bub
        and $func_str_buc
        and $func_str_bud
        and $func_str_bue
        and $func_str_buf
      )
    )
}

rule capa_gather_freshftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather freshftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-freshftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bug = "FreshFTP" ascii wide
    $func_str_buh = ".SMF" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bug
      and $func_str_buh
    )
}

rule capa_gather_fasttrack_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather fasttrack-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-fasttrack-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bui = "FastTrack" ascii wide
    $func_str_buj = "ftplist.txt" ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_str_bui
        and $func_str_buj
      )
    )
}

rule capa_gather_classicftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather classicftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-classicftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_buk = /Software\\NCH Software\\ClassicFTP\\FTPAccounts/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_buk
    )
}

rule capa_gather_softx_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather softx-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-softx-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bul = /Software\\FTPClient\\Sites/ ascii wide
    $func_re_bum = /Software\\SoftX.org\\FTPClient\\Sites/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bul
      or $func_re_bum
    )
}

rule capa_gather_ffftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather ffftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ffftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bun  = /Software\\Sota\\FFFTP\\Options/ ascii wide
    $func_re_buo  = /Software\\Sota\\FFFTP/ ascii wide
    $func_re_bup  = /CredentialSalt/ ascii wide
    $func_re_buq  = /CredentialCheck/ ascii wide
    $func_str_bur = "Password" ascii wide
    $func_str_bus = "UserName" ascii wide
    $func_str_but = "HostAdrs" ascii wide
    $func_str_buu = "RemoteDir" ascii wide
    $func_str_buv = "Port" ascii wide

  condition:
    capa_pe_file and
    (
      (
        (
          $func_re_bun
          or $func_re_buo
        )
        and (
          $func_re_bup
          or $func_re_buq
        )
      )
      or (
        $func_str_bur
        and $func_str_bus
        and $func_str_but
        and $func_str_buu
        and $func_str_buv
      )
    )
}

rule capa_gather_ftpshell_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather ftpshell information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpshell-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_buw = "FTPShell" ascii wide
    $func_str_bux = "ftpshell.fsi" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_buw
      and $func_str_bux
    )
}

rule capa_gather_winscp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather winscp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-winscp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_buy = "Password" ascii wide
    $func_str_buz = "HostName" ascii wide
    $func_str_bva = "UserName" ascii wide
    $func_str_bvb = "RemoteDirectory" ascii wide
    $func_str_bvc = "PortNumber" ascii wide
    $func_str_bvd = "FSProtocol" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_buy
      and $func_str_buz
      and $func_str_bva
      and $func_str_bvb
      and $func_str_bvc
      and $func_str_bvd
    )
}

rule capa_gather_frigate3_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather frigate3 information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-frigate3-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bve = /FtpSite\.xml/ ascii wide
    $func_re_bvf = /\\Frigate3/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bve
      and $func_re_bvf
    )
}

rule capa_gather_staff_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather staff-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-staff-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bvg = "Staff-FTP" ascii wide
    $func_str_bvh = "sites.ini" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bvg
      and $func_str_bvh
    )
}

rule capa_gather_xftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather xftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-xftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bvi = ".xfp" ascii wide
    $func_re_bvj  = /\\NetSarang/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bvi
      and $func_re_bvj
    )
}

rule capa_gather_ftpnow_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather ftpnow information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpnow-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bvq = "FTPNow" ascii wide
    $func_str_bvr = "FTP Now" ascii wide
    $func_str_bvs = "sites.xml" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bvq
      and $func_str_bvr
      and $func_str_bvs
    )
}

rule capa_gather_ftpgetter_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather ftpgetter information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpgetter-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bvt = "servers.xml" ascii wide
    $func_re_bvu  = /\\FTPGetter/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bvt
      and $func_re_bvu
    )
}

rule capa_gather_nova_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather nova-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-nova-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bvv = "NovaFTP.db" ascii wide
    $func_re_bvw  = /\\INSoftware\\NovaFTP/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_str_bvv
        and $func_re_bvw
      )
    )
}

rule capa_gather_ftp_explorer_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather ftp-explorer information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftp-explorer-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bvx  = /profiles\.xml/ ascii wide
    $func_re_bvy  = /Software\\FTP Explorer\\FTP Explorer\\Workspace\\MFCToolBar-224/ ascii wide
    $func_re_bvz  = /Software\\FTP Explorer\\Profiles/ ascii wide
    $func_re_bwa  = /\\FTP Explorer/ ascii wide
    $func_str_bwb = "Password" ascii wide
    $func_str_bwc = "Host" ascii wide
    $func_str_bwd = "Login" ascii wide
    $func_str_bwe = "InitialPath" ascii wide
    $func_str_bwf = "PasswordType" ascii wide
    $func_str_bwg = "Port" ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_bvx
        and (
          $func_re_bvy
          or $func_re_bvz
          or $func_re_bwa
        )
      )
      or (
        $func_str_bwb
        and $func_str_bwc
        and $func_str_bwd
        and $func_str_bwe
        and $func_str_bwf
        and $func_str_bwg
      )
    )
}

rule capa_gather_bitkinex_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather bitkinex information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-bitkinex-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bwh = /bitkinex\.ds/ ascii wide
    $func_re_bwi = /\\BitKinex/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bwh
      and $func_re_bwi
    )
}

rule capa_gather_turbo_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather turbo-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-turbo-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bwj = "addrbk.dat" ascii wide
    $func_str_bwk = "quick.dat" ascii wide
    $func_re_bwl  = /installpath/ ascii wide
    $func_re_bwm  = /Software\\TurboFTP/ ascii wide
    $func_re_bwn  = /\\TurboFTP/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_str_bwj
        and $func_str_bwk
      )
      or (
        $func_re_bwl
        and (
          $func_re_bwm
          or $func_re_bwn
        )
      )
    )
}

rule capa_gather_nexusfile_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather nexusfile information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-nexusfile-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bwo = "NexusFile" ascii wide
    $func_str_bwp = "ftpsite.ini" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bwo
      and $func_str_bwp
    )
}

rule capa_gather_ftp_voyager_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather ftp-voyager information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftp-voyager-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bwq  = /\\RhinoSoft.com/ ascii wide
    $func_str_bwr = "FTPVoyager.ftp" ascii wide
    $func_str_bws = "FTPVoyager.qc" ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bwq
      and $func_str_bwr
      and $func_str_bws
    )
}

rule capa_gather_blazeftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather blazeftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-blazeftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bwt = "BlazeFtp" ascii wide
    $func_str_bwu = "site.dat" ascii wide
    $func_str_bwv = "LastPassword" ascii wide
    $func_str_bww = "LastAddress" ascii wide
    $func_str_bwx = "LastUser" ascii wide
    $func_str_bwy = "LastPort" ascii wide
    $func_re_bwz  = /Software\\FlashPeak\\BlazeFtp\\Settings/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bwt
      and $func_str_bwu
      and (
        $func_str_bwv
        or $func_str_bww
        or $func_str_bwx
        or $func_str_bwy
        or $func_re_bwz
      )
    )
}

rule capa_gather_ftp_commander_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather ftp-commander information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftp-commander-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bxa  = /FTP Navigator/ ascii wide
    $func_re_bxb  = /FTP Commander/ ascii wide
    $func_str_bxc = "ftplist.txt" ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_bxa
        or $func_re_bxb
      )
      and (
        $func_str_bxc
      )
    )
}

rule capa_gather_filezilla_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather filezilla information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-filezilla-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bxd  = /\\sitemanager\.xml/ ascii wide
    $func_re_bxe  = /\\recentservers\.xml/ ascii wide
    $func_re_bxf  = /\\filezilla.xml/ ascii wide
    $func_re_bxg  = /Software\\FileZilla/ ascii wide
    $func_str_bxh = "Install_Dir" ascii wide
    $func_re_bxi  = /Software\\FileZilla Client/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_bxd
        and $func_re_bxe
        and $func_re_bxf
      )
      or (
        $func_re_bxg
        and $func_str_bxh
        and $func_re_bxi
      )
    )
}

rule capa_gather_global_downloader_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather global-downloader information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-global-downloader-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bxj  = /\\Global Downloader/ ascii wide
    $func_str_bxk = "SM.arch" ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bxj
      and $func_str_bxk
    )
}

rule capa_gather_direct_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather direct-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-direct-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bxl  = /Software\\CoffeeCup Software\\Internet\\Profiles/ ascii wide
    $func_re_bxm  = /\\CoffeeCup Software/ ascii wide
    $func_str_bxn = "Password" ascii wide
    $func_str_bxo = "HostName" ascii wide
    $func_str_bxp = "Port" ascii wide
    $func_str_bxq = "Username" ascii wide
    $func_str_bxr = "HostDirName" ascii wide
    $func_str_bxs = "FTP destination server" ascii wide
    $func_str_bxt = "FTP destination user" ascii wide
    $func_str_bxu = "FTP destination password" ascii wide
    $func_str_bxv = "FTP destination port" ascii wide
    $func_str_bxw = "FTP destination catalog" ascii wide
    $func_str_bxx = "FTP profiles" ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bxl
      or $func_re_bxm
      or (
        $func_str_bxn
        and $func_str_bxo
        and $func_str_bxp
        and $func_str_bxq
        and $func_str_bxr
      )
      or (
        $func_str_bxs
        and $func_str_bxt
        and $func_str_bxu
        and $func_str_bxv
        and $func_str_bxw
        and $func_str_bxx
      )
    )
}

rule capa_gather_faststone_browser_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather faststone-browser information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-faststone-browser-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bxy  = /FastStone Browser/ ascii wide
    $func_str_bxz = "FTPList.db" ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bxy
      and $func_str_bxz
    )
}

rule capa_gather_ultrafxp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather ultrafxp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ultrafxp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bya = /UltraFXP/ ascii wide
    $func_re_byb = /\\sites\.xml/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_bya
      and $func_re_byb
    )
}

rule capa_gather_netdrive_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather netdrive information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-netdrive-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_byc = "NDSites.ini" ascii wide
    $func_re_byd  = /\\NetDrive/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_byc
      and $func_re_byd
    )
}

rule capa_gather_total_commander_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather total-commander information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-total-commander-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bye  = /Software\\Ghisler\\Total Commander/ ascii wide
    $func_re_byf  = /Software\\Ghisler\\Windows Commander/ ascii wide
    $func_str_byg = "FtpIniName" ascii wide
    $func_str_byh = "wcx_ftp.ini" ascii wide
    $func_re_byi  = /\\GHISLER/ ascii wide
    $func_str_byj = "InstallDir" ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_bye
        or $func_re_byf
      )
      and (
        $func_str_byg
        or $func_str_byh
        or $func_re_byi
        or $func_str_byj
      )
    )
}

rule capa_gather_ftpinfo_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather ftpinfo information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-ftpinfo-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_byk = "ServerList.xml" ascii wide
    $func_str_byl = "DataDir" ascii wide
    $func_re_bym  = /Software\\MAS-Soft\\FTPInfo\\Setup/ ascii wide
    $func_re_byn  = /FTPInfo/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_byk
      and $func_str_byl
      and (
        $func_re_bym
        or $func_re_byn
      )
    )
}

rule capa_gather_flashfxp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather flashfxp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-flashfxp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_byo = /Software\\FlashFXP/ ascii wide
    $func_re_byp = /DataFolder/ ascii wide
    $func_re_byq = /Install Path/ ascii wide
    $func_re_byr = /\\Sites.dat/ ascii wide
    $func_re_bys = /\\Quick.dat/ ascii wide
    $func_re_byt = /\\History.dat/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_byo
        and $func_re_byp
        and $func_re_byq
      )
      or (
        $func_re_byr
        and $func_re_bys
        and $func_re_byt
      )
    )
}

rule capa_gather_securefx_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather securefx information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-securefx-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_byu  = /\\Sessions/ ascii wide
    $func_str_byv = ".ini" ascii wide
    $func_re_byw  = /Config Path/ ascii wide
    $func_re_byx  = /_VanDyke\\Config\\Sessions/ ascii wide
    $func_re_byy  = /Software\\VanDyke\\SecureFX/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_byu
      and $func_str_byv
      and $func_re_byw
      and (
        $func_re_byx
        or $func_re_byy
      )
    )
}

rule capa_gather_robo_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather robo-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-robo-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_byz  = /SOFTWARE\\Robo-FTP/ ascii wide
    $func_re_bza  = /\\FTPServers/ ascii wide
    $func_re_bzb  = /FTP File/ ascii wide
    $func_str_bzc = "FTP Count" ascii wide
    $func_str_bzd = "Password" ascii wide
    $func_str_bze = "ServerName" ascii wide
    $func_str_bzf = "UserID" ascii wide
    $func_str_bzg = "PortNumber" ascii wide
    $func_str_bzh = "InitialDirectory" ascii wide
    $func_str_bzi = "ServerType" ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_byz
        and (
          $func_re_bza
          or $func_re_bzb
          or $func_str_bzc
        )
      )
      or (
        $func_str_bzd
        and $func_str_bze
        and $func_str_bzf
        and $func_str_bzg
        and $func_str_bzh
        and $func_str_bzi
      )
    )
}

rule capa_gather_bulletproof_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather bulletproof-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-bulletproof-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bzj = ".dat" ascii wide
    $func_str_bzk = ".bps" ascii wide
    $func_re_bzl  = /Software\\BPFTP\\Bullet Proof FTP\\Main/ ascii wide
    $func_re_bzm  = /Software\\BulletProof Software\\BulletProof FTP Client\\Main/ ascii wide
    $func_re_bzn  = /Software\\BulletProof Software\\BulletProof FTP Client\\Options/ ascii wide
    $func_re_bzo  = /Software\\BPFTP\\Bullet Proof FTP\\Options/ ascii wide
    $func_re_bzp  = /Software\\BPFTP/ ascii wide
    $func_str_bzq = "LastSessionFile" ascii wide
    $func_str_bzr = "SitesDir" ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_str_bzj
        and $func_str_bzk
      )
      or (
        (
          $func_re_bzl
          or $func_re_bzm
          or $func_re_bzn
          or $func_re_bzo
          or $func_re_bzp
        )
        and (
          $func_str_bzq
          or $func_str_bzr
        )
      )
    )
}

rule capa_gather_alftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather alftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-alftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bzs = "ESTdb2.dat" ascii wide
    $func_str_bzt = "QData.dat" ascii wide
    $func_re_bzu  = /\\Estsoft\\ALFTP/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bzs
      and $func_str_bzt
      and $func_re_bzu
    )
}

rule capa_gather_expandrive_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather expandrive information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-expandrive-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_bzv = /Software\\ExpanDrive\\Sessions/ ascii wide
    $func_re_bzw = /Software\\ExpanDrive/ ascii wide
    $func_re_bzx = /ExpanDrive_Home/ ascii wide
    $func_re_bzy = /\\drives\.js/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_re_bzv
        or $func_re_bzw
      )
      and (
        $func_re_bzx
        or $func_re_bzy
      )
    )
}

rule capa_gather_goftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather goftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-goftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_bzz = "GoFTP" ascii wide
    $func_str_caa = "Connections.txt" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_bzz
      and $func_str_caa
    )
}

rule capa_gather_3d_ftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 {
  meta:
    description  = "gather 3d-ftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-3d-ftp-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_cab = "3D-FTP" ascii wide
    $func_str_cac = "sites.ini" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_cab
      and $func_str_cac
    )
}

rule capa_reference_SQL_statements: CAPA COLLECTION DATABASE SQL FUNCTION T1213 {
  meta:
    description  = "reference SQL statements (converted from capa rule)"
    namespace    = "collection/database/sql"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    attack       = "Collection::Data from Information Repositories [T1213]"
    hash         = "5F66B82558CA92E54E77F216EF4C066C"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/database/sql/reference-sql-statements.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_cai = /SELECT.\\\{,1000\\\}FROM.\\\{,1000\\\}WHERE/ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_cai
    )
}

rule capa_reference_WMI_statements: CAPA COLLECTION DATABASE WMI FUNCTION T1213 {
  meta:
    description  = "reference WMI statements (converted from capa rule)"
    namespace    = "collection/database/wmi"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "function"
    attack       = "Collection::Data from Information Repositories [T1213]"
    hash         = "al-khaser_x86.exe_:0x433490"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/database/wmi/reference-wmi-statements.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_caj = /SELECT\s+\*\s+FROM\s+CIM_./ ascii wide
    $func_re_cak = /SELECT\s+\*\s+FROM\s+Win32_./ ascii wide
    $func_re_cal = /SELECT\s+\*\s+FROM\s+MSAcpi_./ ascii wide

  condition:
    capa_pe_file and
    (
      $func_re_caj
      or $func_re_cak
      or $func_re_cal
    )
}

rule capa_self_delete_via_COMSPEC_environment_variable: CAPA ANTI_ANALYSIS ANTI_FORENSIC SELF_DELETION FUNCTION T1070_004 F0007_001 {
  meta:
    description  = "self delete via COMSPEC environment variable (converted from capa rule)"
    namespace    = "anti-analysis/anti-forensic/self-deletion"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Indicator Removal on Host::File Deletion [T1070.004]"
    mbc          = "Defense Evasion::Self Deletion::COMSPEC Environment Variable [F0007.001]"
    hash         = "Practical Malware Analysis Lab 14-02.exe_:0x401880"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-forensic/self-deletion/self-delete-via-comspec-environment-variable.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_can = /\/c\s*del\s*/ ascii wide  // /c del

  condition:
    capa_pe_file and
    (
      capa_get_COMSPEC_environment_variable

      and capa_create_process

      and $func_re_can
    )
}

rule capa_check_for_windows_sandbox_via_process_name: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FUNCTION T1497_001 B0009 {
  meta:
    description  = "check for windows sandbox via process name (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    hash         = "773290480d5445f11d3dc1b800728966"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-process-name.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_caq = "CExecSvc.exe" ascii wide

  condition:
    capa_pe_file and
    (
      capa_enumerate_processes

      and $func_str_caq
    )
}

rule capa_get_CPU_information: CAPA HOST_INTERACTION HARDWARE CPU FUNCTION T1082 {
  meta:
    description  = "get CPU information (converted from capa rule)"
    namespace    = "host-interaction/hardware/cpu"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Discovery::System Information Discovery [T1082]"
    hash         = "BFB9B5391A13D0AFD787E87AB90F14F5"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/cpu/get-cpu-information.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_cbf = /Hardware\\Description\\System\\CentralProcessor/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      capa_query_or_enumerate_registry_value

      and $func_re_cbf
    )
}

rule capa_disable_code_signing: CAPA HOST_INTERACTION BOOTLOADER FUNCTION T1553_006 {
  meta:
    description  = "disable code signing (converted from capa rule)"
    namespace    = "host-interaction/bootloader"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Subvert Trust Controls::Code Signing Policy Modification [T1553.006]"
    hash         = "0596C4EA5AA8DEF47F22C85D75AACA95"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/bootloader/disable-code-signing.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_cbj = /\x00bcdedit(\.exe)? -set TESTSIGNING ON/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      capa_create_process

      and $func_re_cbj
    )
}

rule capa_find_taskbar: CAPA HOST_INTERACTION GUI TASKBAR FIND FUNCTION B0043 {
  meta:
    description  = "find taskbar (converted from capa rule)"
    namespace    = "host-interaction/gui/taskbar/find"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    mbc          = "Discovery::Taskbar Discovery [B0043]"
    hash         = "B7841B9D5DC1F511A93CC7576672EC0C"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/gui/taskbar/find/find-taskbar.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_cbk = "Shell_TrayWnd" ascii wide

  condition:
    capa_pe_file and
    (
      $func_str_cbk
      and capa_find_graphical_window

    )
}

rule capa_linked_against_Go_process_enumeration_library: CAPA HOST_INTERACTION PROCESS LIST FILE T1057 T1518 {
  meta:
    description  = "linked against Go process enumeration library (converted from capa rule)"
    namespace    = "host-interaction/process/list"
    description  = "Enumerating processes using a Go library"
    scope        = "file"
    attack       = "Discovery::Process Discovery [T1057]"
    attack       = "Discovery::Software Discovery [T1518]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-process-enumeration-library.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_cdv = "github.com/mitchellh/go-ps.FindProcess" ascii wide
    $file_str_cdw = "github.com/mitchellh/go-ps.Processes" ascii wide

  condition:
    capa_pe_file and
    (
      capa_compiled_with_Go

      and (
        $file_str_cdv
        or $file_str_cdw
      )
    )
}

rule capa_linked_against_Go_WMI_library: CAPA COLLECTION DATABASE WMI FILE T1213 {
  meta:
    description  = "linked against Go WMI library (converted from capa rule)"
    namespace    = "collection/database/wmi"
    description  = "StackExchange's WMI library is used to interact with WMI."
    scope        = "file"
    attack       = "Collection::Data from Information Repositories [T1213]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-wmi-library.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_cek = "github.com/StackExchange/wmi.CreateQuery" ascii wide
    $file_str_cel = "github.com/StackExchange/wmi.Query" ascii wide

  condition:
    capa_pe_file and
    (
      capa_compiled_with_Go

      and (
        $file_str_cek
        or $file_str_cel
      )
    )
}

rule capa_check_for_windows_sandbox_via_mutex: CAPA ANTI_ANALYSIS ANTI_VM VM_DETECTION FUNCTION T1497_001 B0009 {
  meta:
    description  = "check for windows sandbox via mutex (converted from capa rule)"
    namespace    = "anti-analysis/anti-vm/vm-detection"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Defense Evasion::Virtualization/Sandbox Evasion::System Checks [T1497.001]"
    mbc          = "Anti-Behavioral Analysis::Virtual Machine Detection [B0009]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/check-for-windows-sandbox-via-mutex.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_ceq = "WindowsSandboxMutex" ascii wide

  condition:
    capa_pe_file and
    (
      capa_check_mutex

      and $func_str_ceq
    )
}

rule capa_linked_against_Go_registry_library: CAPA HOST_INTERACTION REGISTRY FILE {
  meta:
    description  = "linked against Go registry library (converted from capa rule)"
    namespace    = "host-interaction/registry"
    description  = "Uses a Go library for interacting with the Windows registry."
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-registry-library.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_cer = "golang.org/x/sys/windows/registry.Key.Close" ascii wide
    $file_str_ces = "github.com/golang/sys/windows/registry.Key.Close" ascii wide

  condition:
    capa_pe_file and
    (
      capa_compiled_with_Go

      and (
        $file_str_cer
        or $file_str_ces
      )
    )
}

rule capa_capture_screenshot_in_Go: CAPA COLLECTION SCREENSHOT FILE T1113 E1113_m01 {
  meta:
    description  = "capture screenshot in Go (converted from capa rule)"
    namespace    = "collection/screenshot"
    description  = "Detects screenshot capability via WinAPI for Go files."
    scope        = "file"
    attack       = "Collection::Screen Capture [T1113]"
    mbc          = "Collection::Screen Capture::WinAPI [E1113.m01]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/capture-screenshot-in-go.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_cey = "syscall.NewLazyDLL" ascii wide  // Dynamic loading of DLLs
    $file_re_cez  = /user32.dll/ ascii wide
    $file_re_cfa  = /GetWindowDC/ ascii wide
    $file_re_cfb  = /GetDC/ ascii wide
    $file_re_cfc  = /gdi32.dll/ ascii wide
    $file_re_cfd  = /BitBlt/ ascii wide
    $file_re_cfe  = /GetDIBits/ ascii wide
    $file_re_cff  = /CreateCompatibleDC/ ascii wide

  condition:
    capa_pe_file and
    (
      capa_compiled_with_Go

      and (
        $file_str_cey
        and (
          (
            $file_re_cez
            and (
              $file_re_cfa
              or $file_re_cfb
            )
          )
          or (
            $file_re_cfc
            and (
              $file_re_cfd
              or $file_re_cfe
            )
          )
        )
        and $file_re_cff
      )
    )
}

rule capa_linked_against_Go_static_asset_library: CAPA EXECUTABLE RESOURCE FILE {
  meta:
    description  = "linked against Go static asset library (converted from capa rule)"
    namespace    = "executable/resource"
    description  = "Detects if the Go file includes an static assets."
    scope        = "file"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/linked-against-go-static-asset-library.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $file_str_cfh = "github.com/rakyll/statik/fs.IsDefaultNamespace" ascii wide
    $file_str_cfi = "github.com/rakyll/statik/fs.RegisterWithNamespace" ascii wide
    $file_str_cfj = "github.com/rakyll/statik/fs.NewWithNamespace" ascii wide
    $file_str_cfk = "github.com/rakyll/statik/fs.Register" ascii wide
    $file_str_cfl = "github.com/gobuffalo/packr.NewBox" ascii wide
    $file_str_cfm = "github.com/markbates/pkger.Open" ascii wide
    $file_str_cfn = "github.com/markbates/pkger.Include" ascii wide
    $file_str_cfo = "github.com/markbates/pkger.Parse" ascii wide
    $file_str_cfp = "github.com/GeertJohan/go.rice.FindBox" ascii wide
    $file_str_cfq = "github.com/GeertJohan/go.rice.MustFindBox" ascii wide
    $file_re_cfr  = /\/bindata\.go/ ascii wide  // go-bindata
    $file_re_cfs  = /\.Asset/ ascii wide
    $file_str_cft = "github.com/lu4p/binclude.Include" ascii wide
    $file_str_cfu = "github.com/omeid/go-resources" ascii wide
    $file_str_cfv = "github.com/pyros2097/go-embed" ascii wide

  condition:
    capa_pe_file and
    (
      capa_compiled_with_Go

      and (
        (
          $file_str_cfh
          or $file_str_cfi
          or $file_str_cfj
          or $file_str_cfk
        )
        or (
          $file_str_cfl
        )
        or (
          $file_str_cfm
          or $file_str_cfn
          or $file_str_cfo
        )
        or (
          $file_str_cfp
          or $file_str_cfq
        )
        or (
          $file_re_cfr
          and $file_re_cfs
        )
        or (
          $file_str_cft
        )
        or (
          $file_str_cfu
        )
        or (
          $file_str_cfv
        )
      )
    )
}

rule capa_send_HTTP_request: CAPA COMMUNICATION HTTP CLIENT FUNCTION C0002_003 {
  meta:
    description  = "send HTTP request (converted from capa rule)"
    namespace    = "communication/http/client"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    mbc          = "Communication::HTTP Communication::Send Request [C0002.003]"
    hash         = "BFB9B5391A13D0AFD787E87AB90F14F5"
    hash         = "6A352C3E55E8AE5ED39DC1BE7FB964B1"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/communication/http/client/send-http-request.yml"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_cgb = /HTTP/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      (
        (
          pe.imports(/wininet/i, /HttpOpenRequest/)
          or pe.imports(/wininet/i, /InternetConnect/)
        )
        and (
          pe.imports(/wininet/i, /HttpSendRequest/)
          or pe.imports(/wininet/i, /HttpSendRequestEx/)
        )
      )
      or (
        pe.imports(/winhttp/i, /WinHttpSendRequest/)
        and pe.imports(/winhttp/i, /WinHttpWriteData/)
      )
      or (
        capa_send_data_on_socket

        and $func_re_cgb
      )
    )
}

rule capa_create_container: CAPA HOST_INTERACTION CONTAINER DOCKER FUNCTION T1610 {
  meta:
    description  = "create container (converted from capa rule)"
    namespace    = "host-interaction/container/docker"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    attack       = "Execution::Deploy Container [T1610]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/create-container.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_cjk = /\x00docker(\.exe)? create/ ascii wide
    $func_re_cjl = /\x00docker(\.exe)? start/ ascii wide
    $func_re_cjm = /\/v1\.[0-9]{1,2}\/containers\/create/ ascii wide  // docker API endpoint, e.g., /v1.24/containers/create
    $func_re_cjn = /\/v1\.[0-9]{1,2}\/containers\/[0-9a-fA-F]+\/start/ ascii wide  // docker API endpoint, e.g., /v1.24/containers/e90e34656806/start

  condition:
    capa_pe_file and
    (
      $func_re_cjk
      or $func_re_cjl
      or (
        capa_send_HTTP_request

        and $func_re_cjm
      )
      or (
        capa_send_HTTP_request

        and $func_re_cjn
      )
    )
}

rule capa_list_containers: CAPA HOST_INTERACTION CONTAINER DOCKER FUNCTION T1613 {
  meta:
    description  = "list containers (converted from capa rule)"
    namespace    = "host-interaction/container/docker"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    attack       = "Discovery::Container and Resource Discovery [T1613]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/list-containers.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_cjs = /\x00docker(\.exe)? ps/ ascii wide
    $func_re_cjt = /\/v1\.[0-9]{1,2}\/containers\/json/ ascii wide  // docker API endpoint, e.g., /v1.24/containers/json?all=1&before=8dfafdbc3a40&size=1

  condition:
    capa_pe_file and
    (
      $func_re_cjs
      or (
        capa_send_HTTP_request

        and $func_re_cjt
      )
    )
}

rule capa_build_Docker_image: CAPA HOST_INTERACTION CONTAINER DOCKER FUNCTION T1612 {
  meta:
    description  = "build Docker image (converted from capa rule)"
    namespace    = "host-interaction/container/docker"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    attack       = "Defense Evasion::Build Image on Host [T1612]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/build-docker-image.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_ckj = /\x00docker(\.exe)? build/ ascii wide
    $func_re_ckk = /\/v1\.[0-9]{1,2}\/build/ ascii wide  // docker API endpoint, e.g., /v1.24/build

  condition:
    capa_pe_file and
    (
      $func_re_ckj
      or (
        capa_send_HTTP_request

        and $func_re_ckk
      )
    )
}

rule capa_run_in_container: CAPA HOST_INTERACTION CONTAINER DOCKER FUNCTION T1609 {
  meta:
    description  = "run in container (converted from capa rule)"
    namespace    = "host-interaction/container/docker"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    attack       = "Execution::Container Administration Command [T1609]"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/run-in-container.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_ckl = /\x00docker(\.exe)? exec/ ascii wide
    $func_re_ckm = /\x00kubectl(\.exe)? exec/ ascii wide
    $func_re_ckn = /\x00kubectl(\.exe)? run/ ascii wide
    $func_re_cko = /\/v1\.[0-9]{1,2}\/containers\/[0-9a-fA-F]+\/exec/ ascii wide  // docker API endpoint, e.g., /v1.24/containers/e90e34656806/exec
    $func_re_ckp = /\/v1\.[0-9]{1,2}\/exec\/[0-9a-fA-F]+\/start/ ascii wide  // docker API endpoint, e.g., /v1.24/exec/e90e34656806/start

  condition:
    capa_pe_file and
    (
      $func_re_ckl
      or $func_re_ckm
      or $func_re_ckn
      or (
        capa_send_HTTP_request

        and $func_re_cko
      )
      or (
        capa_send_HTTP_request

        and $func_re_ckp
      )
    )
}

rule capa_send_HTTP_request_with_Host_header: CAPA COMMUNICATION HTTP FUNCTION {
  meta:
    description  = "send HTTP request with Host header (converted from capa rule)"
    namespace    = "communication/http"
    author       = "anamaria.martinezgom@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/send-http-request-with-host-header.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_ckq = /Host:/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      capa_send_HTTP_request

      and $func_re_ckq
    )
}

rule capa_make_an_HTTP_request_with_a_Cookie: CAPA COMMUNICATION HTTP CLIENT FUNCTION {
  meta:
    description  = "make an HTTP request with a Cookie (converted from capa rule)"
    namespace    = "communication/http/client"
    author       = "anamaria.martinezgom@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/make-an-http-request-with-a-cookie.yml"
    capa_nursery = "True"
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_ckx = /Cookie:/ nocase ascii wide

  condition:
    capa_pe_file and
    (
      capa_send_HTTP_request

      and $func_re_ckx
    )
}

rule capa_delete_file: CAPA HOST_INTERACTION FILE_SYSTEM DELETE FUNCTION C0047 INCOMPLETE {
  meta:
    description  = "delete file (converted from capa rule)"
    namespace    = "host-interaction/file-system/delete"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    mbc          = "File System::Delete File [C0047]"
    hash         = "946A99F36A46D335DEC080D9A4371940"
    hash         = "563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/delete/delete-file.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_cqg = /\bDeleteFileTransacted(A|W)?\b/ ascii wide
    $api_cqh = /\bNtDeleteFile(A|W)?\b/ ascii wide
    $api_cqi = /\bZwDeleteFile(A|W)?\b/ ascii wide
    $api_cqj = /\bremove(A|W)?\b/ ascii wide
    $api_cqk = /\b_wremove(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      pe.imports(/kernel32/i, /DeleteFile/)
      or $api_cqg
      or $api_cqh
      or $api_cqi
      or $api_cqj
      or $api_cqk
    )
}

rule capa_copy_file: CAPA HOST_INTERACTION FILE_SYSTEM COPY FUNCTION C0045 INCOMPLETE {
  meta:
    description  = "copy file (converted from capa rule)"
    namespace    = "host-interaction/file-system/copy"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    mbc          = "File System::Copy File [C0045]"
    hash         = "Practical Malware Analysis Lab 01-01.exe_:0x401440"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/file-system/copy/copy-file.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_cqm = /\bCopyFile2(A|W)?\b/ ascii wide
    $api_cqn = /\bCopyFileTransacted(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      pe.imports(/kernel32/i, /CopyFile/)
      or pe.imports(/kernel32/i, /CopyFileEx/)
      or $api_cqm
      or $api_cqn
    )
}

rule capa_get_disk_size: CAPA HOST_INTERACTION HARDWARE STORAGE FUNCTION T1082 INCOMPLETE {
  meta:
    description  = "get disk size (converted from capa rule)"
    namespace    = "host-interaction/hardware/storage"
    author       = "michael.hunhoff@fireeye.com"
    scope        = "function"
    attack       = "Discovery::System Information Discovery [T1082]"
    hash         = "al-khaser_x86.exe_:0x4343D0"
    hash         = "al-khaser_x86.exe_:0x434010"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/hardware/storage/get-disk-size.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_cqt  = /SELECT\s+\*\s+FROM\s+Win32_LogicalDisk/ nocase ascii wide
    $func_re_cqu  = /SELECT\s+\*\s+FROM\s+Win32_DiskDrive\s+WHERE\s+\(SerialNumber\s+IS\s+NOT\s+NULL\)\s+AND\s+\(MediaType\s+LIKE\s+\'Fixed\s+hard\s+disk\%\'\)/ nocase ascii wide
    $func_str_cqv = "Size" ascii wide

  condition:
    capa_pe_file and
    (
      pe.imports(/kernel32/i, /GetDiskFreeSpace/)
      or pe.imports(/kernel32/i, /GetDiskFreeSpaceEx/)
      or (
        (
          $func_re_cqt
          or $func_re_cqu
        )
        and $func_str_cqv
      )
    )
}

rule capa_interact_with_driver_via_control_codes: CAPA HOST_INTERACTION DRIVER FUNCTION T1569_002 INCOMPLETE {
  meta:
    description  = "interact with driver via control codes (converted from capa rule)"
    namespace    = "host-interaction/driver"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Execution::System Services::Service Execution [T1569.002]"
    hash         = "Practical Malware Analysis Lab 10-03.exe_:0x401000"
    hash         = "9412A66BC81F51A1FA916AC47C77E02AC1A7C9DFF543233ED70AA265EF6A1E76"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/driver/interact-with-driver-via-control-codes.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_cqw = /\bDeviceIoControl(A|W)?\b/ ascii wide
    $api_cqx = /\bNtUnloadDriver(A|W)?\b/ ascii wide
    $api_cqy = /\bZwUnloadDriver(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      $api_cqw
      or $api_cqx
      or $api_cqy
    )
}

rule capa_get_local_IPv4_addresses: CAPA HOST_INTERACTION NETWORK ADDRESS FUNCTION T1016 INCOMPLETE {
  meta:
    description  = "get local IPv4 addresses (converted from capa rule)"
    namespace    = "host-interaction/network/address"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Discovery::System Network Configuration Discovery [T1016]"
    hash         = "Practical Malware Analysis Lab 05-01.dll_:0x100037e6"
    hash         = "4C0553285D724DCAF5909924B4E3E90A"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/host-interaction/network/address/get-local-ipv4-addresses.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_crb = /\bGetAdaptersAddresses(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      (
        $api_crb
      )
    )
}

rule capa_encrypt_data_using_Sosemanuk: CAPA DATA_MANIPULATION ENCRYPTION SOSEMANUK BASICBLOCK T1027 E1027_m05 C0027_008 INCOMPLETE {
  meta:
    description  = "encrypt data using Sosemanuk (converted from capa rule)"
    namespace    = "data-manipulation/encryption/sosemanuk"
    author       = "@recvfrom"
    description  = "Looks for cryptographic constants associated with the Sosemanuk stream cipher"
    scope        = "basic block"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
    mbc          = "Cryptography::Encrypt Data::Sosemanuk [C0027.008]"
    hash         = "ea7bb99e03606702c1cbe543bb32b27e"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/sosemanuk/encrypt-data-using-sosemanuk.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_crf = { 00 00 00 00 E1 9F CF 13 6B 97 37 26 8A 08 F8 35 D6 87 6E 4C 37 18 A1 5F BD 10 59 6A 5C 8F 96 79 05 A7 DC 98 E4 38 13 8B 6E 30 EB BE 8F AF 24 AD D3 20 B2 D4 32 BF 7D C7 B8 B7 85 F2 59 28 4A E1 0A E7 11 99 EB 78 DE 8A 61 70 26 BF 80 EF E9 AC DC 60 7F D5 3D FF B0 C6 B7 F7 48 F3 56 68 87 E0 0F 40 CD 01 EE DF 02 12 64 D7 FA 27 85 48 35 34 D9 C7 A3 4D 38 58 6C 5E B2 50 94 6B 53 CF 5B 78 }  // mul_a
    $basic_crg = { 00 00 00 00 13 CF 9F E1 26 37 97 6B 35 F8 08 8A 4C 6E 87 D6 5F A1 18 37 6A 59 10 BD 79 96 8F 5C 98 DC A7 05 8B 13 38 E4 BE EB 30 6E AD 24 AF 8F D4 B2 20 D3 C7 7D BF 32 F2 85 B7 B8 E1 4A 28 59 99 11 E7 0A 8A DE 78 EB BF 26 70 61 AC E9 EF 80 D5 7F 60 DC C6 B0 FF 3D F3 48 F7 B7 E0 87 68 56 01 CD 40 0F 12 02 DF EE 27 FA D7 64 34 35 48 85 4D A3 C7 D9 5E 6C 58 38 6B 94 50 B2 78 5B CF 53 }  // mul_a_4byte_array_le
    $basic_crh = { 00 00 00 00 18 0F 40 CD 30 1E 80 33 28 11 C0 FE 60 3C A9 66 78 33 E9 AB 50 22 29 55 48 2D 69 98 C0 78 FB CC D8 77 BB 01 F0 66 7B FF E8 69 3B 32 A0 44 52 AA B8 4B 12 67 90 5A D2 99 88 55 92 54 29 F0 5F 31 31 FF 1F FC 19 EE DF 02 01 E1 9F CF 49 CC F6 57 51 C3 B6 9A 79 D2 76 64 61 DD 36 A9 E9 88 A4 FD F1 87 E4 30 D9 96 24 CE C1 99 64 03 89 B4 0D 9B 91 BB 4D 56 B9 AA 8D A8 A1 A5 CD 65 }  // mul_ia
    $basic_cri = { 00 00 00 00 CD 40 0F 18 33 80 1E 30 FE C0 11 28 66 A9 3C 60 AB E9 33 78 55 29 22 50 98 69 2D 48 CC FB 78 C0 01 BB 77 D8 FF 7B 66 F0 32 3B 69 E8 AA 52 44 A0 67 12 4B B8 99 D2 5A 90 54 92 55 88 31 5F F0 29 FC 1F FF 31 02 DF EE 19 CF 9F E1 01 57 F6 CC 49 9A B6 C3 51 64 76 D2 79 A9 36 DD 61 FD A4 88 E9 30 E4 87 F1 CE 24 96 D9 03 64 99 C1 9B 0D B4 89 56 4D BB 91 A8 8D AA B9 65 CD A5 A1 }  // mul_ia_4byte_array_le

  condition:
    capa_pe_file and
    (
      $basic_crf
      or $basic_crg
      or $basic_crh
      or $basic_cri
    )
}

rule capa_encrypt_data_using_DES: CAPA DATA_MANIPULATION ENCRYPTION DES BASICBLOCK T1027 E1027_m05 C0027_004 INCOMPLETE {
  meta:
    description  = "encrypt data using DES (converted from capa rule)"
    namespace    = "data-manipulation/encryption/des"
    author       = "@_re_fox"
    scope        = "basic block"
    attack       = "Defense Evasion::Obfuscated Files or Information [T1027]"
    mbc          = "Defense Evasion::Obfuscated Files or Information::Encryption-Standard Algorithm [E1027.m05]"
    mbc          = "Cryptography::Encrypt Data::3DES [C0027.004]"
    hash         = "91a12a4cf437589ba70b1687f5acad19"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/encryption/des/encrypt-data-using-des.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_crj = { 0E 04 0D 01 02 0F 0B 08 03 0A 06 0C 05 09 00 07 00 0F 07 04 0E 02 0D 01 0A 06 0C 0B 09 05 03 08 04 01 0E 08 0D 06 02 0B 0F 0C 09 07 03 0A 05 00 0F 0C 08 02 04 09 01 07 05 0B 03 0E 0A 00 06 0D }  // SBOX S1
    $basic_crk = { 0F 01 08 0E 06 0B 03 04 09 07 02 0D 0C 00 05 0A 03 0D 04 07 0F 02 08 0E 0C 00 01 0A 06 09 0B 05 00 0E 07 0B 0A 04 0D 01 05 08 0C 06 09 03 02 0F 0D 08 0A 01 03 0F 04 02 0B 06 07 0C 00 05 0E 09 }  // SBOX S2
    $basic_crl = { 0A 00 09 0E 06 03 0F 05 01 0D 0C 07 0B 04 02 08 0D 07 00 09 03 04 06 0A 02 08 05 0E 0C 0B 0F 01 0D 06 04 09 08 0F 03 00 0B 01 02 0C 05 0A 0E 07 01 0A 0D 00 06 09 08 07 04 0F 0E 03 0B 05 02 0C }  // SBOX S3
    $basic_crm = { 07 0D 0E 03 00 06 09 0A 01 02 08 05 0B 0C 04 0F 0D 08 0B 05 06 0F 00 03 04 07 02 0C 01 0A 0E 09 0A 06 09 00 0C 0B 07 0D 0F 01 03 0E 05 02 08 04 03 0F 00 06 0A 01 0D 08 09 04 05 0B 0C 07 02 0E }  // SBOX S4
    $basic_crn = { 02 0C 04 01 07 0A 0B 06 08 05 03 0F 0D 00 0E 09 0E 0B 02 0C 04 07 0D 01 05 00 0F 0A 03 09 08 06 04 02 01 0B 0A 0D 07 08 0F 09 0C 05 06 03 00 0E 0B 08 0C 07 01 0E 02 0D 06 0F 00 09 0A 04 05 03 }  // SBOX S5
    $basic_cro = { 0C 01 0A 0F 09 02 06 08 00 0D 03 04 0E 07 05 0B 0A 0F 04 02 07 0C 09 05 06 01 0D 0E 00 0B 03 08 09 0E 0F 05 02 08 0C 03 07 00 04 0A 01 0D 0B 06 04 03 02 0C 09 05 0F 0A 0B 0E 01 07 06 00 08 0D }  // SBOX S6
    $basic_crp = { 04 0B 02 0E 0F 00 08 0D 03 0C 09 07 05 0A 06 01 0D 00 0B 07 04 09 01 0A 0E 03 05 0C 02 0F 08 06 01 04 0B 0D 0C 03 07 0E 0A 0F 06 08 00 05 09 02 06 0B 0D 08 01 04 0A 07 09 05 00 0F 0E 02 03 0C }  // SBOX S7
    $basic_crq = { 0D 02 08 04 06 0F 0B 01 0A 09 03 0E 05 00 0C 07 01 0F 0D 08 0A 03 07 04 0C 05 06 0B 00 0E 09 02 07 0B 04 01 09 0C 0E 02 00 06 0A 0D 0F 03 05 08 02 01 0E 07 04 0A 08 0D 0F 0C 09 00 03 05 06 0B }  // SBOX S8
    $basic_crr = { 39 31 29 21 19 11 09 01 3A 32 2A 22 1A 12 0A 02 3B 33 2B 23 1B 13 0B 03 3C 34 2C 24 3F 37 2F 27 1F 17 0F 07 3E 36 2E 26 1E 16 0E 06 3D 35 2D 25 1D 15 0D 05 1C 14 0C 04 }  // PC1
    $basic_crs = { 0E 11 0B 18 01 05 03 1C 0F 06 15 0A 17 13 0C 04 1A 08 10 07 1B 14 0D 02 29 34 1F 25 2F 37 1E 28 33 2D 21 30 2C 31 27 38 22 35 2E 2A 32 24 1D 20 }  // PC2
    $basic_crt = { 3A 32 2A 22 1A 12 0A 02 3C 34 2C 24 1C 14 0C 04 3E 36 2E 26 1E 16 0E 06 40 38 30 28 20 18 10 08 39 31 29 21 19 11 09 01 3B 33 2B 23 1B 13 0B 03 3D 35 2D 25 1D 15 0D 05 3F 37 2F 27 1F 17 0F 07 }  // Initial Permutation
    $basic_cru = { 28 08 30 10 38 18 40 20 27 07 2F 0F 37 17 3F 1F 26 06 2E 0E 36 16 3E 1E 25 05 2D 0D 35 15 3D 1D 24 04 2C 0C 34 14 3C 1C 23 03 2B 0B 33 13 3B 1B 22 02 2A 0A 32 12 3A 1A 21 01 29 09 31 11 39 19 }  // Final Permutation
    $basic_crv = { 20 01 02 03 04 05 04 05 06 07 08 09 08 09 0A 0B 0C 0D 0C 0D 0E 0F 10 11 10 11 12 13 14 15 14 15 16 17 18 19 18 19 1A 1B 1C 1D 1C 1D 1E 1F 20 01 }  // DES Expansion
    $basic_crw = { 10 07 14 15 1D 0C 1C 11 01 0F 17 1A 05 12 1F 0A 02 08 18 0E 20 1B 03 09 13 0D 1E 06 16 0B 04 19 }  // PBOX

  condition:
    capa_pe_file and
    (
      $basic_crj
      or $basic_crk
      or $basic_crl
      or $basic_crm
      or $basic_crn
      or $basic_cro
      or $basic_crp
      or $basic_crq
      or $basic_crr
      or $basic_crs
      or $basic_crt
      or $basic_cru
      or $basic_crv
      or $basic_crw
    )
}

rule capa_hash_data_with_CRC32: CAPA DATA_MANIPULATION CHECKSUM CRC32 FUNCTION C0032_001 INCOMPLETE {
  meta:
    description  = "hash data with CRC32 (converted from capa rule)"
    namespace    = "data-manipulation/checksum/crc32"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    mbc          = "Data::Checksum::CRC32 [C0032.001]"
    hash         = "7D28CB106CB54876B2A5C111724A07CD"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/checksum/crc32/hash-data-with-crc32.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_csb = /\bRtlComputeCrc32(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      $api_csb
    )
}

rule capa_hash_data_using_SHA1: CAPA DATA_MANIPULATION HASHING SHA1 FUNCTION C0029_002 INCOMPLETE {
  meta:
    description  = "hash data using SHA1 (converted from capa rule)"
    namespace    = "data-manipulation/hashing/sha1"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    mbc          = "Cryptography::Cryptographic Hash::SHA1 [C0029.002]"
    hash         = "D063B1804E8D2BB26BD2E097141C1BBC"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/sha1/hash-data-using-sha1.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    // Magic initialization constants used in SHA1
    $num_csc = { 01 23 45 67 }  // A, also used by MD5
    $num_csd = { 89 AB CD EF }  // B, also used by MD5
    $num_cse = { FE DC BA 98 }  // C, also used by MD5
    $num_csf = { 76 54 32 10 }  // D, also used by MD5
    $num_csg = { F0 E1 D2 C3 }  // specific to SHA1, not MD4 nor MD5

  condition:
    capa_pe_file and
    (
      (
        $num_csc
        and $num_csd
        and $num_cse
        and $num_csf
        and $num_csg
      )
    )
}

rule capa_hash_data_using_tiger: CAPA DATA_MANIPULATION HASHING TIGER BASICBLOCK C0029_005 INCOMPLETE {
  meta:
    description  = "hash data using tiger (converted from capa rule)"
    namespace    = "data-manipulation/hashing/tiger"
    author       = "@_re_fox"
    scope        = "basic block"
    mbc          = "Cryptography::Cryptographic Hash::Tiger [C0029.005]"
    hash         = "0761142efbda6c4b1e801223de723578"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/tiger/hash-data-using-tiger.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $basic_csi = { 5E 0C E9 F7 7C B1 AA 02 EC A8 43 E2 03 4B 42 AC D3 FC D5 0D E3 5B CD 72 3A 7F F9 F6 93 9B 01 6D 93 91 1F D2 FF 78 99 CD E2 29 80 70 C9 A1 73 75 C3 83 2A 92 6B 32 64 B1 70 58 91 04 EE 3E 88 46 E6 EC 03 71 05 E3 AC EA 5C 53 A3 08 B8 69 41 C5 7C C4 DE 8D 91 54 E7 4C 0C F4 0D DC DF F4 A2 0A FA BE 4D A7 18 6F B7 10 6A AB D1 5A 23 B6 CC C6 FF E2 2F 57 21 61 72 13 1E 92 9D 19 6F 8C 48 1A CA 07 00 DA F4 F9 C9 4B C7 41 52 E8 F6 E6 F5 26 B6 47 59 EA DB 79 90 85 92 8C 9E C9 C5 85 18 4F 4B 86 6F A9 1E 76 8E D7 7D C1 B5 }  // sbox1
    $basic_csj = { 38 21 A1 05 5A BE A6 E6 98 7C F8 B4 A5 22 A1 B5 90 69 0B 14 89 60 3C 56 D5 5D 1F 39 2E CB 46 4C 34 94 B7 C9 DB AD 32 D9 F5 AF 15 20 E4 70 EA 08 F1 8C 47 3E 67 A6 65 D7 99 8D 27 AB 7E 75 FB C4 92 06 6E 2D 86 C6 11 DF 16 3B 7F 0D F1 84 EB DD 04 EA 65 A6 04 F6 2E 6F B3 DF E0 F0 0F 0F 8E 4A 51 BA BC 3D F8 EE ED A5 1E 37 A4 0E 2A 0A 4F FC 29 84 B3 5C A8 1D 3E E8 E2 1C 1B BA 82 F8 8F DC 0D E8 53 83 5E 50 45 CD 17 07 DB D4 00 9A D1 18 01 81 F3 A5 ED CF A0 34 F2 CA 87 88 51 7E E7 0B 36 51 C4 B3 38 14 34 1E F9 CC 89 }  // sbox2
    $basic_csk = { 9B F3 DA F1 2F CC 9F F4 81 92 F2 6F C6 D5 7F 48 3F A8 DC FC 67 06 A3 E8 63 CE FC D2 E3 4B 9B 2C C2 BB FB 93 4B F7 3F DA 66 BA 70 FE D2 65 A1 2F D4 93 0E 97 79 E2 03 A1 71 5E E4 B0 77 EC CD BE 97 E4 85 39 72 1E B4 CF 17 50 F7 5E 02 AA 0A B7 E0 B8 40 38 F0 09 23 D4 79 85 89 35 D0 1A FC 8E C5 AB B2 E2 0B 92 C6 96 72 91 5A 37 63 41 AF 66 FB 27 71 CA DC AB 74 21 41 FF 72 4A A6 CE 3C B3 A5 66 30 08 33 49 4A F0 F5 9A 28 D7 CD 0A 97 8D 5E C2 C8 31 E0 E8 96 8F 47 5D 87 76 22 C0 FE F3 DD 90 61 05 10 F3 7B EC 91 14 0F }  // sbox3
    $basic_csl = { 55 3C 32 26 85 60 0E 5B F5 59 1B FA A9 C1 46 1A FA 8F 4C 7C A1 45 E2 A9 D7 55 29 DB 59 51 CA 65 C2 AF 35 CE 76 0A DB 05 45 3D 11 A9 7E C7 EA 81 0D 0A AC B6 8A F8 8E 52 FF E3 7B 59 53 A2 9E A0 56 CD 48 AC B3 DF 0D 43 6F E4 5C F4 7A A6 B3 C4 5E D0 E2 FB D8 CF CE 4E F0 35 99 B3 10 6F F5 3E C6 19 D6 9C 82 D6 22 0B 69 20 DF 74 0A 46 FD 17 40 ED 10 85 8E CC F8 6C A7 CA 6E 3A BF 24 C8 D6 49 70 81 1A 58 3D 24 61 A2 63 C1 BB B6 AC 8B 04 32 CC 44 7D C2 8A A3 D9 AB 10 F4 AA 5B FF DD 7F 4B 82 04 A8 5A 49 6D AD 94 9F 8C }  // sbox4

  condition:
    capa_pe_file and
    (
      $basic_csi
      or $basic_csj
      or $basic_csk
      or $basic_csl
    )
}

rule capa_hash_data_using_murmur3: CAPA DATA_MANIPULATION HASHING MURMUR FUNCTION C0030_001 INCOMPLETE {
  meta:
    description  = "hash data using murmur3 (converted from capa rule)"
    namespace    = "data-manipulation/hashing/murmur"
    author       = "william.ballenthin@fireeye.com"
    scope        = "function"
    mbc          = "Data::Non-Cryptographic Hash::MurmurHash [C0030.001]"
    hash         = "c66172b12971a329f8d5ff01665f204b"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/data-manipulation/hashing/murmur/hash-data-using-murmur3.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $num_cso = { 6B CA EB 85 }  // 32-bit finalization mix constant 1
    $num_csp = { 35 AE B2 C2 }  // 32-bit finalization mix constant 2
    $num_csq = { CD 8C 55 ED D7 AF 51 FF }  // 64-bit finalization mix constant 1
    $num_csr = { 53 EC 85 1A FE B9 CE C4 }  // 64-bit finalization mix constant 2
    $num_css = { 51 2D 9E CC }  // c1 32-bit hash
    $num_cst = { 93 35 87 1B }  // c2 32-bit hash
    $num_csu = { 1B 96 9B 23 }  // 32-bit c1 for 128-bit hash
    $num_csv = { 89 97 0E AB }  // 32-bit c2 for 128-bit hash
    $num_csw = { E5 4A B3 38 }  // 32-bit c3 for 128-bit hash
    $num_csx = { 93 8B E3 A1 }  // 32-bit c4 for 128-bit hash
    $num_csy = { D5 53 42 11 91 7B C3 87 }  // 64-bit c1 for 128-bit hash
    $num_csz = { 7F 93 45 27 43 AD F5 4C }  // 64-bit c2 for 128-bit hash

  condition:
    capa_pe_file and
    (
      (
        $num_cso
        and $num_csp
      )
      or (
        $num_csq
        and $num_csr
      )
      or (
        $num_css
        and $num_cst
      )
      or (
        $num_csu
        and $num_csv
        and $num_csw
        and $num_csx
      )
      or (
        $num_csy
        and $num_csz
      )
    )
}

rule capa_persist_via_Windows_service: CAPA PERSISTENCE SERVICE FUNCTION T1543_003 T1569_002 INCOMPLETE {
  meta:
    description  = "persist via Windows service (converted from capa rule)"
    namespace    = "persistence/service"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    attack       = "Persistence::Create or Modify System Process::Windows Service [T1543.003]"
    attack       = "Execution::System Services::Service Execution [T1569.002]"
    hash         = "Practical Malware Analysis Lab 03-02.dll_:0x10004706"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/persistence/service/persist-via-windows-service.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_re_ctc = /\x00sc(\.exe)?$/ nocase ascii wide
    $func_re_ctd = /create / nocase ascii wide
    $func_re_cte = /\x00sc(\.exe)? create/ nocase ascii wide
    $func_re_ctf = /New-Service / nocase ascii wide

  condition:
    capa_pe_file and
    (
      (
        capa_create_process

        and (
          (
            $func_re_ctc
            and $func_re_ctd
          )
          or $func_re_cte
          or $func_re_ctf
        )
      )
    )
}

rule capa_move_file: CAPA HOST_INTERACTION FILE_SYSTEM MOVE FUNCTION INCOMPLETE {
  meta:
    description  = "move file (converted from capa rule)"
    namespace    = "host-interaction/file-system/move"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/move-file.yml"
    capa_nursery = "True"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $api_ctq = /\bMoveFileWithProgress(A|W)?\b/ ascii wide
    $api_ctr = /\bMoveFileTransacted(A|W)?\b/ ascii wide
    $api_cts = /\brename(A|W)?\b/ ascii wide
    $api_ctt = /\b_wrename(A|W)?\b/ ascii wide

  condition:
    capa_pe_file and
    (
      pe.imports(/kernel32/i, /MoveFile/)
      or pe.imports(/kernel32/i, /MoveFileEx/)
      or $api_ctq
      or $api_ctr
      or $api_cts
      or $api_ctt
    )
}

rule capa_hash_data_with_MD5: CAPA DATA_MANIPULATION HASHING MD5 FUNCTION INCOMPLETE {
  meta:
    description  = "hash data with MD5 (converted from capa rule)"
    namespace    = "data-manipulation/hashing/md5"
    author       = "moritz.raabe@fireeye.com"
    scope        = "function"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/nursery/hash-data-with-md5.yml"
    capa_nursery = "True"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $num_cua = { 01 23 45 67 }  // A
    $num_cub = { 89 AB CD EF }  // B
    $num_cuc = { FE DC BA 98 }  // C
    $num_cud = { 76 54 32 10 }  // D
    $num_cue = { F0 E1 D2 C3 }  // likely SHA1

  condition:
    capa_pe_file and
    (
      (
        $num_cua
        and $num_cub
        and $num_cuc
        and $num_cud
        and not $num_cue
      )
    )
}

rule capa_capture_screenshot: CAPA COLLECTION SCREENSHOT FUNCTION T1113 E1113_m01 INCOMPLETE {
  meta:
    description  = "capture screenshot (converted from capa rule)"
    namespace    = "collection/screenshot"
    scope        = "function"
    attack       = "Collection::Screen Capture [T1113]"
    mbc          = "Collection::Screen Capture::WinAPI [E1113.m01]"
    hash         = "BFB9B5391A13D0AFD787E87AB90F14F5"
    hash         = "7204e3efc2434012e13ca939db0d0b02"
    hash         = "50D5EE1CE2CA5E30C6B1019EE64EEEC2"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/screenshot/capture-screenshot.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_cum = "DISPLAY" ascii wide

  condition:
    capa_pe_file and
    (
      (
        (
          pe.imports(/user32/i, /GetWindowDC/)
          or pe.imports(/user32/i, /GetDC/)
          or (
            pe.imports(/gdi32/i, /CreateDCA/)
            and $func_str_cum
          )
        )
        and (
          pe.imports(/gdi32/i, /BitBlt/)
          or pe.imports(/gdi32/i, /GetDIBits/)
        )
        and pe.imports(/gdi32/i, /CreateCompatibleDC/)
        and pe.imports(/gdi32/i, /CreateCompatibleBitmap/)
      )
    )
}

rule capa_gather_leapftp_information: CAPA COLLECTION FILE_MANAGERS FUNCTION T1555 INCOMPLETE {
  meta:
    description  = "gather leapftp information (converted from capa rule)"
    namespace    = "collection/file-managers"
    author       = "@_re_fox"
    scope        = "function"
    attack       = "Credential Access::Credentials from Password Stores [T1555]"
    hash         = "5a2f620f29ca2f44fc22df67b674198f"
    reference    = "This YARA rule converted from capa rule: https://github.com/fireeye/capa-rules/blob/master/collection/file-managers/gather-leapftp-information.yml"
    comment      = "This rule is incomplete because a branch inside an Or-statement had an unsupported feature and was skipped => coverage is reduced compared to the original capa rule. "
    date         = "2021-05-25"
    minimum_yara = "3.8"
    license      = "Apache-2.0 License"

  strings:
    $func_str_cun = "InstallPath" ascii wide
    $func_str_cuo = "DataDir" ascii wide
    $func_str_cup = "sites.dat" ascii wide
    $func_str_cuq = "sites.ini" ascii wide

  condition:
    capa_pe_file and
    (
      (
        $func_str_cun
        and $func_str_cuo
        and $func_str_cup
        and $func_str_cuq
      )
    )
}