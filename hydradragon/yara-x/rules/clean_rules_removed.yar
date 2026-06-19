rule genericSMS2: smsFraud android {
  meta:
    author    = "https://twitter.com/plutec_net"
    reference = "https://koodous.com/"
    sample    = "1f23524e32c12c56be0c9a25c69ab7dc21501169c57f8d6a95c051397263cf9f"
    sample2   = "2cf073bd8de8aad6cc0d6ad5c98e1ba458bd0910b043a69a25aabdc2728ea2bd"
    sample3   = "20575a3e5e97bcfbf2c3c1d905d967e91a00d69758eb15588bdafacb4c854cba"

  strings:
    $a = "NotLeftTriangleEqual=022EC"
    $b = "SHA1-Digest: X27Zpw9c6eyXvEFuZfCL2LmumtI="
    $c = "_ZNSt12_Vector_baseISsSaISsEE13_M_deallocateEPSsj"
    $d = "FBTP2AHR3WKC6LEYON7D5GZXVISMJ4QU"

  condition:
    all of them

}

rule moscow_fake: banker androoid {
  meta:
    author       = "Fernando Denis"
    reference    = "https://koodous.com/ https://twitter.com/fdrg21"
    description  = "Moskow Droid Development"
    thread_level = 3
    in_the_wild  = true

  strings:
    $string_a = "%ioperator%"
    $string_b = "%imodel%"
    $string_c = "%ideviceid%"
    $string_d = "%ipackname%"
    $string_e = "VILLLLLL"

  condition:
    all of ($string_*)
}

rule xbot007: android {
  meta:
    reference = "https://github.com/maldroid/maldrolyzer/blob/master/plugins/xbot007.py"

  strings:
    $a = "xbot007"

  condition:
    any of them
}

rule Mal_PotPlayer_DLL: dll {
  meta:
    description = "Detects a malicious PotPlayer.dll"
    author      = "Florian Roth"
    reference   = "https://goo.gl/13Wgy1"
    date        = "2016-05-25"
    score       = 70
    hash1       = "705409bc11fb45fa3c4e2fa9dd35af7d4613e52a713d9c6ea6bc4baff49aa74a"

  strings:
    $x1 = "C:\\Users\\john\\Desktop\\PotPlayer\\Release\\PotPlayer.pdb" fullword ascii

    $s3 = "PotPlayer.dll" fullword ascii
    $s4 = "\\update.dat" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and $x1 or all of ($s*)
}

rule bleedinglife2_java_2010_0842_exploit: EK {
  meta:
    author          = "Josh Berry"
    date            = "2016-06-26"
    description     = "BleedingLife2 Exploit Kit Detection"
    hash0           = "b14ee91a3da82f5acc78abd10078752e"
    sample_filetype = "unknown"
    yaragenerator   = "https://github.com/Xen0ph0n/YaraGenerator"

  strings:
    $string0 = "META-INF/MANIFEST.MFManifest-Version: 1.0"
    $string1 = "ToolsDemo.classPK"
    $string2 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProvider5"
    $string3 = "Created-By: 1.6.0_22 (Sun Microsystems Inc.)"
    $string4 = "META-INF/PK"
    $string5 = "ToolsDemo.class"
    $string6 = "META-INF/services/PK"
    $string7 = "ToolsDemoSubClass.classPK"
    $string8 = "META-INF/MANIFEST.MFPK"
    $string9 = "ToolsDemoSubClass.classeN"

  condition:
    9 of them
}

rule zeus_js: EK {
  meta:
    author          = "Josh Berry"
    date            = "2016-06-26"
    description     = "Zeus Exploit Kit Detection"
    hash0           = "c87ac7a25168df49a64564afb04dc961"
    sample_filetype = "js-html"
    yaragenerator   = "https://github.com/Xen0ph0n/YaraGenerator"

  strings:
    $string0  = "var jsmLastMenu "
    $string1  = "position:absolute; z-index:99' "
    $string2  = " -1)jsmSetDisplayStyle('popupmenu' "
    $string3  = " '<tr><td><a href"
    $string4  = "  jsmLastMenu "
    $string5  = "  var ids "
    $string6  = "this.target"
    $string7  = " jsmPrevMenu, 'none');"
    $string8  = "  if(jsmPrevMenu "
    $string9  = ")if(MenuData[i])"
    $string10 = " '<div style"
    $string11 = "popupmenu"
    $string12 = "  jsmSetDisplayStyle('popupmenu' "
    $string13 = "function jsmHideLastMenu()"
    $string14 = " MenuData.length; i"

  condition:
    14 of them
}

rule Contains_VBE_File: maldoc {
  meta:
    author      = "Didier Stevens (https://DidierStevens.com)"
    description = "Detect a VBE file inside a byte sequence"
    method      = "Find string starting with #@~^ and ending with ^#~@"

  strings:
    $vbe = /#@~\^.+\^#~@/

  condition:
    $vbe
}

rule Trojan_Win32_Plakpeer: Platinum {
  meta:
    author               = "Microsoft"
    description          = "Zc tool v2"
    original_sample_sha1 = "2155c20483528377b5e3fde004bb604198463d29"
    unpacked_sample_sha1 = "dc991ef598825daabd9e70bac92c79154363bab2"
    activity_group       = "Platinum"
    version              = "1.0"
    last_modified        = "2016-04-12"

  strings:
    $str1 = "@@E0020(%d)" wide
    $str2 = /exit.{0,3}@exit.{0,3}new.{0,3}query.{0,3}rcz.{0,3}scz/ wide
    $str3 = "---###---" wide
    $str4 = "---@@@---" wide

  condition:
    $str1 and $str2 and $str3 and $str4
}

rule docx_macro: mail {
  strings:
    $header     = "PK"
    $vbaStrings = "word/vbaProject.bin" nocase

  condition:
    $header at 0 and $vbaStrings
}
