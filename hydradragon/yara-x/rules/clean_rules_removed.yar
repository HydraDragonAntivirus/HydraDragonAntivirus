rule Sphinx_Moth_nvcplex {
  meta:
    description = "sphinx moth threat group file nvcplex.dat"
    author      = "Kudelski Security - Nagravision SA"
    reference   = "www.kudelskisecurity.com"
    date        = "2015-08-06"

  strings:
    $s0  = "mshtaex.exe" fullword wide
    $op0 = { 41 8b cc 44 89 6c 24 28 48 89 7c 24 20 ff 15 d3 }  /* Opcode */
    $op1 = { 48 3b 0d ad 8f 00 00 74 05 e8 ba f5 ff ff 48 8b }  /* Opcode */
    $op2 = { 8b ce e8 49 47 00 00 90 8b 43 04 89 05 93 f1 00 }  /* Opcode */

  condition:
    uint16(0) == 0x5a4d and filesize < 214KB and all of them
}

rule win_xwormmm_s1_6f74 {
  meta:
    author                    = "Johannes Bader"
    date                      = "2022-11-13"
    description               = "detects unpacked Xwormmm samples"
    hash1_md5                 = "6005e1ccaea62626a5481e09bbb653da"
    hash1_sha1                = "74138872ec0d0791b7f58eda8585250af40feaf9"
    hash1_sha256              = "7fc6a365af13150e7b1738129832ebd91f1010705b0ab0955a295e2c7d88be62"
    tlp                       = "TLP:WHITE"
    version                   = "v1.0"
    yarahub_author_email      = "yara@bin.re"
    yarahub_author_twitter    = "@viql"
    yarahub_license           = "CC BY-SA 4.0"
    yarahub_reference_md5     = "6005e1ccaea62626a5481e09bbb653da"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp  = "TLP:WHITE"
    yarahub_uuid              = "6f74e598-0f7c-42f4-9730-1925d1b08ebe"

  strings:
    $str_01 = "Mutexx"
    $str_02 = "USBS"
    $str_03 = "_appMutex"
    $str_04 = "dTimer2"
    $str_05 = "dosstu"
    $str_06 = "nameee"
    $str_07 = "ruta"
    $str_08 = "usbSP"
    $str_09 = "GetEncoderInfo"
    $str_10 = "AppendOutputText"
    $str_11 = "capCreateCaptureWindowA"
    $str_12 = "capGetDriverDescriptionA"
    $str_13 = "MyProcess_ErrorDataReceived"
    $str_14 = "MyProcess_OutputDataReceived"
    $str_15 = "STOBS64"
    $str_16 = "keybd_event"
    $str_17 = "AES_Decryptor"
    $str_18 = "AES_Encryptor"
    $str_19 = "tickees"
    $str_20 = "INDATE"
    $str_21 = "GetHashT"
    $str_22 = "isDisconnected"

    $str_23 = "PING?" wide
    $str_24 = "IsInRole" wide
    $str_25 = "Select * from AntivirusProduct" wide
    $str_26 = "FileManagerSplitFileManagerSplit" wide
    $str_27 = "\nError: " wide
    $str_28 = "[Folder]" wide

    $str_29 = "XKlog.txt" wide
    $str_30 = "<Xwormmm>" wide
    $str_32 = "GfvaHzPAZuTqRREB" wide

  condition:
    uint16(0) == 0x5A4D and
    (
      20 of ($str*)
    )
}

rule IISRaid {
  meta:
    id             = "40tj9tn6FNrr4xE042IPIm"
    fingerprint    = "521b0798e25a620534f8e04c8fd62fd42c90ea5b785968806cb7538986dedac6"
    version        = "1.0"
    creation_date  = "2021-08-01"
    first_imported = "2021-12-30"
    last_modified  = "2021-12-30"
    status         = "RELEASED"
    sharing        = "TLP:WHITE"
    source         = "BARTBLAZE"
    author         = "@bartblaze"
    description    = "Identifies IISRaid."
    category       = "MALWARE"
    malware        = "IISRAID"
    malware_type   = "BACKDOOR"
    reference      = "https://github.com/0x09AL/IIS-Raid"

  strings:
    $pdb1 = "\\IIS-Raid-master\\" ascii wide
    $pdb2 = "\\IIS-Backdoor.pdb" ascii wide
    $s1   = "C:\\Windows\\System32\\credwiz.exe" ascii wide
    $s2   = "C:\\Windows\\Temp\\creds.db" ascii wide
    $s3   = "CHttpModule::" ascii wide
    $s4   = "%02d/%02d/%04d %02d:%02d:%02d | %s" ascii wide

  condition:
    any of ($pdb*) or 3 of ($s*)
}

rule Tinba2 {
  meta:
    author      = "n3sfox <n3sfox@gmail.com>"
    date        = "2015/11/07"
    description = "Tinba 2 (DGA) banking trojan"
    reference   = "https://securityintelligence.com/tinba-malware-reloaded-and-attacking-banks-around-the-world"
    filetype    = "memory"
    hash1       = "c7f662594f07776ab047b322150f6ed0"
    hash2       = "dc71ef1e55f1ddb36b3c41b1b95ae586"
    hash3       = "b788155cb82a7600f2ed1965cffc1e88"

  strings:
    $str1   = "MapViewOfFile"
    $str2   = "OpenFileMapping"
    $str3   = "NtCreateUserProcess"
    $str4   = "NtQueryDirectoryFile"
    $str5   = "RtlCreateUserThread"
    $str6   = "DeleteUrlCacheEntry"
    $str7   = "PR_Read"
    $str8   = "PR_Write"
    $pubkey = "BEGIN PUBLIC KEY"
    $code1  = { 50 87 44 24 04 6A ?? E8 }

  condition:
    all of ($str*) and $pubkey and $code1
}

rule Contains_hidden_PE_File_inside_a_sequence_of_numbers {
  meta:
    author      = "Martin Willing (https://evild3ad.com)"
    description = "Detect a hidden PE file inside a sequence of numbers (comma separated)"
    reference   = "http://blog.didierstevens.com/2016/01/07/blackenergy-xls-dropper/"
    reference   = "http://www.welivesecurity.com/2016/01/04/blackenergy-trojan-strikes-again-attacks-ukrainian-electric-power-industry/"
    date        = "2016-01-09"
    filetype    = "decompressed VBA macro code"

  strings:
    $a = "= Array("  // Array of bytes
    $b = "77, 90,"  // MZ
    $c = "33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46,"  // !This program cannot be run in DOS mode.

  condition:
    all of them
}
