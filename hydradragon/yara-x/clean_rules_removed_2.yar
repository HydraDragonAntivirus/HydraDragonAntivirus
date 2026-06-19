rule Sphinx_Moth_cudacrt {
  meta:
    description = "sphinx moth threat group file cudacrt.dll"
    author      = "Kudelski Security - Nagravision SA"
    reference   = "www.kudelskisecurity.com"
    date        = "2015-08-06"

  strings:
    $s0 = "HPSSOEx.dll" fullword wide
    $s1 = "255.255.255.254" fullword wide
    $s2 = "SOFTWARE\\SsoAuth\\Service" fullword wide

    $op0 = { ff 15 5f de 00 00 48 8b f8 48 85 c0 75 0d 48 8b }  /* Opcode */
    $op1 = { 45 33 c9 4c 8d 05 a7 07 00 00 33 d2 33 c9 ff 15 }  /* Opcode */
    $op2 = { e8 7a 1c 00 00 83 f8 01 74 17 b9 03 }  /* Opcode */

  condition:
    uint16(0) == 0x5a4d and filesize < 243KB and all of ($s*) and 1 of ($op*)
}

rule KPortScan {
  meta:
    id             = "3ywZWmdGN5mlc73cUnzre"
    fingerprint    = "ee8fb9b2387f2fe406f89b99b46f8f1b3855df23e09908c67b53c13532160915"
    version        = "1.0"
    creation_date  = "2020-08-01"
    first_imported = "2021-12-30"
    last_modified  = "2021-12-30"
    status         = "RELEASED"
    sharing        = "TLP:WHITE"
    source         = "BARTBLAZE"
    author         = "@bartblaze"
    description    = "Identifies KPortScan, port scanner."
    category       = "MALWARE"
    malware_type   = "SCANNER"

  strings:
    $s1  = "KPortScan 3.0" ascii wide
    $s2  = "KPortScan3.exe" ascii wide
    $x1  = "Count of goods:" ascii wide
    $x2  = "Current range:" ascii wide
    $x3  = "IP ranges list is clear" ascii wide
    $x4  = "ip,port,state" ascii wide
    $x5  = "on_loadFinished(QNetworkReply*)" ascii wide
    $x6  = "on_scanDiapFinished()" ascii wide
    $x7  = "on_scanFinished()" ascii wide
    $x8  = "scanDiapFinished()" ascii wide
    $x9  = "scanFinished()" ascii wide
    $x10 = "with port" ascii wide
    $x11 = "without port" ascii wide

  condition:
    any of ($s*) or 3 of ($x*)
}

rule Ekans {
  meta:
    id             = "6Kzy2bA2Zj7kvpXriuZ14m"
    fingerprint    = "396b915c02a14aa809060946c9294f487a5107ab37ebefb6d5cde07de4113d43"
    version        = "1.0"
    creation_date  = "2020-03-01"
    first_imported = "2021-12-30"
    last_modified  = "2023-12-24"
    status         = "RELEASED"
    sharing        = "TLP:WHITE"
    source         = "BARTBLAZE"
    author         = "@bartblaze"
    description    = "Identifies Ekans aka Snake ransomware unpacked or in memory."
    category       = "MALWARE"
    malware        = "EKANS"
    malware_type   = "RANSOMWARE"

  strings:
    $ = "already encrypted!" ascii wide
    $ = "error encrypting %v : %v" ascii wide
    $ = "faild to get process list" ascii wide
    $ = "There can be only one" ascii wide fullword
    $ = "total lengt: %v" ascii wide fullword

  condition:
    3 of them
}

rule Exela {
  meta:
    author      = "Any.RUN"
    reference   = "https://twitter.com/MalGamy12/status/1703704904039047273"
    description = "Detects Exela Stealer"
    date        = "2023-09-20"
    hash1       = "bf5d70ca2faf355d86f4b40b58032f21e99c3944b1c5e199b9bb728258a95c1b"
    hash2       = "e9e59ca2c8e786f92e81134f088ea08c53fc4c8c252871613ccc51b473814633"

  strings:
    $x1 = "Exela Stealer" wide nocase
    $x2 = "Exela\\Exela\\obj\\Release\\Exela.pdb" ascii fullword

    $s1  = "discord.com/api/webhooks" wide
    $s2  = "wifi.txt" wide
    $s3  = "network.txt" wide
    $s4  = "Autofills.txt" wide
    $s5  = "Downloads.txt" wide
    $s6  = "Cookies.txt" wide
    $s7  = "Passwords.txt" wide
    $s8  = "Cards.txt" wide
    $s9  = "Mutex already exist." wide
    $s10 = "All User Profile\\s*: (.*)" wide
    $s11 = "Key Content\\s*: (.*)" wide

  condition:
    uint16(0) == 0x5A4D and filesize < 400KB
    and
    (
      any of ($x*)
      or
      all of ($s*)
    )

}

rule Fusion {
  meta:
    id             = "5zeDUSWAX6101brsHGmiNB"
    fingerprint    = "a1e5d90fc057d3d32754d241df9b1847eaad9e67e4b54368c28ee179a796944e"
    version        = "1.0"
    creation_date  = "2021-06-01"
    first_imported = "2021-12-30"
    last_modified  = "2021-12-30"
    status         = "RELEASED"
    sharing        = "TLP:WHITE"
    source         = "BARTBLAZE"
    author         = "@bartblaze"
    description    = "Identifies Fusion ransomware, Go variant of Nemty/Nefilim."
    category       = "MALWARE"
    malware        = "FUSION"
    malware_type   = "RANSOMWARE"

  strings:
    $s1   = "main.getdrives" ascii wide
    $s2   = "main.SaveNote" ascii wide
    $s3   = "main.FileSearch" ascii wide
    $s4   = "main.BytesToPublicKey" ascii wide
    $s5   = "main.GenerateRandomBytes" ascii wide
    $x1   = /Fa[i1]led to fi.Close/ ascii wide
    $x2   = /Fa[i1]led to fi2.Close/ ascii wide
    $x3   = /Fa[i1]led to get stat/ ascii wide
    $x4   = /Fa[i1]led to os.OpenFile/ ascii wide
    $pdb1 = "C:/OpenServer/domains/build/aes.go" ascii wide
    $pdb2 = "C:/Users/eugene/Desktop/test go/test.go" ascii wide
    $pdb3 = "C:/Users/eugene/Desktop/web/src/aes_" ascii wide

  condition:
    4 of ($s*) or 3 of ($x*) or any of ($pdb*)
}

rule MortisLocker {
  meta:
    author      = "ANY.RUN"
    description = "Detects MortisLocker ransomware"
    date        = "2023-10-05"
    reference   = "https://twitter.com/MalGamy12/status/1709475837685256466"
    hash1       = "a5012e20342f4751360fd0d15ab013385cecd2a5f3e7a3e8503b1852d8499819"
    hash2       = "b6a4331334a16af65c5e4193f45b17c874e3eff8dd8667fd7cb8c7a570e2a8b9"
    hash3       = "c6df9cb7c26e0199106bdcd765d5b93436f373900b26f23dfc03b8b645c6913f"
    hash4       = "dac667cfc7824fd45f511bba83ffbdb28fa69cdeff0909979de84064ca2e0283"

  strings:
    $malname = "MortisLocker" fullword ascii

    $app_policy = "AppPolicyGetProcessTerminationMethod" fullword ascii

    $dbg_1 = "C:\\Users\\Admin\\OneDrive\\Desktop\\Test" fullword ascii
    $dbg_2 = "C:\\Users\\Admin\\source\\repos\\Mortis\\Release\\" fullword ascii

    $ext_susp_1 = ".Mortis" fullword ascii
    $ext_susp_2 = ".tabun" fullword ascii

    $dir_susp_1 = "config.msi" fullword ascii
    $dir_susp_2 = "recycle.bin" fullword ascii
    $dir_susp_3 = "windows.old" fullword ascii
    $dir_susp_4 = "$windows.~ws" fullword ascii
    $dir_susp_5 = "$windows.~bt" fullword ascii
    $dir_susp_6 = "msocache" fullword ascii
    $dir_susp_7 = "perflogs" fullword ascii

    $log_bcrypt  = /BCrypt[\w]+ failed with error code:/ fullword ascii
    $log_drive_1 = "[i] Encrypting Logical Drives:" fullword ascii
    $log_drive_2 = "[-] No drives found." fullword ascii
    $log_share_1 = "[i] Encrypting Network Shares:" fullword ascii
    $log_share_2 = "[!] Failed to enumerate network shares:" fullword ascii
    $log_share_3 = "[-] No network shares found." fullword ascii
    $log_file_1  = "Encryption failed for file:" fullword ascii
    $log_file_2  = "Encryption successful. Encrypted file:" fullword ascii
    $log_file_3  = "Failed to open output file:" fullword ascii
    $log_file_4  = "Failed to rename file:" fullword ascii
    $log_file_5  = "File is empty:" fullword ascii
    $log_rbin_1  = "[+] Emptied Recycle Bin." fullword ascii
    $log_rbin_2  = "Recycle Bin emptied successfully." fullword ascii
    $log_rbin_3  = "[!] Failed to Empty Recycle Bin." fullword ascii
    $log_rbin_4  = "Failed to empty Recycle Bin." fullword ascii
    $log_priv_1  = "[+] Enabled Privileges." fullword ascii
    $log_priv_2  = "[!] Failed to enable privileges." fullword ascii
    $log_aes_1   = "[*] AES Key:" fullword ascii
    $log_aes_2   = "[i] AES Key:" fullword ascii
    $log_aes_3   = "[!] Failed to generate AES Key." fullword ascii
    $log_folder  = "[*] Ignored Folder:" fullword ascii
    $log_lock    = "[+] Locked:" fullword ascii
    $log_msg_1   = "cryptDir execution time:" fullword ascii

  condition:
    uint16(0) == 0x5A4D and
    (
      2 of ($malname, $app_policy, $dbg_*) or
      1 of ($malname, $app_policy, $dbg_*) and
      (
        3 of ($log_*) or
        6 of ($dir_susp_*, $ext_susp_*)
      )
    )
}

rule Pysa {
  meta:
    id             = "240byxdCwyzaTk3xgjzbEa"
    fingerprint    = "7f8819e9f76b9c97e90cd5da7ea788c9bb1eb135d8e1cb8974d6f17ecf51b3c3"
    version        = "1.0"
    creation_date  = "2021-03-01"
    first_imported = "2021-12-30"
    last_modified  = "2021-12-30"
    status         = "RELEASED"
    sharing        = "TLP:WHITE"
    source         = "BARTBLAZE"
    author         = "@bartblaze"
    description    = "Identifies Pysa aka Mespinoza ransomware."
    category       = "MALWARE"
    malware        = "PYSA"
    malware_type   = "RANSOMWARE"
    mitre_att      = "S0583"

  strings:
    $code = {
      8a 0? 41 84 c0 75 ?? 2b ce 8b 35 ?? ?? ?? ?? 8d 41 01 50 5? 6a 07 6a 00 68 ?? ?? ??
      ?? ff 7? ?? ff d? 6a 05 68 ?? ?? ?? ?? 6a 07 6a 00 68 ?? ?? ?? ?? ff 7? ?? ff d? ff 7? ?? ff
      15 ?? ?? ?? ?? 8b 4? ?? 33 cd 5e e8 ?? ?? ?? ?? 8b e5 5d c3
    }
    $s1   = "n.pysa" ascii wide fullword
    $s2   = "%s\\Readme.README" ascii wide
    $s3   = "Every byte on any types of your devices was encrypted." ascii wide

  condition:
    $code or 2 of ($s*)
}

rule RagnarLocker {
  meta:
    id             = "5066KiqBNrcicJGfWPfDx5"
    fingerprint    = "fd403ea38a9c6c269ff7b72dea1525010f44253a41e72bf3fce55fa4623245a3"
    version        = "1.0"
    creation_date  = "2020-07-01"
    first_imported = "2021-12-30"
    last_modified  = "2021-12-30"
    status         = "RELEASED"
    sharing        = "TLP:WHITE"
    source         = "BARTBLAZE"
    author         = "@bartblaze"
    description    = "Identifies RagnarLocker ransomware unpacked or in memory."
    category       = "MALWARE"
    malware        = "RAGNAR LOCKER"
    malware_type   = "RANSOMWARE"
    mitre_att      = "S0481"

  strings:
    $ = "RAGNRPW" ascii wide
    $ = "---END KEY R_R---" ascii wide
    $ = "---BEGIN KEY R_R---" ascii wide

  condition:
    any of them
}

rule Sfile {
  meta:
    id             = "64arpb3yJ0mZxamCG9jIVs"
    fingerprint    = "7a2be690f14a9ea61917c2c31b4d44186295de7d8a1342f081ed9507a8ac46b0"
    version        = "1.0"
    creation_date  = "2020-09-01"
    first_imported = "2021-12-30"
    last_modified  = "2021-12-30"
    status         = "RELEASED"
    sharing        = "TLP:WHITE"
    source         = "BARTBLAZE"
    author         = "@bartblaze"
    description    = "Identifies Sfile aka Escal ransomware."
    category       = "MALWARE"
    malware_type   = "RANSOMWARE"

  strings:
    $pdb = "D:\\code\\ransomware_win\\bin\\ransomware.pdb" ascii wide
    $    = "%s SORTING time : %s" ascii wide
    $    = "%ws -> WorkModeDecryptFiles : %d of %d files decrypted +%d (%d MB)..." ascii wide
    $    = "%ws -> WorkModeEncryptFiles : %d of %d files encrypted +%d [bps : %d, size = %d MB] (%d skipped, ld = %d.%d.%d %d:%d:%d, lf = %ws)..." ascii wide
    $    = "%ws -> WorkModeEnded" ascii wide
    $    = "%ws -> WorkModeFindFiles : %d files / %d folders found (already (de?)crypted %d/%d) (lf = %ws)..." ascii wide
    $    = "%ws -> WorkModeSorting" ascii wide
    $    = "%ws ENCRYPTFILES count : %d (%d skipped), time : %s" ascii wide
    $    = "%ws FINDFILES RESULTS : dwDirectoriesCount = %d, dwFilesCount = %d MB = %d (FIND END)" ascii wide
    $    = "%ws FINDFILES time : %s" ascii wide
    $    = "DRIVE_FIXED : %ws" ascii wide
    $    = "EncryptDisk(%ws) DONE" ascii wide
    $    = "ScheduleRoutine() : gogogo" ascii wide
    $    = "ScheduleRoutine() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
    $    = "WARN! FileLength more then memory has %ws" ascii wide
    $    = "WaitForHours() : gogogo" ascii wide
    $    = "WaitForHours() : waiting for sacred time... Expecting %d hours, now id %d" ascii wide
    $    = "Your network has been penetrated." ascii wide
    $    = "--kill-susp" ascii wide
    $    = "--enable-shares" ascii wide

  condition:
    $pdb or 3 of them
}

rule WinLock {
  meta:
    id             = "3MQTREUk3DgifGki8sa7hl"
    fingerprint    = "6d659e5dc636a9535d07177776551ae3b32eae97b86e3e7dd01d74d0bbe33c82"
    version        = "1.0"
    creation_date  = "2020-08-01"
    first_imported = "2021-12-30"
    last_modified  = "2021-12-30"
    status         = "RELEASED"
    sharing        = "TLP:WHITE"
    source         = "BARTBLAZE"
    author         = "@bartblaze"
    description    = "Identifies WinLock (aka Blocker) ransomware variants generically."
    category       = "MALWARE"
    malware        = "WINLOCK"
    malware_type   = "RANSOMWARE"

  strings:
    $s1  = "twexx32.dll" ascii wide
    $s2  = "s?cmd=ul&id=%s" ascii wide
    $s3  = "card_ukash.png" ascii wide
    $s4  = "toneo_card.png" ascii wide
    $pdb = "C:\\Kuzja 1.4\\vir.vbp" ascii wide
    $x1  = "AntiWinLockerTray.exe" ascii wide
    $x2  = "Computer name:" ascii wide
    $x3  = "Current Date:" ascii wide
    $x4  = "Information about blocking" ascii wide
    $x5  = "Key Windows:" ascii wide
    $x6  = "Password attempts:" ascii wide
    $x7  = "Registered on:" ascii wide
    $x8  = "ServiceAntiWinLocker.exe" ascii wide
    $x9  = "Time of Operation system:" ascii wide
    $x10 = "To removing the system:" ascii wide

  condition:
    3 of ($s*) or $pdb or 5 of ($x*)
}

rule XenoRAT {
  meta:
    description = "Detects XenoRAT"
    author      = "Any.Run"
    reference   = "https://github.com/moom825/xeno-rat"
    date        = "2024-01-13"

    hash1 = "AA28B0FF8BADF57AAEEACD82F0D8C5FBBD28008449A3075D8A4DA63890232418"
    hash2 = "34AB005B549534DBA9A83D9346E1618A18ECEE2C99A93079551634F9480B2B79"
    hash3 = "99C24686E9AC15EC6914D314A1D72DD9A1EBECE08FD1B8A75E00373051E82079"

    url1 = "https://app.any.run/tasks/ca9ee9db-760f-40cb-b1ad-5210cc2b972e"
    url2 = "https://app.any.run/tasks/4bf50208-0a9d-4c39-9a53-82a417ebac4d"
    url3 = "https://app.any.run/tasks/efcd6fc0-75a4-4628-b367-9a17e4254834"

  strings:
    $x1 = "xeno rat client" ascii wide
    $x2 = "xeno_rat_client" ascii
    $x3 = "%\\XenoManager\\" fullword wide
    $x4 = "XenoUpdateManager" fullword wide
    $x5 = "RecvAllAsync_ddos_unsafer" ascii

    $s1  = "SELECT * FROM AntivirusProduct" fullword wide
    $s2  = "SELECT * FROM Win32_OperatingSystem" fullword wide
    $s3  = "WindowsUpdate" fullword wide
    $s4  = "HWID" fullword ascii
    $s5  = "AddToStartupNonAdmin" ascii
    $s6  = "CreateSubSock" ascii
    $s7  = "Badapplexe Executor from github important" fullword wide
    $s8  = "mutex_string" fullword ascii
    $s9  = "_EncryptionKey" fullword ascii
    $s10 = "/query /v /fo csv" fullword wide
    $s11 = "<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>" wide
    $s12 = "/C choice /C Y /N /D Y /T 3 & Del \"" fullword wide

  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and
    (1 of ($x*) or 7 of them)
}

rule Zeppelin {
  meta:
    id             = "RIttcGgKqwaotJyTgah7j"
    fingerprint    = "a4da7defafa7f510df1c771e3d67bf5d99f3684a44f56d2b0e6f40f0a7fea84f"
    version        = "1.0"
    creation_date  = "2019-11-01"
    first_imported = "2021-12-30"
    last_modified  = "2021-12-30"
    status         = "RELEASED"
    sharing        = "TLP:WHITE"
    source         = "BARTBLAZE"
    author         = "@bartblaze"
    description    = "Identifies Zeppelin ransomware and variants (Buran, Vega etc.)"
    category       = "MALWARE"
    malware        = "ZEPPELIN"
    malware_type   = "RANSOMWARE"

  strings:
    $s1 = "TUnlockAndEncryptU" ascii wide
    $s2 = "TDrivesAndShares" ascii wide
    $s3 = "TExcludeFoldersU" ascii wide
    $s4 = "TExcludeFiles" ascii wide
    $s5 = "TTaskKillerU" ascii wide
    $s6 = "TPresenceU" ascii wide
    $s7 = "TSearcherU" ascii wide
    $s8 = "TReadme" ascii wide
    $s9 = "TKeyObj" ascii wide
    $x  = "TZeppelinU" ascii wide

  condition:
    2 of ($s*) or $x
}

rule UPX_Alternative_stub {
  strings:
    $a0 = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }

  condition:
    $a0 at pe.entry_point
}

rule PENinja_modified {
  strings:
    $a0 = { 5D 8B C5 81 ED B2 2C 40 00 2B 85 94 3E 40 00 2D 71 02 00 00 89 85 98 3E 40 00 0F B6 B5 9C 3E 40 00 8B FD }

  condition:
    $a0 at pe.entry_point
}

rule PE_Crypter {
  strings:
    $a0 = { 60 E8 00 00 00 00 5D EB 26 }

  condition:
    $a0 at pe.entry_point
}

rule Reflexive_Arcade_Wrapper {
  strings:
    $a0 = { 55 8B EC 6A FF 68 98 68 42 00 68 14 FA 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 F8 50 42 00 33 D2 8A D4 89 15 3C E8 42 00 8B C8 81 E1 FF 00 00 00 89 0D 38 E8 42 00 C1 E1 08 03 CA 89 0D 34 E8 42 00 C1 E8 10 A3 30 E8 }

  condition:
    $a0 at pe.entry_point
}

rule kryptor_5 {
  strings:
    $a0 = { E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0 }

  condition:
    $a0 at pe.entry_point
}

rule WinRAR_32_bit_SFX_Module {
  strings:
    $a0 = { E9 ?? ?? 00 00 00 00 00 00 90 90 90 ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? FF }

  condition:
    $a0 at pe.entry_point
}

rule Install_Stub_32_bit {
  strings:
    $a0 = { 55 8B EC 81 EC 14 ?? 00 00 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 29 }

  condition:
    $a0 at pe.entry_point
}

rule Password_protector_my_SMT {
  strings:
    $a0 = { E8 ?? ?? ?? ?? 5D 8B FD 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 46 80 ?? ?? 74 }

  condition:
    $a0 at pe.entry_point
}

rule ARC_SFX_Archive {
  strings:
    $a0 = { 8C C8 8C DB 8E D8 8E C0 89 ?? ?? ?? 2B C3 A3 ?? ?? 89 ?? ?? ?? BE ?? ?? B9 ?? ?? BF ?? ?? BA ?? ?? FC AC 32 C2 8A D8 }

  condition:
    $a0 at pe.entry_point
}
